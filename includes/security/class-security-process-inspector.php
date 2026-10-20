<?php
/**
 * Process inspector for list-processes / kill-process.
 *
 * Reads `/proc/<pid>/` directly (no shell, no exec) and only ever reports or
 * signals processes owned by the same user as PHP. The parsing, suspicion and
 * refusal rules are pure static methods so they can be tested against fake
 * /proc trees; the instance methods are thin wrappers that touch the OS.
 *
 * Why it exists: on a hacked site a background shell loop started by a fake
 * mu-plugin kept rewriting index.php from a hidden file under /tmp, so every
 * file cleanup was undone until the process was stopped.
 *
 * @package EMCP_Tools
 * @since   3.21.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * @since 3.21.0
 */
class EMCP_Tools_Security_Process_Inspector {

	/** Clock ticks per second used by /proc start times (USER_HZ is 100 on Linux). */
	const CLOCK_TICKS = 100;

	/** Longest command line returned, in bytes. */
	const MAX_CMDLINE = 512;

	/** Most /proc entries looked at in one listing. */
	const MAX_SCAN = 5000;

	/** Most processes returned in one listing. */
	const MAX_LIST = 300;

	/** Signals kill-process may send. */
	const SIGNALS = array(
		'TERM' => 15,
		'KILL' => 9,
	);

	/** Temporary directories a site's own code has no business running from. */
	const TEMP_DIRS = array( '/tmp/', '/var/tmp/', '/dev/shm/' );

	/** Shell interpreters, matched on the basename of argv[0]. */
	const SHELLS = array( 'sh', 'bash', 'dash', 'ash', 'zsh', 'ksh', 'busybox' );

	/** @var string */
	private $proc_root;

	/** @var string */
	private $os_family;

	/** @var array|null { uid, pid, ppid } */
	private $identity;

	/** @var string */
	private $uploads_dir;

	/**
	 * @param string     $proc_root   The /proc mount (a fake tree in tests).
	 * @param string     $os_family   PHP_OS_FAMILY, injectable for tests.
	 * @param array|null $identity    { uid, pid, ppid } of this PHP process; null to detect.
	 * @param string     $uploads_dir Absolute uploads directory; '' to ask WordPress.
	 */
	public function __construct( string $proc_root = '/proc', string $os_family = PHP_OS_FAMILY, ?array $identity = null, string $uploads_dir = '' ) {
		$this->proc_root   = rtrim( $proc_root, '/' );
		$this->os_family   = $os_family;
		$this->identity    = $identity;
		$this->uploads_dir = $uploads_dir;
	}

	// ---- Pure parsing ------------------------------------------------------

	/**
	 * Parse `/proc/<pid>/stat`. The command name sits in parentheses and may
	 * itself contain spaces or parentheses, so split on the LAST ')'.
	 *
	 * @param string $raw File contents.
	 * @return array|null { pid, comm, state, ppid, start_time } or null when malformed.
	 */
	public static function parse_stat( string $raw ): ?array {
		$open  = strpos( $raw, '(' );
		$close = strrpos( $raw, ')' );
		if ( false === $open || false === $close || $close < $open ) {
			return null;
		}
		$pid    = trim( substr( $raw, 0, $open ) );
		$fields = preg_split( '/\s+/', trim( substr( $raw, $close + 1 ) ) );
		// Fields after the name start at stat field 3 (state); starttime is field 22.
		if ( ! ctype_digit( $pid ) || ! is_array( $fields ) || count( $fields ) < 20 || ! ctype_digit( $fields[19] ) ) {
			return null;
		}
		return array(
			'pid'        => (int) $pid,
			'comm'       => substr( $raw, $open + 1, $close - $open - 1 ),
			'state'      => (string) $fields[0],
			'ppid'       => (int) $fields[1],
			'start_time' => (string) $fields[19],
		);
	}

	/**
	 * Parse `/proc/<pid>/status` for the name and the real and effective uid.
	 *
	 * @param string $raw File contents.
	 * @return array { name, ruid, euid } (uids are -1 when missing).
	 */
	public static function parse_status( string $raw ): array {
		$out = array(
			'name' => '',
			'ruid' => -1,
			'euid' => -1,
		);
		foreach ( explode( "\n", $raw ) as $line ) {
			if ( 0 === strpos( $line, 'Name:' ) ) {
				$out['name'] = trim( substr( $line, 5 ) );
			} elseif ( 0 === strpos( $line, 'Uid:' ) ) {
				$ids = preg_split( '/\s+/', trim( substr( $line, 4 ) ) );
				if ( isset( $ids[0], $ids[1] ) && ctype_digit( $ids[0] ) && ctype_digit( $ids[1] ) ) {
					$out['ruid'] = (int) $ids[0];
					$out['euid'] = (int) $ids[1];
				}
			}
		}
		return $out;
	}

	/**
	 * Parse `/proc/<pid>/cmdline` (NUL-separated argv).
	 *
	 * @param string $raw File contents.
	 * @param int    $max Byte cap for the joined text.
	 * @return array { argv: string[], text: string, truncated: bool }
	 */
	public static function parse_cmdline( string $raw, int $max = self::MAX_CMDLINE ): array {
		$argv = array_values(
			array_filter(
				explode( "\0", $raw ),
				static function ( $part ) {
					return '' !== $part;
				}
			)
		);
		$text      = self::redact( $argv );
		$truncated = strlen( $text ) > $max;
		if ( $truncated ) {
			$text = substr( $text, 0, $max );
		}
		return array(
			'argv'      => $argv,
			'text'      => $text,
			'truncated' => $truncated,
		);
	}

	/**
	 * Join argv with spaces, masking values that look like credentials: a
	 * `name=value` whose name mentions a password, secret, token or key, the
	 * value after `--password`, a MySQL client's `-p<password>`, and the
	 * password in a `scheme://user:password@host` URL.
	 *
	 * @param string[] $argv Arguments.
	 */
	public static function redact( array $argv ): string {
		$mysql = isset( $argv[0] ) && preg_match( '/^(mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)$/', basename( $argv[0] ) );
		$out   = array();
		$mask  = false;
		foreach ( $argv as $i => $arg ) {
			if ( $mask ) {
				$out[] = '***';
				$mask  = false;
				continue;
			}
			if ( preg_match( '/^--?(password|passwd|pass|secret|token|api[_-]?key)$/i', $arg ) ) {
				$mask = true;
			} elseif ( $mysql && $i > 0 && preg_match( '/^-p.+/', $arg ) ) {
				$arg = '-p***';
			}
			$arg   = preg_replace( '/((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth[_-]?key|access[_-]?key)[a-z_]*=)[^\s&]+/i', '$1***', $arg );
			$arg   = preg_replace( '#(://[^/\s:@]+:)[^@\s/]+@#', '$1***@', (string) $arg );
			$out[] = (string) $arg;
		}
		return implode( ' ', $out );
	}

	// ---- Pure suspicion rules ----------------------------------------------

	/**
	 * Reasons a process looks like something an attacker left running.
	 *
	 * @param array  $proc        { comm, argv, exe, cwd } (exe/cwd null when unreadable).
	 * @param string $uploads_dir Absolute uploads directory ('' to match wp-content/uploads only).
	 * @return array[] Each { code, detail }.
	 */
	public static function suspicion_reasons( array $proc, string $uploads_dir = '' ): array {
		$argv    = isset( $proc['argv'] ) && is_array( $proc['argv'] ) ? $proc['argv'] : array();
		$exe     = isset( $proc['exe'] ) ? (string) $proc['exe'] : '';
		$cwd     = isset( $proc['cwd'] ) ? (string) $proc['cwd'] : '';
		$paths   = array_merge( array( $exe ), $argv );
		$reasons = array();

		$temp = self::first_match( $paths, array( __CLASS__, 'in_temp_dir' ) );
		if ( '' !== $temp ) {
			$reasons[] = self::reason( 'temp_dir', sprintf( 'Runs from a temporary directory: %s', $temp ) );
		} elseif ( '' !== $cwd && self::in_temp_dir( $cwd . '/' ) ) {
			$reasons[] = self::reason( 'temp_cwd', sprintf( 'Working directory is a temporary directory: %s', $cwd ) );
		}
		$hidden = self::first_match( $paths, array( __CLASS__, 'is_hidden_path' ) );
		if ( '' !== $hidden ) {
			$reasons[] = self::reason( 'hidden_name', sprintf( 'Uses a hidden file or folder name: %s', $hidden ) );
		}
		if ( '' !== $exe && ' (deleted)' === substr( $exe, -10 ) ) {
			$reasons[] = self::reason( 'deleted_exe', 'Its program file was deleted after it started, a common way to hide a running back door.' );
		}
		$shell = self::shell_loop_reason( $argv );
		if ( '' !== $shell ) {
			$reasons[] = self::reason( 'shell_loop', $shell );
		}
		if ( isset( $argv[0] ) && preg_match( '/^\[[^\]]+\]$/', implode( ' ', $argv ) ) ) {
			$reasons[] = self::reason( 'fake_kernel_thread', 'Names itself like a kernel thread, but kernel threads have no command line and never run as the site user.' );
		}
		$php = self::php_uploads_target( $argv, $uploads_dir );
		if ( '' !== $php ) {
			$reasons[] = self::reason( 'php_in_uploads', sprintf( 'PHP is running a file from the uploads folder: %s', $php ) );
		}
		return $reasons;
	}

	/** True when a path sits under /tmp, /var/tmp or /dev/shm. */
	public static function in_temp_dir( string $path ): bool {
		foreach ( self::TEMP_DIRS as $dir ) {
			if ( 0 === strpos( $path, $dir ) ) {
				return true;
			}
		}
		return false;
	}

	/** True when an absolute path has a segment starting with a dot (not `.` or `..`). */
	public static function is_hidden_path( string $path ): bool {
		if ( '' === $path || '/' !== $path[0] ) {
			return false;
		}
		return (bool) preg_match( '#/\.(?!\.?(?:/|$))[^/]#', $path );
	}

	/**
	 * Why a shell command looks like a watcher loop, or ''.
	 *
	 * @param string[] $argv Arguments.
	 */
	public static function shell_loop_reason( array $argv ): string {
		if ( ! isset( $argv[0] ) || ! in_array( basename( $argv[0] ), self::SHELLS, true ) ) {
			return '';
		}
		foreach ( array_slice( $argv, 1 ) as $arg ) {
			if ( self::in_temp_dir( $arg ) ) {
				return sprintf( 'A shell is running a script from a temporary directory: %s', $arg );
			}
		}
		$script = implode( ' ', array_slice( $argv, 1 ) );
		if ( preg_match( '/\bwhile\s+(?:true|:|\[\s*1\s*\]|\(\(\s*1\s*\)\))/', $script ) ) {
			return 'A shell is running an endless while loop.';
		}
		if ( preg_match( '/\bsleep\b/', $script ) && preg_match( '/\b(?:while|until|for)\b/', $script ) ) {
			return 'A shell is running a loop that sleeps and repeats.';
		}
		return '';
	}

	/**
	 * The uploads file PHP is running, or ''.
	 *
	 * @param string[] $argv        Arguments.
	 * @param string   $uploads_dir Absolute uploads directory.
	 */
	public static function php_uploads_target( array $argv, string $uploads_dir = '' ): string {
		if ( ! isset( $argv[0] ) || ! preg_match( '/^php(?:[0-9.]*|-cli|-cgi)$/', basename( $argv[0] ) ) ) {
			return '';
		}
		$uploads_dir = '' === $uploads_dir ? '' : rtrim( $uploads_dir, '/' ) . '/';
		foreach ( array_slice( $argv, 1 ) as $arg ) {
			if ( false !== strpos( $arg, '/wp-content/uploads/' ) || ( '' !== $uploads_dir && 0 === strpos( $arg, $uploads_dir ) ) ) {
				return $arg;
			}
		}
		return '';
	}

	// ---- Pure refusal rules ------------------------------------------------

	/**
	 * Map a requested signal to its name, or null when it is not allowed.
	 *
	 * @param mixed $value 'TERM' (default when empty), 'KILL', with or without 'SIG'.
	 */
	public static function normalize_signal( $value ): ?string {
		if ( null === $value || '' === $value ) {
			return 'TERM';
		}
		if ( ! is_string( $value ) ) {
			return null;
		}
		$name = strtoupper( trim( $value ) );
		if ( 0 === strpos( $name, 'SIG' ) ) {
			$name = substr( $name, 3 );
		}
		return isset( self::SIGNALS[ $name ] ) ? $name : null;
	}

	/**
	 * Why a kill must be refused, or '' when it may go ahead.
	 *
	 * @param int        $pid        Requested pid.
	 * @param string     $start_time Start time the caller saw in list-processes.
	 * @param array|null $live       Fresh { pid, ruid, euid, start_time } from /proc, null when gone.
	 * @param array      $self       { uid, pid, ppid } of this PHP process.
	 * @param bool       $can_signal Whether posix_kill() is available.
	 * @return string Refusal code.
	 */
	public static function kill_refusal( int $pid, string $start_time, ?array $live, array $self, bool $can_signal ): string {
		if ( ! $can_signal ) {
			return 'posix_unavailable';
		}
		if ( $pid < 1 ) {
			return 'invalid_pid';
		}
		if ( 1 === $pid ) {
			return 'pid_one';
		}
		if ( (int) $self['pid'] === $pid ) {
			return 'self_process';
		}
		if ( (int) $self['ppid'] === $pid ) {
			return 'parent_process';
		}
		if ( '' === $start_time || ! ctype_digit( $start_time ) ) {
			return 'start_time_required';
		}
		if ( null === $live ) {
			return 'not_found';
		}
		if ( ! self::is_owned( $live, (int) $self['uid'] ) ) {
			return 'not_owned';
		}
		if ( (string) $live['start_time'] !== $start_time ) {
			return 'start_time_mismatch';
		}
		if ( self::is_server_process( (string) ( $live['comm'] ?? '' ) ) ) {
			return 'server_process';
		}
		return '';
	}

	/**
	 * Whether a process name belongs to a web server, PHP worker or database. On
	 * shared hosting these run as the same user for every site of the account,
	 * so stopping one can take other sites down; they are never signalled.
	 *
	 * @param string $comm Process name from /proc/<pid>/stat (at most 15 characters).
	 */
	public static function is_server_process( string $comm ): bool {
		return 1 === preg_match( '/^(php-fpm|php-cgi|lsphp|httpd|apache2?|nginx|litespeed|lshttpd|openlitespeed|mysqld|mariadbd|redis-server|memcached)/i', trim( $comm ) );
	}

	/** True when both the real and effective uid of a process are PHP's uid. */
	public static function is_owned( array $proc, int $uid ): bool {
		return $uid >= 0 && (int) $proc['ruid'] === $uid && (int) $proc['euid'] === $uid;
	}

	/**
	 * Human message for a refusal code.
	 *
	 * @param string $code Refusal code from kill_refusal().
	 */
	public static function refusal_message( string $code ): string {
		$messages = array(
			'posix_unavailable'   => __( 'This PHP build has no posix_kill(), so processes cannot be signalled from here.', 'emcp-tools' ),
			'invalid_pid'         => __( 'pid must be a positive whole number.', 'emcp-tools' ),
			'pid_one'             => __( 'PID 1 is the system init process and is never signalled.', 'emcp-tools' ),
			'self_process'        => __( 'That is the PHP process handling this request.', 'emcp-tools' ),
			'parent_process'      => __( 'That is the parent of the PHP process handling this request (the PHP-FPM master, web server or MCP server).', 'emcp-tools' ),
			'start_time_required' => __( 'Pass start_time exactly as list-processes returned it, so a reused pid is never signalled by mistake.', 'emcp-tools' ),
			'not_found'           => __( 'No process with that pid is running now.', 'emcp-tools' ),
			'not_owned'           => __( 'That process does not belong to the user PHP runs as.', 'emcp-tools' ),
			'server_process'      => __( 'That is a web server, PHP worker or database process. On shared hosting it can serve other sites of the same account, so it is never stopped from here. Ask the host to restart it.', 'emcp-tools' ),
			'start_time_mismatch' => __( 'That pid now belongs to a different process than the one listed (its start time changed). Run list-processes again.', 'emcp-tools' ),
		);
		return $messages[ $code ] ?? $code;
	}

	// ---- OS wrappers -------------------------------------------------------

	/**
	 * Why listing is not possible here, or '' when it is.
	 */
	public function unsupported_reason(): string {
		if ( 'Linux' !== $this->os_family ) {
			/* translators: %s: operating system family. */
			return sprintf( __( 'Process listing reads /proc, which only Linux has. This server runs %s.', 'emcp-tools' ), $this->os_family );
		}
		if ( ! @is_readable( $this->proc_root . '/stat' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir warnings are expected.
			return __( 'PHP cannot read /proc on this server (open_basedir or the host blocks it).', 'emcp-tools' );
		}
		return '';
	}

	/**
	 * The uid, pid and parent pid of this PHP process.
	 *
	 * @return array { uid, pid, ppid }
	 */
	public function identity(): array {
		if ( null !== $this->identity ) {
			return $this->identity;
		}
		$uid  = function_exists( 'posix_geteuid' ) ? (int) posix_geteuid() : (int) getmyuid();
		$pid  = (int) getmypid();
		$ppid = function_exists( 'posix_getppid' ) ? (int) posix_getppid() : 0;
		if ( 0 === $ppid ) {
			$stat = self::parse_stat( $this->read( $pid . '/stat' ) );
			$ppid = $stat ? (int) $stat['ppid'] : 0;
		}
		$this->identity = array(
			'uid'  => $uid,
			'pid'  => $pid,
			'ppid' => $ppid,
		);
		return $this->identity;
	}

	/**
	 * List this user's processes with suspicion flags.
	 *
	 * @return array
	 */
	public function list_processes(): array {
		$reason = $this->unsupported_reason();
		if ( '' !== $reason ) {
			return array(
				'supported' => false,
				'reason'    => $reason,
				'processes' => array(),
			);
		}
		$self    = $this->identity();
		$clock   = $this->clock();
		$pids    = $this->pids();
		$scanned = 0;
		$list    = array();
		foreach ( $pids as $pid ) {
			if ( ++$scanned > self::MAX_SCAN || count( $list ) >= self::MAX_LIST ) {
				break;
			}
			$proc = $this->read_process( $pid );
			if ( null === $proc || ! self::is_owned( $proc, (int) $self['uid'] ) ) {
				continue;
			}
			$list[] = $this->describe( $proc, $self, $clock );
		}
		usort(
			$list,
			static function ( $a, $b ) {
				return ( (int) $b['suspicious'] <=> (int) $a['suspicious'] ) ?: ( $a['pid'] <=> $b['pid'] );
			}
		);
		return array(
			'supported'        => true,
			'uid'              => (int) $self['uid'],
			'self_pid'         => (int) $self['pid'],
			'parent_pid'       => (int) $self['ppid'],
			'count'            => count( $list ),
			'suspicious_count' => count( array_filter( array_column( $list, 'suspicious' ) ) ),
			'truncated'        => $scanned > self::MAX_SCAN || count( $list ) >= self::MAX_LIST,
			'processes'        => $list,
		);
	}

	/**
	 * Fresh facts about one process, or null when it is gone or unreadable.
	 *
	 * @param int $pid Process id.
	 * @return array|null { pid, ppid, comm, state, start_time, name, ruid, euid, argv, cmdline, cmdline_truncated, exe, cwd }
	 */
	public function read_process( int $pid ): ?array {
		$stat = self::parse_stat( $this->read( $pid . '/stat' ) );
		if ( null === $stat || $stat['pid'] !== $pid ) {
			return null;
		}
		$cmd = self::parse_cmdline( $this->read( $pid . '/cmdline' ) );
		return array_merge(
			$stat,
			self::parse_status( $this->read( $pid . '/status' ) ),
			array(
				'argv'              => $cmd['argv'],
				'cmdline'           => $cmd['text'],
				'cmdline_truncated' => $cmd['truncated'],
				'exe'               => $this->read_link( $this->proc_root . '/' . $pid . '/exe' ),
				'cwd'               => $this->read_link( $this->proc_root . '/' . $pid . '/cwd' ),
			)
		);
	}

	/**
	 * Signal a listed process after re-checking it, then report whether it ended.
	 *
	 * @param int    $pid        Process id.
	 * @param string $start_time Start time from list-processes.
	 * @param string $signal     'TERM' or 'KILL' (already normalized).
	 * @return array|WP_Error
	 */
	public function kill( int $pid, string $start_time, string $signal ) {
		$reason = $this->unsupported_reason();
		if ( '' !== $reason ) {
			return new WP_Error( 'not_supported', $reason );
		}
		$live    = $this->read_process( $pid );
		$refusal = self::kill_refusal( $pid, $start_time, $live, $this->identity(), $this->can_signal() );
		if ( '' !== $refusal ) {
			return new WP_Error( $refusal, self::refusal_message( $refusal ) );
		}
		if ( ! $this->send_signal( $pid, self::SIGNALS[ $signal ] ) ) {
			return new WP_Error( 'signal_failed', __( 'The signal could not be sent (the process may have just ended, or the host refused it).', 'emcp-tools' ) );
		}
		$gone = $this->wait_until_gone( $pid, $start_time );
		return array(
			'pid'        => $pid,
			'signal'     => $signal,
			'sent'       => true,
			'gone'       => $gone,
			'name'       => (string) $live['comm'],
			'cmdline'    => (string) $live['cmdline'],
			'start_time' => $start_time,
		);
	}

	/**
	 * Poll for up to about two seconds. A zombie (state Z) has exited and only
	 * waits for its parent to collect it, so it counts as gone.
	 *
	 * @param int    $pid        Process id.
	 * @param string $start_time Start time of the signalled process.
	 */
	protected function wait_until_gone( int $pid, string $start_time ): bool {
		for ( $i = 0; $i < 10; $i++ ) {
			$stat = self::parse_stat( $this->read( $pid . '/stat' ) );
			if ( null === $stat || $stat['start_time'] !== $start_time || in_array( $stat['state'], array( 'Z', 'X', 'x' ), true ) ) {
				return true;
			}
			$this->pause( 200000 );
		}
		return false;
	}

	/** Whether posix_kill() can be called. */
	protected function can_signal(): bool {
		return function_exists( 'posix_kill' );
	}

	/**
	 * @param int $pid    Process id.
	 * @param int $signal Signal number.
	 */
	protected function send_signal( int $pid, int $signal ): bool {
		return (bool) posix_kill( $pid, $signal );
	}

	/** @param int $microseconds Delay. */
	protected function pause( int $microseconds ): void {
		usleep( $microseconds );
	}

	/**
	 * Target of a /proc symlink, or null when it cannot be read (another
	 * user's process, or a host that hides it).
	 *
	 * @param string $path Link path.
	 */
	protected function read_link( string $path ): ?string {
		$target = @readlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable links are expected.
		return false === $target ? null : (string) $target;
	}

	/** @return int[] Numeric /proc entries, ascending. */
	private function pids(): array {
		$names = @scandir( $this->proc_root ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! is_array( $names ) ) {
			return array();
		}
		$pids = array_map( 'intval', array_filter( $names, 'ctype_digit' ) );
		sort( $pids );
		return $pids;
	}

	/**
	 * Boot time and uptime, for start dates and elapsed seconds.
	 *
	 * @return array { btime: int, uptime: float }
	 */
	private function clock(): array {
		$btime = 0;
		if ( preg_match( '/^btime\s+(\d+)/m', $this->read( 'stat' ), $m ) ) {
			$btime = (int) $m[1];
		}
		$uptime = (float) strtok( $this->read( 'uptime' ), ' ' );
		return array(
			'btime'  => $btime,
			'uptime' => $uptime,
		);
	}

	/**
	 * The listed shape of one process.
	 *
	 * @param array $proc  read_process() result.
	 * @param array $self  identity().
	 * @param array $clock clock().
	 */
	private function describe( array $proc, array $self, array $clock ): array {
		$since   = (int) $proc['start_time'] / self::CLOCK_TICKS;
		$reasons = self::suspicion_reasons( $proc, $this->uploads_dir() );
		return array(
			'pid'               => $proc['pid'],
			'ppid'              => $proc['ppid'],
			'name'              => $proc['comm'],
			'state'             => $proc['state'],
			'uid'               => $proc['ruid'],
			'start_time'        => $proc['start_time'],
			'started_at'        => $clock['btime'] > 0 ? gmdate( 'Y-m-d\TH:i:s\Z', (int) ( $clock['btime'] + $since ) ) : null,
			'elapsed_seconds'   => $clock['uptime'] > 0 ? max( 0, (int) ( $clock['uptime'] - $since ) ) : null,
			'cmdline'           => $proc['cmdline'],
			'cmdline_truncated' => $proc['cmdline_truncated'],
			'exe'               => $proc['exe'],
			'cwd'               => $proc['cwd'],
			'is_self'           => $proc['pid'] === (int) $self['pid'],
			'is_parent'         => $proc['pid'] === (int) $self['ppid'],
			'suspicious'        => ! empty( $reasons ),
			'reasons'           => $reasons,
		);
	}

	/** Absolute uploads directory, from the constructor or WordPress. */
	private function uploads_dir(): string {
		if ( '' === $this->uploads_dir && function_exists( 'wp_get_upload_dir' ) ) {
			$dir               = wp_get_upload_dir();
			$this->uploads_dir = is_array( $dir ) && ! empty( $dir['basedir'] ) ? (string) $dir['basedir'] : '';
		}
		return $this->uploads_dir;
	}

	/**
	 * Read a file under the /proc root, '' when unreadable.
	 *
	 * @param string $relative Path below the root.
	 */
	private function read( string $relative ): string {
		$raw = @file_get_contents( $this->proc_root . '/' . $relative ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- /proc pseudo-files.
		return false === $raw ? '' : $raw;
	}

	/**
	 * First value a predicate accepts, or ''.
	 *
	 * @param string[] $values    Candidates.
	 * @param callable $predicate Test.
	 */
	private static function first_match( array $values, callable $predicate ): string {
		foreach ( $values as $value ) {
			if ( '' !== (string) $value && $predicate( (string) $value ) ) {
				return (string) $value;
			}
		}
		return '';
	}

	/**
	 * @param string $code   Machine code.
	 * @param string $detail Plain explanation.
	 */
	private static function reason( string $code, string $detail ): array {
		return array(
			'code'   => $code,
			'detail' => $detail,
		);
	}
}
