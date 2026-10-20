<?php
/**
 * Tests for list-processes / kill-process: /proc parsing, suspicion rules,
 * kill refusal rules, and the listing and kill wrappers run against fake /proc
 * trees built in temp directories (no symlinks needed; exe/cwd links come
 * from a test double).
 *
 * @package EMCP_Tools
 */

use PHPUnit\Framework\TestCase;

require_once EMCP_TOOLS_DIR . 'includes/security/class-security-process-inspector.php';
require_once EMCP_TOOLS_DIR . 'includes/abilities/class-process-abilities.php';

/**
 * Inspector double: links from an array, signals recorded, no sleeping.
 */
class EMCP_Test_Process_Inspector extends EMCP_Tools_Security_Process_Inspector {

	/** @var array path => target */
	public $links = array();

	/** @var array[] [pid, signal] pairs sent */
	public $signals = array();

	/** @var bool */
	public $can = true;

	/** @var bool Whether a signalled process disappears from the tree. */
	public $dies = true;

	/** @var string */
	public $root;

	public function __construct( string $root, array $identity ) {
		parent::__construct( $root, 'Linux', $identity, '/var/www/site/wp-content/uploads' );
		$this->root = $root;
	}

	protected function read_link( string $path ): ?string {
		return $this->links[ $path ] ?? null;
	}

	protected function can_signal(): bool {
		return $this->can;
	}

	protected function send_signal( int $pid, int $signal ): bool {
		$this->signals[] = array( $pid, $signal );
		if ( $this->dies ) {
			foreach ( array( 'stat', 'status', 'cmdline' ) as $f ) {
				@unlink( $this->root . '/' . $pid . '/' . $f );
			}
			@rmdir( $this->root . '/' . $pid );
		}
		return true;
	}

	protected function pause( int $microseconds ): void {
	}
}

final class ProcessToolsTest extends TestCase {

	const UID   = 1001;
	const BTIME = 1792000000;

	/** @var string[] */
	private $dirs = array();

	protected function tearDown(): void {
		foreach ( $this->dirs as $dir ) {
			$this->rmtree( $dir );
		}
		$this->dirs = array();
	}

	// ---- Fake /proc helpers ------------------------------------------------

	private static function stat_line( int $pid, string $comm, string $state, int $ppid, string $start ): string {
		// Fields after ")" : state ppid then 17 fillers, then starttime (field 22).
		return $pid . ' (' . $comm . ') ' . $state . ' ' . $ppid . ' ' . implode( ' ', array_fill( 0, 17, '0' ) ) . ' ' . $start . " 1000 200\n";
	}

	/**
	 * @param array[] $procs Each { pid, ppid, comm, uid, start, argv, state? }.
	 */
	private function tree( array $procs ): string {
		$root = sys_get_temp_dir() . '/emcp-proc-' . bin2hex( random_bytes( 4 ) );
		mkdir( $root );
		$this->dirs[] = $root;
		file_put_contents( $root . '/stat', "cpu 1 2 3\nbtime " . self::BTIME . "\nprocesses 99\n" );
		file_put_contents( $root . '/uptime', "50000.00 90000.00\n" );
		mkdir( $root . '/net' );
		foreach ( $procs as $p ) {
			$dir = $root . '/' . $p['pid'];
			mkdir( $dir );
			file_put_contents( $dir . '/stat', self::stat_line( $p['pid'], $p['comm'], $p['state'] ?? 'S', $p['ppid'], (string) $p['start'] ) );
			file_put_contents( $dir . '/status', "Name:\t{$p['comm']}\nState:\tS (sleeping)\nUid:\t{$p['uid']}\t{$p['uid']}\t{$p['uid']}\t{$p['uid']}\n" );
			file_put_contents( $dir . '/cmdline', implode( "\0", $p['argv'] ) . "\0" );
		}
		return $root;
	}

	private function rmtree( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		foreach ( scandir( $dir ) as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$path = $dir . '/' . $name;
			is_dir( $path ) ? $this->rmtree( $path ) : unlink( $path );
		}
		rmdir( $dir );
	}

	private static function watcher_script(): string {
		return '/tmp/.wp-cache-' . 'watch.4242';
	}

	/** A typical shared-host tree: FPM master, this worker, a watcher, someone else's process. */
	private function site_tree(): array {
		$root = $this->tree(
			array(
				array( 'pid' => 1, 'ppid' => 0, 'comm' => 'systemd', 'uid' => 0, 'start' => '1', 'argv' => array( '/sbin/init' ) ),
				array( 'pid' => 400, 'ppid' => 1, 'comm' => 'php-fpm8.3', 'uid' => self::UID, 'start' => '5000', 'argv' => array( 'php-fpm: pool site' ) ),
				array( 'pid' => 401, 'ppid' => 400, 'comm' => 'php-fpm8.3', 'uid' => self::UID, 'start' => '5100', 'argv' => array( 'php-fpm: pool site' ) ),
				array( 'pid' => 4242, 'ppid' => 1, 'comm' => 'sh', 'uid' => self::UID, 'start' => '900000', 'argv' => array( 'sh', self::watcher_script() ) ),
				array( 'pid' => 777, 'ppid' => 1, 'comm' => 'sshd', 'uid' => 0, 'start' => '300', 'argv' => array( '/usr/sbin/sshd', '-D' ) ),
				array( 'pid' => 900, 'ppid' => 1, 'comm' => 'bash', 'uid' => 2002, 'start' => '7000', 'argv' => array( 'bash', '/tmp/other-user.sh' ) ),
			)
		);
		$inspector = new EMCP_Test_Process_Inspector(
			$root,
			array(
				'uid'  => self::UID,
				'pid'  => 401,
				'ppid' => 400,
			)
		);
		$inspector->links[ $root . '/4242/exe' ] = '/usr/bin/dash';
		$inspector->links[ $root . '/4242/cwd' ] = '/tmp';
		return array( $root, $inspector );
	}

	// ---- Parsing -----------------------------------------------------------

	public function test_parse_stat_handles_spaces_and_parens_in_name(): void {
		$s = EMCP_Tools_Security_Process_Inspector::parse_stat( self::stat_line( 55, 'odd ) name', 'R', 7, '123456' ) );
		$this->assertSame( 55, $s['pid'] );
		$this->assertSame( 'odd ) name', $s['comm'] );
		$this->assertSame( 'R', $s['state'] );
		$this->assertSame( 7, $s['ppid'] );
		$this->assertSame( '123456', $s['start_time'] );
	}

	public function test_parse_stat_rejects_garbage(): void {
		$this->assertNull( EMCP_Tools_Security_Process_Inspector::parse_stat( '' ) );
		$this->assertNull( EMCP_Tools_Security_Process_Inspector::parse_stat( '12 (x) S 1 2' ) );
		$this->assertNull( EMCP_Tools_Security_Process_Inspector::parse_stat( 'abc (x) ' . str_repeat( '0 ', 25 ) ) );
	}

	public function test_parse_status_reads_real_and_effective_uid(): void {
		$s = EMCP_Tools_Security_Process_Inspector::parse_status( "Name:\tsh\nUmask:\t0022\nUid:\t1001\t0\t1001\t1001\nGid:\t1\t1\t1\t1\n" );
		$this->assertSame( 'sh', $s['name'] );
		$this->assertSame( 1001, $s['ruid'] );
		$this->assertSame( 0, $s['euid'] );
		$this->assertSame( -1, EMCP_Tools_Security_Process_Inspector::parse_status( 'Name: x' )['ruid'] );
	}

	public function test_parse_cmdline_joins_nul_and_caps_length(): void {
		$c = EMCP_Tools_Security_Process_Inspector::parse_cmdline( "sh\0-c\0echo hi\0" );
		$this->assertSame( array( 'sh', '-c', 'echo hi' ), $c['argv'] );
		$this->assertSame( 'sh -c echo hi', $c['text'] );
		$this->assertFalse( $c['truncated'] );

		$long = EMCP_Tools_Security_Process_Inspector::parse_cmdline( 'php' . "\0" . str_repeat( 'a', 900 ), 64 );
		$this->assertSame( 64, strlen( $long['text'] ) );
		$this->assertTrue( $long['truncated'] );
	}

	public function test_redact_masks_credentials(): void {
		$r = function ( array $argv ) {
			return EMCP_Tools_Security_Process_Inspector::redact( $argv );
		};
		$this->assertSame( 'mysqldump -uwp -p*** db', $r( array( 'mysqldump', '-uwp', '-phunter2', 'db' ) ) );
		$this->assertSame( 'wp --password *** x', $r( array( 'wp', '--password', 'hunter2', 'x' ) ) );
		$this->assertSame( 'run DB_PASSWORD=*** API_KEY=***', $r( array( 'run', 'DB_PASSWORD=hunter2', 'API_KEY=abc123' ) ) );
		$this->assertSame( 'curl https://user:***@example.com/x', $r( array( 'curl', 'https://user:hunter2@example.com/x' ) ) );
		$this->assertSame( 'grep -p pattern', $r( array( 'grep', '-p', 'pattern' ) ) );
	}

	// ---- Suspicion rules ---------------------------------------------------

	private static function codes( array $proc ): array {
		return array_column( EMCP_Tools_Security_Process_Inspector::suspicion_reasons( $proc, '/var/www/site/wp-content/uploads' ), 'code' );
	}

	public function test_incident_watcher_is_flagged_three_ways(): void {
		$codes = self::codes( array( 'argv' => array( 'sh', self::watcher_script() ), 'exe' => '/usr/bin/dash', 'cwd' => '/tmp' ) );
		$this->assertContains( 'temp_dir', $codes );
		$this->assertContains( 'hidden_name', $codes );
		$this->assertContains( 'shell_loop', $codes );
	}

	public function test_ordinary_processes_are_not_flagged(): void {
		$this->assertSame( array(), self::codes( array( 'argv' => array( 'php-fpm: pool site' ), 'exe' => '/usr/sbin/php-fpm8.3', 'cwd' => '/' ) ) );
		$this->assertSame( array(), self::codes( array( 'argv' => array( '/usr/bin/php', '/var/www/site/wp-cron.php' ), 'exe' => '/usr/bin/php8.3', 'cwd' => '/var/www/site' ) ) );
		$this->assertSame( array(), self::codes( array( 'argv' => array( 'bash', '-c', 'cd /var/www/site && wp cron event run --due-now' ), 'exe' => null, 'cwd' => null ) ) );
		$this->assertSame( array(), self::codes( array( 'argv' => array( '/usr/bin/php', '/home/u/./site/../site/x.php' ) ) ) );
	}

	public function test_temp_dirs_and_temp_cwd(): void {
		$this->assertContains( 'temp_dir', self::codes( array( 'argv' => array( '/dev/shm/x' ) ) ) );
		$this->assertContains( 'temp_dir', self::codes( array( 'argv' => array( 'y' ), 'exe' => '/var/tmp/y' ) ) );
		$this->assertSame( array( 'temp_cwd' ), self::codes( array( 'argv' => array( '/usr/bin/sleep', '100' ), 'cwd' => '/tmp' ) ) );
	}

	public function test_deleted_exe(): void {
		$this->assertContains( 'deleted_exe', self::codes( array( 'argv' => array( 'httpd' ), 'exe' => '/usr/local/bin/httpd (deleted)' ) ) );
	}

	public function test_shell_loops(): void {
		$this->assertContains( 'shell_loop', self::codes( array( 'argv' => array( '/bin/bash', '-c', 'while true; do cp /x /y; done' ) ) ) );
		$this->assertContains( 'shell_loop', self::codes( array( 'argv' => array( 'sh', '-c', 'while :; do x; done' ) ) ) );
		$this->assertContains( 'shell_loop', self::codes( array( 'argv' => array( 'sh', '-c', 'for i in $(seq 100); do x; sleep 30; done' ) ) ) );
		$this->assertNotContains( 'shell_loop', self::codes( array( 'argv' => array( 'php', '-r', 'while true' ) ) ) );
	}

	public function test_fake_kernel_thread_name(): void {
		$this->assertContains( 'fake_kernel_thread', self::codes( array( 'argv' => array( '[kworker/0:1]' ) ) ) );
		$this->assertNotContains( 'fake_kernel_thread', self::codes( array( 'argv' => array( '[x]', 'arg' ) ) ) );
	}

	public function test_php_running_from_uploads(): void {
		$this->assertContains( 'php_in_uploads', self::codes( array( 'argv' => array( 'php8.2', '/var/www/site/wp-content/uploads/2026/05/x.php' ) ) ) );
		$this->assertContains( 'php_in_uploads', self::codes( array( 'argv' => array( '/usr/bin/php', '-f', '/var/www/site/wp-content/uploads/cache.php' ) ) ) );
		$this->assertNotContains( 'php_in_uploads', self::codes( array( 'argv' => array( 'cat', '/var/www/site/wp-content/uploads/x.php' ) ) ) );
	}

	// ---- Refusal rules -----------------------------------------------------

	private static function live( string $start = '900000', int $uid = self::UID ): array {
		return array(
			'pid'        => 4242,
			'ruid'       => $uid,
			'euid'       => $uid,
			'start_time' => $start,
		);
	}

	private static function refusal( int $pid, string $start, ?array $live, bool $posix = true ): string {
		return EMCP_Tools_Security_Process_Inspector::kill_refusal(
			$pid,
			$start,
			$live,
			array(
				'uid'  => self::UID,
				'pid'  => 401,
				'ppid' => 400,
			),
			$posix
		);
	}

	public function test_refusals(): void {
		$this->assertSame( '', self::refusal( 4242, '900000', self::live() ) );
		$this->assertSame( 'posix_unavailable', self::refusal( 4242, '900000', self::live(), false ) );
		$this->assertSame( 'invalid_pid', self::refusal( 0, '900000', self::live() ) );
		$this->assertSame( 'pid_one', self::refusal( 1, '1', self::live() ) );
		$this->assertSame( 'self_process', self::refusal( 401, '5100', self::live() ) );
		$this->assertSame( 'parent_process', self::refusal( 400, '5000', self::live() ) );
		$this->assertSame( 'start_time_required', self::refusal( 4242, '', self::live() ) );
		$this->assertSame( 'not_found', self::refusal( 4242, '900000', null ) );
		$this->assertSame( 'not_owned', self::refusal( 4242, '900000', self::live( '900000', 2002 ) ) );
		$this->assertSame( 'start_time_mismatch', self::refusal( 4242, '899999', self::live() ) );
	}

	public function test_server_and_database_processes_are_never_signalled(): void {
		// On shared hosting the same user also owns sibling sites' PHP workers and services.
		foreach ( array( 'php-fpm8.2', 'php-fpm: pool www', 'lsphp', 'php-cgi', 'httpd', 'apache2', 'nginx', 'litespeed', 'mysqld', 'mariadbd', 'redis-server', 'memcached' ) as $comm ) {
			$this->assertSame( 'server_process', self::refusal( 4242, '900000', array( 'comm' => $comm ) + self::live() ), $comm );
		}
		foreach ( array( 'sh', 'bash', 'php', 'perl', 'python3', '.wp-cache-watc' ) as $comm ) {
			$this->assertSame( '', self::refusal( 4242, '900000', array( 'comm' => $comm ) + self::live() ), $comm );
		}
		$this->assertNotSame( '', EMCP_Tools_Security_Process_Inspector::refusal_message( 'server_process' ) );
	}

	public function test_a_setuid_style_process_is_not_owned(): void {
		$this->assertFalse( EMCP_Tools_Security_Process_Inspector::is_owned( array( 'ruid' => self::UID, 'euid' => 0 ), self::UID ) );
		$this->assertFalse( EMCP_Tools_Security_Process_Inspector::is_owned( array( 'ruid' => -1, 'euid' => -1 ), -1 ) );
	}

	public function test_signal_normalization(): void {
		$this->assertSame( 'TERM', EMCP_Tools_Security_Process_Inspector::normalize_signal( null ) );
		$this->assertSame( 'TERM', EMCP_Tools_Security_Process_Inspector::normalize_signal( 'sigterm' ) );
		$this->assertSame( 'KILL', EMCP_Tools_Security_Process_Inspector::normalize_signal( 'KILL' ) );
		$this->assertNull( EMCP_Tools_Security_Process_Inspector::normalize_signal( 'HUP' ) );
		$this->assertNull( EMCP_Tools_Security_Process_Inspector::normalize_signal( 9 ) );
	}

	// ---- Listing against a fake /proc --------------------------------------

	public function test_listing_shows_only_own_processes_with_flags(): void {
		list( , $inspector ) = $this->site_tree();
		$out = $inspector->list_processes();

		$this->assertTrue( $out['supported'] );
		$this->assertSame( array( 4242, 400, 401 ), array_column( $out['processes'], 'pid' ) );
		$this->assertSame( 1, $out['suspicious_count'] );

		$watcher = $out['processes'][0];
		$this->assertTrue( $watcher['suspicious'] );
		$this->assertSame( 'sh ' . self::watcher_script(), $watcher['cmdline'] );
		$this->assertSame( '/usr/bin/dash', $watcher['exe'] );
		$this->assertSame( '900000', $watcher['start_time'] );
		$this->assertSame( gmdate( 'Y-m-d\TH:i:s\Z', self::BTIME + 9000 ), $watcher['started_at'] );
		$this->assertSame( 41000, $watcher['elapsed_seconds'] );

		$by_pid = array_column( $out['processes'], null, 'pid' );
		$this->assertTrue( $by_pid[401]['is_self'] );
		$this->assertTrue( $by_pid[400]['is_parent'] );
		$this->assertFalse( $by_pid[400]['suspicious'] );
		$this->assertNull( $by_pid[400]['exe'] );
	}

	public function test_non_linux_and_unreadable_proc_are_reported_not_fatal(): void {
		$win = new EMCP_Tools_Security_Process_Inspector( '/proc', 'Windows', array( 'uid' => 1, 'pid' => 2, 'ppid' => 3 ) );
		$out = $win->list_processes();
		$this->assertFalse( $out['supported'] );
		$this->assertStringContainsString( 'Linux', $out['reason'] );

		$missing = new EMCP_Tools_Security_Process_Inspector( sys_get_temp_dir() . '/emcp-no-proc-here', 'Linux', array( 'uid' => 1, 'pid' => 2, 'ppid' => 3 ) );
		$this->assertFalse( $missing->list_processes()['supported'] );
		$this->assertSame( 'not_supported', $missing->kill( 5, '1', 'TERM' )->get_error_code() );
	}

	public function test_ability_filters_suspicious_only(): void {
		list( , $inspector ) = $this->site_tree();
		$tools = new EMCP_Tools_Process_Abilities( $inspector );
		$out   = $tools->execute_list_processes( array( 'suspicious_only' => true ) );
		$this->assertSame( 1, $out['count'] );
		$this->assertSame( 4242, $out['processes'][0]['pid'] );
	}

	// ---- Kill against a fake /proc -----------------------------------------

	public function test_kill_rereads_proc_and_reports_gone(): void {
		list( , $inspector ) = $this->site_tree();
		$out = $inspector->kill( 4242, '900000', 'TERM' );
		$this->assertIsArray( $out );
		$this->assertTrue( $out['gone'] );
		$this->assertSame( array( array( 4242, 15 ) ), $inspector->signals );
	}

	public function test_kill_reports_a_process_that_survives(): void {
		list( , $inspector ) = $this->site_tree();
		$inspector->dies = false;
		$out = $inspector->kill( 4242, '900000', 'KILL' );
		$this->assertFalse( $out['gone'] );
		$this->assertSame( array( array( 4242, 9 ) ), $inspector->signals );
	}

	public function test_kill_refuses_reused_pid_and_other_users(): void {
		list( , $inspector ) = $this->site_tree();
		$this->assertSame( 'start_time_mismatch', $inspector->kill( 4242, '123', 'TERM' )->get_error_code() );
		$this->assertSame( 'not_owned', $inspector->kill( 900, '7000', 'TERM' )->get_error_code() );
		$this->assertSame( 'pid_one', $inspector->kill( 1, '1', 'TERM' )->get_error_code() );
		$this->assertSame( 'parent_process', $inspector->kill( 400, '5000', 'TERM' )->get_error_code() );
		$this->assertSame( 'not_found', $inspector->kill( 31337, '1', 'TERM' )->get_error_code() );
		$inspector->can = false;
		$this->assertSame( 'posix_unavailable', $inspector->kill( 4242, '900000', 'TERM' )->get_error_code() );
		$this->assertSame( array(), $inspector->signals );
	}

	public function test_kill_ability_requires_confirm_and_valid_signal(): void {
		list( , $inspector ) = $this->site_tree();
		$tools = new EMCP_Tools_Process_Abilities( $inspector );
		$this->assertSame( 'confirm_required', $tools->execute_kill_process( array( 'pid' => 4242, 'start_time' => '900000' ) )->get_error_code() );
		$this->assertSame( 'confirm_required', $tools->execute_kill_process( array( 'pid' => 4242, 'start_time' => '900000', 'confirm' => 'yes' ) )->get_error_code() );
		$this->assertSame( 'invalid_signal', $tools->execute_kill_process( array( 'pid' => 4242, 'start_time' => '900000', 'signal' => 'HUP', 'confirm' => true ) )->get_error_code() );
		$this->assertSame( 'invalid_pid', $tools->execute_kill_process( array( 'pid' => '12; rm', 'start_time' => '900000', 'confirm' => true ) )->get_error_code() );
		$this->assertSame( array(), $inspector->signals );

		$out = $tools->execute_kill_process( array( 'pid' => 4242, 'start_time' => 900000, 'confirm' => true ) );
		$this->assertTrue( $out['gone'] );
		$this->assertFalse( $out['undoable'] );
	}

	public function test_kill_is_recorded_as_irreversible_history(): void {
		$process = proc_open(
			array( PHP_BINARY, __DIR__ . '/fixtures/process-kill-history.php' ),
			array( 0 => array( 'pipe', 'r' ), 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ),
			$pipes
		);
		$this->assertIsResource( $process );
		fclose( $pipes[0] );
		$output = stream_get_contents( $pipes[1] );
		$error  = stream_get_contents( $pipes[2] );
		fclose( $pipes[1] );
		fclose( $pipes[2] );
		$this->assertSame( 0, proc_close( $process ), $output . $error );
		$this->assertSame( "PASS\n", $output, $error );
	}

	public function test_registration_and_annotations(): void {
		emcp_test_reset();
		$tools = new EMCP_Tools_Process_Abilities( new EMCP_Tools_Security_Process_Inspector( '/proc', 'Windows' ) );
		$tools->register();
		$this->assertSame( array( 'emcp-tools/list-processes', 'emcp-tools/kill-process' ), $tools->get_ability_names() );
		$kill = $GLOBALS['emcp_test']['abilities']['emcp-tools/kill-process'];
		$this->assertTrue( $kill['meta']['annotations']['destructive'] );
		$this->assertStringContainsString( 'cannot be undone', $kill['description'] );
		$this->assertTrue( $GLOBALS['emcp_test']['abilities']['emcp-tools/list-processes']['meta']['annotations']['readonly'] );
	}
}
