<?php
/**
 * Finds and searches web server access logs for the search-access-log tool.
 *
 * Logs are only read from a fixed list of directories: an optional configured
 * directory (EMCP_TOOLS_ACCESS_LOG_DIR constant, else the
 * emcp_tools_access_log_dir option), then common places next to and above
 * the site. Only regular files whose name looks like an access log are
 * listed, symlinks are skipped, and the caller can only choose among the
 * detected names, never pass a path. Plain files are read line by line,
 * .gz files through gzopen(); no shell. Every search stops at a time and byte
 * budget and says so.
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
class EMCP_Tools_Access_Log_Search {

	const CONSTANT = 'EMCP_TOOLS_ACCESS_LOG_DIR';
	const OPTION   = 'emcp_tools_access_log_dir';

	/** Most log files listed or searched in one call. */
	const MAX_FILES = 200;

	/** Bytes read per fgets/gzgets call; longer lines are cut and the rest skipped. */
	const READ_CHUNK = 16384;

	/** How often (in lines) the time budget is checked. */
	const CLOCK_EVERY = 500;

	/** @var array<string,string>|null label => directory, or null to detect. */
	private $dirs;

	/**
	 * @param array<string,string>|null $dirs Candidate directories (label => path). Null uses candidate_dirs().
	 */
	public function __construct( ?array $dirs = null ) {
		$this->dirs = $dirs;
	}

	/**
	 * The directories searched for logs, in priority order.
	 *
	 * IONOS Click&Build keeps `htdocs/logs/access.log*` two levels above a site
	 * installed in `htdocs/clickandbuilds/<name>/`, so both the parent and the
	 * grandparent of the site root are checked.
	 *
	 * @param string $abspath    Site root.
	 * @param string $home       Account home directory, or ''.
	 * @param string $configured Configured log directory, or ''.
	 * @return array<string,string> label => path.
	 */
	public static function candidate_dirs( string $abspath, string $home, string $configured ): array {
		$root = rtrim( str_replace( '\\', '/', $abspath ), '/' );
		$dirs = array();
		if ( '' !== trim( $configured ) ) {
			$dirs['configured'] = rtrim( str_replace( '\\', '/', trim( $configured ) ), '/' );
		}
		if ( '' !== $root ) {
			$parent                    = dirname( $root );
			$dirs['site-parent']       = $parent . '/logs';
			$dirs['site-grandparent']  = dirname( $parent ) . '/logs';
			$dirs['site']              = $root . '/logs';
		}
		if ( '' !== trim( $home ) ) {
			$dirs['home'] = rtrim( str_replace( '\\', '/', trim( $home ) ), '/' ) . '/logs';
		}
		$dirs['apache2'] = '/var/log/apache2';
		$dirs['httpd']   = '/var/log/httpd';
		$dirs['nginx']   = '/var/log/nginx';
		return $dirs;
	}

	/**
	 * The configured log directory from the constant, else the option.
	 *
	 * @return string
	 */
	public static function configured_dir(): string {
		if ( defined( self::CONSTANT ) && is_string( constant( self::CONSTANT ) ) ) {
			return (string) constant( self::CONSTANT );
		}
		$option = get_option( self::OPTION, '' );
		return is_string( $option ) ? $option : '';
	}

	/**
	 * @return array<string,string>
	 */
	private function dirs(): array {
		if ( null !== $this->dirs ) {
			return $this->dirs;
		}
		$home = getenv( 'HOME' );
		return self::candidate_dirs( ABSPATH, is_string( $home ) ? $home : '', self::configured_dir() );
	}

	/**
	 * Lists readable access log files in the candidate directories, newest
	 * first. Each file gets an id `<label>/<name>`, for example
	 * `site-grandparent/access.log.1.gz`.
	 *
	 * @return array{files: array<int,array>, dirs: array<int,array>}
	 */
	public function detect_files(): array {
		$files = array();
		$dirs  = array();
		$seen  = array();
		foreach ( $this->dirs() as $label => $dir ) {
			$real = @realpath( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- open_basedir can warn.
			if ( false === $real || ! @is_dir( $real ) || ! @is_readable( $real ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$key = str_replace( '\\', '/', $real );
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$entries      = @scandir( $real ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! is_array( $entries ) ) {
				continue;
			}
			$found = 0;
			foreach ( $entries as $name ) {
				if ( ! EMCP_Tools_Access_Log_Parser::is_log_name( $name ) ) {
					continue;
				}
				$path = $real . DIRECTORY_SEPARATOR . $name;
				if ( is_link( $path ) || ! is_file( $path ) || ! is_readable( $path ) ) {
					continue;
				}
				$files[] = array(
					'id'         => $label . '/' . $name,
					'name'       => $name,
					'dir_label'  => $label,
					'path'       => $path,
					'size'       => (int) @filesize( $path ), // phpcs:ignore WordPress.PHP.NoSilencedErrors
					'mtime'      => (int) @filemtime( $path ), // phpcs:ignore WordPress.PHP.NoSilencedErrors
					'compressed' => EMCP_Tools_Access_Log_Parser::is_gzip_name( $name ),
				);
				++$found;
			}
			$dirs[] = array( 'label' => $label, 'path' => $key, 'log_files' => $found );
		}
		usort(
			$files,
			static function ( $a, $b ) {
				return $b['mtime'] <=> $a['mtime'] ?: strcmp( $a['id'], $b['id'] );
			}
		);
		return array(
			'files' => array_slice( $files, 0, self::MAX_FILES ),
			'dirs'  => $dirs,
		);
	}

	/**
	 * Picks the requested files from the detected list. A request matches a
	 * detected id exactly (`site/access.log`) or a bare name (`access.log`,
	 * which picks that name in every directory). Anything else is refused, so
	 * input can never reach a path that was not detected.
	 *
	 * @param array<int,array> $detected  Output of detect_files()['files'].
	 * @param string[]         $requested Requested names; empty picks every file.
	 * @return array<int,array>|\WP_Error
	 */
	public static function select_files( array $detected, array $requested ) {
		if ( empty( $requested ) ) {
			return $detected;
		}
		$picked  = array();
		$unknown = array();
		foreach ( $requested as $want ) {
			$hit = false;
			foreach ( $detected as $file ) {
				if ( $want === $file['id'] || $want === $file['name'] ) {
					$picked[ $file['id'] ] = $file;
					$hit                   = true;
				}
			}
			if ( ! $hit ) {
				$unknown[] = $want;
			}
		}
		if ( ! empty( $unknown ) ) {
			return new \WP_Error(
				'emcp_access_log_unknown_file',
				sprintf(
					/* translators: %s: comma-separated file names. */
					__( 'Not a detected access log: %s. Call with list_files: true to see the names you can use.', 'emcp-tools' ),
					implode( ', ', array_map( array( 'EMCP_Tools_Access_Log_Parser', 'to_utf8' ), $unknown ) )
				)
			);
		}
		return array_values(
			array_filter(
				$detected,
				static function ( $file ) use ( $picked ) {
					return isset( $picked[ $file['id'] ] );
				}
			)
		);
	}

	/**
	 * Public view of a detected file (no absolute path).
	 *
	 * @param array $file Detected file.
	 * @return array
	 */
	private static function describe( array $file ): array {
		return array(
			'name'       => $file['id'],
			'dir'        => $file['dir_label'],
			'size'       => $file['size'],
			'mtime'      => gmdate( 'c', $file['mtime'] ),
			'compressed' => $file['compressed'],
		);
	}

	/**
	 * Runs the tool.
	 *
	 * @param array $input Tool input.
	 * @return array|\WP_Error
	 */
	public function run( array $input ) {
		$filters = EMCP_Tools_Access_Log_Parser::normalize_input( $input );
		if ( is_wp_error( $filters ) ) {
			return $filters;
		}

		$detected = $this->detect_files();
		if ( $filters['list_files'] ) {
			return array(
				'files'          => array_map( array( __CLASS__, 'describe' ), $detected['files'] ),
				'count'          => count( $detected['files'] ),
				'searched_dirs'  => $detected['dirs'],
				'configured_dir' => '' !== self::configured_dir(),
			);
		}
		if ( empty( $detected['files'] ) ) {
			return new \WP_Error(
				'emcp_access_log_not_found',
				__( 'No readable access log was found. Set the EMCP_TOOLS_ACCESS_LOG_DIR constant (or the emcp_tools_access_log_dir option) to the folder that holds access.log.', 'emcp-tools' )
			);
		}

		$selected = self::select_files( $detected['files'], $filters['files'] );
		if ( is_wp_error( $selected ) ) {
			return $selected;
		}

		return $this->search( $selected, $filters );
	}

	/**
	 * Searches the given files, newest first, within the budgets.
	 *
	 * @param array<int,array> $files   Selected files.
	 * @param array            $filters Output of normalize_input().
	 * @return array
	 */
	public function search( array $files, array $filters ): array {
		$state = array(
			'started'   => microtime( true ),
			'deadline'  => microtime( true ) + $filters['max_seconds'],
			'max_bytes' => $filters['max_mb'] * 1048576,
			'bytes'     => 0,
			'matches'   => array(),
			'stop'      => null,
		);
		$searched = array();
		$skipped  = array();

		foreach ( $files as $file ) {
			if ( null !== $state['stop'] ) {
				$skipped[] = array( 'name' => $file['id'], 'reason' => 'budget' );
				continue;
			}
			if ( null !== $filters['since'] && $file['mtime'] > 0 && $file['mtime'] < $filters['since'] ) {
				$skipped[] = array( 'name' => $file['id'], 'reason' => 'older_than_since' );
				continue;
			}
			$result = $this->scan_file( $file, $filters, $state );
			if ( null === $result ) {
				$skipped[] = array( 'name' => $file['id'], 'reason' => 'unreadable' );
				continue;
			}
			$searched[] = array_merge( self::describe( $file ), $result );
		}

		return array(
			'matches'          => $state['matches'],
			'count'            => count( $state['matches'] ),
			'truncated'        => null !== $state['stop'],
			'truncated_reason' => $state['stop'],
			'files_searched'   => $searched,
			'files_skipped'    => $skipped,
			'query_strings'    => $filters['include_query'] ? 'included' : 'removed',
			'scan_meta'        => array(
				'elapsed_ms'  => (int) round( ( microtime( true ) - $state['started'] ) * 1000 ),
				'bytes_read'  => $state['bytes'],
				'max_seconds' => $filters['max_seconds'],
				'max_mb'      => $filters['max_mb'],
				'limit'       => $filters['limit'],
			),
		);
	}

	/**
	 * Reads one file line by line. Thin wrapper around fopen/gzopen.
	 *
	 * @param array $file    Detected file.
	 * @param array $filters Normalised filters.
	 * @param array $state   Shared budget and match state (by reference).
	 * @return array|null Per-file stats, or null when the file cannot be opened.
	 */
	private function scan_file( array $file, array $filters, array &$state ): ?array {
		$gz     = $file['compressed'];
		$handle = $gz ? @gzopen( $file['path'], 'rb' ) : @fopen( $file['path'], 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( false === $handle ) {
			return null;
		}

		$line_no  = 0;
		$bytes    = 0;
		$complete = true;
		while ( true ) {
			$line = $this->read_line( $handle, $gz, $bytes );
			if ( null === $line ) {
				break;
			}
			++$line_no;

			$row = EMCP_Tools_Access_Log_Parser::evaluate_line( $line, $filters );
			if ( null !== $row ) {
				$state['matches'][] = array_merge(
					array(
						'file'        => $file['id'],
						'line_number' => $line_no,
					),
					$row
				);
				if ( count( $state['matches'] ) >= $filters['limit'] ) {
					$state['stop'] = 'limit';
				}
			}

			if ( null === $state['stop'] && $state['bytes'] + $bytes >= $state['max_bytes'] ) {
				$state['stop'] = 'bytes';
			}
			if ( null === $state['stop'] && 0 === $line_no % self::CLOCK_EVERY && microtime( true ) >= $state['deadline'] ) {
				$state['stop'] = 'time';
			}
			if ( null !== $state['stop'] ) {
				$complete = $this->at_end( $handle, $gz );
				break;
			}
		}

		if ( $gz ) {
			gzclose( $handle );
		} else {
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		}
		$state['bytes'] += $bytes;

		return array(
			'lines_read' => $line_no,
			'bytes_read' => $bytes,
			'complete'   => $complete,
		);
	}

	/**
	 * Reads one line, at most READ_CHUNK bytes; the rest of a longer line is
	 * read and dropped so the next call starts on a fresh line.
	 *
	 * @param resource $handle File handle.
	 * @param bool     $gz     Whether the handle is a gzip stream.
	 * @param int      $bytes  Running byte count (by reference).
	 * @return string|null Null at end of file.
	 */
	private function read_line( $handle, bool $gz, int &$bytes ): ?string {
		$line = $gz ? gzgets( $handle, self::READ_CHUNK ) : fgets( $handle, self::READ_CHUNK );
		if ( false === $line ) {
			return null;
		}
		$bytes += strlen( $line );
		$tail   = $line;
		while ( "\n" !== substr( $tail, -1 ) && ! $this->at_end( $handle, $gz ) ) {
			$tail = $gz ? gzgets( $handle, self::READ_CHUNK ) : fgets( $handle, self::READ_CHUNK );
			if ( false === $tail ) {
				break;
			}
			$bytes += strlen( $tail );
		}
		return $line;
	}

	/**
	 * @param resource $handle File handle.
	 * @param bool     $gz     Whether the handle is a gzip stream.
	 * @return bool
	 */
	private function at_end( $handle, bool $gz ): bool {
		return $gz ? gzeof( $handle ) : feof( $handle );
	}
}
