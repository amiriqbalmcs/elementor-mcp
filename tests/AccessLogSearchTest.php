<?php
/**
 * Tests for the search-access-log tool: the pure parser and filters, query
 * stripping, plain and gzip reading through temp files, budgets and the
 * file-name whitelist.
 *
 * @package EMCP_Tools
 */

use PHPUnit\Framework\TestCase;

require_once EMCP_TOOLS_DIR . 'includes/security/class-access-log-parser.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-access-log-search.php';
require_once EMCP_TOOLS_DIR . 'includes/abilities/class-access-log-abilities.php';

final class AccessLogSearchTest extends TestCase {

	const COMBINED = '203.0.113.9 - - [17/Oct/2026:10:22:01 +0200] "POST /wp-content/plugins/foo/prompts/prompts/index.php?k=SECRET123 HTTP/1.1" 200 512 "https://example.com/?ref=tok" "Mozilla/5.0 (X11)"';
	const IONOS    = '198.51.100.7 - - [17/Oct/2026:10:25:44 +0200] "GET /wp-login.php HTTP/1.1" 200 328027 example.com "-" "curl/8.1" "-"';
	const COMMON   = '192.0.2.1 - frank [10/Oct/2026:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 404 -';

	/** @var string */
	private $dir;

	protected function setUp(): void {
		emcp_test_reset();
		$this->dir = sys_get_temp_dir() . '/emcp-access-log-' . uniqid( '', true );
		mkdir( $this->dir, 0777, true );
	}

	protected function tearDown(): void {
		foreach ( (array) glob( $this->dir . '/*' ) as $file ) {
			@unlink( $file );
		}
		@rmdir( $this->dir );
	}

	private function filters( array $input ): array {
		$f = EMCP_Tools_Access_Log_Parser::normalize_input( $input );
		$this->assertIsArray( $f );
		return $f;
	}

	// ---- Parser ------------------------------------------------------------

	public function test_parses_combined_format(): void {
		$f = EMCP_Tools_Access_Log_Parser::parse_line( self::COMBINED . "\n" );
		$this->assertNotNull( $f );
		$this->assertSame( '203.0.113.9', $f['ip'] );
		$this->assertSame( 'POST', $f['method'] );
		$this->assertSame( '/wp-content/plugins/foo/prompts/prompts/index.php?k=SECRET123', $f['path'] );
		$this->assertSame( 'HTTP/1.1', $f['protocol'] );
		$this->assertSame( 200, $f['status'] );
		$this->assertSame( 512, $f['bytes'] );
		$this->assertNull( $f['host'] );
		$this->assertSame( 'https://example.com/?ref=tok', $f['referer'] );
		$this->assertSame( 'Mozilla/5.0 (X11)', $f['user_agent'] );
		$this->assertSame( gmmktime( 8, 22, 1, 10, 17, 2026 ), $f['timestamp'] );
	}

	public function test_parses_ionos_format_with_host_field(): void {
		$f = EMCP_Tools_Access_Log_Parser::parse_line( self::IONOS );
		$this->assertNotNull( $f );
		$this->assertSame( 'example.com', $f['host'] );
		$this->assertSame( 328027, $f['bytes'] );
		$this->assertNull( $f['referer'] );
		$this->assertSame( 'curl/8.1', $f['user_agent'] );
		$this->assertSame( 'GET', $f['method'] );
	}

	public function test_parses_common_format_without_referer(): void {
		$f = EMCP_Tools_Access_Log_Parser::parse_line( self::COMMON );
		$this->assertNotNull( $f );
		$this->assertSame( 'frank', $f['user'] );
		$this->assertSame( 404, $f['status'] );
		$this->assertNull( $f['bytes'] );
		$this->assertNull( $f['user_agent'] );
	}

	public function test_escaped_quote_in_request_and_bad_request_line(): void {
		$f = EMCP_Tools_Access_Log_Parser::parse_line( '1.2.3.4 - - [17/Oct/2026:10:00:00 +0000] "GET /a\"b HTTP/1.1" 400 0 "-" "x"' );
		$this->assertNotNull( $f );
		$this->assertSame( 400, $f['status'] );

		$junk = EMCP_Tools_Access_Log_Parser::parse_line( '1.2.3.4 - - [17/Oct/2026:10:00:00 +0000] "\x16\x03\x01" 400 0 "-" "-"' );
		$this->assertNotNull( $junk );
		$this->assertNull( $junk['method'] );
	}

	public function test_malformed_lines_return_null(): void {
		$this->assertNull( EMCP_Tools_Access_Log_Parser::parse_line( '' ) );
		$this->assertNull( EMCP_Tools_Access_Log_Parser::parse_line( 'PHP Warning: something broke in /x.php' ) );
		$this->assertNull( EMCP_Tools_Access_Log_Parser::parse_line( '1.2.3.4 - - [17/Oct/2026] "GET /" 200' ) );
		$this->assertNull( EMCP_Tools_Access_Log_Parser::parse_time( 'not a time' ) );
	}

	public function test_parse_bound_formats(): void {
		$want = gmmktime( 10, 0, 0, 10, 17, 2026 );
		$this->assertSame( $want, EMCP_Tools_Access_Log_Parser::parse_bound( '2026-10-17T10:00:00Z' ) );
		$this->assertSame( $want, EMCP_Tools_Access_Log_Parser::parse_bound( (string) $want ) );
		$this->assertSame( $want, EMCP_Tools_Access_Log_Parser::parse_bound( '17/Oct/2026:12:00:00 +0200' ) );
		$this->assertNull( EMCP_Tools_Access_Log_Parser::parse_bound( '???' ) );
	}

	// ---- File names --------------------------------------------------------

	public function test_log_name_whitelist(): void {
		foreach ( array( 'access.log', 'access.log.1', 'access.log.2.gz', 'access.log.2026-10-17.gz', 'ssl_access.log', 'example.com-access.log', 'access_log', 'other_vhosts_access.log' ) as $ok ) {
			$this->assertTrue( EMCP_Tools_Access_Log_Parser::is_log_name( $ok ), $ok );
		}
		foreach ( array( 'error.log', 'access.php', 'access.log.php', 'access.log.bz2', '../access.log', 'logs/access.log', '.access.log', 'debug.log', '' ) as $bad ) {
			$this->assertFalse( EMCP_Tools_Access_Log_Parser::is_log_name( $bad ), $bad );
		}
	}

	public function test_candidate_dirs_cover_ionos_layout(): void {
		$dirs = EMCP_Tools_Access_Log_Search::candidate_dirs( '/kunden/homepages/1/htdocs/clickandbuilds/site/', '/home/u1', '/srv/logs/' );
		$this->assertSame( '/srv/logs', $dirs['configured'] );
		$this->assertSame( '/kunden/homepages/1/htdocs/clickandbuilds/logs', $dirs['site-parent'] );
		$this->assertSame( '/kunden/homepages/1/htdocs/logs', $dirs['site-grandparent'] );
		$this->assertSame( '/kunden/homepages/1/htdocs/clickandbuilds/site/logs', $dirs['site'] );
		$this->assertSame( '/home/u1/logs', $dirs['home'] );
		$this->assertArrayHasKey( 'nginx', $dirs );
		$this->assertSame( 'configured', array_key_first( $dirs ) );
	}

	// ---- Filters -----------------------------------------------------------

	public function test_contains_is_required_unless_listing(): void {
		$this->assertInstanceOf( WP_Error::class, EMCP_Tools_Access_Log_Parser::normalize_input( array() ) );
		$this->assertIsArray( EMCP_Tools_Access_Log_Parser::normalize_input( array( 'list_files' => true ) ) );
	}

	public function test_bad_inputs_are_refused(): void {
		foreach ( array(
			array( 'contains' => 'x', 'method' => 'PO ST' ),
			array( 'contains' => 'x', 'status' => '700' ),
			array( 'contains' => 'x', 'since' => '???' ),
			array( 'contains' => 'x', 'files' => 'access.log' ),
			array( 'contains' => str_repeat( 'a', 501 ) ),
		) as $input ) {
			$this->assertInstanceOf( WP_Error::class, EMCP_Tools_Access_Log_Parser::normalize_input( $input ) );
		}
	}

	public function test_limits_are_clamped(): void {
		$f = $this->filters( array( 'contains' => 'x', 'limit' => 9999, 'max_seconds' => 0, 'max_mb' => 99999 ) );
		$this->assertSame( 500, $f['limit'] );
		$this->assertSame( 1, $f['max_seconds'] );
		$this->assertSame( 2048, $f['max_mb'] );
		$d = $this->filters( array( 'contains' => 'x' ) );
		$this->assertSame( 100, $d['limit'] );
		$this->assertFalse( $d['include_query'] );
	}

	public function test_field_filters(): void {
		$fields = EMCP_Tools_Access_Log_Parser::parse_line( self::COMBINED );
		$m      = function ( array $in ) use ( $fields ) {
			return EMCP_Tools_Access_Log_Parser::matches( self::COMBINED, $fields, $this->filters( array_merge( array( 'contains' => 'index.php' ), $in ) ) );
		};
		$this->assertTrue( $m( array() ) );
		$this->assertTrue( $m( array( 'contains' => 'INDEX.PHP' ) ) );
		$this->assertTrue( $m( array( 'ip' => '203.0.113.9', 'method' => 'post', 'status' => '2xx', 'path_contains' => 'prompts/prompts' ) ) );
		$this->assertTrue( $m( array( 'status' => '200' ) ) );
		$this->assertFalse( $m( array( 'ip' => '203.0.113.90' ) ) );
		$this->assertFalse( $m( array( 'method' => 'GET' ) ) );
		$this->assertFalse( $m( array( 'status' => '4xx' ) ) );
		$this->assertFalse( $m( array( 'path_contains' => 'wp-login' ) ) );
		$this->assertTrue( $m( array( 'since' => '2026-10-17T08:00:00Z', 'until' => '2026-10-17T09:00:00Z' ) ) );
		$this->assertFalse( $m( array( 'since' => '2026-10-17T08:30:00Z' ) ) );
		$this->assertFalse( $m( array( 'until' => '2026-10-17T08:00:00Z' ) ) );
	}

	public function test_unparsed_line_matches_as_raw_text(): void {
		$raw = 'weird proxy line 203.0.113.9 POST "POST /x.php" 500 something';
		$this->assertNull( EMCP_Tools_Access_Log_Parser::parse_line( $raw ) );
		$this->assertTrue( EMCP_Tools_Access_Log_Parser::matches( $raw, null, $this->filters( array( 'contains' => 'x.php', 'ip' => '203.0.113.9', 'method' => 'POST', 'status' => '5xx' ) ) ) );
		$this->assertFalse( EMCP_Tools_Access_Log_Parser::matches( $raw, null, $this->filters( array( 'contains' => 'x.php', 'since' => '2026-01-01' ) ) ) );
	}

	// ---- Query stripping and output cleanup --------------------------------

	public function test_query_strings_are_removed_by_default(): void {
		$row = EMCP_Tools_Access_Log_Parser::evaluate_line( self::COMBINED, $this->filters( array( 'contains' => 'index.php' ) ) );
		$this->assertNotNull( $row );
		$this->assertStringNotContainsString( 'SECRET123', $row['line'] );
		$this->assertStringNotContainsString( 'ref=tok', $row['line'] );
		$this->assertStringContainsString( 'index.php?[query removed]', $row['line'] );
		$this->assertSame( '/wp-content/plugins/foo/prompts/prompts/index.php?[query removed]', $row['fields']['path'] );
		$this->assertSame( 'https://example.com/?[query removed]', $row['fields']['referer'] );
		$this->assertStringNotContainsString( 'SECRET123', $row['fields']['request'] );
	}

	public function test_query_strings_kept_on_request(): void {
		$row = EMCP_Tools_Access_Log_Parser::evaluate_line( self::COMBINED, $this->filters( array( 'contains' => 'index.php', 'include_query' => true ) ) );
		$this->assertStringContainsString( 'SECRET123', $row['line'] );
		$this->assertStringContainsString( 'k=SECRET123', $row['fields']['path'] );
	}

	public function test_long_and_binary_lines_are_capped_and_valid_utf8(): void {
		$line = '1.2.3.4 - - [17/Oct/2026:10:00:00 +0000] "GET /' . str_repeat( 'a', 3000 ) . " HTTP/1.1\" 200 1 \"-\" \"\xff\xfe\"";
		$row  = EMCP_Tools_Access_Log_Parser::evaluate_line( $line, $this->filters( array( 'contains' => 'aaa' ) ) );
		$this->assertTrue( $row['line_truncated'] );
		$this->assertLessThanOrEqual( EMCP_Tools_Access_Log_Parser::MAX_LINE_BYTES, strlen( $row['line'] ) );
		$this->assertNotFalse( json_encode( $row ) );
	}

	// ---- Files: detection, whitelist, plain and gzip reading ---------------

	private function write_logs(): EMCP_Tools_Access_Log_Search {
		file_put_contents( $this->dir . '/access.log', self::COMBINED . "\n" . self::IONOS . "\nnot a log line index.php\n" );
		$gz = gzopen( $this->dir . '/access.log.2.gz', 'wb' );
		gzwrite( $gz, self::IONOS . "\n" . str_replace( '10:22:01', '09:01:00', self::COMBINED ) . "\n" );
		gzclose( $gz );
		file_put_contents( $this->dir . '/error.log', "index.php fatal\n" );
		file_put_contents( $this->dir . '/notes.txt', "index.php\n" );
		touch( $this->dir . '/access.log.2.gz', time() - 3600 );
		return new EMCP_Tools_Access_Log_Search( array( 'site-grandparent' => $this->dir, 'missing' => $this->dir . '/nope' ) );
	}

	public function test_list_files_returns_only_access_logs(): void {
		$out = $this->write_logs()->run( array( 'list_files' => true ) );
		$this->assertSame( 2, $out['count'] );
		$names = array_column( $out['files'], 'name' );
		$this->assertSame( array( 'site-grandparent/access.log', 'site-grandparent/access.log.2.gz' ), $names );
		$this->assertTrue( $out['files'][1]['compressed'] );
		$this->assertGreaterThan( 0, $out['files'][0]['size'] );
		$this->assertArrayNotHasKey( 'path', $out['files'][0] );
	}

	public function test_search_reads_plain_and_gzip_files(): void {
		$out = $this->write_logs()->run( array( 'contains' => 'index.php' ) );
		$this->assertSame( 3, $out['count'] );
		$this->assertFalse( $out['truncated'] );
		$this->assertSame( 'site-grandparent/access.log', $out['matches'][0]['file'] );
		$this->assertSame( 1, $out['matches'][0]['line_number'] );
		$this->assertNull( $out['matches'][1]['fields'] );
		$gz = array_values( array_filter( $out['matches'], static function ( $m ) {
			return 'site-grandparent/access.log.2.gz' === $m['file'];
		} ) );
		$this->assertCount( 1, $gz );
		$this->assertSame( 2, $gz[0]['line_number'] );
		$this->assertStringNotContainsString( 'SECRET123', wp_json_encode_test( $out ) );
		$this->assertSame( 'removed', $out['query_strings'] );
	}

	public function test_files_subset_by_id_or_bare_name(): void {
		$search = $this->write_logs();
		$out    = $search->run( array( 'contains' => 'index.php', 'files' => array( 'access.log.2.gz' ) ) );
		$this->assertSame( 1, $out['count'] );
		$out = $search->run( array( 'contains' => 'index.php', 'files' => array( 'site-grandparent/access.log' ) ) );
		$this->assertSame( 2, $out['count'] );
	}

	public function test_file_names_outside_the_detected_list_are_refused(): void {
		$search = $this->write_logs();
		foreach ( array( 'error.log', '../../wp-config.php', $this->dir . '/access.log', '/etc/passwd', 'notes.txt' ) as $bad ) {
			$out = $search->run( array( 'contains' => 'x', 'files' => array( $bad ) ) );
			$this->assertInstanceOf( WP_Error::class, $out, $bad );
			$this->assertSame( 'emcp_access_log_unknown_file', $out->get_error_code() );
		}
	}

	public function test_limit_truncates_and_reports(): void {
		$out = $this->write_logs()->run( array( 'contains' => 'index.php', 'limit' => 2 ) );
		$this->assertSame( 2, $out['count'] );
		$this->assertTrue( $out['truncated'] );
		$this->assertSame( 'limit', $out['truncated_reason'] );
		$this->assertSame( 'budget', $out['files_skipped'][0]['reason'] );
	}

	public function test_byte_budget_stops_the_scan(): void {
		$line = str_replace( 'SECRET123', str_repeat( 'b', 900 ), self::COMBINED ) . "\n";
		file_put_contents( $this->dir . '/access.log', str_repeat( $line, 1500 ) );
		$search = new EMCP_Tools_Access_Log_Search( array( 'site' => $this->dir ) );
		$out    = $search->run( array( 'contains' => 'zzz-no-match', 'max_mb' => 1 ) );
		$this->assertTrue( $out['truncated'] );
		$this->assertSame( 'bytes', $out['truncated_reason'] );
		$this->assertFalse( $out['files_searched'][0]['complete'] );
		$this->assertLessThan( 1500, $out['files_searched'][0]['lines_read'] );
	}

	public function test_since_skips_files_last_written_before_it(): void {
		$search = $this->write_logs();
		$out    = $search->run( array( 'contains' => 'index.php', 'since' => (string) ( time() - 600 ) ) );
		$this->assertSame( 'older_than_since', $out['files_skipped'][0]['reason'] );
	}

	public function test_no_logs_found_is_an_error(): void {
		$search = new EMCP_Tools_Access_Log_Search( array( 'site' => $this->dir . '/nope' ) );
		$out    = $search->run( array( 'contains' => 'x' ) );
		$this->assertInstanceOf( WP_Error::class, $out );
		$this->assertSame( 'emcp_access_log_not_found', $out->get_error_code() );
	}

	// ---- Ability registration ----------------------------------------------

	public function test_ability_is_read_only_and_admin_only(): void {
		$abilities = new EMCP_Tools_Access_Log_Abilities( $this->write_logs() );
		$abilities->register();
		$this->assertSame( array( 'emcp-tools/search-access-log' ), $abilities->get_ability_names() );
		$args = $GLOBALS['emcp_test']['abilities']['emcp-tools/search-access-log'];
		$this->assertTrue( $args['meta']['annotations']['readonly'] );
		$this->assertFalse( $args['meta']['annotations']['destructive'] );
		$this->assertTrue( $abilities->check_permission() );
		$GLOBALS['emcp_test']['caps'] = array( 'edit_posts' );
		$this->assertFalse( $abilities->check_permission() );
		$this->assertSame( 3, $abilities->execute_search_access_log( array( 'contains' => 'index.php' ) )['count'] );
	}
}

/**
 * JSON-encodes a result for leak checks.
 *
 * @param mixed $data Data.
 * @return string
 */
function wp_json_encode_test( $data ): string {
	return (string) json_encode( $data );
}
