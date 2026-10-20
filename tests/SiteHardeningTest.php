<?php
/**
 * Tests for harden-site: toggle parsing and validation, the option merge, each
 * hook decision as a pure function, the live-status interpreters, and the
 * ability's option write.
 *
 * Self-contained: requires the security classes directly; the change ledger is
 * not loaded, so the ability skips recording (covered by the option rollback type).
 *
 * @package EMCP_Tools
 */

use PHPUnit\Framework\TestCase;

require_once EMCP_TOOLS_DIR . 'includes/security/class-security-finding.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-malware-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-integrity-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-hardening-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-software-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-scanner.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-site-hardening.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-hardening-status.php';
require_once EMCP_TOOLS_DIR . 'includes/abilities/class-security-abilities.php';

if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( $name ): bool {
		unset( $GLOBALS['emcp_test']['options'][ $name ] );
		return true;
	}
}

final class SiteHardeningTest extends TestCase {

	protected function setUp(): void {
		emcp_test_reset();
	}

	// ---- parse_toggles -----------------------------------------------------

	public function test_parse_accepts_known_boolean_toggles(): void {
		$out = EMCP_Tools_Site_Hardening::parse_toggles( array( 'disable_xmlrpc' => true, 'hide_php_errors' => false ) );
		$this->assertSame( array( 'disable_xmlrpc' => true, 'hide_php_errors' => false ), $out );
	}

	public function test_parse_rejects_empty_and_non_array(): void {
		$this->assertSame( 'invalid_toggles', EMCP_Tools_Site_Hardening::parse_toggles( array() )->get_error_code() );
		$this->assertSame( 'invalid_toggles', EMCP_Tools_Site_Hardening::parse_toggles( 'disable_xmlrpc' )->get_error_code() );
		$this->assertSame( 'invalid_toggles', EMCP_Tools_Site_Hardening::parse_toggles( null )->get_error_code() );
	}

	public function test_parse_rejects_unknown_toggle(): void {
		$e = EMCP_Tools_Site_Hardening::parse_toggles( array( 'disable_xmlrpc' => true, 'nope' => true ) );
		$this->assertSame( 'unknown_toggle', $e->get_error_code() );
		$this->assertStringContainsString( 'block_user_enumeration', $e->get_error_message() );
	}

	public function test_parse_explains_block_readme(): void {
		$e = EMCP_Tools_Site_Hardening::parse_toggles( array( 'block_readme' => true ) );
		$this->assertSame( 'unsupported_toggle', $e->get_error_code() );
		$this->assertStringContainsString( 'static files', $e->get_error_message() );
	}

	public function test_parse_rejects_non_boolean_values(): void {
		foreach ( array( 1, 'true', 'yes', null, array() ) as $value ) {
			$e = EMCP_Tools_Site_Hardening::parse_toggles( array( 'hide_wp_version' => $value ) );
			$this->assertSame( 'invalid_value', $e->get_error_code() );
		}
	}

	// ---- normalize / merge / state_map ------------------------------------

	public function test_normalize_keeps_only_known_strict_true(): void {
		$this->assertSame( array(), EMCP_Tools_Site_Hardening::normalize( 'garbage' ) );
		$this->assertSame(
			array( 'disable_xmlrpc' => true, 'hide_php_errors' => true ),
			EMCP_Tools_Site_Hardening::normalize( array( 'hide_php_errors' => true, 'x' => true, 'hide_wp_version' => 1, 'disable_xmlrpc' => true ) )
		);
	}

	public function test_merge_turns_on_and_off_and_keeps_others(): void {
		$current = array( 'disable_xmlrpc' => true, 'hide_wp_version' => true );
		$next    = EMCP_Tools_Site_Hardening::merge( $current, array( 'hide_wp_version' => false, 'block_user_enumeration' => true ) );
		$this->assertSame( array( 'disable_xmlrpc' => true, 'block_user_enumeration' => true ), $next );
	}

	public function test_merge_all_off_is_empty(): void {
		$this->assertSame( array(), EMCP_Tools_Site_Hardening::merge( array( 'disable_xmlrpc' => true ), array( 'disable_xmlrpc' => false ) ) );
	}

	public function test_state_map_lists_every_toggle(): void {
		$map = EMCP_Tools_Site_Hardening::state_map( array( 'hide_php_errors' => true ) );
		$this->assertSame( EMCP_Tools_Site_Hardening::TOGGLES, array_keys( $map ) );
		$this->assertTrue( $map['hide_php_errors'] );
		$this->assertFalse( $map['disable_xmlrpc'] );
	}

	// ---- Hook decisions ----------------------------------------------------

	public function test_cli_and_cron_are_exempt(): void {
		$this->assertTrue( EMCP_Tools_Site_Hardening::is_exempt_context( true, false ) );
		$this->assertTrue( EMCP_Tools_Site_Hardening::is_exempt_context( false, true ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::is_exempt_context( false, false ) );
	}

	public function test_should_block_xmlrpc(): void {
		$this->assertTrue( EMCP_Tools_Site_Hardening::should_block_xmlrpc( true, true ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_block_xmlrpc( true, false ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_block_xmlrpc( false, true ) );
	}

	public function test_strip_pingback_header_any_case(): void {
		$out = EMCP_Tools_Site_Hardening::strip_pingback_header( array( 'X-Pingback' => 'x', 'x-pingback' => 'y', 'Content-Type' => 'text/html' ) );
		$this->assertSame( array( 'Content-Type' => 'text/html' ), $out );
	}

	public function test_strip_pingback_methods(): void {
		$out = EMCP_Tools_Site_Hardening::strip_pingback_methods( array( 'pingback.ping' => 1, 'pingback.extensions.getPingbacks' => 2, 'wp.getPosts' => 3 ) );
		$this->assertSame( array( 'wp.getPosts' => 3 ), $out );
	}

	public function test_strip_core_version_only_when_it_matches(): void {
		$v = '6.9.1';
		// The version is swapped for a per-site token, not removed, so a core update still busts caches.
		$t = 'a1b2c3d4';
		$this->assertSame( 'https://s.test/a.css?ver=' . $t, EMCP_Tools_Site_Hardening::strip_core_version( 'https://s.test/a.css?ver=6.9.1', $v, $t ) );
		$this->assertSame( 'https://s.test/a.js?ver=' . $t . '&x=1', EMCP_Tools_Site_Hardening::strip_core_version( 'https://s.test/a.js?ver=6.9.1&x=1', $v, $t ) );
		$this->assertSame( 'https://s.test/a.js?x=1&ver=' . $t . '#f', EMCP_Tools_Site_Hardening::strip_core_version( 'https://s.test/a.js?x=1&ver=6.9.1#f', $v, $t ) );
		$this->assertSame( 'https://s.test/p.css?ver=2.3.0', EMCP_Tools_Site_Hardening::strip_core_version( 'https://s.test/p.css?ver=2.3.0', $v, $t ) );
		$this->assertSame( 'https://s.test/p.css?nover=6.9.1', EMCP_Tools_Site_Hardening::strip_core_version( 'https://s.test/p.css?nover=6.9.1', $v, $t ) );
		$this->assertSame( 'https://s.test/p.css', EMCP_Tools_Site_Hardening::strip_core_version( 'https://s.test/p.css', $v, $t ) );
		$this->assertSame( 'https://s.test/a.css?ver=6.9.1', EMCP_Tools_Site_Hardening::strip_core_version( 'https://s.test/a.css?ver=6.9.1', '', $t ) );
	}

	public function test_the_version_token_hides_the_version_but_changes_with_it(): void {
		$a = EMCP_Tools_Site_Hardening::version_token( '6.9.1', 'salt' );
		$this->assertSame( 8, strlen( $a ) );
		$this->assertStringNotContainsString( '6.9', $a );
		$this->assertNotSame( $a, EMCP_Tools_Site_Hardening::version_token( '6.9.2', 'salt' ), 'a core update changes the token' );
		$this->assertNotSame( $a, EMCP_Tools_Site_Hardening::version_token( '6.9.1', 'other' ), 'the version cannot be looked up from the token' );
	}

	public function test_users_routes_are_matched_exactly(): void {
		$this->assertTrue( EMCP_Tools_Site_Hardening::is_users_route( '/wp/v2/users' ) );
		$this->assertTrue( EMCP_Tools_Site_Hardening::is_users_route( '/wp/v2/users/(?P<id>[\d]+)' ) );
		$this->assertTrue( EMCP_Tools_Site_Hardening::is_users_route( '/wp/v2/users/me' ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::is_users_route( '/wp/v2/users-extra' ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::is_users_route( '/wp/v2/posts' ) );
	}

	public function test_may_list_users(): void {
		$this->assertFalse( EMCP_Tools_Site_Hardening::may_list_users( false, false ) );
		$this->assertTrue( EMCP_Tools_Site_Hardening::may_list_users( true, false ) );
		$this->assertTrue( EMCP_Tools_Site_Hardening::may_list_users( false, true ) );
	}

	public function test_filter_user_endpoints(): void {
		$endpoints = array(
			'/wp/v2/posts'                => array(),
			'/wp/v2/users'                => array(),
			'/wp/v2/users/(?P<id>[\d]+)'  => array(),
			'/wp/v2/users/me'             => array(),
		);
		$this->assertSame( array( '/wp/v2/posts' => array() ), EMCP_Tools_Site_Hardening::filter_user_endpoints( $endpoints, false ) );
		$this->assertSame( $endpoints, EMCP_Tools_Site_Hardening::filter_user_endpoints( $endpoints, true ) );
	}

	public function test_should_block_author_request(): void {
		$this->assertTrue( EMCP_Tools_Site_Hardening::should_block_author_request( array( 'author' => '1' ), false ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_block_author_request( array( 'author_name' => 'admin' ), false ), 'author archives stay: the name is already known to whoever asks for it' );
		$this->assertTrue( EMCP_Tools_Site_Hardening::should_block_author_request( array( 'author' => '1', 'author_name' => 'admin' ), false ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_block_author_request( array( 'author' => 'admin' ), false ), 'only numeric ids enumerate' );
		$this->assertSame( 302, EMCP_Tools_Site_Hardening::AUTHOR_REDIRECT_STATUS, 'a 302 is not cached, so switching the toggle off takes effect' );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_block_author_request( array( 'author' => '1' ), true ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_block_author_request( array( 'author' => '' ), false ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_block_author_request( array( 'author' => '0' ), false ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_block_author_request( array( 'p' => '5' ), false ) );
	}

	public function test_strip_oembed_author(): void {
		$out = EMCP_Tools_Site_Hardening::strip_oembed_author( array( 'title' => 't', 'author_name' => 'a', 'author_url' => 'u' ) );
		$this->assertSame( array( 'title' => 't' ), $out );
	}

	public function test_should_hide_errors_spares_admins(): void {
		$this->assertTrue( EMCP_Tools_Site_Hardening::should_hide_errors( true, false ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_hide_errors( true, true ) );
		$this->assertFalse( EMCP_Tools_Site_Hardening::should_hide_errors( false, false ) );
	}

	public function test_init_with_no_option_hooks_nothing(): void {
		EMCP_Tools_Site_Hardening::init();
		$this->assertSame( 'x', EMCP_Tools_Site_Hardening::filter_pingback_url( 'x', 'pingback_url' ) );
		$this->assertSame( array( 'X-Pingback' => 'a' ), EMCP_Tools_Site_Hardening::filter_headers( array( 'X-Pingback' => 'a' ) ) );
	}

	// ---- Live-status interpreters ------------------------------------------

	public function test_interpret_xmlrpc(): void {
		$this->assertSame( 'answering', EMCP_Tools_Hardening_Status::interpret_xmlrpc( 200, '<?xml version="1.0"?><methodResponse><params/></methodResponse>' ) );
		$this->assertSame( 'blocked', EMCP_Tools_Hardening_Status::interpret_xmlrpc( 403, '' ) );
		$this->assertSame( 'blocked', EMCP_Tools_Hardening_Status::interpret_xmlrpc( 405, 'XML-RPC server accepts POST requests only.' ) );
		$this->assertSame( 'unknown', EMCP_Tools_Hardening_Status::interpret_xmlrpc( 0, '' ) );
		$this->assertSame( 'unknown', EMCP_Tools_Hardening_Status::interpret_xmlrpc( 200, '<html>' ) );
	}

	public function test_interpret_users(): void {
		$this->assertSame( array( 'status' => 'lists_users', 'count' => 2 ), EMCP_Tools_Hardening_Status::interpret_users( 200, '[{"id":1},{"id":2}]' ) );
		$this->assertSame( array( 'status' => 'empty', 'count' => 0 ), EMCP_Tools_Hardening_Status::interpret_users( 200, '[]' ) );
		$this->assertSame( 'blocked', EMCP_Tools_Hardening_Status::interpret_users( 404, '{"code":"rest_no_route"}' )['status'] );
		$this->assertSame( 'unknown', EMCP_Tools_Hardening_Status::interpret_users( 200, '{"code":"x"}' )['status'] );
		$this->assertSame( 'unknown', EMCP_Tools_Hardening_Status::interpret_users( 0, '' )['status'] );
	}

	public function test_interpret_author(): void {
		$this->assertSame( 'leaks_slug', EMCP_Tools_Hardening_Status::interpret_author( 301, 'https://s.test/author/admin/' ) );
		$this->assertSame( 'blocked', EMCP_Tools_Hardening_Status::interpret_author( 301, 'https://s.test/' ) );
		$this->assertSame( 'no_author', EMCP_Tools_Hardening_Status::interpret_author( 404, '' ) );
		$this->assertSame( 'leaks_slug', EMCP_Tools_Hardening_Status::interpret_author( 200, '' ) );
		$this->assertSame( 'unknown', EMCP_Tools_Hardening_Status::interpret_author( 0, '' ) );
	}

	public function test_detect_generator_reused_from_audit(): void {
		$audit = new EMCP_Tools_Security_Hardening_Audit();
		$this->assertTrue( $audit->detect_generator( '<meta name="generator" content="WordPress 6.9.1" />' ) );
		$this->assertFalse( $audit->detect_generator( '<meta name="viewport" content="width=device-width">' ) );
	}

	// ---- harden-site ability ----------------------------------------------

	public function test_ability_requires_confirm(): void {
		$abilities = new EMCP_Tools_Security_Abilities();
		$e         = $abilities->execute_harden_site( array( 'toggles' => array( 'disable_xmlrpc' => true ) ) );
		$this->assertSame( 'confirm_required', $e->get_error_code() );
		$this->assertArrayNotHasKey( EMCP_Tools_Site_Hardening::OPTION, $GLOBALS['emcp_test']['options'] );
	}

	public function test_ability_writes_autoloaded_option_and_reports_previous(): void {
		$abilities = new EMCP_Tools_Security_Abilities();
		$out       = $abilities->execute_harden_site( array( 'toggles' => array( 'disable_xmlrpc' => true, 'hide_wp_version' => true ), 'confirm' => true ) );
		$this->assertTrue( $out['changed'] );
		$this->assertFalse( $out['previous']['disable_xmlrpc'] );
		$this->assertTrue( $out['current']['disable_xmlrpc'] );
		$this->assertSame( array( 'disable_xmlrpc' => true, 'hide_wp_version' => true ), $GLOBALS['emcp_test']['options'][ EMCP_Tools_Site_Hardening::OPTION ] );
		$this->assertTrue( $GLOBALS['emcp_test']['autoload'][ EMCP_Tools_Site_Hardening::OPTION ] );

		$again = $abilities->execute_harden_site( array( 'toggles' => array( 'disable_xmlrpc' => true ), 'confirm' => true ) );
		$this->assertFalse( $again['changed'] );
		$this->assertTrue( $again['previous']['hide_wp_version'] );
	}

	public function test_ability_deletes_option_when_all_off(): void {
		$GLOBALS['emcp_test']['options'][ EMCP_Tools_Site_Hardening::OPTION ] = array( 'hide_php_errors' => true );
		$abilities = new EMCP_Tools_Security_Abilities();
		$out       = $abilities->execute_harden_site( array( 'toggles' => array( 'hide_php_errors' => false ), 'confirm' => true ) );
		$this->assertTrue( $out['changed'] );
		$this->assertTrue( $out['previous']['hide_php_errors'] );
		$this->assertArrayNotHasKey( EMCP_Tools_Site_Hardening::OPTION, $GLOBALS['emcp_test']['options'] );
	}

	public function test_ability_passes_validation_errors_through(): void {
		$abilities = new EMCP_Tools_Security_Abilities();
		$e         = $abilities->execute_harden_site( array( 'toggles' => array( 'block_readme' => true ), 'confirm' => true ) );
		$this->assertSame( 'unsupported_toggle', $e->get_error_code() );
	}

	public function test_ability_registers_both_tools(): void {
		$abilities = new EMCP_Tools_Security_Abilities();
		$abilities->register();
		$names = $abilities->get_ability_names();
		$this->assertContains( 'emcp-tools/harden-site', $names );
		$this->assertContains( 'emcp-tools/get-hardening-status', $names );
	}
}
