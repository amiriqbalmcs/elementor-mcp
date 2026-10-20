<?php
/**
 * Tests for the scan-security `compromise` audit (pure evaluators), the three
 * compromise-related malware rules, and the scanner wiring for the new check.
 *
 * Self-contained: requires the security classes directly; the evaluators and
 * scan_code() need no WordPress functions.
 *
 * @package EMCP_Tools
 */

use PHPUnit\Framework\TestCase;

require_once EMCP_TOOLS_DIR . 'includes/security/class-security-finding.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-malware-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-integrity-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-hardening-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-software-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-compromise-audit.php';
require_once EMCP_TOOLS_DIR . 'includes/security/class-security-scanner.php';

final class SecurityCompromiseAuditTest extends TestCase {

	const NOW = 1792281600; // 2026-10-18 00:00 UTC.
	const DAY = 86400;

	/** @var EMCP_Tools_Security_Compromise_Audit */
	private $audit;

	protected function setUp(): void {
		$this->audit = new EMCP_Tools_Security_Compromise_Audit();
	}

	// ---- Twin folders ------------------------------------------------------

	public function test_no_twins_passes(): void {
		$f = $this->audit->evaluate_twin_folders( array() );
		$this->assertSame( 'pass', $f['status'] );
		$this->assertSame( 'compromise', $f['category'] );
	}

	public function test_legit_elementor_twin_without_htaccess_is_ignored(): void {
		$f = $this->audit->evaluate_twin_folders(
			array(
				array( 'path' => 'wp-content/plugins/elementor/modules/atomic-widgets/elements/atomic-list/atomic-list', 'files' => array( 'atomic-list.php', 'atomic-list.html.twig' ) ),
				array( 'path' => 'wp-content/plugins/foo/vendor_prefixed/twig/twig', 'files' => array( 'Environment.php', 'composer.json' ) ),
			)
		);
		$this->assertSame( 'pass', $f['status'] );
	}

	public function test_twin_with_htaccess_is_critical(): void {
		$f = $this->audit->evaluate_twin_folders(
			array(
				array( 'path' => 'wp-content/plugins/foo/prompts/prompts', 'files' => array( '.htaccess', 'index.php', 'x7k2.wmv' ) ),
				array( 'path' => 'wp-content/uploads/2026/05/05', 'files' => array( '.htaccess', 'index.php' ) ),
			)
		);
		$this->assertSame( 'critical', $f['status'] );
		$this->assertSame( 2, $f['value']['count'] );
		$this->assertContains( 'wp-content/plugins/foo/prompts/prompts', $f['value']['paths'] );
		$this->assertNotEmpty( $f['recommendation'] );
	}

	public function test_twin_with_odd_php_outside_library_is_warning(): void {
		$f = $this->audit->evaluate_twin_folders(
			array( array( 'path' => 'wp-content/themes/acme/assets/assets', 'files' => array( 'qzr91.php' ) ) )
		);
		$this->assertSame( 'warning', $f['status'] );
	}

	// ---- Back-dated files --------------------------------------------------

	private function stomped( string $path ): array {
		return array( 'path' => $path, 'ctime' => self::NOW - 1 * self::DAY, 'mtime' => self::NOW - 155 * self::DAY );
	}

	public function test_backdated_mu_plugin_is_critical(): void {
		$f = $this->audit->evaluate_timestomp( array( $this->stomped( 'wp-content/mu-plugins/contact-form-7.php' ) ), self::NOW );
		$this->assertSame( 'critical', $f['status'] );
		$this->assertSame( 1, $f['value']['in_core_or_mu'] );
	}

	public function test_backdated_root_file_is_critical(): void {
		$f = $this->audit->evaluate_timestomp( array( $this->stomped( 'wp-l0gin.php' ) ), self::NOW );
		$this->assertSame( 'critical', $f['status'] );
	}

	public function test_backdated_plugin_file_is_warning(): void {
		$f = $this->audit->evaluate_timestomp( array( $this->stomped( 'wp-content/plugins/foo/foo.php' ) ), self::NOW );
		$this->assertSame( 'warning', $f['status'] );
		$this->assertSame( 1, $f['value']['count'] );
	}

	public function test_recent_mtime_passes(): void {
		$f = $this->audit->evaluate_timestomp(
			array(
				array( 'path' => 'wp-content/mu-plugins/a.php', 'ctime' => self::NOW - self::DAY, 'mtime' => self::NOW - 2 * self::DAY ),
				// Old ctime: outside the window even though mtime is older still.
				array( 'path' => 'wp-content/mu-plugins/b.php', 'ctime' => self::NOW - 90 * self::DAY, 'mtime' => self::NOW - 400 * self::DAY ),
			),
			self::NOW
		);
		$this->assertSame( 'pass', $f['status'] );
	}

	// ---- Cloaking ----------------------------------------------------------

	private function page( string $title, int $status = 200, int $length = 50000 ): array {
		return array( 'ok' => true, 'status' => $status, 'title' => $title, 'length' => $length, 'error' => null );
	}

	public function test_cloaking_title_mismatch_is_critical(): void {
		$f = $this->audit->evaluate_cloaking( $this->page( 'Locksmith South London' ), $this->page( 'Günstige Schuhe kaufen | Online Shop' ) );
		$this->assertSame( 'critical', $f['status'] );
		$this->assertContains( 'title differs', $f['value']['reasons'] );
	}

	public function test_cloaking_same_page_passes(): void {
		$f = $this->audit->evaluate_cloaking( $this->page( 'Acme &amp; Co' ), $this->page( "  ACME &  co\n", 200, 52000 ) );
		$this->assertSame( 'pass', $f['status'] );
	}

	public function test_cloaking_size_mismatch_is_critical(): void {
		$f = $this->audit->evaluate_cloaking( $this->page( 'Acme' ), $this->page( 'Acme', 200, 9000 ) );
		$this->assertSame( 'critical', $f['status'] );
	}

	public function test_cloaking_fetch_error_is_info(): void {
		$f = $this->audit->evaluate_cloaking( $this->page( 'Acme' ), array( 'ok' => false, 'status' => 0, 'title' => '', 'length' => 0, 'error' => 'cURL error 28' ) );
		$this->assertSame( 'info', $f['status'] );
		$this->assertSame( 'cURL error 28', $f['value']['bot'] );
	}

	public function test_cloaking_firewall_block_is_warning_not_critical(): void {
		$f = $this->audit->evaluate_cloaking( $this->page( 'Acme' ), $this->page( 'Attention Required!', 403, 4000 ) );
		$this->assertSame( 'warning', $f['status'] );
	}

	// ---- Public backups ----------------------------------------------------

	public function test_public_backup_200_is_critical(): void {
		$f = $this->audit->evaluate_public_backups(
			array(
				array( 'path' => 'wp-content/ai1wm-backups/site-20261001.wpress', 'size' => 1300000000, 'status' => 200 ),
				array( 'path' => 'wp-content/updraft/backup_2026-10-01-db.gz', 'size' => 4000000, 'status' => 403 ),
			)
		);
		$this->assertSame( 'critical', $f['status'] );
		$this->assertSame( 1, $f['value']['public'] );
	}

	public function test_protected_backup_403_passes(): void {
		$f = $this->audit->evaluate_public_backups( array( array( 'path' => 'wp-content/updraft/x-db.gz', 'size' => 10, 'status' => 403 ) ) );
		$this->assertSame( 'pass', $f['status'] );
	}

	public function test_no_backups_passes(): void {
		$this->assertSame( 'pass', $this->audit->evaluate_public_backups( array() )['status'] );
	}

	public function test_unknown_backup_status_is_warning(): void {
		$f = $this->audit->evaluate_public_backups( array( array( 'path' => 'wp-content/backups/x.zip', 'size' => 10, 'status' => null ) ) );
		$this->assertSame( 'warning', $f['status'] );
	}

	public function test_unchecked_files_in_blocked_dir_are_inferred_blocked(): void {
		$candidates = array();
		for ( $i = 0; $i < 13; $i++ ) {
			$candidates[] = array( 'path' => "wp-content/updraft/backup_{$i}-db.gz", 'size' => 100, 'status' => $i < 10 ? 403 : null );
		}
		$f = $this->audit->evaluate_public_backups( $candidates );
		$this->assertSame( 'pass', $f['status'] );
		$this->assertSame( 3, $f['value']['inferred_blocked'] );
	}

	public function test_mixed_dir_with_one_public_file_is_critical(): void {
		$f = $this->audit->evaluate_public_backups(
			array(
				array( 'path' => 'wp-content/updraft/a-db.gz', 'size' => 1, 'status' => 403 ),
				array( 'path' => 'wp-content/updraft/b-db.gz', 'size' => 1, 'status' => 200 ),
				array( 'path' => 'wp-content/updraft/c-db.gz', 'size' => 1, 'status' => null ),
			)
		);
		$this->assertSame( 'critical', $f['status'] );
		$this->assertSame( 0, $f['value']['inferred_blocked'] );
	}

	public function test_unchecked_file_in_dir_without_checks_is_warning(): void {
		$f = $this->audit->evaluate_public_backups(
			array(
				array( 'path' => 'wp-content/updraft/a-db.gz', 'size' => 1, 'status' => 403 ),
				array( 'path' => 'wp-content/ai1wm-backups/site.wpress', 'size' => 1, 'status' => null ),
			)
		);
		$this->assertSame( 'warning', $f['status'] );
	}

	public function test_failed_check_keeps_unchecked_siblings_unknown(): void {
		$f = $this->audit->evaluate_public_backups(
			array(
				array( 'path' => 'wp-content/updraft/a-db.gz', 'size' => 1, 'status' => 403 ),
				array( 'path' => 'wp-content/updraft/b-db.gz', 'size' => 1, 'status' => 0 ),
				array( 'path' => 'wp-content/updraft/c-db.gz', 'size' => 1, 'status' => null ),
			)
		);
		$this->assertSame( 'warning', $f['status'] );
		$this->assertSame( 0, $f['value']['inferred_blocked'] );
	}

	public function test_head_order_covers_each_dir_before_repeating(): void {
		$order = $this->audit->head_order(
			array(
				array( 'path' => 'wp-content/updraft/a.gz' ),
				array( 'path' => 'wp-content/updraft/b.gz' ),
				array( 'path' => 'wp-content/updraft/c.gz' ),
				array( 'path' => 'wp-content/ai1wm-backups/x.wpress' ),
				array( 'path' => 'site.zip' ),
			)
		);
		$this->assertSame( array( 0, 3, 4, 1, 2 ), $order );
	}

	// ---- Must-use plugins --------------------------------------------------

	public function test_mu_plugin_named_like_contact_form_7_is_warning(): void {
		$f = $this->audit->evaluate_mu_plugins(
			array(
				array( 'name' => '000-ionos.php', 'size' => 900, 'mtime' => self::NOW ),
				array( 'name' => 'contact-form-7.php', 'size' => 4200, 'mtime' => self::NOW - 155 * self::DAY ),
			)
		);
		$this->assertSame( 'warning', $f['status'] );
		$this->assertSame( 'contact-form-7.php', $f['value']['suspicious'][0]['name'] );
	}

	public function test_mu_plugin_cache_name_without_active_plugin_is_warning(): void {
		$files = array( array( 'name' => 'super-fast-cache.php', 'size' => 1, 'mtime' => self::NOW ) );
		$this->assertSame( 'warning', $this->audit->evaluate_mu_plugins( $files )['status'] );
		$this->assertSame( 'info', $this->audit->evaluate_mu_plugins( $files, array( 'super-fast-cache' ) )['status'] );
	}

	public function test_mu_plugin_backdated_is_warning(): void {
		$files = array( array( 'name' => 'loader.php', 'size' => 1, 'mtime' => self::NOW ) );
		$this->assertSame( 'warning', $this->audit->evaluate_mu_plugins( $files, array(), array( 'loader.php' ) )['status'] );
	}

	public function test_benign_mu_plugins_are_info_and_none_is_pass(): void {
		$files = array( array( 'name' => '000-ionos.php', 'size' => 900, 'mtime' => self::NOW ) );
		$this->assertSame( 'info', $this->audit->evaluate_mu_plugins( $files )['status'] );
		$this->assertSame( 'pass', $this->audit->evaluate_mu_plugins( array() )['status'] );
	}

	// ---- Orphaned cron -----------------------------------------------------

	public function test_suspicious_orphan_hook_is_warning(): void {
		$f = $this->audit->evaluate_orphan_cron(
			array(
				array( 'hook' => 'fm_cache_index_inject_cron', 'next' => self::NOW ),
				array( 'hook' => 'old_plugin_daily_cleanup', 'next' => self::NOW ),
			)
		);
		$this->assertSame( 'warning', $f['status'] );
		$this->assertSame( 'fm_cache_index_inject_cron', $f['value']['suspicious'][0]['hook'] );
		$this->assertSame( 2, $f['value']['count'] );
	}

	public function test_benign_orphan_hook_is_info(): void {
		$f = $this->audit->evaluate_orphan_cron( array( array( 'hook' => 'woocommerce_cleanup_sessions', 'next' => self::NOW ) ) );
		$this->assertSame( 'info', $f['status'] );
	}

	public function test_no_orphans_passes(): void {
		$this->assertSame( 'pass', $this->audit->evaluate_orphan_cron( array() )['status'] );
	}

	// ---- Malware rules -----------------------------------------------------

	private function rule_ids( string $code ): array {
		$malware = new EMCP_Tools_Security_Malware_Audit();
		return array_column( $malware->scan_code( $code, 'wp-content/plugins/x/x.php' ), 'status', 'id' );
	}

	public function test_split_superglobal_is_critical(): void {
		// Samples are assembled at runtime so no intact signature sits on disk (see issue #100).
		$ids = $this->rule_ids( '<?php $c = ${\'_C' . 'O\'.\'OKI\'.\'E\'}; $p = ${"_P" . "OST"};' );
		$this->assertSame( 'critical', $ids['malware_split_superglobal'] ?? null );
	}

	public function test_split_non_superglobal_is_ignored(): void {
		$ids = $this->rule_ids( '<?php $k = \'_AB\' . \'CD\';' );
		$this->assertArrayNotHasKey( 'malware_split_superglobal', $ids );
	}

	public function test_injector_marker_is_critical(): void {
		$ids = $this->rule_ids( "<?php\n//" . 'DU' . "AN_START\n\$x = 1;\n//" . 'DU' . 'AN_END' );
		$this->assertSame( 'critical', $ids['malware_injector_marker'] ?? null );
	}

	public function test_zlib_and_phar_include_are_critical(): void {
		$this->assertSame( 'critical', $this->rule_ids( '<?php include "compress' . '.zlib://" . $f;' )['malware_zlib_include'] ?? null );
		$this->assertSame( 'critical', $this->rule_ids( "<?php require_once('ph" . "ar://x.jpg/a.php');" )['malware_zlib_include'] ?? null );
		$this->assertArrayNotHasKey( 'malware_zlib_include', $this->rule_ids( "<?php require_once __DIR__ . '/a.php';" ) );
	}

	// ---- Scanner wiring ----------------------------------------------------

	public function test_scanner_resolves_and_groups_compromise(): void {
		$scanner = new EMCP_Tools_Security_Scanner();
		$this->assertSame( array( 'compromise' ), $scanner->resolve_checks( array( 'compromise' ) ) );
		$this->assertContains( 'compromise', $scanner->resolve_checks( null ) );
		$this->assertCount( 5, $scanner->resolve_checks( null ) );
		$this->assertArrayHasKey( 'compromise', $scanner->group_by_category( array() ) );
	}

	// ---- Partial walks, time budget, skipped folders (review fixes) --------

	public function test_a_truncated_walk_does_not_pass_twin_folders(): void {
		$f = $this->audit->evaluate_twin_folders( array(), 'time_budget' );
		$this->assertSame( 'info', $f['status'] );
		$this->assertStringContainsString( 'partly', $f['message'] );
		$this->assertSame( 'time_budget', $f['value']['truncated_reason'] );
	}

	public function test_a_truncated_walk_does_not_pass_backdated_files(): void {
		$f = $this->audit->evaluate_timestomp( array(), self::NOW, array(), 'max_dirs' );
		$this->assertSame( 'info', $f['status'] );
		$this->assertStringContainsString( 'partly', $f['message'] );
	}

	public function test_a_truncated_walk_keeps_what_it_found(): void {
		$f = $this->audit->evaluate_twin_folders( array( array( 'path' => 'wp-content/plugins/foo/prompts/prompts', 'files' => array( '.htaccess', 'index.php' ) ) ), 'time_budget' );
		$this->assertSame( 'critical', $f['status'] );
		$this->assertSame( 'time_budget', $f['value']['truncated_reason'] );
	}

	public function test_dependency_and_vcs_folders_are_not_walked(): void {
		$this->assertTrue( EMCP_Tools_Security_Compromise_Audit::is_skipped_dir( 'node_modules' ) );
		$this->assertTrue( EMCP_Tools_Security_Compromise_Audit::is_skipped_dir( '.git' ) );
		$this->assertFalse( EMCP_Tools_Security_Compromise_Audit::is_skipped_dir( 'vendor' ), 'backdoors hide in vendor folders too' );
		$this->assertFalse( EMCP_Tools_Security_Compromise_Audit::is_skipped_dir( 'prompts' ) );
	}

	public function test_network_timeouts_fit_the_remaining_budget(): void {
		$this->assertSame( EMCP_Tools_Security_Compromise_Audit::FETCH_TIMEOUT, EMCP_Tools_Security_Compromise_Audit::timeout_for( 60, EMCP_Tools_Security_Compromise_Audit::FETCH_TIMEOUT ) );
		$this->assertSame( 4, EMCP_Tools_Security_Compromise_Audit::timeout_for( 5, EMCP_Tools_Security_Compromise_Audit::FETCH_TIMEOUT ) );
		$this->assertSame( 0, EMCP_Tools_Security_Compromise_Audit::timeout_for( 1, EMCP_Tools_Security_Compromise_Audit::HEAD_TIMEOUT ), 'no time left: skip the request' );
	}

	public function test_a_skipped_cloaking_check_says_why(): void {
		$skip = array( 'ok' => false, 'error' => 'skipped: time budget used up' );
		$f    = $this->audit->evaluate_cloaking( $skip, $skip );
		$this->assertSame( 'info', $f['status'] );
		$this->assertStringContainsString( 'time budget', json_encode( $f['value'] ) );
	}

	public function test_emcp_backup_folders_are_checked(): void {
		$this->assertContains( 'emcp-backups*', EMCP_Tools_Security_Compromise_Audit::BACKUP_DIRS );
	}

	public function test_a_public_archive_is_not_claimed_to_be_a_full_database(): void {
		$f = $this->audit->evaluate_public_backups( array( array( 'path' => 'theme.zip', 'size' => 10, 'status' => 200 ) ) );
		$this->assertSame( 'critical', $f['status'] );
		$this->assertStringContainsString( 'can expose', $f['message'] );
	}

	public function test_the_scanner_hands_its_time_budget_to_the_audit(): void {
		$spy = new class() extends EMCP_Tools_Security_Compromise_Audit {
			public $seen = null;
			public function run( int $max_seconds = self::TIME_BUDGET ): array {
				$this->seen = $max_seconds;
				return array( 'findings' => array(), 'stats' => array() );
			}
		};
		( new EMCP_Tools_Security_Scanner( null, null, null, null, $spy ) )->scan( array( 'checks' => array( 'compromise' ), 'max_seconds' => 7 ) );
		$this->assertSame( 7, $spy->seen );
	}
}
