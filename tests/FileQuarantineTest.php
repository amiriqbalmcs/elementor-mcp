<?php
/**
 * Tests for the file quarantine: the pure rules (path checks, refusals, ids,
 * locations, manifests) and temp-dir round trips (quarantine then restore, by
 * rename and by the verified copy fallback, plus the rollback-change path).
 *
 * @package EMCP_Tools
 */

use PHPUnit\Framework\TestCase;

require_once EMCP_TOOLS_DIR . 'includes/class-filesystem-guard.php';
require_once EMCP_TOOLS_DIR . 'includes/class-file-mover.php';
require_once EMCP_TOOLS_DIR . 'includes/class-file-quarantine.php';

if ( ! function_exists( 'wp_mkdir_p' ) ) {
	function wp_mkdir_p( $dir ) {
		return is_dir( $dir ) || @mkdir( $dir, 0777, true );
	}
}
if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $flags = 0 ) {
		return json_encode( $data, $flags );
	}
}

final class FileQuarantineTest extends TestCase {

	const NOW = 1792281600; // 2026-10-18 00:00 UTC.

	/** @var string Temp sandbox: <tmp>/site is the root, <tmp> is the folder above it. */
	private $tmp;

	/** @var string */
	private $root;

	protected function setUp(): void {
		emcp_test_reset();
		$this->tmp  = EMCP_File_Quarantine_Test_Dir::make();
		$this->root = $this->tmp . '/site';
		mkdir( $this->root . '/wp-content/plugins/demo/prompts/prompts', 0777, true );
		file_put_contents( $this->root . '/wp-content/plugins/demo/prompts/prompts/index.php', "<?php // twin folder\n" );
		file_put_contents( $this->root . '/wp-content/plugins/demo/demo.php', "<?php // plugin\n" );
		file_put_contents( $this->root . '/wp-config.php', "<?php\n" );
	}

	protected function tearDown(): void {
		EMCP_File_Quarantine_Test_Dir::remove( $this->tmp );
	}

	private function ctx( array $extra = array() ): array {
		return array_merge(
			array(
				'root'        => $this->root,
				'content_dir' => $this->root . '/wp-content',
				'plugin_dir'  => '',
				'outside_ok'  => true,
				'user_id'     => 7,
				'user_login'  => 'admin',
				'now'         => self::NOW,
			),
			$extra
		);
	}

	private function code( $result ): string {
		$this->assertInstanceOf( WP_Error::class, $result );
		return $result->get_error_code();
	}

	// ---- Pure rules ----------------------------------------------------

	public function test_normalize_cleans_relative_paths(): void {
		$this->assertSame( 'wp-content/a/b.php', EMCP_Tools_File_Quarantine::normalize_relative( './wp-content//a\\b.php' ) );
		$this->assertSame( 'wp-content/x.php', EMCP_Tools_File_Quarantine::normalize_relative( '/var/www/wp-content/x.php', '/var/www' ) );
		$this->assertSame( '', EMCP_Tools_File_Quarantine::normalize_relative( '.' ) );
	}

	public function test_normalize_refuses_traversal_absolute_and_null_bytes(): void {
		$this->assertSame( 'outside_root', $this->code( EMCP_Tools_File_Quarantine::normalize_relative( 'wp-content/../../etc/passwd' ) ) );
		$this->assertSame( 'outside_root', $this->code( EMCP_Tools_File_Quarantine::normalize_relative( '/etc/passwd', '/var/www' ) ) );
		$this->assertSame( 'outside_root', $this->code( EMCP_Tools_File_Quarantine::normalize_relative( 'C:/Windows/win.ini' ) ) );
		$this->assertSame( 'invalid_path', $this->code( EMCP_Tools_File_Quarantine::normalize_relative( "a.php\0.txt" ) ) );
		$this->assertSame( 'invalid_path', $this->code( EMCP_Tools_File_Quarantine::normalize_relative( '  ' ) ) );
	}

	/** @dataProvider refused_paths */
	public function test_refusal_rules( string $rel, string $code ): void {
		$this->assertSame( $code, $this->code( EMCP_Tools_File_Quarantine::refusal( $rel, 'wp-content', 'wp-content/plugins/emcp-tools' ) ) );
	}

	public static function refused_paths(): array {
		return array(
			'site root'              => array( '', 'protected_root' ),
			'wp-config.php'          => array( 'wp-config.php', 'protected_core' ),
			'wp-load.php'            => array( 'wp-load.php', 'protected_core' ),
			'wp-settings.php'        => array( 'wp-settings.php', 'protected_core' ),
			'root index.php'         => array( 'index.php', 'protected_core' ),
			'case does not matter'   => array( 'WP-Config.PHP', 'protected_core' ),
			'wp-includes file'       => array( 'wp-includes/version.php', 'protected_core' ),
			'wp-admin folder'        => array( 'wp-admin', 'protected_core' ),
			'wp-content itself'      => array( 'wp-content', 'protected_root' ),
			'quarantine folder'      => array( 'wp-content/emcp-quarantine', 'protected_quarantine' ),
			'inside quarantine'      => array( 'wp-content/emcp-quarantine/x/a.php', 'protected_quarantine' ),
			'EMCP itself'            => array( 'wp-content/plugins/emcp-tools/emcp-tools.php', 'protected_plugin' ),
		);
	}

	public function test_refusal_allows_ordinary_suspects(): void {
		$this->assertNull( EMCP_Tools_File_Quarantine::refusal( 'wp-content/plugins/demo/prompts/prompts/index.php' ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::refusal( 'wp-content/uploads/2026/10/x.php' ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::refusal( 'blog/index.php' ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::refusal( 'wp-content/plugins/emcp-tools-evil/x.php', 'wp-content', 'wp-content/plugins/emcp-tools' ) );
	}

	public function test_ids_and_paths(): void {
		$id = EMCP_Tools_File_Quarantine::new_id( self::NOW, 'A1B2C3D4' );
		$this->assertSame( '20261018-000000-a1b2c3d4', $id );
		$this->assertTrue( EMCP_Tools_File_Quarantine::is_valid_id( $id ) );
		$this->assertFalse( EMCP_Tools_File_Quarantine::is_valid_id( '../20261018-000000-a1b2c3d4' ) );
		$this->assertFalse( EMCP_Tools_File_Quarantine::is_valid_id( '20261018-000000-zz' ) );
		$this->assertSame( '/q/' . $id . '/wp-content/a.php', EMCP_Tools_File_Quarantine::stored_path( '/q', $id, 'wp-content/a.php' ) );
		$this->assertSame( '/q/' . $id . '.json', EMCP_Tools_File_Quarantine::manifest_path( '/q/', $id ) );
	}

	public function test_base_goes_above_root_or_falls_back_to_wp_content(): void {
		$outside = EMCP_Tools_File_Quarantine::choose_base( '/srv/site/public', '/srv/site/public/wp-content', true );
		$this->assertSame( array( 'dir' => '/srv/site/emcp-quarantine', 'location' => 'outside-web-root' ), $outside );
		$inside = EMCP_Tools_File_Quarantine::choose_base( '/srv/site/public', '/srv/site/public/wp-content', false );
		$this->assertSame( array( 'dir' => '/srv/site/public/wp-content/emcp-quarantine', 'location' => 'wp-content' ), $inside );
	}

	public function test_htaccess_covers_apache_22_and_24(): void {
		$rules = EMCP_Tools_File_Quarantine::htaccess_rules();
		$this->assertStringContainsString( 'Require all denied', $rules );
		$this->assertStringContainsString( 'Deny from all', $rules );
		$this->assertStringContainsString( '<IfModule !mod_authz_core.c>', $rules );
	}

	public function test_manifest_shape_and_reason_cleanup(): void {
		$m = EMCP_Tools_File_Quarantine::build_manifest(
			array(
				'id'            => '20261018-000000-a1b2c3d4',
				'original_path' => 'wp-content/x.php',
				'type'          => 'file',
				'size'          => 12,
				'sha256'        => str_repeat( 'a', 64 ),
				'mtime'         => 5,
				'ctime'         => 6,
				'reason'        => "twin\nfolder " . str_repeat( 'x', 600 ),
				'user_id'       => 7,
				'user_login'    => 'admin',
				'time'          => self::NOW,
				'location'      => 'wp-content',
				'method'        => 'rename',
			)
		);
		$this->assertSame( 'quarantined', $m['status'] );
		$this->assertSame( 1, $m['files'] );
		$this->assertSame( '2026-10-18T00:00:00+00:00', $m['time'] );
		$this->assertSame( array( 'id' => 7, 'login' => 'admin' ), $m['user'] );
		$this->assertSame( 500, strlen( $m['reason'] ) );
		$this->assertStringStartsWith( 'twin folder', $m['reason'] );
		$dir = EMCP_Tools_File_Quarantine::build_manifest( array( 'type' => 'dir', 'files' => 3, 'sha256' => 'ignored' ) );
		$this->assertNull( $dir['sha256'] );
		$this->assertSame( 3, $dir['files'] );
	}

	public function test_parse_manifest_rejects_foreign_or_escaping_data(): void {
		$good = array( 'id' => '20261018-000000-a1b2c3d4', 'original_path' => 'wp-content/x.php' );
		$this->assertIsArray( EMCP_Tools_File_Quarantine::parse_manifest( json_encode( $good ) ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::parse_manifest( 'not json' ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::parse_manifest( json_encode( array_merge( $good, array( 'id' => 'x' ) ) ) ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::parse_manifest( json_encode( array_merge( $good, array( 'original_path' => '../../x.php' ) ) ) ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::parse_manifest( json_encode( array_merge( $good, array( 'original_path' => '/etc/x' ) ) ) ) );
	}

	public function test_restore_conflict_needs_overwrite(): void {
		$this->assertSame( 'target_exists', $this->code( EMCP_Tools_File_Quarantine::restore_conflict( true, false ) ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::restore_conflict( true, true ) );
		$this->assertNull( EMCP_Tools_File_Quarantine::restore_conflict( false, false ) );
	}

	// ---- Round trips ---------------------------------------------------

	public function test_round_trip_file_outside_web_root(): void {
		$rel    = 'wp-content/plugins/demo/prompts/prompts/index.php';
		$hash   = hash_file( 'sha256', $this->root . '/' . $rel );
		$result = EMCP_Tools_File_Quarantine::quarantine( $rel, 'twin folder back door', $this->ctx() );
		$this->assertIsArray( $result, is_wp_error( $result ) ? $result->get_error_message() : '' );
		$m = $result['manifest'];
		$this->assertSame( 'outside-web-root', $m['location'] );
		$this->assertSame( 'rename', $m['method'] );
		$this->assertSame( $hash, $m['sha256'] );
		$this->assertSame( 'twin folder back door', $m['reason'] );
		$this->assertFileDoesNotExist( $this->root . '/' . $rel );
		// Stored under a name no web server runs as PHP, even where .htaccess is ignored (nginx, IIS).
		$this->assertFileDoesNotExist( $this->tmp . '/emcp-quarantine/' . $m['id'] . '/' . $rel );
		$this->assertFileExists( $this->tmp . '/emcp-quarantine/' . $m['id'] . '/' . $rel . '.quarantined' );
		$this->assertTrue( $m['neutralized'] );
		$this->assertFileExists( $this->tmp . '/emcp-quarantine/' . $m['id'] . '.json' );
		$this->assertFileExists( $this->tmp . '/emcp-quarantine/.htaccess' );
		$this->assertStringContainsString( '<deny users="*"', (string) file_get_contents( $this->tmp . '/emcp-quarantine/web.config' ) );
		$this->assertFileExists( $this->tmp . '/emcp-quarantine/index.php' );

		$listed = EMCP_Tools_File_Quarantine::entries( 'quarantined', $this->ctx() );
		$this->assertCount( 1, $listed );
		$this->assertSame( $m['id'], $listed[0]['id'] );

		$back = EMCP_Tools_File_Quarantine::restore( $m['id'], false, $this->ctx() );
		$this->assertIsArray( $back, is_wp_error( $back ) ? $back->get_error_message() : '' );
		$this->assertSame( 'ok', $back['integrity'] );
		$this->assertSame( $hash, hash_file( 'sha256', $this->root . '/' . $rel ) );
		$this->assertDirectoryDoesNotExist( $this->tmp . '/emcp-quarantine/' . $m['id'] );
		$this->assertCount( 0, EMCP_Tools_File_Quarantine::entries( 'quarantined', $this->ctx() ) );
		$this->assertCount( 1, EMCP_Tools_File_Quarantine::entries( 'restored', $this->ctx() ) );
		$this->assertSame( 'already_restored', $this->code( EMCP_Tools_File_Quarantine::restore( $m['id'], false, $this->ctx() ) ) );
	}

	public function test_round_trip_folder_by_verified_copy_in_wp_content_fallback(): void {
		$ctx    = $this->ctx( array( 'outside_ok' => false, 'force_copy' => true ) );
		$result = EMCP_Tools_File_Quarantine::quarantine( 'wp-content/plugins/demo', 'whole plugin', $ctx );
		$this->assertIsArray( $result, is_wp_error( $result ) ? $result->get_error_message() : '' );
		$m    = $result['manifest'];
		$base = $this->root . '/wp-content/emcp-quarantine';
		$this->assertSame( 'wp-content', $m['location'] );
		$this->assertSame( 'copy', $m['method'] );
		$this->assertSame( 'dir', $m['type'] );
		$this->assertSame( 2, $m['files'] );
		$this->assertSame( array(), $result['warnings'] );
		$this->assertDirectoryDoesNotExist( $this->root . '/wp-content/plugins/demo' );
		$this->assertFileExists( $base . '/' . $m['id'] . '/wp-content/plugins/demo/prompts/prompts/index.php.quarantined' );
		$this->assertFileExists( $base . '/' . $m['id'] . '/wp-content/plugins/demo/demo.php.quarantined' );
		$this->assertFileDoesNotExist( $base . '/' . $m['id'] . '/wp-content/plugins/demo/demo.php' );
		$this->assertStringContainsString( 'Require all denied', (string) file_get_contents( $base . '/.htaccess' ) );
		$this->assertSame( '', trim( str_replace( array( '<?php', '// Silence is golden.' ), '', (string) file_get_contents( $base . '/index.php' ) ) ) );

		$back = EMCP_Tools_File_Quarantine::restore( $m['id'], false, $ctx );
		$this->assertIsArray( $back, is_wp_error( $back ) ? $back->get_error_message() : '' );
		$this->assertSame( 'copy', $back['method'] );
		$this->assertFileExists( $this->root . '/wp-content/plugins/demo/prompts/prompts/index.php' );
		$this->assertFileExists( $this->root . '/wp-content/plugins/demo/demo.php' );
		$this->assertFileDoesNotExist( $this->root . '/wp-content/plugins/demo/demo.php.quarantined' );
	}

	public function test_a_parent_folder_that_looks_web_served_is_not_used(): void {
		$this->assertTrue( EMCP_Tools_File_Quarantine::looks_web_served( $this->tmp . '/public_html' ) );
		$this->assertTrue( EMCP_Tools_File_Quarantine::looks_web_served( $this->tmp . '/htdocs' ) );
		file_put_contents( $this->tmp . '/index.php', "<?php
" );
		$this->assertTrue( EMCP_Tools_File_Quarantine::looks_web_served( $this->tmp ), 'a parent with its own index.php is a web root (WordPress in a subfolder)' );

		$ctx = $this->ctx();
		unset( $ctx['outside_ok'] );
		$result = EMCP_Tools_File_Quarantine::quarantine( 'wp-content/plugins/demo/demo.php', 'x', $ctx );
		$this->assertIsArray( $result, is_wp_error( $result ) ? $result->get_error_message() : '' );
		$this->assertSame( 'wp-content', $result['manifest']['location'] );
	}

	public function test_a_plain_parent_folder_is_used(): void {
		$this->assertFalse( EMCP_Tools_File_Quarantine::looks_web_served( $this->tmp ) );
	}

	public function test_a_file_already_named_quarantined_round_trips(): void {
		file_put_contents( $this->root . '/wp-content/plugins/demo/x.php.quarantined', 'odd' );
		$result = EMCP_Tools_File_Quarantine::quarantine( 'wp-content/plugins/demo/x.php.quarantined', 'x', $this->ctx() );
		$back   = EMCP_Tools_File_Quarantine::restore( $result['manifest']['id'], false, $this->ctx() );
		$this->assertIsArray( $back, is_wp_error( $back ) ? $back->get_error_message() : '' );
		$this->assertSame( 'odd', file_get_contents( $this->root . '/wp-content/plugins/demo/x.php.quarantined' ) );
	}

	public function test_restore_refuses_existing_path_unless_overwrite_and_keeps_the_replaced_item(): void {
		$rel = 'wp-content/plugins/demo/demo.php';
		$q   = EMCP_Tools_File_Quarantine::quarantine( $rel, '', $this->ctx() );
		$this->assertIsArray( $q );
		file_put_contents( $this->root . '/' . $rel, "<?php // reinstalled\n" );

		$this->assertSame( 'target_exists', $this->code( EMCP_Tools_File_Quarantine::restore( $q['manifest']['id'], false, $this->ctx() ) ) );
		$this->assertSame( "<?php // reinstalled\n", file_get_contents( $this->root . '/' . $rel ) );

		$back = EMCP_Tools_File_Quarantine::restore( $q['manifest']['id'], true, $this->ctx() );
		$this->assertIsArray( $back, is_wp_error( $back ) ? $back->get_error_message() : '' );
		$this->assertSame( "<?php // plugin\n", file_get_contents( $this->root . '/' . $rel ) );
		$this->assertTrue( EMCP_Tools_File_Quarantine::is_valid_id( (string) $back['replaced_by'] ) );
		$held = EMCP_Tools_File_Quarantine::entries( 'quarantined', $this->ctx() );
		$this->assertCount( 1, $held );
		$this->assertSame( $back['replaced_by'], $held[0]['id'] );
	}

	public function test_rollback_change_path_restores_and_force_overwrites(): void {
		$rel = 'wp-content/plugins/demo/demo.php';
		$q   = EMCP_Tools_File_Quarantine::quarantine( $rel, '', $this->ctx() );
		$this->assertIsArray( $q );
		$rb = array( 'type' => EMCP_Tools_File_Quarantine::ROLLBACK_TYPE, 'quarantine_id' => $q['manifest']['id'] );
		file_put_contents( $this->root . '/' . $rel, 'new' );
		$this->assertSame( 'target_exists', $this->code( EMCP_Tools_File_Quarantine::rollback( $rb, false, $this->ctx() ) ) );
		$this->assertTrue( EMCP_Tools_File_Quarantine::rollback( $rb, true, $this->ctx() ) );
		$this->assertSame( "<?php // plugin\n", file_get_contents( $this->root . '/' . $rel ) );
	}

	public function test_live_rollback_respects_the_file_edit_gate(): void {
		$GLOBALS['emcp_test']['caps'] = array( 'manage_options' ); // No edit_files.
		$result = EMCP_Tools_File_Quarantine::rollback( array( 'quarantine_id' => '20261018-000000-a1b2c3d4' ) );
		$this->assertSame( 'file_edit_disabled', $this->code( $result ) );
	}

	/** @dataProvider live_refusals */
	public function test_quarantine_refusals_on_disk( string $path, string $code ): void {
		$this->assertSame( $code, $this->code( EMCP_Tools_File_Quarantine::quarantine( $path, '', $this->ctx() ) ) );
	}

	public static function live_refusals(): array {
		return array(
			'wp-config.php'      => array( 'wp-config.php', 'protected_core' ),
			'traversal'          => array( 'wp-content/../../outside.txt', 'outside_root' ),
			'missing file'       => array( 'wp-content/nope.php', 'not_found' ),
			'quarantine itself'  => array( 'wp-content/emcp-quarantine', 'protected_quarantine' ),
		);
	}

	public function test_quarantine_refuses_absolute_path_outside_root(): void {
		file_put_contents( $this->tmp . '/outside.txt', 'x' );
		$this->assertSame( 'outside_root', $this->code( EMCP_Tools_File_Quarantine::quarantine( $this->tmp . '/outside.txt', '', $this->ctx() ) ) );
		$this->assertFileExists( $this->tmp . '/outside.txt' );
	}

	public function test_symlink_out_of_root_is_refused_and_in_root_link_moves_itself(): void {
		file_put_contents( $this->tmp . '/secret.txt', 'outside' );
		if ( ! @symlink( $this->tmp . '/secret.txt', $this->root . '/wp-content/out-link' ) ) {
			$this->markTestSkipped( 'This system does not allow creating symlinks.' );
		}
		$this->assertSame( 'symlink_outside_root', $this->code( EMCP_Tools_File_Quarantine::quarantine( 'wp-content/out-link', '', $this->ctx() ) ) );
		$this->assertFileExists( $this->tmp . '/secret.txt' );

		symlink( $this->root . '/wp-content/plugins/demo/demo.php', $this->root . '/wp-content/in-link' );
		$q = EMCP_Tools_File_Quarantine::quarantine( 'wp-content/in-link', '', $this->ctx() );
		$this->assertIsArray( $q, is_wp_error( $q ) ? $q->get_error_message() : '' );
		$this->assertTrue( $q['manifest']['symlink'] );
		$this->assertFileExists( $this->root . '/wp-content/plugins/demo/demo.php' );
	}

	public function test_restore_rejects_bad_ids(): void {
		$this->assertSame( 'invalid_id', $this->code( EMCP_Tools_File_Quarantine::restore( '../x', false, $this->ctx() ) ) );
		$this->assertSame( 'not_found', $this->code( EMCP_Tools_File_Quarantine::restore( '20261018-000000-a1b2c3d4', false, $this->ctx() ) ) );
	}

	public function test_move_path_copy_fallback_moves_a_file_and_verifies_it(): void {
		$src  = $this->root . '/wp-content/plugins/demo/demo.php';
		$dest = $this->tmp . '/moved.php';
		$out  = EMCP_Tools_File_Mover::move( $src, $dest, true );
		$this->assertSame( array( 'method' => 'copy', 'left_behind' => array() ), $out );
		$this->assertFileDoesNotExist( $src );
		$this->assertSame( "<?php // plugin\n", file_get_contents( $dest ) );
	}
}

/**
 * Temp directory helper for the quarantine tests.
 */
final class EMCP_File_Quarantine_Test_Dir {

	public static function make(): string {
		$dir = str_replace( '\\', '/', sys_get_temp_dir() ) . '/emcp-quarantine-test-' . bin2hex( random_bytes( 4 ) );
		mkdir( $dir, 0777, true );
		return (string) realpath( $dir );
	}

	public static function remove( string $dir ): void {
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $it as $f ) {
			if ( $f->isLink() || ! $f->isDir() ) {
				@unlink( $f->getPathname() ) || @rmdir( $f->getPathname() );
			} else {
				@rmdir( $f->getPathname() );
			}
		}
		@rmdir( $dir );
	}
}
