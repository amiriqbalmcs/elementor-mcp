<?php
use PHPUnit\Framework\TestCase;
require_once dirname( __DIR__ ) . '/includes/cloud/safe-update-runtime.php';

final class SafeUpdateRuntimeTest extends TestCase {
	private string $root;
	private array $state;
	protected function setUp(): void {
		$this->root = str_replace( '\\', '/', sys_get_temp_dir() ) . '/emcp-safe-unit-' . bin2hex( random_bytes( 6 ) ) . '/';
		mkdir( $this->root, 0700, true ); mkdir( $this->root . '.emcp-update-test', 0700 );
		file_put_contents( $this->root . 'wp-config.php', '<?php /* original */' );
		$this->state = array( 'job' => 'test', 'root' => $this->root, 'dir' => $this->root . '.emcp-update-test', 'phase' => 'prepared', 'group' => 0, 'groups' => array( array( array( 'id' => 'plugin:a' ) ), array( array( 'id' => 'plugin:b' ) ) ), 'deadline' => time() + 600, 'config_hash' => hash_file( 'sha256', $this->root . 'wp-config.php' ) );
		EMCP_Update_Runtime::write( $this->state['dir'] . '/original-config.php', '<?php /* original */' );
		EMCP_Update_Runtime::write( $this->state['dir'] . '/state.php', $this->state );
	}
	protected function tearDown(): void {
		EMCP_Update_Runtime::$tick_bytes = 33554432; EMCP_Update_Runtime::$tick_rows = 5000;
		EMCP_Update_Runtime::$tick_seconds = 5; EMCP_Update_Runtime::$scan_entries = 2000;
		EMCP_Update_Runtime::$inspection_seconds = 3;
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $this->root, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
		foreach ( $it as $entry ) { $entry->isDir() ? rmdir( $entry->getPathname() ) : unlink( $entry->getPathname() ); }
		rmdir( $this->root );
	}
	private function command( string $action ): void {
		EMCP_Update_Runtime::advance( $this->state, array( 'action' => $action, 'phase' => $this->state['phase'], 'group' => $this->state['group'] ) );
	}
	/** Each integration test owns a randomly named database, never the developer site. */
	private function scratch_database(): mysqli {
		$conf = getenv( 'EMCP_SAFE_UPDATE_TEST_DB' );
		if ( ! $conf || ! extension_loaded( 'mysqli' ) ) { $this->markTestSkipped( 'EMCP_SAFE_UPDATE_TEST_DB not set.' ); }
		list( $host, $user, $pass ) = array_pad( explode( '|', $conf ), 3, '' );
		mysqli_report( MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT );
		$db = new mysqli( $host, $user, $pass ); $name = 'emcp_su_' . bin2hex( random_bytes( 4 ) );
		$db->query( 'CREATE DATABASE `' . $name . '`' ); $db->select_db( $name ); $db->set_charset( 'utf8mb4' );
		$this->state['db'] = array( 'host' => $host, 'user' => $user, 'password' => $pass, 'name' => $name, 'prefix' => 'wp_' );
		return $db;
	}
	private function drop_scratch_database( mysqli $db ): void {
		$db->query( 'DROP DATABASE `' . $db->query( 'SELECT DATABASE()' )->fetch_row()[0] . '`' ); $db->close();
	}
	private function runtime( string $method, ...$args ) {
		return ( new ReflectionMethod( EMCP_Update_Runtime::class, $method ) )->invokeArgs( null, $args );
	}
	private function rocket_dropin( ?string $path = null ): string {
		return "<?php\nuse WP_Rocket\\Buffer\\Cache;\ndefine( 'WP_ROCKET_ADVANCED_CACHE', true );\n\$rocket_cache_path = " . var_export( $path ?? $this->root . 'wp-content/cache/wp-rocket/', true ) . ';';
	}
	/** Query transcripts model grant metadata without creating or changing server accounts. */
	private function grant_database( array $responses, string $version = '8.0.40', int $number = 80040, ?mysqli $comparisons = null ) {
		return new class( $responses, $version, $number, $comparisons ) {
			public array $queries = array();
			public function __construct( private array $responses, public string $server_info, public int $server_version, private ?mysqli $comparisons ) {}
			public function prepare( $sql ) {
				if ( ! $this->comparisons ) { throw new LogicException( 'Unexpected comparison: ' . $sql ); }
				return $this->comparisons->prepare( $sql );
			}
			public function query( $sql ) {
				$this->queries[] = $sql;
				if ( ! array_key_exists( $sql, $this->responses ) ) { throw new LogicException( 'Unexpected metadata query: ' . $sql ); }
				$rows = array_map( static fn( $value ) => is_array( $value ) ? $value : array( $value ), $this->responses[ $sql ] );
				return new class( $rows ) extends ArrayIterator { public function fetch_row() { return array_values( $this[0] ); } };
			}
		};
	}
	public function test_recovery_requires_trigger_visibility_and_foreign_key_parent_permissions(): void {
		$base = 'SELECT, INSERT, CREATE, DROP';
		$db = $this->grant_database( array(), '5.7.33', 50733 );
		foreach ( array( array( $base, '', false ), array( $base . ', TRIGGER', '', true ), array( $base . ', TRIGGER', "CREATE TABLE wp_child (\n  CONSTRAINT `fk` FOREIGN KEY (`id`) REFERENCES `wp_parent` (`id`)\n)", false ), array( $base . ', TRIGGER, REFERENCES', "CREATE TABLE wp_child (\n  CONSTRAINT `fk` FOREIGN KEY (`id`) REFERENCES `wp_parent` (`id`)\n)", true ) ) as list( $privileges, $ddl, $allowed ) ) {
			try {
				$this->runtime( 'recovery_privileges', $db, 'fixture', $ddl, array( 'GRANT ' . $privileges . ' ON *.* TO `user`@`host`' ) );
				$this->assertTrue( $allowed );
			} catch ( RuntimeException $error ) { $this->assertFalse( $allowed ); $this->assertSame( 'database_recovery_privileges_required', $error->getMessage() ); }
		}
	}
	public function test_mysql_expands_only_currently_active_roles(): void {
		$roles = '`restore``role`@`localhost`,`reader`@`%`';
		$grants = array( 'GRANT SELECT, INSERT, CREATE, DROP, TRIGGER ON *.* TO `user`@`host`' );
		$db = $this->grant_database( array( 'SHOW GRANTS' => array( 'GRANT `inactive`@`%` TO `user`@`host`' ), 'SELECT CURRENT_ROLE()' => array( $roles ), 'SHOW GRANTS FOR CURRENT_USER USING ' . $roles => $grants ) );
		$this->runtime( 'recovery_privileges', $db, 'fixture' );
		$this->assertSame( array( 'SHOW GRANTS', 'SELECT CURRENT_ROLE()', 'SHOW GRANTS FOR CURRENT_USER USING ' . $roles ), $db->queries );
		$db = $this->grant_database( array( 'SHOW GRANTS' => array( 'GRANT `inactive`@`%` TO `user`@`host`' ), 'SELECT CURRENT_ROLE()' => array( 'NONE' ) ) );
		try { $this->runtime( 'recovery_privileges', $db, 'fixture' ); $this->fail( 'Inactive role was accepted' ); }
		catch ( RuntimeException $e ) { $this->assertSame( 'database_recovery_privileges_required', $e->getMessage() ); }
		$db = $this->grant_database( array( 'SHOW GRANTS' => array(), 'SELECT CURRENT_ROLE()' => array( '`role`@`%`; SELECT 1' ) ) );
		try { $this->runtime( 'effective_grants', $db ); $this->fail( 'Unvalidated role syntax' ); }
		catch ( RuntimeException $e ) { $this->assertSame( 'database_roles_unavailable', $e->getMessage() ); }
	}
	public function test_mariadb_expands_enabled_inherited_roles_and_quotes_role_names(): void {
		$db = $this->grant_database( array( 'SHOW GRANTS' => array(), 'SELECT ROLE_NAME FROM information_schema.ENABLED_ROLES' => array( 'reader', 'restore`role' ), 'SHOW GRANTS FOR `reader`' => array( 'GRANT SELECT ON *.* TO `reader`' ), 'SHOW GRANTS FOR `restore``role`' => array( 'GRANT INSERT, CREATE, DROP, TRIGGER ON *.* TO `restore``role`' ) ), '10.11.6-MariaDB', 101106 );
		$this->runtime( 'recovery_privileges', $db, 'fixture' );
		$this->assertCount( 4, $db->queries );
	}
	public function test_partial_revokes_schema_scopes_are_literal_for_grants_and_revocations(): void {
		$settings = 'SELECT @@partial_revokes, @@lower_case_table_names';
		$db = $this->grant_database( array( $settings => array( array( 1, 0 ) ) ) );
		$base = 'GRANT SELECT, INSERT, CREATE, DROP, TRIGGER ON *.* TO `user`@`host`';
		foreach ( array( array( 'parent_db', 'parentXdb', false ), array( 'parent%db', 'parentOtherdb', false ), array( 'parent_db', 'parent_db', true ), array( 'parent\\_db', 'parent_db', true ), array( 'Parent_db', 'parent_db', false ) ) as list( $grant_schema, $parent, $allowed ) ) {
			$ddl = "CREATE TABLE wp_child (\n  CONSTRAINT `fk` FOREIGN KEY (`id`) REFERENCES `$parent`.`wp_parent` (`id`)\n)";
			$grants = array( $base, 'GRANT REFERENCES ON `' . $grant_schema . '`.* TO `user`@`host`' );
			try { $this->runtime( 'recovery_privileges', $db, 'site', $ddl, $grants ); $this->assertTrue( $allowed ); }
			catch ( RuntimeException $e ) { $this->assertFalse( $allowed ); $this->assertSame( 'database_recovery_privileges_required', $e->getMessage() ); }
		}
		// A restriction on a similarly named schema must not revoke this schema's grant.
		$this->runtime( 'recovery_privileges', $db, 'parentXdb', '', array( $base, 'REVOKE DROP ON `parent_db`.* FROM `user`@`host`' ) );
		$this->assertCount( 6, $db->queries );
		$db = $this->grant_database( array( $settings => array( array( 1, 1 ) ) ) );
		$this->runtime( 'recovery_privileges', $db, 'PARENT_DB', '', array( 'GRANT SELECT, INSERT, CREATE, DROP, TRIGGER ON `parent_db`.* TO `user`@`host`' ) );
		$this->assertSame( array( $settings ), $db->queries );
	}
	public function test_wildcard_grant_matching_obeys_schema_case_rules_and_not_connection_collation(): void {
		$native = $this->scratch_database();
		try {
			$native->query( "SET collation_connection = 'utf8mb4_general_ci'" );
			foreach ( array( array( '5.7.33', 50733 ), array( '8.0.40', 80040 ), array( '10.11.6-MariaDB', 101106 ) ) as list( $version, $number ) ) {
				foreach ( array( 0, 1, 2 ) as $fold ) {
					$settings = 80040 === $number ? array( 'SELECT @@partial_revokes, @@lower_case_table_names' => array( array( 0, $fold ) ) ) : array( 'SELECT @@lower_case_table_names' => array( $fold ) );
					$db = $this->grant_database( $settings, $version, $number, $native );
					foreach ( array( array( 'Parent%', 'parentdb', 0 !== $fold ), array( 'parent%', 'parentdb', true ), array( 'caf%Café', 'cafXCafe', false ), array( 'parent\\_db', 'parent_db', true ), array( 'parent\\_db', 'parentXdb', false ) ) as list( $scope, $schema, $allowed ) ) {
						$ddl = "CREATE TABLE wp_child (\n  FOREIGN KEY (`id`) REFERENCES `$schema`.`wp_parent` (`id`)\n)";
						$grants = array( 'GRANT SELECT, INSERT, CREATE, DROP, TRIGGER ON *.* TO `user`@`host`', 'GRANT REFERENCES ON `' . $scope . '`.* TO `user`@`host`' );
						$accepted = false;
						try { $this->runtime( 'recovery_privileges', $db, 'site', $ddl, $grants ); $accepted = true; }
						catch ( RuntimeException $e ) { $this->assertSame( 'database_recovery_privileges_required', $e->getMessage() ); }
						$this->assertSame( $allowed, $accepted, $version . ':' . $scope );
					}
				}
			}
		} finally { $this->drop_scratch_database( $native ); }
	}
	public function test_overlapping_schema_grants_cannot_manufacture_recovery_permissions(): void {
		$native = $this->scratch_database();
		try {
			$db = $this->grant_database( array( 'SELECT @@partial_revokes, @@lower_case_table_names' => array( array( 0, 0 ) ) ), '8.0.40', 80040, $native );
			$all = 'SELECT, INSERT, CREATE, DROP, TRIGGER';
			foreach ( array(
				array( array( 'GRANT SELECT ON `site_db`.* TO `user`@`host`', 'GRANT INSERT, CREATE, DROP, TRIGGER ON `site%`.* TO `user`@`host`' ), false ),
				array( array( 'GRANT SELECT ON `site\\_db`.* TO `user`@`host`', 'GRANT ' . $all . ' ON `site%`.* TO `user`@`host`' ), false ),
				array( array( 'GRANT SELECT ON `s%`.* TO `user`@`host`', 'GRANT INSERT, CREATE, DROP, TRIGGER ON `s______`.* TO `user`@`host`' ), false ),
				array( array( 'GRANT SELECT ON `s%`.* TO `user`@`host`', 'GRANT INSERT, CREATE, DROP, TRIGGER ON `s_%`.* TO `user`@`host`' ), false ),
				array( array( 'GRANT SELECT ON `site%`.* TO `user`@`host`', 'GRANT ' . $all . ' ON `site\\_db`.* TO `user`@`host`' ), true ),
				array( array( 'GRANT ' . $all . ' ON `site%`.* TO `user`@`host`', 'GRANT SELECT ON `s%`.* TO `user`@`host`' ), true ),
				array( array( 'GRANT SELECT ON `site%`.* TO `user`@`host`', 'GRANT INSERT, CREATE, DROP, TRIGGER ON `site%`.* TO `user`@`host`' ), true ),
				array( array( 'GRANT ' . $all . ' ON *.* TO `user`@`host`', 'GRANT SELECT ON `site%`.* TO `user`@`host`' ), true ),
				array( array( 'GRANT ' . $all . ' ON `site%`.* TO `reader`', 'GRANT SELECT ON `site_db`.* TO `writer`' ), true ),
			) as list( $grants, $allowed ) ) {
				foreach ( array( $grants, array_reverse( $grants ) ) as $order ) {
					$accepted = false;
					try { $this->runtime( 'recovery_privileges', $db, 'site_db', '', $order ); $accepted = true; }
					catch ( RuntimeException $e ) { $this->assertSame( 'database_recovery_privileges_required', $e->getMessage() ); }
					$this->assertSame( $allowed, $accepted );
				}
			}
			// A matching row without REFERENCES still participates in precedence.
			$ddl = "CREATE TABLE wp_child (\n  FOREIGN KEY (`id`) REFERENCES `parent_db`.`wp_parent` (`id`)\n)";
			$grants = array( 'GRANT ' . $all . ' ON *.* TO `user`@`host`', 'GRANT SELECT ON `parent\\_db`.* TO `user`@`host`', 'GRANT REFERENCES ON `parent%`.* TO `user`@`host`' );
			try { $this->runtime( 'recovery_privileges', $db, 'site_db', $ddl, $grants ); $this->fail( 'An ineffective REFERENCES grant was accepted' ); }
			catch ( RuntimeException $e ) { $this->assertSame( 'database_recovery_privileges_required', $e->getMessage() ); }
		} finally { $this->drop_scratch_database( $native ); }
	}
	public function test_generated_invisible_key_metadata_is_enabled_only_on_servers_that_support_it(): void {
		$sql = 'SET SESSION show_gipk_in_create_table_and_information_schema = ON';
		foreach ( array( array( '8.0.40', 80040, true ), array( '8.4.3', 80403, true ), array( '8.0.29', 80029, false ), array( '5.7.33', 50733, false ), array( '10.11.6-MariaDB', 101106, false ) ) as list( $version, $number, $supported ) ) {
			$db = $this->grant_database( array( $sql => array() ), $version, $number );
			$this->runtime( 'show_invisible_keys', $db ); $this->assertSame( $supported ? array( $sql ) : array(), $db->queries );
		}
	}
	public function test_sizing_queries_use_the_native_timeout_syntax_and_refuse_unguarded_servers(): void {
		foreach ( array( array( '8.0.40', 80040, 'SELECT /*+ MAX_EXECUTION_TIME(250) */ SUM(id) FROM wp_t' ), array( '10.11.6-MariaDB', 101106, 'SET STATEMENT max_statement_time=0.25 FOR SELECT SUM(id) FROM wp_t' ) ) as list( $version, $number, $expected ) ) {
			$db = $this->grant_database( array( $expected => array() ), $version, $number );
			$this->runtime( 'bounded_select', $db, 'SELECT SUM(id) FROM wp_t', 0.25 );
			$this->assertSame( array( $expected ), $db->queries );
		}
		$db = $this->grant_database( array(), '5.6.51', 50651 );
		try { $this->runtime( 'bounded_select', $db, 'SELECT SUM(id) FROM wp_t', 1 ); $this->fail( 'Unbounded scan was allowed' ); }
		catch ( RuntimeException $e ) { $this->assertSame( 'database_query_timeout_not_supported', $e->getMessage() ); }
		$this->assertSame( array(), $db->queries );
	}
	public function test_recovery_probe_replays_each_ddl_crash_boundary_without_orphans(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (id INT PRIMARY KEY) ENGINE=InnoDB' );
			foreach ( array( 'reserved', 'created', 'inserted' ) as $stage ) {
				$owner = bin2hex( random_bytes( 16 ) ); $name = 'wp_emcp_probe_' . substr( $owner, 0, 16 );
				$this->state['recovery_probe'] = array( 'name' => $name, 'owner' => $owner, 'stage' => $stage );
				if ( 'inserted' !== $stage ) { $db->query( "CREATE TABLE `$name` (id INT PRIMARY KEY, value VARBINARY(64)) ENGINE=InnoDB COMMENT='emcp:$owner'" ); }
				if ( 'created' === $stage ) { $db->query( "INSERT INTO `$name` VALUES (0,'recovery')" ); }
				$this->state['phase'] = 'snapshot'; $this->install_gate(); $this->command( 'tick' );
				$this->assertSame( 'snapshot', $this->state['phase'], $this->state['code'] ?? '' );
				$this->assertArrayNotHasKey( 'recovery_probe', $this->state );
				$this->assertSame( array( 'wp_t' ), $this->state['tables'] );
				$this->assertSame( 0, $db->query( "SHOW TABLES LIKE '$name'" )->num_rows );
				unset( $this->state['tables'] );
			}
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_probe_name_collision_preserves_foreign_table_and_recovery_state(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_probe_collision (id INT PRIMARY KEY) ENGINE=InnoDB' ); $db->query( 'INSERT INTO wp_probe_collision VALUES (42)' );
			$this->state['recovery_probe'] = array( 'name' => 'wp_probe_collision', 'owner' => str_repeat( 'a', 32 ), 'stage' => 'reserved' );
			$this->state['phase'] = 'snapshot'; $this->install_gate(); $this->command( 'tick' );
			$this->assertSame( 'manual_recovery', $this->state['phase'] );
			$this->assertSame( 'database_probe_cleanup_failed', $this->state['code'] );
			$this->assertSame( '42', $db->query( 'SELECT id FROM wp_probe_collision' )->fetch_row()[0] );
			$this->assertArrayHasKey( 'db', $this->state ); $this->assertArrayHasKey( 'recovery_probe', $this->state );
			$this->assertStringContainsString( 'EMCP_UPDATE_GATE', file_get_contents( $this->root . 'wp-config.php' ) );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_cancelling_snapshot_removes_only_its_owned_probe(): void {
		$db = $this->scratch_database();
		try {
			$owner = str_repeat( 'b', 32 ); $name = 'wp_emcp_probe_cancelled';
			$db->query( "CREATE TABLE `$name` (id INT PRIMARY KEY) ENGINE=InnoDB COMMENT='emcp:$owner'" );
			$this->state['recovery_probe'] = array( 'name' => $name, 'owner' => $owner, 'stage' => 'created' );
			$this->state['phase'] = 'snapshot'; $this->install_gate(); $this->command( 'rollback' );
			$this->assertSame( 'failed', $this->state['phase'] ); $this->assertArrayNotHasKey( 'recovery_probe', $this->state );
			$this->assertSame( 0, $db->query( "SHOW TABLES LIKE '$name'" )->num_rows );
		} finally { $db->query( 'DROP DATABASE `' . $db->query( 'SELECT DATABASE()' )->fetch_row()[0] . '`' ); $db->close(); }
	}
	public function test_database_sizing_has_a_server_enforced_time_limit_and_fails_readiness_closed(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (id INT PRIMARY KEY) ENGINE=InnoDB' ); $db->query( 'INSERT INTO wp_t VALUES (0)' );
			for ( $n = 1; $n < 1024; $n *= 2 ) { $db->query( 'INSERT INTO wp_t SELECT id+' . $n . ' FROM wp_t' ); }
			$start = microtime( true );
			try { $this->runtime( 'bounded_select', $db, 'SELECT SUM(a.id+b.id+c.id) FROM wp_t a CROSS JOIN wp_t b CROSS JOIN wp_t c', 0.05 ); $this->fail( 'Query was not interrupted' ); }
			catch ( RuntimeException $error ) { $this->assertSame( 'database_inspection_time_limit', $error->getMessage() ); }
			$this->assertLessThan( 2, microtime( true ) - $start );
			EMCP_Update_Runtime::$inspection_seconds = 0;
			try { EMCP_Update_Runtime::preflight_database( $this->state['db'] ); $this->fail( 'Readiness ignored inspection budget' ); }
			catch ( RuntimeException $error ) { $this->assertSame( 'database_inspection_time_limit', $error->getMessage() ); }
			$this->assertSame( '1024', $db->query( 'SELECT COUNT(*) FROM wp_t' )->fetch_row()[0] );
			$this->state['phase'] = 'snapshot'; $this->install_gate(); $this->command( 'tick' ); $this->command( 'tick' );
			$this->assertSame( 'failed', $this->state['phase'] ); $this->assertSame( 'database_inspection_time_limit', $this->state['code'] );
			$this->assertSame( '1024', $db->query( 'SELECT COUNT(*) FROM wp_t' )->fetch_row()[0] );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_failed_migration_trigger_and_modified_rows_are_rolled_back_to_the_snapshot(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (id INT PRIMARY KEY) ENGINE=InnoDB' ); $db->query( 'INSERT INTO wp_t VALUES (1)' );
			$this->state['phase'] = 'snapshot'; $this->install_gate();
			for ( $i = 0; $i < 10 && 'snapshot' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'] );
			$db->query( 'CREATE TRIGGER wp_t_new_trigger BEFORE INSERT ON wp_t FOR EACH ROW SET NEW.id=2' );
			$db->query( 'INSERT INTO wp_t VALUES(3)' );
			$this->state['phase'] = 'updating'; $this->command( 'tick' );
			$this->assertSame( 'restoring', $this->state['phase'] );
			for ( $i = 0; $i < 10 && 'restoring' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( array( array( '1' ) ), $db->query( 'SELECT id FROM wp_t' )->fetch_all() );
			$this->assertSame( 0, $db->query( 'SHOW TRIGGERS' )->num_rows );
			$this->command( 'release' ); $this->assertSame( 'rolled_back', $this->state['phase'] );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_bit_values_restore_without_silent_numeric_coercion(): void {
		$this->assert_bit_restore( false );
	}
	public function test_float_values_restore_with_their_original_precision(): void {
		$this->assert_float_restore( false );
	}
	public function test_enum_values_and_set_bitmasks_restore_without_text_aliasing(): void {
		$this->assert_enum_set_restore( false );
	}
	public function test_enum_primary_keys_preserve_zero_and_empty_members_after_interruption(): void {
		$this->assert_enum_set_restore( true );
	}
	private function assert_enum_set_restore( bool $enum_key ): void {
		$db = $this->scratch_database();
		try {
			$db->query( "SET SESSION sql_mode='NO_AUTO_VALUE_ON_ZERO'" );
			$members = implode( ',', array_map( static fn( $i ) => "'v" . $i . "'", range( 0, 63 ) ) );
			$db->query( "CREATE TABLE wp_t (id INT, e ENUM('','ready'), alias_set SET('a','A') COLLATE utf8mb4_general_ci, full_set SET($members), nullable ENUM('','ready') NULL, numeric_enum ENUM('2','1'), numeric_set SET('2','1'), PRIMARY KEY(" . ( $enum_key ? 'e' : 'id' ) . ')) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4' );
			$db->query( 'INSERT INTO wp_t VALUES(1,0,1,18446744073709551615,NULL,1,1),(2,1,2,9223372036854775809,0,2,2),(3,2,3,0,1,0,3)' );
			$sql = 'SELECT id,e+0,alias_set+0,CAST(full_set AS UNSIGNED),nullable+0,numeric_enum+0,numeric_set+0 FROM wp_t ORDER BY id'; $before = $db->query( $sql )->fetch_all();
			$this->assertSame( '0', $before[0][1] ); $this->assertSame( '1', $before[1][1] );
			$this->assertSame( '18446744073709551615', $before[0][3] ); $this->assertSame( '9223372036854775809', $before[1][3] );
			$this->assertGreaterThan( 0, EMCP_Update_Runtime::preflight_database( $this->state['db'] ) );
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 1;
			for ( $n = 0; $n < 15 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$db->query( 'DELETE FROM wp_t' ); $this->command( 'rollback' ); $interrupted = false;
			for ( $n = 0; $n < 25 && 'restoring' === $this->state['phase']; $n++ ) {
				$saved = $this->state; $this->command( 'tick' );
				if ( ! $interrupted && 0 === ( $saved['restore_created'] ?? -1 ) ) { $this->state = $saved; $interrupted = true; }
			}
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertTrue( $interrupted ); $this->assertSame( $before, $db->query( $sql )->fetch_all() );
			$this->command( 'release' ); $this->assertSame( 'rolled_back', $this->state['phase'] );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_keyless_enum_set_snapshots_preserve_distinct_numeric_members_and_duplicates(): void {
		$db = $this->scratch_database();
		try {
			$db->query( "SET SESSION sql_mode='NO_AUTO_VALUE_ON_ZERO'" );
			$db->query( "CREATE TABLE wp_t (e ENUM('','ready'), s SET('a','A') COLLATE utf8mb4_general_ci) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" );
			$db->query( 'INSERT INTO wp_t VALUES(0,1),(1,2),(1,2),(2,3),(NULL,NULL)' );
			$sql = 'SELECT e+0,s+0,COUNT(*) FROM wp_t GROUP BY e+0,s+0 ORDER BY e+0,s+0'; $before = $db->query( $sql )->fetch_all();
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 1;
			for ( $n = 0; $n < 15 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'] ); $db->query( 'DELETE FROM wp_t' ); $this->command( 'rollback' );
			for ( $n = 0; $n < 25 && 'restoring' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( $before, $db->query( $sql )->fetch_all() );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_legacy_enum_set_text_snapshots_keep_numeric_looking_labels_as_text(): void {
		$db = $this->scratch_database();
		try {
			$db->query( "CREATE TABLE wp_t (id INT PRIMARY KEY, e ENUM('7','8'), s SET('1','2')) ENGINE=InnoDB" );
			$db->query( 'INSERT INTO wp_t VALUES(1,1,1),(2,2,2)' );
			$before = $db->query( 'SELECT id,e+0,s+0 FROM wp_t ORDER BY id' )->fetch_all();
			$rows = array_map( array( EMCP_Update_Runtime::class, 'encode_row' ), $db->query( 'SELECT * FROM wp_t ORDER BY id' )->fetch_all( MYSQLI_ASSOC ) );
			$create = $db->query( 'SHOW CREATE TABLE wp_t' )->fetch_row()[1];
			$dir = $this->state['dir'] . '/snapshot-0'; mkdir( $dir, 0700 );
			$this->state['files'] = array(); $this->state['tables'] = array( 'wp_t' ); $this->state['snapshot'] = 'snapshot-0'; $this->state['snapshot_ready'] = true;
			$this->install_gate();
			foreach ( array( 1, 2 ) as $format ) {
				$backup = array( 'create' => $create, 'rows' => $rows );
				if ( 2 === $format ) {
					EMCP_Update_Runtime::write( $dir . '/table-0-chunk-0.php', $rows );
					$backup['format'] = 2; $backup['rows'] = count( $rows );
					$backup['chunks'] = array( array( 'rows' => count( $rows ), 'hash' => hash_file( 'sha256', $dir . '/table-0-chunk-0.php' ) ) );
				}
				EMCP_Update_Runtime::write( $dir . '/table-0.php', $backup );
				$this->state['table_hashes'] = array( hash_file( 'sha256', $dir . '/table-0.php' ) );
				$db->query( 'DELETE FROM wp_t' ); $this->state['phase'] = 'applying'; $this->command( 'rollback' );
				for ( $n = 0; $n < 15 && 'restoring' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
				$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
				$this->assertSame( $before, $db->query( 'SELECT id,e+0,s+0 FROM wp_t ORDER BY id' )->fetch_all() );
			}
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_float_primary_keys_restore_without_collisions_after_interruption(): void {
		$this->assert_float_restore( true );
	}
	private function assert_float_restore( bool $float_key ): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (id INT, f FLOAT, nullable FLOAT NULL, fixed FLOAT(12,4), PRIMARY KEY(' . ( $float_key ? 'f' : 'id' ) . ')) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_t VALUES(1,1.0000001,NULL,123.4567),(2,1.0000002,0.123456789,-123.4567),(3,-1.0000001,-1e-40,0),(4,3.4028234e38,1e-40,0.0001),(5,1e-40,0,999.9999),(6,0,NULL,1),(7,-1e-40,1.0000001,-1)' );
			$sql = 'SELECT id,f+0e0,nullable+0e0,fixed+0e0 FROM wp_t ORDER BY id';
			$before = $db->query( $sql )->fetch_all();
			$this->assertNotSame( $before[0][1], $before[1][1] );
			$this->assertGreaterThan( 0, EMCP_Update_Runtime::preflight_database( $this->state['db'] ) );
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 1;
			for ( $n = 0; $n < 20 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$db->query( 'DELETE FROM wp_t' ); $this->command( 'rollback' ); $interrupted = false;
			for ( $n = 0; $n < 25 && 'restoring' === $this->state['phase']; $n++ ) {
				$saved = $this->state; $this->command( 'tick' );
				if ( ! $interrupted && 0 === ( $saved['restore_created'] ?? -1 ) ) { $this->state = $saved; $interrupted = true; }
			}
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertTrue( $interrupted );
			$this->assertSame( $before, $db->query( $sql )->fetch_all() );
			$this->command( 'release' ); $this->assertSame( 'rolled_back', $this->state['phase'] );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_keyless_float_snapshots_preserve_close_values_and_duplicate_counts(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (f FLOAT NULL) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_t VALUES(1.0000001),(1.0000002),(1.0000001),(1.0000002),(NULL),(0.123456789),(-1e-40)' );
			$sql = 'SELECT f+0e0,COUNT(*) FROM wp_t GROUP BY f ORDER BY f'; $before = $db->query( $sql )->fetch_all();
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 1;
			for ( $n = 0; $n < 20 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$db->query( 'DELETE FROM wp_t' ); $this->command( 'rollback' );
			for ( $n = 0; $n < 25 && 'restoring' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( $before, $db->query( $sql )->fetch_all() );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_bit_primary_keys_restore_without_collisions_after_interruption(): void {
		$this->assert_bit_restore( true );
	}
	private function assert_bit_restore( bool $bit_key ): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (id INT, flag BIT(8), full_width BIT(64), nullable BIT(1) NULL, wide BIT(9), PRIMARY KEY(' . ( $bit_key ? 'flag' : 'id' ) . ')) ENGINE=InnoDB' );
			$db->query( "INSERT INTO wp_t VALUES(1,b'10100101',0xffffffffffffffff,NULL,0x0101),(2,b'01010101',0x0123456789abcdef,b'1',0x01ff),(3,b'00000000',0x00,b'0',0x00),(4,b'11111111',0x01,NULL,0x0100)" );
			$sql = 'SELECT id,HEX(flag),HEX(full_width),HEX(nullable),HEX(wide) FROM wp_t ORDER BY id';
			$before = $db->query( $sql )->fetch_all();
			$this->assertSame( 'A5', $before[0][1] );
			$this->assertGreaterThan( 0, EMCP_Update_Runtime::preflight_database( $this->state['db'] ) );
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 1;
			for ( $n = 0; $n < 15 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$db->query( 'DELETE FROM wp_t' ); $this->command( 'rollback' ); $interrupted = false;
			for ( $n = 0; $n < 20 && 'restoring' === $this->state['phase']; $n++ ) {
				$saved = $this->state; $this->command( 'tick' );
				if ( ! $interrupted && 0 === ( $saved['restore_created'] ?? -1 ) ) {
					$this->state = $saved; $interrupted = true; // Lose the journal response after a committed INSERT.
				}
			}
			$this->assertTrue( $interrupted );
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( $before, $db->query( $sql )->fetch_all() );
			$this->command( 'release' ); $this->assertSame( 'rolled_back', $this->state['phase'] );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_invisible_primary_key_and_hidden_values_are_projected_and_resume_exactly(): void {
		$this->state['phase'] = 'snapshot'; $this->state['tables'] = array( 'wp_invisible' ); $this->state['table_index'] = 0;
		$this->state['table_snapshot'] = array( 'create' => 'CREATE TABLE wp_invisible (secret_id INT PRIMARY KEY, value TEXT, hidden BLOB)', 'columns' => array( 'secret_id', 'value', 'hidden' ), 'types' => array( 'secret_id' => 'int', 'value' => 'text', 'hidden' => 'blob' ), 'collations' => array(), 'keys' => array( 'secret_id' ), 'max_row' => 1000, 'max_packet' => 67108864, 'bytes' => 1000, 'rows' => 0, 'chunks' => array(), 'last' => null );
		$dir = $this->state['dir'] . '/snapshot-0'; mkdir( $dir, 0700 ); EMCP_Update_Runtime::$tick_rows = 1;
		$rows = array( array( 'secret_id' => '0', 'value' => 'first', 'hidden' => "\x00\xff" ), array( 'secret_id' => '1', 'value' => null, 'hidden' => '' ), array( 'secret_id' => '2', 'value' => 'last', 'hidden' => null ) );
		$select = 'SELECT `secret_id`,`value`,`hidden` FROM `wp_invisible`';
		$queries = array( $select . ' ORDER BY `secret_id` LIMIT 1' => array( $rows[0] ) );
		foreach ( $rows as $i => $row ) { $queries[ $select . " WHERE (`secret_id`) > (CAST(CONVERT(X'" . bin2hex( $row['secret_id'] ) . "' USING utf8mb4) AS DECIMAL(65,0))) ORDER BY `secret_id` LIMIT 1" ] = isset( $rows[ $i + 1 ] ) ? array( $rows[ $i + 1 ] ) : array(); }
		$db = new class( $queries ) {
			public function __construct( private array $queries ) {}
			public function query( $sql, $mode ) {
				if ( ! array_key_exists( $sql, $this->queries ) ) { throw new LogicException( 'Snapshot omitted an explicitly selected invisible column: ' . $sql ); }
				return new class( $this->queries[ $sql ] ) extends ArrayIterator {
					public function fetch_assoc() { if ( ! $this->valid() ) { return null; } $row = $this->current(); $this->next(); return $row; }
					public function free() {}
				};
			}
		};
		$chunk = new ReflectionMethod( EMCP_Update_Runtime::class, 'snapshot_table_chunk' );
		$chunk->invokeArgs( null, array( &$this->state, $db, $dir ) ); $saved = $this->state;
		$chunk->invokeArgs( null, array( &$this->state, $db, $dir ) ); $this->state = $saved;
		for ( $i = 0; $i < 3; $i++ ) { $chunk->invokeArgs( null, array( &$this->state, $db, $dir ) ); }
		$manifest = EMCP_Update_Runtime::read( $dir . '/table-0.php' );
		$this->assertSame( 3, $manifest['rows'] ); $this->assertSame( 1, $this->state['table_index'] );
		$actual = array();
		foreach ( $manifest['chunks'] as $i => $info ) { foreach ( EMCP_Update_Runtime::read( $dir . '/table-0-chunk-' . $i . '.php' ) as $row ) { $actual[] = EMCP_Update_Runtime::decode_row( $row ); } }
		$this->assertSame( $rows, $actual );
	}
	public function test_native_invisible_columns_and_generated_key_restore_when_mysql_eight_is_available(): void {
		$db = $this->scratch_database();
		try {
			if ( false !== stripos( $db->server_info, 'MariaDB' ) || $db->server_version < 80023 ) { $this->markTestSkipped( 'Native invisible column test requires MySQL 8.0.23+.' ); }
			$db->query( "SET SESSION sql_mode = 'NO_AUTO_VALUE_ON_ZERO'" );
			$db->query( 'CREATE TABLE wp_t (secret_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT INVISIBLE PRIMARY KEY, value TEXT, hidden BLOB INVISIBLE) ENGINE=InnoDB' );
			$db->query( "INSERT INTO wp_t(secret_id,value,hidden) VALUES(0,'zero',X'00ff'),(5,NULL,''),(9,'last',NULL)" );
			$before = $db->query( 'SELECT secret_id,value,hidden FROM wp_t ORDER BY secret_id' )->fetch_all();
			$this->assertGreaterThan( 0, EMCP_Update_Runtime::preflight_database( $this->state['db'] ) );
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 1;
			for ( $n = 0; $n < 10 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$db->query( 'DELETE FROM wp_t' ); $this->command( 'rollback' );
			for ( $n = 0; $n < 15 && 'restoring' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( $before, $db->query( 'SELECT secret_id,value,hidden FROM wp_t ORDER BY secret_id' )->fetch_all() );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_large_table_snapshot_and_interrupted_restore_are_bounded_and_exact(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_large (id BIGINT PRIMARY KEY, value LONGBLOB NULL) ENGINE=InnoDB' );
			$db->query( "INSERT INTO wp_large VALUES (0,REPEAT('0123456789abcdef',32))" );
			for ( $size = 1; $size < 65536; $size *= 2 ) { $db->query( 'INSERT INTO wp_large SELECT id+' . $size . ',value FROM wp_large' ); }
			$db->query( 'UPDATE wp_large SET value=NULL WHERE id % 101=0' );
			$before = $db->query( 'SELECT COUNT(*), SUM(CRC32(CONCAT(id,COALESCE(HEX(value),"NULL")))) FROM wp_large' )->fetch_row();
			$this->assertGreaterThan( 20971520, EMCP_Update_Runtime::preflight_database( $this->state['db'] ) );
			$this->state['phase'] = 'snapshot'; $this->install_gate();
			EMCP_Update_Runtime::$tick_bytes = 700000;
			$this->command( 'tick' ); $this->command( 'tick' );
			$this->assertSame( 'snapshot', $this->state['phase'] );
			$this->assertGreaterThan( 0, $this->state['table_snapshot']['rows'] );
			$saved = $this->state; $this->command( 'tick' );
			// Discard the cursor save after durable chunk files, as on a killed process.
			$this->state = $saved;
			for ( $n = 0; $n < 150 && 'snapshot' === $this->state['phase']; $n++ ) {
				$this->command( 'tick' );
				$this->state = EMCP_Update_Runtime::read( $this->state['dir'] . '/state.php' );
			}
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$manifest = EMCP_Update_Runtime::read( $this->state['dir'] . '/snapshot-0/table-0.php' );
			$this->assertSame( 65536, $manifest['rows'] );
			$this->assertGreaterThan( 50, count( $manifest['chunks'] ) );
			$db->query( 'DELETE FROM wp_large' ); $db->query( "INSERT INTO wp_large VALUES (999999,'changed')" );
			$this->command( 'rollback' );
			for ( $n = 0; $n < 200 && ! isset( $this->state['restore_created'] ); $n++ ) { $this->command( 'tick' ); }
			$this->assertArrayHasKey( 'restore_created', $this->state );
			$saved = $this->state; $this->command( 'tick' ); $this->state = $saved;
			// Finish in fresh PHP processes with a memory limit below the table's
			// encoded size, proving that standalone restore never loads it all.
			EMCP_Update_Runtime::write( $this->state['dir'] . '/state.php', $this->state );
			$step = $this->state['dir'] . '/step.php';
			file_put_contents( $step, '<?php ini_set("memory_limit","32M"); require __DIR__."/runtime.php"; $s=EMCP_Update_Runtime::read(__DIR__."/state.php"); EMCP_Update_Runtime::advance($s,array("action"=>"tick","phase"=>$s["phase"],"group"=>$s["group"])); echo $s["phase"];' );
			for ( $n = 0; $n < 150; $n++ ) {
				$out = $this->php( $step );
				$this->assertContains( $out, array( 'restoring', 'verify_restore' ) );
				if ( 'verify_restore' === $out ) { break; }
			}
			$this->assertSame( 'verify_restore', $out );
			$this->assertSame( $before, $db->query( 'SELECT COUNT(*), SUM(CRC32(CONCAT(id,COALESCE(HEX(value),"NULL")))) FROM wp_large' )->fetch_row() );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_chunked_snapshot_preserves_composite_keys_and_keyless_duplicate_binary_rows(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_keys (a BIGINT, b VARBINARY(20), value LONGBLOB NULL, PRIMARY KEY(a,b)) ENGINE=InnoDB' );
			$db->query( 'CREATE TABLE wp_duplicates (value LONGBLOB NULL) ENGINE=InnoDB' );
			for ( $i = 0; $i < 12; $i++ ) {
				$db->query( 'INSERT INTO wp_keys VALUES (' . intdiv( $i, 3 ) . ", X'" . bin2hex( (string) ( $i % 3 ) ) . "', X'00ff275c')" );
				$db->query( "INSERT INTO wp_duplicates VALUES (X'00ff275c'),(X'4161'),(X'6141'),(NULL),(''),(CONCAT(REPEAT('x',2048),'" . $i . "'))" );
			}
			$before = $db->query( 'SELECT SHA2(value,256), COUNT(*) FROM wp_duplicates GROUP BY SHA2(value,256) ORDER BY SHA2(value,256)' )->fetch_all();
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 3;
			for ( $i = 0; $i < 15 && 'snapshot' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$db->query( 'DELETE FROM wp_keys' ); $db->query( 'DELETE FROM wp_duplicates' );
			$this->command( 'rollback' );
			for ( $i = 0; $i < 50 && 'restoring' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( '12', $db->query( 'SELECT COUNT(*) FROM wp_keys' )->fetch_row()[0] );
			$this->assertSame( $before, $db->query( 'SELECT SHA2(value,256), COUNT(*) FROM wp_duplicates GROUP BY SHA2(value,256) ORDER BY SHA2(value,256)' )->fetch_all() );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_primary_key_cursors_preserve_large_integers_collations_and_enum_order(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_numbers (id BIGINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_numbers VALUES (9007199254740992),(9007199254740993),(18446744073709551614),(18446744073709551615)' );
			$db->query( 'CREATE TABLE wp_text (id VARCHAR(30) CHARACTER SET latin1 COLLATE latin1_swedish_ci PRIMARY KEY) ENGINE=InnoDB' );
			$db->query( "INSERT INTO wp_text VALUES ('a'),('B'),('z'),('ä')" );
			$db->query( "CREATE TABLE wp_enum (id ENUM('z','b','a') PRIMARY KEY) ENGINE=InnoDB" ); $db->query( "INSERT INTO wp_enum VALUES ('z'),('b'),('a')" );
			$before = array();
			foreach ( array( 'wp_enum', 'wp_numbers', 'wp_text' ) as $table ) { $before[ $table ] = $db->query( 'SELECT id FROM ' . $table . ' ORDER BY id' )->fetch_all(); }
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 1;
			for ( $i = 0; $i < 15 && 'snapshot' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			foreach ( array_keys( $before ) as $table ) { $db->query( 'DELETE FROM ' . $table ); }
			$this->command( 'rollback' );
			for ( $i = 0; $i < 30 && 'restoring' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			foreach ( $before as $table => $rows ) { $this->assertSame( $rows, $db->query( 'SELECT id FROM ' . $table . ' ORDER BY id' )->fetch_all() ); }
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_corrupt_later_chunk_is_refused_before_dropping_the_table(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (id INT PRIMARY KEY) ENGINE=InnoDB' ); $db->query( 'INSERT INTO wp_t VALUES (1),(2),(3)' );
			$this->state['phase'] = 'snapshot'; $this->install_gate(); EMCP_Update_Runtime::$tick_rows = 1;
			for ( $i = 0; $i < 10 && 'snapshot' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'] );
			file_put_contents( $this->state['dir'] . '/snapshot-0/table-0-chunk-2.php', 'corrupted' );
			$db->query( 'INSERT INTO wp_t VALUES (4)' ); $this->command( 'rollback' );
			for ( $i = 0; $i < 10 && 'restoring' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'manual_recovery', $this->state['phase'] );
			$this->assertSame( 'snapshot_corrupt', $this->state['code'] );
			$this->assertSame( '4', $db->query( 'SELECT COUNT(*) FROM wp_t' )->fetch_row()[0] );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_database_readiness_rejects_the_same_unsupported_shapes_as_snapshot(): void {
		$db = $this->scratch_database();
		try {
			foreach ( array(
				'innodb_required' => 'CREATE TABLE wp_t (id INT) ENGINE=MyISAM',
				'generated_columns_not_supported' => 'CREATE TABLE wp_t (id INT, computed INT GENERATED ALWAYS AS (id+1) STORED) ENGINE=InnoDB',
				'database_row_too_large' => 'CREATE TABLE wp_t (id INT, value LONGBLOB) ENGINE=InnoDB',
			) as $expected => $ddl ) {
				$db->query( $ddl );
				if ( 'database_row_too_large' === $expected ) { $db->query( "INSERT INTO wp_t VALUES (1,REPEAT('x',5000000))" ); }
				try { EMCP_Update_Runtime::preflight_database( $this->state['db'] ); $this->fail( 'Readiness accepted ' . $expected ); }
				catch ( RuntimeException $error ) { $this->assertSame( $expected, $error->getMessage() ); }
				$db->query( 'DROP TABLE wp_t' );
			}
			$db->query( 'CREATE TABLE wp_t (id INT) ENGINE=InnoDB' );
			$db->query( 'CREATE TRIGGER wp_t_trigger BEFORE INSERT ON wp_t FOR EACH ROW SET NEW.id=1' );
			try { EMCP_Update_Runtime::preflight_database( $this->state['db'] ); $this->fail( 'Readiness accepted triggers' ); }
			catch ( RuntimeException $error ) { $this->assertSame( 'database_triggers_not_supported', $error->getMessage() ); }
		} finally { $this->drop_scratch_database( $db ); }
	}
	/** Inspect the real enrollment class in a fresh process with a disposable site root. */
	private function readiness( array $dropins, array $constants = array() ): array {
		$script = $this->root . 'inspect.php'; $db = $this->state['db'];
		$source = '<?php define("ABSPATH",' . var_export( $this->root, true ) . ');';
		foreach ( array( 'DB_HOST' => $db['host'], 'DB_USER' => $db['user'], 'DB_PASSWORD' => $db['password'], 'DB_NAME' => $db['name'], 'WP_CONTENT_DIR' => $this->root . 'wp-content', 'WP_PLUGIN_DIR' => $this->root . 'wp-content/plugins' ) as $key => $value ) {
			$source .= 'define(' . var_export( $key, true ) . ',' . var_export( $value, true ) . ');';
		}
		foreach ( $constants as $key => $value ) { $source .= 'define(' . var_export( $key, true ) . ',' . var_export( $value, true ) . ');'; }
		$source .= '$wpdb=(object)array("prefix"=>"wp_"); function is_multisite(){return false;} function is_ssl(){return true;} function home_url(){return "https://fixture.invalid";} function site_url(){return home_url();} function untrailingslashit($s){return rtrim($s,"/");} function wp_normalize_path($s){return str_replace("\\\\","/",$s);} function get_option($s){return false;} function wp_using_ext_object_cache(){return false;} function get_dropins(){return ' . var_export( $dropins, true ) . ';}';
		$source .= 'require ' . var_export( dirname( __DIR__ ) . '/includes/cloud/class-safe-updates.php', true ) . '; echo json_encode((new ReflectionMethod("EMCP_Tools_Safe_Updates","blockers"))->invoke(null));';
		file_put_contents( $script, $source );
		return json_decode( $this->php( $script ), true, 512, JSON_THROW_ON_ERROR );
	}
	public function test_readiness_accepts_page_cache_but_keeps_other_dropins_and_permissions_blocked(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (id INT PRIMARY KEY) ENGINE=InnoDB' );
			mkdir( $this->root . 'wp-content/plugins', 0700, true );
			file_put_contents( $this->root . 'wp-content/advanced-cache.php', $this->rocket_dropin() );
			$this->assertSame( array(), $this->readiness( array( 'advanced-cache.php' => array() ) ) );
			foreach ( array( '<?php /* Unknown cache engine */', $this->rocket_dropin( $this->root . 'custom-cache/' ) ) as $source ) {
				file_put_contents( $this->root . 'wp-content/advanced-cache.php', $source );
				$this->assertContains( 'page_cache_adapter_not_supported', $this->readiness( array( 'advanced-cache.php' => array() ) ) );
			}
			file_put_contents( $this->root . 'wp-content/advanced-cache.php', $this->rocket_dropin() );
			$this->assertContains( 'dropin_requires_host_recovery:object-cache.php', $this->readiness( array( 'advanced-cache.php' => array(), 'object-cache.php' => array() ) ) );
			$this->assertContains( 'dropin_requires_host_recovery:db.php', $this->readiness( array( 'db.php' => array() ) ) );
			chmod( $this->root . 'wp-content/advanced-cache.php', 0444 );
			try { $this->assertContains( 'files_not_writable', $this->readiness( array( 'advanced-cache.php' => array() ) ) ); }
			finally { chmod( $this->root . 'wp-content/advanced-cache.php', 0644 ); }
			mkdir( $this->root . 'wp-content/cache/wp-rocket', 0700, true );
			$cached = $this->root . 'wp-content/cache/wp-rocket/index.html'; file_put_contents( $cached, 'stale' ); chmod( $cached, 0444 );
			try { $this->assertContains( 'page_cache_not_writable', $this->readiness( array( 'advanced-cache.php' => array() ) ) ); }
			finally { chmod( $cached, 0644 ); }
			$db->query( 'ALTER TABLE wp_t ENGINE=MyISAM' );
			$this->assertContains( 'innodb_required', $this->readiness( array() ) );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_readiness_validates_predefined_tenweb_cache_paths_in_fresh_processes(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_t (id INT PRIMARY KEY) ENGINE=InnoDB' );
			mkdir( $this->root . 'wp-content/plugins', 0700, true );
			file_put_contents( $this->root . 'wp-content/advanced-cache.php', "<?php define('TENWEB_SO_ADVANCED_CACHE',true); define('TENWEB_SO_PAGE_CACHE_DIR', WP_CONTENT_DIR . '/cache/tw_optimize/page_cache/');" );
			$default = $this->root . 'wp-content/cache/tw_optimize/page_cache/';
			$this->assertSame( array(), $this->readiness( array( 'advanced-cache.php' => array() ) ) );
			foreach ( array( $this->root . 'custom-cache/', rtrim( $default, '/' ), $default . '../other/', '', false, null ) as $path ) {
				$this->assertContains( 'page_cache_adapter_not_supported', $this->readiness( array( 'advanced-cache.php' => array() ), array( 'TENWEB_SO_PAGE_CACHE_DIR' => $path ) ) );
			}
			foreach ( array( $default, $default . '/' ) as $path ) {
				$this->assertSame( array(), $this->readiness( array( 'advanced-cache.php' => array() ), array( 'TENWEB_SO_PAGE_CACHE_DIR' => $path ) ) );
			}
			if ( '\\' === DIRECTORY_SEPARATOR ) {
				$this->assertSame( array(), $this->readiness( array( 'advanced-cache.php' => array() ), array( 'TENWEB_SO_PAGE_CACHE_DIR' => str_replace( '/', '\\', $default ) ) ) );
			}
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_predefined_tenweb_override_blocks_purge_before_any_cache_is_deleted(): void {
		$default = $this->root . 'wp-content/cache/tw_optimize/page_cache/site/source.html';
		$custom = $this->root . 'custom-cache/site/source.html';
		foreach ( array( $default, $custom ) as $file ) { mkdir( dirname( $file ), 0700, true ); file_put_contents( $file, 'preserve until supported' ); }
		file_put_contents( $this->root . 'wp-content/advanced-cache.php', "<?php define('TENWEB_SO_ADVANCED_CACHE',true); define('TENWEB_SO_PAGE_CACHE_DIR', WP_CONTENT_DIR . '/cache/tw_optimize/page_cache/');" );
		$script = $this->root . 'purge-override.php';
		$root = $this->root;
		$write_script = static function ( $path ) use ( $script, $root ) {
			// Keep one root spelling: Windows __DIR__ expands sys_get_temp_dir()'s 8.3 alias.
			file_put_contents( $script, '<?php define("ABSPATH",' . var_export( $root, true ) . '); define("TENWEB_SO_PAGE_CACHE_DIR",' . var_export( $path, true ) . '); require ' . var_export( dirname( __DIR__ ) . '/includes/cloud/safe-update-runtime.php', true ) . '; try { EMCP_Update_Runtime::page_caches(ABSPATH,true); echo "accepted"; } catch (RuntimeException $e) {echo $e->getMessage();}' );
		};
		$write_script( $this->root . 'custom-cache/' );
		$this->assertSame( 'page_cache_adapter_not_supported', $this->php( $script ) );
		$this->assertFileExists( $default ); $this->assertFileExists( $custom );
		$write_script( $this->root . 'wp-content/cache/tw_optimize/page_cache/' );
		$this->assertSame( 'accepted', $this->php( $script ) );
		$this->assertFileDoesNotExist( $default ); $this->assertFileExists( $custom );
	}
	public function test_page_cache_is_purged_on_success_and_rollback_preserving_configuration(): void {
		foreach ( array( array( 'verify', 'approve' ), array( 'verify_restore', 'release' ) ) as list( $phase, $action ) ) {
			foreach ( array( 'wp-content/cache/wp-rocket/site/index.html', 'wp-content/cache/tw_optimize/page_cache/site/source.html', 'wp-content/wp-rocket-config/site.php', 'wp-content/10web-page-cache-config/config.json', 'wp-content/cache/other/keep.txt' ) as $path ) {
				if ( ! is_dir( dirname( $this->root . $path ) ) ) { mkdir( dirname( $this->root . $path ), 0700, true ); }
				file_put_contents( $this->root . $path, 'cache or configuration' );
			}
			$this->state['phase'] = $phase; $this->state['group'] = 1; unset( $this->state['cleaned'] ); $this->install_gate();
			$this->command( $action );
			$this->assertContains( $this->state['phase'], array( 'completed', 'rolled_back' ) );
			$this->assertFileDoesNotExist( $this->root . 'wp-content/cache/wp-rocket/site/index.html' );
			$this->assertFileDoesNotExist( $this->root . 'wp-content/cache/tw_optimize/page_cache/site/source.html' );
			$this->assertFileExists( $this->root . 'wp-content/wp-rocket-config/site.php' );
			$this->assertFileExists( $this->root . 'wp-content/10web-page-cache-config/config.json' );
			$this->assertFileExists( $this->root . 'wp-content/cache/other/keep.txt' );
		}
	}
	public function test_static_caches_are_purged_before_baseline_and_again_after_drain(): void {
		mkdir( $this->root . 'wp-content/cache/wp-rocket/site', 0700, true );
		mkdir( $this->root . 'wp-content/cache/tw_optimize/page_cache/site', 0700, true );
		file_put_contents( $this->root . 'wp-content/advanced-cache.php', $this->rocket_dropin() );
		$caches = array( 'wp-content/cache/wp-rocket/site/index.html', 'wp-content/cache/tw_optimize/page_cache/site/index.html' );
		foreach ( $caches as $cache ) { file_put_contents( $this->root . $cache, 'stale before gate' ); }
		$this->command( 'tick' ); $this->assertSame( 'baseline', $this->state['phase'] );
		foreach ( $caches as $cache ) { $this->assertFileDoesNotExist( $this->root . $cache ); }
		$this->assertStringContainsString( 'EMCP_UPDATE_GATE', file_get_contents( $this->root . 'wp-config.php' ) );
		$this->command( 'approve' );
		foreach ( $caches as $cache ) { mkdir( dirname( $this->root . $cache ), 0700, true ); file_put_contents( $this->root . $cache, 'old request finished during drain' ); }
		$this->state['drain_until'] = time() - 1; $this->command( 'tick' );
		$this->assertSame( 'snapshot', $this->state['phase'] );
		foreach ( $caches as $cache ) { $this->assertFileDoesNotExist( $this->root . $cache ); }
	}
	public function test_cache_purge_restarts_after_gate_installation_and_entry_failure_reopens_unchanged_site(): void {
		mkdir( $this->root . 'wp-content/cache/wp-rocket', 0700, true );
		$cached = $this->root . 'wp-content/cache/wp-rocket/index.html'; file_put_contents( $cached, 'stale' );
		$this->install_gate( '<?php /* original */' ); // Killed after installing the gate, before saving baseline.
		$this->command( 'tick' ); $this->assertSame( 'baseline', $this->state['phase'] ); $this->assertFileDoesNotExist( $cached );
		$this->command( 'rollback' );
		unset( $this->state['cleaned'] ); $this->state['phase'] = 'prepared';
		EMCP_Update_Runtime::write( $this->state['dir'] . '/original-config.php', '<?php /* original */' );
		file_put_contents( $cached, 'readonly' ); chmod( $cached, 0444 );
		try { $this->command( 'tick' ); }
		finally { chmod( $cached, 0644 ); }
		$this->assertSame( 'failed', $this->state['phase'] ); $this->assertSame( 'page_cache_not_writable', $this->state['code'] );
		$this->assertSame( '<?php /* original */', file_get_contents( $this->root . 'wp-config.php' ) );
		$this->assertArrayNotHasKey( 'snapshot_ready', $this->state );
	}
	public function test_unknown_and_custom_cache_layouts_are_blocked_but_native_defaults_are_supported(): void {
		mkdir( $this->root . 'wp-content', 0700 ); $file = $this->root . 'wp-content/advanced-cache.php';
		foreach ( array( '<?php /* Another page cache */', $this->rocket_dropin( $this->root . 'external-cache/' ), "<?php define('TENWEB_SO_ADVANCED_CACHE',true); define('TENWEB_SO_PAGE_CACHE_DIR','/custom/cache/');" ) as $source ) {
			file_put_contents( $file, $source );
			try { EMCP_Update_Runtime::page_caches( $this->root ); $this->fail( 'Unpurgeable cache accepted' ); }
			catch ( RuntimeException $error ) { $this->assertSame( 'page_cache_adapter_not_supported', $error->getMessage() ); }
		}
		file_put_contents( $file, $this->rocket_dropin() ); $this->assertSame( 'wp-rocket', EMCP_Update_Runtime::cache_adapter( $this->root ) );
		file_put_contents( $file, $this->rocket_dropin( str_replace( '/', '\\', $this->root . 'wp-content/cache/wp-rocket/' ) ) );
		$this->assertSame( 'wp-rocket', EMCP_Update_Runtime::cache_adapter( $this->root ) );
		$quoted = $this->root . "quoted'site/"; mkdir( $quoted . 'wp-content', 0700, true );
		file_put_contents( $quoted . 'wp-content/advanced-cache.php', $this->rocket_dropin( $quoted . 'wp-content/cache/wp-rocket/' ) );
		$this->assertSame( 'wp-rocket', EMCP_Update_Runtime::cache_adapter( $quoted ) );
		file_put_contents( $file, "<?php use TenWebOptimizer\\WebPageCache\\OptimizerWebPageCache; define('TENWEB_SO_ADVANCED_CACHE',true); define('TENWEB_SO_PAGE_CACHE_DIR', WP_CONTENT_DIR . '/cache/tw_optimize/page_cache/');" );
		$this->assertSame( '10web', EMCP_Update_Runtime::cache_adapter( $this->root ) );
	}
	public function test_failed_later_group_purges_caches_before_reopening_and_retains_gate_if_purge_fails(): void {
		$cached = $this->root . 'wp-content/cache/wp-rocket/index.html'; mkdir( dirname( $cached ), 0700, true );
		foreach ( array( 'rollback', 'tick', 'unwritable' ) as $failure ) {
			file_put_contents( $cached, 'old approved group' );
			file_put_contents( $this->root . 'index.php', '<?php /* changed */' );
			$this->state['phase'] = 'snapshot'; $this->state['group'] = 1;
			unset( $this->state['cleaned'] ); $this->install_gate();
			if ( 'tick' === $failure ) {
				$this->state['files'] = array( array( 'path' => 'index.php', 'hash' => str_repeat( '0', 64 ) ) );
				$this->state['tables'] = array(); $this->state['file_index'] = 0; $this->state['table_index'] = 0;
			}
			if ( 'unwritable' === $failure ) { chmod( $cached, 0444 ); }
			try { $this->command( 'tick' === $failure ? 'tick' : 'rollback' ); }
			finally { if ( file_exists( $cached ) ) { chmod( $cached, 0644 ); } }
			if ( 'unwritable' === $failure ) {
				$this->assertSame( 'manual_recovery', $this->state['phase'] ); $this->assertSame( 'page_cache_cleanup_failed', $this->state['code'] );
				$this->assertStringContainsString( 'EMCP_UPDATE_GATE', file_get_contents( $this->root . 'wp-config.php' ) );
			} else {
				$this->assertSame( 'failed', $this->state['phase'] ); $this->assertFileDoesNotExist( $cached );
				$this->assertStringNotContainsString( 'EMCP_UPDATE_GATE', file_get_contents( $this->root . 'wp-config.php' ) );
			}
		}
	}
	public function test_renamed_foreign_key_tables_restore_after_interrupted_schema_reset(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_parent (id INT PRIMARY KEY) ENGINE=InnoDB' );
			$db->query( 'CREATE TABLE wp_child (id INT PRIMARY KEY, parent INT, CONSTRAINT shared_fk FOREIGN KEY(parent) REFERENCES wp_parent(id)) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_parent VALUES(1)' ); $db->query( 'INSERT INTO wp_child VALUES(2,1)' );
			$db->query( 'CREATE TABLE unrelated (id INT PRIMARY KEY) ENGINE=InnoDB' ); $db->query( 'INSERT INTO unrelated VALUES(99)' );
			$ddl = $db->query( 'SHOW CREATE TABLE wp_child' )->fetch_row()[1];
			$this->state['phase'] = 'snapshot'; $this->install_gate();
			for ( $n = 0; $n < 15 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'] );
			$db->query( 'RENAME TABLE wp_child TO wp_shadow' );
			$db->query( 'CREATE TABLE wp_child (id INT PRIMARY KEY, parent INT) ENGINE=InnoDB' );
			$db->query( 'CREATE VIEW wp_new_view AS SELECT id FROM wp_parent' );
			$this->command( 'rollback' ); EMCP_Update_Runtime::$tick_rows = 1; $interrupted = false;
			for ( $n = 0; $n < 40 && 'restoring' === $this->state['phase']; $n++ ) {
				$saved = $this->state; $this->command( 'tick' );
				if ( ! $interrupted && ! empty( $saved['restore_reset']['cursor'] ) && empty( $saved['restore_reset']['done'] ) ) {
					$this->state = $saved; $interrupted = true; // Replay a DROP whose cursor save was lost.
				}
			}
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertTrue( $interrupted );
			$this->assertSame( array( array( '2', '1' ) ), $db->query( 'SELECT * FROM wp_child' )->fetch_all() );
			$this->assertSame( $ddl, $db->query( 'SHOW CREATE TABLE wp_child' )->fetch_row()[1] );
			$this->assertSame( array( array( '99' ) ), $db->query( 'SELECT * FROM unrelated' )->fetch_all() );
			$this->assertSame( 0, $db->query( "SHOW TABLES LIKE 'wp_shadow'" )->num_rows );
			$this->assertSame( 0, $db->query( "SHOW TABLES LIKE 'wp_new_view'" )->num_rows );
			$this->command( 'release' ); $this->assertSame( 'rolled_back', $this->state['phase'] );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_swapped_baseline_tables_cannot_keep_each_others_foreign_key_names(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_parent (id INT PRIMARY KEY) ENGINE=InnoDB' ); $db->query( 'INSERT INTO wp_parent VALUES(1)' );
			foreach ( array( 'a', 'b' ) as $i => $suffix ) {
				$db->query( 'CREATE TABLE wp_' . $suffix . ' (id INT PRIMARY KEY, parent INT, CONSTRAINT fk_' . $suffix . ' FOREIGN KEY(parent) REFERENCES wp_parent(id)) ENGINE=InnoDB' );
				$db->query( 'INSERT INTO wp_' . $suffix . ' VALUES(' . ( $i + 2 ) . ',1)' );
			}
			$this->state['phase'] = 'snapshot'; $this->install_gate();
			for ( $n = 0; $n < 15 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'] );
			$db->query( 'RENAME TABLE wp_a TO wp_swap, wp_b TO wp_a, wp_swap TO wp_b' ); $this->command( 'rollback' );
			for ( $n = 0; $n < 30 && 'restoring' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( array( array( '2', '1' ) ), $db->query( 'SELECT * FROM wp_a' )->fetch_all() );
			$this->assertSame( array( array( '3', '1' ) ), $db->query( 'SELECT * FROM wp_b' )->fetch_all() );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_corrupt_later_table_preserves_live_tables_and_renamed_backup_before_reset(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_parent (id INT PRIMARY KEY) ENGINE=InnoDB' ); $db->query( 'INSERT INTO wp_parent VALUES(1)' );
			$db->query( 'CREATE TABLE wp_child (id INT PRIMARY KEY, parent INT, CONSTRAINT shared_fk FOREIGN KEY(parent) REFERENCES wp_parent(id)) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_child VALUES(2,1)' );
			$this->state['phase'] = 'snapshot'; $this->install_gate();
			for ( $n = 0; $n < 15 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'] );
			$db->query( 'RENAME TABLE wp_child TO wp_shadow' ); $db->query( 'CREATE TABLE wp_child (id INT PRIMARY KEY) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_child VALUES(99)' );
			$parent = array_search( 'wp_parent', $this->state['tables'], true );
			file_put_contents( $this->state['dir'] . '/snapshot-0/table-' . $parent . '-chunk-0.php', 'corrupt' );
			$this->command( 'rollback' );
			for ( $n = 0; $n < 20 && 'restoring' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'manual_recovery', $this->state['phase'] ); $this->assertSame( 'snapshot_corrupt', $this->state['code'] );
			$this->assertSame( array( array( '99' ) ), $db->query( 'SELECT * FROM wp_child' )->fetch_all() );
			$this->assertSame( array( array( '2', '1' ) ), $db->query( 'SELECT * FROM wp_shadow' )->fetch_all() );
			$this->assertSame( array( array( '1' ) ), $db->query( 'SELECT * FROM wp_parent' )->fetch_all() );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_constraint_owner_outside_prefix_stops_before_dropping_scoped_tables(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_parent (id INT PRIMARY KEY) ENGINE=InnoDB' ); $db->query( 'INSERT INTO wp_parent VALUES(1)' );
			$db->query( 'CREATE TABLE wp_child (id INT PRIMARY KEY, parent INT, CONSTRAINT shared_fk FOREIGN KEY(parent) REFERENCES wp_parent(id)) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_child VALUES(2,1)' );
			$this->state['phase'] = 'snapshot'; $this->install_gate();
			for ( $n = 0; $n < 15 && 'snapshot' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'] );
			$db->query( 'RENAME TABLE wp_child TO archive_child' ); $db->query( 'CREATE TABLE wp_child (id INT PRIMARY KEY) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_child VALUES(99)' ); $this->command( 'rollback' );
			for ( $n = 0; $n < 20 && 'restoring' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'manual_recovery', $this->state['phase'] ); $this->assertSame( 'database_recovery_constraint_outside_scope', $this->state['code'] );
			$this->assertSame( array( array( '99' ) ), $db->query( 'SELECT * FROM wp_child' )->fetch_all() );
			$this->assertSame( array( array( '2', '1' ) ), $db->query( 'SELECT * FROM archive_child' )->fetch_all() );
			$this->assertSame( array( array( '1' ) ), $db->query( 'SELECT * FROM wp_parent' )->fetch_all() );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_foreign_keys_restore_and_parent_permission_checks_fail_closed(): void {
		$db = $this->scratch_database();
		try {
			$db->query( 'CREATE TABLE wp_parent (id INT PRIMARY KEY) ENGINE=InnoDB' );
			$db->query( 'CREATE TABLE wp_child (id INT PRIMARY KEY, parent INT, FOREIGN KEY(parent) REFERENCES wp_parent(id)) ENGINE=InnoDB' );
			$db->query( 'INSERT INTO wp_parent VALUES(1)' ); $db->query( 'INSERT INTO wp_child VALUES(2,1)' );
			$ddl = $db->query( 'SHOW CREATE TABLE wp_child' )->fetch_row()[1]; $name = $this->state['db']['name'];
			$grants = array( "GRANT SELECT, INSERT, CREATE, DROP, TRIGGER ON `$name`.* TO `fixture`@`localhost`" );
			try { $this->runtime( 'recovery_privileges', $db, $name, $ddl, $grants ); $this->fail( 'Missing REFERENCES accepted' ); }
			catch ( RuntimeException $error ) { $this->assertSame( 'database_recovery_privileges_required', $error->getMessage() ); }
			$grants[] = "GRANT REFERENCES ON `$name`.* TO `fixture`@`localhost`";
			$this->runtime( 'recovery_privileges', $db, $name, $ddl, $grants );
			$grants[] = "REVOKE TRIGGER ON `$name`.* FROM `fixture`@`localhost`";
			try { $this->runtime( 'recovery_privileges', $db, $name, $ddl, $grants ); $this->fail( 'Revoked TRIGGER accepted' ); }
			catch ( RuntimeException $error ) { $this->assertSame( 'database_recovery_privileges_required', $error->getMessage() ); }
			$this->assertGreaterThan( 0, EMCP_Update_Runtime::preflight_database( $this->state['db'] ) );
			$this->state['phase'] = 'snapshot'; $this->install_gate();
			for ( $i = 0; $i < 10 && 'snapshot' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'] );
			$db->query( 'DELETE FROM wp_child' ); $db->query( 'DELETE FROM wp_parent' ); $this->command( 'rollback' );
			for ( $i = 0; $i < 15 && 'restoring' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( array( array( '2', '1' ) ), $db->query( 'SELECT * FROM wp_child' )->fetch_all() );
			$this->assertSame( $ddl, $db->query( 'SHOW CREATE TABLE wp_child' )->fetch_row()[1] );
		} finally { $this->drop_scratch_database( $db ); }
	}
	public function test_guarded_journal_round_trip_and_receipt_does_not_expose_secrets(): void {
		$this->state['db'] = array( 'password' => 'private' );
		EMCP_Update_Runtime::write( $this->state['dir'] . '/state.php', $this->state );
		$this->assertStringStartsWith( '<?php exit; ?>', file_get_contents( $this->state['dir'] . '/state.php' ) );
		$this->assertSame( $this->state, EMCP_Update_Runtime::read( $this->state['dir'] . '/state.php' ) );
		$this->assertArrayNotHasKey( 'db', EMCP_Update_Runtime::receipt( $this->state ) );
	}
	public function test_preparation_does_not_change_config_until_authenticated_tick(): void {
		$this->assertStringNotContainsString( 'EMCP_UPDATE_GATE', file_get_contents( $this->root . 'wp-config.php' ) );
		$this->command( 'tick' );
		$this->assertSame( 'baseline', $this->state['phase'] );
		$this->assertStringContainsString( 'EMCP_UPDATE_GATE', file_get_contents( $this->root . 'wp-config.php' ) );
		$this->command( 'rollback' );
		$this->assertSame( 'failed', $this->state['phase'] );
		$this->assertSame( '<?php /* original */', file_get_contents( $this->root . 'wp-config.php' ) );
	}
	public function test_changed_config_before_start_fails_closed_without_overwriting_it(): void {
		file_put_contents( $this->root . 'wp-config.php', '<?php /* changed elsewhere */' );
		$this->command( 'tick' );
		$this->assertSame( 'manual_recovery', $this->state['phase'] );
		$this->assertSame( '<?php /* changed elsewhere */', file_get_contents( $this->root . 'wp-config.php' ) );
	}
	public function test_baseline_approval_waits_for_old_requests_to_drain(): void {
		$this->command( 'tick' ); $this->command( 'approve' );
		$this->assertSame( 'draining', $this->state['phase'] );
		$p = EMCP_Update_Runtime::receipt( $this->state )['progress'];
		$this->assertGreaterThanOrEqual( 119, $p['drain_remaining_seconds'] );
		$this->command( 'tick' ); $this->assertSame( 'draining', $this->state['phase'] );
		$this->state['drain_until'] = time() - 1; $this->command( 'tick' );
		$this->assertSame( 'snapshot', $this->state['phase'] );
	}
	public function test_snapshot_scan_resumes_with_identical_scope_and_private_progress(): void {
		mkdir( $this->root . 'wp-content/plugins/demo', 0700, true );
		mkdir( $this->root . 'wp-content/uploads', 0700, true );
		for ( $i = 0; $i < 7; $i++ ) { file_put_contents( $this->root . 'wp-content/plugins/demo/' . $i . '.php', 'content-' . $i ); }
		file_put_contents( $this->root . 'wp-content/uploads/excluded.txt', 'private upload' );
		$this->state['phase'] = 'snapshot'; EMCP_Update_Runtime::$scan_entries = 2;
		$scan = new ReflectionMethod( EMCP_Update_Runtime::class, 'scan_snapshot' );
		$scan->invokeArgs( null, array( &$this->state ) );
		$this->assertArrayHasKey( 'scan', $this->state );
		for ( $i = 0; $i < 30 && isset( $this->state['scan'] ); $i++ ) {
			EMCP_Update_Runtime::write( $this->state['dir'] . '/state.php', $this->state );
			$this->state = EMCP_Update_Runtime::read( $this->state['dir'] . '/state.php' );
			$scan->invokeArgs( null, array( &$this->state ) );
		}
		$this->assertArrayNotHasKey( 'scan', $this->state );
		$this->assertCount( 7, $this->state['files'] );
		$this->assertCount( 7, array_unique( array_column( $this->state['files'], 'path' ) ) );
		$this->assertSame( 63, $this->state['snapshot_bytes_total'] );
		$this->assertStringNotContainsString( 'demo', json_encode( EMCP_Update_Runtime::receipt( $this->state ) ) );
	}
	public function test_changed_or_corrupt_previous_snapshot_falls_back_to_a_fresh_copy(): void {
		foreach ( array( 'changed', 'corrupt', 'unchanged' ) as $case ) {
			$old = $this->state['dir'] . '/snapshot-0'; $new = $this->state['dir'] . '/snapshot-1';
			if ( ! is_dir( $old ) ) { mkdir( $old ); mkdir( $new ); }
			file_put_contents( $this->root . 'index.php', 'current' );
			file_put_contents( $old . '/file-0.php', EMCP_Update_Runtime::GUARD . ( 'unchanged' === $case ? 'current' : 'old' ) );
			@unlink( $new . '/file-0.php' );
			$this->state['phase'] = 'snapshot'; $this->state['group'] = 1;
			$this->state['files'] = array( array( 'path' => 'index.php', 'mode' => 0644, 'hash' => hash( 'sha256', 'current' ) ) );
			$this->state['tables'] = array(); $this->state['file_index'] = 0; $this->state['table_index'] = 0;
			$this->state['previous_snapshot'] = 'snapshot-0'; $this->state['files_reused'] = 0;
			$this->state['previous_files'] = array( 'index.php' => array( 'hash' => hash( 'sha256', 'changed' === $case ? 'old' : 'current' ), 'index' => 0 ) );
			$this->command( 'tick' );
			$this->assertSame( 'applying', $this->state['phase'] );
			$this->assertSame( 'unchanged' === $case && function_exists( 'link' ) ? 1 : 0, $this->state['files_reused'] );
			$this->assertSame( EMCP_Update_Runtime::GUARD . 'current', file_get_contents( $new . '/file-0.php' ) );
		}
	}
	public function test_stale_approval_cannot_advance_a_later_group(): void {
		$this->state['phase'] = 'verify';
		$input = array( 'action' => 'approve', 'phase' => 'verify', 'group' => 0 );
		EMCP_Update_Runtime::advance( $this->state, $input );
		$this->assertSame( 1, $this->state['group'] );
		$this->state['phase'] = 'verify';
		EMCP_Update_Runtime::advance( $this->state, $input );
		$this->assertSame( 'verify', $this->state['phase'] ); $this->assertSame( 1, $this->state['group'] );
	}
	public function test_interrupted_updater_is_never_replayed(): void {
		$this->state['phase'] = 'updating'; $this->state['snapshot_ready'] = true;
		$this->command( 'tick' );
		$this->assertSame( 'restoring', $this->state['phase'] );
		$this->assertSame( 'update_interrupted', $this->state['code'] );
	}
	public function test_deadline_causes_recovery_instead_of_another_update(): void {
		$this->state['phase'] = 'applying'; $this->state['snapshot_ready'] = true; $this->state['deadline'] = time() - 1;
		$this->command( 'tick' ); $this->assertSame( 'restoring', $this->state['phase'] );
	}
	public function test_restore_is_not_reported_successful_until_explicit_health_confirmation(): void {
		$this->command( 'tick' ); $this->state['phase'] = 'verify_restore';
		$this->command( 'tick' ); $this->assertSame( 'verify_restore', $this->state['phase'] );
		$this->command( 'release' ); $this->assertSame( 'rolled_back', $this->state['phase'] );
		$this->assertSame( '<?php /* original */', file_get_contents( $this->root . 'wp-config.php' ) );
	}

	/**
	 * Host malware scanners flag decoding next to file writes (issue #100, the 3.14
	 * restore engine), so the recovery runtime stores database values as hex.
	 */
	public function test_recovery_files_carry_no_base64_decoding(): void {
		foreach ( array( 'safe-update-runtime.php', 'safe-update-gate.php', 'class-safe-updates.php' ) as $file ) {
			$this->assertStringNotContainsString( 'base64_', (string) file_get_contents( dirname( __DIR__ ) . '/includes/cloud/' . $file ), $file );
		}
		$row = array( 'a' => 'bytes' . chr( 0 ) . chr( 255 ) . "'\"", 'b' => null, 'c' => '' );
		$this->assertSame( $row, EMCP_Update_Runtime::decode_row( EMCP_Update_Runtime::encode_row( $row ) ) );
	}

	/** A restored non-PHP file (an upload holding PHP code) must never sit under a .php name, even briefly. */
	public function test_temporary_copies_keep_a_non_executable_name(): void {
		$this->assertStringEndsWith( '.tmp', EMCP_Update_Runtime::temp_path( '/site/wp-content/uploads/photo.jpg' ) );
		$this->assertStringEndsWith( '.tmp', EMCP_Update_Runtime::temp_path( '/site/.htaccess' ) );
		$this->assertStringEndsWith( '.php', EMCP_Update_Runtime::temp_path( '/site/.emcp-update-x/state.php' ) );
		$this->assertNotSame( EMCP_Update_Runtime::temp_path( '/site/a.php' ), EMCP_Update_Runtime::temp_path( '/site/a.php' ) );
	}

	/** Snapshots and restore deletions stay inside what updates write; other apps and user files are never touched. */
	public function test_snapshot_scope_excludes_other_apps_uploads_and_backups(): void {
		foreach ( array( 'index.php', 'wp-admin/a.php', 'wp-includes/b.php', 'wp-content/plugins/p/p.php', 'wp-content/themes/t/style.css', 'wp-content/languages/x.mo', 'shop/app.php', 'wp-content/uploads/2026/photo.jpg', 'wp-content/cache/page.html', 'wp-content/emcp-backups/site.emcp', 'wp-content/emcp-backups-3f9a1c/emcp_x/site.emcp' ) as $file ) {
			if ( ! is_dir( dirname( $this->root . $file ) ) ) { mkdir( dirname( $this->root . $file ), 0700, true ); }
			file_put_contents( $this->root . $file, 'x' );
		}
		$files = ( new ReflectionMethod( EMCP_Update_Runtime::class, 'files' ) )->invoke( null, $this->state, false );
		$paths = array_column( $files, 'path' );
		sort( $paths );
		$this->assertSame( array( 'index.php', 'wp-admin/a.php', 'wp-content/languages/x.mo', 'wp-content/plugins/p/p.php', 'wp-content/themes/t/style.css', 'wp-includes/b.php' ), $paths );
	}

	/** Files the job could not snapshot or restore are found before the maintenance window starts, and named. */
	public function test_preflight_names_files_the_job_cannot_write(): void {
		mkdir( $this->root . 'wp-includes', 0700 );
		file_put_contents( $this->root . 'wp-includes/locked.php', 'x' );
		file_put_contents( $this->root . 'wp-includes/open.php', 'x' );
		chmod( $this->root . 'wp-includes/locked.php', 0444 );
		try {
			EMCP_Update_Runtime::preflight_files( $this->root );
			$this->fail( 'expected files_not_writable' );
		} catch ( RuntimeException $e ) {
			$this->assertSame( 'files_not_writable', $e->getMessage() );
			$this->assertSame( array( 'wp-includes/locked.php' ), EMCP_Update_Runtime::$last_unwritable );
		} finally {
			chmod( $this->root . 'wp-includes/locked.php', 0644 );
		}
		chmod( $this->root . 'wp-includes/locked.php', 0644 );
		EMCP_Update_Runtime::preflight_files( $this->root );
		$this->assertSame( array(), EMCP_Update_Runtime::$last_unwritable );
	}

	public function test_host_marker_is_preserved_while_mu_plugins_remain_in_snapshot_and_prune_scope(): void {
		mkdir( $this->root . 'wp-content/mu-plugins', 0700, true );
		$mu = 'wp-content/mu-plugins/host.php';
		file_put_contents( $this->root . $mu, '<?php /* host integration */' );
		file_put_contents( $this->root . '.wp-launcher-ready', 'host-owned' );
		chmod( $this->root . '.wp-launcher-ready', 0444 );
		try {
			EMCP_Update_Runtime::preflight_files( $this->root );
			$files = ( new ReflectionMethod( EMCP_Update_Runtime::class, 'files' ) )->invoke( null, $this->state, false );
			$this->assertSame( array( $mu ), array_column( $files, 'path' ) );
			$this->state['files'] = $files;
			file_put_contents( $this->root . 'wp-content/mu-plugins/new.php', '<?php throw new Exception("broken");' );
			( new ReflectionMethod( EMCP_Update_Runtime::class, 'prune' ) )->invoke( null, $this->state );
			$this->assertFileDoesNotExist( $this->root . 'wp-content/mu-plugins/new.php' );
			$this->assertSame( 'host-owned', file_get_contents( $this->root . '.wp-launcher-ready' ) );
			$this->assertFileExists( $this->root . $mu );
		} finally { chmod( $this->root . '.wp-launcher-ready', 0644 ); }
		$this->assertTrue( EMCP_Update_Runtime::in_scope( '.htaccess', false ) );
		$this->assertTrue( EMCP_Update_Runtime::in_scope( '.user.ini', false ) );
		$this->assertTrue( EMCP_Update_Runtime::in_scope( 'wp-content/plugins/x/.wp-launcher-ready', false ) );
	}

	public function test_gate_blocks_before_a_broken_mu_plugin_can_execute(): void {
		$this->state['phase'] = 'restoring';
		$this->install_gate( '<?php throw new Exception("MU plugin loaded");' );
		$out = $this->visit();
		$this->assertStringContainsString( 'Scheduled maintenance', $out );
		$this->assertStringNotContainsString( 'MU plugin loaded', $out );
	}

	/** Real file + MySQL snapshot, then fresh-process recovery while MU PHP cannot boot. */
	public function test_standalone_rollback_restores_broken_mu_plugin_and_database_preserving_host_marker(): void {
		$conf = getenv( 'EMCP_SAFE_UPDATE_TEST_DB' );
		if ( ! $conf || ! extension_loaded( 'mysqli' ) ) { $this->markTestSkipped( 'EMCP_SAFE_UPDATE_TEST_DB not set.' ); }
		list( $host, $user, $pass ) = array_pad( explode( '|', $conf ), 3, '' );
		$name = 'emcp_su_' . bin2hex( random_bytes( 4 ) );
		mysqli_report( MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT );
		$admin = new mysqli( $host, $user, $pass );
		$admin->query( 'CREATE DATABASE `' . $name . '`' );
		try {
			$admin->select_db( $name );
			$admin->query( 'CREATE TABLE wp_options (id INT PRIMARY KEY, value TEXT) ENGINE=InnoDB' );
			$admin->query( "INSERT INTO wp_options VALUES (1,'before')" );
			$admin->query( 'CREATE TABLE wp_hostinger_ai_version_options (id BIGINT PRIMARY KEY, version_id BIGINT, option_name VARCHAR(191), option_value LONGTEXT) ENGINE=InnoDB' );
			$admin->query( 'CREATE TABLE wp_hostinger_ai_version_posts (id BIGINT PRIMARY KEY, version_id BIGINT, post_id BIGINT, post_author BIGINT, post_content LONGTEXT, post_title TEXT, post_status VARCHAR(20), post_type VARCHAR(20)) ENGINE=InnoDB' );
			$admin->query( "INSERT INTO wp_hostinger_ai_version_options VALUES (1,2,'sample','history-before')" );
			mkdir( $this->root . 'wp-content/mu-plugins', 0700, true );
			$mu = $this->root . 'wp-content/mu-plugins/host.php';
			$original = '<?php echo "HOST HEALTHY";';
			file_put_contents( $mu, $original );
			file_put_contents( $this->root . '.wp-launcher-ready', 'host-owned' );
			chmod( $this->root . '.wp-launcher-ready', 0444 );
			$this->state['db'] = array( 'host' => $host, 'user' => $user, 'password' => $pass, 'name' => $name, 'prefix' => 'wp_' );
			$this->state['phase'] = 'snapshot';
			$this->install_gate();
			for ( $i = 0; $i < 10 && 'snapshot' === $this->state['phase']; $i++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertTrue( $this->state['snapshot_ready'] );
			$this->assertContains( 'wp_hostinger_ai_version_options', $this->state['tables'] );
			$this->assertContains( 'wp_hostinger_ai_version_posts', $this->state['tables'] );
			// A second group must checkpoint the new database, even when its files can be reused.
			$admin->query( "UPDATE wp_options SET value='after-first-group'" );
			$this->state['phase'] = 'verify'; $this->command( 'approve' );
			$this->command( 'tick' ); // Scan and initialize the new checkpoint.
			$this->assertSame( 'snapshot', $this->state['phase'] );
			$this->command( 'tick' ); // Small tables share this request with file copying.
			$this->assertSame( 'applying', $this->state['phase'], $this->state['code'] ?? '' );
			$this->assertSame( count( $this->state['tables'] ), $this->state['table_index'] );
			$this->assertGreaterThan( 0, $this->state['files_reused'] );
			file_put_contents( $mu, '<?php throw new Exception("broken host integration");' );
			file_put_contents( $this->root . 'wp-content/mu-plugins/added.php', '<?php die("bad");' );
			$admin->query( "UPDATE wp_options SET value='after'" );
			$admin->query( "UPDATE wp_hostinger_ai_version_options SET option_value='history-after'" );
			$this->command( 'rollback' );
			$script = $this->state['dir'] . '/step.php';
			file_put_contents( $script, '<?php require __DIR__ . "/runtime.php"; $s = EMCP_Update_Runtime::read(__DIR__ . "/state.php"); EMCP_Update_Runtime::advance($s, array("action" => "tick", "phase" => $s["phase"], "group" => $s["group"])); echo $s["phase"];' );
			for ( $i = 0; $i < 10; $i++ ) {
				$out = $this->php( $script );
				$this->assertContains( $out, array( 'restoring', 'verify_restore' ) );
				if ( 'verify_restore' === $out ) { break; }
			}
			$this->assertSame( 'verify_restore', $out );
			$this->assertSame( $original, file_get_contents( $mu ) );
			$this->assertSame( 'HOST HEALTHY', $this->php( $mu ) );
			$this->assertFileDoesNotExist( $this->root . 'wp-content/mu-plugins/added.php' );
			$this->assertSame( 'after-first-group', $admin->query( 'SELECT value FROM wp_options' )->fetch_row()[0] );
			$this->assertSame( 'history-before', $admin->query( 'SELECT option_value FROM wp_hostinger_ai_version_options' )->fetch_row()[0] );
			$this->assertSame( 'host-owned', file_get_contents( $this->root . '.wp-launcher-ready' ) );
			$this->state = EMCP_Update_Runtime::read( $this->state['dir'] . '/state.php' );
			$this->command( 'release' );
			$this->assertSame( 'rolled_back', $this->state['phase'] );
			// A real overlapping installation remains blocked by the standalone snapshot check.
			$admin->query( 'CREATE TABLE wp_shop_options (option_id BIGINT PRIMARY KEY, option_name VARCHAR(191), option_value LONGTEXT, autoload VARCHAR(20)) ENGINE=InnoDB' );
			$admin->query( 'CREATE TABLE wp_shop_posts (ID BIGINT PRIMARY KEY, post_author BIGINT, post_content LONGTEXT, post_title TEXT, post_status VARCHAR(20), post_type VARCHAR(20)) ENGINE=InnoDB' );
			try {
				( new ReflectionMethod( EMCP_Update_Runtime::class, 'tables' ) )->invoke( null, $admin, 'wp_' );
				$this->fail( 'Expected overlapping installation to remain blocked' );
			} catch ( RuntimeException $error ) { $this->assertSame( 'shared_database_prefix', $error->getMessage() ); }
		} finally {
			chmod( $this->root . '.wp-launcher-ready', 0644 );
			$admin->query( 'DROP DATABASE `' . $name . '`' ); $admin->close();
		}
	}

	/** A second WordPress install whose prefix extends ours (wp_shop_ under wp_) must never be snapshotted or restored. */
	public function test_other_installs_sharing_the_prefix_are_detected(): void {
		$tables = array( 'wp_options', 'wp_posts', 'wp_wc_orders', 'wp_actionscheduler_actions', 'wp_shop_options', 'wp_shop_posts', 'wp_shop_usermeta', 'wp_forms_options' );
		$this->assertSame( array( 'wp_shop_' ), EMCP_Update_Runtime::other_installs( $tables, 'wp_' ) );
		$this->assertSame( array(), EMCP_Update_Runtime::other_installs( array( 'wp_options', 'wp_posts', 'wp_wc_orders', 'wp_forms_options' ), 'wp_' ) );
		$this->assertSame( array(), EMCP_Update_Runtime::other_installs( array( 'wp_options', 'wp_posts', 'wp_shop_options', 'wp_shop_posts' ), 'wp_shop_' ) );
	}

	public function test_hostinger_history_tables_are_not_mistaken_for_an_install_but_real_installs_are(): void {
		$schema = array(
			'wp_hostinger_ai_version_options' => array( 'id', 'version_id', 'option_name', 'option_value' ),
			'wp_hostinger_ai_version_posts' => array( 'id', 'version_id', 'post_id', 'post_author', 'post_content', 'post_title', 'post_status', 'post_type' ),
			'wp_shop_options' => array( 'option_id', 'option_name', 'option_value', 'autoload' ),
			'wp_shop_posts' => array( 'ID', 'post_author', 'post_content', 'post_title', 'post_status', 'post_type' ),
		);
		$reader = static fn( $table ) => $schema[ $table ];
		$this->assertSame( array(), EMCP_Update_Runtime::other_installs( array_slice( array_keys( $schema ), 0, 2 ), 'wp_', $reader ) );
		$this->assertSame( array( 'wp_shop_' ), EMCP_Update_Runtime::other_installs( array_keys( $schema ), 'wp_', $reader ) );
		// The policy is schema-based, not a host-specific prefix exemption.
		$schema['wp_hostinger_ai_version_options'] = $schema['wp_shop_options'];
		$this->assertSame( array( 'wp_hostinger_ai_version_', 'wp_shop_' ), EMCP_Update_Runtime::other_installs( array_keys( $schema ), 'wp_', static fn( $table ) => $schema[ $table ] ) );
	}

	public function test_unreadable_candidate_schema_fails_closed(): void {
		$this->expectExceptionMessage( 'database_schema_unavailable' );
		EMCP_Update_Runtime::other_installs( array( 'wp_shop_options', 'wp_shop_posts' ), 'wp_', static fn() => array() );
	}

	private function install_gate( string $original = "<?php echo 'SITE';" ): void {
		copy( dirname( __DIR__ ) . '/includes/cloud/safe-update-runtime.php', $this->state['dir'] . '/runtime.php' );
		copy( dirname( __DIR__ ) . '/includes/cloud/safe-update-gate.php', $this->state['dir'] . '/gate.php' );
		EMCP_Update_Runtime::write( $this->state['dir'] . '/original-config.php', $original );
		file_put_contents( $this->root . 'wp-config.php', EMCP_Update_Runtime::gate_line( $this->state['dir'] ) . $original );
		EMCP_Update_Runtime::write( $this->state['dir'] . '/state.php', $this->state );
	}
	/** A visitor request: like wp-load.php, the entry script includes wp-config.php. */
	private function visit(): string {
		file_put_contents( $this->root . 'index.php', '<?php require __DIR__ . "/wp-config.php";' );
		return $this->php( $this->root . 'index.php' );
	}
	private function php( string $script ): string {
		return (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $script ) . ' 2>&1' );
	}

	/** Cloud going silent before any update ran must not leave the site in maintenance past the deadline. */
	public function test_gate_reopens_an_expired_window_when_nothing_was_changed(): void {
		foreach ( array( array( 'baseline', 0 ), array( 'draining', 0 ), array( 'snapshot', 0 ) ) as list( $phase, $group ) ) {
			$this->state['phase'] = $phase; $this->state['group'] = $group; $this->state['deadline'] = time() - 1;
			$this->install_gate();
			$this->assertSame( 'SITE', $this->visit(), $phase );
			$state = EMCP_Update_Runtime::read( $this->state['dir'] . '/state.php' );
			$this->assertSame( array( 'failed', 'deadline_exceeded' ), array( $state['phase'], $state['code'] ), $phase );
			$this->assertSame( "<?php echo 'SITE';", file_get_contents( $this->root . 'wp-config.php' ), $phase );
		}
	}

	/** Once an update may have run, only an explicit restore can reopen the site. */
	public function test_gate_keeps_maintenance_after_updates_may_have_run(): void {
		foreach ( array( array( 'verify', 0 ), array( 'updating', 0 ), array( 'snapshot', 1 ), array( 'restoring', 0 ), array( 'verify_restore', 0 ), array( 'manual_recovery', 0 ) ) as list( $phase, $group ) ) {
			$this->state['phase'] = $phase; $this->state['group'] = $group; $this->state['deadline'] = time() - 1;
			$this->install_gate();
			$this->assertStringContainsString( 'Scheduled maintenance', $this->visit(), $phase );
			$this->assertSame( $phase, EMCP_Update_Runtime::read( $this->state['dir'] . '/state.php' )['phase'], $phase );
		}
	}

	/** A deleted or quarantined job folder shows the maintenance page instead of a fatal error on every request. */
	public function test_missing_job_folder_shows_maintenance_instead_of_a_fatal(): void {
		file_put_contents( $this->root . 'wp-config.php', EMCP_Update_Runtime::gate_line( $this->root . '.emcp-update-gone' ) . "<?php echo 'SITE';" );
		$out = $this->visit();
		$this->assertStringContainsString( 'Scheduled maintenance', $out );
		$this->assertStringNotContainsString( 'SITE', $out );
		$this->assertStringNotContainsString( 'Fatal', $out );
	}

	/** The plugin's own copies refuse direct requests; only the copies inside a job folder run. */
	public function test_source_files_refuse_direct_requests(): void {
		$this->assertSame( '', $this->php( dirname( __DIR__ ) . '/includes/cloud/safe-update-gate.php' ) );
		file_put_contents( $this->root . 'probe.php', '<?php require ' . var_export( dirname( __DIR__ ) . '/includes/cloud/safe-update-runtime.php', true ) . '; echo "LOADED";' );
		$this->assertSame( '', $this->php( $this->root . 'probe.php' ) );
	}

	/** A finished job keeps only an authenticated receipt: no credentials, original config, offers or snapshots. */
	public function test_finished_job_keeps_only_a_receipt(): void {
		foreach ( array( array( 'verify', 'approve', 'completed' ), array( 'verify_restore', 'release', 'rolled_back' ) ) as list( $phase, $action, $terminal ) ) {
			$this->state['phase'] = $phase; $this->state['group'] = 1; $this->state['snapshot'] = 'snapshot-1';
			$this->state['db'] = array( 'password' => 'private' );
			$this->state['groups'][1][0]['_source'] = array( 'key' => 'b/b.php', 'offer' => array( 'package' => 'https://example.com/b.zip?key=secret' ) );
			$this->install_gate();
			mkdir( $this->state['dir'] . '/snapshot-1', 0700 ); file_put_contents( $this->state['dir'] . '/snapshot-1/file-0.php', 'x' );
			$this->command( $action );
			$this->assertSame( $terminal, $this->state['phase'] );
			$stored = EMCP_Update_Runtime::read( $this->state['dir'] . '/state.php' );
			$this->assertSame( $terminal, $stored['phase'] );
			$this->assertArrayNotHasKey( 'db', $stored );
			$this->assertStringNotContainsString( 'secret', json_encode( $stored ) );
			$this->assertFileDoesNotExist( $this->state['dir'] . '/snapshot-1' );
			$this->assertFileDoesNotExist( $this->state['dir'] . '/original-config.php' );
			$this->assertFileDoesNotExist( $this->state['dir'] . '/gate.php' );
			$this->assertSame( "<?php echo 'SITE';", file_get_contents( $this->root . 'wp-config.php' ) );
			unset( $stored['cleaned'] );
			$this->state = $stored + array( 'groups' => array( array( array( 'id' => 'plugin:a' ) ), array( array( 'id' => 'plugin:b' ) ) ) );
		}
	}

	/** File restore and snapshot work stay within a per-request byte budget. */
	public function test_file_restore_is_bounded_per_request(): void {
		$this->state['phase'] = 'restoring'; $this->state['snapshot'] = 'snapshot-0'; $this->state['restore_step'] = 0; $this->state['restore_db'] = 0;
		$this->state['restore_pruned'] = true; $this->state['tables'] = array();
		mkdir( $this->state['dir'] . '/snapshot-0', 0700 );
		foreach ( array( 'a', 'b', 'c' ) as $i => $name ) {
			$this->state['files'][] = array( 'path' => $name . '.php', 'mode' => 0644, 'hash' => hash( 'sha256', $name ) );
			file_put_contents( $this->state['dir'] . '/snapshot-0/file-' . $i . '.php', EMCP_Update_Runtime::GUARD . $name );
		}
		EMCP_Update_Runtime::$tick_bytes = 1;
		$this->command( 'tick' );
		$this->assertSame( 1, $this->state['restore_step'] );
		$this->assertFileDoesNotExist( $this->root . 'b.php' );
	}

	/** Files left by an interrupted write (such as a temporary copy) are swept before the database is restored. */
	public function test_restore_sweeps_files_left_by_interrupted_writes(): void {
		$this->state['phase'] = 'restoring'; $this->state['snapshot'] = 'snapshot-0'; $this->state['restore_step'] = 0; $this->state['restore_db'] = 0;
		$this->state['restore_pruned'] = true; $this->state['files'] = array(); $this->state['tables'] = array();
		mkdir( $this->state['dir'] . '/snapshot-0', 0700 );
		mkdir( $this->root . 'wp-content/plugins/p', 0700, true );
		file_put_contents( $this->root . 'wp-content/plugins/p/p.php.0123456789ab.php', 'leftover' );
		$this->state['db'] = array( 'host' => '127.0.0.1:1', 'user' => 'x', 'password' => '', 'name' => 'x', 'prefix' => 'wp_' );
		$this->command( 'tick' );
		$this->assertFileDoesNotExist( $this->root . 'wp-content/plugins/p/p.php.0123456789ab.php' );
	}

	/**
	 * A restore killed between a committed insert and the journal save resumes from the
	 * rows actually present, never duplicating or skipping any. Needs a scratch MySQL server:
	 * EMCP_SAFE_UPDATE_TEST_DB="host|user|password".
	 */
	public function test_interrupted_table_restore_resumes_exactly(): void {
		$conf = getenv( 'EMCP_SAFE_UPDATE_TEST_DB' );
		if ( ! $conf || ! extension_loaded( 'mysqli' ) ) { $this->markTestSkipped( 'EMCP_SAFE_UPDATE_TEST_DB not set.' ); }
		list( $host, $user, $pass ) = array_pad( explode( '|', $conf ), 3, '' );
		$name = 'emcp_su_' . bin2hex( random_bytes( 4 ) );
		mysqli_report( MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT );
		$admin = new mysqli( $host, $user, $pass );
		$admin->query( 'CREATE DATABASE `' . $name . '`' );
		try {
			$create = 'CREATE TABLE `wp_t` (`id` bigint NOT NULL AUTO_INCREMENT, `v` longblob, PRIMARY KEY (`id`)) ENGINE=InnoDB';
			$rows = array();
			for ( $i = 0; $i < 25; $i++ ) { $rows[] = EMCP_Update_Runtime::encode_row( array( 'id' => (string) $i, 'v' => 0 === $i % 5 ? null : random_bytes( 40 ) . "'\\" ) ); }
			$this->state['db'] = array( 'host' => $host, 'user' => $user, 'password' => $pass, 'name' => $name, 'prefix' => 'wp_' );
			$this->state['phase'] = 'restoring'; $this->state['snapshot'] = 'snapshot-0'; $this->state['restore_step'] = 0; $this->state['restore_db'] = 0;
			$this->state['restore_pruned'] = true; $this->state['restore_swept'] = true; $this->state['files'] = array(); $this->state['tables'] = array( 'wp_t' );
			mkdir( $this->state['dir'] . '/snapshot-0', 0700 );
			EMCP_Update_Runtime::write( $this->state['dir'] . '/snapshot-0/table-0.php', array( 'create' => $create, 'rows' => $rows ) );
			$this->state['table_hashes'] = array( hash_file( 'sha256', $this->state['dir'] . '/snapshot-0/table-0.php' ) );
			EMCP_Update_Runtime::$tick_rows = 7;
			$this->command( 'tick' );
			$saved = $this->state;
			$this->command( 'tick' ); // Committed, then "killed": the journal never records it.
			$this->state = $saved;
			for ( $n = 0; $n < 10 && 'restoring' === $this->state['phase']; $n++ ) { $this->command( 'tick' ); }
			$this->assertSame( 'verify_restore', $this->state['phase'] );
			$db = new mysqli( $host, $user, $pass, $name );
			$got = array();
			foreach ( $db->query( 'SELECT * FROM `wp_t` ORDER BY id' ) as $row ) { $got[] = EMCP_Update_Runtime::encode_row( $row ); }
			$this->assertSame( $rows, $got );
			$db->close();
		} finally {
			$admin->query( 'DROP DATABASE `' . $name . '`' );
			$admin->close();
		}
	}
}
