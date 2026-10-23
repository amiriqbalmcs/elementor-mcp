<?php
use PHPUnit\Framework\TestCase;
require_once dirname( __DIR__ ) . '/includes/cloud/safe-update-runtime.php';

/** Optional native Apache/CGI smoke. Owns only a random temp root and a loopback port. */
final class SafeUpdateApacheCacheTest extends TestCase {
	public function test_static_rocket_hits_stop_before_baseline_and_authenticated_probes_still_boot(): void {
		$apache = getenv( 'EMCP_SAFE_UPDATE_TEST_APACHE' );
		$cgi = getenv( 'EMCP_SAFE_UPDATE_TEST_PHP_CGI' ) ?: dirname( PHP_BINARY ) . '/php-cgi' . ( '\\' === DIRECTORY_SEPARATOR ? '.exe' : '' );
		if ( ! $apache || ! is_file( $apache ) || ! is_file( $cgi ) ) { $this->markTestSkipped( 'Set EMCP_SAFE_UPDATE_TEST_APACHE and, optionally, EMCP_SAFE_UPDATE_TEST_PHP_CGI for native cache smoke.' ); }
		$root = str_replace( '\\', '/', sys_get_temp_dir() ) . '/emcp-safe-apache-' . bin2hex( random_bytes( 6 ) ) . '/';
		mkdir( $root, 0700 ); $server = null;
		try {
			$socket = stream_socket_server( 'tcp://127.0.0.1:0', $errno, $error );
			$this->assertNotFalse( $socket, $error );
			$port = (int) substr( strrchr( stream_socket_get_name( $socket, false ), ':' ), 1 ); fclose( $socket );
			$job = $root . '.emcp-update-test'; mkdir( $job, 0700 );
			$source = dirname( __DIR__ ) . '/includes/cloud/';
			copy( $source . 'safe-update-runtime.php', $job . '/runtime.php' ); copy( $source . 'safe-update-gate.php', $job . '/gate.php' );
			$original = '<?php /* original fixture config */'; file_put_contents( $root . 'wp-config.php', $original );
			file_put_contents( $root . 'index.php', '<?php require __DIR__."/wp-config.php"; function did_action($name){return 1;} echo "LIVE_UNCACHED";' );
			$token = str_repeat( 'a', 64 ); $challenge = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
			$s = array( 'root' => $root, 'dir' => $job, 'job' => 'test', 'phase' => 'prepared', 'group' => 0, 'groups' => array( array() ), 'deadline' => time() + 600, 'config_hash' => hash( 'sha256', $original ), 'token_hash' => hash( 'sha256', $token ), 'paths' => array( '/' ), 'base_path' => '' );
			EMCP_Update_Runtime::write( $job . '/original-config.php', $original ); EMCP_Update_Runtime::write( $job . '/state.php', $s );
			$cached = $root . 'wp-content/cache/wp-rocket/safe-update-cache.test/index.html'; mkdir( dirname( $cached ), 0700, true ); file_put_contents( $cached, 'CACHED_BEFORE_MAINTENANCE' );
			file_put_contents( $root . 'wp-content/advanced-cache.php', "<?php define('WP_ROCKET_ADVANCED_CACHE',true); \$rocket_cache_path = " . var_export( $root . 'wp-content/cache/wp-rocket/', true ) . ';' );
			// WP Rocket's native GET/empty-query/existing-file static delivery conditions.
			file_put_contents( $root . '.htaccess', "RewriteEngine On\nRewriteBase /\nRewriteCond %{REQUEST_METHOD} GET\nRewriteCond %{QUERY_STRING} =\"\"\nRewriteCond \"%{DOCUMENT_ROOT}/wp-content/cache/wp-rocket/%{HTTP_HOST}%{REQUEST_URI}/index.html\" -f\nRewriteRule .* \"/wp-content/cache/wp-rocket/%{HTTP_HOST}%{REQUEST_URI}/index.html\" [L]\n" );
			$apache_root = str_replace( '\\', '/', dirname( dirname( $apache ) ) ); $cgi_root = str_replace( '\\', '/', dirname( $cgi ) );
			$config = "ServerRoot \"$apache_root\"\nListen 127.0.0.1:$port\nServerName safe-update-cache.test\nPidFile \"{$root}httpd.pid\"\nErrorLog \"{$root}error.log\"\nLogLevel warn\n";
			foreach ( array( 'authz_core', 'authz_host', 'dir', 'mime', 'env', 'actions', 'cgi', 'rewrite', 'alias' ) as $module ) { $config .= "LoadModule {$module}_module modules/mod_{$module}.so\n"; }
			$config .= "DocumentRoot \"$root\"\n<Directory \"$root\">\nOptions FollowSymLinks ExecCGI\nCGIPassAuth On\nAllowOverride All\nRequire all granted\n</Directory>\n<Directory \"$cgi_root\">\nOptions ExecCGI\nCGIPassAuth On\nRequire all granted\n</Directory>\nScriptAlias /php-cgi/ \"$cgi_root/\"\nAddHandler application/x-httpd-php .php\nAction application/x-httpd-php /php-cgi/" . basename( $cgi ) . "\nDirectoryIndex index.php\n";
			file_put_contents( $root . 'httpd.conf', $config );
			$server = proc_open( array( $apache, '-f', $root . 'httpd.conf', '-DFOREGROUND' ), array( 0 => array( 'pipe', 'r' ), 1 => array( 'file', $root . 'stdout.log', 'a' ), 2 => array( 'file', $root . 'stderr.log', 'a' ) ), $pipes, null, null, array( 'bypass_shell' => true ) );
			$this->assertIsResource( $server ); fclose( $pipes[0] );
			$ready = false;
			for ( $i = 0; $i < 100; $i++ ) { $probe = @stream_socket_client( 'tcp://127.0.0.1:' . $port, $errno, $error, 0.05 ); if ( $probe ) { fclose( $probe ); $ready = true; break; } usleep( 50000 ); }
			$this->assertTrue( $ready, @file_get_contents( $root . 'stderr.log' ) ?: 'Apache did not start.' );
			$request = static function ( $query = '', $authenticated = false ) use ( $port, $token, $challenge ) {
				$headers = "Host: safe-update-cache.test\r\nConnection: close\r\n";
				if ( $authenticated ) { $headers .= 'Authorization: Bearer ' . $token . "\r\nX-EMCP-Update-Probe: " . $challenge . "\r\n"; }
				$context = stream_context_create( array( 'http' => array( 'header' => $headers, 'ignore_errors' => true, 'timeout' => 5 ) ) );
				$body = file_get_contents( 'http://127.0.0.1:' . $port . '/' . $query, false, $context );
				return array( 'body' => $body, 'headers' => $http_response_header );
			};
			$this->assertSame( 'CACHED_BEFORE_MAINTENANCE', $request()['body'] );
			EMCP_Update_Runtime::advance( $s, array( 'action' => 'tick', 'phase' => 'prepared', 'group' => 0 ) );
			$this->assertSame( 'baseline', $s['phase'], $s['code'] ?? '' );
			$visitor = $request(); $this->assertStringContainsString( '503', $visitor['headers'][0] ); $this->assertStringContainsString( 'Scheduled maintenance', $visitor['body'] );
			$health = $request( '?emcp_update_probe=' . $challenge, true );
			$this->assertStringContainsString( '200', $health['headers'][0] ); $this->assertSame( 'LIVE_UNCACHED', $health['body'] );
			$this->assertContains( 'X-EMCP-Update-Probe-Result: ' . $challenge, $health['headers'] );
			EMCP_Update_Runtime::advance( $s, array( 'action' => 'rollback', 'phase' => 'baseline', 'group' => 0 ) );
			$this->assertSame( 'failed', $s['phase'] ); $this->assertSame( 'LIVE_UNCACHED', $request()['body'] );
		} finally {
			if ( is_resource( $server ) ) {
				$status = proc_get_status( $server );
				if ( $status['running'] ) {
					if ( '\\' === DIRECTORY_SEPARATOR ) {
						// Terminate only the PID tree returned by our own proc_open handle.
						$stop = proc_open( array( 'taskkill', '/PID', (string) $status['pid'], '/T', '/F' ), array( 0 => array( 'pipe', 'r' ), 1 => array( 'file', $root . 'stop.log', 'a' ), 2 => array( 'file', $root . 'stop.log', 'a' ) ), $stop_pipes, null, null, array( 'bypass_shell' => true ) );
						if ( is_resource( $stop ) ) { fclose( $stop_pipes[0] ); proc_close( $stop ); }
					} else { proc_terminate( $server ); }
				}
				proc_close( $server );
			}
			$walk = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
			foreach ( $walk as $entry ) { $entry->isDir() ? rmdir( $entry->getPathname() ) : unlink( $entry->getPathname() ); } rmdir( $root );
		}
	}
}
