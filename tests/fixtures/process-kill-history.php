<?php
/**
 * Standalone harness: kill-process records an audit-only History entry that
 * History refuses to undo. Runs in its own process because it loads the real
 * change log on the in-memory storage.
 *
 * @package EMCP_Tools\Tests
 */

define( 'ABSPATH', dirname( __DIR__, 2 ) . '/' );
define( 'ARRAY_A', 'ARRAY_A' );
$GLOBALS['_wp_options'] = array();
class WP_Error {
	public function __construct( private string $code, private string $message = '' ) {}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
}
function __( $s, $domain = '' ) { return $s; }
function is_wp_error( $v ) { return $v instanceof WP_Error; }
function wp_json_encode( $v ) { return json_encode( $v ); }
function maybe_serialize( $v ) { return is_array( $v ) || is_object( $v ) ? serialize( $v ) : (string) $v; }
function maybe_unserialize( $v ) { return is_string( $v ) && ( 'b:0;' === $v || false !== @unserialize( $v ) ) ? unserialize( $v ) : $v; }
function get_current_user_id() { return 1; }
function get_option( $k, $default = false ) { return array_key_exists( $k, $GLOBALS['_wp_options'] ) ? $GLOBALS['_wp_options'][ $k ] : $default; }
function update_option( $k, $v, $autoload = null ) { $GLOBALS['_wp_options'][ $k ] = $v; return true; }
function add_option( $k, $v, $d = '', $autoload = null ) { $GLOBALS['_wp_options'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['_wp_options'][ $k ] ); return true; }
function wp_cache_delete( ...$a ) { return true; }
function add_filter( ...$a ) { return true; }
function apply_filters( $hook, $value, ...$rest ) { return $value; }
function do_action( ...$args ) {}
function check( $condition, $message ) { if ( ! $condition ) { fwrite( STDERR, $message . "\n" ); exit( 1 ); } }

require ABSPATH . 'includes/class-lease.php';
require ABSPATH . 'includes/class-change-log.php';
require ABSPATH . 'tests/support/class-change-memory-storage.php';
require ABSPATH . 'includes/security/class-security-process-inspector.php';
require ABSPATH . 'includes/abilities/class-process-abilities.php';
EMCP_Tools_Change_Log::use_storage( new EMCP_Tools_Change_Memory_Storage(), EMCP_Tools_Change_Memory_Storage::lease() );

/** Inspector whose kill always succeeds, so only the History side is under test. */
class Fixture_Kill_Inspector extends EMCP_Tools_Security_Process_Inspector {
	public function kill( int $pid, string $start_time, string $signal ) {
		return array(
			'pid'        => $pid,
			'signal'     => $signal,
			'sent'       => true,
			'gone'       => true,
			'name'       => 'sh',
			'cmdline'    => 'sh /tmp/.watcher',
			'start_time' => $start_time,
		);
	}
}

$tools = new EMCP_Tools_Process_Abilities( new Fixture_Kill_Inspector() );
$out   = $tools->execute_kill_process( array( 'pid' => 4242, 'start_time' => '900000', 'confirm' => true ) );
check( is_array( $out ), 'kill failed' );
check( '' !== $out['change_id'], 'no change id' );

$entry = EMCP_Tools_Change_Log::get( $out['change_id'] );
check( is_array( $entry ), 'entry missing' );
check( 'security' === $entry['domain'] && 'kill-process' === $entry['action'], 'domain/action: ' . json_encode( $entry ) );
check( 'pid 4242' === $entry['target'], 'target ' . $entry['target'] );
check( false !== strpos( $entry['summary'], 'Sent TERM to process 4242' ), 'summary ' . $entry['summary'] );
check( 'irreversible' === $entry['rollback']['type'], 'rollback type' );

$blocker = EMCP_Tools_Change_Log::rollback_blocker( $entry );
check( $blocker instanceof WP_Error && 'irreversible' === $blocker->get_error_code(), 'History would try to undo a kill' );
check( false !== strpos( $blocker->get_error_message(), 'cannot be restarted' ), 'reason ' . $blocker->get_error_message() );

echo "PASS\n";
