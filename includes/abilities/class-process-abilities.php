<?php
/**
 * Process MCP tools: list-processes (read-only, enabled) and kill-process
 * (write, disabled by default, confirm:true). Linux only; both read /proc
 * directly and only see processes owned by the user PHP runs as.
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
class EMCP_Tools_Process_Abilities {

	/** @var string[] */
	private $ability_names = array();

	/** @var EMCP_Tools_Security_Process_Inspector */
	private $inspector;

	public function __construct( ?EMCP_Tools_Security_Process_Inspector $inspector = null ) {
		$this->inspector = $inspector ?: new EMCP_Tools_Security_Process_Inspector();
	}

	public function get_ability_names(): array {
		return $this->ability_names;
	}

	public function register(): void {
		$this->register_list_processes();
		$this->register_kill_process();
	}

	/** Both tools require manage_options. */
	public function check_permission(): bool {
		return current_user_can( 'manage_options' );
	}

	// ---- list-processes ------------------------------------------------

	private function register_list_processes(): void {
		$this->ability_names[] = 'emcp-tools/list-processes';
		emcp_tools_register_ability(
			'emcp-tools/list-processes',
			array(
				'label'               => __( 'List Processes', 'emcp-tools' ),
				'description'         => __( 'List the processes running as the same user as PHP (Linux only, read from /proc, no shell): pid, parent pid, state, start time, elapsed seconds, command line (capped, passwords and tokens masked), program and working directory when readable. Marks the current PHP process and its parent, and flags suspicious ones with reasons: running from /tmp, /var/tmp or /dev/shm, hidden names, a deleted program file, shell loops, a fake kernel-thread name, or PHP running a file from uploads. Use it when cleaned files keep coming back. Pass a process\'s pid and start_time to kill-process. Read-only.', 'emcp-tools' ),
				'category'            => 'emcp-tools',
				'execute_callback'    => array( $this, 'execute_list_processes' ),
				'permission_callback' => array( $this, 'check_permission' ),
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'suspicious_only' => array( 'type' => 'boolean', 'description' => __( 'Return only flagged processes. Default false.', 'emcp-tools' ) ),
					),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'meta'                => array(
					'annotations'  => array( 'readonly' => true, 'destructive' => false, 'idempotent' => true ),
					'show_in_rest' => true,
				),
			)
		);
	}

	/**
	 * @param array $input
	 * @return array
	 */
	public function execute_list_processes( $input ): array {
		$out = $this->inspector->list_processes();
		if ( ! empty( $out['supported'] ) && is_array( $input ) && ! empty( $input['suspicious_only'] ) ) {
			$out['processes'] = array_values(
				array_filter(
					$out['processes'],
					static function ( $p ) {
						return ! empty( $p['suspicious'] );
					}
				)
			);
			$out['count'] = count( $out['processes'] );
		}
		return $out;
	}

	// ---- kill-process --------------------------------------------------

	private function register_kill_process(): void {
		$this->ability_names[] = 'emcp-tools/kill-process';
		emcp_tools_register_ability(
			'emcp-tools/kill-process',
			array(
				'label'               => __( 'Kill Process', 'emcp-tools' ),
				'description'         => __( 'Stop one process owned by the same user as PHP by sending TERM (default) or KILL. Pass pid and start_time exactly as list-processes returned them, and confirm:true. Refuses PID 1, the current PHP process and its parent, other users\' processes, and a pid whose start time changed (a reused pid). Waits briefly and reports whether the process is gone. This cannot be undone: a stopped process is not restarted, and History records it for the audit trail only. Linux only. Disabled by default.', 'emcp-tools' ),
				'category'            => 'emcp-tools',
				'execute_callback'    => array( $this, 'execute_kill_process' ),
				'permission_callback' => array( $this, 'check_permission' ),
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'pid'        => array( 'type' => 'integer', 'description' => __( 'Process id from list-processes.', 'emcp-tools' ) ),
						'start_time' => array( 'type' => 'string', 'description' => __( 'start_time of that process from list-processes, to guard against pid reuse.', 'emcp-tools' ) ),
						'signal'     => array( 'type' => 'string', 'enum' => array( 'TERM', 'KILL' ), 'description' => __( 'TERM (default) asks the process to stop; KILL stops it at once.', 'emcp-tools' ) ),
						'confirm'    => array( 'type' => 'boolean', 'description' => __( 'Must be true. Stopping a process cannot be undone.', 'emcp-tools' ) ),
					),
					'required'   => array( 'pid', 'start_time', 'confirm' ),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'meta'                => array(
					'annotations'  => array( 'readonly' => false, 'destructive' => true, 'idempotent' => false ),
					'show_in_rest' => true,
				),
			)
		);
	}

	/**
	 * @param array $input
	 * @return array|\WP_Error
	 */
	public function execute_kill_process( $input ) {
		if ( ! is_array( $input ) || empty( $input['confirm'] ) || true !== $input['confirm'] ) {
			return new \WP_Error( 'confirm_required', __( 'Stopping a process cannot be undone and requires confirm:true.', 'emcp-tools' ) );
		}
		$signal = EMCP_Tools_Security_Process_Inspector::normalize_signal( $input['signal'] ?? null );
		if ( null === $signal ) {
			return new \WP_Error( 'invalid_signal', __( 'signal must be TERM or KILL.', 'emcp-tools' ) );
		}
		$pid = $input['pid'] ?? 0;
		if ( ! is_int( $pid ) && ! ( is_string( $pid ) && ctype_digit( $pid ) ) ) {
			return new \WP_Error( 'invalid_pid', EMCP_Tools_Security_Process_Inspector::refusal_message( 'invalid_pid' ) );
		}
		$start = $input['start_time'] ?? '';
		$start = is_int( $start ) ? (string) $start : ( is_string( $start ) ? trim( $start ) : '' );

		$out = $this->inspector->kill( (int) $pid, $start, $signal );
		if ( is_wp_error( $out ) ) {
			return $out;
		}
		$out['change_id'] = self::record_kill( $out );
		$out['undoable']  = false;
		return $out;
	}

	/**
	 * Record the kill to History as an audit-only entry that cannot be undone.
	 *
	 * @param array $out Kill result.
	 * @return string Change id ('' when History is unavailable).
	 */
	private static function record_kill( array $out ): string {
		if ( ! class_exists( 'EMCP_Tools_Change_Log' ) ) {
			return '';
		}
		$label = '' !== $out['cmdline'] ? $out['cmdline'] : $out['name'];
		return (string) EMCP_Tools_Change_Log::record(
			array(
				'domain'   => 'security',
				'action'   => 'kill-process',
				'target'   => 'pid ' . $out['pid'],
				'summary'  => sprintf( 'Sent %s to process %d (%s)%s', $out['signal'], $out['pid'], substr( $label, 0, 160 ), $out['gone'] ? '' : ', still running' ),
				'rollback' => array(
					'type'   => 'irreversible',
					'reason' => __( 'A stopped process cannot be restarted from History.', 'emcp-tools' ),
				),
			)
		);
	}
}
