<?php
/**
 * Access log search MCP ability (read-only).
 *
 * One tool, search-access-log, that searches the web server access logs the
 * site can read, to find the request behind a hack (for example a POST to a
 * back door at the moment files were rewritten). manage_options; enabled by
 * default like the other read-only file tools.
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
class EMCP_Tools_Access_Log_Abilities {

	/** @var string[] */
	private $ability_names = array();

	/** @var EMCP_Tools_Access_Log_Search */
	private $search;

	public function __construct( ?EMCP_Tools_Access_Log_Search $search = null ) {
		$this->search = $search ?: new EMCP_Tools_Access_Log_Search();
	}

	public function get_ability_names(): array {
		return $this->ability_names;
	}

	public function register(): void {
		$this->register_search_access_log();
	}

	/** Logs hold visitor IPs and URLs, so this is admin only. */
	public function check_permission(): bool {
		return current_user_can( 'manage_options' );
	}

	private function register_search_access_log(): void {
		$this->ability_names[] = 'emcp-tools/search-access-log';
		emcp_tools_register_ability(
			'emcp-tools/search-access-log',
			array(
				'label'               => __( 'Search Access Log', 'emcp-tools' ),
				'description'         => __( 'Searches the web server access logs this site can read (plain and .gz) for matching requests, to find the request behind a hack, for example a POST to a back-door file at the time files were rewritten. Logs are found in the EMCP_TOOLS_ACCESS_LOG_DIR folder when set, else in logs folders next to or above the site (IONOS keeps them two levels up), ~/logs, /var/log/apache2, /var/log/httpd and /var/log/nginx. Pass list_files: true to see the detected logs; files may only name logs from that list. Filters: contains (required), ip, method, status (200 or 4xx), path_contains, since and until. Query strings are removed from returned lines unless include_query is true. Bounded by limit, max_seconds and max_mb; partial results are flagged. Read-only.', 'emcp-tools' ),
				'category'            => 'emcp-tools',
				'execute_callback'    => array( $this, 'execute_search_access_log' ),
				'permission_callback' => array( $this, 'check_permission' ),
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'contains'      => array( 'type' => 'string', 'description' => __( 'Plain text the line must contain (case-insensitive), for example a file name such as index.php. Required unless list_files is true.', 'emcp-tools' ) ),
						'ip'            => array( 'type' => 'string', 'description' => __( 'Only requests from this client IP.', 'emcp-tools' ) ),
						'method'        => array( 'type' => 'string', 'description' => __( 'Only this HTTP method, for example POST.', 'emcp-tools' ) ),
						'status'        => array( 'type' => 'string', 'description' => __( 'Only this status code (200) or class (4xx).', 'emcp-tools' ) ),
						'path_contains' => array( 'type' => 'string', 'description' => __( 'Text the requested path must contain.', 'emcp-tools' ) ),
						'since'         => array( 'type' => 'string', 'description' => __( 'Earliest request time: ISO 8601 (2026-10-17T10:00:00Z), unix seconds, or the log format.', 'emcp-tools' ) ),
						'until'         => array( 'type' => 'string', 'description' => __( 'Latest request time, same formats as since.', 'emcp-tools' ) ),
						'limit'         => array( 'type' => 'integer', 'description' => __( 'Most matches to return (default 100, max 500).', 'emcp-tools' ) ),
						'files'         => array(
							'type'        => 'array',
							'items'       => array( 'type' => 'string' ),
							'description' => __( 'Detected log names to search (as list_files returns them, or a bare name such as access.log). Omit to search every detected log, newest first.', 'emcp-tools' ),
						),
						'list_files'    => array( 'type' => 'boolean', 'description' => __( 'Return the detected log files with size and modified time instead of searching.', 'emcp-tools' ) ),
						'include_query' => array( 'type' => 'boolean', 'description' => __( 'Keep query strings in returned lines. Default false: they can hold tokens and nonces.', 'emcp-tools' ) ),
						'max_seconds'   => array( 'type' => 'integer', 'description' => __( 'Time budget in seconds (default 20, max 120).', 'emcp-tools' ) ),
						'max_mb'        => array( 'type' => 'integer', 'description' => __( 'Most uncompressed megabytes to read (default 256, max 2048).', 'emcp-tools' ) ),
					),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'matches'          => array( 'type' => 'array' ),
						'count'            => array( 'type' => 'integer' ),
						'truncated'        => array( 'type' => 'boolean' ),
						'truncated_reason' => array( 'type' => array( 'string', 'null' ) ),
						'files_searched'   => array( 'type' => 'array' ),
						'files_skipped'    => array( 'type' => 'array' ),
						'files'            => array( 'type' => 'array' ),
						'searched_dirs'    => array( 'type' => 'array' ),
						'scan_meta'        => array( 'type' => 'object' ),
					),
				),
				'meta'                => array(
					'annotations'  => array( 'readonly' => true, 'destructive' => false, 'idempotent' => true ),
					'show_in_rest' => true,
				),
			)
		);
	}

	/**
	 * @param array $input
	 * @return array|\WP_Error
	 */
	public function execute_search_access_log( $input ) {
		if ( ! is_array( $input ) ) {
			$input = array();
		}
		return $this->search->run( $input );
	}
}
