<?php
/**
 * Security & Malware Scanner MCP abilities.
 *
 * scan-security scans for malware, core-integrity, hardening, outdated-software
 * and active-compromise issues and returns a scored report (read-only, enabled
 * by default). harden-site turns the site hardening toggles on or off (write,
 * confirm:true, disabled by default) and get-hardening-status reports them with
 * live checks (read-only). All need manage_options.
 *
 * @package EMCP_Tools
 * @since   3.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * @since 3.0.0
 */
class EMCP_Tools_Security_Abilities {

	/** @var string[] */
	private $ability_names = array();

	/** @var EMCP_Tools_Security_Scanner */
	private $scanner;

	public function __construct( ?EMCP_Tools_Security_Scanner $scanner = null ) {
		$this->scanner = $scanner ?: new EMCP_Tools_Security_Scanner();
	}

	public function get_ability_names(): array {
		return $this->ability_names;
	}

	public function register(): void {
		$this->register_scan_security();
		$this->register_harden_site();
		$this->register_get_hardening_status();
	}

	public function check_permission(): bool {
		return current_user_can( 'manage_options' );
	}

	private function register_scan_security(): void {
		$this->ability_names[] = 'emcp-tools/scan-security';
		emcp_tools_register_ability(
			'emcp-tools/scan-security',
			array(
				'label'               => __( 'Scan Security', 'emcp-tools' ),
				'description'         => __( 'Scans this WordPress site for security and malware problems across five areas: PHP malware heuristics (uploads + active plugins/themes; pass deep=true for the whole tree), WordPress core file integrity (vs official wordpress.org checksums), configuration hardening (file editor, debug output, admin username, XML-RPC, version disclosure, HTTPS, security headers), outdated/abandoned software, and signs of an active compromise (hidden twin-folder backdoors, back-dated PHP files, search-engine cloaking, publicly downloadable backups, suspicious must-use plugins, orphaned scheduled tasks). Returns a scored report (0-100 + A-F grade) with severities and ranked, actionable recommendations. Read-only; self-contained; scans this site only.', 'emcp-tools' ),
				'category'            => 'emcp-tools',
				'execute_callback'    => array( $this, 'execute_scan_security' ),
				'permission_callback' => array( $this, 'check_permission' ),
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'checks'      => array(
							'type'        => 'array',
							'items'       => array( 'type' => 'string', 'enum' => array( 'malware', 'integrity', 'hardening', 'software', 'compromise' ) ),
							'description' => __( 'Subset of audits to run. Omit to run all five.', 'emcp-tools' ),
						),
						'deep'        => array( 'type' => 'boolean', 'description' => __( 'When true, the malware scan covers ALL plugins/themes and the wider tree (slower). Default false: uploads + active plugins/themes only.', 'emcp-tools' ) ),
						'max_files'   => array( 'type' => 'integer', 'description' => __( 'Override the malware file-count cap (default 2000, ceiling 20000).', 'emcp-tools' ) ),
						'max_seconds' => array( 'type' => 'integer', 'description' => __( 'Time budget in seconds for the malware scan and, separately, for the compromise audit (default 20, ceiling 120). A compromise audit that runs out of time says which checks were only partly covered.', 'emcp-tools' ) ),
					),
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'summary'             => array( 'type' => 'object' ),
						'sections'            => array( 'type' => 'object' ),
						'scan_meta'           => array( 'type' => 'object' ),
						'top_recommendations' => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
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
	public function execute_scan_security( $input ) {
		if ( ! is_array( $input ) ) {
			$input = array();
		}
		return $this->scanner->scan( $input );
	}

	// ---- harden-site ---------------------------------------------------

	/**
	 * @since 3.21.0
	 */
	private function register_harden_site(): void {
		$this->ability_names[] = 'emcp-tools/harden-site';
		$toggle                = array( 'type' => 'boolean' );
		emcp_tools_register_ability(
			'emcp-tools/harden-site',
			array(
				'label'               => __( 'Harden Site', 'emcp-tools' ),
				'description'         => __( 'Turns site hardening toggles on or off. disable_xmlrpc: XML-RPC requests get a 403, the X-Pingback header, RSD link and pingback methods are removed; Jetpack, the WordPress mobile apps and other XML-RPC clients stop working, so ask first if the site uses them. hide_wp_version: removes the generator tag and replaces the ver= query on assets where it equals the WordPress version with a per-site token that still changes on every core update. block_user_enumeration: removes the /wp/v2/users REST routes for anyone who cannot list_users or edit_posts, sends logged-out ?author=N requests to the home page (302; author archives asked for by name keep working), drops the users sitemap and oEmbed author fields. hide_php_errors: sets display_errors off for anyone who cannot manage_options; it cannot change WP_DEBUG or WP_DEBUG_DISPLAY in wp-config.php, and errors raised before plugins load can still show. Toggles you leave out keep their state. Never affects WP-CLI or cron. Each change is in History, where Undo restores the previous toggles. Requires confirm:true. Disabled by default.', 'emcp-tools' ),
				'category'            => 'emcp-tools',
				'execute_callback'    => array( $this, 'execute_harden_site' ),
				'permission_callback' => array( $this, 'check_permission' ),
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'toggles' => array(
							'type'                 => 'object',
							'description'          => __( 'Map of toggle name to true (on) or false (off).', 'emcp-tools' ),
							'properties'           => array(
								'disable_xmlrpc'         => $toggle,
								'hide_wp_version'        => $toggle,
								'block_user_enumeration' => $toggle,
								'hide_php_errors'        => $toggle,
							),
						),
						'confirm' => array( 'type' => 'boolean', 'description' => __( 'Must be true to change the toggles.', 'emcp-tools' ) ),
					),
					'required'   => array( 'toggles' ),
				),
				'output_schema'       => array( 'type' => 'object' ),
				'meta'                => array(
					'annotations'  => array( 'readonly' => false, 'destructive' => false, 'idempotent' => true ),
					'show_in_rest' => true,
				),
			)
		);
	}

	/**
	 * @since 3.21.0
	 *
	 * @param array $input
	 * @return array|\WP_Error
	 */
	public function execute_harden_site( $input ) {
		if ( ! is_array( $input ) || true !== ( $input['confirm'] ?? null ) ) {
			return new \WP_Error( 'confirm_required', __( 'Changing hardening toggles requires confirm:true.', 'emcp-tools' ) );
		}
		$changes = EMCP_Tools_Site_Hardening::parse_toggles( $input['toggles'] ?? null );
		if ( is_wp_error( $changes ) ) {
			return $changes;
		}
		$option   = EMCP_Tools_Site_Hardening::OPTION;
		$prior    = get_option( $option, '__EMCP_ABSENT__' );
		$previous = EMCP_Tools_Site_Hardening::normalize( '__EMCP_ABSENT__' === $prior ? array() : $prior );
		$next     = EMCP_Tools_Site_Hardening::merge( $previous, $changes );
		$result   = array(
			'previous'  => EMCP_Tools_Site_Hardening::state_map( $previous ),
			'current'   => EMCP_Tools_Site_Hardening::state_map( $next ),
			'changed'   => false,
			'change_id' => '',
			'note'      => __( 'Toggles take effect on the next request.', 'emcp-tools' ),
		);
		if ( $next === $previous && ( '__EMCP_ABSENT__' === $prior || $prior === $next ) ) {
			return $result;
		}

		if ( empty( $next ) ) {
			delete_option( $option );
		} else {
			update_option( $option, $next, true );
		}
		$result['changed'] = true;

		if ( class_exists( 'EMCP_Tools_Change_Recorder' ) ) {
			$on  = array_keys( $next );
			$id  = EMCP_Tools_Change_Recorder::record_options(
				array( $option => '__EMCP_ABSENT__' === $prior ? '__ABSENT__' : $prior ),
				empty( $on ) ? 'Turned all hardening toggles off' : 'Hardening toggles on: ' . implode( ', ', $on ),
				'Site hardening',
				'security',
				'harden-site'
			);
			$result['change_id'] = $id;
		}
		return $result;
	}

	// ---- get-hardening-status --------------------------------------------

	/**
	 * @since 3.21.0
	 */
	private function register_get_hardening_status(): void {
		$this->ability_names[] = 'emcp-tools/get-hardening-status';
		emcp_tools_register_ability(
			'emcp-tools/get-hardening-status',
			array(
				'label'               => __( 'Get Hardening Status', 'emcp-tools' ),
				'description'         => __( 'Returns the harden-site toggle states plus live checks as an anonymous visitor: whether XML-RPC answers, whether the generator tag is in the home page, whether /wp/v2/users lists users, whether ?author=1 leaks an author slug, and whether readme.html and license.txt exist. Each check is one loopback request to this site. Read-only.', 'emcp-tools' ),
				'category'            => 'emcp-tools',
				'execute_callback'    => array( $this, 'execute_get_hardening_status' ),
				'permission_callback' => array( $this, 'check_permission' ),
				'input_schema'        => array( 'type' => 'object', 'properties' => array() ),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'toggles' => array( 'type' => 'object' ),
						'live'    => array( 'type' => 'object' ),
						'errors'  => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
						'notes'   => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
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
	 * @since 3.21.0
	 *
	 * @param array $input
	 * @return array
	 */
	public function execute_get_hardening_status( $input ): array {
		return ( new EMCP_Tools_Hardening_Status() )->run();
	}
}
