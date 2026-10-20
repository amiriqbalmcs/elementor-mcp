<?php
/**
 * Site hardening toggles, applied on every request.
 *
 * The harden-site tool stores the enabled toggles in ONE autoloaded option.
 * init() reads it once per request; when it is empty nothing is hooked, so a
 * site that never turned a toggle on pays nothing. Every decision lives in a
 * small pure static method (unit-tested); the hook callbacks are thin wrappers
 * that read the request state and call them.
 *
 * Safety: init() never runs for WP-CLI or cron, every callback returns early
 * when its toggle is off, nothing here prints output, and init() swallows any
 * Throwable so a broken hook can never take the site down.
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
class EMCP_Tools_Site_Hardening {

	/** Option that holds the enabled toggles: { toggle => true }. Autoloaded. */
	const OPTION = 'emcp_tools_hardening';

	/** The toggles harden-site accepts, in display order. */
	const TOGGLES = array( 'disable_xmlrpc', 'hide_wp_version', 'block_user_enumeration', 'hide_php_errors' );

	/** Status for the author redirect: temporary, so browsers do not keep it after the toggle goes off. */
	const AUTHOR_REDIRECT_STATUS = 302;

	/** REST route prefix that lists users. */
	const USERS_ROUTE = '/wp/v2/users';

	/** @var array<string,bool> Toggles enabled for this request (set by init()). */
	private static $enabled = array();

	// ---- Pure logic --------------------------------------------------------

	/**
	 * Validate the harden-site `toggles` input.
	 *
	 * @param mixed $raw The input map { toggle => bool }.
	 * @return array<string,bool>|WP_Error
	 */
	public static function parse_toggles( $raw ) {
		if ( ! is_array( $raw ) || empty( $raw ) ) {
			return new WP_Error( 'invalid_toggles', __( 'Pass "toggles" as a non-empty map of toggle names to true or false.', 'emcp-tools' ) );
		}
		$out = array();
		foreach ( $raw as $name => $value ) {
			$name = (string) $name;
			if ( 'block_readme' === $name ) {
				return new WP_Error( 'unsupported_toggle', __( 'block_readme is not available: readme.html and license.txt are static files the web server sends without running PHP, so a plugin cannot block them without editing server config. get-hardening-status reports whether they exist; delete them with delete-file if you want them gone.', 'emcp-tools' ) );
			}
			if ( ! in_array( $name, self::TOGGLES, true ) ) {
				/* translators: 1: toggle name, 2: allowed toggle names. */
				return new WP_Error( 'unknown_toggle', sprintf( __( 'Unknown toggle "%1$s". Allowed: %2$s.', 'emcp-tools' ), $name, implode( ', ', self::TOGGLES ) ) );
			}
			if ( ! is_bool( $value ) ) {
				/* translators: %s: toggle name. */
				return new WP_Error( 'invalid_value', sprintf( __( 'Toggle "%s" must be true or false.', 'emcp-tools' ), $name ) );
			}
			$out[ $name ] = $value;
		}
		return $out;
	}

	/**
	 * The enabled toggles in a stored option value. Unknown keys and anything
	 * that is not strictly true are dropped.
	 *
	 * @param mixed $stored Raw option value.
	 * @return array<string,bool> { toggle => true }, in TOGGLES order.
	 */
	public static function normalize( $stored ): array {
		$out = array();
		if ( ! is_array( $stored ) ) {
			return $out;
		}
		foreach ( self::TOGGLES as $name ) {
			if ( isset( $stored[ $name ] ) && true === $stored[ $name ] ) {
				$out[ $name ] = true;
			}
		}
		return $out;
	}

	/**
	 * Apply validated changes to the current enabled set.
	 *
	 * @param array $current Current stored value (normalized here).
	 * @param array $changes Output of parse_toggles().
	 * @return array<string,bool> The new enabled set, { toggle => true }.
	 */
	public static function merge( array $current, array $changes ): array {
		$next = self::normalize( $current );
		foreach ( $changes as $name => $on ) {
			if ( true === $on ) {
				$next[ (string) $name ] = true;
			} else {
				unset( $next[ (string) $name ] );
			}
		}
		return self::normalize( $next );
	}

	/**
	 * Every toggle with its state, for tool output.
	 *
	 * @param array $enabled { toggle => true }.
	 * @return array<string,bool>
	 */
	public static function state_map( array $enabled ): array {
		$enabled = self::normalize( $enabled );
		$out     = array();
		foreach ( self::TOGGLES as $name ) {
			$out[ $name ] = isset( $enabled[ $name ] );
		}
		return $out;
	}

	/**
	 * Requests the toggles never touch: WP-CLI and cron.
	 *
	 * @param bool $is_cli  WP-CLI request.
	 * @param bool $is_cron Cron request.
	 */
	public static function is_exempt_context( bool $is_cli, bool $is_cron ): bool {
		return $is_cli || $is_cron;
	}

	/**
	 * Whether this request is an XML-RPC call to stop with a 403.
	 *
	 * @param bool $enabled           disable_xmlrpc is on.
	 * @param bool $is_xmlrpc_request XMLRPC_REQUEST is defined and true.
	 */
	public static function should_block_xmlrpc( bool $enabled, bool $is_xmlrpc_request ): bool {
		return $enabled && $is_xmlrpc_request;
	}

	/**
	 * Drop the X-Pingback header from a response header map.
	 *
	 * @param array $headers Header name => value.
	 * @return array
	 */
	public static function strip_pingback_header( array $headers ): array {
		foreach ( array_keys( $headers ) as $name ) {
			if ( 'x-pingback' === strtolower( (string) $name ) ) {
				unset( $headers[ $name ] );
			}
		}
		return $headers;
	}

	/**
	 * Remove the pingback methods from the XML-RPC method map.
	 *
	 * @param array $methods Method name => callback.
	 * @return array
	 */
	public static function strip_pingback_methods( array $methods ): array {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Pure: a per-site stand-in for the WordPress version in asset URLs. It
	 * changes when WordPress updates (so caches are still busted) but cannot be
	 * mapped back to a version without the site's salt.
	 *
	 * @param string $wp_version WordPress version.
	 * @param string $salt       Site secret.
	 */
	public static function version_token( string $wp_version, string $salt ): string {
		return substr( hash( 'sha256', $salt . '|' . $wp_version ), 0, 8 );
	}

	/**
	 * Replace `ver=` in an asset URL with $token when it equals the WordPress
	 * version. Any other version (a plugin's own) is left alone.
	 *
	 * @param string $src        Asset URL.
	 * @param string $wp_version WordPress version.
	 * @param string $token      Replacement value (version_token()).
	 * @return string
	 */
	public static function strip_core_version( string $src, string $wp_version, string $token = '' ): string {
		if ( '' === $src || '' === $wp_version || false === strpos( $src, 'ver=' ) ) {
			return $src;
		}
		$qpos = strpos( $src, '?' );
		if ( false === $qpos ) {
			return $src;
		}
		$hpos     = strpos( $src, '#', $qpos );
		$fragment = false === $hpos ? '' : substr( $src, $hpos );
		$query    = false === $hpos ? substr( $src, $qpos + 1 ) : substr( $src, $qpos + 1, $hpos - $qpos - 1 );
		$kept     = array();
		$removed  = false;
		foreach ( explode( '&', $query ) as $pair ) {
			if ( '' === $pair ) {
				continue;
			}
			$parts = explode( '=', $pair, 2 );
			if ( 'ver' === $parts[0] && isset( $parts[1] ) && rawurldecode( $parts[1] ) === $wp_version ) {
				$removed = true;
				if ( '' !== $token ) {
					$kept[] = 'ver=' . rawurlencode( $token );
				}
				continue;
			}
			$kept[] = $pair;
		}
		if ( ! $removed ) {
			return $src;
		}
		$base = substr( $src, 0, $qpos );
		return $base . ( empty( $kept ) ? '' : '?' . implode( '&', $kept ) ) . $fragment;
	}

	/**
	 * Whether a REST route lists or shows users.
	 *
	 * @param string $route Route pattern, for example /wp/v2/users/(?P<id>[\d]+).
	 */
	public static function is_users_route( string $route ): bool {
		return self::USERS_ROUTE === $route || 0 === strpos( $route, self::USERS_ROUTE . '/' );
	}

	/**
	 * Whether the current user may keep the users REST routes. list_users is the
	 * capability the request names; edit_posts keeps the block editor's author
	 * picker working for editors and authors, who lack list_users. A visitor has
	 * neither.
	 *
	 * @param bool $can_list_users current_user_can( 'list_users' ).
	 * @param bool $can_edit_posts current_user_can( 'edit_posts' ).
	 */
	public static function may_list_users( bool $can_list_users, bool $can_edit_posts ): bool {
		return $can_list_users || $can_edit_posts;
	}

	/**
	 * Remove the users routes from the REST endpoint map unless allowed.
	 *
	 * @param array $endpoints Route => handlers.
	 * @param bool  $allowed   may_list_users() for the current user.
	 * @return array
	 */
	public static function filter_user_endpoints( array $endpoints, bool $allowed ): array {
		if ( $allowed ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( self::is_users_route( (string) $route ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/**
	 * Whether a front-end request is an author lookup to send home. `?author=N`
	 * and /author/<slug>/ both set a query var; logged-in users are never sent away.
	 *
	 * @param array $query_vars   The parsed request query vars.
	 * @param bool  $is_logged_in is_user_logged_in().
	 */
	public static function should_block_author_request( array $query_vars, bool $is_logged_in ): bool {
		if ( $is_logged_in ) {
			return false;
		}
		// Only a numeric id enumerates: ?author=1 redirects to /author/<login>/.
		// An archive asked for by name reveals nothing the visitor did not know.
		$id = (string) ( $query_vars['author'] ?? '' );
		return ctype_digit( $id ) && (int) $id > 0;
	}

	/**
	 * Remove the author fields from an oEmbed response.
	 *
	 * @param array $data oEmbed response data.
	 * @return array
	 */
	public static function strip_oembed_author( array $data ): array {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	/**
	 * Whether to turn display_errors off for this request.
	 *
	 * @param bool $enabled       hide_php_errors is on.
	 * @param bool $is_admin_user The user can manage_options.
	 */
	public static function should_hide_errors( bool $enabled, bool $is_admin_user ): bool {
		return $enabled && ! $is_admin_user;
	}

	// ---- Runtime wiring ----------------------------------------------------

	/**
	 * Read the option and add the hooks for the enabled toggles. Called once on
	 * plugins_loaded. Does nothing when no toggle is on.
	 */
	public static function init(): void {
		try {
			self::$enabled = self::normalize( get_option( self::OPTION, array() ) );
			if ( empty( self::$enabled ) ) {
				return;
			}
			$is_cli  = defined( 'WP_CLI' ) && WP_CLI;
			$is_cron = function_exists( 'wp_doing_cron' ) && wp_doing_cron();
			if ( self::is_exempt_context( $is_cli, $is_cron ) ) {
				self::$enabled = array();
				return;
			}
			if ( self::on( 'disable_xmlrpc' ) ) {
				self::wire_xmlrpc();
			}
			if ( self::on( 'hide_wp_version' ) ) {
				self::wire_version();
			}
			if ( self::on( 'block_user_enumeration' ) ) {
				self::wire_users();
			}
			if ( self::on( 'hide_php_errors' ) ) {
				self::apply_error_display();
			}
		} catch ( \Throwable $e ) {
			self::$enabled = array();
		}
	}

	/**
	 * Whether a toggle is on for this request.
	 *
	 * @param string $name Toggle.
	 */
	private static function on( string $name ): bool {
		return ! empty( self::$enabled[ $name ] );
	}

	private static function wire_xmlrpc(): void {
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', array( __CLASS__, 'filter_xmlrpc_methods' ) );
		add_filter( 'wp_headers', array( __CLASS__, 'filter_headers' ) );
		add_filter( 'bloginfo_url', array( __CLASS__, 'filter_pingback_url' ), 10, 2 );
		remove_action( 'wp_head', 'rsd_link' );
		$is_xmlrpc = defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST;
		if ( self::should_block_xmlrpc( true, $is_xmlrpc ) ) {
			self::deny_xmlrpc();
		}
	}

	private static function wire_version(): void {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
		add_filter( 'style_loader_src', array( __CLASS__, 'filter_asset_src' ), 9999 );
		add_filter( 'script_loader_src', array( __CLASS__, 'filter_asset_src' ), 9999 );
	}

	private static function wire_users(): void {
		add_filter( 'rest_endpoints', array( __CLASS__, 'filter_rest_endpoints' ) );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_redirect_author' ), 0 );
		add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'filter_sitemap_provider' ), 10, 2 );
		add_filter( 'oembed_response_data', array( __CLASS__, 'filter_oembed_data' ) );
	}

	/**
	 * Turn display_errors off for anyone who cannot manage_options. It cannot
	 * change WP_DEBUG or WP_DEBUG_DISPLAY in wp-config.php, and errors raised
	 * before this plugin loads can still show.
	 */
	private static function apply_error_display(): void {
		$is_admin_user = function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
		if ( self::should_hide_errors( true, $is_admin_user ) && function_exists( 'ini_set' ) ) {
			// phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed
			ini_set( 'display_errors', '0' );
		}
	}

	/** Stop an XML-RPC request with a 403 and no body. */
	private static function deny_xmlrpc(): void {
		if ( ! headers_sent() ) {
			if ( function_exists( 'status_header' ) ) {
				status_header( 403 );
			} else {
				http_response_code( 403 );
			}
		}
		exit;
	}

	// ---- Hook callbacks (thin) --------------------------------------------

	/**
	 * @param mixed $methods XML-RPC methods.
	 * @return mixed
	 */
	public static function filter_xmlrpc_methods( $methods ) {
		return is_array( $methods ) && self::on( 'disable_xmlrpc' ) ? self::strip_pingback_methods( $methods ) : $methods;
	}

	/**
	 * @param mixed $headers Response headers.
	 * @return mixed
	 */
	public static function filter_headers( $headers ) {
		return is_array( $headers ) && self::on( 'disable_xmlrpc' ) ? self::strip_pingback_header( $headers ) : $headers;
	}

	/**
	 * Blank the pingback URL so themes print no usable pingback link.
	 *
	 * @param mixed  $url  URL.
	 * @param string $show bloginfo() key.
	 * @return mixed
	 */
	public static function filter_pingback_url( $url, $show = '' ) {
		return ( 'pingback_url' === $show && self::on( 'disable_xmlrpc' ) ) ? '' : $url;
	}

	/**
	 * @param mixed $src Asset URL.
	 * @return mixed
	 */
	public static function filter_asset_src( $src ) {
		if ( ! is_string( $src ) || ! self::on( 'hide_wp_version' ) || ( function_exists( 'is_admin' ) && is_admin() ) ) {
			return $src;
		}
		$version = isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '';
		$salt    = function_exists( 'wp_salt' ) ? wp_salt( 'nonce' ) : '';
		return self::strip_core_version( $src, $version, '' === $version ? '' : self::version_token( $version, $salt ) );
	}

	/**
	 * @param mixed $endpoints REST endpoints.
	 * @return mixed
	 */
	public static function filter_rest_endpoints( $endpoints ) {
		if ( ! is_array( $endpoints ) || ! self::on( 'block_user_enumeration' ) ) {
			return $endpoints;
		}
		$allowed = self::may_list_users( current_user_can( 'list_users' ), current_user_can( 'edit_posts' ) );
		return self::filter_user_endpoints( $endpoints, $allowed );
	}

	/** Send a logged-out ?author=N lookup to the home page (302). */
	public static function maybe_redirect_author(): void {
		if ( ! self::on( 'block_user_enumeration' ) ) {
			return;
		}
		$query_vars = ( isset( $GLOBALS['wp'] ) && is_object( $GLOBALS['wp'] ) && is_array( $GLOBALS['wp']->query_vars ) ) ? $GLOBALS['wp']->query_vars : array();
		if ( ! self::should_block_author_request( $query_vars, is_user_logged_in() ) ) {
			return;
		}
		if ( wp_safe_redirect( home_url( '/' ), self::AUTHOR_REDIRECT_STATUS, 'EMCP Tools' ) ) {
			exit;
		}
	}

	/**
	 * Drop the users sitemap (it lists author archive URLs).
	 *
	 * @param mixed  $provider Sitemap provider.
	 * @param string $name     Provider name.
	 * @return mixed
	 */
	public static function filter_sitemap_provider( $provider, $name = '' ) {
		return ( 'users' === $name && self::on( 'block_user_enumeration' ) ) ? false : $provider;
	}

	/**
	 * @param mixed $data oEmbed data.
	 * @return mixed
	 */
	public static function filter_oembed_data( $data ) {
		return is_array( $data ) && self::on( 'block_user_enumeration' ) ? self::strip_oembed_author( $data ) : $data;
	}
}
