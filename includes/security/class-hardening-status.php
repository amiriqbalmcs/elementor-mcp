<?php
/**
 * Live hardening status for get-hardening-status.
 *
 * Reports the stored harden-site toggles plus what an anonymous visitor
 * actually sees: whether XML-RPC answers, whether the generator tag is in the
 * home page, whether /wp/v2/users lists users, and whether ?author=1 leaks an
 * author slug. Each probe is one same-host loopback request with no cookies;
 * the home page fetch reuses the scan-security hardening audit. Every
 * interpret_*() is pure (unit-tested). Read-only.
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
class EMCP_Tools_Hardening_Status {

	const FETCH_TIMEOUT = 8;

	/** @var EMCP_Tools_Security_Hardening_Audit */
	private $audit;

	public function __construct( ?EMCP_Tools_Security_Hardening_Audit $audit = null ) {
		$this->audit = $audit ?: new EMCP_Tools_Security_Hardening_Audit();
	}

	// ---- Pure interpreters -------------------------------------------------

	/**
	 * Read an XML-RPC probe (system.listMethods).
	 *
	 * @param int    $code HTTP status, 0 when the request failed.
	 * @param string $body Response body.
	 * @return string answering | blocked | unknown
	 */
	public static function interpret_xmlrpc( int $code, string $body ): string {
		if ( 0 === $code ) {
			return 'unknown';
		}
		if ( 200 === $code && false !== stripos( $body, '<methodResponse' ) ) {
			return 'answering';
		}
		if ( in_array( $code, array( 401, 403, 404, 405, 410, 444 ), true ) ) {
			return 'blocked';
		}
		return 'unknown';
	}

	/**
	 * Read an anonymous GET of /wp/v2/users.
	 *
	 * @param int    $code HTTP status, 0 when the request failed.
	 * @param string $body Response body.
	 * @return array{ status: string, count: int } status: lists_users | blocked | empty | unknown
	 */
	public static function interpret_users( int $code, string $body ): array {
		if ( 0 === $code ) {
			return array( 'status' => 'unknown', 'count' => 0 );
		}
		if ( 200 === $code ) {
			$data = json_decode( $body, true );
			if ( is_array( $data ) && array_is_list( $data ) ) {
				return array( 'status' => empty( $data ) ? 'empty' : 'lists_users', 'count' => count( $data ) );
			}
			return array( 'status' => 'unknown', 'count' => 0 );
		}
		if ( in_array( $code, array( 401, 403, 404 ), true ) ) {
			return array( 'status' => 'blocked', 'count' => 0 );
		}
		return array( 'status' => 'unknown', 'count' => 0 );
	}

	/**
	 * Read an anonymous GET of /?author=1 (redirects not followed).
	 *
	 * @param int    $code     HTTP status, 0 when the request failed.
	 * @param string $location Location header, '' when none.
	 * @return string leaks_slug | blocked | no_author | unknown
	 */
	public static function interpret_author( int $code, string $location ): string {
		if ( 0 === $code ) {
			return 'unknown';
		}
		if ( $code >= 300 && $code < 400 ) {
			return false !== stripos( $location, '/author/' ) ? 'leaks_slug' : 'blocked';
		}
		if ( 404 === $code ) {
			return 'no_author';
		}
		return 200 === $code ? 'leaks_slug' : 'unknown';
	}

	// ---- Live gather -------------------------------------------------------

	/**
	 * @return array
	 */
	public function run(): array {
		$stored = EMCP_Tools_Site_Hardening::normalize( get_option( EMCP_Tools_Site_Hardening::OPTION, array() ) );

		$xml   = $this->request( 'POST', site_url( 'xmlrpc.php' ), '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' );
		$users = $this->request( 'GET', rest_url( 'wp/v2/users' ) );
		$auth  = $this->request( 'GET', add_query_arg( 'author', '1', home_url( '/' ) ) );
		$home  = $this->audit->fetch_home();

		return array(
			'toggles' => EMCP_Tools_Site_Hardening::state_map( $stored ),
			'live'    => array(
				'xmlrpc'           => self::interpret_xmlrpc( $xml['code'], $xml['body'] ),
				'generator_tag'    => $home['ok'] ? ( $home['generator'] ? 'present' : 'absent' ) : 'unknown',
				'rest_users'       => self::interpret_users( $users['code'], $users['body'] ),
				'author_query'     => self::interpret_author( $auth['code'], $auth['location'] ),
				'readme_html'      => file_exists( ABSPATH . 'readme.html' ),
				'license_txt'      => file_exists( ABSPATH . 'license.txt' ),
				'display_errors'   => (string) ini_get( 'display_errors' ),
				'wp_debug_display' => defined( 'WP_DEBUG_DISPLAY' ) ? (bool) WP_DEBUG_DISPLAY : ( defined( 'WP_DEBUG' ) && WP_DEBUG ),
			),
			'errors'  => array_values( array_filter( array( $xml['error'], $users['error'], $auth['error'], $home['error'] ) ) ),
			'notes'   => array(
				__( 'Live checks are anonymous loopback requests to this site, so they show what a visitor sees. A host that blocks loopback requests reports "unknown".', 'emcp-tools' ),
				__( 'readme.html and license.txt are static files; no toggle can block them. Delete them with delete-file if you want them gone (WordPress puts them back on core updates).', 'emcp-tools' ),
				__( 'display_errors above is this request\'s value for an administrator; hide_php_errors only changes it for other visitors.', 'emcp-tools' ),
			),
		);
	}

	/**
	 * One loopback request with no cookies and no redirects followed.
	 *
	 * @param string $method GET | POST.
	 * @param string $url    URL.
	 * @param string $body   POST body.
	 * @return array{ code: int, body: string, location: string, error: ?string }
	 */
	private function request( string $method, string $url, string $body = '' ): array {
		$args = array(
			'method'      => $method,
			'timeout'     => self::FETCH_TIMEOUT,
			'redirection' => 0,
			'user-agent'  => 'EMCP-Security-Scanner/' . ( defined( 'EMCP_TOOLS_VERSION' ) ? EMCP_TOOLS_VERSION : '0' ),
		);
		if ( 'POST' === $method ) {
			$args['body']    = $body;
			$args['headers'] = array( 'Content-Type' => 'text/xml' );
		}
		$res = wp_remote_request( $url, $args );
		if ( is_wp_error( $res ) ) {
			return array( 'code' => 0, 'body' => '', 'location' => '', 'error' => $res->get_error_message() );
		}
		$location = wp_remote_retrieve_header( $res, 'location' );
		return array(
			'code'     => (int) wp_remote_retrieve_response_code( $res ),
			'body'     => substr( (string) wp_remote_retrieve_body( $res ), 0, 200000 ),
			'location' => is_array( $location ) ? (string) reset( $location ) : (string) $location,
			'error'    => null,
		);
	}
}
