<?php
/**
 * Serves `.webp` siblings by rewriting attachment URLs.
 *
 * Filters `wp_get_attachment_url` / `wp_get_attachment_image_src` /
 * `wp_calculate_image_srcset`. Rewrites a jpg/png URL to its `.webp` sibling
 * when the sibling file exists, on the frontend while "Serve WebP on the site"
 * is on and always in REST/CLI/cron (so the MCP media tools resolve to WebP).
 *
 * The decision never depends on the visitor's request. Elementor caches the
 * rendered widget HTML and writes image URLs into its generated CSS, so the
 * first request to render a page decided what every later visitor got: a
 * crawler without `image/webp` in its Accept header froze JPEG for everyone,
 * a WebP browser froze WebP for everyone. Every current browser shows WebP.
 *
 * @package EMCP_Tools
 * @since   3.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WebP URL rewriter.
 *
 * @since 3.1.0
 */
class EMCP_Tools_Webp_Rewriter {

	/** @var string Uploads base dir. */
	private $basedir;

	/** @var string Uploads base URL. */
	private $baseurl;

	/** @var bool Whether to rewrite frontend requests. */
	private $serve_frontend;

	/**
	 * @param bool $serve_frontend Rewrite frontend requests too (REST/CLI is always on).
	 */
	public function __construct( bool $serve_frontend = true ) {
		$upload               = wp_upload_dir();
		$this->basedir        = rtrim( $upload['basedir'] ?? '', '/\\' );
		$this->baseurl        = rtrim( $upload['baseurl'] ?? '', '/' );
		$this->serve_frontend = $serve_frontend;
	}

	/** Wire the URL filters. Called by the module's register(). */
	public function register(): void {
		add_filter( 'wp_get_attachment_url', array( $this, 'filter_url' ), 20 );
		add_filter( 'wp_get_attachment_image_src', array( $this, 'filter_image_src' ), 20 );
		add_filter( 'wp_calculate_image_srcset', array( $this, 'filter_srcset' ), 20 );
	}

	/**
	 * Whether URLs are rewritten to WebP in this context. Deliberately takes
	 * nothing from the request (see the file header).
	 *
	 * @param bool $is_rest        Whether we're in a REST/CLI/cron context.
	 * @param bool $serve_frontend Whether frontend rewriting is enabled.
	 * @return bool
	 */
	public static function should_rewrite( bool $is_rest, bool $serve_frontend = true ): bool {
		return $is_rest || $serve_frontend;
	}

	/**
	 * The `.webp` URL for a jpg/png/jpeg URL; other extensions returned as-is.
	 *
	 * @param string $url Source URL.
	 * @return string
	 */
	public static function webp_url( string $url ): string {
		if ( preg_match( '/\.(jpe?g|png)(\?.*)?$/i', $url ) ) {
			// Insert `.webp` before any query string.
			return preg_replace( '/(\.(?:jpe?g|png))(\?.*)?$/i', '$1.webp$2', $url );
		}
		return $url;
	}

	/** @return bool Whether this request is REST/CLI/cron. */
	private function is_rest_context(): bool {
		return ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'WP_CLI' ) && WP_CLI )
			|| ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() );
	}

	/** @return bool Whether the current request should get WebP. */
	private function allowed(): bool {
		return self::should_rewrite( $this->is_rest_context(), $this->serve_frontend );
	}

	/**
	 * Map an uploads URL to its absolute path (only for our uploads base).
	 *
	 * @param string $url Attachment URL.
	 * @return string Absolute path, or '' when outside uploads.
	 */
	private function url_to_path( string $url ): string {
		if ( '' === $this->baseurl || 0 !== strpos( $url, $this->baseurl ) ) {
			return '';
		}
		$rel = ltrim( substr( $url, strlen( $this->baseurl ) ), '/' );
		$rel = preg_replace( '/\?.*$/', '', $rel );
		return $this->basedir . '/' . $rel;
	}

	/**
	 * Rewrite one URL if allowed and its sibling exists.
	 *
	 * @param string $url Source URL.
	 * @return string Rewritten or original URL.
	 */
	private function maybe_rewrite( string $url ): string {
		if ( '' === $url || ! $this->allowed() ) {
			return $url;
		}
		$webp = self::webp_url( $url );
		if ( $webp === $url ) {
			return $url;
		}
		$path = $this->url_to_path( $url );
		if ( '' === $path || ! file_exists( $path . '.webp' ) ) {
			return $url;
		}
		return $webp;
	}

	/**
	 * @param string $url Attachment URL.
	 * @return string
	 */
	public function filter_url( $url ) {
		return is_string( $url ) ? $this->maybe_rewrite( $url ) : $url;
	}

	/**
	 * @param array|false $image [ url, width, height, is_intermediate ].
	 * @return array|false
	 */
	public function filter_image_src( $image ) {
		if ( is_array( $image ) && isset( $image[0] ) && is_string( $image[0] ) ) {
			$image[0] = $this->maybe_rewrite( $image[0] );
		}
		return $image;
	}

	/**
	 * @param array $sources Srcset sources keyed by width.
	 * @return array
	 */
	public function filter_srcset( $sources ) {
		if ( is_array( $sources ) ) {
			foreach ( $sources as $w => $src ) {
				if ( isset( $src['url'] ) && is_string( $src['url'] ) ) {
					$sources[ $w ]['url'] = $this->maybe_rewrite( $src['url'] );
				}
			}
		}
		return $sources;
	}
}
