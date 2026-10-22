<?php
/**
 * Generates `.webp` siblings for image files via WP_Image_Editor.
 *
 * A sibling is `name-800x600.jpg.webp` next to `name-800x600.jpg`, so the
 * original extension is preserved and the rewriter can find it deterministically.
 * The pixels can come from another file than the one the sibling stands in for
 * (the untouched original), so WebP is not encoded from an already
 * re-compressed JPEG.
 *
 * @package EMCP_Tools
 * @since   3.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WebP sibling generator.
 *
 * @since 3.1.0
 */
class EMCP_Tools_Webp_Generator {

	/** @var int WebP quality, already clamped by the caller. */
	private $quality;

	/**
	 * @param int $quality WebP encode quality (1–100).
	 */
	public function __construct( int $quality ) {
		$this->quality = $quality;
	}

	/**
	 * The `.webp` sibling path for a given image file.
	 *
	 * @param string $file Absolute image path.
	 * @return string Sibling path (`$file . '.webp'`).
	 */
	public static function sibling_path( string $file ): string {
		return $file . '.webp';
	}

	/** @return bool Whether this server's image editor can output WebP. */
	public function is_available(): bool {
		return (bool) wp_image_editor_supports( array( 'mime_type' => 'image/webp' ) );
	}

	/**
	 * Generate a `.webp` sibling for one file. Skips if the sibling already
	 * exists or WebP is unsupported.
	 *
	 * @param string $file     Absolute image path the sibling belongs to.
	 * @param string $source   File to encode from ('' = $file), e.g. the backup
	 *                         of the original before compression.
	 * @param int    $max_side Scale the source down to fit this box (0 = keep),
	 *                         so the sibling matches the size of $file.
	 * @return string|\WP_Error Sibling path on success, WP_Error otherwise.
	 */
	public function generate( string $file, string $source = '', int $max_side = 0 ) {
		if ( ! $this->is_available() ) {
			return new \WP_Error( 'webp_unsupported', __( 'This server cannot generate WebP images.', 'emcp-tools' ) );
		}
		$sibling = self::sibling_path( $file );
		if ( file_exists( $sibling ) ) {
			return $sibling;
		}
		$editor = wp_get_image_editor( '' !== $source ? $source : $file );
		if ( is_wp_error( $editor ) ) {
			return $editor;
		}
		if ( $max_side > 0 ) {
			// An error here means the source already fits: encode it as it is.
			$editor->resize( $max_side, $max_side, false );
		}
		// Saving to another format makes WP_Image_Editor reset its quality to
		// the `wp_editor_set_quality` default (86 for WebP), discarding
		// set_quality(), so the setting is applied through that filter instead.
		$quality = $this->quality;
		$force   = static function ( $q, $mime_type ) use ( $quality ) {
			return 'image/webp' === $mime_type ? $quality : $q;
		};
		add_filter( 'wp_editor_set_quality', $force, PHP_INT_MAX, 2 );
		$editor->set_quality( $quality );
		$saved = $editor->save( $sibling, 'image/webp' );
		remove_filter( 'wp_editor_set_quality', $force, PHP_INT_MAX );
		if ( is_wp_error( $saved ) ) {
			return $saved;
		}
		return $sibling;
	}
}
