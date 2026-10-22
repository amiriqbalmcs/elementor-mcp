<?php
/**
 * Compress-on-upload pipeline for the Image Optimization module.
 *
 * Runs on `wp_generate_attachment_metadata`: preserves the full-size (only
 * trimmed when a max-dimension cap is set), backs up each file it touches under
 * `uploads/emcp-originals/`, re-compresses the generated sub-sizes in place, and
 * (when enabled) generates a `.webp` sibling per size from the untouched file,
 * keeping it only when it is smaller than the image. Records per-attachment
 * results in `_emcp_optim` meta and is idempotent (status=done short-circuits).
 *
 * @package EMCP_Tools
 * @since   3.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Image optimizer.
 *
 * @since 3.1.0
 */
class EMCP_Tools_Image_Optimizer {

	const META_KEY = '_emcp_optim';

	/**
	 * How far below the JPEG quality the automatic WebP quality sits. WebP
	 * matches a JPEG's look at a lower number: on sample photos WebP at 45
	 * kept more detail than JPEG at 60 and was 15% smaller.
	 */
	const WEBP_QUALITY_OFFSET = 15;

	/** @var array{compress:bool,webp:bool,quality:int,webp_quality:int,max_dimension:int,keep_originals:bool} */
	private $settings;

	/**
	 * @param array $settings Module settings (see module option map).
	 */
	public function __construct( array $settings ) {
		$quality        = self::clamp_quality( (int) ( $settings['quality'] ?? 60 ) );
		$this->settings = array(
			'compress'       => ! empty( $settings['compress'] ),
			'webp'           => ! empty( $settings['webp'] ),
			'quality'        => $quality,
			'webp_quality'   => self::webp_quality( (int) ( $settings['webp_quality'] ?? 0 ), $quality ),
			'max_dimension'  => max( 0, (int) ( $settings['max_dimension'] ?? 0 ) ),
			'keep_originals' => ! empty( $settings['keep_originals'] ),
		);
	}

	/**
	 * Clamp a quality value to the supported 1–100 range (matches the slider).
	 *
	 * @param int $q Raw quality.
	 * @return int Clamped quality.
	 */
	public static function clamp_quality( int $q ): int {
		return max( 1, min( 100, $q ) );
	}

	/**
	 * The quality WebP siblings are encoded at.
	 *
	 * @param int $webp_quality Stored WebP quality (0 = automatic).
	 * @param int $jpeg_quality JPEG quality.
	 * @return int The stored value, or the JPEG quality less WEBP_QUALITY_OFFSET.
	 */
	public static function webp_quality( int $webp_quality, int $jpeg_quality ): int {
		if ( $webp_quality > 0 ) {
			return self::clamp_quality( $webp_quality );
		}
		return self::clamp_quality( $jpeg_quality - self::WEBP_QUALITY_OFFSET );
	}

	/**
	 * The file a WebP sibling is encoded from: the untouched backup under
	 * `emcp-originals` when there is one, else the file itself (which
	 * process_files() then encodes before re-compressing it). Encoding from the
	 * re-compressed JPEG stacks a second lossy pass on the first and gave
	 * siblings no smaller than the JPEG.
	 *
	 * @param string $file   Absolute image path.
	 * @param string $backup Its backup path (see backup_path()).
	 * @return string Absolute path to encode from.
	 */
	public static function webp_source( string $file, string $backup ): string {
		return ( '' !== $backup && file_exists( $backup ) ) ? $backup : $file;
	}

	/**
	 * Absolute paths of every size file to process (full + generated sub-sizes).
	 *
	 * @param array  $metadata Attachment metadata (`file`, `sizes`).
	 * @param string $basedir  Uploads base dir (no trailing slash).
	 * @return string[] Absolute file paths.
	 */
	public function sizes_to_process( array $metadata, string $basedir ): array {
		$basedir = rtrim( $basedir, '/\\' );
		$files   = array();

		if ( empty( $metadata['file'] ) ) {
			return $files;
		}

		$full    = $basedir . '/' . $metadata['file'];
		$files[] = $full;
		$dir     = dirname( $full );

		if ( ! empty( $metadata['sizes'] ) && is_array( $metadata['sizes'] ) ) {
			foreach ( $metadata['sizes'] as $size ) {
				if ( ! empty( $size['file'] ) ) {
					$files[] = $dir . '/' . $size['file'];
				}
			}
		}
		return array_values( array_unique( $files ) );
	}

	/**
	 * Backup path for a file, mirroring its uploads-relative path under
	 * `uploads/emcp-originals/`.
	 *
	 * @param string $file   Absolute file inside uploads.
	 * @param array  $upload wp_upload_dir() array (needs `basedir`).
	 * @return string Absolute backup path.
	 */
	public static function backup_path( string $file, array $upload ): string {
		$basedir = rtrim( $upload['basedir'] ?? '', '/\\' );
		$rel     = ltrim( str_replace( $basedir, '', $file ), '/\\' );
		return $basedir . '/emcp-originals/' . $rel;
	}

	/**
	 * @param array $optim Existing `_emcp_optim` meta.
	 * @return bool Whether processing should be skipped (already done).
	 */
	public function should_skip( array $optim ): bool {
		return isset( $optim['status'] ) && 'done' === $optim['status'];
	}

	/**
	 * Hook callback for `wp_generate_attachment_metadata`.
	 *
	 * @param array $metadata      Attachment metadata.
	 * @param int   $attachment_id Attachment ID.
	 * @return array The (unchanged) metadata — WordPress expects it returned.
	 */
	public function on_generate_metadata( $metadata, $attachment_id ) {
		if ( ! is_array( $metadata ) ) {
			return $metadata;
		}
		if ( ! $this->settings['compress'] && ! $this->settings['webp'] ) {
			return $metadata;
		}
		/**
		 * Per-attachment opt-out. Return false to skip compression + WebP for a
		 * single attachment — used by sideload-image / add-stock-image when the
		 * caller passes convert_webp:false (conversion timing out on shared hosting).
		 *
		 * @param bool $do            Whether to optimise (default true).
		 * @param int  $attachment_id The attachment being processed.
		 */
		if ( ! apply_filters( 'emcp_tools_optimize_attachment', true, (int) $attachment_id ) ) {
			return $metadata;
		}
		$mime = get_post_mime_type( (int) $attachment_id );
		if ( ! in_array( $mime, array( 'image/jpeg', 'image/png' ), true ) ) {
			return $metadata;
		}
		$existing = get_post_meta( (int) $attachment_id, self::META_KEY, true );
		if ( is_array( $existing ) && $this->should_skip( $existing ) ) {
			return $metadata;
		}

		$upload  = wp_upload_dir();
		$basedir = $upload['basedir'] ?? '';
		$files   = $this->sizes_to_process( $metadata, $basedir );
		$result  = $this->process_files( $files, $upload, $metadata['file'] ?? '', $basedir );

		update_post_meta( (int) $attachment_id, self::META_KEY, $result );
		return $metadata;
	}

	/**
	 * Process a concrete list of files (used by both upload + bulk paths).
	 *
	 * @param string[] $files    Absolute paths.
	 * @param array    $upload   wp_upload_dir() array.
	 * @param string   $full_rel Uploads-relative path of the full-size (for the cap).
	 * @param string   $basedir  Uploads base dir.
	 * @return array Result meta.
	 */
	public function process_files( array $files, array $upload, string $full_rel, string $basedir ): array {
		$generator  = new EMCP_Tools_Webp_Generator( $this->settings['webp_quality'] );
		$webp_ok    = $this->settings['webp'] && $generator->is_available();
		$full_abs   = '' !== $full_rel ? rtrim( $basedir, '/\\' ) . '/' . $full_rel : '';
		$before     = 0;
		$after      = 0;
		$webp_bytes = 0;
		$backups    = array();
		$webps      = array();

		foreach ( $files as $file ) {
			if ( ! file_exists( $file ) ) {
				continue;
			}
			$before += (int) filesize( $file );

			$backup = self::backup_path( $file, $upload );
			if ( $this->settings['keep_originals'] ) {
				if ( ! file_exists( $backup ) ) {
					wp_mkdir_p( dirname( $backup ) );
					@copy( $file, $backup );
					$backups[] = $backup;
				}
			}

			$source    = self::webp_source( $file, $backup );
			$cap       = $this->settings['compress'] && $this->settings['max_dimension'] > 0 && $file === $full_abs ? $this->settings['max_dimension'] : 0;
			$webp_done = false;
			if ( $webp_ok && $source === $file && $this->settings['compress'] ) {
				// No untouched copy outlives the re-save below: encode WebP first.
				$this->write_webp( $generator, $file, $file, $cap );
				$webp_done = true;
			}

			$editor = wp_get_image_editor( $file );
			if ( ! is_wp_error( $editor ) ) {
				if ( $this->settings['max_dimension'] > 0 && $file === $full_abs ) {
					$editor->resize( $this->settings['max_dimension'], $this->settings['max_dimension'], false );
				}
				// After resize(): WP_Image_Editor resets the quality to its default there.
				$editor->set_quality( $this->settings['quality'] );
				if ( $this->settings['compress'] ) {
					$editor->save( $file );
				}
			}
			clearstatcache( true, $file );
			$after += (int) filesize( $file );

			if ( $webp_ok ) {
				if ( ! $webp_done ) {
					// A backup can be larger than the file (capped, or resized
					// by resize-media): scale it to the file's own size.
					$max_side = $cap > 0 ? $cap : ( $source !== $file ? self::longest_side( $file ) : 0 );
					$this->write_webp( $generator, $file, $source, $max_side );
				}
				$sibling = EMCP_Tools_Webp_Generator::sibling_path( $file );
				clearstatcache( true, $sibling );
				if ( file_exists( $sibling ) ) {
					if ( filesize( $sibling ) < filesize( $file ) ) {
						$webps[]     = $sibling;
						$webp_bytes += (int) filesize( $sibling );
					} else {
						// Serving it would make the page heavier, not lighter.
						@unlink( $sibling );
					}
				}
			}
		}

		return array(
			'status'          => 'done',
			'original_bytes'  => $before,
			'optimized_bytes' => $after,
			'webp_bytes'      => $webp_bytes,
			'backups'         => $backups,
			'webps'           => $webps,
		);
	}

	/**
	 * Encode the WebP sibling of $file from $source. A sibling no smaller than
	 * $file (left by versions that encoded from the compressed JPEG) is
	 * replaced; a smaller one is kept.
	 *
	 * @param EMCP_Tools_Webp_Generator $generator Generator.
	 * @param string                    $file      Image the sibling belongs to.
	 * @param string                    $source    File to encode from.
	 * @param int                       $max_side  Fit box for the source (0 = keep).
	 */
	private function write_webp( EMCP_Tools_Webp_Generator $generator, string $file, string $source, int $max_side ): void {
		$sibling = EMCP_Tools_Webp_Generator::sibling_path( $file );
		clearstatcache( true, $sibling );
		if ( file_exists( $sibling ) && filesize( $sibling ) >= filesize( $file ) ) {
			@unlink( $sibling );
		}
		$generator->generate( $file, $source, $max_side );
	}

	/**
	 * @param string $file Absolute image path.
	 * @return int Its longer side in pixels, 0 when unreadable.
	 */
	private static function longest_side( string $file ): int {
		$size = @getimagesize( $file );
		return is_array( $size ) ? max( (int) $size[0], (int) $size[1] ) : 0;
	}
}
