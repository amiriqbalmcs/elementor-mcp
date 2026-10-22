<?php
/**
 * Image Optimization module — auto-compress uploads + generate/serve WebP.
 *
 * When active it hooks `wp_generate_attachment_metadata` (compress sub-sizes +
 * WebP siblings) and registers the WebP URL rewriter (so the frontend and the
 * MCP media tools serve the optimized file). A resumable bulk optimizer handles
 * the existing library from the Modules admin card. Free tier; opt-in.
 *
 * @package EMCP_Tools
 * @since   3.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Image Optimization module.
 *
 * @since 3.1.0
 */
class EMCP_Tools_Image_Optimization_Module extends EMCP_Tools_Module {

	const ID     = 'image-optimization';
	const PREFIX = 'emcp_tools_module_image_optimization_';

	public function id(): string {
		return self::ID;
	}

	/**
	 * Whether the module is active (static helper for the ability registrar, which
	 * runs on wp_abilities_api_init — before the module boots on init:5).
	 *
	 * @return bool
	 */
	public static function module_is_active(): bool {
		$active = (array) get_option( EMCP_Tools_Module::OPTION_ACTIVE, array() );
		return in_array( self::ID, $active, true );
	}

	public function title(): string {
		return __( 'Image Optimization', 'emcp-tools' );
	}

	public function description(): string {
		return __( 'Automatically compress uploaded images and generate/serve WebP. Images added to pages via MCP or AI Chat use the optimized version.', 'emcp-tools' );
	}

	public function tier(): string {
		return 'free';
	}

	/** Modules screen group. */
	public function group(): string {
		return 'content';
	}

	/** Modules screen icon. */
	public function icon(): string {
		return 'image';
	}

	public function default_active(): bool {
		return false;
	}

	/** WebP generation needs an image editor that supports WebP output. */
	public function is_available(): bool {
		return ( new EMCP_Tools_Webp_Generator( 82 ) )->is_available();
	}

	/**
	 * The five option keys + their sanitizers for the Modules settings group.
	 *
	 * @return array<string,array>
	 */
	public function settings_fields(): array {
		$bool = static function ( $v ) {
			return '1' === (string) $v ? '1' : '0';
		};
		$int = static function ( $v ) {
			return (string) max( 0, (int) $v );
		};
		return array(
			self::PREFIX . 'compress'       => array(
				'type'              => 'string',
				'default'           => '1',
				'sanitize_callback' => $bool,
			),
			self::PREFIX . 'webp'           => array(
				'type'              => 'string',
				'default'           => '1',
				'sanitize_callback' => $bool,
			),
			self::PREFIX . 'webp_serve'     => array(
				'type'              => 'string',
				'default'           => '1',
				'sanitize_callback' => $bool,
			),
			self::PREFIX . 'quality'        => array(
				'type'              => 'string',
				'default'           => '60',
				'sanitize_callback' => $int,
			),
			self::PREFIX . 'webp_quality'   => array(
				'type'              => 'string',
				'default'           => '0',
				'sanitize_callback' => static function ( $v ) {
					return (string) max( 0, min( 100, (int) $v ) );
				},
			),
			self::PREFIX . 'max_dimension'  => array(
				'type'              => 'string',
				'default'           => '0',
				'sanitize_callback' => $int,
			),
			self::PREFIX . 'keep_originals' => array(
				'type'              => 'string',
				'default'           => '1',
				'sanitize_callback' => $bool,
			),
		);
	}

	/** Labelled drawer fields (spec 8.4). */
	public function settings_schema(): array {
		return array(
			array( 'key' => self::PREFIX . 'compress', 'type' => 'toggle', 'label' => __( 'Compress uploads', 'emcp-tools' ), 'help' => __( 'Re-encode generated image sizes at the quality below.', 'emcp-tools' ) ),
			array( 'key' => self::PREFIX . 'webp', 'type' => 'toggle', 'label' => __( 'Create WebP copies', 'emcp-tools' ) ),
			array( 'key' => self::PREFIX . 'webp_serve', 'type' => 'toggle', 'label' => __( 'Serve WebP on the site', 'emcp-tools' ), 'parent' => self::PREFIX . 'webp', 'help' => __( 'Every visitor gets WebP where a WebP copy exists, so cached pages look the same for everyone. MCP and REST always get WebP.', 'emcp-tools' ) ),
			array( 'key' => self::PREFIX . 'quality', 'type' => 'range', 'label' => __( 'Quality', 'emcp-tools' ), 'min' => 1, 'max' => 100 ),
			array( 'key' => self::PREFIX . 'webp_quality', 'type' => 'number', 'label' => __( 'WebP quality', 'emcp-tools' ), 'parent' => self::PREFIX . 'webp', 'min' => 0, 'max' => 100, 'help' => __( '0 is automatic: 15 below Quality, where WebP looks the same as the JPEG and is smaller.', 'emcp-tools' ) ),
			array( 'key' => self::PREFIX . 'max_dimension', 'type' => 'number', 'label' => __( 'Largest side', 'emcp-tools' ), 'min' => 0, 'unit' => 'px', 'help' => __( '0 keeps the original size.', 'emcp-tools' ) ),
			array( 'key' => self::PREFIX . 'keep_originals', 'type' => 'toggle', 'label' => __( 'Keep originals', 'emcp-tools' ), 'help' => __( 'Back up files before changing them, so they can be restored.', 'emcp-tools' ) ),
		);
	}

	/** Why the module cannot be turned on here. */
	public function unavailable_reason(): string {
		return $this->is_available() ? '' : __( "Your server's image editor cannot write WebP files.", 'emcp-tools' );
	}

	/**
	 * Resolve the current settings into a typed array for the optimizer.
	 *
	 * @return array{compress:bool,webp:bool,webp_serve:bool,quality:int,webp_quality:int,max_dimension:int,keep_originals:bool}
	 */
	public function current_settings(): array {
		return array(
			'compress'       => '1' === (string) get_option( self::PREFIX . 'compress', '1' ),
			'webp'           => '1' === (string) get_option( self::PREFIX . 'webp', '1' ),
			'webp_serve'     => '1' === (string) get_option( self::PREFIX . 'webp_serve', '1' ),
			'quality'        => EMCP_Tools_Image_Optimizer::clamp_quality( (int) get_option( self::PREFIX . 'quality', 60 ) ),
			'webp_quality'   => max( 0, min( 100, (int) get_option( self::PREFIX . 'webp_quality', 0 ) ) ),
			'max_dimension'  => max( 0, (int) get_option( self::PREFIX . 'max_dimension', 0 ) ),
			'keep_originals' => '1' === (string) get_option( self::PREFIX . 'keep_originals', '1' ),
		);
	}

	/** Wire the module's runtime hooks. Called only when active + available. */
	public function register(): void {
		$settings = $this->current_settings();

		if ( $settings['compress'] || $settings['webp'] ) {
			$optimizer = new EMCP_Tools_Image_Optimizer( $settings );
			add_filter(
				'wp_generate_attachment_metadata',
				array( $optimizer, 'on_generate_metadata' ),
				20,
				2
			);
		}
		if ( $settings['webp'] ) {
			// REST/CLI (MCP media tools) always resolve to WebP; the frontend
			// rewrite is gated by the separate "serve on frontend" toggle.
			( new EMCP_Tools_Webp_Rewriter( $settings['webp_serve'] ) )->register();
		}
	}

	/**
	 * Elementor keeps the image URLs a page was first rendered with: widget HTML
	 * in its element cache, background images in its generated CSS files. So
	 * whenever the module starts or stops serving WebP, flush both, or visitors
	 * keep the old URLs. register() runs only while the module is on, so the
	 * bootstrap wires this unconditionally.
	 */
	public static function watch_changes(): void {
		add_action( 'update_option_' . EMCP_Tools_Module::OPTION_ACTIVE, array( __CLASS__, 'on_modules_changed' ), 10, 2 );
		foreach ( array( 'webp', 'webp_serve' ) as $key ) {
			add_action( 'add_option_' . self::PREFIX . $key, array( __CLASS__, 'flush_elementor_cache' ), 10, 0 );
			add_action( 'update_option_' . self::PREFIX . $key, array( __CLASS__, 'flush_elementor_cache' ), 10, 0 );
		}
	}

	/**
	 * @param mixed $old Previous active module ids.
	 * @param mixed $now New active module ids.
	 */
	public static function on_modules_changed( $old, $now ): void {
		$was = in_array( self::ID, is_array( $old ) ? $old : array(), true );
		$is  = in_array( self::ID, is_array( $now ) ? $now : array(), true );
		if ( $was !== $is ) {
			self::flush_elementor_cache();
		}
	}

	/**
	 * Drop Elementor's rendered-element cache and generated CSS so pages are
	 * rendered again with the current image URLs.
	 */
	public static function flush_elementor_cache(): void {
		if ( class_exists( '\Elementor\Plugin' ) && isset( \Elementor\Plugin::$instance->files_manager ) ) {
			// Deletes the CSS files and, on current Elementor, the element cache.
			\Elementor\Plugin::$instance->files_manager->clear_cache();
		}
		// Older Elementor versions leave the element cache in place.
		delete_post_meta_by_key( EMCP_Tools_Data::ELEMENT_CACHE_META );
	}

	/** Render the card knobs. Delegates to the shared view partial. */
	public function render_settings(): void {
		$settings = $this->current_settings();
		include EMCP_TOOLS_DIR . 'includes/modules/image-optimization/settings-fields.php';
	}
}
