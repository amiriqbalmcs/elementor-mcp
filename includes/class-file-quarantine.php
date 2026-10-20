<?php
/**
 * File quarantine: moves a suspicious file or folder out of the web root so it
 * stops running, keeps a manifest of what it was, and puts it back on request.
 *
 * Entries live in `<folder above WordPress>/emcp-quarantine/` when that folder
 * is writable, else in `wp-content/emcp-quarantine/` behind a deny-all
 * .htaccess and an empty index.php. Each entry is
 * `<base>/<YYYYMMDD-HHMMSS>-<id>/<original relative path>` plus a sibling
 * manifest `<base>/<entry id>.json`.
 *
 * The rules (path checks, refusals, naming, manifests) are pure static methods
 * with no filesystem access, so they are unit tested on their own. quarantine(),
 * restore(), entries() and rollback() are the thin wrappers that touch disk.
 * Every wrapper takes an optional context array (root, content dir, user, time)
 * so tests can run against a temporary directory.
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
class EMCP_Tools_File_Quarantine {

	const DIR_NAME         = 'emcp-quarantine';
	const ROLLBACK_TYPE    = 'file-quarantine';
	const LOCATION_OUTSIDE = 'outside-web-root';
	const LOCATION_CONTENT = 'wp-content';
	const STATUS_HELD      = 'quarantined';
	const STATUS_RESTORED  = 'restored';
	const MAX_FILES        = 20000; // Files in one quarantined folder.
	const MAX_REASON       = 500;   // Characters kept from a reason.
	const MAX_LIST         = 500;   // Entries list-quarantine returns.

	/**
	 * Appended to every stored file name, so no web server runs a quarantined
	 * file as PHP even where the folder's .htaccess is ignored (nginx, IIS).
	 */
	const SUFFIX = '.quarantined';

	/** Folder names that are web roots on common hosts. */
	const WEB_ROOT_NAMES = array( 'public_html', 'public', 'www', 'wwwroot', 'htdocs', 'httpdocs', 'html', 'web' );

	/** Files that mark a folder as served by the web server. */
	const WEB_ROOT_MARKERS = array( 'index.php', 'index.html', 'index.htm', 'wp-config.php', '.htaccess', 'web.config' );

	/** Root files WordPress needs to load at all. */
	const PROTECTED_ROOT_FILES = array( 'wp-config.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', 'index.php' );

	/** Core folders: a back door here is fixed by reinstalling core, not by moving files. */
	const PROTECTED_DIRS = array( 'wp-admin', 'wp-includes' );

	// ---- Pure rules ----------------------------------------------------

	/**
	 * Pure: forward slashes only.
	 *
	 * @param string $path Any path.
	 */
	public static function slash( string $path ): string {
		return str_replace( '\\', '/', $path );
	}

	/**
	 * Pure: whether $path is $dir or inside it (both already normalized).
	 *
	 * @param string $path Path.
	 * @param string $dir  Directory.
	 */
	public static function is_within( string $path, string $dir ): bool {
		$dir = rtrim( $dir, '/' );
		return $path === $dir || 0 === strpos( $path, $dir . '/' );
	}

	/**
	 * Pure: turn input into a clean path relative to the site root. An absolute
	 * path inside $root is accepted. '..' segments and other absolute paths are
	 * refused. Returns '' for the root itself.
	 *
	 * @param string $path Input path.
	 * @param string $root Canonical site root (forward slashes).
	 * @return string|\WP_Error
	 */
	public static function normalize_relative( string $path, string $root = '' ) {
		$path = self::slash( trim( $path ) );
		if ( '' === $path || false !== strpos( $path, "\0" ) ) {
			return new \WP_Error( 'invalid_path', __( 'Invalid file path.', 'emcp-tools' ) );
		}
		$root = rtrim( self::slash( $root ), '/' );
		if ( '' !== $root && self::is_within( $path, $root ) ) {
			$path = (string) substr( $path, strlen( $root ) );
		} elseif ( 1 === preg_match( '#^(/|[A-Za-z]:)#', $path ) ) {
			return new \WP_Error( 'outside_root', __( 'Path is outside the WordPress installation.', 'emcp-tools' ) );
		}
		$parts = array();
		foreach ( explode( '/', $path ) as $segment ) {
			if ( '' === $segment || '.' === $segment ) {
				continue;
			}
			if ( '..' === $segment ) {
				return new \WP_Error( 'outside_root', __( 'Path is outside the WordPress installation.', 'emcp-tools' ) );
			}
			$parts[] = $segment;
		}
		return implode( '/', $parts );
	}

	/**
	 * Pure: why a relative path may not be quarantined, or null when it may.
	 *
	 * @param string $rel         Clean relative path (normalize_relative()).
	 * @param string $content_rel wp-content relative to the root.
	 * @param string $plugin_rel  This plugin's folder relative to the root ('' when outside).
	 * @return \WP_Error|null
	 */
	public static function refusal( string $rel, string $content_rel = 'wp-content', string $plugin_rel = '' ) {
		$lower = strtolower( $rel );
		if ( '' === $lower ) {
			return new \WP_Error( 'protected_root', __( 'The whole site cannot be quarantined.', 'emcp-tools' ) );
		}
		if ( in_array( $lower, self::PROTECTED_ROOT_FILES, true ) ) {
			return new \WP_Error( 'protected_core', __( 'This WordPress core file is needed to load the site. Restore it from a clean WordPress copy instead.', 'emcp-tools' ) );
		}
		$top = explode( '/', $lower )[0];
		if ( in_array( $top, self::PROTECTED_DIRS, true ) ) {
			return new \WP_Error( 'protected_core', __( 'Files in wp-admin and wp-includes are WordPress core. Reinstall core to replace them instead.', 'emcp-tools' ) );
		}
		$content = strtolower( trim( $content_rel, '/' ) );
		if ( '' !== $content && $lower === $content ) {
			return new \WP_Error( 'protected_root', __( 'The whole wp-content folder cannot be quarantined.', 'emcp-tools' ) );
		}
		if ( self::is_within( $lower, ( '' === $content ? '' : $content . '/' ) . self::DIR_NAME ) ) {
			return new \WP_Error( 'protected_quarantine', __( 'The quarantine folder itself cannot be quarantined.', 'emcp-tools' ) );
		}
		$plugin = strtolower( trim( $plugin_rel, '/' ) );
		if ( '' !== $plugin && self::is_within( $lower, $plugin ) ) {
			return new \WP_Error( 'protected_plugin', __( 'EMCP Tools cannot quarantine its own files, because it needs them to restore anything.', 'emcp-tools' ) );
		}
		return null;
	}

	/**
	 * Pure: a quarantine entry id.
	 *
	 * @param int    $time Unix time.
	 * @param string $hex  Random hex characters.
	 */
	public static function new_id( int $time, string $hex ): string {
		return gmdate( 'Ymd-His', $time ) . '-' . strtolower( $hex );
	}

	/**
	 * Pure: whether a string is a well-formed entry id.
	 *
	 * @param string $id Candidate.
	 */
	public static function is_valid_id( string $id ): bool {
		return 1 === preg_match( '/^\d{8}-\d{6}-[a-f0-9]{8}$/', $id );
	}

	/**
	 * Pure: the quarantine folder to use.
	 *
	 * @param string $root        Site root.
	 * @param string $content_dir wp-content directory.
	 * @param bool   $outside_ok  Whether the folder above the root is writable.
	 * @return array{dir: string, location: string}
	 */
	public static function choose_base( string $root, string $content_dir, bool $outside_ok ): array {
		$bases = self::candidate_bases( $root, $content_dir );
		return $outside_ok ? $bases[0] : $bases[1];
	}

	/**
	 * Pure: both possible quarantine folders, outside first.
	 *
	 * @param string $root        Site root.
	 * @param string $content_dir wp-content directory.
	 * @return array<int, array{dir: string, location: string}>
	 */
	public static function candidate_bases( string $root, string $content_dir ): array {
		$parent = rtrim( self::slash( dirname( rtrim( self::slash( $root ), '/' ) ) ), '/' );
		return array(
			array( 'dir' => $parent . '/' . self::DIR_NAME, 'location' => self::LOCATION_OUTSIDE ),
			array( 'dir' => rtrim( self::slash( $content_dir ), '/' ) . '/' . self::DIR_NAME, 'location' => self::LOCATION_CONTENT ),
		);
	}

	/**
	 * Pure: where an entry's payload is stored.
	 *
	 * @param string $base Quarantine folder.
	 * @param string $id   Entry id.
	 * @param string $rel  Original relative path.
	 */
	public static function stored_path( string $base, string $id, string $rel ): string {
		return rtrim( $base, '/' ) . '/' . $id . '/' . $rel;
	}

	/**
	 * Pure: where an entry's manifest is stored (next to the entry folder, so it
	 * can never collide with a quarantined file's own name).
	 *
	 * @param string $base Quarantine folder.
	 * @param string $id   Entry id.
	 */
	public static function manifest_path( string $base, string $id ): string {
		return rtrim( $base, '/' ) . '/' . $id . '.json';
	}

	/**
	 * Pure: a reason as plain text, at most MAX_REASON characters.
	 *
	 * @param string $reason Input.
	 */
	public static function clean_reason( string $reason ): string {
		$reason = trim( (string) preg_replace( '/[\x00-\x1F\x7F]+/u', ' ', $reason ) );
		return function_exists( 'mb_substr' ) ? mb_substr( $reason, 0, self::MAX_REASON ) : substr( $reason, 0, self::MAX_REASON );
	}

	/**
	 * Pure: a manifest from the facts gathered about an item.
	 *
	 * @param array $f id, original_path, type, size, files, sha256, symlink, mtime, ctime,
	 *                 reason, user_id, user_login, time, location, method.
	 * @return array
	 */
	public static function build_manifest( array $f ): array {
		$is_dir = 'dir' === ( $f['type'] ?? '' );
		return array(
			'id'            => (string) ( $f['id'] ?? '' ),
			'original_path' => (string) ( $f['original_path'] ?? '' ),
			'type'          => $is_dir ? 'dir' : 'file',
			'size'          => (int) ( $f['size'] ?? 0 ),
			'files'         => $is_dir ? (int) ( $f['files'] ?? 0 ) : 1,
			'sha256'        => $is_dir || empty( $f['sha256'] ) ? null : (string) $f['sha256'],
			'symlink'       => ! empty( $f['symlink'] ),
			'mtime'         => (int) ( $f['mtime'] ?? 0 ),
			'ctime'         => (int) ( $f['ctime'] ?? 0 ),
			'reason'        => self::clean_reason( (string) ( $f['reason'] ?? '' ) ),
			'user'          => array(
				'id'    => (int) ( $f['user_id'] ?? 0 ),
				'login' => (string) ( $f['user_login'] ?? '' ),
			),
			'time'          => gmdate( 'c', (int) ( $f['time'] ?? 0 ) ),
			'location'      => (string) ( $f['location'] ?? '' ),
			'method'        => (string) ( $f['method'] ?? '' ),
			'status'        => self::STATUS_HELD,
			'change_id'     => (string) ( $f['change_id'] ?? '' ),
			'restored_at'   => null,
			'neutralized'   => ! empty( $f['neutralized'] ),
		);
	}

	/**
	 * Pure: a manifest read from disk, or null when it is not one of ours or
	 * its path would leave the root. Manifests are data, never trusted paths.
	 *
	 * @param string $json Manifest file contents.
	 * @return array|null
	 */
	public static function parse_manifest( string $json ): ?array {
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || ! self::is_valid_id( (string) ( $data['id'] ?? '' ) ) ) {
			return null;
		}
		$rel = self::normalize_relative( (string) ( $data['original_path'] ?? '' ) );
		if ( is_wp_error( $rel ) || '' === $rel || $rel !== $data['original_path'] ) {
			return null;
		}
		return $data;
	}

	/**
	 * Pure: whether a restore may write to the original path.
	 *
	 * @param bool $exists    Something is at the original path now.
	 * @param bool $overwrite The caller passed overwrite:true.
	 * @return \WP_Error|null
	 */
	public static function restore_conflict( bool $exists, bool $overwrite ) {
		if ( $exists && ! $overwrite ) {
			return new \WP_Error( 'target_exists', __( 'Something already exists at the original path. Pass overwrite:true to quarantine it and restore this entry in its place.', 'emcp-tools' ) );
		}
		return null;
	}

	/**
	 * Pure: deny-all rules for Apache 2.4 and 2.2.
	 */
	public static function htaccess_rules(): string {
		return "# EMCP Tools quarantine: never serve these files.\n"
			. "<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n"
			. "<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n";
	}

	/**
	 * Pure: deny-all rules for IIS, which ignores .htaccess.
	 */
	public static function web_config_rules(): string {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n\t<system.webServer>\n\t\t<security>\n\t\t\t<authorization>\n\t\t\t\t<remove users=\"*\" roles=\"\" verbs=\"\" />\n\t\t\t\t<add accessType=\"Deny\" users=\"*\" />\n\t\t\t</authorization>\n\t\t</security>\n\t</system.webServer>\n\t<system.web>\n\t\t<authorization>\n\t\t\t<deny users=\"*\" />\n\t\t</authorization>\n\t</system.web>\n</configuration>\n";
	}

	// ---- Context -------------------------------------------------------

	/**
	 * The live context, merged over anything the caller passes (tests pass a
	 * temporary root and content dir).
	 *
	 * @param array $ctx root, content_dir, plugin_dir, outside_ok, user_id, user_login, now, force_copy.
	 * @return array
	 */
	public static function context( array $ctx = array() ): array {
		$root = rtrim( self::slash( (string) realpath( $ctx['root'] ?? ABSPATH ) ), '/' );
		$out  = array_merge(
			array(
				'content_dir' => defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : $root . '/wp-content',
				'plugin_dir'  => defined( 'EMCP_TOOLS_DIR' ) ? EMCP_TOOLS_DIR : '',
				'user_id'     => function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0,
				'user_login'  => function_exists( 'wp_get_current_user' ) ? (string) wp_get_current_user()->user_login : '',
				'now'         => time(),
				'force_copy'  => false,
			),
			$ctx
		);
		$out['root']        = $root;
		$out['content_dir'] = rtrim( self::slash( (string) $out['content_dir'] ), '/' );
		if ( ! isset( $out['outside_ok'] ) ) {
			$out['outside_ok'] = self::outside_writable( $root );
		}
		return $out;
	}

	/**
	 * Path relative to the root, or the path itself when it is outside.
	 *
	 * @param string $abs  Absolute path (forward slashes).
	 * @param string $root Root.
	 */
	public static function relative( string $abs, string $root ): string {
		$abs = rtrim( self::slash( $abs ), '/' );
		if ( $abs === $root ) {
			return '';
		}
		return self::is_within( $abs, $root ) ? substr( $abs, strlen( $root ) + 1 ) : $abs;
	}

	/**
	 * Whether the folder above the root can hold the quarantine.
	 *
	 * @param string $root Root.
	 */
	private static function outside_writable( string $root ): bool {
		$base = self::candidate_bases( $root, $root )[0]['dir'];
		if ( self::looks_web_served( dirname( $base ) ) ) {
			return false; // WordPress sits in a subfolder of a web root: "above WordPress" is still public.
		}
		if ( is_dir( $base ) ) {
			return @is_writable( $base ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		return @is_writable( dirname( $base ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Whether a folder looks like it is served by the web server: a common
	 * web-root name, or a folder holding an index, wp-config.php or server
	 * config of its own (WordPress installed in a subfolder of a site).
	 *
	 * @param string $dir Folder.
	 */
	public static function looks_web_served( string $dir ): bool {
		$dir = rtrim( self::slash( $dir ), '/' );
		if ( in_array( strtolower( basename( $dir ) ), self::WEB_ROOT_NAMES, true ) ) {
			return true;
		}
		foreach ( self::WEB_ROOT_MARKERS as $marker ) {
			if ( file_exists( $dir . '/' . $marker ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Rename every file of a stored item to end in SUFFIX.
	 *
	 * @param string $stored Stored file or folder.
	 * @return true|\WP_Error
	 */
	private static function neutralize( string $stored ) {
		return self::rename_all( $stored, true );
	}

	/**
	 * Undo neutralize(): strip one SUFFIX from every stored file name.
	 *
	 * @param string $stored Stored file or folder (its plain path).
	 * @return true|\WP_Error
	 */
	private static function revive( string $stored ) {
		return self::rename_all( $stored, false );
	}

	/**
	 * Add or strip SUFFIX on a stored file, or on every file in a stored folder.
	 * A failure part way undoes the renames already made.
	 *
	 * @param string $stored Plain stored path.
	 * @param bool   $add    True to add the suffix, false to strip it.
	 * @return true|\WP_Error
	 */
	private static function rename_all( string $stored, bool $add ) {
		$pairs = array();
		if ( is_dir( $stored ) && ! is_link( $stored ) ) {
			foreach ( EMCP_Tools_File_Mover::walk( $stored ) as $item ) {
				if ( 'dir' === $item['kind'] ) {
					continue;
				}
				if ( $add ) {
					$pairs[] = array( $item['path'], $item['path'] . self::SUFFIX );
				} elseif ( self::SUFFIX === substr( $item['path'], -strlen( self::SUFFIX ) ) ) {
					$pairs[] = array( $item['path'], substr( $item['path'], 0, -strlen( self::SUFFIX ) ) );
				}
			}
		} else {
			$pairs[] = $add ? array( $stored, $stored . self::SUFFIX ) : array( $stored . self::SUFFIX, $stored );
		}
		$done = array();
		foreach ( $pairs as $pair ) {
			if ( ! @rename( $pair[0], $pair[1] ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.rename_rename
				foreach ( array_reverse( $done ) as $back ) {
					@rename( $back[1], $back[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.rename_rename
				}
				return new \WP_Error( 'rename_failed', __( 'Could not rename the quarantined files.', 'emcp-tools' ) );
			}
			$done[] = $pair;
		}
		return true;
	}

	/**
	 * Where a stored item can be found on disk: a single file carries SUFFIX.
	 *
	 * @param string $stored   Plain stored path.
	 * @param array  $manifest Manifest.
	 */
	private static function on_disk( string $stored, array $manifest ): string {
		return ! empty( $manifest['neutralized'] ) && 'dir' !== ( $manifest['type'] ?? '' ) ? $stored . self::SUFFIX : $stored;
	}

	// ---- Quarantine ----------------------------------------------------

	/**
	 * Move a file or folder into quarantine.
	 *
	 * @param string $path   Path relative to the root (or absolute inside it).
	 * @param string $reason Why.
	 * @param array  $ctx    Context overrides (tests).
	 * @return array|\WP_Error { manifest, base, stored_at, warnings }
	 */
	public static function quarantine( string $path, string $reason = '', array $ctx = array() ) {
		$ctx = self::context( $ctx );
		if ( '' === $ctx['root'] ) {
			return self::bad_root();
		}
		$source = self::resolve_source( $path, $ctx );
		if ( is_wp_error( $source ) ) {
			return $source;
		}
		$stats = self::stats( $source['abs'] );
		if ( is_wp_error( $stats ) ) {
			return $stats;
		}
		$base = self::prepare_base( $ctx );
		if ( is_wp_error( $base ) ) {
			return $base;
		}
		$id   = self::new_id( (int) $ctx['now'], bin2hex( random_bytes( 4 ) ) );
		$dest = self::stored_path( $base['dir'], $id, $source['rel'] );
		if ( ! wp_mkdir_p( dirname( $dest ) ) ) {
			return new \WP_Error( 'mkdir_failed', __( 'Could not create the quarantine folder.', 'emcp-tools' ) );
		}
		$moved = EMCP_Tools_File_Mover::move( $source['abs'], $dest, ! empty( $ctx['force_copy'] ) );
		if ( is_wp_error( $moved ) ) {
			EMCP_Tools_File_Mover::prune_empty( dirname( $dest ), $base['dir'] );
			return $moved;
		}
		$neutral = self::neutralize( $dest );
		if ( is_wp_error( $neutral ) ) {
			EMCP_Tools_File_Mover::move( $dest, $source['abs'], ! empty( $ctx['force_copy'] ) );
			EMCP_Tools_File_Mover::prune_empty( dirname( $dest ), $base['dir'] );
			return $neutral;
		}
		$manifest = self::build_manifest(
			array_merge(
				$stats,
				array(
					'neutralized'   => true,
					'id'            => $id,
					'original_path' => $source['rel'],
					'reason'        => $reason,
					'user_id'       => $ctx['user_id'],
					'user_login'    => $ctx['user_login'],
					'time'          => $ctx['now'],
					'location'      => $base['location'],
					'method'        => $moved['method'],
				)
			)
		);
		if ( ! self::write_manifest( $base['dir'], $manifest ) ) {
			self::revive( $dest );
			EMCP_Tools_File_Mover::move( $dest, $source['abs'], ! empty( $ctx['force_copy'] ) );
			EMCP_Tools_File_Mover::prune_empty( dirname( $dest ), $base['dir'] );
			return new \WP_Error( 'manifest_failed', __( 'Could not write the quarantine manifest, so the file was put back.', 'emcp-tools' ) );
		}
		EMCP_Tools_File_Mover::invalidate_opcache( $stats['php'], $source['abs'] );
		return array(
			'manifest'  => $manifest,
			'base'      => $base['dir'],
			'stored_at' => self::on_disk( $dest, $manifest ),
			'warnings'  => EMCP_Tools_File_Mover::left_behind_warning( $moved['left_behind'], $ctx['root'] ),
		);
	}

	/**
	 * Confine the source to the root without following a symlink out of it,
	 * and apply the refusal rules to both the given and the canonical path.
	 *
	 * @param string $path Input.
	 * @param array  $ctx  Context.
	 * @return array|\WP_Error { rel, abs }
	 */
	private static function resolve_source( string $path, array $ctx ) {
		$root = $ctx['root'];
		$rel  = self::normalize_relative( $path, $root );
		if ( is_wp_error( $rel ) ) {
			return $rel;
		}
		$content_rel = self::relative( $ctx['content_dir'], $root );
		$plugin_rel  = '' === (string) $ctx['plugin_dir'] ? '' : self::relative( (string) realpath( $ctx['plugin_dir'] ), $root );
		$refused     = self::refusal( $rel, $content_rel, $plugin_rel );
		if ( $refused ) {
			return $refused;
		}
		$lexical = $root . '/' . $rel;
		if ( ! file_exists( $lexical ) && ! is_link( $lexical ) ) {
			return new \WP_Error( 'not_found', __( 'File or folder not found.', 'emcp-tools' ) );
		}
		$parent = realpath( dirname( $lexical ) );
		if ( false === $parent || ! self::is_within( self::slash( $parent ), $root ) ) {
			return new \WP_Error( 'outside_root', __( 'Path is outside the WordPress installation.', 'emcp-tools' ) );
		}
		if ( is_link( $lexical ) ) {
			$target = realpath( $lexical );
			if ( false === $target || ! self::is_within( self::slash( $target ), $root ) ) {
				return new \WP_Error( 'symlink_outside_root', __( 'This is a symlink that points outside the WordPress installation, so it cannot be quarantined.', 'emcp-tools' ) );
			}
		}
		$abs       = rtrim( self::slash( $parent ), '/' ) . '/' . basename( $lexical );
		$canonical = self::relative( $abs, $root );
		$refused   = self::refusal( $canonical, $content_rel, $plugin_rel );
		if ( $refused ) {
			return $refused;
		}
		foreach ( self::candidate_bases( $root, $ctx['content_dir'] ) as $base ) {
			if ( self::is_within( $abs, $base['dir'] ) ) {
				return new \WP_Error( 'protected_quarantine', __( 'The quarantine folder itself cannot be quarantined.', 'emcp-tools' ) );
			}
		}
		return array( 'rel' => $canonical, 'abs' => $abs );
	}

	/**
	 * Size, file count, hash and times of the item, without following links.
	 *
	 * @param string $abs Item.
	 * @return array|\WP_Error
	 */
	private static function stats( string $abs ) {
		$link = is_link( $abs );
		$stat = $link ? lstat( $abs ) : stat( $abs );
		$out  = array(
			'type'    => ( ! $link && is_dir( $abs ) ) ? 'dir' : 'file',
			'symlink' => $link,
			'size'    => 0,
			'files'   => 0,
			'sha256'  => null,
			'mtime'   => (int) ( $stat['mtime'] ?? 0 ),
			'ctime'   => (int) ( $stat['ctime'] ?? 0 ),
			'php'     => array(),
		);
		if ( 'file' === $out['type'] ) {
			$out['size']   = (int) ( $stat['size'] ?? 0 );
			$out['sha256'] = $link ? null : (string) hash_file( 'sha256', $abs );
			return $out;
		}
		$items = EMCP_Tools_File_Mover::walk( $abs, self::MAX_FILES * 2 );
		if ( count( $items ) >= self::MAX_FILES * 2 ) {
			return self::too_many_files();
		}
		foreach ( $items as $item ) {
			if ( 'file' !== $item['kind'] ) {
				continue;
			}
			++$out['files'];
			if ( $out['files'] > self::MAX_FILES ) {
				return self::too_many_files();
			}
			$out['size'] += (int) filesize( $item['path'] );
			if ( '.php' === strtolower( substr( $item['path'], -4 ) ) ) {
				$out['php'][] = $item['path'];
			}
		}
		return $out;
	}

	/**
	 * The error for a folder too large to move in one step.
	 */
	private static function too_many_files(): \WP_Error {
		return new \WP_Error( 'too_many_files', __( 'This folder holds too many files to quarantine in one step. Quarantine its subfolders instead.', 'emcp-tools' ) );
	}

	/**
	 * The error for a root that cannot be resolved.
	 */
	private static function bad_root(): \WP_Error {
		return new \WP_Error( 'bad_root', __( 'Filesystem root is unavailable.', 'emcp-tools' ) );
	}

	// ---- Restore -------------------------------------------------------

	/**
	 * Move a quarantined entry back to its original path.
	 *
	 * @param string $id        Entry id.
	 * @param bool   $overwrite Quarantine whatever sits at the original path first.
	 * @param array  $ctx       Context overrides (tests).
	 * @return array|\WP_Error
	 */
	public static function restore( string $id, bool $overwrite = false, array $ctx = array() ) {
		$ctx = self::context( $ctx );
		if ( '' === $ctx['root'] ) {
			return self::bad_root();
		}
		$found = self::locate( $id, $ctx );
		if ( is_wp_error( $found ) ) {
			return $found;
		}
		$manifest = $found['manifest'];
		$rel      = $manifest['original_path'];
		$refused  = self::refusal( $rel, self::relative( $ctx['content_dir'], $ctx['root'] ) );
		if ( $refused ) {
			return $refused;
		}
		$stored  = self::stored_path( $found['base'], $id, $rel );
		$on_disk = self::on_disk( $stored, $manifest );
		if ( ! file_exists( $on_disk ) && ! is_link( $on_disk ) ) {
			return new \WP_Error( 'missing_from_quarantine', __( 'The quarantined copy is missing, so there is nothing to restore.', 'emcp-tools' ) );
		}
		$parent = self::confined_parent( $ctx['root'], $rel );
		if ( is_wp_error( $parent ) ) {
			return $parent;
		}
		$target   = $parent . '/' . basename( $rel );
		$replaced = self::clear_target( $target, $id, $overwrite, $ctx );
		if ( is_wp_error( $replaced ) ) {
			return $replaced;
		}
		if ( ! empty( $manifest['neutralized'] ) ) {
			$revived = self::revive( $stored );
			if ( is_wp_error( $revived ) ) {
				if ( is_string( $replaced ) ) {
					self::restore( $replaced, false, $ctx ); // Put back what was there.
				}
				return $revived;
			}
		}
		$integrity = self::integrity( $manifest, $stored );
		$moved     = EMCP_Tools_File_Mover::move( $stored, $target, ! empty( $ctx['force_copy'] ) );
		if ( is_wp_error( $moved ) ) {
			if ( ! empty( $manifest['neutralized'] ) ) {
				self::neutralize( $stored );
			}
			if ( is_string( $replaced ) ) {
				self::restore( $replaced, false, $ctx ); // Put back what was there.
			}
			return $moved;
		}
		$manifest['status']      = self::STATUS_RESTORED;
		$manifest['restored_at'] = gmdate( 'c', (int) $ctx['now'] );
		self::write_manifest( $found['base'], $manifest );
		EMCP_Tools_File_Mover::prune_empty( dirname( $stored ), $found['base'] );
		EMCP_Tools_File_Mover::invalidate_opcache( array(), $target );
		return array(
			'id'          => $id,
			'path'        => $rel,
			'method'      => $moved['method'],
			'integrity'   => $integrity,
			'replaced_by' => $replaced,
			'change_id'   => (string) ( $manifest['change_id'] ?? '' ),
			'warnings'    => EMCP_Tools_File_Mover::left_behind_warning( $moved['left_behind'], $found['base'] ),
		);
	}

	/**
	 * Undo a quarantine recorded in the change ledger (rollback-change).
	 * `force` is treated as overwrite.
	 *
	 * @param array      $rb    Rollback ref { type, quarantine_id }.
	 * @param bool       $force The caller's force flag.
	 * @param array|null $ctx   Context overrides (tests).
	 * @return true|\WP_Error
	 */
	public static function rollback( array $rb, bool $force = false, ?array $ctx = null ) {
		if ( null === $ctx ) {
			$gate = EMCP_Tools_Filesystem_Guard::writes_allowed();
			if ( is_wp_error( $gate ) ) {
				return $gate;
			}
		}
		$result = self::restore( (string) ( $rb['quarantine_id'] ?? '' ), $force, $ctx ?? array() );
		return is_wp_error( $result ) ? $result : true;
	}

	/**
	 * Find an entry's manifest in either quarantine folder.
	 *
	 * @param string $id  Entry id.
	 * @param array  $ctx Context.
	 * @return array|\WP_Error { base, manifest }
	 */
	private static function locate( string $id, array $ctx ) {
		if ( ! self::is_valid_id( $id ) ) {
			return new \WP_Error( 'invalid_id', __( 'Invalid quarantine id. Use an id from list-quarantine.', 'emcp-tools' ) );
		}
		foreach ( self::candidate_bases( $ctx['root'], $ctx['content_dir'] ) as $base ) {
			$file = self::manifest_path( $base['dir'], $id );
			if ( ! is_file( $file ) ) {
				continue;
			}
			$manifest = self::parse_manifest( (string) file_get_contents( $file ) );
			if ( null === $manifest || $manifest['id'] !== $id ) {
				return new \WP_Error( 'bad_manifest', __( 'The quarantine manifest is damaged and cannot be used.', 'emcp-tools' ) );
			}
			if ( self::STATUS_HELD !== ( $manifest['status'] ?? '' ) ) {
				return new \WP_Error( 'already_restored', __( 'This entry has already been restored.', 'emcp-tools' ) );
			}
			return array( 'base' => $base['dir'], 'manifest' => $manifest );
		}
		return new \WP_Error( 'not_found', __( 'Quarantine entry not found.', 'emcp-tools' ) );
	}

	/**
	 * The original parent folder, created when missing, confined to the root
	 * (no symlinked ancestor may lead outside it).
	 *
	 * @param string $root Root.
	 * @param string $rel  Original relative path.
	 * @return string|\WP_Error
	 */
	private static function confined_parent( string $root, string $rel ) {
		$dir   = dirname( $root . '/' . $rel );
		$probe = $dir;
		while ( ! file_exists( $probe ) && strlen( $probe ) > strlen( $root ) ) {
			$probe = dirname( $probe );
		}
		$real = realpath( $probe );
		if ( false === $real || ! self::is_within( self::slash( $real ), $root ) ) {
			return new \WP_Error( 'outside_root', __( 'The original folder now leads outside the WordPress installation.', 'emcp-tools' ) );
		}
		if ( ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'mkdir_failed', __( 'Could not recreate the original folder.', 'emcp-tools' ) );
		}
		$real = realpath( $dir );
		if ( false === $real || ! self::is_within( self::slash( $real ), $root ) ) {
			return new \WP_Error( 'outside_root', __( 'The original folder now leads outside the WordPress installation.', 'emcp-tools' ) );
		}
		return rtrim( self::slash( $real ), '/' );
	}

	/**
	 * Make room at the original path: refuse, or quarantine what is there.
	 *
	 * @param string $target    Original path.
	 * @param string $id        Entry being restored.
	 * @param bool   $overwrite Caller's flag.
	 * @param array  $ctx       Context.
	 * @return string|null|\WP_Error Id of the entry that now holds the replaced item.
	 */
	private static function clear_target( string $target, string $id, bool $overwrite, array $ctx ) {
		$exists   = file_exists( $target ) || is_link( $target );
		$conflict = self::restore_conflict( $exists, $overwrite );
		if ( $conflict ) {
			return $conflict;
		}
		if ( ! $exists ) {
			return null;
		}
		/* translators: %s: quarantine entry id. */
		$why    = sprintf( __( 'Replaced while restoring quarantine entry %s.', 'emcp-tools' ), $id );
		$result = self::quarantine( self::relative( $target, $ctx['root'] ), $why, $ctx );
		return is_wp_error( $result ) ? $result : $result['manifest']['id'];
	}

	/**
	 * Whether a quarantined file still matches its manifest hash.
	 *
	 * @param array  $manifest Manifest.
	 * @param string $stored   Stored path.
	 * @return string ok | changed | not_checked
	 */
	private static function integrity( array $manifest, string $stored ): string {
		if ( empty( $manifest['sha256'] ) || ! is_file( $stored ) || is_link( $stored ) ) {
			return 'not_checked';
		}
		return hash_equals( (string) $manifest['sha256'], (string) hash_file( 'sha256', $stored ) ) ? 'ok' : 'changed';
	}

	// ---- List ----------------------------------------------------------

	/**
	 * Every manifest in both quarantine folders, newest first.
	 *
	 * @param string $status '' | quarantined | restored.
	 * @param array  $ctx    Context overrides (tests).
	 * @return array
	 */
	public static function entries( string $status = '', array $ctx = array() ): array {
		$ctx = self::context( $ctx );
		$out = array();
		if ( '' === $ctx['root'] ) {
			return $out;
		}
		foreach ( self::candidate_bases( $ctx['root'], $ctx['content_dir'] ) as $base ) {
			$files = is_dir( $base['dir'] ) ? glob( $base['dir'] . '/*.json' ) : array();
			foreach ( (array) $files as $file ) {
				$manifest = self::parse_manifest( (string) file_get_contents( $file ) );
				if ( null === $manifest || basename( $file, '.json' ) !== $manifest['id'] ) {
					continue;
				}
				if ( '' !== $status && $status !== ( $manifest['status'] ?? '' ) ) {
					continue;
				}
				$manifest['stored_in'] = $base['dir'];
				$out[]                 = $manifest;
			}
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return strcmp( $b['id'], $a['id'] );
			}
		);
		return array_slice( $out, 0, self::MAX_LIST );
	}

	/**
	 * Record the change ledger id in a manifest, so a restore can mark the
	 * ledger entry as undone.
	 *
	 * @param string $base      Quarantine folder.
	 * @param array  $manifest  Manifest.
	 * @param string $change_id Ledger id.
	 */
	public static function set_change_id( string $base, array $manifest, string $change_id ): void {
		$manifest['change_id'] = $change_id;
		self::write_manifest( $base, $manifest );
	}

	// ---- Disk helpers --------------------------------------------------

	/**
	 * Pick the quarantine folder and make sure it is protected.
	 *
	 * @param array $ctx Context.
	 * @return array|\WP_Error { dir, location }
	 */
	private static function prepare_base( array $ctx ) {
		$order = $ctx['outside_ok'] ? array( true, false ) : array( false );
		foreach ( $order as $outside ) {
			$base = self::choose_base( $ctx['root'], $ctx['content_dir'], $outside );
			if ( self::protect_dir( $base['dir'] ) ) {
				return $base;
			}
		}
		return new \WP_Error( 'quarantine_unavailable', __( 'Could not create a quarantine folder above WordPress or in wp-content.', 'emcp-tools' ) );
	}

	/**
	 * Create a folder with a deny-all .htaccess and an empty index.php. Written
	 * in both locations: the folder above WordPress can still be web-served when
	 * WordPress sits in a subfolder of the web root.
	 *
	 * @param string $dir Folder.
	 */
	private static function protect_dir( string $dir ): bool {
		if ( ! wp_mkdir_p( $dir ) || ! @is_writable( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		if ( ! is_file( $dir . '/.htaccess' ) && false === @file_put_contents( $dir . '/.htaccess', self::htaccess_rules() ) ) { // phpcs:ignore
			return false;
		}
		if ( ! is_file( $dir . '/index.php' ) && false === @file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" ) ) { // phpcs:ignore
			return false;
		}
		if ( ! is_file( $dir . '/web.config' ) && false === @file_put_contents( $dir . '/web.config', self::web_config_rules() ) ) { // phpcs:ignore
			return false;
		}
		return true;
	}

	/**
	 * Write a manifest as pretty JSON.
	 *
	 * @param string $base     Quarantine folder.
	 * @param array  $manifest Manifest.
	 */
	private static function write_manifest( string $base, array $manifest ): bool {
		$json = wp_json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		return is_string( $json ) && false !== file_put_contents( self::manifest_path( $base, $manifest['id'] ), $json . "\n", LOCK_EX );
	}
}
