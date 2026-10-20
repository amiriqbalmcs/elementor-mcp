<?php
/**
 * Verified file moves for the file quarantine: rename() first, and when that
 * fails (another filesystem) copy, check every copy by size and sha256, and
 * only then delete the original. Never follows symlinks.
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
class EMCP_Tools_File_Mover {

	/**
	 * Forward slashes only.
	 *
	 * @param string $path Any path.
	 */
	private static function slash( string $path ): string {
		return str_replace( '\\', '/', $path );
	}

	/**
	 * Move with rename(); when that fails (another filesystem), copy, verify
	 * every copy by size and sha256, and only then delete the original.
	 *
	 * @param string $src        Source.
	 * @param string $dest       Destination (must not exist).
	 * @param bool   $force_copy Skip rename (tests).
	 * @return array|\WP_Error { method, left_behind }
	 */
	public static function move( string $src, string $dest, bool $force_copy = false ) {
		if ( ! $force_copy && @rename( $src, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return array( 'method' => 'rename', 'left_behind' => array() );
		}
		if ( is_link( $src ) ) {
			return new \WP_Error( 'move_failed', __( 'Could not move the symlink.', 'emcp-tools' ) );
		}
		if ( ! is_dir( $src ) ) {
			$copied = self::copy_verified( $src, $dest );
			if ( is_wp_error( $copied ) ) {
				return $copied;
			}
			if ( ! @unlink( $src ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				@unlink( $dest ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return new \WP_Error( 'move_failed', __( 'Could not remove the original after copying it, so nothing was changed.', 'emcp-tools' ) );
			}
			return array( 'method' => 'copy', 'left_behind' => array() );
		}
		$copied = self::copy_tree( $src, $dest );
		if ( is_wp_error( $copied ) ) {
			return $copied;
		}
		return array( 'method' => 'copy', 'left_behind' => self::remove_tree( $src ) );
	}

	/**
	 * Copy one file and prove the copy matches.
	 *
	 * @param string $src  Source.
	 * @param string $dest Destination.
	 * @return true|\WP_Error
	 */
	private static function copy_verified( string $src, string $dest ) {
		if ( ! @copy( $src, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new \WP_Error( 'copy_failed', __( 'Could not copy the file.', 'emcp-tools' ) );
		}
		clearstatcache( true, $dest );
		if ( filesize( $src ) !== filesize( $dest ) || ! hash_equals( (string) hash_file( 'sha256', $src ), (string) hash_file( 'sha256', $dest ) ) ) {
			@unlink( $dest ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new \WP_Error( 'copy_unverified', __( 'The copy did not match the original, so nothing was changed.', 'emcp-tools' ) );
		}
		return true;
	}

	/**
	 * Copy a folder tree file by file. Symlinks inside stop the copy, because
	 * copying would follow them.
	 *
	 * @param string $src  Source folder.
	 * @param string $dest Destination folder.
	 * @return true|\WP_Error
	 */
	private static function copy_tree( string $src, string $dest ) {
		$src = rtrim( self::slash( $src ), '/' );
		if ( ! wp_mkdir_p( $dest ) ) {
			return new \WP_Error( 'copy_failed', __( 'Could not create the destination folder.', 'emcp-tools' ) );
		}
		foreach ( self::walk( $src ) as $item ) {
			$to = $dest . substr( $item['path'], strlen( $src ) );
			if ( 'link' === $item['kind'] ) {
				$error = new \WP_Error( 'copy_symlink', __( 'The folder holds a symlink and has to be moved across filesystems, which would follow it. Quarantine the symlink on its own first.', 'emcp-tools' ) );
			} elseif ( 'dir' === $item['kind'] ) {
				$error = wp_mkdir_p( $to ) ? null : new \WP_Error( 'copy_failed', __( 'Could not create a destination folder.', 'emcp-tools' ) );
			} else {
				$error = self::copy_verified( $item['path'], $to );
				$error = is_wp_error( $error ) ? $error : null;
			}
			if ( $error ) {
				self::remove_tree( $dest );
				return $error;
			}
		}
		return true;
	}

	/**
	 * Delete a folder tree without following links.
	 *
	 * @param string $dir Folder.
	 * @return string[] Paths that could not be removed.
	 */
	private static function remove_tree( string $dir ): array {
		$failed = array();
		foreach ( array_reverse( self::walk( $dir ) ) as $item ) {
			$ok = 'dir' === $item['kind'] ? @rmdir( $item['path'] ) : ( @unlink( $item['path'] ) || @rmdir( $item['path'] ) ); // phpcs:ignore
			if ( ! $ok ) {
				$failed[] = $item['path'];
			}
		}
		if ( ! @rmdir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$failed[] = self::slash( $dir );
		}
		return $failed;
	}

	/**
	 * Every item under a folder, parents before children, links never followed.
	 *
	 * @param string $dir Folder.
	 * @return array<int, array{path: string, kind: string}> kind: dir | file | link.
	 */
	public static function walk( string $dir, int $limit = 0 ): array {
		$items    = array();
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::SELF_FIRST
		);
		foreach ( $iterator as $info ) {
			$kind    = $info->isLink() ? 'link' : ( $info->isDir() ? 'dir' : 'file' );
			$items[] = array( 'path' => self::slash( $info->getPathname() ), 'kind' => $kind );
			if ( $limit > 0 && count( $items ) >= $limit ) {
				break;
			}
		}
		return $items;
	}

	/**
	 * Remove empty folders from $dir up to and including the entry folder.
	 *
	 * @param string $dir  Deepest folder.
	 * @param string $base Quarantine folder (never removed).
	 */
	public static function prune_empty( string $dir, string $base ): void {
		$dir  = rtrim( self::slash( $dir ), '/' );
		$base = rtrim( self::slash( $base ), '/' );
		while ( ( 0 === strpos( $dir, $base . '/' ) ) && $dir !== $base && @rmdir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$dir = self::slash( dirname( $dir ) );
		}
	}

	/**
	 * A warning for originals a cross-filesystem move could not delete.
	 *
	 * @param string[] $paths Paths left behind.
	 * @param string   $root  Root used to shorten them.
	 * @return string[]
	 */
	public static function left_behind_warning( array $paths, string $root ): array {
		if ( empty( $paths ) ) {
			return array();
		}
		$short = array_map(
			static function ( $p ) use ( $root ) {
				return EMCP_Tools_File_Quarantine::relative( $p, $root );
			},
			array_slice( $paths, 0, 20 )
		);
		/* translators: %s: list of paths. */
		return array( sprintf( __( 'Every file was copied and verified, but some originals could not be deleted: %s', 'emcp-tools' ), implode( ', ', $short ) ) );
	}

	/**
	 * Drop OPcache entries for moved PHP files.
	 *
	 * @param string[] $php  PHP files inside a moved folder.
	 * @param string   $path The moved path itself.
	 */
	public static function invalidate_opcache( array $php, string $path ): void {
		if ( ! function_exists( 'opcache_invalidate' ) ) {
			return;
		}
		$php[] = $path;
		foreach ( $php as $file ) {
			if ( '.php' === strtolower( substr( $file, -4 ) ) ) {
				opcache_invalidate( $file, true );
			}
		}
	}
}
