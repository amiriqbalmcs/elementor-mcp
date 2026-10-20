<?php
/**
 * Keeps EMCP's Elementor writes in step with an open Elementor editor.
 *
 * Elementor 4.3 ships its own MCP server and, with it, two seams in
 * Elementor\Modules\Mcp\Utils\Editor_Sync_State:
 *
 * - the `elementor/mcp/pre_execute_guard` filter, which refuses a write while
 *   another user has the document open in the editor with unsaved changes, so
 *   their next save cannot silently overwrite the MCP edit (or the MCP edit
 *   theirs);
 * - a per-post "changed by MCP" marker that the editor's heartbeat reads, so an
 *   open editor learns the document changed underneath it.
 *
 * EMCP's Elementor tools write through EMCP_Tools_Data, so both seams are
 * applied there. On an Elementor without them every method is a no-op.
 *
 * Elementor's guard skips the current user (wp_check_post_lock() ignores it), so
 * one administrator running both the MCP connection and the editor was never
 * protected, and the editor's Force Save then discarded the MCP write (#168). EMCP
 * therefore also reads Elementor's own signals itself: the unsaved-changes
 * transient its heartbeat keeps (value: the editing user's id) and a fresh edit
 * lock, for any user. `ignore_open_editor: true` on an Elementor write tool skips
 * the check for that one call, for an editor that was closed without saving.
 *
 * @package EMCP_Tools
 * @since   3.18.0
 */

defined( 'ABSPATH' ) || exit;

/**
 * Elementor editor sync bridge.
 */
class EMCP_Tools_Elementor_Editor_Sync {

	const GUARD_FILTER = 'elementor/mcp/pre_execute_guard';
	const STATE_CLASS  = '\Elementor\Modules\Mcp\Utils\Editor_Sync_State';

	/** Tool argument that skips the open-editor check for one call. */
	const OVERRIDE_ARG = 'ignore_open_editor';

	/** Elementor's heartbeat transient: the user with unsaved changes in the editor. */
	const UNSAVED_TRANSIENT = '_elementor_editor_unsaved_';

	/** @var int Nesting depth of with_override(). */
	private static $override = 0;

	/**
	 * Runs a callback with the open-editor check switched off.
	 *
	 * @param callable $callback Work to run.
	 * @return mixed The callback's result.
	 */
	public static function with_override( callable $callback ) {
		++self::$override;
		try {
			return $callback();
		} finally {
			--self::$override;
		}
	}

	/**
	 * The user who has the document open in the editor with unsaved changes, or 0.
	 *
	 * Needs both of Elementor's heartbeat signals: the unsaved-changes transient and
	 * an edit lock younger than WordPress's lock window, so an editor closed without
	 * saving stops counting once its lock goes stale.
	 *
	 * @param int $post_id Document.
	 */
	public static function open_editor_user( int $post_id ): int {
		if ( $post_id <= 0 || ! function_exists( 'get_transient' ) || ! function_exists( 'get_post_meta' ) ) {
			return 0;
		}
		if ( (int) get_transient( self::UNSAVED_TRANSIENT . $post_id ) <= 0 ) {
			return 0;
		}
		$lock = explode( ':', (string) get_post_meta( $post_id, '_edit_lock', true ) );
		$time = (int) ( $lock[0] ?? 0 );
		$user = (int) ( $lock[1] ?? 0 );
		/** This filter is documented in wp-admin/includes/post.php */
		$window = function_exists( 'apply_filters' ) ? (int) apply_filters( 'wp_check_post_lock_window', 150 ) : 150;
		if ( $time <= 0 || $user <= 0 || $time <= time() - $window ) {
			return 0;
		}
		return $user;
	}

	/**
	 * Refuses a write Elementor's own MCP tools would refuse.
	 *
	 * @param int $post_id Document being written.
	 * @return WP_Error|null Error to return to the caller, or null to proceed.
	 */
	public static function guard( int $post_id ): ?WP_Error {
		if ( $post_id <= 0 || self::$override > 0 ) {
			return null;
		}
		$refused = false;
		if ( function_exists( 'has_filter' ) && has_filter( self::GUARD_FILTER ) ) {
			try {
				$refused = is_wp_error( apply_filters( self::GUARD_FILTER, null, array( 'post_id' => $post_id ) ) );
			} catch ( \Throwable $e ) {
				$refused = false; // A broken third-party guard must not block every save.
			}
		}
		$user = self::open_editor_user( $post_id );
		if ( ! $refused && 0 === $user ) {
			return null;
		}
		if ( $user > 0 && function_exists( 'get_current_user_id' ) && get_current_user_id() === $user ) {
			/* translators: %d: post ID */
			$why = __( 'Page #%d is open in the Elementor editor with unsaved changes under your own account, in another tab or device. A save there would discard this write, because Force Save keeps the editor copy, so nothing was written. Save or discard the changes in the editor, then retry.', 'emcp-tools' );
		} else {
			/* translators: %d: post ID */
			$why = __( 'Page #%d is open in the Elementor editor with unsaved changes by another user. Ask them to save or discard their changes, then retry. Nothing was written.', 'emcp-tools' );
		}
		return new WP_Error(
			'elementor_editor_unsaved_changes',
			sprintf( $why, $post_id ) . ' ' . __( 'If the editor was closed without saving, retry with ignore_open_editor: true.', 'emcp-tools' ),
			array(
				'status'  => 409,
				'post_id' => $post_id,
			)
		);
	}

	/**
	 * Tells an open Elementor editor that the document changed.
	 *
	 * Call after the write: Elementor clears the marker on `elementor/document/after_save`,
	 * which EMCP's own native save fires.
	 *
	 * @param int $post_id Document that was written.
	 */
	public static function mark_changed( int $post_id ): void {
		$class = self::STATE_CLASS;
		if ( $post_id <= 0 || ! class_exists( $class ) || ! method_exists( $class, 'set_mcp_mutation' ) ) {
			return;
		}
		try {
			$class::set_mcp_mutation( $post_id );
		} catch ( \Throwable $e ) {
			return; // Internal Elementor API: never let it break a completed save.
		}
	}
}
