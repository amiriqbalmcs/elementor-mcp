<?php
/**
 * Pure helpers behind the search-access-log tool: log file name whitelist,
 * common/combined log format parser, input normalisation, line matching and
 * query-string stripping. No filesystem access, no WordPress state, so every
 * method is unit-testable on its own.
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
class EMCP_Tools_Access_Log_Parser {

	/** Longest line (in bytes) returned to the caller; the rest is cut. */
	const MAX_LINE_BYTES = 1000;

	/** Default and ceiling for the number of returned matches. */
	const DEFAULT_LIMIT = 100;
	const MAX_LIMIT     = 500;

	/** Time budget in seconds (same defaults as the security scanner). */
	const DEFAULT_SECONDS = 20;
	const MAX_SECONDS     = 120;

	/** Byte budget (uncompressed bytes read) in megabytes. */
	const DEFAULT_MB = 256;
	const MAX_MB     = 2048;

	/** Longest accepted text filter. */
	const MAX_FILTER_CHARS = 500;

	/** Marker that replaces a removed query string. */
	const QUERY_MARK = '?[query removed]';

	/**
	 * Common/combined log format: host ident user [time] "request" status bytes
	 * followed by anything (referer, user agent, a host field on IONOS).
	 */
	const LINE_PATTERN = '/^(\S+) (\S+) (\S+) \[([^\]]+)\] "((?:[^"\\\\]|\\\\.)*)" (\d{3}|-) (\d+|-)(.*)$/s';

	/**
	 * Whether a bare file name looks like a web server access log.
	 *
	 * Accepts access.log, access.log.1, access.log.2.gz, ssl_access.log,
	 * example.com-access.log, access_log. Refuses anything that is not a plain
	 * name, script extensions and compressed formats other than gzip.
	 *
	 * @param string $name File name without a directory.
	 * @return bool
	 */
	public static function is_log_name( string $name ): bool {
		if ( '' === $name || strlen( $name ) > 200 ) {
			return false;
		}
		if ( ! preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]*$/', $name ) ) {
			return false;
		}
		if ( preg_match( '/\.(php\d?|phtml|phar|bz2|xz|zst|zip|7z|tar|lz4|br)$/i', $name ) ) {
			return false;
		}
		return 1 === preg_match( '/access[A-Za-z0-9_.-]*?[._]log(?:[._-][A-Za-z0-9._-]*)?$/i', $name );
	}

	/**
	 * Whether a log file name is gzip-compressed.
	 *
	 * @param string $name File name.
	 * @return bool
	 */
	public static function is_gzip_name( string $name ): bool {
		return 1 === preg_match( '/\.gz$/i', $name );
	}

	/**
	 * Parses one common/combined format line into fields.
	 *
	 * Handles the IONOS variant, where a bare host name sits between the byte
	 * count and the quoted referer: `200 328027 example.com "-" "UA" "-"`.
	 *
	 * @param string $line Raw line (trailing newline allowed).
	 * @return array|null Fields, or null when the line does not parse.
	 */
	public static function parse_line( string $line ): ?array {
		$line = rtrim( $line, "\r\n" );
		if ( ! preg_match( self::LINE_PATTERN, $line, $m ) ) {
			return null;
		}

		$request  = $m[5];
		$method   = null;
		$path     = null;
		$protocol = null;
		if ( preg_match( '/^([A-Za-z]{1,16}) (\S+)(?: (\S+))?$/', $request, $r ) ) {
			$method   = strtoupper( $r[1] );
			$path     = $r[2];
			$protocol = isset( $r[3] ) ? $r[3] : null;
		}

		$rest = self::split_rest( $m[8] );

		return array(
			'ip'         => $m[1],
			'user'       => '-' === $m[3] ? null : $m[3],
			'time'       => $m[4],
			'timestamp'  => self::parse_time( $m[4] ),
			'method'     => $method,
			'path'       => $path,
			'protocol'   => $protocol,
			'request'    => $request,
			'status'     => '-' === $m[6] ? null : (int) $m[6],
			'bytes'      => '-' === $m[7] ? null : (int) $m[7],
			'host'       => $rest['host'],
			'referer'    => $rest['referer'],
			'user_agent' => $rest['user_agent'],
		);
	}

	/**
	 * Splits the tail after the byte count into an optional bare host field
	 * and the quoted referer and user agent.
	 *
	 * @param string $rest Tail of the line.
	 * @return array{host: ?string, referer: ?string, user_agent: ?string}
	 */
	private static function split_rest( string $rest ): array {
		$bare   = array();
		$quoted = array();
		$rest   = ltrim( $rest );
		$guard  = 0;
		while ( '' !== $rest && $guard < 20 ) {
			++$guard;
			if ( '"' === $rest[0] && preg_match( '/^"((?:[^"\\\\]|\\\\.)*)"\s*/', $rest, $q ) ) {
				$quoted[] = $q[1];
				$rest     = (string) substr( $rest, strlen( $q[0] ) );
				continue;
			}
			if ( ! preg_match( '/^(\S+)\s*/', $rest, $b ) ) {
				break;
			}
			if ( empty( $quoted ) ) {
				$bare[] = $b[1];
			}
			$rest = (string) substr( $rest, strlen( $b[0] ) );
		}

		$dash = static function ( $value ) {
			return ( null === $value || '-' === $value || '' === $value ) ? null : $value;
		};

		return array(
			'host'       => $dash( $bare[0] ?? null ),
			'referer'    => $dash( $quoted[0] ?? null ),
			'user_agent' => $dash( $quoted[1] ?? null ),
		);
	}

	/**
	 * Parses a log timestamp like `17/Oct/2026:10:22:01 +0200`.
	 *
	 * @param string $value Timestamp text from between the brackets.
	 * @return int|null Unix time, or null when it does not parse.
	 */
	public static function parse_time( string $value ): ?int {
		$dt = \DateTime::createFromFormat( 'd/M/Y:H:i:s O', trim( $value ) );
		if ( false === $dt ) {
			return null;
		}
		return $dt->getTimestamp();
	}

	/**
	 * Parses a since/until bound: unix seconds, ISO 8601, or the log format.
	 *
	 * @param mixed $value Raw input.
	 * @return int|null Unix time, or null when it does not parse.
	 */
	public static function parse_bound( $value ): ?int {
		if ( is_int( $value ) ) {
			return $value;
		}
		if ( ! is_string( $value ) ) {
			return null;
		}
		$value = trim( $value );
		if ( '' === $value ) {
			return null;
		}
		if ( preg_match( '/^\d{9,11}$/', $value ) ) {
			return (int) $value;
		}
		$log = self::parse_time( $value );
		if ( null !== $log ) {
			return $log;
		}
		$ts = strtotime( $value );
		return false === $ts ? null : $ts;
	}

	/**
	 * Validates and normalises the tool input.
	 *
	 * @param array $input Raw tool input.
	 * @return array|\WP_Error Normalised filters and options.
	 */
	public static function normalize_input( array $input ) {
		$list_files = ! empty( $input['list_files'] );

		$text = array();
		foreach ( array( 'contains', 'ip', 'path_contains' ) as $key ) {
			$value = isset( $input[ $key ] ) && is_scalar( $input[ $key ] ) ? trim( (string) $input[ $key ] ) : '';
			if ( strlen( $value ) > self::MAX_FILTER_CHARS ) {
				/* translators: %s: input field name. */
				return new \WP_Error( 'emcp_access_log_bad_input', sprintf( __( '%s is too long.', 'emcp-tools' ), $key ) );
			}
			$text[ $key ] = $value;
		}
		if ( ! $list_files && '' === $text['contains'] ) {
			return new \WP_Error( 'emcp_access_log_bad_input', __( 'contains is required (or pass list_files: true to see the detected logs).', 'emcp-tools' ) );
		}

		$method = '';
		if ( isset( $input['method'] ) && '' !== (string) $input['method'] ) {
			$method = strtoupper( trim( (string) $input['method'] ) );
			if ( ! preg_match( '/^[A-Z]{1,16}$/', $method ) ) {
				return new \WP_Error( 'emcp_access_log_bad_input', __( 'method must be an HTTP method such as GET or POST.', 'emcp-tools' ) );
			}
		}

		$status = null;
		if ( isset( $input['status'] ) && '' !== (string) $input['status'] ) {
			$status = strtolower( trim( (string) $input['status'] ) );
			if ( ! preg_match( '/^[1-5](\d\d|xx)$/', $status ) ) {
				return new \WP_Error( 'emcp_access_log_bad_input', __( 'status must be a code such as 200 or a class such as 4xx.', 'emcp-tools' ) );
			}
		}

		$bounds = array();
		foreach ( array( 'since', 'until' ) as $key ) {
			$bounds[ $key ] = null;
			if ( isset( $input[ $key ] ) && '' !== $input[ $key ] && null !== $input[ $key ] ) {
				$bounds[ $key ] = self::parse_bound( $input[ $key ] );
				if ( null === $bounds[ $key ] ) {
					/* translators: %s: input field name. */
					return new \WP_Error( 'emcp_access_log_bad_input', sprintf( __( '%s is not a date or time this tool understands. Use ISO 8601, unix seconds or the log format.', 'emcp-tools' ), $key ) );
				}
			}
		}

		$files = array();
		if ( isset( $input['files'] ) ) {
			if ( ! is_array( $input['files'] ) ) {
				return new \WP_Error( 'emcp_access_log_bad_input', __( 'files must be a list of detected log names.', 'emcp-tools' ) );
			}
			foreach ( $input['files'] as $name ) {
				if ( ! is_string( $name ) || '' === trim( $name ) ) {
					return new \WP_Error( 'emcp_access_log_bad_input', __( 'files must be a list of detected log names.', 'emcp-tools' ) );
				}
				$files[] = trim( $name );
			}
		}

		return array(
			'list_files'    => $list_files,
			'contains'      => $text['contains'],
			'ip'            => $text['ip'],
			'path_contains' => $text['path_contains'],
			'method'        => $method,
			'status'        => $status,
			'since'         => $bounds['since'],
			'until'         => $bounds['until'],
			'files'         => array_values( array_unique( $files ) ),
			'include_query' => ! empty( $input['include_query'] ),
			'limit'         => self::clamp( $input['limit'] ?? null, self::DEFAULT_LIMIT, 1, self::MAX_LIMIT ),
			'max_seconds'   => self::clamp( $input['max_seconds'] ?? null, self::DEFAULT_SECONDS, 1, self::MAX_SECONDS ),
			'max_mb'        => self::clamp( $input['max_mb'] ?? null, self::DEFAULT_MB, 1, self::MAX_MB ),
		);
	}

	/**
	 * @param mixed $value   Raw value.
	 * @param int   $default Used when the value is missing or not numeric.
	 * @param int   $min     Floor.
	 * @param int   $max     Ceiling.
	 * @return int
	 */
	private static function clamp( $value, int $default, int $min, int $max ): int {
		if ( null === $value || '' === $value || ! is_numeric( $value ) ) {
			return $default;
		}
		return max( $min, min( $max, (int) $value ) );
	}

	/**
	 * Whether a line passes every filter. Field filters use the parsed fields;
	 * for a line that does not parse they fall back to plain text matching on
	 * the raw line, except since/until, which need a real timestamp.
	 *
	 * @param string     $raw     Raw line.
	 * @param array|null $fields  Parsed fields, or null.
	 * @param array      $filters Output of normalize_input().
	 * @return bool
	 */
	public static function matches( string $raw, ?array $fields, array $filters ): bool {
		if ( '' !== $filters['contains'] && false === stripos( $raw, $filters['contains'] ) ) {
			return false;
		}
		if ( '' !== $filters['ip'] ) {
			$ok = null !== $fields ? ( $fields['ip'] === $filters['ip'] ) : ( false !== strpos( $raw, $filters['ip'] ) );
			if ( ! $ok ) {
				return false;
			}
		}
		if ( '' !== $filters['method'] ) {
			$ok = ( null !== $fields && null !== $fields['method'] )
				? ( $fields['method'] === $filters['method'] )
				: ( false !== stripos( $raw, '"' . $filters['method'] . ' ' ) );
			if ( ! $ok ) {
				return false;
			}
		}
		if ( null !== $filters['status'] && ! self::status_matches( $raw, $fields, $filters['status'] ) ) {
			return false;
		}
		if ( '' !== $filters['path_contains'] ) {
			$haystack = ( null !== $fields && null !== $fields['path'] ) ? $fields['path'] : $raw;
			if ( false === stripos( $haystack, $filters['path_contains'] ) ) {
				return false;
			}
		}
		if ( null !== $filters['since'] || null !== $filters['until'] ) {
			$ts = null !== $fields ? $fields['timestamp'] : null;
			if ( null === $ts ) {
				return false;
			}
			if ( null !== $filters['since'] && $ts < $filters['since'] ) {
				return false;
			}
			if ( null !== $filters['until'] && $ts > $filters['until'] ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @param string     $raw    Raw line.
	 * @param array|null $fields Parsed fields, or null.
	 * @param string     $want   Exact code ("404") or class ("4xx").
	 * @return bool
	 */
	private static function status_matches( string $raw, ?array $fields, string $want ): bool {
		$is_class = 'xx' === substr( $want, 1 );
		if ( null !== $fields ) {
			if ( null === $fields['status'] ) {
				return false;
			}
			$code = (string) $fields['status'];
			return $is_class ? ( $code[0] === $want[0] ) : ( $code === $want );
		}
		$pattern = $is_class ? '/\s' . $want[0] . '\d\d\s/' : '/\s' . $want . '\s/';
		return 1 === preg_match( $pattern, $raw );
	}

	/**
	 * Removes query strings from URLs in a piece of log text. A query string
	 * can hold tokens, nonces and passwords, so lines are cleaned before they
	 * are returned unless the caller opts in.
	 *
	 * @param string $text Line or field.
	 * @return string
	 */
	public static function strip_query( string $text ): string {
		return (string) preg_replace( '/(?<=[^\s"])\?[^\s"]*/', self::QUERY_MARK, $text );
	}

	/**
	 * Makes a string safe to return: valid UTF-8 and at most $max bytes.
	 *
	 * @param string $text Raw text.
	 * @param int    $max  Byte cap.
	 * @return array{text: string, truncated: bool}
	 */
	public static function cap( string $text, int $max = self::MAX_LINE_BYTES ): array {
		$truncated = strlen( $text ) > $max;
		if ( $truncated ) {
			$text = substr( $text, 0, $max );
		}
		return array(
			'text'      => self::to_utf8( $text ),
			'truncated' => $truncated,
		);
	}

	/**
	 * Replaces invalid UTF-8 so the result always encodes as JSON.
	 *
	 * @param string $text Raw bytes.
	 * @return string
	 */
	public static function to_utf8( string $text ): string {
		if ( 1 === preg_match( '//u', $text ) ) {
			return $text;
		}
		if ( function_exists( 'mb_scrub' ) ) {
			return mb_scrub( $text, 'UTF-8' );
		}
		return (string) preg_replace( '/[\x80-\xFF]/', '?', $text );
	}

	/**
	 * Runs one raw line through parse, match and output cleanup.
	 *
	 * @param string $raw     Raw line (trailing newline allowed).
	 * @param array  $filters Output of normalize_input().
	 * @return array|null Result row without file and line number, or null when it does not match.
	 */
	public static function evaluate_line( string $raw, array $filters ): ?array {
		$raw    = rtrim( $raw, "\r\n" );
		$fields = self::parse_line( $raw );
		if ( ! self::matches( $raw, $fields, $filters ) ) {
			return null;
		}

		$line = $filters['include_query'] ? $raw : self::strip_query( $raw );
		$cap  = self::cap( $line );

		if ( null !== $fields ) {
			foreach ( array( 'path', 'request', 'referer', 'user_agent', 'host', 'user' ) as $key ) {
				if ( null === $fields[ $key ] ) {
					continue;
				}
				$value          = ( ! $filters['include_query'] && in_array( $key, array( 'path', 'request', 'referer' ), true ) )
					? self::strip_query( $fields[ $key ] )
					: $fields[ $key ];
				$fields[ $key ] = self::cap( $value, 500 )['text'];
			}
			$fields['ip']   = self::cap( $fields['ip'], 100 )['text'];
			$fields['time'] = self::cap( $fields['time'], 100 )['text'];
		}

		return array(
			'line'           => $cap['text'],
			'line_truncated' => $cap['truncated'],
			'fields'         => $fields,
		);
	}
}
