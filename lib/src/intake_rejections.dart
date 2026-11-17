/// The one rejection-code registry - the single table behind every
/// rejection the server can put on the wire, read by the server itself and
/// by the registry test that walks it and matches it against the README
/// wire table. A code the server produces but the table lacks fails the
/// walk loudly; a new rejection is added here first, then to the README.
///
/// The registry covers rejection codes only - the replies shaped
/// `{"ok": false, "error": <code>, ...}` the server refuses a request
/// with. Handler-outcome codes (`internal`, the handler's own codes, the
/// `command_failed` fallback) are the handler contract, pinned by their
/// own guards, and stay outside this table.
library;

/// One registry row: the wire status of one rejection code and whether
/// that rejection, when it fires over an unread body, cuts immediately
/// instead of spending the bounded drain window. Only the two documented
/// paths cut immediately: the concurrency-seat busy reject and the
/// host-authority (DNS-rebinding) reject - every unread-body rejection
/// drains bounded instead, and every read-body rejection closes managed,
/// so the close method itself follows the body fact, never the code.
class IntakeRejectSpec {
  /// Builds the row - [status] is the wire status, [immediateCut] marks the
  /// documented immediate-cut paths above.
  const IntakeRejectSpec(this.status, {this.immediateCut = false});

  /// The HTTP status this code answers with - the registry is the single
  /// source the server replies from and the test pins the wire against.
  final int status;

  /// Whether this code, firing over an unread body, destroys the connection
  /// at once (the accepted reply-loss paths: `server_busy` at the seat gate
  /// and `blocked_by_protection`). False keeps the bounded drain - the
  /// reply is still flushed first either way.
  final bool immediateCut;
}

/// The registry itself - every rejection code the intake answers with, its
/// status, and its unread-body close flavor. Sorted by status then code for
/// review; the lookup is by code and reads identically either way.
const Map<String, IntakeRejectSpec> intakeRejectionRegistry =
    <String, IntakeRejectSpec>{
      // 400 - wire shapes and body facts
      'bad_request': IntakeRejectSpec(400),
      'duplicate_header': IntakeRejectSpec(400),
      'empty_payload': IntakeRejectSpec(400),
      'invalid_utf8': IntakeRejectSpec(400),
      'origin_malformed': IntakeRejectSpec(400),
      'origin_too_long': IntakeRejectSpec(400),
      'token_too_long': IntakeRejectSpec(400),
      'unsupported_payload_shape': IntakeRejectSpec(400),
      // 403 - policy and authority denials
      'blocked_by_protection': IntakeRejectSpec(403, immediateCut: true),
      'cross_site_blocked': IntakeRejectSpec(403),
      'origin_blocked': IntakeRejectSpec(403),
      'origin_declined': IntakeRejectSpec(403),
      'origin_not_listed': IntakeRejectSpec(403),
      'origin_pending': IntakeRejectSpec(403),
      'origin_unknown': IntakeRejectSpec(403),
      // 405 / 408
      'method_not_allowed': IntakeRejectSpec(405),
      'request_timeout': IntakeRejectSpec(408),
      // 413 / 415
      'payload_too_complex': IntakeRejectSpec(413),
      'payload_too_large': IntakeRejectSpec(413),
      'unsupported_media_type': IntakeRejectSpec(415),
      // 429
      'origin_rate_limited': IntakeRejectSpec(429),
      'token_locked': IntakeRejectSpec(429),
      // 503 / 504
      'handler_timeout': IntakeRejectSpec(504),
      'protection_disposed': IntakeRejectSpec(503),
      'server_busy': IntakeRejectSpec(503, immediateCut: true),
    };
