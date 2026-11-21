/// The pipeline's end contract: the package ends at delivering a "trusted
/// command" - it knows neither its meaning nor any specific hardware (neutrality).
library;

import 'dart:typed_data' show Uint8List;

import 'intake_protection.dart';

/// The cooperative cancellation signal a handler may read: the intake
/// fires it when the command leaves its seat (the handler budget expired
/// and the `504 handler_timeout` is on its way) and when the server stops,
/// so long work can wrap up early instead of finishing into a reply
/// nobody will read. Reading it is the handler's choice - the signal
/// never interrupts anything on its own, and no client-disconnect
/// detection is wired (dart:io exposes no clean way without watching the
/// socket): the two fires above are the whole contract.
abstract class CommandCancelSignal {
  /// Whether the intake has asked this command to wrap up.
  bool get isCancelled;

  /// Builds a fresh, not-cancelled signal - the intake builds one per
  /// command; a host composing its own pipeline may build its own.
  factory CommandCancelSignal() = _LiveCancelSignal;

  /// The const, shared, never-cancelled instance carried by commands
  /// built outside the intake: no lifecycle ever fires it.
  const factory CommandCancelSignal.never() = _NeverCancelSignal;

  /// Fires the signal. The intake calls it at the budget expiry and when
  /// the server stops; a handler may fire its own copy to mark its work
  /// abandoned - firing changes nothing but the flag.
  void cancel();
}

/// The live per-command signal the intake hands out.
class _LiveCancelSignal implements CommandCancelSignal {
  bool _cancelled = false;

  @override
  bool get isCancelled => _cancelled;

  @override
  void cancel() {
    _cancelled = true;
  }
}

/// The const default: false forever, by construction.
class _NeverCancelSignal implements CommandCancelSignal {
  const _NeverCancelSignal();

  @override
  bool get isCancelled => false;

  @override
  void cancel() {}
}

/// The pipeline's end contract: the package ends at delivering a "trusted
/// command" - it knows neither its meaning nor any specific hardware (neutrality).
class TrustedCommand {
  /// Builds the command - the package constructs it, the host consumes it;
  /// [source], [payloads], [headers], and [correlationId] are required.
  /// [admission] defaults to [IntakeAdmission.unrecorded] so hosts and
  /// tests building a command by hand keep compiling; the server always
  /// passes the record its admission step produced.
  const TrustedCommand({
    required this.source,
    required this.payloads,
    required this.headers,
    required this.correlationId,
    this.admission = IntakeAdmission.unrecorded,
    this.cancellation = const CommandCancelSignal.never(),
    this.binaryPayload,
  });

  /// The sender's origin as protection read it ('unknown-origin' when absent).
  final String source;

  /// Payloads as extracted (kept as a list - no join before the guards).
  ///
  /// Extraction contract: inside a JSON array, non-string and
  /// empty-string elements drop without notice (the `strictPayloadItems`
  /// option refuses them instead); a body that fails JSON decoding, or a
  /// JSON number, boolean, or `null` body, arrives as raw command text
  /// (the `rejectInvalidJson` and `requireJsonBodies` options refuse
  /// those paths instead). Empty (never carries the file) when the
  /// request arrived as a binary body - see [binaryPayload].
  final List<String> payloads;

  /// Useful request headers (lowercase keys) plus the correlation id.
  /// With the binary-body option on, the sender's `X-Command` value rides
  /// here under the `x-command` key (empty string when absent).
  final Map<String, String> headers;

  /// The thread tying logs together (honored when incoming, or host-generated).
  final String correlationId;

  /// The admission record the server's single admission step produced for
  /// the request that carried this command - the accepted route, the CORS
  /// echo decision, and the verbose-error decision in one place. A command
  /// built outside the intake carries [IntakeAdmission.unrecorded].
  final IntakeAdmission admission;

  /// The cooperative cancellation signal for this command: the intake
  /// passes a live per-command signal and fires it at the handler-budget
  /// expiry and at stop; a command built outside the intake carries the
  /// const never-cancelled instance. Reading it is the handler's choice.
  final CommandCancelSignal cancellation;

  /// The raw bytes of a binary body, delivered only when the
  /// binary-body option is on and the request arrived as
  /// `application/octet-stream`; null for every JSON or raw-text
  /// request. A binary body is never JSON-parsed and never UTF-8-decoded:
  /// [payloads] stays empty and the command name rides
  /// [headers]`['x-command']`. The bytes sit under the server's internal
  /// binary ceiling - a body over it is refused before the handler runs.
  final Uint8List? binaryPayload;
}

/// The host-side command execution result.
class CommandOutcome {
  /// Builds the outcome: [ok] true with no error fields for an executed
  /// command, false with [errorCode] (and optionally [errorMessage]) for
  /// a refusal or a failure. [data] carries optional reply data for the
  /// page and is read on success only. [refusalStatus] marks a failed
  /// outcome as the sender's doing - inert unless the server's
  /// refusal option is on (see the field's contract).
  const CommandOutcome({
    required this.ok,
    this.errorCode,
    this.errorMessage,
    this.data,
    this.refusalStatus,
  });

  /// Whether the host executed the command: true answers the sender with
  /// `200` and `{"ok": true}`; false answers `500` with the error fields.
  final bool ok;

  /// The host's wire error code for a failed command - sent as the `error`
  /// field of the JSON reply; null falls back to the configured fallback
  /// error code (`command_failed` by default).
  final String? errorCode;

  /// Optional host text for a failed command - delivered only to senders
  /// the protection marks verbose (a correct token or a listed origin);
  /// the allow-all path sees the code without this text.
  final String? errorMessage;

  /// Optional JSON-encodable data the page reads back on success - sent
  /// as the `data` field of the `{"ok": true}` reply. Read on success
  /// only: a failed command's reply carries the error contract and never
  /// data, whatever this field holds. The encoded size is bounded by the
  /// package's internal reply-data cap (64 KiB of UTF-8 after
  /// `jsonEncode`): data over the cap refuses the whole result with
  /// `413 reply_data_too_large` - no truncation, and the command stays
  /// executed (the refusal is about the reply, not the work). A value
  /// `jsonEncode` cannot serialize fails the reply into the
  /// internal-error path with the real cause on the host's telemetry -
  /// keep [data] plain JSON types (null, bool, num, String, List, Map).
  final Object? data;

  /// The handler's refusal mark for a failed outcome - the claim that the
  /// failure is the sender's doing, so the wire may answer a client
  /// error. Accepted only while the server is built with the refusal
  /// option on: a value inside 400..499 then rides the wire as the reply
  /// status (with the [errorCode] and the usual error shape unchanged);
  /// null keeps the standing `500`, a value outside 400..499 is ignored
  /// with one throttled warning, and with the option off the whole field
  /// is inert - every failed outcome answers `500` exactly as before.
  /// Read on failure only; a successful outcome never carries an error
  /// status.
  final int? refusalStatus;
}

/// The host's single registration point (it knows nothing of ports).
///
/// The payloads it receives are unvalidated wire data: a body that fails
/// JSON decoding arrives as raw command text, a JSON number, boolean, or
/// `null` body likewise arrives as raw text, and inside a JSON array the
/// non-string and empty-string elements drop without notice. Validating
/// the payload language stays the host's job.
typedef TrustedCommandHandler =
    Future<CommandOutcome> Function(TrustedCommand command);
