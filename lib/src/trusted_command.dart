/// The pipeline's end contract: the package ends at delivering a "trusted
/// command" - it knows neither its meaning nor any specific hardware (neutrality).
library;

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

  /// Fires the signal. The intake calls it at the budget expiry and at
  /// [stop]; a handler may fire its own copy to mark its work abandoned -
  /// firing changes nothing but the flag.
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
  });

  /// The sender's origin as protection read it ('unknown-origin' when absent).
  final String source;

  /// Payloads as extracted (kept as a list - no join before the guards).
  ///
  /// Extraction contract: inside a JSON array, non-string and
  /// empty-string elements drop without notice; a body that fails JSON
  /// decoding, or a JSON number, boolean, or `null` body, arrives as raw
  /// command text.
  final List<String> payloads;

  /// Useful request headers (lowercase keys) plus the correlation id.
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
}

/// The host-side command execution result.
class CommandOutcome {
  /// Builds the outcome: [ok] true with no error fields for an executed
  /// command, false with [errorCode] (and optionally [errorMessage]) for
  /// a refusal or a failure.
  const CommandOutcome({required this.ok, this.errorCode, this.errorMessage});

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
