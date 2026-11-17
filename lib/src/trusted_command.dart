/// The pipeline's end contract: the package ends at delivering a "trusted
/// command" - it knows neither its meaning nor any specific hardware (neutrality).
library;

import 'intake_protection.dart';

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
