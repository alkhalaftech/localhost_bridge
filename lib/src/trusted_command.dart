/// The pipeline's end contract: the package ends at delivering a "trusted
/// command" - it knows neither its meaning nor any specific hardware (neutrality).
class TrustedCommand {
  const TrustedCommand({
    required this.source,
    required this.payloads,
    required this.headers,
    required this.correlationId,
  });

  /// The sender's origin as protection read it ('unknown-portal' when absent).
  final String source;

  /// Payloads as extracted (kept as a list - no join before the guards).
  final List<String> payloads;

  /// Useful request headers (lowercase keys) plus the correlation id.
  final Map<String, String> headers;

  /// The thread tying logs together (honored when incoming, or host-generated).
  final String correlationId;
}

/// The host-side command execution result (fields unchanged).
class CommandOutcome {
  const CommandOutcome({required this.ok, this.errorCode, this.errorMessage});

  final bool ok;
  final String? errorCode;
  final String? errorMessage;
}

/// The host's single registration point (it knows nothing of ports).
typedef TrustedCommandHandler =
    Future<CommandOutcome> Function(TrustedCommand command);
