/// Literal, injectable defaults - every number is named and valued to match
/// the behavior it governs; any deviation from them documents its reason.
/// Values are checked when a LocalIntakeServer is built: a non-positive
/// cap or timeout throws ArgumentError instead of silently rejecting
/// everything.
class BridgeConfig {
  const BridgeConfig({
    this.maxBodyBytes = 1024 * 1024,
    this.maxConcurrentRequests = 16,
    this.maxJsonElements = 10_000,
    this.maxJsonDepth = 32,
    this.requestTimeout = const Duration(seconds: 30),
    this.idleTimeout = const Duration(seconds: 60),
    this.extraHosts = const <String>[],
    this.allowedContentTypes = defaultContentTypes,
    this.payloadWrapperKeys = defaultPayloadWrapperKeys,
    this.fallbackErrorCode = 'command_failed',
  });

  /// Media types a POST body may carry (the part before ';', lowercased).
  /// The default admits exactly what the ecosystem sends - `application/json`
  /// and the textual gateway's `text/plain` - plus an absent header (raw
  /// socket integrations), and refuses hidden-HTML-form types
  /// (`application/x-www-form-urlencoded`, `multipart/form-data`) with
  /// `415 unsupported_media_type`. Tighten to `{'application/json'}` to also
  /// force every browser request through a CORS preflight.
  static const Set<String> defaultContentTypes = {
    'application/json',
    'text/plain',
  };

  /// Request body cap in bytes - protects intake only; the decompressed
  /// body cap after inflating compressed payloads is the host's responsibility.
  final int maxBodyBytes;

  /// Concurrent seat cap - a synchronous check + 503 before the first await
  /// (a hard cap; time-based relief is the host's separate knob).
  final int maxConcurrentRequests;

  /// JSON structural element cap - `{`, `[`, and `,` outside strings, counted
  /// in one linear pass before any decoding. A body over it is rejected with
  /// `413 payload_too_complex`: a tiny body of empty elements must not
  /// amplify into many parsed objects after jsonDecode.
  final int maxJsonElements;

  /// JSON nesting depth cap, counted in the same pre-decode pass. A deeply
  /// nested body can sit under the element cap and still stress the decoder;
  /// 32 is far beyond any real command shape, and over it the same
  /// `413 payload_too_complex` lands before jsonDecode runs.
  final int maxJsonDepth;

  /// Per-request timeout (anchored at request arrival, not server start).
  final Duration requestTimeout;

  /// Idle timeout - an occupied seat outlives it by the close-handling grace.
  final Duration idleTimeout;

  /// Extra hosts accepted as local authorities - a bare name also matches
  /// `name:boundPort` (browsers always send the port). A public DNS name
  /// here is the host's explicit opt-out of the DNS-rebinding guard for
  /// that one name; list only names you control that resolve to this
  /// machine.
  final List<String> extraHosts;

  /// Media types a POST body may carry - see [defaultContentTypes].
  final Set<String> allowedContentTypes;

  /// Wrapper keys a JSON body may carry the command strings under - a body
  /// shaped `{"<key>": ["..."]}` (or a single string value) unwraps to its
  /// elements. The default set is domain-neutral; a host whose gateways use
  /// a domain-specific key adds it here rather than the package hard-coding
  /// every domain's vocabulary.
  final Set<String> payloadWrapperKeys;

  /// The neutral default for [payloadWrapperKeys].
  static const Set<String> defaultPayloadWrapperKeys = {
    'data',
    'payload',
    'commands',
  };

  /// Error code reported when a handler fails without setting one. The
  /// default is domain-neutral; a host with an existing wire contract sets
  /// its own code here and keeps its contract byte-for-byte.
  final String fallbackErrorCode;
}
