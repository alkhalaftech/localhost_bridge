/// Literal, injectable defaults - every number is named and valued to match
/// the behavior it governs; any deviation from them documents its reason.
/// Values are checked when a LocalIntakeServer is built: a non-positive
/// cap or timeout throws ArgumentError instead of silently rejecting
/// everything.
class BridgeConfig {
  /// Builds the configuration - every parameter is optional and defaults to
  /// the values documented above. A LocalIntakeServer re-checks the
  /// positive limits at its own construction and throws [ArgumentError]
  /// for a non-positive cap or timeout.
  const BridgeConfig({
    this.maxBodyBytes = 1024 * 1024,
    this.maxConcurrentRequests = 16,
    this.maxSeatsPerOrigin = defaultMaxSeatsPerOrigin,
    this.maxOpenConnections = 0,
    this.maxJsonElements = 10_000,
    this.maxJsonDepth = 32,
    this.requestTimeout = const Duration(seconds: 30),
    this.idleTimeout = const Duration(seconds: 60),
    this.handlerTimeout = defaultHandlerTimeout,
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

  /// The default share of the seats one sender may hold at once - see
  /// [maxSeatsPerOrigin].
  static const int defaultMaxSeatsPerOrigin = 4;

  /// Per-origin seat cap - the share of [maxConcurrentRequests] a single
  /// origin may hold at the same moment (default [defaultMaxSeatsPerOrigin]).
  /// Without it one listed page - or one allow-all page - can occupy every
  /// seat with slow requests and answer every other sender `503`; with it
  /// the monopolizer is refused `503 origin_seat_limit` past its share
  /// while the server still has room for others. Requests without an
  /// `Origin` header (the token layer's clients) share one originless
  /// bucket under the same cap, and an `OPTIONS` preflight counts into
  /// its origin's share exactly like a command. The gate sits inside the
  /// global seats: the full server still answers `server_busy` first, a
  /// value at or above [maxConcurrentRequests] never binds (the global
  /// gate binds first), and one origin filling its share never deducts
  /// from another origin's - each sender is bounded by its own bucket,
  /// and the pairing layer's session and record caps are protection-state
  /// limits, not seats: a paired page's signed requests count into its
  /// origin's seat share like any other request.
  final int maxSeatsPerOrigin;

  /// Open-connection cap - dart:io never bounds the sockets a listening
  /// server has accepted (idle keep-alive sockets included), so a host
  /// that wants a hard ceiling on open connections sets this above zero:
  /// a request arriving while more sockets than the cap are open answers
  /// `503 server_busy`, and once the count drops (senders finish, idle
  /// sockets time out) the next request is served. `0` (the default)
  /// keeps the option off - the wire never refuses for open sockets
  /// alone. A negative value throws [ArgumentError] at server
  /// construction.
  final int maxOpenConnections;


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

  /// The default handler budget - the deadline over the host's command
  /// handler itself, applied when [LocalIntakeServer.handlerTimeout] is
  /// left at null. A handler running past it is answered `504
  /// handler_timeout`, its seat is freed, and the still-running work
  /// becomes a counted orphan, so a stuck handler can never hold a seat
  /// forever nor stall [LocalIntakeServer.stop] without a bound. To ask
  /// for no handler deadline at all, pass
  /// [LocalIntakeServer.noHandlerTimeout] - null no longer means
  /// unbounded. Must be positive; a non-positive value throws
  /// [ArgumentError] at server construction.
  static const Duration defaultHandlerTimeout = Duration(seconds: 30);

  /// The default budget field itself.
  final Duration handlerTimeout;

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
