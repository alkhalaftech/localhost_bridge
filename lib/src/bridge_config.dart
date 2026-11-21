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
    this.strictPayloadItems = false,
    this.requireValidJsonShape = false,
    this.rejectInvalidJson = false,
    this.requireJsonBodies = false,
    this.acceptHandlerRefusal = false,
    this.maxErrorMessageLength = 0,
    this.acceptBinaryBodies = false,
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

  /// Strict list elements - when true, a JSON command list (top-level or
  /// under a [payloadWrapperKeys] wrapper) carrying a non-string or
  /// empty-string element refuses the whole request `400
  /// invalid_payload_item` instead of the default silent drop of the
  /// offending element. `false` (the default) keeps the silent-drop wire:
  /// the strings of the list are delivered, the rest vanish without
  /// notice.
  final bool strictPayloadItems;

  /// Pre-decode shape scan - when true, a body whose leading shape claims a
  /// JSON container (it starts with `{` or `[`) must scan structurally
  /// complete (every opener closed, every string terminated) or the request
  /// answers `400 malformed_json_shape` before jsonDecode runs. `false`
  /// (the default) keeps the raw fallthrough: a cut-off container decodes
  /// badly and travels onward as raw command text. The scan is scoped to
  /// container-shaped bodies only - a quote-leading raw text command is
  /// never scanned, so textual gateways are untouched by this option.
  final bool requireValidJsonShape;

  /// Declared-type JSON strictness - when true, a body sent with the
  /// `application/json` media type (the part before `;`) that fails JSON
  /// decoding refuses `400 invalid_json` instead of the default raw-text
  /// fallthrough. `false` (the default) keeps the tested non-JSON
  /// contract: a broken body under any content type travels as raw
  /// command text.
  final bool rejectInvalidJson;

  /// JSON-only mode - when true, the raw-text fallback path refuses
  /// `400 non_json_body` whole: a body that fails JSON decoding under any
  /// content type, and a JSON number, boolean, or `null` body (they arrive
  /// as raw command text by the standing contract), are refused instead of
  /// delivered. `false` (the default) keeps textual gateways working: raw
  /// command text stays a valid delivery. A JSON string body (`"SIZE
  /// 4mm"`) is still JSON and keeps its decoded delivery under the mode.
  /// With [rejectInvalidJson] also true, a broken `application/json` body
  /// reads `invalid_json` - the declared-type code is the specific one and
  /// wins.
  final bool requireJsonBodies;

  /// Handler-marked refusals - when true, a failed [CommandOutcome]
  /// carrying a [CommandOutcome.refusalStatus] inside 400..499 answers the
  /// sender with that status instead of the standing `500`: the handler
  /// knows the failure is the sender's doing (a malformed label, an
  /// unknown device command) and says so on the wire. `false` (the
  /// default) keeps the failure contract: every failed outcome answers
  /// `500` with its error code, whatever the marker holds. A marker
  /// outside 400..499 is ignored with one throttled warning - the default
  /// stays `500` either way.
  final bool acceptHandlerRefusal;

  /// Host-message cap in UTF-8 bytes - the standing failure reply echoes
  /// [CommandOutcome.errorMessage] verbatim; a value above zero bounds
  /// that text on the wire byte-wise: a longer message is truncated to
  /// at most this many UTF-8 bytes, cut at a whole-character boundary -
  /// a multi-byte character is never split, it is dropped whole (a cap
  /// smaller than the first character truncates to an empty message).
  /// The code and the `ok` shape are never touched. `0` (the default)
  /// keeps the option off - messages travel whole. A negative value
  /// throws [ArgumentError] at server construction.
  final int maxErrorMessageLength;

  /// Binary bodies - when true, `application/octet-stream` joins the
  /// admitted media types and the raw bytes of such a body are delivered
  /// to the handler as [TrustedCommand.binaryPayload] (payloads stay
  /// empty - a binary body is never JSON-parsed), with the command name
  /// riding the `X-Command` request header into
  /// [TrustedCommand.headers] and joining the CORS allowed-header list
  /// while the option is on. The bytes sit under the package's internal
  /// binary ceiling - a fixed named constant, deliberately not an option;
  /// a body over it refuses `413 payload_too_large`. `false` (the
  /// default) keeps the media gate: `octet-stream` refuses `415
  /// unsupported_media_type` and the allowed-header list never offers
  /// `X-Command`.
  final bool acceptBinaryBodies;

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
