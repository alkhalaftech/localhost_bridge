/// Configuration values for the bridge - the numbers and switches a host
/// tunes, each checked at construction time.
library;

import 'dart:io';

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
    this.listenIPv6Loopback = false,
    this.unixSocketPath,
    this.securityContext,
    this.tlsHandshakeTimeout = defaultTlsHandshakeTimeout,
    this.healthPath,
    this.maxJsonElements = 10_000,
    this.maxJsonDepth = 32,
    this.strictPayloadItems = false,
    this.requireValidJsonShape = false,
    this.rejectInvalidJson = false,
    this.requireJsonBodies = false,
    this.acceptHandlerRefusal = false,
    this.maxErrorMessageLength = 0,
    this.acceptBinaryBodies = false,
    this.allowStreamingReplies = false,
    this.wsPath,
    this.localPages,
    this.requestTimeout = const Duration(seconds: 30),
    this.bodyTimeout,
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
  /// sockets close between [idleTimeout] and twice that) the next request
  /// is served. The count is the sum
  /// over every bound listener plus the TLS feed's in-flight handshakes
  /// (sockets accepted on the TLS transport whose handshake has not yet
  /// been delivered - while this cap is on, the feed cuts a socket that
  /// would push the total over it at accept time, since a pre-arming cut
  /// is the one that reaches the wire). `0` (the default) keeps the
  /// option off - the wire never refuses for open sockets alone, and the
  /// TLS feed then holds its own internal ceiling over the in-flight
  /// handshakes alone: a delivered connection is never counted as an
  /// in-flight handshake and is never refused for open sockets. A
  /// negative value throws [ArgumentError] at server construction.
  final int maxOpenConnections;

  /// The optional `::1` (loopback IPv6) listener - when true, `start`
  /// binds a second listener on `InternetAddress.loopbackIPv6` at the same
  /// port (IPv6-only, never dual-stack: the IPv4 side keeps its own
  /// listener), and the local host authorities widen in the same start
  /// with the `[::1]:port` and bare `::1` spellings - a request naming
  /// them passes the Host gate only while the listener is actually bound,
  /// and a start on a host that cannot bind `::1` warns once and continues
  /// on `127.0.0.1` alone. `false` (the default) keeps the listener and
  /// the authority set exactly as before: nothing listens on `::1`, and a
  /// request whose Host names it reads `403 blocked_by_protection`.
  /// [LocalIntakeServer.pause] and `resume` rebind both listeners.
  final bool listenIPv6Loopback;

  /// The optional unix-domain-socket listener (Linux and macOS only) -
  /// when non-null, `start` also binds an HTTP listener on this filesystem
  /// path for local command-line clients: the socket file's owner-only
  /// permissions (mode 0600, enforced at bind by the system `/bin/chmod`
  /// at its full path and verified before the listener serves) are the
  /// transport boundary, and the socket's parent directory must already
  /// be owner-only (mode 0700) - the file is born with the process's
  /// permissions and tightens a moment later, so a permissive parent
  /// fails the whole start naming the directory and the socket is only
  /// ever created where no other user can traverse - there is no IP to
  /// rebind and no Origin to read, so the request crosses the same single
  /// admission step origin-less, by its token alone, behind the same Host
  /// authority gate (an HTTP/1.1 client sends `Host: localhost`). A path
  /// that is already occupied (any existing file, including a stale socket)
  /// fails the whole start with [IntakeBindException] - the package never
  /// deletes a path it did not create - and a successful stop removes the
  /// socket file the package itself created, so a restart on the same path
  /// rebinds cleanly. `null` (the default) keeps the option off. A value
  /// that is empty or carries a NUL byte throws [ArgumentError] at server
  /// construction, and so does any value at all on Windows - unix domain
  /// sockets are not part of dart:io there. Setting it together with
  /// [securityContext] also throws [ArgumentError] at construction: dart:io
  /// has no secure unix-domain bind, and a listener that silently stays
  /// plain under a TLS option would promise cover it does not deliver.
  final String? unixSocketPath;

  /// The optional TLS transport - when non-null, the bridge's TCP listeners
  /// (the `127.0.0.1` listener and the optional `::1` listener) bind a
  /// raw listening socket and feed it through the package's TLS
  /// handshake gate with this exact context, so the address the browser
  /// uses becomes `https://127.0.0.1:<port>` (and `wss://` for the
  /// WebSocket channel), and the served local pages' own origin arms as
  /// its `https://` spelling. The gate works on the first full TLS
  /// record: a first byte that is not a handshake record (a plain HTTP
  /// client on the TLS port) is cut at once with no bytes sent back, a
  /// first record declaring a length over the transport record maximum
  /// is cut at once, and the whole handshake from accept to delivery is
  /// bounded by [tlsHandshakeTimeout] - the silent client, the slow
  /// drip, and the client that completes its first record and then goes
  /// silent are all cut at the deadline, and the cut closes the raw
  /// socket the transport still holds, so it reaches the peer. The host
  /// supplies a ready [SecurityContext] - one
  /// that already carries a certificate chain and its private key: this
  /// package never generates a certificate, never installs or trusts one,
  /// and never reads or writes any file for it; device trust in the
  /// certificate (a locally installed issuing authority or a publicly
  /// trusted name) is entirely the host's responsibility, and installing a
  /// local issuing authority on a device is a decision to weigh against the
  /// risks documented in the README. `null` (the default) keeps the option
  /// off: every bind path stays letter identical to previous releases and
  /// the port speaks plain HTTP. Setting it together with
  /// [unixSocketPath] throws [ArgumentError] at server construction (dart:io
  /// has no secure unix-domain bind). The admission, the wire codes, and
  /// every reply contract are byte-for-byte the same over either transport
  /// - the one exception is the connection cap itself: with
  /// [maxOpenConnections] on, a new TLS connection over the cap is cut
  /// before arming with no reply, where the plain door answers `503`; TLS
  /// terminates below the HTTP layer. `stop` reaps every socket still
  /// completing its handshake - pre-arming and armed alike - and every
  /// reaped socket is a counted cut, so the in-flight count returns to
  /// zero at the stop's return. A context without a certificate
  /// chain fails at connection time with dart:io's own handshake error.
  final SecurityContext? securityContext;

  /// The whole-handshake deadline for the TLS transport - how long a
  /// socket accepted on the secure listener may take from its accept
  /// to its delivery ([securityContext]'s handshake window) before it
  /// is cut on the wire. This bounds the silent client (connects,
  /// sends nothing), the slow drip (sends the record header, then
  /// trickles bytes), and the armed silent client (completes its first
  /// record, then goes quiet) alike - the deadline is not restarted by
  /// arriving bytes or by arming, and the cut closes the raw socket the
  /// transport still holds, so it reaches the peer in every state. The
  /// default is five seconds, far above any measured loopback handshake
  /// and wide enough for real network RTT; values below one second or
  /// above sixty seconds throw [ArgumentError] at server construction.
  final Duration tlsHandshakeTimeout;

  /// The default whole-handshake budget - see [tlsHandshakeTimeout].
  static const Duration defaultTlsHandshakeTimeout = Duration(seconds: 5);

  /// The health page - when non-null, a `GET` on exactly this path is
  /// answered `200` with the literal body `{"ok":true}`: no version
  /// number, no counters, no details, so the page can never be used to
  /// fingerprint the host. It passes the standing gate like every
  /// other request - the origin and Host gates, the seat caps, and the
  /// single admission step with its settle - and only an origin the
  /// policy accepts reads the answer (the reply echoes its CORS); a
  /// non-accepted origin reads the standing refusal with no CORS echo,
  /// so a browser probe reveals nothing. The page answers on the bridge's
  /// own listener only (a forwarded GET on a mounted door answers `405`
  /// like any non-POST). `null` - the default - keeps the option off: the
  /// path answers `405 method_not_allowed` like every GET. The value must
  /// be a non-empty path starting with `/`, different from the command
  /// root `/`, the pairing route `/pair`, the WebSocket path, and every
  /// registered local-page path - a violation throws [ArgumentError] at
  /// server construction.
  final String? healthPath;

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

  /// Streaming replies - when true, a command whose request carries the
  /// `X-Bridge-Stream: events` header answers `text/event-stream` instead
  /// of a single JSON body: every handler progress report travels as one
  /// `event: progress` frame the page reads from the streamed body, and the
  /// handler's final outcome travels as the last `event: result` frame
  /// carrying the standing reply contract (`{"ok": ...}` with the same
  /// error codes and the same reply-data cap). The header joins the CORS
  /// allowed-header list only while the option is on, so the disarmed wire
  /// is letter identical to previous releases. `false` (the default) keeps
  /// the header unknown: a page sending it anyway reads the ordinary JSON
  /// reply. The per-event data cap is the same internal page cap the
  /// result answers to - a progress report over it ends the stream with
  /// `progress_data_too_large` and fires the command's cancel signal, so
  /// a flooding handler wraps up instead of writing into a closed reply.
  final bool allowStreamingReplies;

  /// The WebSocket channel's path - when non-null, a `GET` upgrade
  /// handshake on exactly this path is answered with a WebSocket upgrade
  /// (after the same single admission step every request passes: origin,
  /// fetch metadata, host authority, and the seat caps answer their
  /// standing wire codes BEFORE the upgrade). The connection opens only
  /// after its first message carries a verified credential - the shared
  /// token or a paired origin-bound signature - within the auth deadline;
  /// every inbound message is a command passing the same payload checks,
  /// and every reply is an event the host shaped. `null` (the default)
  /// keeps the channel off: the path answers like any non-POST path
  /// (`405 method_not_allowed`), and the wire never upgrades. The value
  /// must be non-empty, start with `/`, and differ from the pairing route
  /// `/pair` - a violation throws [ArgumentError] at server construction.
  /// The channel also refuses to arm on a dart:io older than 3.13 (the
  /// first release whose `WebSocketTransformer.upgrade` carries the
  /// `maxPayloadLength` transport ceiling): arming the channel without a
  /// frame memory limit never happens, so an older SDK throws
  /// [ArgumentError] at server construction and every non-channel path
  /// works unchanged.
  /// Before its credential, a connection waits in a small internal pool
  /// that holds no command seat: a total cap of 8 channels, and a
  /// per-origin cap of min([maxSeatsPerOrigin], 8) keyed by the
  /// normalized origin. A handshake over either pool cap is refused
  /// before the upgrade with the standing codes (`503 server_busy` for
  /// the total cap, `503 origin_seat_limit` for the origin cap), so a
  /// flood of credential-less channels - origin rotation included - can
  /// never starve the command seats: the worst case is channels refused
  /// temporarily while commands stay served. At credential acceptance
  /// the connection takes one concurrency seat and its origin share -
  /// the same seat budget the HTTP commands hold - and holds both for
  /// the channel's lifetime, so the seat caps bound the authenticated
  /// connections per origin exactly like they bound the live commands.
  /// A channel whose seat or share is gone by its acceptance closes
  /// with the same standing code inside the rejection frame, and its
  /// pool slot is freed. [LocalIntakeServer.stop] closes pooled channels
  /// with the live ones and waits for the pool to empty.
  final String? wsPath;

  /// The local pages - when non-null, a `GET` on exactly one of the
  /// registered paths is answered with the page the host passed (from
  /// memory: the path, the content, the content type), carrying the
  /// page's security headers (a strict CSP, `X-Frame-Options: DENY`,
  /// `Referrer-Policy: no-referrer`, and `X-Content-Type-Options:
  /// nosniff`) and no CORS echo. Every other `GET` keeps its standing
  /// `405 method_not_allowed`. `null` - the default - keeps the option
  /// off: the wire is letter identical, and nothing is ever read from
  /// the filesystem (the pages live in the host's memory; serving a
  /// folder from disk is not part of this package). A non-null value
  /// must list at least one page with unique, well-formed paths that
  /// stay off the pairing route and the WebSocket path - a violation
  /// throws [ArgumentError] at server construction. The page's own
  /// origin (the bound loopback origin in its `127.0.0.1` and
  /// `localhost` spellings) crosses the admission on its own explicit
  /// path - never through allow-all - and the pages answer on the
  /// bridge's own listener only (a forwarded `GET` on a mounted door
  /// answers `405` like any non-POST).
  final List<BridgeLocalPage>? localPages;

  /// Per-request timeout (anchored at request arrival, not server start) -
  /// the deadline over the whole pre-handler phase: the gates, the policy
  /// checks, and the body read. The body read alone is cut earlier, at
  /// [bodyTimeout].
  final Duration requestTimeout;

  /// The deadline over reading one request body - the phase a seat is
  /// held while the sender is still transmitting. A body that has not
  /// completed within it is refused `408 request_timeout` and its seat is
  /// freed, so a sender that drips a body one byte at a time cannot hold
  /// a seat for the whole [requestTimeout]. `null` - the default -
  /// selects the shorter of [defaultBodyTimeout] and [requestTimeout]: a
  /// host that lowered [requestTimeout] below ten seconds without
  /// touching this option keeps its build and its behaviour, the body
  /// limit following it down. An explicit value must be positive and no
  /// longer than [requestTimeout]; otherwise building a
  /// [LocalIntakeServer] throws [ArgumentError]. Raise it together with
  /// [maxBodyBytes] for a device whose legitimate uploads need longer
  /// than ten seconds.
  final Duration? bodyTimeout;

  /// The default body-phase deadline - see [bodyTimeout].
  static const Duration defaultBodyTimeout = Duration(seconds: 10);

  /// Idle timeout of the HTTP listeners. A connection that carries no
  /// request closes between this value and twice that: the idle timer of
  /// `dart:io` runs once per period, marking a connection on one pass and
  /// destroying it on the next. An occupied seat outlives it by the
  /// close-handling grace. The WebSocket channel keeps its own idle timer
  /// and its own code (`ws_idle_timeout`).
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

/// One in-memory page the host serves through the local-pages option
/// ([BridgeConfig.localPages]) - the headless host's display surface: a
/// settings status, a pointer to the portal, any non-secret state the
/// user reads. The content lives in the host's memory: nothing here
/// names a file, and the bridge never reads the filesystem, so there is
/// no path to traverse and no folder to serve - the reply is a verbatim
/// write of [content]. A plain `GET` with no browser headers reads the
/// page, so no pairing code, no token, and no secret belong in it: the
/// pairing code is shown through the host's own channel where only the
/// human at the device reads it.
class BridgeLocalPage {
  /// Builds the page. [path] must be a non-empty path starting with `/`,
  /// unique across the list, and different from the pairing route `/pair`
  /// and the WebSocket path - a violation throws [ArgumentError] at
  /// server construction. [content] is served verbatim on `GET` [path].
  /// [contentType] is the `Content-Type` header the reply carries - it
  /// defaults to an HTML document in UTF-8.
  const BridgeLocalPage({
    required this.path,
    required this.content,
    this.contentType = 'text/html; charset=utf-8',
  });

  /// The exact request path the page answers - matched against
  /// `request.uri.path`, so a query string on the request is not part of
  /// the match.
  final String path;

  /// The page body, served verbatim from the host's memory.
  final String content;

  /// The `Content-Type` header the reply carries, exactly as given.
  final String contentType;
}
