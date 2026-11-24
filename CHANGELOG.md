## 0.2.0

- **Breaking: one sender can no longer monopolize the seats** -
  `BridgeConfig.maxSeatsPerOrigin` (default 4 of the 16) bounds the
  seats a single origin holds at once; requests without an `Origin`
  header share one originless bucket under the same cap, and an
  `OPTIONS` preflight counts into its origin's share exactly like a
  command. Past the share the sender reads `503 origin_seat_limit`
  while the server still has room for others - one listed page or one
  allow-all page holding every seat with slow requests used to answer
  every other sender `503`. The gate lives inside the global seats
  (the full server still answers `server_busy` first, a value at or
  above `maxConcurrentRequests` never binds, and one origin filling
  its share never deducts from another origin's).
- **Breaking: listed origins ship with a rate budget** -
  `OriginPolicy.listedPerOriginPerMinute` defaults to 120/minute
  instead of unquotaed, so a compromised listed origin cannot flood
  the shared seats faster than two sustained commands a second; over
  it the page reads `429 origin_rate_limited` with the honest
  `Retry-After`. `0` remains the explicit documented opt-out keeping
  listed origins unquotaed. See MIGRATION-0.2.0.md for both default
  changes.
- Security: a WebSocket channel waiting for its credential no longer
  holds a command seat. Credential-less channels wait in a small
  internal pool - 8 channels in total, `maxSeatsPerOrigin` (default 4)
  per origin - and a handshake over either pool cap is refused before
  the upgrade with the standing `503 server_busy` / `503
  origin_seat_limit` codes, so a flood of channels that never
  authenticates (origin rotation included) can no longer occupy the
  command seats and answer every POST `503`: the worst case is channels
  refused temporarily while commands stay served. At credential
  acceptance the channel takes its seat and its origin share at the
  same moment and keeps them for its lifetime; a channel whose seat or
  share is gone by its acceptance closes with the same standing code in
  the rejection frame. `stop` closes pooled channels with the live ones
  and waits for the pool to empty.
- Added: `BridgeConfig.maxOpenConnections` - an optional hard ceiling
  on open connections (`dart:io` never bounds them): a request arriving
  while more sockets than the cap are open answers `503`, and once the
  count drops the next request is served. `0` - the default - keeps it
  off, and the wire never refuses for open sockets alone.
- Added: `CommandOutcome.data` - optional JSON-encodable data the page
  reads back on success, sent as the `data` field of the success reply.
  Data over the internal page cap (64 KiB after JSON encoding) refuses
  the whole result with `413 reply_data_too_large` - never truncated,
  and the command stays executed; a failed reply carries the error
  contract and never data. Without `data` the success reply is
  byte-identical to previous releases.
- Added: the correlation-id dedup helper as package surface -
  `DedupLedger` and `idempotentCommand` (moved out of
  `example/idempotent_handler.dart`, which is now a wiring demo on top
  of them). The ledger registers a command under its correlation id
  before the work runs, stores the settled reply, and replays it for
  every repeat - a retry after `504 handler_timeout` returns the first
  result and never executes the command twice. The memory is bounded by
  size (`maxEntries` - a full ledger answers `ledger_full` and never
  evicts a live entry) and by time (`ttl`, swept on the next look). A
  non-positive `ttl` or `maxEntries` throws `ArgumentError` at
  construction - release builds included - and the default clock is
  monotonic, so a wall-clock jump never ends an entry before its ttl.
- Added: an optional `::1` listener - `BridgeConfig.listenIPv6Loopback`
  (default off) binds a second loopback-IPv6 listener (`::1`, IPv6-only)
  at the same port, and the local host authorities widen in the same
  start with the `[::1]:port` and bare `::1` spellings; a host that
  cannot bind `::1` warns once and stays on `127.0.0.1` alone. Off, the
  authority set keeps exactly its IPv4 loopback forms.
- Added: an optional unix-socket listener - `BridgeConfig.unixSocketPath`
  (default off; Linux and macOS) also serves HTTP on the named
  filesystem path for local CLI clients. The socket file's owner-only
  permissions (mode 0600, enforced by the system `/bin/chmod` at its
  full path and verified by reading the actual file mode before
  anything is served) are the transport boundary, and the socket's
  parent directory must already be owner-only (mode 0700) - a
  permissive parent fails the whole start naming the directory (judged
  once, before any port is tried), so the socket is only ever created
  where no other user can traverse; a chmod or verification failure
  fails the start - the failure message names `/bin/chmod` at its
  fixed path - so no unguarded socket ever serves. The request rides
  the same single admission step with no
  Origin (token alone; a headerless CLI needs
  `OriginPolicy.requireFetchMetadata: false`, the standing switch)
  behind the same Host gate. An occupied path fails the start with
  `IntakeBindException` (the package never deletes a path it did not
  create); the socket file the package created is removed at `stop` -
  and when its bind fails the guard - so a restart on the same path
  rebinds cleanly. The open-connection cap
  counts this listener too.
- Added: an optional TLS transport - `BridgeConfig.securityContext`
  (default off) binds the bridge's TCP listeners as plain sockets fed
  through the package's TLS handshake gate with a ready
  `SecurityContext` the host
  passes, so the page URL becomes `https://127.0.0.1:<port>` (and
  `wss://` for the WebSocket channel) and a served local page's own
  origin arms as its `https://` spelling. The package never generates,
  installs, or trusts a certificate and never reads or writes any file
  for TLS - the host supplies the context and owns the device trust in
  the certificate. Off by default the wire stays letter identical plain
  HTTP; setting `securityContext` together with `unixSocketPath` throws
  `ArgumentError` at construction.
- Added: the mobile lifecycle pair - `pause()` closes every bound
  listener under the same graceful drain `stop()` runs and remembers the
  bound port; `resume()` rebinds on that exact port with no fallbacks,
  and when another process took the port meanwhile it refuses with
  `IntakeBindException` naming the remembered port as taken while the
  pause state survives for a retry. The instance identity carries
  across: `BridgeInstanceInfo` (read via `server.instanceInfo`) names
  the actually bound port, a stable secure-random `instanceId` (32 hex,
  constant across pause/resume and restarts - the pinning identity),
  and the `protocolVersion` wire-contract constant
  (`BridgeInstanceInfo.bridgeProtocolVersion`). `start()` while paused
  supersedes the pause.
- Added: the health page - `BridgeConfig.healthPath` (default off) arms
  a `GET` route that passes the standing gate (origin and Host gates,
  seat caps, the one admission step with its settle) and answers the
  accepted origin alone with literally `{"ok":true}` - no version
  number, no counters, no details, so the page can never be used to
  fingerprint the host; a non-accepted origin reads the standing
  refusal with no CORS echo. The page answers on the bridge's own
  listener only; disarmed, the path keeps its standing `405`.
- **Breaking: the handler budget is on by default** - `handlerTimeout`
  left at null no longer means "no deadline"; it selects the configured
  default budget (`BridgeConfig.handlerTimeout`, 30 seconds shipped). A
  handler running past the budget is answered `504 handler_timeout`, its
  seat is freed, and the still-running work becomes a counted orphan;
  `stop()` awaits orphans up to the same budget and retires whatever
  remains at its return. To ask for no handler deadline at all, pass the
  named constant `LocalIntakeServer.noHandlerTimeout` (its value is
  `Duration.zero`, which is no longer an error - a negative budget still
  throws `ArgumentError` at construction). See MIGRATION-0.2.0.md.
- Added: a bounded stop - `stop({Duration? timeout})` returns a
  `BridgeStopReport` (seats and orphan handlers still running at the
  return); with a timeout the whole drain - the graceful close, the seat
  wait, the orphan grace - is bounded by it, and a listener that misses
  the graceful close inside the deadline is force-closed. The live
  WebSocket channels close in parallel, each bounded by the deadline's
  remainder: a channel that misses its close inside the deadline never
  stretches the stop past it and is announced by count at the return.
  Every
  still-working orphan is retired at the stop's return: a restart never
  inherits the previous generation's orphans into its live-work budget,
  and they stay visible in the orphan counter until they settle.
- Added: read-only counters - `LocalIntakeServer.counters` answers a
  `BridgeCounters` snapshot: active seats, working orphans across
  generations with the retired ones named, every rejection by wire code
  (counted at the single reply exit), and two overlapping tallies -
  protocol-shape rejections (the pre-admission gates the protection
  counter never sees) and pairing rejections (the pairing route plus the
  pairing-family codes off it).
- Added: `onOrphanSettled` on the server - fired once per orphaned
  handler settlement, current-generation or retired alike; a throwing
  callback is contained with one telemetry error line and never breaks
  the wire or the drain.
- Added: the cooperative cancel signal - `TrustedCommand.cancellation`
  carries a per-command `CommandCancelSignal` the handler may read; the
  intake fires it at the handler-budget expiry (the 504 moment) and at
  stop. A command built outside the intake carries the const
  never-cancelled instance. No client-disconnect detection is wired.
- Changed: the periodic idle sweeps cover the three pairing maps -
  expired sessions, paired records (their id-index mirror leaving with
  them), and replay-cache entries leave on ordinary request traffic, at
  most once a second. A session swept by idleness answers
  `pair_code_invalid` for its code instead of `pair_code_expired` (both
  403, both telling the page to pair again); records and replay are
  wire-invisible.
- **Breaking: the three intake names are renamed, the old ones removed
  with no deprecation window** - the token header `X-Portal-Token`
  becomes `X-Bridge-Token`, the generator `generatePortalToken()`
  becomes `generateBridgeToken()`, and the originless command source
  marker `'unknown-portal'` becomes `'unknown-origin'`. A request
  carrying `X-Portal-Token` is treated as a request without a token
  (the bridge writes one muted warning per second naming
  `X-Bridge-Token`, so the developer sees why the token did not
  authenticate), the allowed CORS headers list carries `X-Bridge-Token`
  alone, and the token length cap (`400 token_too_long`) and the
  single-value header gate now guard the new name. See
  MIGRATION-0.2.0.md for the three renames and the migration paths.
- **Breaking: the WebSocket channel refuses to arm below Dart 3.13** -
  `WebSocketTransformer.upgrade` carries the `maxPayloadLength`
  transport ceiling from Dart 3.13 onward, and the channel never runs
  without it: arming `BridgeConfig.wsPath` on an older SDK throws
  `ArgumentError` at server construction with the reason named (the
  package's declared 3.8 floor still compiles, and every non-channel
  path works unchanged there - the message says so). On Dart 3.13+ the
  channel works exactly as before, with the ceiling enforced at the
  upgrade and no fallback upgrade without a memory limit.
- Changed: the token failure window is a signal about wrong guesses,
  never a refusal of the verified sender - the correct token is compared
  and accepted whatever the failure history, from any sender, with or
  without an `Origin` header, and a match clears the window. The
  wrong-guess budget is 5 wrong token attempts per 60-second window,
  per origin (originless attempts share one window): above it, further
  wrong tokens answer `429 token_locked` with the honest remaining wait,
  stamp nothing, and write one muted security line per second carrying
  the attempt count. `token_locked` is never produced for the correct
  token.
- Changed: `update()` additionally refuses a configured token below the
  character-diversity floor (fewer than 8 distinct characters - a
  repeated-character token is guessable at a glance);
  `generateBridgeToken()` output always passes.
- Compatibility: a saved token below the diversity floor keeps loading
  and stays active at startup with one rotation warning -
  `updateFromSaved` refuses no legitimate saved state at upgrade; the
  refusal lives in `update()` at set time alone.
- Added: a single admission step - `IntakeProtection.admit` answers one
  request with one `IntakeAdmission` record that carries the accepted
  route, the CORS echo decision, and the verbose-error decision,
  `TrustedCommand.admission` delivers that record to the host, and
  `intakeRejectionRegistry` is the single table behind every rejection
  code on the wire.
- Changed: a `413` over an unread body now writes the reply and flushes
  before the write side closes - the sender reads the code even when it
  never stops sending, the seat frees at the reply, and the remaining
  body drains in the background within the existing discard limits.
- Changed: `update()` refuses a configured token longer than the wire's
  header cap (a request carrying it could never pass `token_too_long`),
  and a saved token over the cap boots the token layer inert with one
  loud rotation warning instead of silently never matching.
- Changed: a `HEAD` response carries headers only - no JSON body on the
  wire.
- Documentation: the allowlist port semantics are stated and pinned by a
  witness - an entry with an explicit port matches that port alone; a
  bare or wildcard entry matches the host on any port.
- Added: the pairing route - `POST /pair` (only while pairing is armed)
  exchanges the displayed one-time code for the origin-bound token; its
  replies always echo CORS (the code is the gate, not the origin), and
  disarmed the path rides the ordinary non-root behavior, wire letter
  unchanged. The allowed CORS header list extends with
  `X-Bridge-Pairing` only while pairing is armed, and the single-value
  gate and the 256-byte length gate guard it there (`400
  duplicate_header`, `400 pairing_too_long`).
- Added: the real-browser lab pairs a page end to end - a desktop
  Chrome/Chromium headlessly pairs with the displayed code, signs its
  command with WebCrypto (the same HMAC construction the server
  verifies), reads the reply, and sees the replay and the proofless
  page refused; `dart run tool/emulator_pairing_lab.dart` runs the same
  story against an emulator's browser over adb reverse, reading the
  verdicts from the page's report collector.
- Added: proof-of-possession for paired pages - under
  `requireOriginWithToken`, a page signs every request with HMAC-SHA-256
  (the package's internal digest primitives) over the pairing id, a
  millisecond wall-clock stamp, the method, the path, and the
  correlation id, and presents the proof in `X-Bridge-Pairing`: the raw
  paired token never travels after pairing day. The stamp accepts one
  minute of clock skew; a reused proof or a stale stamp answers `403
  pair_signature_replay` (the replay cache keys the full proof, so two
  different commands signed within the same millisecond never collide);
  verification compares constant-time, the
  origin binding is checked before any token verdict, and an unqualified
  origin never learns whether its proof was valid.
- Changed: the pairing entrances refuse a disposed protection -
  `startPairing` and `pair` throw `StateError` after `dispose` (matching
  the admission path's `protection_disposed` refusal) instead of minting
  a code or judging one against a disposed object; and
  `restorePairedOrigin` throws `ArgumentError` for a remainder above the
  paired-token age (24 hours) - a pairing never outlives the token age
  it was issued with, so a bigger remainder is a corrupt host timestamp
  rather than a binding; the exact age still restores.
- Deprecated: the per-question protection probes (`check`,
  `echoesCorsFor`, `verboseErrorsFor`, `noteRejection`, `logRejection`,
  and `normalize`) in favor of the admission record; removal is planned
  for 0.3.0.
- Added: `OriginPolicy.requireOriginWithToken` (off by default - the
  default wire is unchanged) requires an admitted origin AND a token
  bound to it: a qualified origin without a valid token answers `403
  token_required`, and the token alone never admits - from an
  unqualified origin it is answered with the origin rejection alone, so
  a wrong-origin sender learns nothing about its token.
- Security: one site rotating subdomains of a single parent at any depth
  can no longer spend the whole new-question budget -
  `OriginPolicy.askFiresPerParentPerWindow` (off by default) bounds each
  parent domain's new questions - the parent is the host's last two
  labels - beside the global 10-per-10-minutes
  ceiling, its suppressed questions fire nothing and spend nothing from
  the global budget, so an unrelated origin keeps its question; and at
  the 1,000-decision cap the oldest remembered deny is now evicted
  before any always-allow decision, so a session full of denied origins
  no longer washes out the pages the user approved (a cap with no deny
  still evicts the oldest entry).
- Changed: the parent-budget-suppressed question reads its own code now
  - `429 origin_parent_rate_limited` with the honest `Retry-After`
  (the remainder of the parent's window) - instead of the generic
  `origin_pending`, so a page can tell "your site asked too much" from
  "a consent window is open"; the global ceiling still answers
  `origin_pending`, and with the option off (the default) the wire is
  unchanged. The new code sits in `intakeRejectionRegistry` and the
  README wire tables, walked on the live wire like every other code.
- Added: `IntakeProtection.onQuestionClosed` - fired exactly once when a
  consent question window ends (the answer arrived, the host future
  threw, or the ask timeout closed it) with the normalized origin, so
  the host dialog closes without racing `askTimeout`;
  `onUnknownOrigin`'s signature is unchanged, budget-suppressed
  questions never signal, and `dispose()` closes the rest silently.
- Added: the payload-contract options - seven `BridgeConfig` switches,
  **every one off by default, so the default wire is byte-identical to
  previous releases**; each carries enabled and disabled witnesses:
  - `strictPayloadItems` - a JSON command list (top-level or under a
    wrapper key) carrying a non-string or empty-string element refuses
    `400 invalid_payload_item` instead of the default silent drop of
    that element.
  - `requireValidJsonShape` - a body whose leading shape claims a JSON
    container (`{`/`[`) must scan structurally complete (every opener
    closed, every string terminated) or it answers `400
    malformed_json_shape` before decoding; quote-leading raw text is
    never scanned, so textual gateways are untouched.
  - `rejectInvalidJson` - a body sent as `application/json` that fails
    JSON decoding answers `400 invalid_json` instead of the default
    raw-text fallthrough; other content types keep the raw path.
  - `requireJsonBodies` (JSON-only mode) - the raw-text fallback refuses
    `400 non_json_body` whole: raw command text and JSON scalar bodies
    (number, boolean, null) alike; a JSON string body still serves. With
    `rejectInvalidJson` also on, a broken `application/json` body reads
    the more specific `invalid_json`.
  - `acceptHandlerRefusal` - a failed `CommandOutcome` carrying the new
    `refusalStatus` field (400..499) answers that client-error status
    with its code instead of the standing `500`; null keeps `500`, an
    out-of-range marker is ignored with one throttled warning, and with
    the option off the field is inert - the default stays `500`.
  - `maxErrorMessageLength` (0 = off, negative throws at construction) -
    the host error text echoed to trusted origins is capped on the wire
    to at most this many UTF-8 bytes, cut at a whole-character boundary
    (a multi-byte character is dropped whole, never split); the code and
    the reply shape are never touched.
  - `acceptBinaryBodies` - `application/octet-stream` joins the admitted
    media types and the raw bytes reach the handler as the new
    `TrustedCommand.binaryPayload` (`payloads` stays empty - a binary
    body is never JSON-parsed), with the command name riding the
    `X-Command` header into `TrustedCommand.headers` and joining the
    CORS allowed-header list while the option is on. The bytes sit under
    an internal named ceiling - 256 KiB, a fixed constant deliberately
    not an option - and a binary body over it answers `413
    payload_too_large` naming the binary cap; a binary body without its
    `X-Command` name - absent, blank, or with an empty body - answers
    `400 command_required` (the bridge delivers only named binary
    commands); below the ceiling a named file (image or PDF) travels
    with its command. Off, the type refuses `415` and the header list
    never offers `X-Command`.
- The four new refusal codes (`invalid_payload_item`,
  `malformed_json_shape`, `invalid_json`, `non_json_body`) sit in
  `intakeRejectionRegistry` and the README wire tables, walked on the
  live wire like every other code; the handler-refusal statuses are
  handler-chosen outcomes and stay outside the registry by its contract,
  and `command_required` (the unnamed binary body) joins the same
  registry and tables with its own walk.
- Added: the streaming reply - `BridgeConfig.allowStreamingReplies`
  (off by default) plus the request header `X-Bridge-Stream: events`
  turn one command into a `text/event-stream` reply: every handler
  progress report travels as one `event: progress` frame the page
  reads from the streamed body in call order (the sink is
  `TrustedCommand.progress`, non-null only for opted-in commands),
  and the handler's outcome travels as the final `event: result`
  frame carrying the standing reply contract - the same error codes,
  the same host-text verbosity and byte cap, and the same 64 KiB
  reply-data cap (`reply_data_too_large` refuses whole, never
  truncated). A progress report over the internal 64 KiB event cap
  ends the stream with `progress_data_too_large`, fires the command's
  cancel signal, and turns the sink inert. The page closing mid-stream
  reaches the handler as cancellation and leaves no seat nor socket.
  The header joins the CORS allowed-header list only while the option
  is on; the disarmed wire is letter identical to previous releases.
- Added: the WebSocket channel - `BridgeConfig.wsPath` (null, off by
  default) opens a `dart:io` WebSocket on the host-chosen path. The
  handshake passes the same single admission step every request
  passes: origin, fetch metadata (the browser's own
  `Sec-Fetch-Mode: websocket` handshake shape is a real send method),
  host authority, and the seat caps - every refusal answers its
  standing wire code BEFORE the upgrade. The connection opens only
  after its first message carries a verified credential - the shared
  token or a paired origin-bound signature (`token_required` /
  `token_locked` / `pair_signature_replay` close with their literal
  codes) - within the auth deadline (10 seconds); an admitted origin
  without a credential in time is closed (`ws_auth_timeout`). Inbound
  messages are commands passing the same payload checks; replies are
  events shaped by the standing reply contract. The message cap
  (256 KiB) and transport ceiling (2 MiB) are fixed named constants:
  a message between them reads `ws_message_too_large` in a refusal
  frame, a frame over the ceiling is refused by `dart:io`'s own
  transformer before any payload byte buffers; silence past
  `BridgeConfig.idleTimeout` closes `ws_idle_timeout`; a heartbeat
  keeps NAT paths alive and cuts dead peers. One open connection
  holds one concurrency seat - the seat caps bound the live
  connections per origin exactly like the live commands; a stop
  closes the live channels inside its drain. The four channel codes
  (`ws_auth_timeout`, `ws_auth_invalid`, `ws_message_too_large`,
  `ws_idle_timeout`) and `progress_data_too_large` sit in
  `intakeRejectionRegistry` and both README wire tables, walked on
  their own wire like every other code.
- Added: the host feed - `LocalIntakeServer.acceptHostFeed(...)` hands
  a message from a non-HTTP channel (an Android `WebMessageListener`
  callback, an iOS `WKScriptMessage`, a native client) to the same
  single admission step and the same payload checks, and returns an
  accepted `TrustedCommand` or the rejection with the standing wire
  codes. The origin travels with a required trust grade
  (`OriginTrustLevel`: `browserHeader`, `platformVerified` - the
  platform verified the origin itself - or `none`, an originless native
  client crossing by its token); the grade is recorded on the admission
  record (`IntakeAdmission.originTrust`) and never appears on any
  reply, and an origin with the `none` grade is refused loudly instead
  of posing as a browser header. A platform-verified origin carries no
  Fetch Metadata headers, so only the absence gates do not fire for
  that grade; every other check - origin form, policy, quotas, token
  layer, body limit, payload checks, the live-work budget - applies
  unchanged, and every rejection counts through the same rejection
  counter. The HTTP wire is letter identical to previous releases.
- Added: `tool/native_messaging_adapter.dart` - a dependency-free
  reference native-messaging host for browser extensions: four
  little-endian length bytes then JSON on stdin, and the standing
  reply contract framed the same way on stdout. The extension origin
  comes from the adapter's own configuration (never from the message)
  and feeds the same admission step as a platform-verified origin; a
  frame declaring a length over the body cap is refused from the
  header alone and its body is never read.
- Added: `LocalIntakeServer.handleHostRequest(request, hostPort: ...)`
  - the mount on an existing `dart:io` server: the host keeps its own
  `HttpServer` and its routing and forwards the requests the bridge
  owns to this entry, which processes each one through the full
  standing protection - the same gates in the same order, the same
  wire codes, and the reply written and cut over the detached socket
  exactly as the private listener does - and the local host
  authorities are computed from the host server's own port
  (`hostPort`), so a forwarded request's `Host` header passes the
  authority gate as it would on the private server. The default wire
  is letter identical to previous releases; the entry is called only
  where the host chooses to call it.
- Security: the mounted entry checks the remote peer itself, so a host
  bound to `0.0.0.0` does not break the package's loopback guarantee -
  a request whose remote address is not loopback is refused with the
  standing `403 blocked_by_protection` (no new wire code) by the first
  gate: no header is read, no log line is written, and no warning
  budget is spent; the rejection is counted only in the
  rejection-codes counter, an in-memory number that helps the host see
  the attempts, so a remote party cannot write into the bridge's
  security log; the denial is silent, the refusal carries a generated
  correlation id only, and the reply is cut over the detached socket;
  an IPv4-mapped IPv6 peer
  (`::ffff:127.0.0.1`, what a dual-stack host bind delivers for an
  IPv4 loopback caller) counts as loopback, and an unreadable peer
  fact refuses. The open-connection cap guards the bridge's own
  listener and has no fact to read on the mount; the seat budget binds
  there, and a mounted request mid-flight holds its seat inside
  `stop`'s drain exactly as on the private server.
- Security: the local page is readable by every program on the device
  - a plain `GET` with no browser headers reads it - so no pairing
  code, no token, and no secret belong in a local page; the pairing
  code is shown through the host's own channel (its screen, or its
  terminal), and the local-page documentation and example serve a
  status page, never a pairing-code page.
- Added: `BridgeConfig.localPages` - the local pages, an optional
  page from memory for the host without a UI (a CLI tool, a service
  showing a status readout or its settings): pass the pages (a path,
  the content, the content type) and a `GET` on exactly those paths
  answers the page, while every other `GET` keeps its standing
  `405 method_not_allowed`. `null` - the default - keeps the option
  off with the wire letter identical, and nothing is ever read from
  the filesystem: the pages live in the host's memory, and serving a
  folder from disk is not part of this package. The pages answer on
  the bridge's own listener only.
- Security: the page reply carries a strict CSP (nothing loads from
  anywhere except the page's own inline script and style, and
  connections stay on the bridge's own origin via
  `connect-src 'self'`), `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`,
  and no CORS echo, so a foreign page cannot read it cross-origin.
  The page's own origin (the bound loopback origin in its
  `127.0.0.1` and `localhost` spellings) crosses the admission on
  its own explicit path (`IntakeAdmissionPath.bridgeOrigin`) - never
  through the allow-all mode - behind the same host-authority gate,
  browser send-method checks, listed quota, and seat caps as a
  listed origin, while any other loopback origin (another port
  included) stays refused exactly as before.
- Added: the four protection presets - `BridgePresets.closed()`,
  `allowList(origins:)`, `tokenOnly(token:)`, and
  `mobile(token:, origins:)` (the paired-host shape: the token plus
  `requireOriginWithToken` and pairing armed with the host's
  callbacks). Each preset returns an `IntakeProtection` whose policy is
  exactly the shape its documentation names, none of them opens
  allow-all and none arms discovery, and the standing token validation
  runs at build time - a preset never arms a token the wire would
  refuse.
- Added: `LocalIntakeServer.telemetry` and
  `LocalIntakeServer.correlationIdGenerator` are optional - the host
  passes nothing to get sensible defaults. Telemetry defaults to the
  line-writing `PrintTelemetry` (security warnings reach stderr;
  pass `SilentTelemetry` to hide them), and correlation ids default to
  an internal secure-random generator; an incoming `X-Correlation-Id`
  is still honored verbatim and never passes through the generator.
- Added: `bin/bridge_demo.dart` - a token-only bridge a host can try
  from the command line in a minute (`dart bin/bridge_demo.dart`, or
  `dart run localhost_bridge:bridge_demo` from a depending project).
  It generates and prints its own token with the bound port, a ready
  `curl` carrying that token, and the stop method; it serves real
  commands with that token and refuses every argument beyond
  `--port <n>` loudly before anything binds - an allow-all or
  discovery opener cannot be passed to it.
- Deprecated: `IntakeProtection.updateFromSaved` - build the
  `OriginPolicy` from your own saved settings and call
  `update(policy:, token:)`, which validates at set time instead of
  landing an unknown mode string on the closed default in silence; and
  `IntakeProtection.onRejected` - refresh from the admission records
  you settle (a record with a non-null `rejection` is a rejection; the
  outside ones ride `IntakeAdmission.noteAuthorityReject`), or read
  the `rejectedCount` getter. Both keep working unchanged; removal is
  planned for 0.3.0.
- Changed: `ArrivalGuard` settles as an experimental host-side tool -
  it stays in the public API as a standalone meter you record arrival
  facts into and stays deliberately unwired from the server's admission
  path (the intake never calls it; the wire enforces its per-origin
  budgets without it).
- Changed: channel rejections count exactly once per refusal in the
  per-code counters - the five channel refusal paths
  (`unsupported_payload_shape`, `invalid_payload_item`, `invalid_json`,
  `non_json_body` from the JSON path, and `server_busy`) used to rise
  by two per refusal; every channel refusal now reads one increment,
  the same contract the HTTP replies always had.
- Changed: a streamed command carries the same admission record the
  single-reply path delivers - `TrustedCommand.admission` on a
  streaming command used to be the unrecorded placeholder, so a
  streaming handler read no accepted route and no origin trust grade.
- Security: the settle step re-checks the consumable admission facts on
  the live state - a one-time grant still present, a pairing proof's
  replay key still unused, the per-origin quota window and the token
  guess budget not yet full. A request admitted and then held before
  its acceptance gate (the host-owned telemetry measure is such a
  holder) no longer rides a fact a concurrent request already
  consumed: its record settles into the standing refusal for the live
  state (`origin_pending`, `pair_signature_replay`,
  `origin_rate_limited`, or `token_locked`), so one allow-once grant
  accepts one request and one pairing proof passes once, whatever the
  concurrency. Records whose facts are unchanged settle exactly as
  before.
- API: `BridgeConfig.tlsFirstRecordTimeout` (default five seconds,
  bounds one to sixty seconds, `ArgumentError` outside at
  construction) bounds the TLS transport's first-record window; the
  three TLS counters on `server.counters` are named
  `tlsHandshakesInFlight`, `tlsSocketsCut`, and
  `tlsHandshakesDelivered`; while `maxOpenConnections` is on it counts
  in-flight TLS handshakes too; and `stop` announces in one line the
  TLS handshakes left stuck past arming.

## 0.1.3

- Security: an early rejection (405, a Host, shape or policy reject,
  415, a payload-shape reject, an OPTIONS preflight) no longer holds a
  concurrency seat: the connection is cut after the reply, and no
  request holds a seat past the request timeout before its handler
  starts.
- Security: the per-origin quota and token-failure window maps have an
  internal size cap.
- Security: a body carrying more than one payload wrapper key is refused
  with `400 unsupported_payload_shape` instead of running the first key
  alone.
- Security: an `Origin` that is not `scheme://host[:port]` is refused
  with `400 origin_malformed`, and the consent callback receives the
  normalized origin.
- Security: a listed origin sending a mismatched `Sec-Fetch-Mode` or
  `Sec-Fetch-Dest` is refused with `403 cross_site_blocked`.
- Security: an `X-Portal-Token` longer than 1,024 bytes is refused with
  `400 token_too_long`.
- Security: the `Origin` value in telemetry contexts is sanitized like
  the rejection log lines.
- A body the HTTP parser rejects is answered `400 bad_request` instead
  of `500 internal`.
- A POST to a path other than `/` logs a throttled warning; the request
  is still served.
- Intake warning lines are throttled to one per second, with the muted
  count on the next line.
- `ArrivalGuard` queues are bounded by their per-minute limits.
- Documentation: the token path and the availability model, re-verified
  browser and platform tables, a consent example page, two domain
  examples, and an attack-to-test index.

## 0.1.2

- Security: a long run of `/` characters in the `Origin` header no
  longer freezes the intake.
- Security: while the token failure window is locked, a failing
  handler's reply no longer carries the host's message, and no new
  consent question opens.
- An `Origin` header longer than 1,024 characters is refused with
  `400 origin_too_long`.
- `start()` called while `stop()` is still draining waits for it;
  after a failed start, `port` is `0`.
- Minimum Dart SDK lowered to 3.8.0 (Flutter 3.32.0).
- The protection log is no longer silent in the documented setup: the
  server builds its default protection with the server's own telemetry,
  and `start()` logs a warning when a protection passed in has no
  telemetry of its own, so the allow-all warning and the rejection
  lines reach the host log as documented.
- A late answer to an expired consent question can no longer override a
  newer decision for the same origin: answers apply only when they
  answer that origin's most recent question.
- Updating only the token no longer drops a pending consent answer: the
  consent generation advances only when origin decisions change, so an
  `allowAlways` answer given after a token update is still remembered.
- The per-origin rate-limit window no longer counts rejected attempts,
  so the window stays at quota length and `Retry-After` is computed
  from the real oldest entry. A client that honors `Retry-After` and
  waits it out is accepted on its next attempt.
- The request-body deadline is absolute: a single timer starts when the
  body read begins, and a body that completes after the limit answers
  `408` with the handler never invoked (the inter-chunk silence timeout
  is unchanged).
- Rejection log lines no longer carry the raw `Origin` value: the
  unlisted-origin reason is a fixed sentence and the origin stays in
  the sanitized `origin=` field, watch-mode lines included.
- A `TimeoutException` thrown by your handler reports as a plain `500`
  again: only the bridge's own handler budget produces `504`, so a
  deliberate handler timeout no longer counts the command as orphaned.
- The token path echoes CORS headers only for origins the origin policy
  would echo for, as the contract states; non-browser clients are
  unaffected.
- The example dedup ledger no longer drops a live entry when full:
  expired entries are swept first, and a ledger still at capacity
  refuses new commands with a `ledger_full` outcome (the work never
  starts) instead of repeating old work on a retry.
- Every non-loopback `extraHosts` entry now logs the DNS-rebinding
  opt-out warning at startup, dotless names and non-loopback IPv6
  addresses included; the loopback literals stay silent.
- A listener bound before a startup-step failure is closed instead of
  leaking past the fallback: `start()` closes the bound server and
  resets its state before trying the next port, so a failed startup
  leaves no live listener without a reference.
- The example's failure reply carries a fixed sentence - `The command
  failed; see the host log` - instead of the thrown error text, so
  environment detail from an exception never reaches the page.
- Documentation: platform tables are dated and sourced; what a
  browser page can use in this release, and accuracy fixes in the
  README and SECURITY.md.

## 0.1.1

- `429` replies that carry `Retry-After` (`origin_rate_limited`,
  `token_locked`) now echo the CORS headers of admitted origins, so the
  retrying page can read its rejection code and the honest wait instead
  of an opaque network error.
- `start()` rejects a double start through its returned future (the same
  `StateError` on every path), so `.catchError`, `then(onError:)`, and
  `await` inside `try/catch` all observe the rejection identically.
- `update()` validates the origin policy numbers up front: a non-positive
  `perOriginPerMinute` or `askTimeout` throws `ArgumentError` before
  anything is applied, so a failed update keeps the previous protection
  state intact.
- Rejection logs sanitize the logged `Origin` value: control characters
  are stripped and the value is capped, so a hostile header cannot forge
  log lines or bloat every throttled line.
- `413` now reaches the client on Linux and macOS: after the early
  rejection the reply is written to the raw socket and the unread
  remainder of the body is drained within bounded patience (about two
  seconds or four bodies, whichever comes first) before the connection
  closes, instead of closing over unread data - which those kernels
  answer with a reset that discarded the reply. A sender past the bounds
  keeps the immediate cut. The busy `503` reply stays an immediate cut
  on purpose: a saturated server spends no drain windows, so a dropped
  busy reply reads to the page as the retryable network error it already
  looks like.
- The 413 limit label reads `1 MiB`.
- Documentation honesty: lib docs describe a host logger, plain
  commands, and a local Dart app (no original-product vocabulary), test
  headers reference no repository tooling, two protection comments match
  the code and `SECURITY.md`, and the README dependency claims are
  exact.
- Documentation surface: browser support and host platform tables
  (reviewed 2026-11) — Safari and every iOS browser are unsupported
  (mixed content blocks `http://127.0.0.1` from `https` pages), Android
  reaches the bridge behind the Local Network Access prompt with the
  token layer as the practical requirement against forged local
  origins; a page-side JavaScript reference shows
  `targetAddressSpace: 'loopback'`, the `origin_pending` retry honoring
  the seconds-based `Retry-After`, 504 treated as an unknown outcome
  reconciled on `X-Correlation-Id`, a bounded
  `navigator.permissions.query({name: 'loopback-network'})`, and
  `allow="loopback-network"` (plus `allow-same-origin` under `sandbox`)
  for iframes; a 504 unknown-outcome callout opens the wire contract;
  the Arabic guide is now an explicit Arabic summary instead of
  claiming a full mirror; the allowlist contract states bare hosts
  match the host name on any port, the fourteen wire cases are one test
  replaying a corpus across three protection modes, and "trusted"
  commands mean admitted by the origin decision, never a validated
  payload; and `ArrivalGuard` is documented as a standalone host-side
  tool the server never calls, with its keep-or-remove decision
  deferred to a later release.
- Reporting: `SECURITY.md` now reflects reality — the package is
  published on pub.dev, the public repository is the single source of
  truth, and its private vulnerability reporting channel is the way to
  reach the maintainer.
- Packaging: the placeholder `homepage` is removed from `pubspec.yaml`
  so pub.dev shows the repository link, and the READMEs open with CI
  and pub.dev badges.
- Packaging: CI workflow files are excluded from the published archive
  via `.pubignore`, so the pub.dev archive lists package files only.

## 0.1.0

- Initial release. A localhost HTTP intake server on `127.0.0.1` that lets
  admitted web pages deliver origin-trusted, payload-untrusted commands to
  a local Dart app.
- CORS echo for admitted origins only (`Vary: Origin`, never `*`), DNS
  rebinding defense (Host must textually match the bound port's
  authorities), and duplicate-header rejection.
- Unified origin policy: closed by default; an allowlist of exact origins,
  bare hosts, and `*.domain` patterns; hardened allow-all (valid HTTPS
  origin + fetch-mode checks + per-origin rate limit); first-use consent
  through a host callback (`allowAlways`, `allowOnce`, `reject`,
  `dismissed`); an independent token layer for non-browser integrations;
  and a watch mode (`reportOnly`) that observes both per-origin quotas
  without rejecting.
- Resource limits: 1 MiB body cap, JSON structural-element cap (default
  10,000) and nesting-depth cap (default 32) counted in one pre-decode
  pass, concurrency seats with `503` (seats plus timed-out handlers are
  one live-work budget), per-request and idle timeouts, optional
  `handlerTimeout` freeing a seat with `504` (the command may still have
  run — deduplicate on `X-Correlation-Id` before retrying).
- Content types: POST bodies must carry `application/json` or `text/plain`
  (`BridgeConfig.allowedContentTypes`); hidden-HTML-form types are refused
  with `415 unsupported_media_type`. The browser-facing form defense is
  the fetch-mode hardening (`Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest:
  empty`) — the content-type gate raises the floor for non-browser
  clients, and `OriginPolicy.requireFetchMetadata` (on by default)
  extends the shape checks to headerless requests from legacy browsers.
- Configuration honesty: `update()` changes only what you pass — updating
  the policy keeps the token, updating the token keeps the policy.
  Remembered consent answers are cleared only when the origin policy
  actually changes. A rejected token never appears in error messages.
  Stable error codes throughout; `SECURITY.md` documents the threat
  model, the residuals, and how to report a vulnerability.
