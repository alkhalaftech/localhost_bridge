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
  evicts a live entry) and by time (`ttl`, swept on the next look).
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
  the graceful close inside the deadline is force-closed. Every
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
  minute of clock skew; a reused or stale stamp answers `403
  pair_signature_replay`; verification compares constant-time, the
  origin binding is checked before any token verdict, and an unqualified
  origin never learns whether its proof was valid.
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
- Security: one site rotating subdomains of a single parent can no
  longer spend the whole new-question budget -
  `OriginPolicy.askFiresPerParentPerWindow` (off by default) bounds each
  parent domain's new questions beside the global 10-per-10-minutes
  ceiling, its suppressed questions fire nothing and spend nothing from
  the global budget, so an unrelated origin keeps its question; and at
  the 1,000-decision cap the oldest remembered deny is now evicted
  before any always-allow decision, so a session full of denied origins
  no longer washes out the pages the user approved (a cap with no deny
  still evicts the oldest entry).
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
    to exactly this many characters; the code and the reply shape are
    never touched.
  - `acceptBinaryBodies` - `application/octet-stream` joins the admitted
    media types and the raw bytes reach the handler as the new
    `TrustedCommand.binaryPayload` (`payloads` stays empty - a binary
    body is never JSON-parsed), with the command name riding the
    `X-Command` header into `TrustedCommand.headers` and joining the
    CORS allowed-header list while the option is on. The bytes sit under
    an internal named ceiling - 256 KiB, a fixed constant deliberately
    not an option - and a binary body over it answers `413
    payload_too_large` naming the binary cap; below the ceiling a file
    (image or PDF) travels with its command. Off, the type refuses `415`
    and the header list never offers `X-Command`.
- The four new refusal codes (`invalid_payload_item`,
  `malformed_json_shape`, `invalid_json`, `non_json_body`) sit in
  `intakeRejectionRegistry` and the README wire tables, walked on the
  live wire like every other code; the handler-refusal statuses are
  handler-chosen outcomes and stay outside the registry by its contract.

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
