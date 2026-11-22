# Security Policy — localhost_bridge

## Reporting a vulnerability

The public repository
[alkhalaftech/localhost_bridge](https://github.com/alkhalaftech/localhost_bridge)
is where the package is published and where reports go. That repository
has **Private vulnerability reporting** enabled — use it to reach the
maintainer privately. Do not open a public issue for a suspected
vulnerability. Include the package version, a minimal reproduction, and the
affected surface (intake server, protection policy, token layer, or the
example apps).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Threat model

`localhost_bridge` is an intake server that binds to `127.0.0.1` and hands
opaque command payloads to a host-registered handler. The browser is the
adversary it is built against: any page open in any tab on the machine can
attempt to reach the port. The protections below assume the page model
(Same-Origin Policy, Fetch Metadata) — they are real walls against web
pages and honest documentation about everything else.

The browser's Local Network Access permission is not a security boundary
of this bridge: the user can turn it off, and internal browser paths can
reach loopback without it. The boundaries the bridge itself enforces are
the Host-authority check, the origin policy, and the token layer.

### What the bridge protects against

- **Cross-origin command injection from web pages** — an origin allowlist
  (default closed), first-use consent questions for unknown origins, and
  no `Access-Control-Allow-Origin` echo for anyone the policy rejects, so
  a page can neither send silently nor read replies.
- **DNS rebinding** — the `Host` header must textually equal one of the
  authorities computed from the actually-bound port (`127.0.0.1:port`,
  `localhost:port`, bare forms, plus configured `extraHosts`); absolute-form
  request URIs and headers carrying `@`, `/`, or `\` are refused. No name
  resolution happens in the request path, so a rebound name never matches —
  unless the host itself listed that public name in `extraHosts`: pinning a
  public DNS name there is the host's explicit opt-out of this guard for
  that one name.
- **Hidden-form / beacon / no-cors sends** — request-shape checks
  (`Sec-Fetch-Mode`/`Sec-Fetch-Dest`) on browsers that send Fetch
  Metadata: this is the browser-facing form defense, and
  `OriginPolicy.requireFetchMetadata` (on by default) extends it to
  headerless requests from legacy browsers. The Content-Type gate raises
  the floor for non-browser clients by refusing
  `application/x-www-form-urlencoded` and `multipart/form-data`
  (`415 unsupported_media_type`) — note that `text/plain` is itself a
  valid HTML form enctype, so it passes that gate and is stopped by the
  fetch-mode checks alone.
- **Silent sends are write-side only** — even when a shape check is
  skipped, a non-CORS send cannot read the reply.
- **Token guessing** — a 32-byte length floor and a character-diversity
  floor (fewer than 8 distinct characters) for a configured token
  (`update()` throws on either; the bounds measure length and repetition,
  not entropy — `generateBridgeToken` is the recommended source of a
  token, and its output always passes both floors), constant-time padded
  comparison, and a per-origin wrong-guess budget (5 wrong token attempts
  / 60 s → further **wrong** tokens answer `429 token_locked`, whose
  `Retry-After` states the real remaining window and one muted security
  line per second carries the attempt count). The budget is a signal
  about wrong guesses, never a refusal of the verified sender: the
  correct token is compared and accepted whatever the failure history,
  from any sender, with or without an `Origin` header, and a match
  clears the window — a flood of wrong tokens cannot lock out the
  legitimate token holder, originless included. Wrong guesses above the
  budget stamp nothing, so the window drains honestly and the announced
  wait stays true. The budget pins its window to one origin: a local
  sender can rotate `Origin` values to walk past it — the barrier ahead
  of that path is the token's randomness itself. Nor does the budget
  stop a page on the allow-all or discovery paths (discovery is the
  consent-callback mode — the `OriginPolicy` reference in README.md
  names the callback behind the term): a site can rotate subdomains,
  and each rotated origin opens its own window.
- **Resource exhaustion** — body byte cap with early `Content-Length`
  refusal, JSON structural-element cap before decoding, concurrency seat
  cap with `503`, per-request and idle timeouts, per-origin rate quota,
  an internal `Origin` length cap (`400 origin_too_long` — a value over
  1,024 characters is refused before any map, log line, consent question,
  handler, or telemetry context reads it), and bounded bookkeeping under
  web-page flood: the per-origin failure and quota maps sweep their idle
  entries once their window expires, and each map is held to an internal
  10,000-entry cap, so a same-session local program forging many distinct
  `Origin` values no longer pins expired entries past the cap. A flood
  with rotating origins can evict a live window from the map, and origin
  rotation bypasses the quota and the lockout anyway; that residual is
  stated here (the request being processed never loses its own window, so
  the token lockout still forms under the flood).
- **Header smuggling ambiguity** — duplicate `Origin`, `X-Bridge-Token`,
  or `X-Correlation-Id` headers are refused (`400 duplicate_header`).
- **Information disclosure** — rejected origins get no CORS echo at all;
  host error text is visible only to authorized origins; internal errors
  return a fixed body; secrets never reach the command handler.
  Consent-question rejections and the 429s that carry a wait duration are
  readable on purpose, and with a consent callback configured, any HTTPS
  origin not yet declined can read `origin_pending`.

### What the bridge does NOT protect against

These are stated plainly so no host builds on a false assumption:

- **Programs running in the same user session.** Loopback TCP has no peer
  authentication: any local process can open `127.0.0.1:port` and write
  `Origin: https://your-portal` verbatim. On Windows, a same-session
  process can also unprotect DPAPI-stored tokens. The token layer raises
  the cost from "know a public string" to "hold a secret" — and only while
  no origin path accepts: with a non-empty allowlist, allow-all, or a
  remembered consent, that forged listed origin enters without the secret.
- **Reading every served local page.** A served local page
  (`BridgeConfig.localPages`) is readable by every program on the
  device — a plain `GET` with no browser headers reads it — so no
  pairing code, no token, and no secret belong in a local page. The
  pairing code is shown through the host's own channel: its screen, or
  its terminal, where only the human at the device reads it; a page
  that displayed it would hand it to every local program.
- **A local program that binds the port before the bridge.** Whoever
  binds `127.0.0.1:port` first receives the pages' commands — and the
  token does not help, because the client sends the token to whatever
  answers on that port. The host's levers: a known, fixed port, and
  out-of-band verification of the responder if the deployment needs it.
  The same port number is also free on `::1` while the bridge runs —
  another local program can listen there, so senders should use the
  literal `127.0.0.1`.
- **Mobile host platforms.** On Android, every installed app can open the
  port and send any `Origin` it likes — the origin policy is not a
  barrier there at all, and the origin+token requirement with pairing is
  the practical barrier: the page pairs with a displayed one-time code,
  receives a token bound to its origin (expiring in 24 hours, revocable
  and rotatable by the host), and never sends it raw again - every
  request carries only its HMAC signature, so a same-device app that
  forges the listed origin still cannot sign. The shared token path
  (headerless native clients) holds with the same caveat as above: it
  holds only while no origin path admits without the secret. The in-app
  server runs while the host app is
  foregrounded or behind a foreground service; backgrounded without one,
  the system may stop it. And on Android 17, loopback traffic between two
  profiles (work and personal) is blocked by default for every app
  regardless of targetSdk; loopback within one profile is unaffected.
  Native clients on the device send the token. With the requirement off
  (the default), a browser page presents the token only where its
  preflight is echoed: a listed origin, or any valid https origin not yet
  refused under the discovery and allow-all modes - and an installed app
  can present that same listed origin.
  On iOS there is no path from a browser at all: Safari, and iOS browsers
  built on WebKit, block `http://127.0.0.1` from an `https` page as mixed
  content — Apple permits other engines in the EU (iOS 17.4+); none is
  tested here — and in-app sockets suspend when the host app goes to the
  background.
- **Administrator/SYSTEM-level malware.** It can inject into the host
  process, read the token from memory, or command devices directly
  through the OS without this bridge entirely.
- **A compromised allowed origin.** A listed site that itself turns
  malicious is indistinguishable from a legitimate one. The mitigation is
  host-side: validate and allowlist the payload language, cap quantities,
  and keep a human review path.
- **Rogue browser extensions** with broad host permissions — they operate
  inside the page's authority and bypass CORS entirely.
- **Multi-user hosts (RDP/terminal servers).** Loopback is shared between
  sessions; only the token layer (or an ACL'd transport such as a named
  pipe / restricted unix socket, not provided here) distinguishes callers.
- **Port scanning / service fingerprinting.** Rejections are uniform and
  quiet, but the port's existence cannot be hidden from local software.
  The readable exceptions — consent-question rejections and the 429s that
  carry a wait duration — are deliberate, not leaks.
- **Browsers without Fetch Metadata are closed by default.**
  `requireFetchMetadata` is on: the allow-all and discovery paths refuse
  requests carrying no `Sec-Fetch-Mode: cors` and `Sec-Fetch-Dest: empty`
  (`cross_site_blocked`), so a legacy browser (e.g. Safari before 16.4)
  cannot send silently. A host that turns the flag off to serve headerless
  non-browser clients through the browser paths re-opens this residual
  knowingly: in `allowAllHardened` mode such a client executes a hidden
  form or `no-cors` send silently (write-side; the reply stays unreadable).
- **A blind retry after `504 handler_timeout`.** The timeout frees the
  seat, but the handler may still complete in the background — a retried
  command can double-execute. Callers must deduplicate on
  `X-Correlation-Id` before retrying, not treat 504 as "not executed".
- **A stuck handler with no `handlerTimeout`.** No deadline covers the
  handler phase: a stuck handler holds its seat until it completes, and
  its caller waits on a reply that may never come — sixteen stuck
  handlers exhaust the service. Set `handlerTimeout` for the
  disciplined path: the seat frees at the handler's budget with
  `504 handler_timeout`, and the orphaned handler is counted in the
  live-work budget; the full remedy (a bounded `stop()` and a default
  budget) is planned for a later release.
- **Host-side process-identity decisions.** The bridge never identifies
  peers; a host that decides to kill or trust a local process by image
  name (e.g. a `tasklist` prefix match) is forgeable by any process that
  picks the same name. Identity needs a full path plus a digital
  signature check — a host responsibility, not a bridge one.
- **An unverified owner on the unix-socket boundary.** The
  parent-directory check reads the directory's permission mode and
  cannot know its owner — `dart:io` exposes no owner identity. For a
  normal user the OS already constrains who owns what; the gap matters
  only when the host runs as **root**, where every path is traversable
  and the mode bits are the sole fact being checked. And on a system
  without `/bin/chmod` at its fixed path the listener refuses to arm at
  all — the whole start fails closed, and the failure message names
  `/bin/chmod` so the missing requirement is never a mystery.
- **The pairing signature covers the request line, not the body.** The
  HMAC canonical string binds the pairing id, the stamp, the method,
  the path, and the correlation id — the request body is not part of
  the proof. Two different bodies sent with the same method, path, and
  correlation id carry the same proof; the replay cache keys the full
  proof, so an identical proof is refused as a replay, but a different
  body under the same signature facts is accepted as a new request.
  What a body may ask stays host-side: validate the payload language in
  the handler.
- **The pairing-code budget is shared across all live sessions.** One
  wrong code attempt counts against every armed session at once — that
  is what makes a guess hostile, since the guesser cannot know which
  session it targets. The readable consequence: on a path that echoes
  preflights to arbitrary https origins (allow-all, discovery), any web
  page can send five wrong codes and exhaust the budget of the code
  currently displayed on the screen, so the legitimate user reads `429
  pair_budget_exceeded` until that session expires (its 120-second
  life). Pairing is a mobile-host control, not a defense against a
  hostile page the origin policy already admits.
- **`POST /pair` answers a CORS echo for any origin.** The pairing door
  is deliberately readable — the code is the gate, not the origin — so
  the reply echoes `Access-Control-Allow-Origin` whatever origin asks.
  Any web page can therefore probe the door and learn whether pairing
  is armed on this port: a small fingerprint, and one more reason a
  host disarms pairing when no page needs it.
- **Channel commands always carry a generated correlation id.** A
  WebSocket cannot carry `X-Correlation-Id` headers, so the bridge
  generates a fresh id for every command delivered over the channel.
  Consequence: `idempotentCommand` — keyed by source and correlation id
  — can never recognize a channel repeat; a page re-sending the same
  command over the channel presents a new id every time and the ledger
  replays nothing. Exactly-once over the channel needs the page's own
  discipline; the ledger covers the HTTP path, where the page sends the
  header itself.
- **Originless token clients share one ledger source.** A command
  without an `Origin` header carries the source marker `unknown-origin`,
  and the dedup ledger keys on (source, correlation id). Two different
  local programs sending tokens without an origin therefore share one
  key space: the same correlation id from both makes one's registered
  command or stored reply the other's duplicate verdict. Local CLI
  clients should generate unique correlation ids — or send distinct
  origins — whenever a dedup ledger is wired.

### Availability

What the bridge guards now:

- **Seats are one bounded budget.** `maxConcurrentRequests` (default 16)
  bounds requests in flight; seats and orphaned handlers count as one
  live-work budget and above it new commands get `503 server_busy`.
  Inside that budget one sender cannot monopolize it:
  `maxSeatsPerOrigin` (default 4) bounds the seats a single origin
  holds at once — requests without an `Origin` share one originless
  bucket under the same cap, an `OPTIONS` preflight counts into its
  origin's share, and past the share the sender reads `503
  origin_seat_limit` while the server still has room for others.
  The total request deadline (`requestTimeout`, 30 s default) bounds
  the pre-handler phase — the gates, the policy checks, and the body
  read — so no pre-handler seat outlives it; a handler without a
  budget holds its seat until it completes.
- **Early rejections cannot pin seats.** Every pre-body rejection (405,
  the origin and token policy rejects, 415, the parser's 400) replies
  and cuts the connection, draining the unread body under bounded
  patience in a background that holds no seat — a flood of malformed
  requests cannot keep seats occupied.
- **Per-origin bookkeeping is capped.** The per-origin token-miss and
  quota maps are each held to an internal 10,000-entry cap — oldest
  evicted, the request being processed never evicted — so origin
  rotation cannot grow the bridge's bookkeeping without bound; the
  worst case is the cap, not the flood.

What remains:

- **An allow-all flood rotating origins can still fill the global
  seats.** The per-origin seat cap (`maxSeatsPerOrigin`, 4 by default)
  bounds each sender's share, and the listed quota (120/minute by
  default, `0` the explicit opt-out) bounds each listed origin's rate —
  but a flood rotating across four or more distinct origin buckets can
  still occupy all sixteen seats, answering every further sender `503`.
  The cap bounds one sender's share, never the sum of senders; set
  `handlerTimeout` so a slow handler frees its seat early with a
  reconcilable `504 handler_timeout` - without one a slow handler
  holds its seat until it completes.
- **Peak memory under origin rotation is bounded by the caps** — the
  two 10,000-entry maps plus `dart:io`'s own per-connection buffers,
  which the package does not bound.
- **`dart:io` sets no limit on a single header's length.** The package
  caps the headers it reads (`Origin` over 1,024 characters,
  `X-Bridge-Token` over 1,024 bytes); the seats bound requests in
  flight, and idle connections close after `idleTimeout` (60 s
  default). The count of open connections is unbounded by `dart:io`
  itself — a host that wants a hard ceiling sets
  `BridgeConfig.maxOpenConnections` above zero, and a request arriving
  over the cap answers `503` until the count drops; `0` (the default)
  keeps the option off. On the TLS door the count includes the feed's
  in-flight handshakes, an accept over the cap cuts the new socket
  before arming it (the one cut that reaches the wire), and while the
  option is off the TLS transport still holds an internal
  64-handshake ceiling — a handshake stuck past arming is the one
  socket the server can never free by itself, so it gets the tighter
  ceiling.
- **A TLS client that completes its first record and then goes silent
  holds a socket until the peer closes it — what the package does not
  build, stated plainly.** The TLS gate bounds the path up to the
  first record: a non-handshake first byte and an over-cap declared
  length are cut at once, a silent client and a slow drip are cut at
  `BridgeConfig.tlsFirstRecordTimeout`, and every such cut lands while
  the socket is unarmed — the one state where the cut reaches the
  wire. Once the first record completes, the TLS engine is armed, and
  from that moment dart:io offers no handshake deadline and no kill
  that reaches the wire: `destroy` and `close` on the server side do
  not reach such a peer, a forced `stop` cannot reap it, and the
  package does not pretend otherwise. Such a client holds one
  in-flight handshake slot until it closes on its own; the bound on
  how many slots it can hold is the ceiling — the feed counts its
  in-flight handshakes into `maxOpenConnections`, holds an internal
  64-handshake ceiling while that option is off, cuts any socket that
  would push the total past the cap before arming it, and `stop`
  announces in one line how many handshakes were left stuck past
  arming (written only when the count is above zero). The tallies are
  visible in `server.counters`: handshakes in flight, sockets cut on
  the wire, and handshakes delivered.

## Recommended setup for irreversible commands

A command the host cannot undo (print, pay, unlock, send) turns every
residual above into wasted material or real money, so a host that
accepts such commands through the bridge carries five disciplines on
its own side:

1. **Keep the origin policy empty and make the token the only path.**
   The empty policy (the default) rejects every origin; with the token
   layer on, the holders of the secret are the only senders, and a web
   page - whatever it forges - cannot enter at all while no consent
   callback is configured.
   **The browser-page alternative replaces step 1, not the rest:** a
   page that must send irreversible commands admits itself with an
   explicit origin list instead: `allowed` names the exact page origins
   and nothing else, and every other origin is refused before the
   handler runs. (In the discovery and allow-all modes the preflight is
   echoed for any valid https origin not yet refused, so a page on such
   an origin can send the token too — the empty-policy token setup
   above keeps no such echo.) Steps 2 to 5 below apply to this path
   unchanged. The residual of the page path: another local program can
   present a listed origin (the header is forgeable outside a browser),
   which is why the empty-policy token path above stays the default for
   senders that do not need a browser.
2. **Set `handlerTimeout`.** Without a budget a stuck handler holds its
   seat indefinitely — no deadline covers the handler phase, and the
   caller waits on a reply that may never come. A handler budget frees
   the seat early with a reconcilable `504 handler_timeout` while the
   irreversible command is being confirmed.
3. **Give the handler a closed list of commands and refuse everything
   else.** The bridge hands opaque payloads to your handler; the allow
   list of what may run is host code, not bridge configuration.
4. **Put a human confirmation in the host UI before every irreversible
   command.** It is the one control that still works when the sender
   is a compromised page, extension, or listed origin.
5. **Keep a deduplication ledger keyed by the correlation id.** A 504
   frees the seat while the handler may still finish, so a blind retry
   can run the command twice; a ledger that registers before the work
   and replays the stored reply makes the repeat harmless. The package
   ships that ledger as surface - `DedupLedger` with `idempotentCommand`;
   `example/idempotent_handler.dart` is the wiring demo.
   A full ledger refuses new commands with `ledger_full` instead of
   evicting a live entry - size its cap above your realistic command
   rate.

## Attack → control → witness

Every control is pinned by a test that names the attack. The index below
maps every known attack this package defends against to the test or
tests that guard it (all in `test/`); broader randomized corpora remain
on the roadmap. The names are the tests' real names.

| Attack | Control | Witness test(s) |
|---|---|---|
| Origin rotation flooding the per-origin bookkeeping | Per-origin maps held to an internal 10,000-entry cap, oldest evicted, the request being processed never evicted | `the token-miss map is hard-capped: the oldest-inserted window is evicted by the flood` · `the origin quota map is hard-capped: the oldest-inserted window is evicted by the flood` · `during an eviction flood a fixed origin still locks: five misses then the sixth answers 429` (`window_map_cap_test`) |
| Origin rotation walking past a per-origin quota (documented residual) | Per-origin quota with honest `429`, rotation stated as residual | `per-origin quota exceeded: 429, another origin passes same moment` (`hardened_open_test`) · `unlisted origin with correct token: accepted whatever the guessing history, another passes` (`priority_contract_test`) |
| Hidden HTML form / `no-cors` fetch / navigation send | `Sec-Fetch` request-shape checks on every browser path, listed included | `navigate and no-cors fetch modes rejected: 403 cross_site_blocked` (`hardened_open_test`) · `a navigate send from a listed origin answers 403 cross_site_blocked and never reaches the handler` · `a no-cors send from a listed origin answers 403 cross_site_blocked` · `a document fetch destination from a listed origin answers 403 cross_site_blocked even with mode cors` · `a real hidden-form send (text/plain wire shape) from a listed origin is blocked before the handler` (`listed_fetch_metadata_test`) |
| Form-encoded body smuggling | Content-Type gate (415) | `hidden-form content types are refused while the textual gateway passes` (`wire_contract_test`) |
| Malformed `Origin` shapes (userinfo, path, query, control characters) | Shape gate answers `400 origin_malformed` before any map, log, consent question, or echo | `a userinfo origin answers 400 origin_malformed with the handler, the consent callback, the rejection counter, and its log untouched` · `path, query, space, and control-character origins each answer 400 origin_malformed and no consent question fires` · `the consent callback receives the normalized origin: lowercase scheme and host, port kept` (`origin_malformed_test`) |
| Oversized `Origin` header | 1,024-character cap, `400 origin_too_long` first | `an Origin one char over the cap answers 400 origin_too_long with the handler and the consent callback never invoked` (`origin_cap_test`) · `the length gate precedes the shape gate: an Origin both oversized and malformed answers origin_too_long` (`origin_malformed_test`) · `the length gate precedes the single-header gate: a duplicated oversized Origin answers origin_too_long, not duplicate_header` (`origin_cap_test`) · `a 64 KiB slash-padded Origin is answered inside the usual test response timeout, then the next normal request is served` (`wire_contract_test`) |
| Oversized token header | 1,024-byte cap, `400 token_too_long`, no miss window left behind | `a 1,025-byte token answers 400 token_too_long with the handler, the rejection counter, its log, and CORS untouched` · `five oversized tokens leave no miss window behind: the correct token right after them is served, not locked` · `the Origin gates settle first: an oversized token with a malformed Origin answers origin_malformed` (`token_length_cap_test`) |
| Timing side channel on the token comparison | Constant-time padded comparison over `max(256, secret length)` | `comparison semantics hold for generated lengths: correct passes, and wrong at the first byte, the last byte, past the secret, and below the secret all fail` (`token_length_cap_test`) · `lengths 32/255/256/257: correct accepted, wrong rejected at each` (`priority_contract_test`) |
| Token brute force and budget edges | 5 wrong-token attempts / 60 s → further wrong tokens answer `429 token_locked` with the honest remaining window; the correct token is always accepted | `Retry-After says the real lockout window, not a generic constant` (`wire_contract_test`) · `window edges on the injected clock: the sixth miss locks, 60001ms unlocks` · `no-origin and web-origin misses keep two independent windows` · `unlisted origin with correct token: accepted whatever the guessing history, another passes` (`priority_contract_test`) · `after any number of wrong tokens from any sender, the correct token is accepted in the next request` (`token_guess_budget_test`) |
| Pairing-code guessing (a hostile page probing the displayed code) | Six-digit one-time code, 120 s life, 5 wrong attempts per pairing session → `429 pair_budget_exceeded` with the session's honest remainder; the budget is per session, never per origin | `code guessing is budget-bound: five wrong attempts per pairing session, then 429 with the honest remaining session wait` (`pairing_test`) · `a wrong code on the wire answers 403 pair_code_invalid - readable, counted, and the honest budget follows` (`pairing_route_test`) · `pair_budget_exceeded` and `pair_code_expired` and `pair_code_invalid` walk scenarios (`intake_rejection_registry_test`) |
| Stolen pairing credential replayed (a captured signature resent) | One-minute stamp-skew window plus a capped replay cache (4,096 entries, 120 s, oldest evicted) keyed on the full proof → the same proof never proves twice: `403 pair_signature_replay`; outside the skew refuses the same way, so a cache flood opens no replay window - and two different commands signed within the same millisecond never collide | `a replayed signature is refused pair_signature_replay: the same proof never proves twice` · `two different proofs stamped at the same millisecond both pass…` · `a stale signature (outside the skew window) is refused as a replay…` · `the replay cache is capped at 4,096 entries: a stamp flood never opens a replay window` (`pairing_signature_test`) · the browser reads the refusal: `the paired page pairs with the displayed code…` (`browser_lab_test`) |
| Forged origin under the origin+token requirement (a local program presenting a listed origin) | `OriginPolicy.requireOriginWithToken` makes the token a requirement on the qualified origin; a paired origin cannot be transplanted (the signature binds the origin) and an unqualified origin never learns whether its token was valid | `requireOriginWithToken: a qualified origin without the token is refused token_required` · `requireOriginWithToken: the correct token from another origin is refused by the origin rejection alone - no token oracle for unqualified origins` (`origin_token_policy_test`) · `a signature keyed by another origin token is refused by the origin rejection…` (`pairing_signature_test`) · the browser and the forged-origin wire send in `the paired page pairs with the displayed code…` (`browser_lab_test`) |
| Guessable or short configured token | 32-byte floor at `update()`, saved short token inert at boot, empty token disables the layer | the `short token refusal: configuration error, inert at boot` group with `update() throws for a token below 32 bytes instead of warning` · `the short-token error names the length, never the token itself` (`intake_protection_test`) · `empty configured token: the header layer is fully disabled` (`priority_contract_test`) |
| JSON amplification (small body, huge parse) | Structural-element and depth count before decode, `413 payload_too_complex` | `a 1MiB body of empty JSON elements is rejected with 413 payload_too_complex before parsing` · `braces and commas inside JSON strings are not counted as elements` (`intake_limits_test`) · `json amplification: 16 concurrent 1MiB bodies of empty objects stay under a declared ceiling` (`resources_test`) · `a real nested 1MB body over the live wire leaves the server alive` (`wire_contract_test`) · `deep nesting under the element cap is refused before decode` (`intake_health_test`) |
| Body flood / memory growth | Byte cap with early refusal, bounded buffers | `300 consecutive 413 rejections: RSS stays stable` (`hardened_open_test`) · `body resources: 15 chunked rejections over the cap plus 15 accepts at the cap — RSS never escapes` (`resources_test`) |
| Seat starvation by early rejections | Every pre-body rejection replies and cuts, draining in a background that holds no seat | `sixteen early-rejected connections with an unfinished body cannot starve the next legitimate request` · `every attacker connection is closed after the request timeout with margin, and the next request is served` (`early_reject_cut_test`) · `above the concurrent request cap: 503 comes immediately without waiting` (`intake_limits_test`) |
| Stuck handler pinning seats | `handlerTimeout` frees the seat with a reconcilable 504; without it the handler holds its seat - the documented hold | `a null handler budget lets a handler run past the request timeout and answer 200 - the total deadline never reaches the handler phase` · `a handler budget longer than the request timeout answers 504 at its own deadline and counts the handler as an orphan` · `sixteen handlers without a handler budget hold their seats past the request timeout - the seventeenth request is refused 503 server_busy` (`handler_deadline_contract_test`) · `handler exceeds handlerTimeout: 504 handler_timeout, seat freed, late ignored` · `orphan handlers count against the live-work budget: the 17th request is refused before any new handler` (`intake_health_test`) |
| Replay after `504 handler_timeout` | Reconcile on `X-Correlation-Id`; the reference ledger registers before the work runs | `the same command twice: the second send after an artificial 504 replays the stored reply and the work ran once` · `a duplicate racing the first execution is refused while it runs, then replayed once the first settles` · `a flood of fresh ids cannot evict a running command: the repeat sees duplicate_in_flight and the work stays one execution` (`idempotent_handler_test`) |
| Log-line injection via control characters or oversized origins | Sanitize and truncate to 200 characters before any log or measurement context | `logged Origin is stripped of control characters and capped` (`intake_protection_test`) · `strips control characters (BEL, ESC) before it truncates` · `caps a 1,024-character value at exactly 200 characters` · `an Origin carrying BEL and ESC control characters is refused 400 origin_malformed before any measurement context captures it` (`origin_telemetry_sanitized_test`) · `no rejection line and no telemetry context carries an Origin longer than the cap` (`origin_cap_test`) |
| Raw disclosure through telemetry contexts | Sanitized origin only; correlation id replaced, only its length logged | `a long well-formed Origin reaches the measurement context truncated to exactly 200 characters` · `an ordinary short Origin reaches the measurement context exactly as sent` (`origin_telemetry_sanitized_test`) · `correlation id: valid is honored — invalid replaced, only its length logged` (`priority_contract_test`) · `the seam carries level, category, error, stack, and context without loss` (`telemetry_seam_test`) |
| Parser destruction (`Content-Length` + `Transfer-Encoding`, lying chunk sizes) | Parser errors answer `400 bad_request` and cut the connection | `a request carrying Content-Length together with Transfer-Encoding answers 400 bad_request with the handler, the security counter, and the crash log untouched` · `an invalid chunk-size line mid-body is answered 400 bad_request the same way` · `the next request on a fresh connection is served after a parser-error reject` (`parser_error_test`) |
| Disconnect-on-rejection semantics (readable vs unreadable) | Policy rejects cut after the reply; consent and quota rejections stay CORS-readable by design | `protocol rejections cut the connection after the reply` · `an origin_pending reply is readable while the body still arrives, then the connection cuts` · `a rate-limited listed origin reply is readable with an unread body, then the connection cuts` (`early_reject_cut_test`) · `origin_rate_limited 429 echoes CORS: the page reads the code and Retry-After` · `token_locked 429 echoes CORS: the page reads the code and Retry-After` (`hardened_open_test`) |
| Port exhaustion and bind races | Explicit `IntakeBindException`, fallback ports | `all ports busy: IntakeBindException — a plain Exception, never an Error` (`intake_health_test`) · `falls back when preferred port is busy` (`intake_payload_test`) |
| DNS rebinding / forged `Host` | Host-authority allowlist, absolute-form refusal, explicit opt-out warnings | `replays 14 corpus cases over the wire across 3 protection modes and writes the comparison output` (cases `12_host_evil`, `13_absolute_form`) (`wire_contract_test`) · `a loopback-resolving public name warns; literal loopback stays silent` · `a public extraHost name warns about the rebinding opt-out` · `every non-loopback extraHosts entry warns - dotless names and non-loopback IPv6 included` (`intake_health_test`) |
| Duplicate-header smuggling | `400 duplicate_header` | `duplicate X-Correlation-Id: 400 duplicate_header, connection closed, zone clean` · `repeated Origin or X-Bridge-Token, even identical values: 400 duplicate_header` (`intake_health_test`) · `400 duplicate header with ACAO for listed origins — stranger gets none` (`priority_contract_test`) |
| Consent-question flooding | 3 open windows, a 10-per-10-minutes ask budget, honest `Retry-After` | `question-budget Retry-After tells the honest multi-minute wait` (`wire_contract_test`) · `a throwing consent callback consumes the question budget` · `a late answer for an open question survives a thousand abandoned windows` (`intake_protection_test`) |
| Slowloris / body drip | Absolute body deadline, `408`, trickling senders never hold a gate | `a request stalling mid-body is answered with 408 within the timeout` · `a chunked body completing after the deadline is rejected 408, handler untouched` · `a drip under the silence window is cut by the absolute deadline before 1.25x of it` (`intake_limits_test`) · `413 drain cut on time: a trickling sender never holds the gate` (`wire_contract_test`) |
| 413 drain abuse | Bounded drain budget, cut past it | `413 drain is bounded: past four bodies the connection is cut` · `413 drain cut on the byte-counter path: a chunked body with no Content-Length past the cap` · `both 413 responses name the 1 MiB limit, never 0MB` (`wire_contract_test`) |
| Handler crash information leak | Fixed `500` body; host error text only for trusted senders | `a handler crash still answers 500 internal - the internal-error path is unchanged` (`parser_error_test`) · `safety net: escaped exception returns 500 internal, server stays alive` (`intake_health_test`) · `host failure detail hidden from unapproved origin, shown to trusted one` (`hardened_open_test`) · `a wrong token never earns the host message even over a spent budget; the verified token does` (`priority_contract_test`) |
| Reading replies cross-origin | CORS echo for the admitted only | `no ACAO for unlisted origin; listed and allow-all echo theirs` · `token-only host: a preflight from any origin carries no ACAO` (`hardened_open_test`) · `CORS echo of 503 and 400 for listed origins — rejects stay echoless` · `declined discovery origins (origin_declined) see no ACAO` (`priority_contract_test`) |
| Warning-line flooding (log spam) | Every warning throttled to one line per second with the muted count | `a thousand busy rejects within one injected second write exactly one warning line, and the next second writes a line carrying the muted count` · `a thousand orphan-busy rejects within one injected second write exactly one warning line, and the next second writes a line carrying the muted count` · `a thousand handler timeouts within one injected second write exactly one warning line, and the next second writes a line carrying the muted count` · `a thousand total-deadline cuts within one injected second write exactly one warning line, and the next second writes a line carrying the muted count` (`throttled_warnings_test`) · `correlation-id warning throttle on the injected clock: per-second cap, suppressed count reported` (`priority_contract_test`) |
| Non-root path abuse | Wire unchanged, throttled warning only | `a POST on /x is still served 200 with the handler invoked - the wire behavior does not change` · `a thousand POSTs to /x within one injected second write exactly one warning line, and the next second writes a line carrying the muted count` · `an OPTIONS preflight on /x answers 204 and writes no path warning - only the command method warns` · `a bloated request path is capped inside the warning line` (`reserved_path_warning_test`) |
| Policy-change TOCTOU | Policy generation seals updates; late answers under a stale policy are void | `updateFromSaved: removed open mode denies with a warning` · `a policy change revokes grants but keeps the denials` (`intake_protection_test`) · `policy generation seals the updateFromSaved TOCTOU bypass` · `late answer under a stale policy is void after update` (`priority_contract_test`) |
| Bookkeeping growth inside `ArrivalGuard` | Per-minute queue caps plus one | `a hundred thousand decide calls in one window keep every verdict identical and hold the fingerprint queue at the per-minute limit plus one` · `an arrival judged flood still extends the flood state after the cap, and the state still expires exactly with its window` (`arrival_queue_cap_test`) · `map cap 500: idle fingerprints are evicted` · `window 60_000: stamps outside it are pruned` (`arrival_guard_test`) |
| Double start / use after dispose | `StateError` on double start; dispose final on every path | `second start rejects with StateError, first server stays alive` (`intake_health_test`) · `dispose is final on every path: listed and token flows stop too` · `full idleness after dispose: no prompt, no timer, no answer effect` (`priority_contract_test`) |
| Silent sends from browsers without Fetch Metadata | `requireFetchMetadata` on by default | `missing Sec-Fetch headers: rejected by default, pass with requireFetchMetadata off` (`hardened_open_test`) · `with requireFetchMetadata off the listed path still blocks a wrong value and still serves absence` (`listed_fetch_metadata_test`) · `fetch metadata: navigate, no-cors, and absent headers rejected — cors alone passes` (`intake_protection_test`) |

## Binding and deployment notes

- Bind stays `InternetAddress.loopbackIPv4`; the package never binds
  `0.0.0.0`/`anyIPv4` and exposes no IPv6 listener. If a host ever adds
  one, `[::1]:port` must join the authority set in the same change.
- The package stays dependency-free. The one process it ever spawns is
  the system `/bin/chmod` at its full path, run only when the optional
  unix-socket listener is armed (Linux and macOS) and only on that
  socket's own path, to enforce the file's owner-only permissions;
  payload semantics (including command allowlists) are the host's
  responsibility, demonstrated in `example/main.dart`.
