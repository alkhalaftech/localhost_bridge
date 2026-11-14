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
- **Token guessing** — 32-byte length floor for a configured token
  (`update()` throws on shorter; the bound measures length, not entropy —
  `generatePortalToken` is the recommended source of a token),
  constant-time padded comparison, and a per-origin lockout (5 misses /
  60 s → `429 token_locked`) whose `Retry-After` states the real
  remaining window. The lockout stops pages: a local sender can rotate
  `Origin` values to walk past it — the barrier ahead of that path is
  the token's randomness itself. Nor does the lockout stop a page on the
  allow-all or discovery paths: a site can rotate subdomains, and each
  rotated origin opens its own window. The residual that remains: a
  local sender can keep originless token clients locked out with five
  wrong tokens per minute in the shared originless window.
- **Resource exhaustion** — body byte cap with early `Content-Length`
  refusal, JSON structural-element cap before decoding, concurrency seat
  cap with `503`, per-request and idle timeouts, per-origin rate quota,
  an internal `Origin` length cap (`400 origin_too_long` — a value over
  1,024 characters is refused before any map, log line, consent question,
  handler, or telemetry context reads it), and bounded bookkeeping under
  web-page flood: the per-origin failure and quota maps sweep their idle
  entries once their window expires even below the map cap, so a
  same-session local program forging many distinct `Origin` values no
  longer pins expired entries until the cap is crossed (what remains is
  inside the trust boundary those maps defend against anyway).
- **Header smuggling ambiguity** — duplicate `Origin`, `X-Portal-Token`,
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
  barrier there at all, and the token layer is the practical barrier,
  with the same caveat as above: it holds only while no origin path
  admits without the secret. The in-app server runs while the host app is
  foregrounded or behind a foreground service; backgrounded without one,
  the system may stop it. And on Android 17, loopback traffic between two
  profiles (work and personal) is blocked by default for every app
  regardless of targetSdk; loopback within one profile is unaffected.
  On Android, any installed app can reach the port and send any `Origin`, so the token is the real barrier there. Native clients on the device send the token. In this release a browser page cannot present the token: it is admitted through a listed origin or user consent, and another installed app can present the same origin. On
  iOS there is no path from a browser at all: Safari, and iOS browsers
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
- **A stuck handler with no `handlerTimeout`.** The default (null) sets no
  deadline: a stuck handler holds its seat indefinitely, sixteen stuck
  handlers stop the service, and `stop()` waits for them — set
  `handlerTimeout`; the full remedy (a bounded `stop()` and a default
  budget) is planned for a later release.
- **Host-side process-identity decisions.** The bridge never identifies
  peers; a host that decides to kill or trust a local process by image
  name (e.g. a `tasklist` prefix match) is forgable by any process that
  picks the same name. Identity needs a full path plus a digital
  signature check — a host responsibility, not a bridge one.

## Recommended setup for irreversible commands

A command the host cannot undo (print, pay, unlock, send) turns every
residual above into wasted material or real money, so a host that
accepts such commands through the bridge carries five disciplines on
its own side:

1. **Keep the origin policy empty and make the token the only path.**
   The empty policy (the default) rejects every origin; with the token
   layer on, the holders of the secret are the only senders, and a web
   page - whatever it forges - cannot enter at all.
   **The browser-page alternative replaces step 1, not the rest:** in
   this release a browser page cannot use the token path - the CORS
   preflight that would let a page send `X-Portal-Token` is answered
   only for origins the origin policy admits - so a page that must send
   irreversible commands admits itself with an explicit origin list
   instead: `allowed` names the exact page origins and nothing else,
   and every other origin is refused before the handler runs. Steps 2
   to 5 below apply to this path unchanged. The residual of the page
   path: another local program can present a listed origin (the header
   is forgeable outside a browser), which is why the empty-policy token
   path above stays the default for senders that do not need a browser.
2. **Set `handlerTimeout`.** Without it a stuck handler holds its seat
   indefinitely; a bounded budget keeps the service responsive while
   the irreversible command is being confirmed.
3. **Give the handler a closed list of commands and refuse everything
   else.** The bridge hands opaque payloads to your handler; the allow
   list of what may run is host code, not bridge configuration.
4. **Put a human confirmation in the host UI before every irreversible
   command.** It is the one control that still works when the sender
   is a compromised page, extension, or listed origin.
5. **Keep a deduplication ledger keyed by the correlation id.** A 504
   frees the seat while the handler may still finish, so a blind retry
   can run the command twice; a ledger that registers before the work
   and replays the stored reply makes the repeat harmless.
   `example/idempotent_handler.dart` is that ledger, ready to adapt.
   A full ledger refuses new commands with `ledger_full` instead of
   evicting a live entry - size its cap above your realistic command
   rate.

## Attack → control → witness

Every control is pinned by a test that names the attack. Representative
witnesses (all in `test/`):

| Attack | Control | Witness test |
|---|---|---|
| Rebound DNS name reaching the port | Host authority allowlist, absolute-form refusal | `replays 14 corpus cases over the wire…` (cases `12_host_evil`, `13_absolute_form`) |
| Hidden HTML form / `no-cors` fetch / navigation send | `Sec-Fetch` request-shape checks | `navigate and no-cors fetch modes rejected: 403 cross_site_blocked` |
| Form-encoded body smuggling | Content-Type gate (415) | `hidden-form content types are refused while the textual gateway passes` |
| Token guessing from a page | Constant-time compare + per-origin lockout with honest `Retry-After` | `Retry-After says the real lockout window, not a generic constant` |
| Guessable configured token | 32-byte length floor at `update()`, inert saved short token at boot | `short token refusal: configuration error, inert at boot` |
| Consent-question flooding | Ask caps + time budget with honest `Retry-After` | `question-budget Retry-After tells the honest multi-minute wait` |
| Duplicate-header smuggling | 400 `duplicate_header` | `400 duplicate header with ACAO for listed origins — stranger gets none` |
| Body flood / memory growth | Byte cap + early refusal + bounded buffers | `300 consecutive 413 rejections: RSS stays stable` |
| Deep-JSON inflation | Structural element cap before decode | `a 1MiB body of empty JSON elements is rejected with 413 …` |
| Reading replies cross-origin | CORS echo for the admitted only | `CORS echo of 503 and 400 for listed origins — rejects stay echoless` |

## Binding and deployment notes

- Bind stays `InternetAddress.loopbackIPv4`; the package never binds
  `0.0.0.0`/`anyIPv4` and exposes no IPv6 listener. If a host ever adds
  one, `[::1]:port` must join the authority set in the same change.
- No TLS by design: on the browser path over loopback, a self-signed
  certificate trains users to click through warnings and buys nothing
  against the browser adversary model above (see `README.md`).
- The package never spawns processes and stays dependency-free; payload
  semantics (including command allowlists) are the host's
  responsibility, demonstrated in `example/main.dart`.
