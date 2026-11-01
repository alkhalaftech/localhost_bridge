# Security Policy — localhost_bridge

## Reporting a vulnerability

Report privately to the maintainer through the channel listed in
`pubspec.yaml` (`repository` → Security Advisories / a private issue).
Note: the package is not published yet (`publish_to: none`) and its
`repository` field is a placeholder until the single hosting repository is
finalized — until then, reach the maintainer through the security contact
of the product this bridge ships in. Do not open a public issue for a
suspected vulnerability. Include the package version, a minimal
reproduction, and the affected surface (intake server, protection policy,
token layer, or the example apps).

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
- **Token guessing** — 32-byte floor for a configured token (`update()`
  throws on shorter), constant-time padded comparison, and a per-origin
  lockout (5 misses / 60 s → `429 token_locked`) whose `Retry-After`
  states the real remaining window.
- **Resource exhaustion** — body byte cap with early `Content-Length`
  refusal, JSON structural-element cap before decoding, concurrency seat
  cap with `503`, per-request and idle timeouts, per-origin rate quota,
  and bounded bookkeeping under web-page flood (a same-session local
  program forging many distinct `Origin` values can grow the per-origin
  failure and quota maps past the idle-sweep cap — it is inside the trust
  boundary those maps defend against anyway).
- **Header smuggling ambiguity** — duplicate `Origin`, `X-Portal-Token`,
  or `X-Correlation-Id` headers are refused (`400 duplicate_header`).
- **Information disclosure** — rejected origins get no CORS echo at all;
  host error text is visible only to authorized origins; internal errors
  return a fixed body; secrets never reach the command handler.

### What the bridge does NOT protect against

These are stated plainly so no host builds on a false assumption:

- **Programs running in the same user session.** Loopback TCP has no peer
  authentication: any local process can open `127.0.0.1:port` and write
  `Origin: https://your-portal` verbatim. On Windows, a same-session
  process can also unprotect DPAPI-stored tokens. The token layer raises
  the cost from "know a public string" to "hold a secret" — and only while
  no origin path accepts: with a non-empty allowlist, allow-all, or a
  remembered consent, that forged listed origin enters without the secret.
- **Administrator/SYSTEM-level malware.** It can inject into the host
  process, read the token from memory, or print directly through the OS
  spooler without this bridge entirely.
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
- **Host-side process-identity decisions.** The bridge never identifies
  peers; a host that decides to kill or trust a local process by image
  name (e.g. a `tasklist` prefix match) is forgable by any process that
  picks the same name. Identity needs a full path plus a digital
  signature check — a host responsibility, not a bridge one.

## Attack → control → witness

Every control is pinned by a test that names the attack. Representative
witnesses (all in `test/`):

| Attack | Control | Witness test |
|---|---|---|
| Rebound DNS name reaching the port | Host authority allowlist, absolute-form refusal | `replays 14 corpus cases over the wire…` (cases `12_host_evil`, `13_absolute_form`) |
| Hidden HTML form / `no-cors` fetch / navigation send | `Sec-Fetch` request-shape checks | `navigate and no-cors fetch modes rejected: 403 cross_site_blocked` |
| Form-encoded body smuggling | Content-Type gate (415) | `hidden-form content types are refused while the textual gateway passes` |
| Token guessing from a page | Constant-time compare + per-origin lockout with honest `Retry-After` | `Retry-After says the real lockout window, not a generic constant` |
| Guessable configured token | 32-byte floor at `update()`, inert saved short token at boot | `short token refusal: configuration error, inert at boot` |
| Consent-question flooding | Ask caps + time budget with honest `Retry-After` | `question-budget Retry-After tells the honest multi-minute wait` |
| Duplicate-header smuggling | 400 `duplicate_header` | `400 duplicate header with ACAO for listed origins — stranger gets none` |
| Body flood / memory growth | Byte cap + early refusal + bounded buffers | `300 consecutive 413 rejections: RSS stays stable` |
| Deep-JSON inflation | Structural element cap before decode | `a 1MiB body of empty JSON elements is rejected with 413 …` |
| Reading replies cross-origin | CORS echo for the admitted only | `CORS echo of 503 and 400 for listed origins — rejects stay echoless` |

## Binding and deployment notes

- Bind stays `InternetAddress.loopbackIPv4`; the package never binds
  `0.0.0.0`/`anyIPv4` and exposes no IPv6 listener. If a host ever adds
  one, `[::1]:port` must join the authority set in the same change.
- No TLS by design: a self-signed certificate on loopback trains users to
  click through warnings and buys nothing against the browser adversary
  model above (see `README.md`).
- The package never spawns processes and stays dependency-free; payload
  semantics (including printer-command allowlists) are the host's
  responsibility, demonstrated in `example/main.dart`.
