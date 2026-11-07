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
