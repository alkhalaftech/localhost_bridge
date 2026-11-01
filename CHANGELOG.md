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
  extends the shape checks to headerless requests.
- Content types: POST bodies must carry `application/json` or `text/plain`
  (`BridgeConfig.allowedContentTypes`); hidden-HTML-form types are refused
  with `415 unsupported_media_type`. The browser-facing form defense is
  the fetch-mode hardening (`Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest:
  empty`) — the content-type gate raises the floor for non-browser
  clients, and `OriginPolicy.requireFetchMetadata` extends the shape
  checks to headerless requests from legacy browsers.
- Configuration honesty: `update()` changes only what you pass — updating
  the policy keeps the token, updating the token keeps the policy.
  Remembered consent answers are cleared only when the origin policy
  actually changes. A rejected token never appears in error messages.
  Stable error codes throughout; `SECURITY.md` documents the threat
  model, the residuals, and how to report a vulnerability.
