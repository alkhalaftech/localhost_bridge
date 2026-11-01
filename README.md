# localhost_bridge

A localhost HTTP bridge that lets web pages deliver origin-trusted
commands to a local Dart app — CORS-ready, hardened origin policies,
first-use consent, token layer, strict limits.

Your Dart app runs an HTTP server on `127.0.0.1` (never exposed to the
network). A web page the user visits sends commands to it directly from
the browser. The bridge decides **who may talk** and **how much**; what
the commands *mean* stays entirely in your handler.

- **Zero runtime dependencies** — pure `dart:io`, one package, no native code.
- Every rejection carries a stable error `code` — the developer contract.

## Quick start

```dart
import 'dart:io';
import 'dart:math';
import 'package:localhost_bridge/localhost_bridge.dart';

void main() async {
  final server = LocalIntakeServer(
    // Required: your command handler — the bridge is payload-agnostic.
    onCommand: (cmd) async {
      print('from ${cmd.source}: ${cmd.payloads}');
      return const CommandOutcome(ok: true);
    },
    // Required: your telemetry sink (use const SilentTelemetry() to start).
    telemetry: const SilentTelemetry(),
    // Required: correlation ids — any unique string per request. A
    // Random.secure-based UUID-v4-style generator lives in example/main.dart.
    correlationIdGenerator: () =>
        '${DateTime.now().microsecondsSinceEpoch.toRadixString(16)}'
        '-${Random.secure().nextInt(1 << 32).toRadixString(36)}',
    protection: IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example.com', '*.partner.io'],
        ),
        // Optional token layer for non-browser integrations only — the
        // token must be persisted and shared out-of-band (the quick start
        // omits it; see the token layer bullet below).
      ),
  );

  final port = await server.start(preferredPort: 9100);
  print('listening on http://127.0.0.1:$port');
}
```

The page side is a plain `fetch('http://127.0.0.1:9100/', { method: 'POST',
... })` — the server answers with CORS headers for **admitted** origins
(origin echo + `Vary: Origin`), so HTTPS pages you admitted can call and
read it; every other origin is rejected **before your handler runs** — the
request never reaches your command code, and the reply is unreadable. From
an HTTPS page, add `targetAddressSpace: 'loopback'` to the fetch options —
Chrome's Local Network Access guide asks for it, keeping the request
exempt from mixed-content blocking and checking the address space against
loopback after DNS resolution.

## Security model — read before choosing a policy

The bridge cannot know whether a site is legitimate or compromised: it
only sees the `Origin` header (set by the browser, forgeable by any local
program), the `Sec-Fetch-*` headers, and the payload.

- **Closed by default.** An empty policy rejects everything. Ship-safe.
- **Allowlist** stops unknown sites. It does **not** stop a compromised
  allowlisted site.
- **Allow-all (hardened)** accepts any valid HTTPS origin, but blocks
  hidden form posts, `no-cors`/beacon requests, sandboxed/`null` origins
  and non-HTTPS pages, and rate-limits each origin. It does **not** stop
  a malicious HTTPS site using `fetch`, nor a compromised legitimate
  site. Its name is deliberately loud; a warning is logged when active.
- **First-use consent** (`onUnknownOrigin`) asks your app once per new
  origin — the only layer that makes "a human vouched for this site"
  real. Declined origins are remembered for the session (applying a
  changed policy revokes remembered grants, not denials); once-only
  consent is not.
- **Token layer** is an independent entry path, not a gate over the other
  modes: presenting the right `X-Portal-Token` crosses without browser
  headers. It is the only mode that resists other local programs (other
  apps on the machine, other users on a shared host) — and that holds only
  while no origin path accepts: with a non-empty allowlist,
  `allowAllHardened`, or a remembered consent, a local program can present
  a listed `Origin` (the header is browser-set, locally forgeable) and
  enter without the secret.
- **In every mode, payloads are untrusted.** Your handler must validate
  them (for printers: allow-list the command set; block configuration,
  file-storage and firmware commands) and cap decompressed size.
  A body of many small JSON elements (e.g. 1 MiB of `{}`) would amplify
  into hundreds of MB of parsed objects, so the bridge counts structural
  elements (`{`, `[`, `,` outside strings) in one linear pass **before**
  decoding and rejects over `maxJsonElements` (default 10,000) with
  `413 payload_too_complex` — braces and commas inside strings count
  nothing, and raw non-JSON command text is never counted.
- **What your page sees when the user denies the Local Network Access
  prompt:** a plain network error, indistinguishable from the bridge being
  down — handle it like a connection failure, not a bridge error.

Chrome 142+ asks the user before a public page may reach `localhost` via
`fetch`; that prompt is not documented to cover top-level navigations or
form submissions, so the bridge does not rely on it — the fetch-mode
hardening above does not depend on the browser asking.

`reportOnly: true` watches the origin quota only: an over-quota request is
logged as a would-reject and still served, so you can measure a live gate
for a day before switching policies. The request-shape hardening (valid
HTTPS origin, fetch-mode checks) always rejects — watching included —
because no legitimate `fetch` caller can ever fail those checks.

## Origin policy reference

| `OriginPolicy` field | Effect |
|---|---|
| `allowed` | Exact origins (`https://host`), bare hosts (`partner.io`), and `*.example.com` (subdomains only — list the root explicitly). |
| `allowAllHardened` | Any valid HTTPS origin passes the hardening (origin, fetch-mode, per-origin quota). Loud warning on activation. |
| `allowLocalHttp` | Dev exception: accept `http://localhost` / `http://127.0.0.1` (allow-all path and bare/wildcard entries). |
| `onUnknownOrigin` | First-use consent callback (`allowAlways` / `allowOnce` / `reject` / `dismissed`). Non-blocking: the request returns `origin_pending` immediately (CORS-readable, with `Retry-After` exposed) and the page retries after the host answers; `allowOnce` grants exactly one retry within ~30s; `dismissed` closes the question with no decision — nothing is remembered and the origin is asked again on its next request. New questions carry a time budget (10 per 10 minutes) — beyond it the request still gets `origin_pending`, with no new question until stamps age out. Call `dispose()` when done to cancel pending window timers. |
| `reportOnly` | Observe-and-log for the origin quota only; request-shape checks always reject. |
| `perOriginPerMinute` | Per-origin rate budget on the allow-all path (default 30). |
| `listedPerOriginPerMinute` | Optional per-origin budget on the listed path too — 0 (the default) keeps listed origins unquotaed; a positive value bounds a compromised listed origin's flood with the same `429 origin_rate_limited`. Watch mode (`reportOnly`) covers this quota like the allow-all one, and a failed token attempt carrying a listed origin also counts against its window. |
| `requireFetchMetadata` | On by default. The allow-all and discovery paths refuse requests carrying no `Sec-Fetch-Mode: cors` / `Sec-Fetch-Dest: empty` (`cross_site_blocked`) — closing silent sends from browsers without Fetch Metadata. Headerless non-browser clients on the token layer are unaffected; turn it off only if you serve such clients through the browser paths. |
| `askTimeout` | Max lifetime of a silent consent window (default 60s); the slot frees only on answer or expiry. |

## Wire contract (what your page sees)

JSON everywhere: `POST` with `Origin`; responses carry `X-Correlation-Id` (yours echoed back when it matches `[A-Za-z0-9._-]` and is at most 128 chars; anything else is replaced with a generated id) Stable error codes:

| HTTP | `error` code | Meaning |
|---|---|---|
| 200 | — | Handler succeeded (`{"ok":true}`). |
| 400 | `duplicate_header` | A single-valued header was sent twice. |
| 400 | `invalid_utf8` / `empty_payload` / `unsupported_payload_shape` | Body not UTF-8 / no valid command payload / JSON object without any of the known command keys. A body that fails JSON decoding altogether is **not** a 400 — it falls through as a raw text command (the tested non-JSON contract). |
| 405 | `method_not_allowed` | Only `POST` (and `OPTIONS` preflight) are accepted. |
| 403 | `origin_not_listed` / `origin_declined` / `origin_unknown` / `origin_blocked` / `origin_pending` | Origin policy rejection (not listed / consent declined / not confirmable / allow-all hardening / consent window open — retry after `Retry-After`). |
| 403 | `cross_site_blocked` | Fetch-mode hardening: `Sec-Fetch-Mode` not `cors`. |
| 403 | `blocked_by_protection` | Host-authority rejection (DNS-rebinding defense). |
| 408 | `request_timeout` | Body did not arrive in time. |
| 413 | `payload_too_large` / `payload_too_complex` | Body over the byte cap (default 1 MiB) / JSON body over the element cap (default 10,000 structural elements, counted before parsing). |
| 415 | `unsupported_media_type` | POST body carries a `Content-Type` outside `BridgeConfig.allowedContentTypes` (default `application/json` and `text/plain`, which covers JSON clients and textual gateways; an absent header passes for raw-socket integrations). Hidden-HTML-form types (`application/x-www-form-urlencoded`, `multipart/form-data`) are refused. Checked after intake admission, so an untrusted origin still sees its origin rejection. Note: `text/plain` itself is a valid HTML form enctype, so it passes this gate — the browser-facing form defense is the fetch-mode hardening (`cross_site_blocked`), with `OriginPolicy.requireFetchMetadata` extending it to headerless requests. |
| 429 | `origin_rate_limited` / `token_locked` | Per-origin budget exhausted / too many failed token attempts in the last minute from this origin (originless attempts share one window; correct tokens are also refused while the window is locked). |
| 503 | `server_busy` / `protection_disposed` | Concurrency seats full (seats plus timed-out handlers still running are one live-work budget) / the protection object was disposed — create a new one. |
| 504 | `handler_timeout` | Your handler exceeded `handlerTimeout`; the seat is freed and the late result ignored. **The command may still have run** — treat 504 as "outcome unknown", not "not executed": a blind retry can double-execute. Deduplicate on `X-Correlation-Id` before retrying. |
| 500 | `internal` / your code / `command_failed` | Handler failure; `command_failed` is the fallback code when your handler fails without one (set `BridgeConfig.fallbackErrorCode` to keep an existing wire contract). Host error *text* is echoed only to trusted origins; everyone gets the code. |

Bodies arrive as an array of strings, a bare string, or
`{"data": [...]}` / `{"payload": ...}` / `{"commands": [...]}` wrappers
(`BridgeConfig.payloadWrapperKeys` — add your domain's key there if your
gateways use one). Compressed payloads are delivered as-is —
decompression is the host's responsibility, by design.

## Limits (by design)

- Loopback IPv4 only (`127.0.0.1`); no IPv6 binding in this release.
- JSON nesting is capped in the same pre-decode pass (`maxJsonDepth`,
  default 32) — deeper bodies get the same `413 payload_too_complex`
  before `jsonDecode` runs.
- If you pass fallback ports to `start()`, the page must use the port
  `start()` returns — never assume the preferred one (a same-session
  program may hold it).
- `BridgeConfig.extraHosts` adds host authorities the server answers for
  (a bare name matches `name:boundPort` too, like the built-ins). Every
  entry must be a name you control that resolves to this machine — a
  non-loopback name there (public DNS or private-network alike) is your
  explicit opt-out of the DNS-rebinding guard for that name, and startup
  says so once in the log.
- Caps and timeouts are validated when the server is built: a non-positive
  `BridgeConfig` value or timeout override throws `ArgumentError` instead of
  silently rejecting every request.
- No payload interpretation, no identity, no device binding, no
  persistence — the bridge carries bytes and judgements, nothing else.
- Local-network-access permission prompts differ across browsers; the
  fetch-mode layer does not depend on them.
- Hostile-wire behavior is pinned by contract tests (`wire_contract_test`
  covers 14 rejection and pass-through cases; `priority_contract_test`
  replays 300 seeded request rounds) — broader randomized corpora remain
  on the roadmap.
- Why no TLS: a self-signed certificate on loopback trains users to click
  through warnings and buys nothing against the browser adversary model
  above; the transport is loopback-only and never leaves the machine.

## Documentation

See `example/main.dart` for a complete runnable host (pure Dart, zero
dependencies). `example/live_check.dart` verifies the browser channel in a
real browser with one command — `dart run example/live_check.dart` — then
open the two URLs it prints (expect all checks green via `localhost`, and
blocked by design via `127.0.0.1`). It serves its check page from loopback
and admits `localhost` only, so it proves the loopback CORS round trip —
admission of a public HTTPS origin is proven by opening your deployed
page. API docs ship with the package. An Arabic guide lives in
`README.ar.md`.

License: BSD 3-Clause.
