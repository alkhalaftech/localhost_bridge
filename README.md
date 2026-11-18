# localhost_bridge

[![CI](https://github.com/alkhalaftech/localhost_bridge/actions/workflows/dart.yml/badge.svg)](https://github.com/alkhalaftech/localhost_bridge/actions/workflows/dart.yml) [![pub](https://img.shields.io/pub/v/localhost_bridge.svg)](https://pub.dev/packages/localhost_bridge)

A localhost HTTP bridge for Dart & Flutter: web pages and local token
clients (CLIs, AI agents) send commands to your app; CORS, Local Network
Access handling, a DNS-rebinding guard and strict limits are built in —
and the bridge parses the payload's shape — JSON, wrapper keys, element
and depth counts — without interpreting the command, so its meaning
belongs to your handler alone.

Your Dart app runs an HTTP server on `127.0.0.1` (never exposed to the
network). A web page the user visits sends commands to it directly from
the browser; a local program reaches the same port with a token and no
browser. The bridge decides **who may talk** and **how much**; what the
commands *mean* stays entirely in your handler.

- **Zero runtime dependencies** — pure `dart:io`, one package, no native
  code. (The SDK constraint pub.dev displays is a compatibility range,
  not a dependency.)
- Rejections carry a stable error `code` — the developer contract. The
  honest exceptions cut the connection immediately: the busy 503, the
  403 Host reject (a request whose Host is not this bridge's local
  address), and a 413 whose body cannot be drained within the discard
  limits — on those paths the code may never reach the caller.

## Quick start

```dart
import 'dart:math';
import 'package:localhost_bridge/localhost_bridge.dart';

// One telemetry sink, shared with the protection object — a protection
// built without one logs nothing. This one prints its lines: the const
// SilentTelemetry() type swallows the security warnings (lockouts,
// policy blocks, oversized tokens), so keep a printing sink while you
// bring the bridge up.
final class _PrintTelemetry extends BridgeTelemetry {
  const _PrintTelemetry();

  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) =>
      print('[warn/$category] $message');

  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) =>
      print('[error/$category] $message');

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) =>
      body();
}

void main() async {
  const telemetry = _PrintTelemetry();

  final server = LocalIntakeServer(
    // Required: your command handler — the bridge is payload-agnostic.
    onCommand: (cmd) async {
      print('from ${cmd.source}: ${cmd.payloads}');
      return const CommandOutcome(ok: true);
    },
    // Required: your telemetry sink — print the warnings while you wire
    // the bridge up; the silent sink hides the security lines.
    telemetry: telemetry,
    // Required: correlation ids — any unique string per request. A
    // Random.secure-based UUID-v4-style generator lives in example/main.dart.
    correlationIdGenerator: () =>
        '${DateTime.now().microsecondsSinceEpoch.toRadixString(16)}'
        '-${Random.secure().nextInt(1 << 32).toRadixString(36)}',
    // Frees a slow handler's seat with a reconcilable 504
    // handler_timeout; without it a slow handler holds its seat until
    // it completes - pass a value in production.
    handlerTimeout: Duration(seconds: 10),
    protection: IntakeProtection(telemetry: telemetry)
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example.com', '*.partner.io'],
          // Bounds a compromised listed origin with the same 429 as the
          // allow-all path; 0 (the default) leaves listed origins
          // unquotaed, so a flood from one holds seats for as long as
          // its requests stay in flight.
          listedPerOriginPerMinute: 120,
        ),
        // Optional token layer — most useful for non-browser
        // integrations; the token must be persisted and shared
        // out-of-band (the quick start omits it; the token bullet below
        // says where a page can send one too).
      ),
  );

  final port = await server.start(preferredPort: 9100);
  print('listening on http://127.0.0.1:$port'); // the port start() returned
}
```

The page side is a plain `fetch` `POST` to the port `start()` returned —
the page-side reference below reads it from the URL the host used to
open the page. The server answers with CORS headers for **admitted**
origins (origin echo + `Vary: Origin`), so HTTPS pages you admitted can
call and read it; every other origin is rejected **before your handler
runs** — the request never reaches your command code, and the page can
read such a reply only where the CORS echo applies (the
consent-question rejection and the quota rejections that carry
`Retry-After` are readable by design). From
an HTTPS page, add `targetAddressSpace: 'loopback'` to the fetch options —
Chrome's Local Network Access guide asks for it (verified 2026-11-13) and
re-verified 2026-11-15, keeping the request exempt from mixed-content
blocking and checking the address space against loopback after DNS resolution
([Local Network Access guide](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access)).

Adding a token does not make it required: while any origin path admits
(a listed origin, allow-all, a remembered consent), a local program can
present that Origin and enter without the token. To require the token,
keep the origin policy empty. In this release whether a browser page can
use the token path follows the CORS echo: with an empty origin policy
and no consent callback nothing is echoed at all, so the token stays a
non-browser path; with a listed origin policy it is echoed for the
listed origins themselves - a page on one can send `X-Bridge-Token`
too, though it is already admitted without it; in the discovery
and allow-all modes the preflight is answered for any valid https origin
that has not been refused, so a page on such an origin can send
`X-Bridge-Token` as well.

A local token client needs no browser at all — one `curl` is the whole
client. Configure the token once with
`update(token: generateBridgeToken())` and share it out-of-band:

```bash
curl -X POST http://127.0.0.1:9100/ \
  -H 'Content-Type: application/json' \
  -H "X-Bridge-Token: $BRIDGE_TOKEN" \
  -d '{"data": ["your-command"]}'
```

## Security model — read before choosing a policy

The bridge cannot know whether a site is legitimate or compromised: it
only sees the `Origin` header (set by the browser, forgeable by any local
program), the `Sec-Fetch-*` headers, and the payload.

- **Closed by default.** An empty policy rejects every origin — token
  holders still enter once a token is configured, because the token
  layer is an independent entry path, not a gate over the policy.
  Ship-safe.
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
  modes: presenting the right `X-Bridge-Token` crosses without browser
  headers. It is the only mode that resists other local programs (other
  apps on the machine, other users on a shared host). Adding a token does
  not make it required: while any origin path admits (a listed origin,
  allow-all, a remembered consent), a local program can present that
  Origin and enter without the token. To require the token, keep the
  origin policy empty. In this release a browser page can use the token
  path wherever the preflight is echoed for it: listed and
  always-approved origins (the origins your consent callback answered
  with a remembered `allowAlways` grant) always - a page on a listed
  origin can present the token too, though it is already admitted
  without it - and in the discovery and allow-all modes any valid https
  origin not yet refused.
  Only with an empty origin policy and no consent callback is nothing
  echoed, so the token belongs to non-browser senders there. On Android it is
  the practical requirement, not an optional extra: any installed app
  can open the port and present a forged `Origin`.
- **"Trusted" means admitted, not validated.** A `TrustedCommand` is so
  named because it passed the origin decision on its way in — the name
  says nothing about the payload's safety. Payload validation is always
  yours (next bullet).
- **In every mode, payloads are untrusted.** Your handler must validate
  them (for a device: allow-list the command verbs; block configuration,
  storage and firmware commands) and cap decompressed size.
  A body of many small JSON elements (e.g. 1 MiB of `{}`) would amplify
  into hundreds of MB of parsed objects, so the bridge counts structural
  elements (`{`, `[`, `,` outside strings) in one linear pass **before**
  decoding and rejects over `maxJsonElements` (default 10,000) with
  `413 payload_too_complex` — braces and commas inside strings count
  nothing, and raw non-JSON command text is never counted. A body that
  starts with `{` or `[` is counted whether or not it is valid JSON; any
  other text is not counted.
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
| `allowed` | Exact origins (`https://host`) — matched against the full origin the browser sends, so a non-default port must be written in the entry itself (`https://host:8443`) and a portless entry matches only the portless form (browsers omit default ports, so `https://host` is what `https://host:443` pages send); bare hosts (`partner.io`) — matched against the host name alone, so a bare entry admits the host on **any** port; and `*.example.com` (subdomains only — list the root explicitly) matches its subdomains on **any** port, because the page's port is chosen by whoever serves the page and the bare/wildcard forms gate on the domain. Bare and wildcard entries admit `https` only (plus local `http` under `allowLocalHttp`); full-origin entries carry their scheme. |
| `allowAllHardened` | Any valid HTTPS origin passes the hardening (origin, fetch-mode, per-origin quota). Loud warning on activation. |
| `allowLocalHttp` | Dev exception: accept `http://localhost` / `http://127.0.0.1` (allow-all path and bare/wildcard entries). |
| `onUnknownOrigin` | First-use consent callback (`allowAlways` / `allowOnce` / `reject` / `dismissed`) — this callback is the whole of the **discovery** mode named elsewhere in the docs: an origin that no rule admits asks the host once through it. Non-blocking: the request returns `origin_pending` immediately (CORS-readable, with `Retry-After` exposed) and the page retries after the host answers; `allowOnce` grants exactly one retry within ~30s; `dismissed` closes the question with no decision — nothing is remembered and the origin is asked again on its next request. New questions carry a time budget (10 per 10 minutes) — beyond it the request still gets `origin_pending`, with no new question until stamps age out. Call `dispose()` when done to cancel pending window timers. |
| `reportOnly` | Observe-and-log for the origin quota only; request-shape checks always reject. |
| `perOriginPerMinute` | Per-origin rate budget on the allow-all path (default 30). |
| `listedPerOriginPerMinute` | Optional per-origin budget on the listed path too — 0 (the default) keeps listed origins unquotaed; a positive value bounds a compromised listed origin's flood with the same `429 origin_rate_limited`. Watch mode (`reportOnly`) covers this quota like the allow-all one, and a failed token attempt carrying a listed origin also counts against its window. |
| `requireFetchMetadata` | On by default. The allow-all and discovery paths refuse requests carrying no `Sec-Fetch-Mode: cors` / `Sec-Fetch-Dest: empty` (`cross_site_blocked`) — closing silent sends from browsers without Fetch Metadata. Headerless non-browser clients on the token layer are unaffected; turn it off only if you serve such clients through the browser paths. |
| `askTimeout` | Max lifetime of a silent consent window (default 60s); the slot frees only on answer or expiry. |

### Building the consent dialog

When you wire `onUnknownOrigin`, the dialog your host shows is part of the
security model — four disciplines keep the human decision real:

- **Show the scheme and host only** (`https://portal.example.com`), and
  highlight the registrable part of the host — an origin never carries a
  path, and the registrable part is what the user can actually judge.
- **No default accept button, and a short delay before the buttons
  respond** — a dialog that can be accepted by reflex is not a human
  decision.
- **One window per origin** — the package itself opens a single consent
  question per origin and joins concurrent requests to it, so do not stack
  one dialog per request.
- **Close the dialog with your own timer, equal to `askTimeout`, and answer
  `dismissed` when it fires** — that keeps your UI in step with the
  package's window, which expires on the same `askTimeout`.

## ArrivalGuard — an optional host-side tool

`ArrivalGuard` is a standalone metering class the package exports for
hosts that want their own arrival bookkeeping. It is **not** wired into
the server: the intake path never calls it, and every protection the
bridge enforces (origin policy, fetch-mode checks, per-origin quotas,
token lockout, seat cap) is computed without it. Treat it as a helper you
call yourself, not as a guard the bridge applies for you.

It answers one question per request: given arrival facts you record, does
this fingerprint look like a flood or a duplicate loop? The decision comes
back as a fact for your log — the class never rejects anything.

```dart
final guard = ArrivalGuard(); // 60 s window, at most 500 live fingerprints

CommandOutcome handle(TrustedCommand cmd) {
  final decision = guard.decide(ArrivalFacts(
    elapsedMs: stopwatch.elapsedMilliseconds, // one monotonic clock, yours
    fingerprint: fingerprintOf(cmd),          // you define the identity
    maxPerMinute: 120,
    dupWindowMs: 5000,
    maxDupPerMinute: 3,
  ));
  if (decision is ReviewArrival) {
    // decision.reason is 'flood' or 'dupLoop'; decision.dups counts
    // repeats inside the dup window. Your review path decides.
  }
  return const CommandOutcome(ok: true);
}
```

The decision to keep this class in the public API or remove it is
deferred to a later release; treat it as provisional.

## Wire contract (what your page sees)

> **A `504 handler_timeout` is an unknown outcome, not a failure.** The
> handler may still complete after the seat frees — a blind retry can
> double-execute the command. Reconcile on `X-Correlation-Id` before any
> retry (the page-side reference shows the flow).

JSON everywhere: `POST` with `Origin`; responses carry `X-Correlation-Id` (yours echoed back when it matches `[A-Za-z0-9._-]` and is at most 128 chars; anything else is replaced with a generated id).

The `Access-Control-Allow-Headers` list is fixed — `Content-Type`,
`X-Bridge-Token`, `X-Correlation-Id` — so the page must not send any
other header: the preflight answer will not allow it. Commands are sent
to `/`: in this release every path reaches the handler, and non-root
POSTs just warn the host — so keep sending commands to `/`.

Stable error codes:

| HTTP | `error` code | Meaning |
|---|---|---|
| 200 | — | Handler succeeded (`{"ok":true}`). |
| 400 | `duplicate_header` / `origin_too_long` | A single-valued header was sent twice / an `Origin` header over the package's internal length cap (1,024 characters), refused before any processing. |
| 400 | `origin_malformed` / `token_too_long` / `bad_request` | An `Origin` header that is not `scheme://host[:port]` / an `X-Bridge-Token` header over the internal byte cap (1,024 bytes) / the HTTP parser rejected the request framing — all refused before your handler runs. |
| 400 | `invalid_utf8` / `empty_payload` / `unsupported_payload_shape` | Body not UTF-8 / no valid command payload / JSON object without any of the known command keys. A body that fails JSON decoding altogether is **not** a 400 — it falls through as a raw text command (the tested non-JSON contract); a JSON number, boolean, or `null` body takes the same raw path. Inside a JSON array, non-string and empty-string elements drop without notice. |
| 405 | `method_not_allowed` | Only `POST` (and `OPTIONS` preflight) are accepted. |
| 403 | `origin_not_listed` / `origin_declined` / `origin_unknown` / `origin_blocked` / `origin_pending` | Origin policy rejection (not listed / consent declined / not confirmable / allow-all hardening / consent window open — retry after `Retry-After`). |
| 403 | `token_required` | The origin qualified, but `OriginPolicy.requireOriginWithToken` is on and the request carried no valid token (the shared token, or a paired origin-bound signature) — the readable refusal a paired page retries from. |
| 403 | `cross_site_blocked` | Fetch-mode hardening: `Sec-Fetch-Mode` not `cors`. |
| 403 | `blocked_by_protection` | Host-authority rejection (DNS-rebinding defense). |
| 408 | `request_timeout` | Body did not arrive in time. |
| 413 | `payload_too_large` / `payload_too_complex` | Body over the byte cap (default 1 MiB) / JSON body over the element cap (default 10,000 structural elements, counted before parsing). |
| 415 | `unsupported_media_type` | POST body carries a `Content-Type` outside `BridgeConfig.allowedContentTypes` (default `application/json` and `text/plain`, which covers JSON clients and textual gateways; an absent header passes for raw-socket integrations). Hidden-HTML-form types (`application/x-www-form-urlencoded`, `multipart/form-data`) are refused. Checked after intake admission, so an untrusted origin still sees its origin rejection. Note: `text/plain` itself is a valid HTML form enctype, so it passes this gate — the browser-facing form defense is the fetch-mode hardening (`cross_site_blocked`), with `OriginPolicy.requireFetchMetadata` extending it to headerless requests. |
| 429 | `origin_rate_limited` / `token_locked` | Per-origin budget exhausted / too many **wrong** token attempts in the last 60 seconds from this origin — the wrong-guess budget is 5 attempts per window (originless attempts share one window). The budget is a signal about wrong guesses, never a refusal of the verified sender: the correct token is compared and accepted whatever the failure history, and a match clears the window. |
| 503 | `server_busy` / `protection_disposed` | Concurrency seats full (seats plus timed-out handlers still running are one live-work budget) / the protection object was disposed — create a new one. |
| 504 | `handler_timeout` | Your handler exceeded `handlerTimeout`; the seat is freed and the late result ignored. **The command may still have run** — treat 504 as "outcome unknown", not "not executed": a blind retry can double-execute. Deduplicate on `X-Correlation-Id` before retrying — the page sends its own id and the bridge echoes it back unchanged on a retry; a server-generated id is not one you can settle on when a reply is lost. |
| 500 | `internal` / your code / `command_failed` | Handler failure; `command_failed` is the fallback code when your handler fails without one (set `BridgeConfig.fallbackErrorCode` to keep an existing wire contract). Host error *text* is echoed only to trusted origins; everyone gets the code. |

Bodies arrive as an array of strings, a bare string, or
`{"data": [...]}` / `{"payload": ...}` / `{"commands": [...]}` wrappers
(`BridgeConfig.payloadWrapperKeys` — add your domain's key there if your
gateways use one). Compressed payloads are delivered as-is —
decompression is the host's responsibility, by design.

## Page-side reference (JavaScript)

The wire contract above is the real contract; the snippet below is a
reference pattern for a browser page, not a required client.

```javascript
// BRIDGE_PORT travels from the host that opened this page - here read
// from the query string the opener used (?bridge-port=9100). The host
// prints the port start() returned at boot. Page code never assumes the
// preferred port: a same-session program may hold it, and start() then
// serves elsewhere.
const BRIDGE_PORT = new URLSearchParams(location.search).get('bridge-port');
const ENDPOINT = `http://127.0.0.1:${BRIDGE_PORT}/`;

// Explain the Local Network Access permission to the user before the
// browser raises its own prompt. The query can hang in some embedded
// contexts, so bound it with a timer instead of awaiting it blind.
async function loopbackPermissionState() {
  const timeout = new Promise((resolve) => setTimeout(() => resolve(null), 3000));
  // Browsers that do not know the permission name reject query() with a
  // TypeError (or throw it synchronously). Left bare, that rejection
  // would settle the race below and make this whole function throw
  // instead of answering — so every failure path folds into `null`,
  // which the last line reports as 'unknown'.
  const query = (async () => {
    try {
      return await navigator.permissions.query({ name: 'loopback-network' });
    } catch (permissionError) {
      return null; // name not recognized here -> report 'unknown'
    }
  })();
  const status = await Promise.race([query, timeout]);
  return status ? status.state : 'unknown'; // 'granted' | 'prompt' | 'denied' | 'unknown'
}

async function sendCommand(payload, correlationId, mayRetry = true) {
  let response;
  // The request itself may hang with no answer at all (a prompt nobody
  // answers, an embedded frame that cannot show one), so bound it and
  // regain control instead of waiting forever.
  const abort = new AbortController();
  const giveUp = setTimeout(() => abort.abort(), 15000);
  try {
    response = await fetch(ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Correlation-Id': correlationId,
      },
      body: JSON.stringify(payload),
      // From an HTTPS page, declare the target address space so the
      // request stays exempt from mixed-content blocking (Chrome 142+).
      targetAddressSpace: 'loopback',
      signal: abort.signal,
    });
  } catch (networkError) {
    // A network error does NOT tell you why it happened. It covers both
    // a policy rejection the browser could not read and the bridge
    // simply being down — and an aborted timeout lands here too. Treat
    // it as "no answer", never as a verdict.
    throw new Error('bridge unreachable — no verdict about the command');
  } finally {
    clearTimeout(giveUp);
  }

  if (response.status === 403 || response.status === 429) {
    const body = await response.json();
    if (body.error === 'origin_pending' && mayRetry) {
      // The consent question is open. Wait exactly what the server
      // states — Retry-After is in seconds — and retry once.
      const waitSeconds = Number(response.headers.get('Retry-After')) || 2;
      await new Promise((resolve) => setTimeout(resolve, waitSeconds * 1000));
      return sendCommand(payload, correlationId, false);
    }
    // Every other rejection lands here. Rate-limit rejections (429, and
    // budget-shaped 403s) carry an honest Retry-After; this reference
    // does not auto-retry a rate limit (that would defeat it), so the
    // wait travels on the error as retryAfterSeconds whenever the
    // server stated one, and the caller honors it before trying again.
    const rejection = new Error(`rejected: ${body.error}`);
    const retryAfterSeconds = Number(response.headers.get('Retry-After'));
    if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
      rejection.retryAfterSeconds = retryAfterSeconds;
    }
    throw rejection;
  }

  if (response.status === 504) {
    // handler_timeout: the handler may still complete in the background.
    // This is an UNKNOWN outcome, not a failure — reconcile on your
    // correlation id before any retry, or the command can double-run.
    throw new Error('outcome unknown — reconcile on X-Correlation-Id');
  }

  return response.json();
}

// Every permission state has its own behavior:
// - 'granted' -> connect now.
// - 'prompt'  -> the browser needs a real user gesture: wire the send to
//   an explicit button. A request fired at page load, or from a Service
//   Worker, never raises the prompt - it just fails as a network error.
// - 'denied'  -> stop retrying; tell the user how to re-enable the
//   permission for this site (address-bar lock icon -> Site settings),
//   and send again only after they re-grant it.
// - 'unknown' -> no permission API in this browser: attempt the send and
//   treat any failure like the plain network error it is.
const state = await loopbackPermissionState();
if (state === 'denied') {
  showReenableHint(); // your UI - point at this site's settings
} else if (state === 'prompt') {
  connectButton.addEventListener('click', () =>
    sendCommand(payload, newCorrelationId()));
} else {
  // 'granted' or 'unknown' - connecting is allowed now.
  await sendCommand(payload, newCorrelationId());
}
```

**The first request follows an explicit user action** — a click on your
page, not the page-load event, and never a Service Worker: the browser
raises the permission prompt only on a real gesture, and a request that
never gets that chance simply fails as a network error. Once the state
is `denied`, retry loops accomplish nothing — the fix lives in the site
settings, with the user.

Two properties of the wire are worth designing around. First, a policy
rejection arrives as an HTTP status with a stable `error` code — but the
page can read that body only where CORS allows it: admitted origins, the
consent-question rejection, and quota rejections carrying `Retry-After`
when the origin qualifies for the echo. Second, everything else surfaces
as a plain network error that cannot distinguish "the policy said no"
from "the bridge is not running" — design your state machine so neither
case reports a command verdict.

If the sending page lives in an `<iframe>`, the embedding page must
delegate the Local Network Access permission to the frame with
`allow="loopback-network"` on the iframe tag — without it the frame's
requests fail regardless of what the user would have granted. A
sandboxed iframe runs on an opaque origin the policy rejects, and some
browsers show no prompt for a sandboxed frame; grant
`allow-same-origin`.

Background Fetch is not a side door around any of this: in Chrome 157
and Edge 157 a Background Fetch request is subject to the same CORS
enforcement and Local Network Access checks as a regular `fetch`, so it
cannot reach the bridge where a `fetch` cannot
([Chrome 157 release notes](https://chromestatus.com/release-notes/157),
verified 2026-11-15).

## Browser support (reviewed 2026-11)

Status vocabulary: **shipped** — in the vendor's shipped, documented
release; **planned** — dated by the vendor, not shipped yet;
**untested here** — verified against documents, not against a device;
**not supported** — the vendor's documented behavior blocks it. Edge is
built on the Chromium engine, so the Chromium sources in this table govern
the behavior they share.

| Browser | Status | As of | Source |
|---|---|---|---|
| Chrome, Edge (desktop and Android) | shipped — the browser asks the user for Local Network Access permission | 2026-11-15 | [Chrome: Local Network Access](https://developer.chrome.com/blog/local-network-access) · [Chrome 142 release notes](https://chromestatus.com/release-notes/142) |
| Firefox (desktop 153+) | shipped — permission prompt as above, enabled by default | 2026-11-15 | [Firefox 153.0 release notes](https://www.mozilla.org/en-US/firefox/153.0/releasenotes/) |
| Firefox (Android 160+) | shipped — the vendor's shipped-versions feed lists 160.0 at re-verification | 2026-11-15 | [Mozilla product details: Firefox for Android versions](https://product-details.mozilla.org/1.0/mobile_versions.json) · [Mozilla release calendar](https://wiki.mozilla.org/Release_Management/Calendar) |
| Safari, and iOS browsers built on WebKit | not supported — WebKit blocks `http://127.0.0.1` from an `https` page as mixed content, with no Local Network Access prompt to exempt it. Apple permits other engines in the EU (iOS 17.4+); none is tested here | 2026-11-15 | [WebKit bug 171934](https://bugs.webkit.org/show_bug.cgi?id=171934) · [Apple: alternative browser engines](https://developer.apple.com/support/alternative-browser-engines) |
| Android WebView | untested here — no permission prompt of its own; reachability follows the permissions of the app embedding the WebView. On Android 17, WebView traffic inherits the host app's local-network permission state, and the `ACCESS_LOCAL_NETWORK` permission applies only to apps targeting SDK 37; the official local-network definition does not mention loopback | 2026-11-15 | [Android: local network permission](https://developer.android.com/privacy-and-security/local-network-permission) · [Android: local network definition](https://developer.android.com/privacy-and-security/local-network-definition) |

"Shipped" means the page can send and read a reply after the user grants
the prompt. The fetch-mode hardening does not depend on any prompt — it
applies wherever the request arrives.

## Host platforms

| Host platform | Status | As of | Source |
|---|---|---|---|
| Desktop (Windows, macOS, Linux) | shipped — the usual loopback server model; Windows and Linux put no platform gate on it, while a macOS host inside App Sandbox needs the `com.apple.security.network.server` entitlement | 2026-11-15 | [Apple: App Sandbox entitlements](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.server) |
| Android | shipped — an in-app loopback server; run the host app foregrounded or behind a foreground service, or the system may stop it. Chrome and Firefox reach it after the user grants Local Network Access. On Android 17, loopback traffic between two profiles (work and personal) is blocked by default for every app regardless of targetSdk; loopback within one profile is unaffected. On Android, any installed app can reach the port and send any `Origin`, so the token is the real barrier there. Native clients on the device send the token. In this release a browser page presents the token only where its preflight is echoed: a listed origin, or any valid https origin not yet refused under the discovery and allow-all modes — and an installed app can present that same listed origin. | 2026-11-15 | [Android: local network permission](https://developer.android.com/privacy-and-security/local-network-permission) · [Android 17 behavior changes](https://developer.android.com/about/versions/17/behavior-changes-all) |
| iOS | untested here — no browser path: WebKit blocks `http://127.0.0.1` from `https` pages (mixed content), and iOS suspends in-app sockets when the host app backgrounds | 2026-11-15 | [WebKit bug 171934](https://bugs.webkit.org/show_bug.cgi?id=171934) |

### When this package fits

The bridge is built for pages driving local commands where a silent or
replayed send must be stopped by barriers, not by luck: irreversible
commands (print, pay, unlock, open a file, change device state) where
you want origin admission, consent questions, quotas, and
a deduplication ledger your host keeps around every send
(`example/idempotent_handler.dart` is that ledger, ready to adapt). The
ledger never drops a live entry to make room: a full ledger refuses new
commands with a `ledger_full` outcome until entries settle or expire.
For that case, SECURITY.md collects the host-side disciplines in one
place: "Recommended setup for irreversible commands", with the two
sender paths spelled out — non-browser senders keep the origin policy
empty and hold the token, and a browser page is admitted through an
explicit origin list instead (and in the discovery and allow-all modes
its preflight is echoed, so it can use the token path there too); each
path names its residual (a local program can present a listed origin).
A command that is safe to
repeat and carries no consequence is fine on a plain local HTTP server — the
bridge's walls exist for the commands that must not run twice or from
the wrong page.

Addressing: the server binds IPv4 only, so page code should use
`127.0.0.1` — a `localhost` name can resolve to `::1` (IPv6), where
nothing listens in this release, and another local program can listen on
`::1` at the same port number while the bridge is running.

## Limits (by design)

- Loopback IPv4 only (`127.0.0.1`); no IPv6 binding in this release.
- JSON nesting is capped in the same pre-decode pass (`maxJsonDepth`,
  default 32) — deeper bodies get the same `413 payload_too_complex`
  before `jsonDecode` runs.
- If you pass fallback ports to `start()`, the page must use the port
  `start()` returns — never assume the preferred one (a same-session
  program may hold it).
- Handlers that never complete keep counting against the seats across
  `stop()` and `start()` — that counter is per server object, so only
  building a new `LocalIntakeServer` clears it. At the default seat cap
  (16), sixteen stuck handlers mean every command is answered
  `503 server_busy`.
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
  persistence in this release — the bridge carries bytes and judgements,
  nothing else.
- Local-network-access permission prompts differ across browsers; the
  fetch-mode layer does not depend on them.
- Hostile-wire behavior is pinned by contract tests (`wire_contract_test`
  is a single test replaying a fourteen-case corpus across three
  protection modes; `priority_contract_test` replays 300 seeded request
  rounds) — broader randomized corpora remain on the roadmap.
- The browser channel is proven by a real-browser lab (`browser_lab_test`)
  that drives a system Chrome/Chromium headlessly, with zero added
  dependencies: a page carrying the accepted token sends a command and
  reads the reply; an unpaired page is refused with no readable verdict
  while the wire carries the literal code; and the preflight round trip
  announces `X-Bridge-Token`. Without a browser the lab skips itself and
  states why; CI runs it where the runner image ships Chrome.
- Why no TLS: on the browser path over loopback, a self-signed certificate
  trains users to click through warnings and buys nothing against the
  browser adversary model above; the transport is loopback-only and never
  leaves the machine.

## Documentation

See `example/main.dart` for a complete runnable host (pure Dart, zero
runtime dependencies). `example/live_check.dart` verifies the browser channel in a
real browser with one command — `dart run example/live_check.dart` — then
open the two URLs it prints (expect all checks green via `localhost`, and
blocked by design via `127.0.0.1`). It serves its check page from loopback
and admits `localhost` only, so it proves the loopback CORS round trip —
admission of a public HTTPS origin is proven by opening your deployed
page. `example/origin_pending_page.dart` walks the consent question as a
full state machine — pending, one respectful `Retry-After` retry, grant
or refuse — over the wire at boot, and serves the same machine as a page
to copy into your https portal. Two examples from outside printing show
host-side validation in other domains: `example/shipping_label.dart`
(label commands with a closed spec) and `example/payment_receipt.dart`
(token-only policy with a single-use, host-issued authorize ref). API
docs ship with the package. An Arabic guide lives in
`README.ar.md`.

License: BSD 3-Clause.
