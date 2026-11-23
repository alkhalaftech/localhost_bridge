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
  honest exceptions cut the connection immediately: the busy 503 (the
  global seat cap and the open-connection cap), the per-origin seat
  503, the 403 Host reject (a request whose Host is not this bridge's
  local address), and a 413 whose body cannot be drained within the
  discard limits — on those paths the code may never reach the caller.

## Quick start

Three lines and a running bridge - the host passes nothing but its
handler: the telemetry defaults to a sink that writes the security
warnings to stderr, the correlation ids get an internal secure-random
generator, and the `mobile` preset arms the paired-host shape (the
token plus the origin-with-token requirement and pairing):

```dart
import 'package:localhost_bridge/localhost_bridge.dart';

final server = LocalIntakeServer(
    onCommand: (cmd) async => const CommandOutcome(ok: true),
    protection: BridgePresets.mobile(token: generateBridgeToken()));
final port = await server.start(preferredPort: 9100);
```

Prefer a different posture? Swap the preset - `closed()`, `allowList()`,
or `tokenOnly()` (the preset the command-line demo below runs) - each
one documented in [Ready-made presets](#ready-made-presets) below. The
rest of this section walks the full setup, every knob named:

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
    // Optional: your telemetry sink — the default already writes the
    // security warnings to stderr; this custom sink keeps them in your
    // own log (the silent sink hides the security lines entirely).
    telemetry: telemetry,
    // Optional: correlation ids — an incoming X-Correlation-Id is honored
    // verbatim, and requests without one already get an id from the
    // internal secure-random generator. Pass your own to shape the ids.
    correlationIdGenerator: () =>
        '${DateTime.now().microsecondsSinceEpoch.toRadixString(16)}'
        '-${Random.secure().nextInt(1 << 32).toRadixString(36)}',
    // Customizes the handler budget (the default is 30 seconds from
    // BridgeConfig.handlerTimeout): a handler running past the budget is
    // answered 504 handler_timeout, its seat is freed, the still-running
    // work becomes a counted orphan, and stop() retires whatever remains
    // at its return. To ask for no handler deadline at all, pass
    // LocalIntakeServer.noHandlerTimeout - null selects the configured
    // default budget.
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
present that Origin and enter without the token. To make the token
**required on top of the admitted origin**, set
`OriginPolicy.requireOriginWithToken`: a qualified origin without a
valid token reads `403 token_required`, and the token alone - from an
unqualified origin or with no Origin at all - never admits (the origin
rejection answers it, so a wrong-origin sender learns nothing about its
token). That mode is where **pairing** lives: the host displays a
six-digit one-time code (`startPairing`, 120-second life; shown on the
host's own screen or terminal - a local page is readable by every
program on the device, so it never carries the code), the page
sends it with its origin to `POST /pair`, and receives a token bound to
that origin for 24 hours - revocable and rotatable by the host
(`revokePairedOrigin` / `rotatePairedOrigin`) and never sent raw again:
the page proves possession by signing every request (HMAC-SHA-256 over
the pairing id, a wall-clock stamp, the method, the path, and the
correlation id) in the `X-Bridge-Pairing` header. The page-side
signature is plain WebCrypto:

```javascript
async function signProof(tokenHex, pairingId, method, path, correlationId) {
  const stamp = Date.now(); // keep stamps unique: never sign twice in one ms
  const canonical = `v1\n${pairingId}\n${stamp}\n${method}\n${path}\n${correlationId}`;
  const keyBytes = new Uint8Array(tokenHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey(
      'raw', keyBytes, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign(
      'HMAC', key, new TextEncoder().encode(canonical));
  const sigHex = [...new Uint8Array(sig)]
      .map(b => b.toString(16).padStart(2, '0')).join('');
  return `${pairingId}.${stamp}.${sigHex}`;
}
// headers: { 'X-Bridge-Pairing': proof, 'X-Correlation-Id': cid, ... }
```

A reused or stale (outside one minute of the server's clock) signature
reads `403 pair_signature_replay`; sign a fresh request and increment
nothing - the stamp is the freshness. Five wrong codes absorb a pairing
session's whole guess budget (`429 pair_budget_exceeded`): any page can
spend the budget of the code currently displayed, so when the host reads
that code the host calls `startPairing()` again to display a new one —
the new session starts with its own full budget. With the requirement off (the
default), today's behavior stands: the token stays an optional
independent path, a browser page can send `X-Bridge-Token` wherever its
preflight is echoed, and headerless local clients keep their token door.

A local token client needs no browser at all — one `curl` is the whole
client. Configure the token once with
`update(token: generateBridgeToken())` and share it out-of-band:

```bash
curl -X POST http://127.0.0.1:9100/ \
  -H 'Content-Type: application/json' \
  -H "X-Bridge-Token: $BRIDGE_TOKEN" \
  -d '{"data": ["your-command"]}'
```

## Ready-made presets

`BridgePresets` returns a fully built `IntakeProtection` for one of four
postures; each factory's policy is exactly the shape its row names, so
you can assert what you shipped:

| Preset | The policy it arms | What admits |
|---|---|---|
| `BridgePresets.closed()` | The closed shape: empty list, no allow-all, no discovery, pairing disarmed, no token | Nothing - every page and every token attempt reads `403 origin_not_listed` |
| `BridgePresets.allowList(origins: [...])` | Your origins stored with the standing normalization and matched like every listed entry; everything else stays off | Listed origins alone |
| `BridgePresets.tokenOnly(token: ...)` | The policy stays closed and the token is the one door; `requireOriginWithToken` stays off (the token crosses its own independent path) | A correct `X-Bridge-Token` from a headerless local client; everything else reads the origin rejection - a wrong token learns nothing about itself |
| `BridgePresets.mobile(token: ..., origins: [...])` | `requireOriginWithToken: true` plus pairing armed (the paired-host shape) | An origin carrying its proof: the shared token, or a paired origin-bound signature; a qualified origin without proof reads `403 token_required`, and the token alone never admits |

None of the four opens allow-all and none of them arms discovery - the
widest thing a preset can produce is your own origin list. Token
validation is the standing one: a token below the 32-byte floor, over
the header cap, or too low in character diversity throws at build
time, so a preset never arms a token the wire would refuse. `mobile`
is the preset a mobile host starts from: it pairs the pages it serves,
and pages the bridge itself serves qualify on their own while the
local-pages option is armed; any external origins it lists go beside
them.

### Try it in a minute from the command line

`bin/bridge_demo.dart` runs a real bridge on the `tokenOnly` preset: it
generates its own token, prints it with the port it bound, a ready
`curl` carrying that exact token, and the stop method - then serves
commands. It accepts only `--port <n>`: an allow-all or discovery
opener cannot be passed to it, and any other argument refuses loudly
before anything binds:

```bash
dart bin/bridge_demo.dart              # from a checkout of the package
dart run localhost_bridge:bridge_demo  # from any project that depends on it
```

Ctrl+C stops it - the listener drains and closes cleanly (a SIGINT
watch; sigint is watchable on Windows too, per dart:io's `ProcessSignal.watch`
docs, [verified 2026-11-22](https://api.dart.dev/stable/dart-io/ProcessSignal/watch.html)).

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
  Origin and enter without the token. To make it required, set
  `OriginPolicy.requireOriginWithToken`: a qualified origin must also
  present a valid token - the shared secret, or a paired origin-bound
  signature - and the token alone never admits from an unqualified
  origin (the origin rejection answers it, never a token verdict). This
  origin+token requirement with **pairing** is the setup that admits a
  browser page while resisting other local programs: the page pairs once
  with a displayed one-time code and holds a token bound to its origin,
  expiring in 24 hours, revocable and rotatable by the host, and never
  sent raw - every request carries only its HMAC signature. With the
  requirement off (the default), a browser page can use the token path
  wherever the preflight is echoed for it: listed and always-approved
  origins always, and in the discovery and allow-all modes any valid
  https origin not yet refused. On Android the requirement is the
  practical setup, not an optional extra: any installed app can open the
  port and present a forged `Origin` - but it cannot sign without the
  paired secret.
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
| `listedPerOriginPerMinute` | Per-origin budget on the listed path — 120/minute shipped (two sustained commands a second: a real page fires commands per user action and sits far below it, while a compromised listed origin cannot flood the shared seats). `0` is the explicit opt-out keeping listed origins unquotaed. Over the budget the page reads `429 origin_rate_limited` with the honest `Retry-After`. Watch mode (`reportOnly`) covers this quota like the allow-all one, and a failed token attempt carrying a listed origin also counts against its window. |
| `requireFetchMetadata` | On by default. The allow-all and discovery paths refuse requests carrying no `Sec-Fetch-Mode: cors` / `Sec-Fetch-Dest: empty` (`cross_site_blocked`) — closing silent sends from browsers without Fetch Metadata. Headerless non-browser clients on the token layer are unaffected; turn it off only if you serve such clients through the browser paths. |
| `askTimeout` | Max lifetime of a silent consent window (default 60s); the slot frees only on answer or expiry. |
| `askFiresPerParentPerWindow` | Optional per-parent budget on **new** consent questions (default `0` — off, the global ceiling alone): one parent domain — the last two labels of the origin's host (`x.r1.example.com`, `x.r2.example.com` and `example.com` all share `example.com`; a two-label host or an IP literal is its own parent; hosts under a multi-label public suffix such as `co.uk` share that suffix) — may open at most this many new questions per 10-minute window, beside the global 10-per-10-minutes budget. A question past its parent's budget answers its own `429 origin_parent_rate_limited` with the honest `Retry-After`, but fires nothing and spends nothing from the global budget, so one site rotating subdomains at any depth can no longer starve another origin's question; the global ceiling keeps its `origin_pending`. A negative value throws at `update()` time. |

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
- **Or close it from the package's own end-of-question signal** — set
  `IntakeProtection.onQuestionClosed` and the host is told exactly once
  when a question window ends (the answer arrived, the host future threw,
  or `askTimeout` closed it), with the normalized origin. `onUnknownOrigin`'s
  signature is unchanged; a question the question budget suppressed never
  opened and never signals, and `dispose()` closes the rest silently.

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

The class is settled as **experimental** in 0.2.0: it stays in the
public API as a standalone host-side tool and stays deliberately
unwired from the server - its facts (the fingerprint, the budgets) are
yours to record, and the bridge's own admission path enforces its
per-origin budgets on the wire without it. Depend on it as a helper,
not as a package guarantee; whether it graduates to a wired option or
leaves the API is a question for a future major release, decided by
how hosts actually use it.

## Wire contract (what your page sees)

> **A `504 handler_timeout` is an unknown outcome, not a failure.** The
> handler may still complete after the seat frees — a blind retry can
> double-execute the command. Reconcile on `X-Correlation-Id` before any
> retry (the page-side reference shows the flow).

JSON everywhere: `POST` with `Origin`; responses carry `X-Correlation-Id` (yours echoed back when it matches `[A-Za-z0-9._-]` and is at most 128 chars; anything else is replaced with a generated id).

The `Access-Control-Allow-Headers` list is fixed — `Content-Type`,
`X-Bridge-Token`, `X-Correlation-Id` (plus `X-Bridge-Pairing` only while
pairing is armed, and `X-Command` only while the binary-body option
`BridgeConfig.acceptBinaryBodies` is on) — so the page must not send any
other header: the preflight answer will not allow it. Commands are sent
to `/`: every path reaches the handler, and non-root
POSTs just warn the host — so keep sending commands to `/` (with
pairing armed, `POST /pair` is the pairing door and answers its own
codes; disarmed it is no path at all).

Stable error codes:

| HTTP | `error` code | Meaning |
|---|---|---|
| 200 | — | Handler succeeded (`{"ok":true}` - plus the handler's data field when `CommandOutcome.data` was returned and it sat under the internal 64 KiB page cap; over the cap the whole result is refused as `reply_data_too_large`). |
| 400 | `duplicate_header` / `origin_too_long` | A single-valued header was sent twice / an `Origin` header over the package's internal length cap (1,024 characters), refused before any processing. |
| 400 | `origin_malformed` / `token_too_long` / `pairing_too_long` / `bad_request` | An `Origin` header that is not `scheme://host[:port]` / an `X-Bridge-Token` header over the internal byte cap (1,024 bytes) / an `X-Bridge-Pairing` header over the internal byte cap (256 bytes, pairing armed only) / the HTTP parser rejected the request framing — all refused before your handler runs. |
| 400 | `invalid_utf8` / `empty_payload` / `unsupported_payload_shape` | Body not UTF-8 / no valid command payload / JSON object without any of the known command keys. A body that fails JSON decoding altogether is **not** a 400 — it falls through as a raw text command (the tested non-JSON contract); a JSON number, boolean, or `null` body takes the same raw path. Inside a JSON array, non-string and empty-string elements drop without notice. |
| 400 | `invalid_payload_item` / `malformed_json_shape` / `invalid_json` / `non_json_body` | The payload-contract options — each **off by default**, so the default wire never answers these: `strictPayloadItems` refuses a JSON list carrying a non-string or empty element (the default drops it silently) / `requireValidJsonShape` refuses a container-shaped body that scans structurally incomplete — an unclosed bracket or string (the default falls through as raw text) / `rejectInvalidJson` refuses a body sent as `application/json` that fails JSON decoding / `requireJsonBodies` (JSON-only mode) refuses the raw-text path whole — raw command text and scalar JSON bodies alike. All four answer before your handler runs. |
| 400 | `command_required` | With `BridgeConfig.acceptBinaryBodies` on: an `application/octet-stream` body that carries no `X-Command` name — absent, blank, or with an empty body: one rule, no size carve-out (the raw-text path refuses its empty body `empty_payload` the same way). The bridge delivers only named binary commands; with the option off, `octet-stream` never passes the media gate at all (`415`). |
| 405 | `method_not_allowed` | Only `POST` (and `OPTIONS` preflight) are accepted - every `GET` included, except on the registered local-page paths while `BridgeConfig.localPages` is armed (those answer the page), and on the armed health page (`BridgeConfig.healthPath`, which answers `{"ok":true}` to an accepted origin). |
| 403 | `origin_not_listed` / `origin_declined` / `origin_unknown` / `origin_blocked` / `origin_pending` | Origin policy rejection (not listed / consent declined / not confirmable / allow-all hardening / consent window open — retry after `Retry-After`). |
| 403 | `token_required` | The origin qualified, but `OriginPolicy.requireOriginWithToken` is on and the request carried no valid token (the shared token, or a paired origin-bound signature) — the readable refusal a paired page retries from. |
| 403 | `pair_code_invalid` / `pair_code_expired` | On `POST /pair` (pairing armed): an unknown or already-used one-time code / a code past its 120-second life. The reply always echoes CORS — the pairing door is readable by design (the code is the gate, not the origin). |
| 403 | `pair_signature_replay` | A pairing signature whose stamp was already used, or lies outside the accepted one-minute clock-skew window — the same stamp never proves twice. Sign a fresh request. |
| 403 | `cross_site_blocked` | Fetch-mode hardening: `Sec-Fetch-Mode` not `cors`. |
| 403 | `blocked_by_protection` | Host-authority rejection (DNS-rebinding defense). |
| 408 | `request_timeout` | Body did not arrive in time. |
| 413 | `payload_too_large` / `payload_too_complex` / `reply_data_too_large` | Body over the byte cap (default 1 MiB) / JSON body over the element cap (default 10,000 structural elements, counted before parsing) / the command succeeded but its `CommandOutcome.data` is over the internal page cap (64 KiB after JSON encoding) - the whole result is refused, never truncated, and the command stays executed. |
| 415 | `unsupported_media_type` | POST body carries a `Content-Type` outside `BridgeConfig.allowedContentTypes` (default `application/json` and `text/plain`, which covers JSON clients and textual gateways; an absent header passes for raw-socket integrations). Hidden-HTML-form types (`application/x-www-form-urlencoded`, `multipart/form-data`) are refused. Checked after intake admission, so an untrusted origin still sees its origin rejection. Note: `text/plain` itself is a valid HTML form enctype, so it passes this gate — the browser-facing form defense is the fetch-mode hardening (`cross_site_blocked`), with `OriginPolicy.requireFetchMetadata` extending it to headerless requests. With `BridgeConfig.acceptBinaryBodies` on, `application/octet-stream` joins the admitted types: the raw bytes reach your handler as `TrustedCommand.binaryPayload` (`payloads` stays empty; the command name rides the `X-Command` header into `TrustedCommand.headers`) under the package's internal binary ceiling — a fixed 256 KiB constant, deliberately not an option; a binary body over it answers `413 payload_too_large` naming the binary cap, and a binary body without its `X-Command` name (blank name or empty body alike) answers `400 command_required`. |
| 429 | `origin_rate_limited` / `token_locked` | Per-origin budget exhausted / too many **wrong** token attempts in the last 60 seconds from this origin — the wrong-guess budget is 5 attempts per window (originless attempts share one window). The budget is a signal about wrong guesses, never a refusal of the verified sender: the correct token is compared and accepted whatever the failure history, and a match clears the window. |
| 429 | `origin_parent_rate_limited` | Discovery only (with `OriginPolicy.askFiresPerParentPerWindow` set): this parent domain's new-question budget is spent — the request is refused without opening a consent question; it fires nothing and spends nothing from the global budget, whose `origin_pending` never changes. The honest `Retry-After` carries the remainder of the parent's window. |
| 429 | `pair_budget_exceeded` | On `POST /pair` (pairing armed): five wrong code attempts per pairing session have been absorbed — the honest `Retry-After` carries the remaining life of the displayed session. The budget is per session, never per origin. |
| 503 | `server_busy` / `origin_seat_limit` / `protection_disposed` | Concurrency seats full (seats plus timed-out handlers still running are one live-work budget) / one origin holds its full seat share while the server still has room (see `BridgeConfig.maxSeatsPerOrigin`) / the protection object was disposed — create a new one. |
| 504 | `handler_timeout` | Your handler exceeded `handlerTimeout`; the seat is freed and the late result ignored. **The command may still have run** — treat 504 as "outcome unknown", not "not executed": a blind retry can double-execute. Deduplicate on `X-Correlation-Id` before retrying — the page sends its own id and the bridge echoes it back unchanged on a retry; a server-generated id is not one you can settle on when a reply is lost. |
| 500 | `internal` / your code / `command_failed` | Handler failure; `command_failed` is the fallback code when your handler fails without one (set `BridgeConfig.fallbackErrorCode` to keep an existing wire contract). A failed outcome carrying `CommandOutcome.refusalStatus` (400..499) answers with that client-error status instead, only while `BridgeConfig.acceptHandlerRefusal` is on — the default stays `500`, and a marker outside 400..499 is ignored. Host error *text* is echoed only to trusted origins; everyone gets the code; `BridgeConfig.maxErrorMessageLength` (0 = off) caps that text on the wire to at most that many UTF-8 bytes, cut at a whole-character boundary (a multi-byte character is dropped whole, never split) when set. |

The channel codes answer over their own wire, not as HTTP replies: a
WebSocket channel (below, `BridgeConfig.wsPath`) reads them as the final
JSON frame before the close (the close reason carries the literal code
too), and the streaming reply (below, `BridgeConfig.allowStreamingReplies`)
reads `progress_data_too_large` as the final `event: result` frame. The
`HTTP` column on these rows names the same-failure HTTP family the fact
would answer with on the HTTP wire - it is the registry status, not a
status line the code actually writes. A refusal that happens BEFORE the
WebSocket upgrade (origin policy, host authority, seat caps) is a plain
HTTP reply with the standing codes above - no channel-specific rows exist
for it.

| HTTP | `error` code | Meaning |
|---|---|---|
| 403 | `ws_auth_timeout` / `ws_auth_invalid` | The channel's credential step: an admitted origin whose first message carried no credential within the auth deadline (10 seconds) is closed / the first message was not a JSON object carrying exactly one credential - `"token"` or `"pairing"`, never both. Browsers cannot add headers to a WebSocket handshake, so the credential travels in the first message and the handshake itself defers it. |
| 408 | `ws_idle_timeout` | No message arrived within `BridgeConfig.idleTimeout` on the open channel - the connection is closed and its seat freed. |
| 413 | `ws_message_too_large` | An inbound message over the internal channel cap (256 KiB, a fixed named constant). Two layers enforce it: a message between the cap and the transport ceiling (2 MiB) carries this refusal frame before the close; a frame over the transport ceiling itself is refused by `dart:io`'s own transformer at the declared length (before any payload byte buffers) and the close reads the transport-level 1002 - the counted, readable refusal lives at the delivery cap under the ceiling, while a transport-ceiling kill is the transport guarding memory on its own and leaves no counted frame. The channel refuses to arm on a dart:io older than 3.13 (the first release whose upgrade carries the length parameter): arming `wsPath` there throws `ArgumentError` at construction - the channel never runs without its transport ceiling, and no ceiling-less upgrade exists. |
| 413 | `progress_data_too_large` | Streaming replies: a progress report over the internal 64 KiB event cap ends the stream with this refusal frame, fires the command's cancel signal, and turns the progress sink inert - the reply channel is gone, so wrapping up is the honest ask. |

Bodies arrive as an array of strings, a bare string, or
`{"data": [...]}` / `{"payload": ...}` / `{"commands": [...]}` wrappers
(`BridgeConfig.payloadWrapperKeys` — add your domain's key there if your
gateways use one). Inside a list, non-string and empty-string elements
drop without notice by default — `BridgeConfig.strictPayloadItems`
refuses the request instead. A body that fails JSON decoding falls
through as raw command text by default — `BridgeConfig.rejectInvalidJson`
(scoped to `application/json` senders) and `BridgeConfig.requireJsonBodies`
(JSON-only mode) refuse those paths instead. Compressed payloads are
delivered as-is — decompression is the host's responsibility, by design.

## The host-to-page channels (streaming replies and the WebSocket)

Both channels are off by default; the default wire is byte-identical to
previous releases.

**Streaming replies** - `BridgeConfig.allowStreamingReplies: true` lets a
page opt one command in with the request header `X-Bridge-Stream: events`
(a CORS preflight header, allowed only while the option is on). The reply
is `text/event-stream`: the handler reports progress through
`TrustedCommand.progress` (one call = one `event: progress` frame, in
call order), and the handler's outcome travels as the final
`event: result` frame with the standing reply contract (`{"ok":...}` -
same codes, same data cap, same message rules as the JSON reply). The
page reads it with `fetch` and a streamed-body reader:

```javascript
const res = await fetch(ENDPOINT, {method: 'POST', headers: {
  'Content-Type': 'application/json', 'X-Bridge-Stream': 'events',
}, body: '["LONG-JOB"]'});
const reader = res.body.getReader();  // frames: event: progress / result
```

A progress value over the internal 64 KiB event cap ends the stream with
`progress_data_too_large` and fires the command's cancel signal; the
page closing mid-stream fires that same cancel signal and leaves no seat
nor socket behind.

**The WebSocket channel** - `BridgeConfig.wsPath: '/ws'` (any path but
`/pair`) upgrades a browser handshake through the same admission step as
every request: origin, fetch metadata, host authority, and the seat caps
answer their standing codes BEFORE the upgrade. The browser cannot add
headers to a handshake, so the credential - the token or a pairing
signature - travels in the first message (a JSON object
`{"token": "..."} ` or `{"pairing": "id.stamp.sig"}`, within the 10
second auth deadline; the pairing signature signs `WS`, the channel
path, and a correlation id you choose). Every inbound message is a
command under the same payload checks; every reply is an event shaped by
the standing reply contract. The connection holds one concurrency seat
for its lifetime, so `maxConcurrentRequests` and `maxSeatsPerOrigin`
bound the live connections per origin exactly like live commands; a
heartbeat keeps the path alive, silence past `idleTimeout` closes it,
and messages over the internal 256 KiB cap close it
(`ws_message_too_large`).

```javascript
const ws = new WebSocket('ws://127.0.0.1:' + BRIDGE_PORT + '/ws');
ws.onopen = () => {
  ws.send(JSON.stringify({token: TOKEN, correlationId: 'ws-1'}));
  ws.send(JSON.stringify(['PRINT', 'label-zpl']));
};
ws.onmessage = (e) => console.log(JSON.parse(e.data));  // the reply event
```

## Mounting the bridge on an existing dart:io server

If the host already runs an HTTP server and wants the bridge on a route
of it - not on a second port - it forwards the requests the bridge owns
to `handleHostRequest`. The host keeps its server and its routing: only
the requests it forwards reach the bridge, so the server's other routes
are never touched by it. Each forwarded request passes the full
standing protection - the same gates in the same order as the private
`start()` listener, the same wire codes - and every reply is written
and the connection cut over the detached socket exactly as the private
server does it. The local host authorities are built from the host
server's own listening port (pass it as `hostPort`), and the bridge
checks the remote peer itself: a request arriving from a non-loopback
address is refused `403 blocked_by_protection` by the FIRST gate -
no header is read, no log line is written, and no warning budget is
spent; the rejection is counted only in the rejection-codes counter,
an in-memory number that helps the host see the attempts (the denial
is silent: a remote party never writes into the bridge's security
log, and the refusal carries a generated correlation id only) - so
binding the host to `0.0.0.0` does not break the
package's loopback guarantee. An IPv4-mapped IPv6 peer
(`::ffff:127.0.0.1`, what a
dual-stack bind delivers for an IPv4 loopback caller) counts as
loopback. The open-connection cap (`maxOpenConnections`) guards the
bridge's own listener and has nothing to read here - the host owns the
accept loop; the seat budget (`maxConcurrentRequests`,
`maxSeatsPerOrigin`, the live-work cap) is the budget that binds on
this path, and a forwarded request mid-flight holds its seat inside
`stop()`'s drain.

One `dart:io` server splitting its requests between the bridge and an
existing app built on another server framework - a documentation
example only, with no dependency on any framework:

```dart
final bridge = LocalIntakeServer(/* your wiring */);
final server = await HttpServer.bind(InternetAddress.anyIPv4, 8080);
server.listen((request) async {
  if (request.uri.path == '/bridge') {
    // الجسر يجيب بالحماية الكاملة، وكل ردٍ يكتب ويُقطع على المقبس المنتزع
    await bridge.handleHostRequest(request, hostPort: server.port);
  } else {
    // التطبيق القائم يجيب مساراته بنفسه بإطاره هو؛ الجسر لا يراها
    await app.handle(request);
  }
});
```

## The local pages (an optional page from memory)

A host without a UI - a CLI tool, a service - has nowhere to show a
status readout or its settings. `BridgeConfig.localPages` arms the
local pages: pass the pages from memory (a path, the content, the
content type) and a `GET` on exactly those paths answers the page,
carrying the page's security headers. Every other `GET` keeps its
standing `405 method_not_allowed`, and `null` - the default - keeps
the option off with the wire letter identical. Nothing is ever read
from the filesystem: the pages live in the host's memory, and serving
a folder from disk is not part of this package. The pages answer on
the bridge's own listener only - on a mounted server the host serves
its own routes, and a forwarded `GET` answers `405` like any
non-POST.

**The local page is readable by every program on the device** - a
plain `GET` with no browser headers reads it - so no pairing code, no
token, and no secret belong in a local page. The pairing code is
shown through the host's own channel: its screen, or its terminal,
where only the human at the device reads it; a page that displayed it
would hand it to every local program.

Every page reply carries a strict CSP - nothing loads from anywhere
except the page's own inline script and style, and connections stay
on the bridge's own origin (`connect-src 'self'`) - plus
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
`X-Content-Type-Options: nosniff`, and it echoes no CORS header, so a
foreign page cannot read it cross-origin.

The page's own origin - `http://127.0.0.1:<port>` and
`http://localhost:<port>` of the bound listener - crosses the
admission on its own explicit path
(`IntakeAdmissionPath.bridgeOrigin`), never through the allow-all
mode. The same gates bind it as a listed origin: the browser
send-method checks, the listed per-origin quota, the host-authority
gate, and the seat caps - and under `OriginPolicy.requireOriginWithToken`
the page needs the shared token or a pairing proof exactly like any
qualified origin (the pairing door accepts the served origin too).
Any other loopback origin - another port included - stays refused
exactly as before. A page path colliding with `/pair` or the
WebSocket path, a duplicate path, or an empty list throw
`ArgumentError` at server construction.

```dart
final bridge = LocalIntakeServer(
  // ... your wiring ...
  config: const BridgeConfig(
    localPages: [
      BridgeLocalPage(
        path: '/status',
        content: '<!doctype html><html><body>'
            '<h1>Printer status</h1><pre id="out">idle</pre>'
            '<script>fetch("/", {method: "POST",'
            ' headers: {"Content-Type": "application/json"},'
            ' body: JSON.stringify(["STATUS"])});</script>'
            '</body></html>',
      ),
    ],
  ),
);
```

## The listeners, the lifecycle, and the health page

Three options extend where and how the bridge listens, plus the mobile
lifecycle pair and the instance identity. Each option is off by default:
the disarmed wire is letter identical to previous releases.

**The optional `::1` listener** — `BridgeConfig.listenIPv6Loopback: true`
binds a second listener on `::1` (loopback IPv6, IPv6-only — never
dual-stack) at the same port, and the local host authorities widen in the
same start with the `[::1]:port` and bare `::1` spellings: a request
naming them passes the Host gate only while that listener is actually
bound. A host that cannot bind `::1` (IPv6 disabled) warns once and
keeps serving on `127.0.0.1` alone.

**The optional unix-socket listener** (Linux and macOS only) —
`BridgeConfig.unixSocketPath: "/run/myapp/bridge.sock"` also serves HTTP
on this filesystem path for local CLI clients. The socket file's
owner-only permissions (mode 0600, enforced at bind by the system
`/bin/chmod` at its full path and verified by reading the file's
actual mode before anything is served) are the transport boundary, and
the socket's parent directory must already be owner-only (mode 0700):
the file is born with the process's permissions and tightens a moment
later, so the socket is only ever created where no other user can
traverse - a permissive parent fails the whole start naming the
directory (judged once, before any port is tried), and a chmod or
verification failure fails it, so no unguarded socket ever serves. Two
honest limits of that boundary: the
parent check reads the directory's permission **mode** only - `dart:io`
exposes no owner identity - so on a host running as root (where every
path is traversable and the mode bits are the only fact checked) the
mode is the sole guarantee; and on a system without `/bin/chmod` at
its fixed path the start fails closed with the failure message naming
the tool. The request rides the same
single admission step with no Origin (cross by the token alone; a CLI
that sends no fetch metadata needs `OriginPolicy.requireFetchMetadata:
false`, the standing headerless switch) behind the same Host gate (an
HTTP/1.1 client sends `Host: localhost`). A path that is already
occupied (any existing file, stale socket included) fails the start with
`IntakeBindException` — the package never deletes a path it did not
create — and the socket file the package itself created is removed at
`stop` - and when its bind fails the owner-only guard - so a restart
on the same path rebinds cleanly. The
open-connection cap counts this listener too.

**The TLS listener** — `BridgeConfig.securityContext` (a ready
`SecurityContext` you pass in) binds the bridge's TCP listeners — the
`127.0.0.1` listener and the optional `::1` listener — as plain
listening sockets fed through the package's TLS handshake gate, so the
address the browser uses becomes
`https://127.0.0.1:<port>` (and `wss://` for the WebSocket channel),
and a served local page's own origin arms as its `https://` spelling.
The gate reads the first full TLS record: a first byte that is not a
handshake record (a plain HTTP client on the TLS port) is cut at once
with no bytes sent back, a first record declaring a length over the
transport record maximum is cut at once, and a first record that never
completes inside `BridgeConfig.tlsFirstRecordTimeout` (five seconds by
default, bounds one to sixty seconds) is cut at the deadline — every
one of those cuts lands while the socket is still unarmed, which is
the one state where the cut reaches the wire, so a silent client and
a slow-dripping client are destroyed on the wire, not left hanging.
What the gate cannot do is stated honestly in the limits section
below: a client that completes its first record and then goes silent
is armed by then; after arming the package holds only the detached
wrapper socket, so `destroy` and `close` on it do not reach the peer
and `stop` does not reap it, and dart:io exposes no public API that
hands the raw engine socket back wrapped as the `Socket` shape
`HttpServer.listenOn` consumes — the in-flight handshake ceiling and
the count are the bound there. This is
the condition Safari and WebKit name themselves: their
mixed-content checker treats a plain-HTTP loopback address as insecure
"unless loaded over HTTPS" (see the browser-support table below). The
package never generates a certificate, never installs or trusts one,
and never reads or writes any file for TLS: you supply a
`SecurityContext` that already carries a certificate chain and its
private key, and the device's trust in that certificate is entirely
your responsibility — installing a locally issued certificate
authority on a device is a decision to weigh against its risks (the
device will trust anything that authority signs, for every app on it,
until it is removed). The admission, the wire codes, and every reply
contract are byte-for-byte the same over either transport — the one
exception is the connection cap itself: over `maxOpenConnections` a
new TLS connection is cut before arming with no reply, where the plain
door answers `503`.
The option is off by default: with `securityContext` left null every
bind path stays letter identical and the port speaks plain HTTP.
Setting it together with `unixSocketPath` throws `ArgumentError` at
construction — dart:io has no secure unix-domain bind, and a listener
silently staying plain under a TLS option would promise cover it does
not deliver. The read-only counters (`server.counters`) carry the
TLS feed's tallies: handshakes in flight, sockets cut on the wire
(cumulative), and handshakes delivered (cumulative). A socket its own
peer abandons (connects, then closes or errors before arming) is
destroyed at the moment of abandonment — no handle lingers — and
`stop` reaps every socket still before arming at once and announces —
in one line, only when the count is above zero — how many handshakes
were left stuck past arming. A practical lab for the real-Safari witness on a mac you
own: `dart run tool/safari_https_loopback_lab.dart --cert <pem> --key
<pem>` (the tool prints its steps and reads its flags; it never
generates or installs a certificate).

**`pause()` and `resume()`** — the mobile lifecycle pair: `pause()`
closes every bound listener under the same graceful drain `stop()` runs
(in-flight replies finish, seats are awaited, orphans get their budget)
and remembers the bound port; `resume()` rebinds on that exact port with
no fallbacks — a silent port move would break every client pinned to the
address. If another process took the port meanwhile, resume refuses with
`IntakeBindException` naming the remembered port as taken, and the pause
state survives so the host can retry once the port frees. The instance
identity carries across untouched; `start()` while paused supersedes it
(the remembered port is forgotten, and `resume()` afterwards reads `not
paused`). The errors are `StateError`s through the returned future,
mirroring `start()`.

**`BridgeInstanceInfo`** — `server.instanceInfo` reads the pinning
identity while a listener is bound: `port` (the actually bound port,
never the requested one), `instanceId` (32 hex characters of secure
random, generated once per server object, stable across pause/resume and
across stop/start generations), and `protocolVersion`
(`BridgeInstanceInfo.bridgeProtocolVersion` — the wire-contract version,
not the package release). `instanceId` stays readable while paused; the
full snapshot throws `StateError` until a listener is bound again.

**The health page** — `BridgeConfig.healthPath: '/health'` arms a `GET`
route on exactly that path. It passes the standing gate like every
request — the origin and Host gates, the seat caps, and the one
admission step with its settle — and answers the accepted origin alone:
the body is literally `{"ok":true}`. No version number, no counters, no
details, so the page can never be used to fingerprint the host. A
non-accepted origin reads the standing refusal with no CORS echo, so a
browser probe reveals nothing. The page answers on the bridge's own
listener only (a forwarded `GET` on a mounted door answers `405` like
any non-POST). Disarmed (the default), the path answers `405
method_not_allowed` like every `GET`.

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
| Safari, and iOS browsers built on WebKit | not supported over plain HTTP — WebKit's own mixed-content checker treats a plain-HTTP loopback address as insecure "unless loaded over HTTPS" ([WebKit bug 281149](https://bugs.webkit.org/show_bug.cgi?id=281149), reopened, last change 2026-04-20, fetched 2026-11-22); the spec-level exemption requests remain open ([WebKit bug 171934](https://bugs.webkit.org/show_bug.cgi?id=171934), NEW with activity through 2026-08-19, fetched 2026-11-22 · [WebKit bug 218623](https://bugs.webkit.org/show_bug.cgi?id=218623), NEW, fetched 2026-11-22), and MDN's mixed-content page (last modified 2026-08-15, fetched 2026-11-22) names Safari as the browser whose default blocks all mixed content while loopback origins stay secure contexts as origins. The TLS option above is exactly the condition WebKit's checker names ("unless loaded over HTTPS") — but whether a current shipped Safari build admits `https://127.0.0.1` with a device-trusted certificate is **not** claimed here: it is the device-lab witness (`tool/safari_https_loopback_lab.dart`), unverified until a trusted-certificate mac runs it. Apple permits other engines in the EU (iOS 17.4+); none is tested here | 2026-11-22 | [WebKit bug 281149](https://bugs.webkit.org/show_bug.cgi?id=281149) · [WebKit bug 171934](https://bugs.webkit.org/show_bug.cgi?id=171934) · [MDN: Mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content) · [Apple: alternative browser engines](https://developer.apple.com/support/alternative-browser-engines) |
| Android WebView | tested on the emulator (Android 16 and 17) — no permission prompt of its own; reachability follows the permissions of the app embedding the WebView. An app that loads a loopback page over plain HTTP into a WebView on Android 16 or below must opt into cleartext for the loopback names in its network security config (the guide's bullet below carries the example), or the platform refuses the page with `ERR_CLEARTEXT_NOT_PERMITTED` before it reaches the bridge; Android 17 allows the loopback page without the declaration, as measured on the emulator. On Android 17, WebView traffic inherits the host app's local-network permission state, and the `ACCESS_LOCAL_NETWORK` permission applies only to apps targeting SDK 37; the official local-network definition does not mention loopback | 2026-11-23 | [Android: Network security configuration](https://developer.android.com/privacy-and-security/security-config) · [Android: local network permission](https://developer.android.com/privacy-and-security/local-network-permission) · [Android: local network definition](https://developer.android.com/privacy-and-security/local-network-definition) |

"Shipped" means the page can send and read a reply after the user grants
the prompt. The fetch-mode hardening does not depend on any prompt — it
applies wherever the request arrives.

The legacy Private Network Access answer header
(`Access-Control-Allow-Private-Network`) is deliberately absent from
every preflight this package writes: verified against the vendors'
official pages on 2026-11-22, no current browser asks for it. Chrome's
Local Network Access guide says "DO NOT rely on deprecated Private
Network Access (PNA) preflight headers" and "PNA preflights were never
enforced as a blocking requirement and are not needed as a fallback"
([Chrome: Local Network Access guide](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access), fetched 2026-11-22); the PNA rollout was put on hold before any enforcement shipped ([Chrome: Private Network Access on hold](https://developer.chrome.com/blog/pna-on-hold), published 2024-10-09: "This rollout is currently on hold", "PNA preflights are not currently enforced"), and Chrome ships the Local Network Access permission prompt instead, launching in Chrome 142 ([Chrome: Local Network Access](https://developer.chrome.com/blog/local-network-access), published 2025-06-09: "Local Network Access replaces that effort, after PNA was put on hold"); Firefox asks permission before connecting to local devices, the restrictions on by default since 153.0 and no preflight header named ([Firefox 153.0 release notes](https://www.firefox.com/en-US/firefox/153.0/releasenotes/), 2026-07-21: "Local Network Access restrictions are now enabled by default for all users", "Firefox requires websites to request permission before connecting to devices on your local network or to apps and services on your device"); and MDN no longer documents the header at all — the header page and the Private Network Access concept page both answered HTTP 404 on 2026-11-22, and the current [MDN: Local network access](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access) page (last modified 2026-08-12) documents permission prompts only. What could not be verified on the vendors' own pages that day: any Apple or WebKit statement about PNA preflights — the [WebKit Features for Safari 26.2](https://webkit.org/blog/17640/webkit-features-for-safari-26-2) post fetched on 2026-11-22 names no Local Network Access — so no Safari claim rides this line.

## Host platforms

| Host platform | Status | As of | Source |
|---|---|---|---|
| Desktop (Windows, macOS, Linux) | shipped — the usual loopback server model; Windows and Linux put no platform gate on it, while a macOS host inside App Sandbox needs the `com.apple.security.network.server` entitlement | 2026-11-15 | [Apple: App Sandbox entitlements](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.server) |
| Android | shipped — an in-app loopback server; run the host app foregrounded or behind a foreground service, or the system may stop it. A loopback page reaches a loopback bridge with no permission grant — measured on the emulator on Android 16 and 17 with Chrome, Firefox, and WebView (WebView with its cleartext opt-in). A real page from the Internet was not measured; with the lab page mapped to the public address space in its place, Chrome 145 on Android 17 shows the Local Network Access prompt, the request that raises it fails, a later load crosses after Allow, and a later load stays blocked with no new prompt after Block; Chrome 134 on the Android 16 image carries no Local Network Access check and crosses with no prompt; Firefox was not measured that way. On Android 17, loopback traffic between two profiles (work and personal) is blocked by default for every app regardless of targetSdk; loopback within one profile is unaffected. On Android, any installed app can reach the port and send any `Origin`, so the origin+token requirement with pairing is the real barrier there: the page pairs with a displayed one-time code and proves possession with HMAC signatures - an installed app can present the same listed origin but cannot sign. Native clients on the device send the shared token. With the requirement off (the default), a browser page presents the token only where its preflight is echoed: a listed origin, or any valid https origin not yet refused under the discovery and allow-all modes - and an installed app can present that same listed origin. The emulator side of the pairing story is runnable with `dart run tool/emulator_pairing_lab.dart` (adb reverse commands and the page URL are printed; the verdicts are read from the page's report collector). | 2026-11-23 | [Android: local network permission](https://developer.android.com/privacy-and-security/local-network-permission) · [Android 17 behavior changes](https://developer.android.com/about/versions/17/behavior-changes-all) |
| iOS | untested here — no verified browser path: WebKit treats a plain-HTTP loopback address as insecure "unless loaded over HTTPS" (mixed content — the Safari row above, fetched 2026-11-22), and iOS suspends in-app sockets when the host app backgrounds | 2026-11-22 | [WebKit bug 281149](https://bugs.webkit.org/show_bug.cgi?id=281149) · [WebKit bug 171934](https://bugs.webkit.org/show_bug.cgi?id=171934) |

### The mobile host (Android and iOS) — verified 2026-11-21

Every line below was verified against the vendor's official
documentation on 2026-11-21 (a live read of each linked page that day);
the source and that date ride the line. Lines that name no vendor fact
(such as the wiring guidance) say so.

**Android**

- Keep the host app foregrounded, or run the server behind a foreground
  service: the foreground service is the platform's form for work that
  is noticeable to the user while they are not directly interacting
  with the app, and it carries a status-bar notification. The official
  guidance: "Only use a foreground service when your app needs to
  perform a task that is noticeable by the user, even when they're not
  directly interacting with the app." Verified 2026-11-21 —
  [Android: Foreground services overview](https://developer.android.com/develop/background-work/services/fgs)
- Pair `pause()` with the background lifecycle callback and `resume()`
  on the foreground return — the same port and the same instance id come
  back (see the listeners and lifecycle section above). Wiring guidance,
  not a vendor fact.
- Chrome (desktop and Android) covers loopback destinations with the
  Local Network Access prompt: the permission's scope explicitly covers
  loopback destinations (`127.0.0.0/8` and `::1/128`), and the prompt
  launched in Chrome 142. Verified 2026-11-21 —
  [Chrome: New permission prompt for Local Network Access](https://developer.chrome.com/blog/local-network-access).
  Measured on the emulator 2026-11-23: the prompt appears for a page
  mapped to the public address space and not for a loopback page (the
  Android row of the host platform table above carries what Allow and
  Block each did).
- Firefox ships the same model: release 153.0 (July 21, 2026) enabled
  Local Network Access restrictions by default for all users —
  websites must request permission before connecting to devices on the
  local network or to apps and services on your device. Verified
  2026-11-21 —
  [Firefox 153.0 release notes](https://www.firefox.com/en-US/firefox/153.0/releasenotes/)
- The Android 17 local-network permission: starting with Android 17
  (API level 37), local-network protections are enforced for apps
  targeting SDK 37 or higher behind the `ACCESS_LOCAL_NETWORK` runtime
  permission (in the `NEARBY_DEVICES` group); accepting an incoming TCP
  connection on a local-network address is among the gated facts, and
  WebView traffic inherits the host app's permission state. The
  official local-network definition lists link-local, CGNAT, and
  RFC1918 ranges plus multicast/broadcast and does not mention loopback
  — the bridge's `127.0.0.1` listener is not in that scope. Verified
  2026-11-21 —
  [Android: Local network permission](https://developer.android.com/privacy-and-security/local-network-permission) ·
  [Android: local network definition](https://developer.android.com/privacy-and-security/local-network-definition)
- WebView and a loopback page over plain HTTP: cleartext support is
  disabled by default (since Android 9, API level 28), so an app that
  loads a `http://127.0.0.1` page into a WebView on Android 16 or below
  must opt into cleartext for the loopback names in its network
  security config — referenced from the manifest with
  `android:networkSecurityConfig="@xml/network_security_config"` — or
  the platform refuses the page with `ERR_CLEARTEXT_NOT_PERMITTED`
  before it reaches the bridge. Android 17 allows the loopback page
  without the declaration, as measured on the emulator. The opt-in:

  ```xml
  <network-security-config>
    <domain-config cleartextTrafficPermitted="true">
      <domain includeSubdomains="false">127.0.0.1</domain>
      <domain includeSubdomains="false">localhost</domain>
    </domain-config>
  </network-security-config>
  ```

  Verified 2026-11-23 —
  [Android: Network security configuration](https://developer.android.com/privacy-and-security/security-config)
- Cross-profile loopback: beginning with Android 17, cross-profile
  loopback traffic is no longer permitted by default, for every app
  running on Android 17 or higher regardless of target API level;
  loopback traffic within the same profile is not affected. Verified
  2026-11-21 —
  [Android 17 behavior changes](https://developer.android.com/about/versions/17/behavior-changes-all)
- Play declaration: apps that request `ACCESS_LOCAL_NETWORK` must
  submit a Play Console declaration to justify access and explain why
  the device pickers are not sufficient, and the permission is
  restricted to apps that need it for core functionality. Verified
  2026-11-21 —
  [Play: Permissions and APIs policy](https://support.google.com/googleplay/android-developer/answer/16909972)
- The emulator side of the lifecycle story is runnable with
  `dart run tool/emulator_pause_resume_lab.dart --pause-after-ms 8000
  --resume-after-ms 8000` — the tool prints the `adb reverse` commands
  and the page URL up front, then prints the `KEYCODE_HOME` command at
  the pause moment and the foreground command at the resume moment, and
  reads the page's three marks (open:OK, paused:FAIL, resumed:OK on the
  same port) for its PASS/INCOMPLETE verdict. A tool, not a vendor fact.

**iOS**

- There is no server in the background: when the app moves to the
  background the system gives `applicationDidEnterBackground(_:)` five
  seconds and "shortly after that method returns, the system puts your
  app into the suspended state" — a loopback listener does not survive
  suspension. Extended runtime exists only through
  `beginBackgroundTask` (bounded, and the system terminates the app if
  tasks are not ended in time), so the honest shape is the same pair:
  `pause()` on the background callback, `resume()` on the foreground
  return. Verified 2026-11-21 —
  [Apple: Extending your app's background execution time](https://developer.apple.com/documentation/uikit/extending-your-app-s-background-execution-time)
- There is no browser path to a loopback HTTP server on iOS (the
  browser-support table above). The iOS host integration is the
  in-process feed (`acceptHostFeed` behind a `WKScriptMessage`
  callback) instead of a network listener — this is this project's own
  integration choice, not a vendor-documented fact, so no source line
  claims it.

### When this package fits

The bridge is built for pages driving local commands where a silent or
replayed send must be stopped by barriers, not by luck: irreversible
commands (print, pay, unlock, open a file, change device state) where
you want origin admission, consent questions, quotas, and
a deduplication ledger around every send - `DedupLedger` with
`idempotentCommand` ships in the package
(`example/idempotent_handler.dart` is the wiring demo). The
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

Addressing: the server binds `127.0.0.1` by default, so page code should
use `127.0.0.1` — a `localhost` name can resolve to `::1` (IPv6), where
nothing listens unless `BridgeConfig.listenIPv6Loopback` is armed, and
another local program can listen on `::1` at the same port number while
the bridge is running. The optional unix-socket listener
(`BridgeConfig.unixSocketPath`) adds a filesystem transport for local
CLI clients on Linux and macOS.

## Limits (by design)

- Loopback only: `127.0.0.1` by default; the optional `::1` listener
  (`BridgeConfig.listenIPv6Loopback`) and the optional unix-socket
  listener (`BridgeConfig.unixSocketPath`, Linux/macOS) join only when
  armed — never a non-loopback or network-facing address.
- The TLS transport bounds its own handshake window, and states
  honestly what stays outside its reach: the first full TLS record is
  gated — a non-handshake first byte and an over-cap declared length
  are cut at once with no bytes sent back, a silent client and a
  slow-dripping client are cut at `BridgeConfig.tlsFirstRecordTimeout`
  (five seconds by default, bounds one to sixty seconds), and every
  one of those cuts lands while the socket is unarmed, which is the
  one state where the cut reaches the wire. What the package cannot
  build — dart:io offers no public lever for it: after arming the
  package holds only the detached wrapper socket, so `destroy` and
  `close` on it do not reach the peer and `stop` does not reap it, and
  no public API hands the raw engine socket back wrapped as the
  `Socket` shape `HttpServer.listenOn` consumes — so a client that
  completes its first record (a real ClientHello) and then goes silent
  holds an in-flight slot until the peer closes it. The bound there is
  the ceiling: the TLS feed counts its in-flight handshakes into the
  open-connection cap (`BridgeConfig.maxOpenConnections`) while that
  option is on, and holds its own internal 64-handshake ceiling while
  the option is off — a ceiling over the in-flight handshakes alone,
  never over delivered connections (sixty-four completed connections
  with the option off never refuse the next sender) — cutting the new
  socket before arming it, and `stop` announces in one
  line how many handshakes were left stuck past arming. A host serving
  TLS on a hostile network reads the same honesty front to back:
  everything before the first record is the package's to bound,
  everything after it is bounded by ceilings and counted, never
  silenced.
- JSON nesting is capped in the same pre-decode pass (`maxJsonDepth`,
  default 32) — deeper bodies get the same `413 payload_too_complex`
  before `jsonDecode` runs.
- If you pass fallback ports to `start()`, the page must use the port
  `start()` returns — never assume the preferred one (a same-session
  program may hold it).
- The handler budget is on by default (`BridgeConfig.handlerTimeout`,
  30 seconds shipped): a handler running past it is answered `504
  handler_timeout`, its seat is freed, and the still-running work
  becomes a counted orphan. `stop({Duration? timeout})` is bounded by
  its timeout when given, returns a `BridgeStopReport` naming what
  still runs, and retires whatever orphans remain at its return — a
  restart never inherits the previous generation's orphans into its
  live-work budget, while they stay visible in the read-only counters
  (`server.counters`: seats, orphans across generations with the
  retired ones named, rejections by wire code, and the protocol-shape
  and pairing tallies). Only the explicit
  `LocalIntakeServer.noHandlerTimeout` constant removes the deadline —
  null selects the configured default budget — and under it sixteen
  stuck handlers still mean every further sender is refused (`503
  server_busy` past the global cap, `503 origin_seat_limit` past its
  own share). A handler may also read the cooperative cancel signal
  (`TrustedCommand.cancellation`) — the intake fires it at the budget
  expiry and at stop — and the host may watch
  `onOrphanSettled` for each orphan settlement.
- One sender cannot monopolize the seats: `BridgeConfig.maxSeatsPerOrigin`
  (default 4 of the 16) bounds the seats a single origin holds at once,
  requests without an `Origin` header share one originless bucket under
  the same cap, and an `OPTIONS` preflight counts into its origin's
  share exactly like a command. The gate lives inside the global seats:
  the full server still answers `server_busy` first, a value at or above
  `maxConcurrentRequests` never binds, and one origin filling its share
  never deducts from another origin's — each sender is bounded by its
  own bucket. The pairing layer's session and record caps are
  protection-state limits, not seats: a paired page's signed requests
  count into its origin's seat share like any other request. Past the
  share the sender reads `503 origin_seat_limit`.
- `dart:io` never bounds the sockets a listening server has accepted,
  so a host that wants a hard ceiling on open connections sets
  `BridgeConfig.maxOpenConnections` above zero: a request arriving while
  more sockets than the cap are open answers `503 server_busy`, and
  once the count drops (senders finish, idle sockets close after
  `idleTimeout`) the next request is served. The count is the sum over
  every bound listener plus the TLS transport's in-flight handshakes,
  and on the TLS door the cap cuts the new socket before arming it —
  the one cut that reaches the wire — instead of answering it. `0` —
  the default — keeps the option off, and the wire never refuses for
  open sockets alone; the TLS transport then holds its own internal
  64-handshake ceiling over the in-flight handshakes alone — a
  delivered connection is never counted as an in-flight handshake and
  never refused for open sockets — because a handshake stuck past
  arming is the one socket the server can never free by itself.
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
  while the wire carries the literal code; the preflight round trip
  announces `X-Bridge-Token`; and a paired page runs the whole pairing
  story in the browser - pair with the displayed code, sign with
  WebCrypto, read `200`, watch the same signature refused
  `pair_signature_replay`, and read the proofless `token_required`.
  Without a browser the lab skips itself and
  states why; CI runs it where the runner image ships Chrome; and the
  emulator side runs with `dart run tool/emulator_pairing_lab.dart`.

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
