# Migrating to localhost_bridge 0.2.0

0.2.0 renames the three intake names and removes the old ones with no
deprecation window: the old header name is not accepted, the old
generator does not exist, and the originless command source marker
carries the new value. This guide names the three renames and the path
for each; later 0.2.0 items extend this guide as they land. It also
changes two defaults on purpose - the per-origin seat share and the
listed-origin rate budget - both documented below.

## The per-origin seat share is bounded by default

0.1.x let one origin hold all sixteen concurrency seats; 0.2.0 bounds
each origin's share to `BridgeConfig.maxSeatsPerOrigin` (default 4).
A monopolizing origin past its share now reads `503 origin_seat_limit`
instead of pushing every other sender into `503 server_busy`.

- A page that legitimately holds more than four concurrent commands
  (a dashboard firing batches) raises the value: `BridgeConfig(
  maxSeatsPerOrigin: 8)` - a value at or above `maxConcurrentRequests`
  never binds, which restores the 0.1.x shape exactly.
- Requests without an `Origin` header (the token layer's clients) share
  one originless bucket under the same cap; split heavy integrations
  across distinct tokens if one bucket is too small for them.
- Nothing else moves: the global seats, the pairing layer, and the
  quotas keep their contracts, and one origin filling its share never
  deducts from another origin's.

## Listed origins ship with a rate budget

0.1.x left listed origins unquotaed (`listedPerOriginPerMinute` was 0);
0.2.0 defaults it to 120 requests/minute per listed origin. Over the
budget the page reads `429 origin_rate_limited` with the honest
`Retry-After` - it already handles that code on the allow-all path.

- A listed page that can legitimately burst past 120 commands a minute
  raises the value, or writes `listedPerOriginPerMinute: 0` explicitly
  to restore the 0.1.x unquotaed shape.
- Nothing else moves: the same code, the same honest `Retry-After`, and
  watch mode (`reportOnly`) still covers the quota before you commit to
  it.

## The three renames

| 0.1.x | 0.2.0 | Where it shows |
|---|---|---|
| `X-Portal-Token` | `X-Bridge-Token` | the token header a client sends |
| `generatePortalToken()` | `generateBridgeToken()` | the token generator (`IntakeProtection`'s library export) |
| `'unknown-portal'` | `'unknown-origin'` | the value of `TrustedCommand.source` when the request carried no `Origin` header |

## Migrating the header

Send the token in `X-Bridge-Token`:

```bash
curl -X POST http://127.0.0.1:9100/ \
  -H 'Content-Type: application/json' \
  -H "X-Bridge-Token: $BRIDGE_TOKEN" \
  -d '{"data": ["your-command"]}'
```

A request that still carries `X-Portal-Token` is treated as a request
without a token: the token layer ignores the value entirely, so a
closed or unqualified origin policy answers the same rejection it would
answer a tokenless request. The bridge writes one muted security
warning per second naming `X-Bridge-Token`, so the log tells the
developer why the token did not authenticate; a flood of legacy-header
requests produces one line per second with the suppressed count on the
next line, never a log flood.

If both headers travel in one request, the new header is the token: the
legacy value is ignored and the warning still fires while the legacy
header remains.

Browser pages see the new name in the preflight: the
`Access-Control-Allow-Headers` list carries `X-Bridge-Token` alone, so
a page still sending the old name gets a preflight that does not allow
it and the request never leaves the browser.

## Migrating the generator

```dart
// 0.1.x
final token = generatePortalToken();
// 0.2.0
final token = generateBridgeToken();
```

The shape is unchanged: 64 hex characters from a secure random source.

## Migrating the source marker

Hosts that branch on `TrustedCommand.source` compare against
`'unknown-origin'` instead of `'unknown-portal'`. The value appears
only when the request carried no `Origin` header (local command-line
clients and similar).

## The wire surfaces that changed with the names

- The token length cap answers `400 token_too_long` over an
  `X-Bridge-Token` header longer than 1,024 UTF-8 bytes; the message
  names the new header.
- The single-value header gate refuses a duplicated `X-Bridge-Token`
  with `400 duplicate_header`.
- The `Access-Control-Allow-Headers` list is
  `Content-Type, X-Bridge-Token, X-Correlation-Id`.

## The origin+token requirement and pairing (new in 0.2.0)

Everything below is **off by default** - a host that configures only
what it configured in 0.1.x sees today's wire letter by letter.

### Requiring the origin and the token together

Set `OriginPolicy.requireOriginWithToken: true` when your page must be
admitted while other local programs must not. The mode closes the two
one-legged doors:

- a qualified origin without a valid token answers `403 token_required`
  (readable for the qualified origin, so its page can retry with a
  proof);
- the token alone - correct or not - never admits from an unqualified
  origin or with no Origin at all: the origin rejection answers it, and
  a sender learns nothing about its token.

Headerless native clients have **no door** in this mode: run them on a
separate listener (or leave the requirement off there). Wrong shared
tokens still feed the wrong-guess budget (`429 token_locked` above it),
and `token_required` is a registry row in the wire tables.

### Pairing a browser page

Arms through `protection.enablePairing(...)`: the host displays a
six-digit code from `startPairing()` (120-second life), the page sends
`{"pairingCode": "..."}` to `POST /pair` with its origin, and receives
`{"ok": true, "token": ..., "pairingId": ..., "expiresInSeconds": 86400}`
- a token bound to that origin, expiring after 24 hours. The host is
told through `onPaired`; `revokePairedOrigin(origin)` kills the
bindings at once and `rotatePairedOrigin(origin)` revokes and offers a
fresh code. The save hooks (`onPairedSave`, `onPairedRevoke`,
`onConsentSave`) hand persistence to the host - the package writes no
file - and `restorePairedOrigin` / `restoreSavedConsent` re-arm what
the host persisted after a restart.

Pairing adds one wire surface while armed: the `X-Bridge-Pairing`
header joins the allowed CORS list, and `POST /pair` answers the
pairing codes (`pair_code_invalid`, `pair_code_expired`,
`pair_budget_exceeded`). Disarmed, `/pair` is no path at all - the
ordinary non-root behavior rides, wire letter unchanged.

### Proving possession instead of sending the token

The paired page never sends its token raw: it signs every request -
HMAC-SHA-256 over the canonical string
`v1\n<pairingId>\n<stampMs>\n<METHOD>\n<path>\n<correlationId>`, keyed
by the token's 32 decoded bytes - and presents
`X-Bridge-Pairing: <pairingId>.<stampMs>.<signature>`. The stamp is the
page's `Date.now()`; keep it unique (never sign twice within one
millisecond) and within one minute of the server's clock. A reused or
stale signature reads `403 pair_signature_replay` - sign a fresh
request. The page-side reference in README.md shows the whole WebCrypto
helper, and `dart run tool/emulator_pairing_lab.dart` drives the same
story against an emulator's browser.

## The handler budget default

In 0.1.x, `handlerTimeout` was null by default and null meant "no
deadline": a stuck handler held its seat forever, `stop()` waited for it
without a bound, and orphaned handlers kept counting across a restart -
after sixteen of them, every command was answered `503 server_busy`.

In 0.2.0:

- Leaving `handlerTimeout` at null selects the configured default
  budget: `BridgeConfig.handlerTimeout`, 30 seconds shipped. A handler
  running past the budget is answered `504 handler_timeout` (the reply
  and the "outcome unknown" contract are unchanged), its seat is freed,
  and the still-running work becomes a counted orphan.
- To keep the old unbounded behavior, pass the named constant:
  `handlerTimeout: LocalIntakeServer.noHandlerTimeout`. Its value is
  `Duration.zero` - which used to throw `ArgumentError` and is now the
  constant's value; a negative duration still throws at construction.
- `stop({Duration? timeout})` returns a `BridgeStopReport`. With a
  timeout the whole drain is bounded and the report names what still
  runs; without one the full drain is waited out, as before. At every
  stop's return the still-working orphans are retired: the next `start()`
  serves from a clean live-work budget while the retired orphans stay
  visible in `server.counters` until they settle.
- New reads and hooks need no migration: `server.counters` (seats,
  orphans across generations, rejections by code, and the protocol-shape
  and pairing tallies), `onOrphanSettled`, and
  `TrustedCommand.cancellation` are additive; commands built by hand
  carry the const never-cancelled signal and keep compiling.
- The pairing layer's idle sweeps are wire-compatible: only a session
  swept by idleness answers `pair_code_invalid` for its code instead of
  `pair_code_expired` (both 403, both telling the page to pair again).
