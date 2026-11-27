# Migrating to localhost_bridge 0.2.0

Every breaking change in 0.2.0 has exactly one section here, in the
CHANGELOG's order: what was, what is now, and what you change in your
code, each with a short example. Everything else in 0.2.0 is additive
or off by default - a host that configures only what it configured in
0.1.x keeps its wire letter, inside the five changes below.

## One sender can no longer monopolize the seats

**What was:** 0.1.x let one origin hold all sixteen concurrency seats:
a listed page - or one allow-all page - firing slow requests answered
every other sender `503 server_busy`.

**What is now:** each origin's share is bounded by
`BridgeConfig.maxSeatsPerOrigin` (default 4 of the 16). Past its share
the sender reads `503 origin_seat_limit` while the server still has
room for others. Requests without an `Origin` header (the token
layer's clients) share one originless bucket under the same cap, and
an `OPTIONS` preflight counts into its origin's share exactly like a
command. The gate lives inside the global seats: the full server
still answers `server_busy` first, a value at or above
`maxConcurrentRequests` never binds, and one origin filling its share
never deducts from another origin's.

**What you change:** nothing, if no sender legitimately holds more
than four concurrent commands. A dashboard firing batches raises the
share - and a value at or above `maxConcurrentRequests` restores the
0.1.x shape exactly:

```dart
import 'package:localhost_bridge/localhost_bridge.dart';

const config = BridgeConfig(
  // A dashboard that legitimately holds eight concurrent commands.
  // A value at or above maxConcurrentRequests never binds, which is
  // the 0.1.x shape.
  maxSeatsPerOrigin: 8,
);
```

## Listed origins ship with a rate budget

**What was:** 0.1.x left listed origins unquotaed
(`listedPerOriginPerMinute` was 0), so one compromised listed page
could flood the shared seats without a budget.

**What is now:** it defaults to 120 requests/minute per listed origin.
Over the budget the page reads `429 origin_rate_limited` with the
honest `Retry-After` - the code the allow-all path already answers, so
a page that handles it there handles it here. Watch mode
(`reportOnly`) still covers the quota before you commit to it.

**What you change:** nothing, unless a listed page legitimately bursts
past 120 commands a minute. Raise the value, or write `0` explicitly
to restore the 0.1.x unquotaed shape:

```dart
import 'package:localhost_bridge/localhost_bridge.dart';

const policy = OriginPolicy(
  // The explicit documented opt-out: listed origins stay unquotaed,
  // as in 0.1.x.
  listedPerOriginPerMinute: 0,
);
```

## The handler budget is on by default

**What was:** in 0.1.x `handlerTimeout` was null by default and null
meant "no deadline": a stuck handler held its seat forever, `stop()`
waited for it without a bound, and orphaned handlers kept counting
across a restart - after sixteen of them, every command was answered
`503 server_busy`.

**What is now:** leaving `handlerTimeout` at null selects the
configured default budget: `BridgeConfig.handlerTimeout`, 30 seconds
shipped. A handler running past the budget is answered `504
handler_timeout` (the reply and the "outcome unknown" contract are
unchanged), its seat is freed, and the still-running work becomes a
counted orphan; `stop()` awaits orphans up to the same budget and
retires whatever remains at its return.

**What you change:** nothing, if 30 seconds suits every handler. To
keep the old unbounded behavior, pass the named constant - its value
is `Duration.zero`, which used to throw `ArgumentError` and is now the
constant's value; a negative duration still throws at construction:

```dart
import 'package:localhost_bridge/localhost_bridge.dart';

final server = LocalIntakeServer(
  onCommand: (command) async => const CommandOutcome(ok: true),
  // The 0.1.x unbounded behavior: Duration.zero, no deadline at all.
  handlerTimeout: LocalIntakeServer.noHandlerTimeout,
);
```

## The three intake names are renamed, the old ones removed with no deprecation window

| 0.1.x | 0.2.0 | Where it shows |
|---|---|---|
| `X-Portal-Token` | `X-Bridge-Token` | the token header a client sends |
| `generatePortalToken()` | `generateBridgeToken()` | the token generator (a library export of the package) |
| `'unknown-portal'` | `'unknown-origin'` | the value of `TrustedCommand.source` when the request carried no `Origin` header |

**What you change:** send and compare the new names only - the old
header is not accepted, the old generator does not exist, and the
marker carries the new value.

The header: send the token in `X-Bridge-Token`:

```bash
curl -X POST http://127.0.0.1:9100/ \
  -H 'Content-Type: application/json' \
  -H "X-Bridge-Token: $BRIDGE_TOKEN" \
  -d '{"data": ["your-command"]}'
```

A request that still carries `X-Portal-Token` is treated as a request
without a token: the token layer ignores the value entirely, so a
closed or unqualified origin policy answers the same rejection it
would answer a tokenless request. The bridge writes one muted security
warning per second naming `X-Bridge-Token`, so the log tells the
developer why the token did not authenticate; a flood of legacy-header
requests produces one line per second with the suppressed count on the
next line, never a log flood. If both headers travel in one request,
the new header is the token and the warning still fires while the
legacy header remains. Browser pages see the new name in the
preflight: the `Access-Control-Allow-Headers` list carries
`X-Bridge-Token` alone, so a page still sending the old name gets a
preflight that does not allow it and the request never leaves the
browser. The token length cap answers `400 token_too_long` over an
`X-Bridge-Token` header longer than 1,024 UTF-8 bytes (the message
names the new header), and the single-value header gate refuses a
duplicated `X-Bridge-Token` with `400 duplicate_header`.

The generator and the source marker:

```dart
import 'package:localhost_bridge/localhost_bridge.dart';

void main() {
  // 0.1.x called generatePortalToken(); 0.2.0:
  final token = generateBridgeToken();
  assert(token.length == 64);
  // A host that branches on the command source compares
  // 'unknown-origin' (was 'unknown-portal'):
  //   if (command.source == 'unknown-origin') { ... }
}
```

The generator's shape is unchanged: 64 hex characters from a secure
random source.

## The WebSocket channel refuses to arm below Dart 3.13

**What was:** 0.1.x had no channel, and 0.2.0's channel has a hard SDK
floor: `WebSocketTransformer.upgrade` carries the `maxPayloadLength`
transport ceiling from Dart 3.13 onward, and the channel never runs
without a frame memory limit.

**What is now:** arming `BridgeConfig.wsPath` on an older SDK throws
`ArgumentError` at server construction with the reason named. The
package's declared 3.8 floor still compiles, and every non-channel
path works unchanged there - the message says so. On Dart 3.13+ the
channel works exactly as documented, with the ceiling enforced at the
upgrade and no fallback upgrade without a memory limit.

**What you change:** arm the channel only where the host runs Dart
3.13 or newer; on an older host, leave `wsPath` unset and every other
path keeps working:

```dart
import 'package:localhost_bridge/localhost_bridge.dart';

// Throws ArgumentError at server construction on a dart:io older
// than 3.13; arms the channel on 3.13+.
final config = BridgeConfig(wsPath: '/bridge');
```
