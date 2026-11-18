# Migrating to localhost_bridge 0.2.0

0.2.0 renames the three intake names and removes the old ones with no
deprecation window: the old header name is not accepted, the old
generator does not exist, and the originless command source marker
carries the new value. This guide names the three renames and the path
for each; later 0.2.0 items extend this guide as they land.

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
