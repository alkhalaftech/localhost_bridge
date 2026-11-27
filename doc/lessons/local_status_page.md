# Lesson — local_status_page.dart

What this example shows
-----------------------

A host without a UI - a CLI tool, a service - still has a display:
`BridgeConfig.localPages` serves a page **from memory** (a path plus a
verbatim string, never a file) on the bridge's own listener. The page
in this example renders live counters: its inline script POSTs a
`STATUS` command from the page's own origin, the handler reads
`server.counters` (`example/local_status_page.dart:143`) and returns
them as reply data, and the script draws the table again every second.

The security lesson is in the page itself: a local page is readable by
every program on the device with a plain GET carrying no browser
headers, so the page says so in its own text and carries **no secret -
no token, no pairing code, only counters**. The self-check proves the
point mechanically: it arms a real token and asserts the token string
never appears in the served markup.

How to run it
-------------

Self-check (no user, no fixed ports):

    dart run example/local_status_page.dart --self-check

Six checks from a real client: the page answers GET verbatim with its
declared HTML type; it carries its security headers
(`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`); the armed
token string is absent from the served markup; a POST from the served
page origin crosses on its explicit admission path and the live
counters come back as reply data; a foreign origin gets the bytes but
no CORS echo, so no foreign page reads it cross-origin; and any other
GET keeps its standing `405 method_not_allowed`. The run ends
`SELF-CHECK PASSED (6 checks)` with exit 0.

Interactive:

    dart run example/local_status_page.dart

It listens on `http://127.0.0.1:9380` - open the printed
`/status` address and watch the counters refresh. Ctrl+C stops it.

Where to look
-------------

- `example/local_status_page.dart:27` - `_statusPage`: the whole page
  as one memory string; the strict CSP allows only its inline script.
- `example/local_status_page.dart:143` - the handler turning
  `server.counters` into reply data (numbers only - nothing secret).
- `example/local_status_page.dart:160` - the option that arms the
  page: `localPages: [BridgeLocalPage(path: '/status', ...)]`.
- `example/local_status_page.dart:127` - the token kept in the host's
  hand only; the page never sees it.

What it deliberately does not do
--------------------------------

- It does not read a folder from disk; the pages live in memory, and
  file serving is not part of this package.
- It does not put any secret on the page - the counter table and a
  note are the whole content, and the check asserts the absence, not
  just the intention.
- It does not let the page origin in through allow-all; the served
  origin crosses on its own explicit admission path with the same
  gates as a listed origin.
- It does not expose raw internal state beyond counters: no tokens,
  no origins, no request contents ever enter the page or the data.
- No TLS, no real credentials - generated demo token only.
