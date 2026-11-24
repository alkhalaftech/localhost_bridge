# Lesson — streaming_reply_and_channel.dart

What this example shows
-----------------------

The two host-to-page channels, armed together on one bridge. A command
whose request carries `X-Bridge-Stream: events` is answered
`text/event-stream`: every handler progress call
(`cmd.progress?.call(...)` in `_runJob`,
`example/streaming_reply_and_channel.dart:30`) becomes one
`event: progress` frame in call order, and the handler's outcome
travels as the final `event: result` frame with the standing reply
contract. The header opts one command in - the same handler, without
the header, still reads the ordinary single JSON reply.

`BridgeConfig.wsPath: '/ws'` opens the WebSocket channel through the
same admission step as every request; the browser cannot put headers
on a handshake, so the credential - here the shared token - travels in
the first message, inside the short auth deadline this example sets
with `wsAuthTimeout: Duration(seconds: 3)`
(`example/streaming_reply_and_channel.dart:68`). A channel that sends
no credential inside that window is cut with `ws_auth_timeout`.

On an SDK older than 3.13 the channel never arms: dart:io learned the
upgrade's transport length ceiling in 3.13, and the package refuses a
ceiling-less channel outright. The example reads
`LocalIntakeServer.wsTransportCeilingSupported` and arms `wsPath` only
where the SDK supports it (`example/streaming_reply_and_channel.dart:74`).

How to run it
-------------

Self-check (no user, no fixed ports):

    dart run example/streaming_reply_and_channel.dart --self-check

Five checks from a real client: the streamed request reads as
`text/event-stream` with at least three progress frames and a final
`{"ok":true}` result frame; the same command without the stream header
reads the standing JSON reply; an unlisted origin with the stream
header is still refused `origin_not_listed` - streaming never bypasses
admission; the channel takes its token credential from the first
message, answers commands as reply events, and closes by both hands;
and a channel with no credential is cut inside the 3-second deadline
with `ws_auth_timeout`, both hands completing that close too. The
probe mode ends with an explicit `exit` on its verdict: a channel cut
by the auth deadline leaves teardown timers alive on this SDK, and a
process that has said its final word does not wait a minute for them.
Below 3.13 the channel checks are replaced by one named SKIP line and
the run still ends `SELF-CHECK PASSED (3 checks, channel skipped)`
with exit 0 - the skip says exactly what was not checked.

Interactive:

    dart run example/streaming_reply_and_channel.dart

It listens on `http://127.0.0.1:9360` and prints a `curl -N` line for
the streamed command plus the browser-side channel recipe. Ctrl+C
stops it.

Where to look
-------------

- `example/streaming_reply_and_channel.dart:30` - `_runJob`: progress
  reports through the sink; it exists only when the request opted in.
- `example/streaming_reply_and_channel.dart:53` - `buildBridge`: the
  whole wiring - streaming on, token armed, `wsPath` and the short
  `wsAuthTimeout` (line 68), and the 3.13 guard (line 74).
- `example/streaming_reply_and_channel.dart:138` - the frame reader:
  an `event:` line names the current frame, the next `data:` line is
  its payload - progress and result never mix.
- `example/streaming_reply_and_channel.dart:190` - the named honest
  skip below 3.13.
- `example/streaming_reply_and_channel.dart:241` - the credential-less
  channel whose cut the deadline check reads.

What it deliberately does not do
--------------------------------

- It does not pretend the channel exists everywhere: on an SDK without
  the transport ceiling it prints one SKIP line naming the missing
  parameter instead of arming a ceiling-less channel.
- It does not stream by default: without the request header the wire
  is the standing single-reply contract, byte for byte.
- It does not open a second listener for the channel; `wsPath` rides
  the bridge's own port and its own admission step.
- It does not leave a channel open after its check - the client closes
  its end so nothing lingers past the run.
- No TLS, no real credentials - generated demo token only.
