# Lesson — mount_existing_server.dart

What this example shows
-----------------------

The bridge does not need its own port. A host that already runs a
dart:io server keeps the server and the routing, and hands the bridge
exactly the requests it wants judged: the forwarder calls
`bridge.handleHostRequest(request, hostPort: host.port)`
(`example/mount_existing_server.dart:73`) and the bridge answers that
one request with the full standing protection - the same gates in the
same order as the private `start()` listener, the same wire codes, and
the reply written over the detached socket exactly as its own server
does. `hostPort` is the host server's real listening port, because the
Host authority the bridge checks is the one the client actually
typed.

Everything the host does not forward never reaches the bridge: the
host's own routes answer themselves, and a POST on such a path is
judged by host code, not bridge code.

How to run it
-------------

Self-check (no user, no fixed ports):

    dart run example/mount_existing_server.dart --self-check

Four checks from a real client: the host route answers itself while
the handler count stays zero; the forwarded `/bridge` path crosses
with `{"ok":true}` and the handler runs once; an unlisted origin on
the forwarded path reads the same `origin_not_listed` refusal the
private door gives, with no CORS echo, and the handler never runs;
and a POST on a path the host keeps is answered by the host - the
bridge never hears it. Each check prints a PASS line and the run ends
with `SELF-CHECK PASSED (4 checks)` and exit 0.

Interactive:

    dart run example/mount_existing_server.dart

The host listens on `http://127.0.0.1:9370` - `POST /bridge` crosses
the mounted door, everything else stays the host's. The curl in the
file header is the one that crosses. Ctrl+C stops it.

Where to look
-------------

- `example/mount_existing_server.dart:31` - `_MountedDemo`: the whole
  wiring in one place - host server, bridge, and the handler counter.
- `example/mount_existing_server.dart:46` - the handler count: the
  one fact the wire cannot show, so the checks read it directly.
- `example/mount_existing_server.dart:73` - the forwarder itself:
  `handleHostRequest` with `hostPort: host.port`.
- `example/mount_existing_server.dart:90` - the teardown: the bridge
  never started a listener here, and `stop()` settles whatever is in
  flight on the mounted path before the host closes.

What it deliberately does not do
--------------------------------

- It does not start the bridge on its own port; the private
  `start()`/port story is `example/main.dart`, this example exists to
  show the door without it.
- It does not forward every path. The host chooses the boundary: one
  path is the bridge's world, the rest stay the host's.
- It does not weaken the wire on the mounted door: the checks prove
  the same refusal, the same no-CORS-echo behavior, and the same
  handler isolation as the private listener.
- It is not a second web framework; the host here is plain dart:io
  and the package carries no framework dependency.
- No TLS, no real credentials - abstract demo origin and
  demo commands only.
