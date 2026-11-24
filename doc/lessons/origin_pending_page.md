# Lesson — origin_pending_page.dart

What this example shows
-----------------------

First use on an unknown origin is a question to a human, not a
shortcut: the walk is `SENDING -> PENDING -> WAITING -> RETRYING ->
GRANTED | REFUSED` - the bridge opens the consent question, the reply
carries `403 origin_pending` with the honest `Retry-After`, the page
honors that wait (no hammering), retries once with the same
correlation id, and the host's answer decides. The host side is a
deterministic simulated human
(`example/origin_pending_page.dart:24`): the demo portal origin is
granted exactly once on its first question, and every other origin -
and every later question - is refused.

The page itself (`_pendingPage`) is the same state machine ready to
copy into an https portal. Served locally over plain http it honestly
reports the blocked state instead of pretending: the discovery path
asks valid https origins only, so a page opened from `http://localhost`
cannot cross at all - that is the bridge's own hardening, not a bug.
The wire demo in the host terminal walks the identical states, so the
machine is visible either way.

How to run it
-------------

Self-check (no user, no fixed ports):

    dart run example/origin_pending_page.dart --self-check

Four checks from a real client: the page serves over http with the
machine in it; the granted origin walks the full wire - pending,
honoring Retry-After, one retry, granted; the consent question really
carried an honest `Retry-After` (one second or more read from the
wire, not assumed); and the stranger origin ends refused without any
grant. The run ends `SELF-CHECK PASSED (4 checks)` with exit 0.

Interactive:

    dart run example/origin_pending_page.dart

The bridge listens on `http://127.0.0.1:9300`, the page on the port
its own server picked; open the printed page URL with
`?bridge-port=<printed>`. The boot walk runs both origins in the
terminal first, so the machine is visible before the page. Ctrl+C
stops it.

Where to look
-------------

- `example/origin_pending_page.dart:45` - `_runFlow`: one round of the
  machine over the wire; it reports the states it visited, the final
  verdict, and the `Retry-After` seconds it read.
- `example/origin_pending_page.dart:221` - `_runSelfCheck`: the page
  GET and the two walks, one PASS line per check.
- `example/origin_pending_page.dart:240` - the wiring: the policy is
  nothing but the consent callback.
- `example/origin_pending_page.dart:316` - the mode switch that keeps
  the interactive walk and the unattended checks on one file.

What it deliberately does not do
--------------------------------

- It does not hammer the port: one respectful retry after the announced
  wait, same correlation id, then stop - the machine has no third ask.
- It does not fake the page path: over plain http the page shows the
  honest blocked state; the copy into your https portal is the real
  flow, and nothing here pretends otherwise.
- It does not remember grants in this demo; the simulated human grants
  once per origin, so the refusal path stays visible every run.
- It does not open allow-all or shortcut the question: the consent
  callback is the whole policy in this example.
- No TLS, no `::1`, no real origins - abstract demo origins only.
