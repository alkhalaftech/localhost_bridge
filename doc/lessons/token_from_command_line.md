# Lesson — token_from_command_line.dart

What this example shows
-----------------------

The token alone is a complete posture: an empty policy (closed by
default) plus one shared secret means the token holder is the only
sender - a web page, whatever origin it forges, never crosses. The
secret's life is the lesson's second half: it is **generated once**
(`generateBridgeToken()`) and **passed on the command line**
(`--token <value>`), never written in code and never stored by the
example. Re-running with the printed `--token ...` line is the whole
out-of-band handoff a real host does with its own channel.

How to run it
-------------

Self-check (no user, no fixed ports):

    dart run example/token_from_command_line.dart --self-check

Nine wire checks from a real client: no token reads
`origin_not_listed`; the correct token crosses with no `Origin`
header at all; five wrong tokens each read the origin rejection and
learn nothing about themselves; the sixth wrong token reads
`token_locked` with the honest `Retry-After`; and the correct token
still crosses after all that - the budget never locks out the
holder. Each check prints a PASS line and the run ends with
`SELF-CHECK PASSED (9 checks)` and exit 0.

Interactive:

    dart run example/token_from_command_line.dart
    dart run example/token_from_command_line.dart --token <the value>

The first form generates a token, prints it with the exact command
line that carries it, and listens on `http://127.0.0.1:9350`. The
second form runs a token minted once elsewhere. Any other argument is
refused loudly with exit 64, and a token below the 32-byte floor is
refused by the bridge at build time with exit 65 - the message names
the length, never the token.

Where to look
-------------

- `example/token_from_command_line.dart:61` - the token generated once
  inside the self-check, then armed with an empty policy at line 63.
- `example/token_from_command_line.dart:111` - the wrong-guess
  sequence that walks the real budget on the wire.
- `example/token_from_command_line.dart:131` - the lockout check with
  the honest `Retry-After`, and line 140 the holder crossing anyway.
- `example/token_from_command_line.dart:176` - the argument switch:
  no args generates, `--token <value>` passes a minted token,
  everything else refuses.
- `example/token_from_command_line.dart:197` - the build-time refusal
  for a weak token (exit 65, message names the length).

What it deliberately does not do
--------------------------------

- It does not write the token anywhere: not in code, not in a file,
  not in the served surface - the command line and the terminal are
  the whole story.
- It does not open any origin path. The policy stays empty, so the
  example can never show a page reading a reply; that is the point of
  the posture, not a gap.
- It does not accept a short or low-diversity token with a warning;
  the bridge refuses it at construction and the example surfaces that
  refusal with its exit code.
- It is not a retry recipe: the lockout check exists to show the
  honest budget behavior, not to teach clients to hammer wrong tokens.
- No TLS, no real credentials - generated demo token only.
