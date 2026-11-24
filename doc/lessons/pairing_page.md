# Lesson — pairing_page.dart

What this example shows
-----------------------

Pairing is the door where the page's credential is its own proof of
possession, not a shared string. The host arms pairing
(`IntakeProtection.enablePairing`), opens a one-time session
(`startPairing()` at `example/pairing_page.dart:285`), and shows the
six-digit code on **its own channel** — the terminal print right below
it in `main()` (`example/pairing_page.dart:434`). The page sends
that code with its origin to `POST /pair` and receives a token bound to
its origin plus a public pairing id. From then on the page never sends
the token raw again: every command carries an `X-Bridge-Pairing` proof —
HMAC-SHA-256 over `v1 / pairingId / stamp / METHOD / path /
correlationId` (`pairProof` at `example/pairing_page.dart:194`, the
Dart translation of the WebCrypto snippet in the README's pairing
section).

The policy shape is the whole idea in one line: `allowed: [...],
requireOriginWithToken: true` (`example/pairing_page.dart:253`) — a
qualified origin without a proof reads `403 token_required`, and no
shared token exists in this example at all.

How to run it
-------------

Self-check (no user, no fixed ports):

    dart run example/pairing_page.dart --self-check

Five wire checks from a real client: a wrong code reads
`pair_code_invalid`; the qualified origin without a proof reads
`token_required`; the displayed code pairs and returns a 64-hex token
with a 16-hex pairing id; the signed request crosses with
`{"ok":true}`; the same proof replayed reads
`pair_signature_replay`. Each check prints a PASS line and the run
ends with `SELF-CHECK PASSED (5 checks)` and exit 0.

Interactive:

    dart run example/pairing_page.dart

It listens on `http://127.0.0.1:9340`, prints the pairing code on the
terminal, and waits for your page on `https://desk.example` (swap in
your real origin). Ctrl+C stops it.

Where to look
-------------

- `example/pairing_page.dart:194` — `pairProof`: the canonical string
  and the exact header value the bridge verifies.
- `example/pairing_page.dart:234` — `_runSelfCheck`: the pairing
  journey over the wire, one check per step.
- `example/pairing_page.dart:253` — the policy that makes a proof
  mandatory on the listed origin.
- `example/pairing_page.dart:285` — `startPairing()`: the host shows
  the code where only the human reads it.

What it deliberately does not do
--------------------------------

- It does not show the pairing code on any served page. A local page is
  readable by every program on the device (a plain GET with no browser
  headers), so the code lives on the host's screen or terminal only.
- It does not share a static token. The paired token travels through
  the pairing door once and is never sent raw again — only its HMAC
  signature is.
- It does not accept a second command with a replayed proof; the
  self-check proves the refusal instead of assuming it.
- It is not a browser page. The client here is a Dart HTTP client that
  plays the page's role, including carrying the page's proof math;
  the real page-side snippet lives in the README's pairing section.
- No TLS, no real credentials — abstract demo origin and
  demo commands only.
