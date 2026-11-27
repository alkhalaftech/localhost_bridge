// localhost_bridge example - exactly-once commands over the bridge.
// A `504 handler_timeout` is an UNKNOWN outcome: the work may still finish
// after the reply, so a retry can execute the same command twice. The
// discipline lives in the library now: `DedupLedger` and
// `idempotentCommand` are exported by the package, and this file is the
// wiring demo - a ledger sized past the handler budget, a handler wrapped
// in the helper, and nothing else.
//
// Run it, then send the same X-Correlation-Id twice:
//   curl -X POST -H "Origin: https://demo.example" \
//     -H "Content-Type: application/json" \
//     -H "X-Correlation-Id: order-42" \
//     -d '{"data":["PAY"]}' http://127.0.0.1:9101/
// The first send executes the work; a second send with the same id gets the
// stored reply without executing anything.
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

void main() async {
  // Ten minutes is far beyond the five-second handler budget below: a 504
  // retry arriving minutes late still finds the stored reply. The entry
  // cap (4096) sits above the realistic command rate times the ttl - a
  // full ledger refuses new commands with `ledger_full`, it never drops a
  // live entry to make room.
  final ledger = DedupLedger(
    ttl: const Duration(minutes: 10),
    maxEntries: 4096,
  );
  final server = LocalIntakeServer(
    // The work - validate payloads here; this demo accepts PAY only.
    onCommand: (cmd) => idempotentCommand(ledger, cmd, (c) async {
      for (final payload in c.payloads) {
        if (payload.trim().toUpperCase() != 'PAY') {
          return const CommandOutcome(
            ok: false,
            errorCode: 'unknown_command',
            errorMessage: 'only PAY is accepted in this demo',
          );
        }
      }
      return const CommandOutcome(ok: true);
    }),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        'demo-${DateTime.now().microsecondsSinceEpoch.toRadixString(36)}',
    handlerTimeout: const Duration(seconds: 5),
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(policy: const OriginPolicy(allowed: ['https://demo.example'])),
  );

  final port = await server.start(preferredPort: 9101);
  stdout
    ..writeln(
      'localhost_bridge dedup example — listening on http://127.0.0.1:$port',
    )
    ..writeln(
      'send a command with your own id, then send it again with the SAME id:',
    )
    ..writeln(
      'curl -X POST -H "Origin: https://demo.example" '
      '-H "Content-Type: application/json" '
      '-H "X-Correlation-Id: order-42" '
      '-d \'{"data":["PAY"]}\' http://127.0.0.1:$port/',
    )
    ..writeln(
      'the first send executes; the repeat gets the stored reply and the '
      'work runs once',
    );

  await ProcessSignal.sigint.watch().first;
  await server.stop();
}
