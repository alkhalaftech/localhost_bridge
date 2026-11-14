// localhost_bridge example - a host-side deduplication ledger for
// exactly-once commands. The bridge replies `504 handler_timeout` when a
// handler exceeds its budget, and a 504 is an UNKNOWN outcome: the work may
// still complete after the reply. The wire contract tells the page to
// reconcile on its own `X-Correlation-Id` before any retry - and this file
// is the host-side half of that contract: a ledger keyed by
// (source, correlation id) that registers each command BEFORE its work
// runs, stores the settled reply, and replays it for every repeat.
//
// Run it, then send the same X-Correlation-Id twice:
//   curl -X POST -H "Origin: https://demo.example" \
//     -H "Content-Type: application/json" \
//     -H "X-Correlation-Id: order-42" \
//     -d '{"data":["PAY"]}' http://127.0.0.1:9101/
// The first send executes the work; a second send with the same id gets the
// stored reply without executing anything.
import 'dart:async';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

/// The lifecycle of one ledger entry, recorded before the work runs.
enum LedgerState { running, done, failed }

/// One entry: the command's state, the reply to replay once settled, and an
/// expiry. The expiry must outlive the longest handler timeout - a 504
/// retry can arrive well after the handler settled, and it must still find
/// the stored reply.
class _Entry {
  _Entry(this.expiresAt) : state = LedgerState.running;

  LedgerState state;
  CommandOutcome? reply;
  final DateTime expiresAt;
}

/// A deduplication ledger keyed by (source, correlation id).
///
/// - [ttl] is the entry lifetime. Keep it longer than the server's
///   `handlerTimeout` (its worst case), or a late 504 retry lands after the
///   entry expired and the ledger can no longer protect the command.
/// - [maxEntries] is the size cap on live entries: once the cap is reached
///   (after sweeping expired ones), new commands are refused - [register]
///   returns false and [idempotentCommand] answers a `ledger_full` outcome
///   without running the work. A live entry is never evicted to make room:
///   dropping a running or settled entry would let a flood of fresh ids
///   make an old command run twice. Size the cap above your realistic
///   command rate times [ttl].
class DedupLedger {
  DedupLedger({required this.ttl, required this.maxEntries})
    : assert(ttl > Duration.zero),
      assert(maxEntries > 0);

  final Duration ttl;
  final int maxEntries;

  final Map<String, _Entry> _entries = <String, _Entry>{};

  // NUL keeps the pair unambiguous even when a source contains the
  // separator characters a correlation id may use.
  String _key(String source, String correlationId) =>
      '$source\x00$correlationId';

  void _sweep(DateTime now) {
    _entries.removeWhere((_, entry) => now.isAfter(entry.expiresAt));
  }

  /// The verdict for this (source, correlation id):
  /// - `null` - a new command: call [register], run the work, then
  ///   [settle] the outcome.
  /// - a stored reply (done or failed entry) - replay it verbatim and run
  ///   nothing; a failed command replays its failure, because re-running a
  ///   possibly-executed command is exactly what the ledger exists to stop.
  /// - a `duplicate_in_flight` notice (running entry) - the same command is
  ///   executing right now; the caller should retry shortly.
  CommandOutcome? replay(String source, String correlationId) {
    final now = DateTime.now();
    _sweep(now);
    final entry = _entries[_key(source, correlationId)];
    if (entry == null) return null;
    switch (entry.state) {
      case LedgerState.running:
        return const CommandOutcome(
          ok: false,
          errorCode: 'duplicate_in_flight',
          errorMessage: 'this command is still running - retry shortly',
        );
      case LedgerState.done:
      case LedgerState.failed:
        return entry.reply;
    }
  }

  /// Records the command BEFORE its work runs, so a retry racing the first
  /// execution sees a running entry instead of silently re-executing.
  ///
  /// Returns false when the ledger is at [maxEntries] with live entries
  /// after sweeping expired ones: the command is not registered and must
  /// not run - [idempotentCommand] answers `ledger_full` in that case.
  bool register(String source, String correlationId) {
    final now = DateTime.now();
    _sweep(now);
    if (_entries.length >= maxEntries) return false;
    _entries[_key(source, correlationId)] = _Entry(now.add(ttl));
    return true;
  }

  /// Stores the settled reply under the running entry. An entry that was
  /// never registered (a `ledger_full` refusal) has nothing to update, and
  /// an entry whose ttl passed while its work ran is still updated - the
  /// next sweep drops it, so the outcome stays replayable only inside its
  /// ttl. The caller always gets the outcome for the request that produced
  /// it.
  void settle(String source, String correlationId, CommandOutcome reply) {
    final entry = _entries[_key(source, correlationId)];
    if (entry == null) return;
    entry
      ..state = reply.ok ? LedgerState.done : LedgerState.failed
      ..reply = reply;
  }
}

/// The exactly-once discipline in one call - consult the ledger, register
/// before the work runs, settle or fail the outcome after. [main] below
/// wires it, and the tests import it, so the documented pattern and the
/// tested pattern are the same code.
Future<CommandOutcome> idempotentCommand(
  DedupLedger ledger,
  TrustedCommand cmd,
  Future<CommandOutcome> Function(TrustedCommand cmd) work,
) async {
  final replay = ledger.replay(cmd.source, cmd.correlationId);
  if (replay != null) return replay;
  if (!ledger.register(cmd.source, cmd.correlationId)) {
    // Fail-closed: the ledger is full of live entries after sweeping the
    // expired ones - the command was not registered and not executed, and
    // the flood is refused rather than evicting a confirmed command.
    return const CommandOutcome(
      ok: false,
      errorCode: 'ledger_full',
      errorMessage:
          'the dedup ledger is full of live entries - this command was not '
          'executed; wait for entries to settle or expire, or raise maxEntries',
    );
  }
  final CommandOutcome outcome;
  try {
    outcome = await work(cmd);
  } catch (error) {
    // The raw error may carry environment detail (paths, hosts, user
    // names) - never echo it to the page. Log `error` here on your own
    // telemetry before returning: this helper deliberately takes no
    // telemetry of its own, so the record stays in the host's log.
    final failure = CommandOutcome(
      ok: false,
      errorCode: 'command_failed',
      errorMessage: 'The command failed; see the host log',
    );
    ledger.settle(cmd.source, cmd.correlationId, failure);
    return failure;
  }
  ledger.settle(cmd.source, cmd.correlationId, outcome);
  return outcome;
}

void main() async {
  // Ten minutes is far beyond the five-second handler budget below: a 504
  // retry arriving minutes late still finds the stored reply.
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
