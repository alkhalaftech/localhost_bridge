/// The correlation-id deduplication helper - the exactly-once discipline
/// a host wraps its command handler with.
///
/// A `504 handler_timeout` is an unknown outcome: the work may still
/// complete after the seat frees, so a blind retry can execute the same
/// command twice. This helper is the library side of the wire contract's
/// advice: register the command under its correlation id BEFORE the work
/// runs, settle the stored reply once, and replay it verbatim for every
/// repeat - the memory behind it is bounded by size ([DedupLedger.maxEntries])
/// and by time ([DedupLedger.ttl]), and a full ledger refuses a new
/// command (`ledger_full`) instead of ever dropping a live entry.
///
/// Compose it inside the host's own handler - the intake never calls it:
///
/// ```dart
/// final ledger = DedupLedger(ttl: const Duration(minutes: 10), maxEntries: 4096);
/// final server = LocalIntakeServer(
///   onCommand: (cmd) => idempotentCommand(ledger, cmd, myWork),
///   ...
/// );
/// ```
library;

import 'trusted_command.dart';

/// The lifecycle of one ledger entry, recorded before the work runs.
enum LedgerState { running, done, failed }

/// One entry: the command's state, the reply to replay once settled, and
/// an expiry. The expiry must outlive the longest handler timeout - a 504
/// retry can arrive well after the handler settled, and it must still
/// find the stored reply.
class _Entry {
  _Entry(this.expiresAt) : state = LedgerState.running;

  LedgerState state;

  /// The settled reply replayed verbatim - never rebuilt, never amended:
  /// a replay that re-decides is a second execution in disguise.
  CommandOutcome? reply;

  final DateTime expiresAt;
}

/// A deduplication ledger keyed by (source, correlation id) - the memory
/// the exactly-once discipline needs, bounded by size and by time.
///
/// - [ttl] is the entry lifetime. Keep it longer than the server's
///   `handlerTimeout` (its worst case), or a late 504 retry lands after
///   the entry expired and the ledger can no longer protect the command.
/// - [maxEntries] is the size cap on live entries: once the cap is
///   reached (after sweeping expired ones), new commands are refused -
///   [register] returns false and [idempotentCommand] answers a
///   `ledger_full` outcome without running the work. A live entry is
///   never evicted to make room: dropping a running or settled entry
///   would let a flood of fresh ids make an old command run twice. Size
///   the cap above your realistic command rate times [ttl].
/// - [now] is the injectable clock; the default reads the wall clock.
///   Tests pass their own to drive expiry deterministically.
class DedupLedger {
  /// Builds the ledger - [ttl] and [maxEntries] are required; a
  /// non-positive value is a programming mistake and asserts at
  /// construction.
  DedupLedger({
    required this.ttl,
    required this.maxEntries,
    DateTime Function()? now,
  }) : assert(ttl > Duration.zero),
       assert(maxEntries > 0),
       _now = now ?? DateTime.now;

  /// The entry lifetime - see the class contract for sizing it.
  final Duration ttl;

  /// The live-entry cap - see the class contract for sizing it.
  final int maxEntries;

  final DateTime Function() _now;

  final Map<String, _Entry> _entries = <String, _Entry>{};

  // الفاصل NUL يبقى الزوج مقروءاً كزوج في أي تشخيص، وصفحة الإرسال لا
  // يمكن أن تدخل NUL أصلاً (المعرف المقبول [A-Za-z0-9._-] والأصل شكل
  // scheme://host[:port] مطبَّعاً) — فالفاصل دفاع قراءة لا بوابة قبول.
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
    final now = _now();
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
    final now = _now();
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
/// before the work runs, settle or fail the outcome after. Wire it inside
/// the host's [LocalIntakeServer.onCommand]; the pairing between the two
/// ids is the wire's: the page sends `X-Correlation-Id` and the bridge
/// echoes it, and this helper keys its memory on exactly that pair.
///
/// A thrown work error settles a fixed `command_failed` sentence - the raw
/// error may carry environment detail (paths, hosts, user names) and never
/// reaches the page; log `error` on your own telemetry first. The helper
/// deliberately takes no telemetry of its own, so the record stays in the
/// host's log.
Future<CommandOutcome> idempotentCommand(
  DedupLedger ledger,
  TrustedCommand cmd,
  Future<CommandOutcome> Function(TrustedCommand cmd) work,
) async {
  final replay = ledger.replay(cmd.source, cmd.correlationId);
  if (replay != null) return replay;
  if (!ledger.register(cmd.source, cmd.correlationId)) {
    // الفشل المغلق: الدفتر ممتلئ بمدخلات حية بعد كنس المنتهي — الأمر لم
    // يُسجل ولم يُنفذ، والفيض يُرفض بدل إسقاط أمر مؤكد من حياته.
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
    // الخطأ الخام قد يحمل تفاصيل بيئة (مسارات وأسماء مستخدمين) — لا يصل
    // الصفحة أبداً؛ سجله على telemetry مضيفك قبل الإرجاع.
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
