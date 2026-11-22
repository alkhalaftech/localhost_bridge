// The library dedup helper (DedupLedger + idempotentCommand) at unit
// level: the replay verdicts, the duplicate-in-flight refusal, the
// fail-closed full ledger, the ttl expiry on the injected clock, and the
// fixed failure sentence. The wire-level story (the same command twice,
// the second send after an artificial 504) stays guarded in
// idempotent_handler_test.dart, which imports the example that wires this
// exact library code.
import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:localhost_bridge/src/command_dedup.dart'
    show dedupMonotonicClock;

void main() {
  test('a fresh id replays null; after register and settle the stored '
      'outcome replays verbatim', () {
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 8);
    expect(
      ledger.replay('src', 'c-1'),
      isNull,
      reason: 'a fresh id is a new command: register, run, settle',
    );
    expect(ledger.register('src', 'c-1'), isTrue);
    ledger.settle('src', 'c-1', const CommandOutcome(ok: true));
    final replayed = ledger.replay('src', 'c-1');
    expect(replayed?.ok, isTrue, reason: 'the stored reply comes back');
  });

  test('a repeat while the first is running answers duplicate_in_flight - '
      'the caller never re-executes', () {
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 8);
    expect(ledger.register('src', 'c-2'), isTrue);
    final racing = ledger.replay('src', 'c-2');
    expect(racing?.ok, isFalse);
    expect(racing?.errorCode, 'duplicate_in_flight');
  });

  test('a failed outcome replays its failure: a retry never re-runs a '
      'possibly-executed command', () {
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 8);
    expect(ledger.register('src', 'c-3'), isTrue);
    ledger.settle(
      'src',
      'c-3',
      const CommandOutcome(ok: false, errorCode: 'printer_jammed'),
    );
    final replayed = ledger.replay('src', 'c-3');
    expect(replayed?.ok, isFalse);
    expect(
      replayed?.errorCode,
      'printer_jammed',
      reason: 'the failure replays verbatim - rerunning is the risk',
    );
  });

  test('a full ledger refuses a new command with ledger_full via the '
      'helper - the work never runs', () async {
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 2);
    expect(ledger.register('src', 'full-1'), isTrue);
    expect(ledger.register('src', 'full-2'), isTrue);
    var workRan = 0;
    final refused = await idempotentCommand(
      ledger,
      TrustedCommand(
        source: 'src',
        payloads: const ['PAY'],
        headers: const {},
        correlationId: 'overflow-1',
      ),
      (cmd) async {
        workRan++;
        return const CommandOutcome(ok: true);
      },
    );
    expect(refused.ok, isFalse);
    expect(
      refused.errorCode,
      'ledger_full',
      reason: 'a live entry is never evicted to make room',
    );
    expect(workRan, 0, reason: 'the refused command never reached the work');
  });

  test('an entry past its ttl is swept on the next look: the same id is a '
      'fresh command again', () {
    final clock = <DateTime>[DateTime(2026, 1, 1)];
    final ledger = DedupLedger(
      ttl: const Duration(seconds: 30),
      maxEntries: 8,
      now: () => clock[0],
    );
    expect(ledger.register('src', 'c-4'), isTrue);
    ledger.settle('src', 'c-4', const CommandOutcome(ok: true));
    expect(ledger.replay('src', 'c-4')?.ok, isTrue);
    clock[0] = clock[0].add(const Duration(seconds: 31));
    expect(
      ledger.replay('src', 'c-4'),
      isNull,
      reason: 'the expired entry is swept - the id is fresh again',
    );
    expect(
      ledger.register('src', 'c-4'),
      isTrue,
      reason: 'the swept id registers as a new command',
    );
  });

  test('a settle after the ttl passed stores into oblivion: the outcome '
      'replays only inside its ttl', () {
    final clock = <DateTime>[DateTime(2026, 1, 1)];
    final ledger = DedupLedger(
      ttl: const Duration(seconds: 30),
      maxEntries: 8,
      now: () => clock[0],
    );
    expect(ledger.register('src', 'c-5'), isTrue);
    clock[0] = clock[0].add(const Duration(seconds: 31));
    // العمل استمر بعد انتهاء ttl مدخله: الاستقرار يحدّث والنظرة التالية
    // تكبّه — النتيجة لا تعود إلا داخل عمرها
    ledger.settle('src', 'c-5', const CommandOutcome(ok: true));
    expect(
      ledger.replay('src', 'c-5'),
      isNull,
      reason: 'the sweep drops the expired entry the settle updated',
    );
  });

  test('a non-positive ttl or maxEntries throws ArgumentError at '
      'construction - release builds included', () {
    expect(
      () => DedupLedger(ttl: Duration.zero, maxEntries: 8),
      throwsArgumentError,
      reason:
          'a zero ttl expires every entry at once - a corrupt value '
          'is a loud setup error, never a silent ledger',
    );
    expect(
      () => DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 0),
      throwsArgumentError,
      reason:
          'a zero cap refuses every command - the refusal must be '
          'loud at construction, not a ledger that answers ledger_full '
          'forever',
    );
  });

  test('a wall-clock jump past the ttl never ends a default-clock entry '
      'before its due', () {
    // الساعة الافتراضية نفسها بجدار محقون: زرع واحد عند البناء ثم
    // Stopwatch حصراً — فقفزة ساعة الجدار فوق الـttl لا تُقرأ إطلاقاً
    // والإدخال يقاس بالزمن المنقضي لا بالجدار
    var wall = DateTime(2026, 1, 1, 12);
    final ledger = DedupLedger(
      ttl: const Duration(minutes: 10),
      maxEntries: 4,
      now: dedupMonotonicClock(wall: () => wall),
    );
    expect(ledger.register('src', 'jump-1'), isTrue);
    wall = wall.add(const Duration(hours: 2));
    final racing = ledger.replay('src', 'jump-1');
    expect(
      racing?.errorCode,
      'duplicate_in_flight',
      reason:
          'the entry survives a wall-clock jump two hours past its '
          'ttl - expiry measures elapsed time, never the wall',
    );
  });

  test('the default ledger stays alive across real waits shorter than '
      'its ttl', () async {
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 4);
    expect(ledger.register('src', 'wall-real-1'), isTrue);
    await Future<void>.delayed(const Duration(milliseconds: 15));
    expect(
      ledger.replay('src', 'wall-real-1')?.errorCode,
      'duplicate_in_flight',
      reason:
          'the default clock serves the standing register/replay '
          'course on real time alone',
    );
  });

  test('a thrown work error stays out of the outcome: the helper settles '
      'a fixed sentence, never the exception text', () async {
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 8);
    // نص مميز يحمل تفاصيل بيئة حقيقية لو وصل إلى الصفحة
    const marker = 'DB-CONN-DETAIL host=internal-db user=svc';
    final outcome = await idempotentCommand(
      ledger,
      TrustedCommand(
        source: 'src',
        payloads: const ['PAY'],
        headers: const {},
        correlationId: 'boom-1',
      ),
      (cmd) async => throw Exception('work blew up: $marker'),
    );
    expect(outcome.ok, isFalse);
    expect(outcome.errorCode, 'command_failed');
    expect(
      outcome.errorMessage,
      'The command failed; see the host log',
      reason: 'the page reads the fixed sentence only',
    );
    expect(
      outcome.errorMessage,
      isNot(contains(marker)),
      reason: 'the exception text never leaves the host log',
    );
    // والفشل مُستقر بالدفتر: الإعادة تحمل الجملة نفسها لا تنفيذاً ثانياً
    final replayed = ledger.replay('src', 'boom-1');
    expect(replayed?.errorCode, 'command_failed');
  });
}
