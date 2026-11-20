// شاهد ب5: دفتر عدم التكرار — الأمر نفسه مرتين والثانية بعد 504 مصطنع
// (المعالج يتجاوز مهلته مرة ثم ينجح): العمل ينفذ مرة واحدة والرد المخزن
// يعود كما هو، ومعرف الصفحة يعود بلا تغيير عند الإعادة. التوصيل هنا هو
// التوصيل نفسه الذي يعرضه example/idempotent_handler.dart فوق
// DedupLedger وidempotentCommand المكتبيتين حرفاً، والمثال ذاته يفحصه
// بوابة analyze (بلا استيراد نسبي لم يعد له معنى بعد انتقال المنطق
// إلى المكتبة).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

Future<Map<String, Object?>> _send(int port, String cid) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', 'https://dedup.test');
    req.headers.set('X-Correlation-Id', cid);
    req.headers.contentType = ContentType.json;
    req.write('{"data":["PAY"]}');
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    return <String, Object?>{
      'status': res.statusCode,
      'body': body,
      'cid': res.headers.value('X-Correlation-Id'),
    };
  } finally {
    client.close(force: true);
  }
}

LocalIntakeServer _dedupServer(
  DedupLedger ledger,
  List<String> executions,
  Completer<void> workStarted,
  Completer<void> workReleased,
) => LocalIntakeServer(
  onCommand: (cmd) => idempotentCommand(ledger, cmd, (c) async {
    executions.add(c.correlationId);
    // التنفيذ الأول يتجاوز مهلة المعالج ثم ينجح — 504 مصطنع والعمل يكمل حقيقيا
    if (executions.length == 1) {
      workStarted.complete();
      await workReleased.future;
    }
    return const CommandOutcome(ok: true);
  }),
  telemetry: const SilentTelemetry(),
  correlationIdGenerator: () => 'witness-gen',
  handlerTimeout: const Duration(milliseconds: 300),
  protection: IntakeProtection(telemetry: const SilentTelemetry())
    ..update(policy: const OriginPolicy(allowed: ['https://dedup.test'])),
);

/// خادم الفيض: عمل يُنجز فورا بلا تعليق — لملء السقف بمدخلات حية واختبار
/// رفض الدفتر الممتلئ (لا تعليق عمل هنا أصلا، فالملء كله يستقر).
LocalIntakeServer _floodServer(DedupLedger ledger, List<String> executions) =>
    LocalIntakeServer(
      onCommand: (cmd) => idempotentCommand(ledger, cmd, (c) async {
        executions.add(c.correlationId);
        return const CommandOutcome(ok: true);
      }),
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'witness-gen',
      handlerTimeout: const Duration(milliseconds: 300),
      protection: IntakeProtection(telemetry: const SilentTelemetry())
        ..update(policy: const OriginPolicy(allowed: ['https://dedup.test'])),
    );

void main() {
  test('the same command twice: the second send after an artificial 504 '
      'replays the stored reply and the work ran once', () async {
    final executions = <String>[];
    final workStarted = Completer<void>();
    final workReleased = Completer<void>();
    final ledger = DedupLedger(
      ttl: const Duration(seconds: 30),
      maxEntries: 64,
    );
    final server = _dedupServer(ledger, executions, workStarted, workReleased);
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    final first = _send(port, 'order-42');
    await workStarted.future; // دخول المعالج إشارة حتمية لا افتراض توقيت
    final firstReply = await first;
    expect(
      firstReply['status'],
      504,
      reason: 'the handler exceeded its budget once - an unknown outcome',
    );

    workReleased.complete();
    // استقرار الدفتر حتمي: settle في سلسلة microtasks بعد عودة العمل
    await pumpEventQueue();

    final second = await _send(port, 'order-42');
    expect(second['status'], 200, reason: 'the stored reply comes back');
    expect(second['body'], '{"ok":true}');
    expect(
      second['cid'],
      'order-42',
      reason: 'the page id returns unchanged on the retry',
    );
    expect(executions, [
      'order-42',
    ], reason: 'the work executed exactly once - the repeat only replayed');
  });

  test('a duplicate racing the first execution is refused while it runs, '
      'then replayed once the first settles', () async {
    final executions = <String>[];
    final workStarted = Completer<void>();
    final workReleased = Completer<void>();
    final ledger = DedupLedger(
      ttl: const Duration(seconds: 30),
      maxEntries: 64,
    );
    final server = _dedupServer(ledger, executions, workStarted, workReleased);
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    final first = _send(port, 'order-42');
    await workStarted.future;
    // إعادة متسابقة أثناء الجري: تُرفض ولا تُنفذ — العمل يبقى واحدا
    final racing = await _send(port, 'order-42');
    expect(
      racing['status'],
      500,
      reason: 'a running duplicate is refused, never re-executed',
    );
    expect(racing['body'], contains('duplicate_in_flight'));
    expect(executions, ['order-42']);

    // ال504 يقرأ قبل التحرير حصرا: المعالج موقوف والموعد المطلق (300ms)
    // يقطع حتما قبل التحرير — ترتيب حتمي لا رهان توقيت
    final firstReply = await first;
    expect(firstReply['status'], 504);

    workReleased.complete();
    await pumpEventQueue();

    final settled = await _send(port, 'order-42');
    expect(
      settled['status'],
      200,
      reason: 'after the first settles, the repeat gets the stored reply',
    );
    expect(executions, ['order-42']);
  });

  test('a flood of fresh ids cannot evict a running command: the repeat sees '
      'duplicate_in_flight and the work stays one execution', () async {
    final executions = <String>[];
    final workStarted = Completer<void>();
    final workReleased = Completer<void>();
    // سقف صغير عمدا: order-42 الجاري + أربع معرفات فريدة = فيض فوق السقف
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 4);
    final server = _dedupServer(ledger, executions, workStarted, workReleased);
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    final first = _send(port, 'order-42');
    await workStarted.future; // دخول المعالج إشارة حتمية: order-42 مسجل وجار
    final firstReply = await first;
    expect(
      firstReply['status'],
      504,
      reason:
          'the first execution timed out - the unknown outcome the ledger guards',
    );
    for (var i = 1; i <= 4; i++) {
      await _send(port, 'flood-$i');
    }

    final repeat = await _send(port, 'order-42');
    expect(
      executions.where((id) => id == 'order-42'),
      ['order-42'],
      reason:
          'order-42 executed exactly once - a full ledger never drops a live '
          'entry, so the flood cannot push it into a second run',
    );
    expect(
      repeat['body'],
      contains('duplicate_in_flight'),
      reason:
          'the running entry survived the flood - the repeat finds it in flight',
    );

    workReleased.complete();
    await pumpEventQueue();
  });

  test('a ledger full of live entries refuses a new command with ledger_full '
      '- the work never runs', () async {
    final executions = <String>[];
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 4);
    final server = _floodServer(ledger, executions);
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    for (var i = 1; i <= 4; i++) {
      final filled = await _send(port, 'fill-$i');
      expect(
        filled['status'],
        200,
        reason: 'live entries up to the cap are admitted and executed',
      );
    }

    final refused = await _send(port, 'overflow-1');
    expect(
      refused['status'],
      500,
      reason:
          'a full ledger refuses the new command instead of dropping a live entry',
    );
    expect(refused['body'], contains('ledger_full'));
    expect(executions, [
      'fill-1',
      'fill-2',
      'fill-3',
      'fill-4',
    ], reason: 'the refused command never reached the work');
  });

  test('a thrown work error stays out of the reply: the page reads a fixed '
      'sentence, never the exception text', () async {
    final ledger = DedupLedger(ttl: const Duration(seconds: 30), maxEntries: 8);
    // نص مميز يحمل تفاصيل بيئة حقيقية لو تسرّب إلى الصفحة
    const marker = 'DB-CONN-DETAIL host=internal-db user=svc';
    final server = LocalIntakeServer(
      onCommand: (cmd) => idempotentCommand(
        ledger,
        cmd,
        (c) async => throw Exception('work blew up: $marker'),
      ),
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'witness-gen',
      handlerTimeout: const Duration(milliseconds: 300),
      protection: IntakeProtection(telemetry: const SilentTelemetry())
        ..update(policy: const OriginPolicy(allowed: ['https://dedup.test'])),
    );
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    final r = await _send(port, 'boom-1');
    expect(r['status'], 500);
    expect(r['body'], contains('command_failed'));
    expect(
      r['body'],
      isNot(contains(marker)),
      reason:
          'the exception text carries environment detail - it never reaches '
          'the page; the host logs it on its own telemetry',
    );
  });
}
