// صحة الخادم أمام مستخدم pub.dev الغريب :
// الترويسات متعددة القيم لم تعد تسقط الطلب في استثناء غير ملتقط يعلّق
// المقبس بلا رد (حادثة سابقة: UNCAUGHT-IN-ZONE + TIMEOUT-3s) بل
// تُرد 400 صريحة مع قطع الاتصال، وأي استثناء ناجٍ يرى ردا، وstart/stop
// صارا بعقد موثوق: بداية مزدوجة StateError، وإيقاف مهذ ينتظر الجاري،
// وفشل المنافذ استثناء محدد النوع (سلالة StateError وException معا).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _counterId() => 'health-${_idSeq++}';

/// Test policy: hardened allow-all with a wide quota (tests are locally safe).
IntakeProtection _openProtection() => IntakeProtection()
  ..update(
    policy: const OriginPolicy(
      allowAllHardened: true,
      perOriginPerMinute: 1000,
    ),
  );

/// Telemetry recorder - captures warns so stop()'s orphan announcements are
/// assertable (SilentTelemetry mutes everything).
class _Rec extends BridgeTelemetry {
  final warns = <String>[];
  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    warns.add(message);
  }

  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) => body();
}

LocalIntakeServer _server({
  required BridgeTelemetry telemetry,
  Future<CommandOutcome> Function()? handler,
}) => LocalIntakeServer(
  telemetry: telemetry,
  correlationIdGenerator: _counterId,
  onCommand: (_) async =>
      handler == null ? const CommandOutcome(ok: true) : await handler(),
  protection: _openProtection(),
);

String _post(String hostHeader, String body, [String extraHeaders = '']) =>
    'POST / HTTP/1.1\r\n'
    'Host: $hostHeader\r\n'
    'Origin: https://agent.test\r\n'
    'Sec-Fetch-Mode: cors\r\n'
    'Sec-Fetch-Dest: empty\r\n'
    'Content-Type: application/json\r\n'
    'Content-Length: ${utf8.encode(body).length}\r\n'
    '$extraHeaders'
    '\r\n$body';

const _alive = '{"data":["ALIVE"]}';

/// Receives a full reply from a connected socket - understands both framings:
/// content-length and chunked (replies written with no explicit length arrive
/// chunked). [remoteClosed], when passed, completes at EOF without cancelling (the cut witness).
Future<Map<String, Object>> _readResponse(
  Socket socket, {
  Duration wait = const Duration(seconds: 5),
  Completer<void>? remoteClosed,
}) {
  final done = Completer<Map<String, Object>>();
  final chunks = <int>[];
  late final StreamSubscription sub;
  sub = socket.listen(
    (d) {
      chunks.addAll(d);
      final text = latin1.decode(chunks, allowInvalid: true);
      final sep = text.indexOf('\r\n\r\n');
      if (done.isCompleted || sep < 0) return;
      final head = text.substring(0, sep);
      final cl = RegExp(
        'content-length:\\s*(\\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      final bodyText = text.substring(sep + 4);
      final hasCl = cl != null && bodyText.length >= int.parse(cl.group(1)!);
      final chunkedEnd = bodyText.endsWith('0\r\n\r\n');
      if (hasCl || chunkedEnd) {
        done.complete({
          'status': int.parse(head.split(' ')[1]),
          'body': bodyText,
        });
      }
    },
    onDone: () {
      if (remoteClosed != null && !remoteClosed.isCompleted) {
        remoteClosed.complete();
      }
      if (!done.isCompleted) {
        done.completeError('انقطع الاتصال قبل اكتمال الرد');
      }
    },
  );
  return done.future.timeout(wait).whenComplete(() {
    if (remoteClosed == null) sub.cancel();
  });
}

/// A pure exchange: connect + send + read the reply, then destroy the socket.
Future<Map<String, Object>> _send(int port, String raw) async {
  final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
  unawaited(socket.done.catchError((Object _) {}));
  socket.write(raw);
  final r = await _readResponse(socket);
  socket.destroy();
  return r;
}

/// A gauge that always works unless armed - then it throws synchronously inside
/// the path (safety net: the survivor sees a reply and closes, not a hung socket).
class _ExplodingMeasure extends BridgeTelemetry {
  var explodeOnHandle = false;

  @override
  void info(
    String m, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  @override
  void warn(
    String m, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  @override
  void error(
    String m, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) {
    if (explodeOnHandle && label == 'intake.handleRequest') {
      throw StateError('synthetic telemetry failure');
    }
    return body();
  }
}

void main() {
  test(
    'duplicate X-Correlation-Id: 400 duplicate_header, connection closed, zone clean',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final zoneErrors = <Object>[];
      await runZonedGuarded(() async {
        final srv = _server(telemetry: const SilentTelemetry());
        await srv.start(preferredPort: 31880, fallbacks: const [31881]);
        addTearDown(srv.stop);

        final req = _post(
          '127.0.0.1:${srv.port}',
          _alive,
          'X-Correlation-Id: cid-one\r\nX-Correlation-Id: cid-two\r\n',
        );
        final socket = await Socket.connect(
          InternetAddress.loopbackIPv4,
          srv.port,
        );
        unawaited(socket.done.catchError((Object _) {}));
        final remoteClosed = Completer<void>();
        // مستمع واحد يفعل الأمرين: الرد الكامل + EOF القطع (Stream أحادي)
        final respFuture = _readResponse(socket, remoteClosed: remoteClosed);
        addTearDown(socket.destroy);
        socket.write(req);
        final resp = await respFuture;
        expect(
          resp['status'],
          400,
          reason:
              'the probe saw an uncaught exception with no reply - the contract is now 400',
        );
        expect(resp['body'], contains('duplicate_header'));
        // الاتصال مغلق من الجهة البعيدة (عقد _terminate) لا معلقا
        await remoteClosed.future.timeout(
          const Duration(seconds: 3),
          onTimeout: () => fail('المقبس بقي معلقا — المسبار نفسه'),
        );

        // والخادم حي بعدها: طلب تال نظيف يمر
        final ok = await _send(
          srv.port,
          _post('127.0.0.1:${srv.port}', _alive),
        );
        expect(ok['status'], 200);
      }, (e, s) => zoneErrors.add(e));
      // نافذة ضخ لالتقاط أي متأخر قبل الحكم — المسبار أمسك خطأه هكذا
      await pumpEventQueue();
      expect(
        zoneErrors,
        isEmpty,
        reason:
            'regression guard: UNCAUGHT-IN-ZONE never returns - zero zone errors',
      );
    },
  );

  test(
    'repeated Origin or X-Portal-Token, even identical values: 400 duplicate_header',
    () async {
      final srv = _server(telemetry: const SilentTelemetry());
      await srv.start(preferredPort: 31882, fallbacks: const [31881]);
      addTearDown(srv.stop);

      final cases = <String, String>{
        'origin': 'Origin: https://a.example\r\nOrigin: https://a.example\r\n',
        'x-portal-token': 'X-Portal-Token: T1\r\nX-Portal-Token: T1\r\n',
      };
      for (final entry in cases.entries) {
        final r = await _send(
          srv.port,
          _post('127.0.0.1:${srv.port}', _alive, entry.value),
        );
        expect(
          r['status'],
          400,
          reason: 'a duplicated ${entry.key} is rejected explicitly',
        );
        expect(r['body'], contains('duplicate_header'));
      }
      final ok = await _send(srv.port, _post('127.0.0.1:${srv.port}', _alive));
      expect(
        ok['status'],
        200,
        reason:
            'the server stays alive - the rejection does not poison the next socket',
      );
    },
  );

  test(
    'safety net: escaped exception returns 500 internal, server stays alive',
    () async {
      final telemetry = _ExplodingMeasure();
      final srv = _server(telemetry: telemetry);
      await srv.start(preferredPort: 31883, fallbacks: const [31881]);
      addTearDown(srv.stop);

      telemetry.explodeOnHandle = true;
      final r = await _send(srv.port, _post('127.0.0.1:${srv.port}', _alive));
      expect(r['status'], 500);
      expect(r['body'], contains('internal'));
      telemetry.explodeOnHandle = false;
      final ok = await _send(srv.port, _post('127.0.0.1:${srv.port}', _alive));
      expect(
        ok['status'],
        200,
        reason: 'the survivor did not break the server or its seats',
      );
    },
  );

  test(
    'second start throws synchronous StateError, first server stays alive',
    () async {
      final srv = _server(telemetry: const SilentTelemetry());
      final p = await srv.start(preferredPort: 31884, fallbacks: const [31881]);
      addTearDown(srv.stop);
      expect(p, greaterThan(0));
      expect(
        () => srv.start(preferredPort: 31884),
        throwsStateError,
        reason:
            'a double start used to bind a second server and leak the first with no reference',
      );
      final ok = await _send(srv.port, _post('127.0.0.1:${srv.port}', _alive));
      expect(ok['status'], 200, reason: 'the first keeps serving requests');
    },
  );

  test(
    'stop waits for in-flight request, response completes, restart works',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final release = Completer<void>();
      final srv = _server(
        telemetry: const SilentTelemetry(),
        handler: () async {
          await release.future;
          return const CommandOutcome(ok: true);
        },
      );
      final p = await srv.start(preferredPort: 31885, fallbacks: const [31881]);

      final socket = await Socket.connect(InternetAddress.loopbackIPv4, p);
      unawaited(socket.done.catchError((Object _) {}));
      final respFuture = _readResponse(socket);
      socket.write(_post('127.0.0.1:$p', _alive));
      // حتى يستقر الطلب داخل مقعد المعالجة
      await pumpEventQueue();

      var stopped = false;
      final stopping = srv.stop().then((_) => stopped = true);
      await pumpEventQueue();
      expect(
        stopped,
        isFalse,
        reason:
            'a graceful stop awaits the in-flight reply - it does not cut one mid-send',
      );
      expect(srv.isListening, isFalse, reason: 'listening stopped at once');

      release.complete();
      final r = await respFuture;
      expect(
        r['status'],
        200,
        reason: 'the reply completed after the release, not amputated',
      );
      socket.destroy();
      await stopping.timeout(const Duration(seconds: 3));

      // وبعد الإفراغ: إعادة البدء على الخادم نفسه شرعية
      final p2 = await srv.start(
        preferredPort: 31885,
        fallbacks: const [31881],
      );
      expect(p2, greaterThan(0));
      final ok = await _send(p2, _post('127.0.0.1:$p2', _alive));
      expect(ok['status'], 200);
    },
  );

  test(
    'all ports busy: IntakeBindException — a plain Exception, never an Error',
    () async {
      final squatA = await ServerSocket.bind(
        InternetAddress.loopbackIPv4,
        31887,
      );
      final squatB = await ServerSocket.bind(
        InternetAddress.loopbackIPv4,
        31888,
      );
      addTearDown(() async {
        await squatA.close();
        await squatB.close();
      });

      final srv = _server(telemetry: const SilentTelemetry());
      await expectLater(
        srv.start(preferredPort: 31887, fallbacks: const [31888]),
        throwsA(isA<IntakeBindException>()),
      );
      // عقد المضيف: on Exception يمسكه (المضيف يصنف الحواجز بها)،
      // وهو ظرف بيئي متوقع لا خطأ برمجيا — فلا يكون Error البتة
      var caught = false;
      Object? seen;
      try {
        await srv.start(preferredPort: 31887, fallbacks: const [31888]);
      } on Exception catch (e) {
        caught = true;
        seen = e;
      }
      expect(
        caught,
        isTrue,
        reason: 'a pure Error would have slipped past on Exception handlers',
      );
      expect(
        seen,
        isNot(isA<Error>()),
        reason:
            'a failed port bind is an environmental condition, not a '
            'programming mistake - Dart Errors are not meant to be caught',
      );
    },
  );

  test(
    'two overlapping stop calls both complete after release — completer intact',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final release = Completer<void>();
      final srv = _server(
        telemetry: const SilentTelemetry(),
        handler: () async {
          await release.future;
          return const CommandOutcome(ok: true);
        },
      );
      final p = await srv.start(preferredPort: 31889, fallbacks: const [31881]);

      final socket = await Socket.connect(InternetAddress.loopbackIPv4, p);
      unawaited(socket.done.catchError((Object _) {}));
      final respFuture = _readResponse(socket);
      socket.write(_post('127.0.0.1:$p', _alive));
      await pumpEventQueue();

      var stoppedA = false;
      var stoppedB = false;
      final stopA = srv.stop().then((_) => stoppedA = true);
      final stopB = srv.stop().then((_) => stoppedB = true);
      await pumpEventQueue();
      expect(
        stoppedA || stoppedB,
        isFalse,
        reason: 'both await the in-flight work - no cut',
      );
      release.complete();
      final r = await respFuture;
      expect(r['status'], 200);
      socket.destroy();
      await stopA.timeout(const Duration(seconds: 3));
      await stopB.timeout(
        const Duration(seconds: 3),
        onTimeout: () => fail('أحد النداءين علق — الثاني طحن مصفّاه'),
      );
      expect(stoppedA && stoppedB, isTrue);
    },
  );

  test(
    'stop during pending start settles binding then closes — no orphan server',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = _server(telemetry: const SilentTelemetry());
      final starting = srv.start(
        preferredPort: 31890,
        fallbacks: const [31881],
      );
      // stop يسبق اكتمال الربط عمدا — العقد: ينتظر الحسم لا أن يعود فورا
      await srv.stop();
      final p = await starting.timeout(const Duration(seconds: 3));
      expect(p, greaterThan(0));
      expect(
        srv.isListening,
        isFalse,
        reason:
            'closed after the start settled - no live server orphaned after stop returns',
      );
      final p2 = await srv.start(preferredPort: p, fallbacks: const [31881]);
      expect(p2, greaterThan(0), reason: 'the instance can restart afterwards');
      await srv.stop();
    },
  );

  test(
    'handlerTimeout: null waits for handler to finish — unchanged behavior',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async {
          // تأخير محاكاة خادم: البطء صناعة الشاهد — بلا هذه المهلة
          // يثبت الفارق الذي يقيس عليه الاختبار مهلة null مقابل المحددة
          await Future<void>.delayed(const Duration(milliseconds: 250));
          return const CommandOutcome(ok: true);
        },
        protection: _openProtection(),
        handlerTimeout: null,
      );
      final p = await srv.start(preferredPort: 31891, fallbacks: const [31881]);
      final r = await _send(p, _post('127.0.0.1:$p', _alive));
      expect(
        r['status'],
        200,
        reason: 'no timeout: waiting behaves exactly as before',
      );
      await srv.stop();
    },
  );

  test(
    'handler exceeds handlerTimeout: 504 handler_timeout, seat freed, late ignored',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final late = Completer<void>();
      var calls = 0;
      var firstHandlerFinished = false;
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async {
          calls++;
          if (calls == 1) {
            await late.future;
            firstHandlerFinished = true;
            // خطأ متأخّر عنصرا شاهدا: بلا ignore كان سيصير خطأ zone يتيم
            throw StateError('late handler failure');
          }
          return const CommandOutcome(ok: true);
        },
        protection: _openProtection(),
        handlerTimeout: const Duration(milliseconds: 300),
        // مقعدان: اليتيم الأول يستهلك مقعدَ العمل الحي الثاني، فلو
        // سرّب الـ504 مقعده لرد الطلب التالي 503 — الشاهد صائم عند
        // التسرب الآن (بمقعد واحد كان اليتيم نفسه يرد 503 بحق)
        config: const BridgeConfig(maxConcurrentRequests: 2),
      );
      final p = await srv.start(preferredPort: 31892, fallbacks: const [31881]);

      final r = await _send(p, _post('127.0.0.1:$p', _alive));
      expect(r['status'], 504);
      expect(r['body'], contains('handler_timeout'));

      // المقعد تحرر: طلب تال فوري يجد مقعدا حيا ويُجاب (المعالق الأول
      // ما زال معلقا كيتيم واحد — داخل ميزانية المقعدَين)
      final ok = await _send(p, _post('127.0.0.1:$p', _alive));
      expect(
        ok['status'],
        200,
        reason:
            'the seat was freed - had the rejection leaked it, this would be 503',
      );

      // الناتج المتأخر يُهمل: المعالج الأول يكمل ثم يرمي بعد الرد — لا انفجار
      late.complete();
      await pumpEventQueue();
      expect(
        firstHandlerFinished,
        isTrue,
        reason:
            'the slow handler did complete - its result is ignored, not the handler itself',
      );
      final ok2 = await _send(p, _post('127.0.0.1:$p', _alive));
      expect(
        ok2['status'],
        200,
        reason: 'the server is alive - no trace of the late result',
      );
      await srv.stop();
    },
  );

  test(
    'null + handler-throws TimeoutException gets 500 internal, as before',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async =>
            throw TimeoutException('host handler own timeout'),
        protection: _openProtection(),
        handlerTimeout: null,
      );
      final p = await srv.start(preferredPort: 31893, fallbacks: const [31881]);
      final r = await _send(p, _post('127.0.0.1:$p', _alive));
      expect(
        r['status'],
        500,
        reason:
            'null يعني لا مهلة: رمي المعالج يمر بمساره الأصلي '
            'لا يصير 504 handler_timeout',
      );
      expect(r['body'], contains('internal'));
      await srv.stop();
    },
  );

  test(
    'orphan handlers count against the live-work budget: the 17th request is refused before any new handler',
    timeout: const Timeout(Duration(seconds: 30)),
    () async {
      var calls = 0;
      final never = Completer<CommandOutcome>();
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) {
          calls++;
          return never.future;
        },
        protection: _openProtection(),
        handlerTimeout: const Duration(milliseconds: 50),
        config: const BridgeConfig(maxConcurrentRequests: 16),
      );
      final p = await srv.start(preferredPort: 31894, fallbacks: const [31881]);
      for (var i = 0; i < 16; i++) {
        final r = await _send(p, _post('127.0.0.1:$p', _alive));
        expect(
          r['status'],
          504,
          reason: 'request ${i + 1} times out and leaves a running orphan',
        );
      }
      final r17 = await _send(p, _post('127.0.0.1:$p', _alive));
      expect(
        r17['status'],
        503,
        reason:
            'seats plus orphans are one budget - the 17th live work is '
            'refused, not a 17th orphan',
      );
      expect(r17['body'], contains('server_busy'));
      expect(
        calls,
        16,
        reason: 'the refused request never reached the handler',
      );
      await srv.stop();
    },
  );

  test(
    'stop() waits for a still-running orphaned handler',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      var handlerDone = false;
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async {
          // يتيم: يتجاوز مهلة الطلب ويستقر بعدها بقليل — داخل ميزانية
          // انتظار stop نفسها
          await Future<void>.delayed(const Duration(milliseconds: 400));
          handlerDone = true;
          return const CommandOutcome(ok: true);
        },
        protection: _openProtection(),
        handlerTimeout: const Duration(milliseconds: 300),
      );
      final p = await srv.start(preferredPort: 31895, fallbacks: const [31881]);
      final r = await _send(p, _post('127.0.0.1:$p', _alive));
      expect(r['status'], 504);
      await srv.stop();
      expect(
        handlerDone,
        isTrue,
        reason:
            'stop() waits for orphaned handlers up to the handler '
            'budget - work must not outlive the stop',
      );
    },
  );

  test(
    'stop() announces orphans that outlive the handler budget',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final rec = _Rec();
      final never = Completer<CommandOutcome>();
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (_) => never.future,
        protection: _openProtection(),
        handlerTimeout: const Duration(milliseconds: 100),
      );
      final p = await srv.start(preferredPort: 31896, fallbacks: const [31881]);
      await _send(p, _post('127.0.0.1:$p', _alive));
      await srv.stop();
      expect(
        rec.warns.any((w) => w.contains('orphan handler')),
        isTrue,
        reason:
            'an orphan that outlives the budget is announced with its '
            'count, not left silent',
      );
    },
  );

  test(
    'deep nesting under the element cap is refused before decode',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: _openProtection(),
      );
      final p = await srv.start(preferredPort: 31897, fallbacks: const [31881]);
      // 5000 قوسا متداخلا: 5000 عنصرا تحت سقف العناصر (10000) وعمق
      // 5000 فوق أي عمق معقول لأمر — قياسان مختلفان للاستغلال
      final body = '[' * 5000 + ']' * 5000;
      final r = await _send(p, _post('127.0.0.1:$p', body));
      expect(
        r['status'],
        413,
        reason: 'the depth cap fires in the same pre-decode pass',
      );
      expect(r['body'], contains('payload_too_complex'));
      await srv.stop();
    },
  );

  test('a public extraHost name warns about the rebinding opt-out', () async {
    final rec = _Rec();
    final srv = LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: _counterId,
      onCommand: (_) async => const CommandOutcome(ok: true),
      protection: _openProtection(),
      config: const BridgeConfig(extraHosts: ['portal.example']),
    );
    await srv.start(preferredPort: 31898, fallbacks: const [31881]);
    expect(
      rec.warns.any((w) => w.contains('DNS-rebinding')),
      isTrue,
      reason:
          'a public name in extraHosts is the host\'s explicit opt-out '
          'of the rebinding guard - say it once at startup',
    );
    await srv.stop();
  });

  test(
    'wrapper keys default to the neutral set — a domain key is opt-in',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: _openProtection(),
      );
      final p = await srv.start(preferredPort: 31901, fallbacks: const [31881]);
      // مفتاح من مجال آخر: ليس من المجموعة الافتراضية — الحزمة محايدة
      // فلا تفك مفتاح مجال إلا من يضيفه لإعداده بنفسه
      final domainKey = await _send(
        p,
        _post('127.0.0.1:$p', '{"tscCode":["QUJD"]}'),
      );
      expect(
        domainKey['status'],
        400,
        reason: 'the default wrapper set is domain-neutral',
      );
      expect(
        domainKey['body'],
        contains('unsupported_payload_shape'),
        reason:
            'an unrecognized wrapper is a known-but-unsupported shape, '
            'not an empty body',
      );
      // والمفاتيح المحايدة كما كانت
      final neutral = await _send(
        p,
        _post('127.0.0.1:$p', '{"data":["QUJD"]}'),
      );
      expect(neutral['status'], 200);
      await srv.stop();

      // ومن يضيف مفتاح مجاله يستعيده حرفيا
      final adapted = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: _openProtection(),
        config: const BridgeConfig(
          payloadWrapperKeys: {'data', 'payload', 'commands', 'tscCode'},
        ),
      );
      final q = await adapted.start(
        preferredPort: 31902,
        fallbacks: const [31881],
      );
      final restored = await _send(
        q,
        _post('127.0.0.1:$q', '{"tscCode":["QUJD"]}'),
      );
      expect(
        restored['status'],
        200,
        reason: 'an opted-in domain key unwraps exactly as before',
      );
      await adapted.stop();
    },
  );

  test(
    'fallbackErrorCode override restores an existing wire contract',
    () async {
      final rec = _Rec();
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (_) async =>
            const CommandOutcome(ok: false, errorMessage: 'boom'),
        protection: _openProtection(),
        config: const BridgeConfig(fallbackErrorCode: 'print_failed'),
      );
      final p = await srv.start(preferredPort: 31903, fallbacks: const [31881]);
      final r = await _send(p, _post('127.0.0.1:$p', _alive));
      expect(r['status'], 500);
      expect(
        r['body'],
        contains('print_failed'),
        reason:
            'a host with a frozen wire code sets it once in config and '
            'keeps its contract byte-for-byte',
      );
      await srv.stop();
    },
  );

  test(
    'a loopback-resolving public name warns; literal loopback stays silent',
    () async {
      final rec = _Rec();
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: _openProtection(),
        config: const BridgeConfig(
          extraHosts: ['127.0.0.1.nip.io', 'localhost', '127.0.0.1'],
        ),
      );
      await srv.start(preferredPort: 31899, fallbacks: const [31881]);
      expect(
        rec.warns.length,
        1,
        reason:
            'exactly one warning - for the public name, none for the '
            'literal loopback entries',
      );
      expect(
        rec.warns.single,
        contains('nip.io'),
        reason: 'the one warning is the public loopback-resolving name',
      );
      await srv.stop();
    },
  );
}
