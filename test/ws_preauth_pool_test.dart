// The pre-auth channel pool: an unauthenticated WebSocket channel waits
// for its credential inside a small internal pool (a total cap and a
// per-origin cap keyed by the normalized origin) and holds no command
// seat while it waits - a flood of credential-less channels can never
// starve the command seats, and a channel above the pool caps is
// refused before the upgrade with the standing wire codes. stop closes
// the pool with the live channels and waits for it to empty.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

final _token = generateBridgeToken();

const _browserHandshakeHeaders = <String, String>{
  'Sec-Fetch-Mode': 'websocket',
  'Sec-Fetch-Dest': 'websocket',
};

// خادم الحوض: السماح للجميع المحصنة مع القناة مسلحة — بيئة حادثة
// تدوير الأصول، والأصول المولَّدة تعبر البوابة كصفحات موقع حقيقي
Future<(LocalIntakeServer, IntakeProtection)> startPool({
  BridgeConfig config = const BridgeConfig(wsPath: '/ws'),
}) async {
  final pr = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(policy: const OriginPolicy(allowAllHardened: true), token: _token);
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    protection: pr,
    onCommand: (cmd) async => const CommandOutcome(ok: true),
    config: config,
  );
  await srv.start(preferredPort: 0);
  return (srv, pr);
}

// مصافحة قناة بلا اعتماد: ترويسات المصافحة الحقيقية بالمتصفح (Mode
// websocket وDest websocket فوق GET) — الرسالة الأولى لا تُرسل أبداً
Future<WebSocket> openPooled(int port, String origin) => WebSocket.connect(
  'ws://127.0.0.1:$port/ws',
  headers: {'Origin': origin, ..._browserHandshakeHeaders},
).timeout(const Duration(seconds: 5));

// انتظار إغلاق الخادم للقناة على السلك — إعادة الاتصال تتبع الإغلاق
Future<void> waitClosed(WebSocket ws) async {
  final done = Completer<void>();
  late final StreamSubscription<Object?> sub;
  sub = ws.listen(
    (_) {},
    onDone: () => done.complete(),
    onError: (Object _) => done.complete(),
  );
  await done.future.timeout(const Duration(seconds: 15));
  unawaited(sub.cancel());
}

// مسبار العميل: رمز الإغلاق الذي قرأه الطرف الآخر من السلك
Future<int?> closeProbe(WebSocket ws) async {
  await waitClosed(ws);
  return ws.closeCode;
}

// مصافحة خام تقرأ رد HTTP الذي كتبه الخادم قبل أي ترقية
Future<(int status, String body)> rawHandshake(
  int port, {
  required String origin,
}) async {
  final s = await Socket.connect('127.0.0.1', port);
  final head = StringBuffer()
    ..write('GET /ws HTTP/1.1\r\n')
    ..write('Host: 127.0.0.1:$port\r\n')
    ..write('Upgrade: websocket\r\n')
    ..write('Connection: Upgrade\r\n')
    ..write('Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n')
    ..write('Sec-WebSocket-Version: 13\r\n')
    ..write('Origin: $origin\r\n');
  _browserHandshakeHeaders.forEach((name, value) {
    head.write('$name: $value\r\n');
  });
  head.write('Content-Length: 0\r\n\r\n');
  s.add(utf8.encode(head.toString()));
  // القراءة حتى نهاية الترويسات لا حتى إغلاق الاتصال: رفضٌ قبل الترقية
  // يجيب ويقطع فورا، وترقية ناجحة يعلن 101 في الرأس ثم يصمت على مهلة
  // الاعتماد — فالحكم على الرأس حصرا يجعل الإحمرار حادا في الحالين
  final done = Completer<String>();
  final buffer = StringBuffer();
  late final StreamSubscription<List<int>> sub;
  sub = s.listen(
    (chunk) {
      buffer.write(utf8.decode(chunk, allowMalformed: true));
      final text = buffer.toString();
      if (done.isCompleted) return;
      // الترقية الناجحة (101) لا جسم يليها — اكتمال رأسها يكفي، أما
      // الرفض فيُكمل قطعُ الاتصال كتابتَه فيُقرأ الجسم كله عند onDone
      // بدل قطع القراءة عند نهاية الترويسات وقد يصل الجسم بقطعة لاحقة
      if (text.startsWith('HTTP/1.1 101') && text.contains('\r\n\r\n')) {
        done.complete(text);
      }
    },
    onDone: () {
      if (!done.isCompleted) done.complete(buffer.toString());
    },
    onError: (Object e) {
      if (!done.isCompleted) done.completeError(e);
    },
  );
  final text = await done.future.timeout(const Duration(seconds: 5));
  s.destroy();
  unawaited(sub.cancel());
  final statusMatch = RegExp(r'HTTP/1\.1 (\d{3})').firstMatch(text);
  return (statusMatch == null ? 0 : int.parse(statusMatch.group(1)!), text);
}

// أمر POST حقيقي من أصله يعيد الحالة — خطأ الشبكة يُسجل ‎(-1)‎
Future<int> post(int port, String origin) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', origin);
    req.headers.set('Sec-Fetch-Mode', 'cors');
    req.headers.set('Sec-Fetch-Dest', 'empty');
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close().timeout(const Duration(seconds: 5));
    await res.transform(utf8.decoder).join();
    return res.statusCode;
  } on Object {
    return -1;
  } finally {
    client.close(force: true);
  }
}

// انتظار محدود لشرط مقروء من العدادات — لا حائط زمني في الحكم
Future<bool> waitFor(
  bool Function() check, {
  Duration limit = const Duration(seconds: 2),
}) async {
  final sw = Stopwatch()..start();
  while (!check() && sw.elapsed < limit) {
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  return check();
}

void main() {
  // على SDK لا يعرف dart:io معلمة سقف النقل (تحت 3.13) لا تُسلَّح القناة
  // أصلاً فلا حوض ولا قنوات — التخطي الصادق مسمّى السبب كما في
  // ws_channel_test، والشواهد الكاملة فوق 3.13 أدناه
  if (!LocalIntakeServer.wsTransportCeilingSupported) {
    test('below Dart 3.13 the channel never arms, so no pre-auth pool '
        'exists - the pool witnesses are honest skips here', () {
      expect(LocalIntakeServer.wsTransportCeilingSupported, isFalse);
    });
    return;
  }

  test(
    'credential-less channels rotating four origins never hold a command '
    'seat: every POST from another origin is served for the whole run, '
    'and the active-seat counter reads zero whenever no POST is in flight',
    timeout: const Timeout(Duration(seconds: 90)),
    () async {
      // إعادة إنتاج الحادثة: أربعة أصول × أربع قنوات بلا اعتماد تعيد
      // الاتصال فور إغلاقها طوال أربعين ثانية — وفوق سقف الحوض الثماني
      // تُرفض المصافحات الجديدة على السلك وتعيد هي الأخرى. والأمر من
      // أصل خامس يُخدم 200 طوال المدة، والمقاعد النشطة صفر في كل لحظة
      // لا يكون فيها POST في الطريق
      final (srv, pr) = await startPool();
      final deadline = DateTime.now().add(const Duration(seconds: 40));

      Future<void> churn(String origin) async {
        while (DateTime.now().isBefore(deadline)) {
          try {
            final ws = await openPooled(srv.port, origin);
            // بلا اعتماد: الخادم يغلقها هو بانقضاء مهلة الاعتماد —
            // إعادة الاتصال فور الإغلاق لا بعده
            await waitClosed(ws);
          } on Object {
            // رفض مصافحة فوق سقف الحوض: إعادة بعد مهلة قصيرة كي لا
            // تحترق الحلقة بلا أثر على السلك
            await Future<void>.delayed(const Duration(milliseconds: 50));
          }
        }
      }

      final rotators = <Future<void>>[
        for (var i = 0; i < 4; i++)
          for (var j = 0; j < 4; j++) churn('https://rot-$i.example'),
      ];
      var served = 0;
      var checked = 0;
      try {
        while (DateTime.now().isBefore(deadline)) {
          // لحظة بلا POST في الطريق: القنوات غير المعتمدة لا تمسك
          // مقعداً فالعدّاد العلني للمقاعد النشطة يقرأ صفراً
          final drained = await waitFor(
            () => srv.counters.activeSeats == 0,
            limit: const Duration(seconds: 2),
          );
          expect(
            drained,
            isTrue,
            reason:
                'unauthenticated channels hold no command seat - the '
                'active-seat counter must read zero whenever no POST is '
                'in flight',
          );
          checked++;
          final status = await post(srv.port, 'https://sender.example');
          expect(
            status,
            200,
            reason:
                'the fifth origin command is served 200 for the whole '
                'run - the channel flood can never starve the command '
                'seats',
          );
          served++;
          // إيقاع تحت حصة الأصل على مسار السماح للجميع كي يبقى الحكم
          // على المقاعد لا على حصة المعدل
          await Future<void>.delayed(const Duration(milliseconds: 2500));
        }
      } finally {
        pr.dispose();
        await srv.stop();
      }
      expect(
        checked,
        greaterThanOrEqualTo(10),
        reason: 'the seat counter is read throughout the run, not once',
      );
      expect(
        served,
        greaterThanOrEqualTo(10),
        reason:
            'the fifth origin is served for the whole run, not just '
            'early on',
      );
      // حلقات التدوير انتهت بمواعيدها — لا مهمة معلقة بعد العودة
      await Future.wait(rotators);
    },
  );

  test(
    'a channel over the pool total cap is refused before the upgrade '
    'with server_busy, and the command from another origin is served',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      final (srv, pr) = await startPool();
      final pooled = <WebSocket>[];
      try {
        // أربعة أصول × قناتان بلا اعتماد = خانات الحوض الثماني كلها
        for (var i = 0; i < 4; i++) {
          for (var j = 0; j < 2; j++) {
            pooled.add(await openPooled(srv.port, 'https://rot-$i.example'));
          }
        }
        expect(pooled, hasLength(8));
        // التاسعة فوق السقف الكلي: رفض قبل الترقية برمز الانشغال القائم
        final (status, body) = await rawHandshake(
          srv.port,
          origin: 'https://ninth.example',
        );
        expect(
          status,
          503,
          reason:
              'the pool total cap refuses the ninth '
              'channel before any upgrade',
        );
        expect(body, contains('"server_busy"'));
        expect(body, isNot(contains('101')));
        // والأمر من أصل آخر يُخدم — الحوض لا يمس المقاعد
        expect(
          await post(srv.port, 'https://sender.example'),
          200,
          reason:
              'the pooled channels hold no seat - the command is '
              'served beside a full pool',
        );
      } finally {
        for (final ws in pooled) {
          unawaited(ws.close());
        }
        pr.dispose();
        await srv.stop();
      }
    },
  );

  test(
    'a channel over the pool per-origin cap is refused before the upgrade '
    'with origin_seat_limit, and another origin keeps its seat share',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // ميزانية المقاعد ضيقة عمدا: القنوات غير المعتمدة لا تمس مقعداً
      // فالأصل الآخر يُخدم رغم امتلاء حوض الأصل الأول — وقبل الإصلاح
      // تمسك القنوات الأربع كل المقاعد فيرد الأمر 503
      final (srv, pr) = await startPool(
        config: const BridgeConfig(wsPath: '/ws', maxConcurrentRequests: 4),
      );
      final pooled = <WebSocket>[];
      try {
        for (var j = 0; j < 4; j++) {
          pooled.add(await openPooled(srv.port, 'https://busy.example'));
        }
        expect(pooled, hasLength(4));
        // الخامسة من الأصل نفسه: سقف الأصل داخل الحوض هو الأصغر من
        // حصة الأصل والسقف الكلي — هنا الأربعة
        final (status, body) = await rawHandshake(
          srv.port,
          origin: 'https://busy.example',
        );
        expect(
          status,
          503,
          reason:
              'the pool per-origin cap refuses the '
              'fifth channel of one sender before any upgrade',
        );
        expect(body, contains('"origin_seat_limit"'));
        expect(body, isNot(contains('101')));
        // والمقاعد فارغة: أصل آخر يُخدم رغم الحوض الممتلئ
        expect(
          await post(srv.port, 'https://other.example'),
          200,
          reason:
              'the pooled channels never hold a seat - another origin '
              'keeps its full share beside the full pool',
        );
      } finally {
        for (final ws in pooled) {
          unawaited(ws.close());
        }
        pr.dispose();
        await srv.stop();
      }
    },
  );

  test(
    'stop harvests the pooled channels on the wire and every counter '
    'returns to zero: no socket survives the stop',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // ست قنوات بلا اعتماد فوق ميزانية مقاعد ضيقة: الحوض يأخذها كلها
      // (ست تحت الثماني، وثلاثة لكل أصل تحت حصة الأصل) والمقاعد فارغة
      final (srv, pr) = await startPool(
        config: const BridgeConfig(wsPath: '/ws', maxConcurrentRequests: 4),
      );
      final pooled = <WebSocket>[];
      var stopReportShown = false;
      try {
        for (var i = 0; i < 2; i++) {
          for (var j = 0; j < 3; j++) {
            pooled.add(await openPooled(srv.port, 'https://rot-$i.example'));
          }
        }
        expect(
          pooled,
          hasLength(6),
          reason:
              'all six credential-less channels upgrade - the pool '
              'never refuses under its caps nor holds a seat',
        );
        expect(
          srv.counters.activeSeats,
          0,
          reason: 'pooled channels hold no seat before the stop',
        );
        // العدّادان يُقرآن بانتظار محدود: ترقية العميل تعود قبل أن ينفذ
        // الخادم سطر تسجيل المقبس بعينه، فالقراءة المتزامنة سباق صادق
        // مع الخطوة الخادمية لا مع العدادات
        final pooledSeen = await waitFor(
          () => srv.counters.wsChannels == 6 && srv.counters.wsPreauthPool == 6,
        );
        expect(
          pooledSeen,
          isTrue,
          reason:
              'the handle counter and the pool counter both see the six '
              'pooled channels',
        );
        final probes = [for (final ws in pooled) closeProbe(ws)];
        final report = await srv.stop().timeout(const Duration(seconds: 5));
        stopReportShown = true;
        expect(
          report.fullyDrained,
          isTrue,
          reason:
              'stop closes the pool with the live channels and waits '
              'for it to empty - a fully drained stop',
        );
        expect(
          srv.counters.activeSeats,
          0,
          reason: 'the counters return to zero at the stop return',
        );
        expect(
          srv.counters.wsChannels,
          0,
          reason:
              'the handle counter returns to zero - no channel socket '
              'survives the stop',
        );
        expect(
          srv.counters.wsPreauthPool,
          0,
          reason: 'the pool counter returns to zero at the stop return',
        );
        expect(srv.isListening, isFalse);
        for (final probe in probes) {
          expect(
            await probe,
            isNotNull,
            reason:
                'every pooled channel client reads the server close '
                'from the wire - no socket survives the stop',
          );
        }
      } finally {
        if (!stopReportShown) {
          try {
            await srv.stop().timeout(const Duration(seconds: 5));
          } on Object {
            // فشل التنظيف بعد فشل الجسم: خطأ الجسم الأصلي أولى أن يُرى
          }
        }
        pr.dispose();
      }
    },
  );
}
