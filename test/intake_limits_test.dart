// اختبارات حدود الموارد للمستقبِل المحلي — انحدار البلوكر الأمني:
// take(1024*1024) كان يعدّ أحداث الدفق لا البايتات فكان سقفا صوريا،
// ولا مهلة ولا سقف اتصالات إطلاقا. هنا نثبت الحدود الثلاثة من خارج
// العملية تماما كما يراها المهاجم: مقبس خام بلا تعاون من العميل.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _counterId() => 'corp-${_idSeq++}';

void main() {
  late LocalIntakeServer server;
  var handlerCalls = 0;

  setUp(() {
    handlerCalls = 0;
    server = LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _counterId,
      onCommand: (cmd) async {
        handlerCalls++;
        return const CommandOutcome(ok: true);
      },
      // مهلة قصيرة كي يثبت اختبار الصمت 408 بسرعة؛ اختبار سقف
      // الاتصالات يرفعها بنفسه عبر خادمه الخاص
      requestTimeout: const Duration(milliseconds: 700),
      protection: IntakeProtection()
        ..update(
          policy: const OriginPolicy(
            allowAllHardened: true,
            requireFetchMetadata: false,
            perOriginPerMinute: 1000,
          ),
        ),
    );
  });

  tearDown(() async => server.stop());

  /// Sends a raw request and returns the first reply status line - pacing
  /// control HttpClient does not offer (an early send cut is expected here, not a failure).
  Future<String> statusLineOf(
    int port,
    List<String> headers, {
    List<int>? body,
  }) async {
    final sock = await Socket.connect(InternetAddress.loopbackIPv4, port);
    // الخادم يقطع الاتصال بعد رد الحدود بينما قد نكون ما زلنا نرسل —
    // خطأ الكتابة متوقع ولا يجوز أن يفجر الاختبار
    unawaited(sock.done.catchError((Object _) {}));
    sock.add(utf8.encode('${headers.join('\r\n')}\r\n\r\n'));
    if (body != null) {
      sock.add(body);
      await sock.flush();
    }
    final completer = Completer<String>();
    late final StreamSubscription subs;
    subs = sock.listen(
      (data) {
        if (!completer.isCompleted) {
          final text = latin1.decode(data);
          final idx = text.indexOf('\r\n');
          if (idx > 0) {
            completer.complete(text.substring(0, idx));
            unawaited(subs.cancel());
            sock.destroy();
          }
        }
      },
      onDone: () {
        if (!completer.isCompleted) {
          completer.completeError('انقطع الاتصال قبل أي رد');
        }
      },
      onError: (Object e) {
        if (!completer.isCompleted) {
          completer.completeError('خطأ مقبس قبل الرد: $e');
        }
      },
    );
    return completer.future.timeout(const Duration(seconds: 10));
  }

  List<String> postHeaders(int contentLength) => [
    'POST / HTTP/1.1',
    'Host: 127.0.0.1',
    'Origin: https://portal.example',
    'Content-Type: application/json',
    'Content-Length: $contentLength',
  ];

  test(
    'a body over 1MB is rejected with 413 and never reaches the handler',
    () async {
      final port = await server.start(preferredPort: 0);
      final body = List<int>.filled(1024 * 1024 + 4096, 0x61); // 'a'
      final status = await statusLineOf(
        port,
        postHeaders(body.length),
        body: body,
      );
      expect(status, contains('413'));
      expect(
        handlerCalls,
        0,
        reason:
            'the rejection must precede any handler call - the guard is on the read',
      );
    },
  );

  test(
    'a body exactly at the 1MB limit is accepted — the cap never breaks legitimate traffic',
    () async {
      final port = await server.start(preferredPort: 0);
      // 1MB ناقص غلاف JSON كي يكون الإجمالي عند الحد لا فوقه
      final inner = 'x' * (1024 * 1024 - 100);
      final client = HttpClient();
      final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
      req.headers.set('Origin', 'https://portal.example');
      req.headers.contentType = ContentType.json;
      req.write('["$inner"]');
      final resp = await req.close();
      expect(resp.statusCode, 200);
      expect(handlerCalls, 1);
      client.close();
    },
  );

  test(
    'a request stalling mid-body is answered with 408 within the timeout',
    () async {
      final port = await server.start(preferredPort: 0);
      final sw = Stopwatch()..start();
      final partial = List<int>.filled(64, 0x61);
      // Content-Length صادق لكننا لا نرسل البقية أبدا — اتصال معلق
      final status = await statusLineOf(
        port,
        postHeaders(1024 * 1024),
        body: partial,
      );
      sw.stop();
      expect(status, contains('408'));
      expect(
        sw.elapsed,
        lessThan(const Duration(seconds: 5)),
        reason:
            'the timeout must cut the stalled request quickly, not wait for it',
      );
      expect(handlerCalls, 0);
    },
  );

  test(
    'above the concurrent request cap: 503 comes immediately without waiting',
    () async {
      // مهلة أطول كي يبقى الشاغلون الـ16 معلقين طوال الاختبار
      final slowServer = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (cmd) async {
          handlerCalls++;
          return const CommandOutcome(ok: true);
        },
        requestTimeout: const Duration(seconds: 10),
        protection: IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
              perOriginPerMinute: 1000,
            ),
          ),
        // موضوع الشاهد السقف العام ومعرف الارتباط في رفض الانشغال لا
        // حصص الأصول — الشوارع الستة عشر من أصل واحد فالسقف لكل أصل
        // يُرفع صراحة للمشهد الأصلي
        config: const BridgeConfig(maxSeatsPerOrigin: 16),
      );
      final port = await slowServer.start(preferredPort: 0);
      addTearDown(() => slowServer.stop());

      // 16 طلبا يصلون للترويسة ثم يصمتون — كل واحد يحجز مقعد معالجة
      final stalls = <Socket>[];
      for (var i = 0; i < const BridgeConfig().maxConcurrentRequests; i++) {
        final sock = await Socket.connect(InternetAddress.loopbackIPv4, port);
        unawaited(sock.done.catchError((Object _) {}));
        sock.add(
          utf8.encode('${postHeaders(1024 * 1024).join('\r\n')}\r\n\r\nhello'),
        );
        await sock.flush();
        stalls.add(sock);
      }
      // الترويسات وصلت والمعالجات بدأت قبل الطلب الفاحص
      await pumpEventQueue();

      final client = HttpClient();
      final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set('X-Correlation-Id', 'busy-cid-1');
      req.headers.contentType = ContentType.json;
      req.write('["ok"]');
      final resp = await req.close();
      expect(
        resp.statusCode,
        503,
        reason: 'over the cap it is rejected at once without reading',
      );
      // كل رد يحمل معرف الارتباط — الانشغال لم يكن يستثنى بعد
      expect(
        resp.headers.value('X-Correlation-Id'),
        'busy-cid-1',
        reason:
            'the busy rejection is tied to the caller attempt like any other reply',
      );
      client.close();
      for (final s in stalls) {
        s.destroy();
      }
    },
  );

  test('a 1MiB body of empty JSON elements is rejected with 413 '
      'payload_too_complex before parsing', () async {
    final port = await server.start(preferredPort: 0);
    // Maximal element density: every three bytes become two decoded map
    // allocations - exactly the amplification shape the cap exists for.
    final parts = <String>['['];
    var budget = 1024 * 1024 - 2;
    while (budget >= 3) {
      final piece = budget > 3 ? '{},' : '{}';
      parts.add(piece);
      budget -= piece.length;
    }
    parts.add(']');
    final body = utf8.encode(parts.join());
    final status = await statusLineOf(
      port,
      postHeaders(body.length),
      body: body,
    );
    expect(status, contains('413'));
    expect(
      handlerCalls,
      0,
      reason: 'the element gate must reject before the handler runs',
    );
  });

  test(
    'braces and commas inside JSON strings are not counted as elements',
    () async {
      final port = await server.start(preferredPort: 0);
      // Structural bytes far beyond the default cap, but all of them sit
      // inside one string: one element of decoding pressure, and it passes.
      final hostile = '{[,,{' * (1024 * 1024 ~/ 20);
      final client = HttpClient();
      final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
      req.headers.set('Origin', 'https://portal.example');
      req.headers.contentType = ContentType.json;
      req.write('["$hostile"]');
      final resp = await req.close();
      expect(resp.statusCode, 200);
      expect(handlerCalls, 1);
      client.close();
    },
  );

  test('the JSON element cap is configurable at the server level', () async {
    final strict = LocalIntakeServer(
      config: const BridgeConfig(maxJsonElements: 4),
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _counterId,
      onCommand: (_) async => const CommandOutcome(ok: true),
      protection: IntakeProtection()
        ..update(
          policy: const OriginPolicy(
            allowAllHardened: true,
            requireFetchMetadata: false,
            perOriginPerMinute: 1000,
          ),
        ),
    );
    final port = await strict.start(preferredPort: 0);
    addTearDown(strict.stop);
    final client = HttpClient();
    Future<int> post(String body) async {
      final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
      req.headers.set('Origin', 'https://portal.example');
      req.headers.contentType = ContentType.json;
      req.write(body);
      final resp = await req.close();
      await resp.drain<void>();
      return resp.statusCode;
    }

    // "["a","b"]" carries 2 structural tokens, the 5-element list carries 5.
    expect(await post('["a","b"]'), 200);
    expect(await post('["a","b","c","d","e"]'), 413);
    client.close();
  });

  test(
    'non-positive caps and timeouts throw ArgumentError at construction',
    () {
      // Each of these would silently reject or break every request at
      // runtime; a configuration mistake must fail at construction instead.
      const badConfigs = [
        BridgeConfig(maxBodyBytes: 0),
        BridgeConfig(maxBodyBytes: -1),
        BridgeConfig(maxConcurrentRequests: 0),
        BridgeConfig(maxJsonElements: 0),
        BridgeConfig(maxJsonElements: -5),
        BridgeConfig(requestTimeout: Duration.zero),
        BridgeConfig(idleTimeout: Duration(milliseconds: -1)),
      ];
      for (final cfg in badConfigs) {
        expect(
          () => LocalIntakeServer(
            onCommand: (_) async => const CommandOutcome(ok: true),
            telemetry: const SilentTelemetry(),
            correlationIdGenerator: _counterId,
            config: cfg,
          ),
          throwsArgumentError,
          reason: 'a non-positive config field must fail loudly',
        );
      }

      LocalIntakeServer buildWith({
        Duration? requestTimeout,
        Duration? handlerTimeout,
      }) => LocalIntakeServer(
        onCommand: (_) async => const CommandOutcome(ok: true),
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        requestTimeout: requestTimeout,
        handlerTimeout: handlerTimeout,
      );

      expect(
        () => buildWith(requestTimeout: Duration.zero),
        throwsArgumentError,
        reason: 'a zero timeout override must fail loudly',
      );
      // الصفر صار الثابت المسماة noHandlerTimeout (بلا مهلة) بعقد ج5 —
      // والسالب يبقى خطأ إعداد يُرفض صاخباً وقت البناء
      expect(
        () => buildWith(handlerTimeout: Duration(milliseconds: -1)),
        throwsArgumentError,
        reason: 'a negative handler budget must fail loudly',
      );
      expect(
        buildWith(handlerTimeout: LocalIntakeServer.noHandlerTimeout),
        isA<LocalIntakeServer>(),
        reason:
            'Duration.zero is the named noHandlerTimeout constant - a '
            'valid explicit no-deadline marker, not a mistake',
      );
    },
  );

  group('the body deadline is absolute, not event-gated', () {
    /// خادم مهلة 5s وحماية محصنة تقبل الأصول https بلا ترويسات fetch.
    /// كل مدد هذه المجموعة عشرة أضعاف جدولها الأصلي والنسب باقية —
    /// هامش الحسم صار بثوان لا بمئات الميلي ثانية فلا يكسره اختلاس
    /// ساعة مضيف محمّل، وبقاؤه بالعقد نفسه (1.25 ضعف الموعد مثلها).
    LocalIntakeServer deadlineServer() => LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _counterId,
      onCommand: (cmd) async {
        handlerCalls++;
        return const CommandOutcome(ok: true);
      },
      requestTimeout: const Duration(seconds: 5),
      protection: IntakeProtection()
        ..update(
          policy: const OriginPolicy(
            allowAllHardened: true,
            requireFetchMetadata: false,
            perOriginPerMinute: 1000,
          ),
        ),
    );

    /// ترويسات POST مقطّعة بلا Content-Length حصراً — فلا بوابة CL
    /// أصلاً والمهلة الصمتية وحدها لا تحرس العمر المطلق.
    Future<Socket> chunkedHead(int port) async {
      final sock = await Socket.connect(InternetAddress.loopbackIPv4, port);
      unawaited(sock.done.catchError((Object _) {}));
      sock.add(
        utf8.encode(
          'POST / HTTP/1.1\r\n'
          'Host: 127.0.0.1:$port\r\n'
          'Origin: https://portal.example\r\n'
          'Content-Type: application/json\r\n'
          'Transfer-Encoding: chunked\r\n\r\n',
        ),
      );
      await sock.flush();
      return sock;
    }

    Future<void> dripChunk(Socket sock, [int size = 64]) async {
      sock.add(utf8.encode('${size.toRadixString(16)}\r\n'));
      sock.add(List<int>.filled(size, 0x61));
      sock.add(utf8.encode('\r\n'));
      await sock.flush();
    }

    /// سطر الحالة الأول من مقبس مفتوح قائم — الطلب أُرسل عليه أصلاً.
    Future<String> statusOfSocket(
      Socket sock, {
      Duration wait = const Duration(seconds: 10),
    }) {
      final completer = Completer<String>();
      late final StreamSubscription subs;
      subs = sock.listen(
        (data) {
          if (completer.isCompleted) return;
          final text = latin1.decode(data);
          final idx = text.indexOf('\r\n');
          if (idx > 0) {
            completer.complete(text.substring(0, idx));
            unawaited(subs.cancel());
          }
        },
        onDone: () {
          if (!completer.isCompleted) completer.completeError('انقطع قبل الرد');
        },
        onError: (Object e) {
          if (!completer.isCompleted) completer.completeError('خطأ مقبس: $e');
        },
      );
      return completer.future.timeout(wait);
    }

    test(
      'a chunked body completing after the deadline is rejected 408, handler untouched',
      timeout: const Timeout(Duration(seconds: 20)),
      () async {
        final server = deadlineServer();
        final port = await server.start(preferredPort: 0);
        addTearDown(server.stop);
        final sock = await chunkedHead(port);
        // الترتيب لا الساعة: الرد يسجَّل قبل كتابة الخاتمة المتأخرة —
        // التوقيت الحدّي القديم (أقل من 600ms أمام ختام ~620ms) كان
        // هامش 20ms يكسره اختلاس واحد فوقه
        final order = <String>[];
        final reply = statusOfSocket(sock);
        unawaited(
          reply.then(
            (_) => order.add('reply'),
            onError: (Object _) => order.add('reply-error'),
          ),
        );
        // الختام عند ~6.2s من البداية حصرا: بعد الموعد المطلق (5s) وقبل
        // أن تُغلق فجوة الصمت (آخر قطرة عند ~3.6s + 5s) — فحص الأحداث
        // وحده كان يقبل هذا الجسم عند اكتماله، والصمت لا يفسر الحسم
        unawaited(
          Future<void>.delayed(const Duration(milliseconds: 6200)).then((
            _,
          ) async {
            order.add('terminator');
            sock.add(utf8.encode('0\r\n\r\n'));
            await sock.flush().catchError((Object _) {});
          }),
        );
        // قطرات ودية قبل الموعد بفجوات دون مهلة الصمت (0 / 2.0s / 3.5s)
        unawaited(dripChunk(sock));
        await Future<void>.delayed(const Duration(milliseconds: 2000));
        await dripChunk(sock);
        await Future<void>.delayed(const Duration(milliseconds: 1500));
        await dripChunk(sock);
        final status = await reply;
        expect(
          status,
          contains('408'),
          reason: 'a late completion is a timeout, not an acceptance',
        );
        expect(
          order.first,
          'reply',
          reason:
              'the reply was recorded before the late terminator was '
              'written - the absolute deadline cuts in its own time; a '
              'deadline gated on body events would accept the body when '
              'the terminator lands (200) or answer after it',
        );
        expect(
          handlerCalls,
          0,
          reason: 'a timed-out body never reaches the handler',
        );
        sock.destroy();
      },
    );

    test(
      'a drip under the silence window is cut by the absolute deadline before 1.25x of it',
      timeout: const Timeout(Duration(seconds: 30)),
      () async {
        final server = deadlineServer();
        final port = await server.start(preferredPort: 0);
        addTearDown(server.stop);
        final sock = await chunkedHead(port);
        final sw = Stopwatch()..start();
        final reply = statusOfSocket(sock);
        // قطرة كل 3.5s: دون مهلة الصمت (5s) ودون هامش الموعد نفسه —
        // القطرة الثانية تقع داخل المهلة بيقين فلا يفسر الوصول المتأخر
        // الحسم، ولا الصمت؛ حسمٌ في موعده لا يفسره إلا المؤقت المطلق.
        // والمدد عشرة أضعاف جدولها الأصلي والنسب باقية: هامش القضية
        // 1.25 ضعف الموعد صار 1.25s بدل 125ms
        unawaited(
          () async {
            for (var i = 0; i < 4; i++) {
              await dripChunk(sock);
              await Future<void>.delayed(const Duration(milliseconds: 3500));
            }
          }().catchError((Object _) {}),
        );
        final status = await reply;
        sw.stop();
        expect(status, contains('408'));
        expect(
          sw.elapsed,
          lessThan(const Duration(milliseconds: 6250)),
          reason:
              '1.25x of the 5s deadline is the bar - a drip pacing '
              'events under the silence window must still be cut on time; '
              'every duration here runs at tenfold with the same ratios, '
              'so the slack is 1.25s of wall clock, not 125ms',
        );
        sock.destroy();
      },
    );

    test(
      'after the deadline cut the seat and timers are freed: the next request is served and stop drains',
      timeout: const Timeout(Duration(seconds: 20)),
      () async {
        final server = deadlineServer();
        final port = await server.start(preferredPort: 0);
        addTearDown(server.stop);
        final sock = await chunkedHead(port);
        final reply = statusOfSocket(sock);
        unawaited(dripChunk(sock));
        // عشرة أضعاف الانتظار الأصلي (650ms): بعد الموعد بيقين والنسبة
        // باقية — القراءة نفسها تنتظر الرد فلا هامش زمني هنا أصلاً
        await Future<void>.delayed(const Duration(milliseconds: 6500));
        expect(await reply, contains('408'));
        sock.destroy();
        // مقعد تال حي يُخدم فورا بعد القطع
        final client = HttpClient();
        final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
        req.headers.set('Origin', 'https://portal.example');
        req.headers.contentType = ContentType.json;
        req.write('["ok"]');
        final resp = await req.close().timeout(const Duration(seconds: 5));
        expect(
          resp.statusCode,
          200,
          reason: 'the cut request released its seat - the next one is served',
        );
        client.close();
        // وstop يفرغ بلا تعليق — لا مؤقت حي ولا مقعد محجوز
        await server.stop().timeout(const Duration(seconds: 3));
      },
    );
  });

  test('a stalled body answers 408 with the stable request_timeout code in '
      'the reply body', () async {
    // الحارس الحرفي للرمز المنشور في جدول Stable error codes: الحالة
    // وحدها لا تكفي — الجسم هو ما تقرأه الصفحة فالرمز يُقاس فيه
    final port = await server.start(preferredPort: 0);
    final sock = await Socket.connect(InternetAddress.loopbackIPv4, port);
    unawaited(sock.done.catchError((Object _) {}));
    sock.add(
      utf8.encode(
        'POST / HTTP/1.1\r\n'
        'Host: 127.0.0.1:$port\r\n'
        'Origin: https://portal.example\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: 100\r\n'
        '\r\nA',
      ),
    );
    final buffer = BytesBuilder();
    final done = Completer<String>();
    late final StreamSubscription<List<int>> sub;
    sub = sock.listen(
      (d) {
        buffer.add(d);
      },
      onDone: () {
        if (!done.isCompleted) {
          done.complete(latin1.decode(buffer.toBytes(), allowInvalid: true));
        }
      },
      onError: (Object _) {
        if (!done.isCompleted) {
          done.complete(latin1.decode(buffer.toBytes(), allowInvalid: true));
        }
      },
    );
    // الرد 408 يقطع الاتصال بعقده (persistentConnection=false) —
    // الاكتمال عند النهاية يجمع الرأس والجسم كما وصلوا لا جزءاً منهما
    final reply = await done.future.timeout(const Duration(seconds: 5));
    await sub.cancel();
    sock.destroy();
    expect(reply.split('\r\n').first, contains(' 408 '));
    expect(
      reply.substring(reply.indexOf('\r\n\r\n') + 4),
      contains('"error":"request_timeout"'),
      reason: 'the published code sits in the body the page reads',
    );
    expect(
      handlerCalls,
      0,
      reason: 'the stalled request never reaches the handler',
    );
  });
}
