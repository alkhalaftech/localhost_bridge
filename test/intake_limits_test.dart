// اختبارات حدود الموارد للمستقبِل المحلي — انحدار البلوكر الأمني:
// take(1024*1024) كان يعدّ أحداث الدفق لا البايتات فكان سقفا صوريا،
// ولا مهلة ولا سقف اتصالات إطلاقا. هنا نثبت الحدود الثلاثة من خارج
// العملية تماما كما يراها المهاجم: مقبس خام بلا تعاون من العميل.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

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
      final port = await server.start(preferredPort: 29991);
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
      final port = await server.start(preferredPort: 29992);
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
      final port = await server.start(preferredPort: 29993);
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
      );
      final port = await slowServer.start(preferredPort: 29994);
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
    final port = await server.start(preferredPort: 29995);
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
      final port = await server.start(preferredPort: 29996);
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
    final port = await strict.start(preferredPort: 29997);
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
      expect(
        () => buildWith(handlerTimeout: Duration.zero),
        throwsArgumentError,
        reason: 'a zero handler timeout must fail loudly',
      );
    },
  );
}
