// سقف الاتصالات المفتوحة الخياري: dart:io لا يحدّ عددها، والخيار
// يرد فوقه 503 ويُخدم الطلب بعد هبوط العدد. الافتراضي مطفأ (0) فالسلك
// بلا الخيار حرفا كما هو. العناوين بالإنجليزية (حزمة منشورة).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/tls_cert.dart';

var _idSeq = 0;
String _cid() => 'conncap-${_idSeq++}';

IntakeProtection _allowlist() {
  final pr = IntakeProtection();
  pr.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
  return pr;
}

/// مقبس كاذب: ترويسات كاملة وجسم معلن ناقص — اتصال مفتوح يبقى حيا
/// (يحمل مقعداً في طور قراءة الجسم) حتى الهدم.
Future<Socket> _stall(
  int port, {
  String origin = 'https://portal.example',
}) async {
  final sock = await Socket.connect(InternetAddress.loopbackIPv4, port);
  unawaited(sock.done.catchError((Object _) {}));
  sock.add(
    utf8.encode(
      'POST / HTTP/1.1\r\n'
      'Host: 127.0.0.1:$port\r\n'
      'Origin: $origin\r\n'
      'Content-Type: application/json\r\n'
      'Content-Length: 100\r\n'
      '\r\nA',
    ),
  );
  await sock.flush();
  return sock;
}

Future<(int, String)> _post(int port) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', 'https://portal.example');
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } on Object {
    return (-1, '');
  } finally {
    client.close(force: true);
  }
}

/// طلب POST حقيقي على الباب الآمن بمصافحة كاملة: الحالة والجسم
Future<(int, String)> _tlsPost(int port) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5)
    ..badCertificateCallback = (cert, host, port) => true;
  try {
    final req = await client.postUrl(Uri.parse('https://127.0.0.1:$port/'));
    req.headers.set('Origin', 'https://portal.example');
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } on Object {
    return (-1, '');
  } finally {
    client.close(force: true);
  }
}

void main() {
  test(
    'above the open-connection cap the request answers 503, and after '
    'the count drops it is served',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: _allowlist(),
        config: const BridgeConfig(
          maxOpenConnections: 2,
          requestTimeout: Duration(seconds: 5),
        ),
      );
      final port = await srv.start(preferredPort: 0);
      final stalls = <Socket>[];
      try {
        stalls.add(await _stall(port));
        stalls.add(await _stall(port));
        await Future<void>.delayed(const Duration(milliseconds: 300));

        final (busy, busyBody) = await _post(port);
        expect(
          busy,
          503,
          reason:
              'the third open connection rides in over the cap of two - '
              'dart:io never bounds connections, so the option refuses '
              'the overflow instead',
        );
        expect(busyBody, contains('server_busy'));

        // هبوط العدد: المقبسان الكاذبان يموتان فيُخدم الطلب
        for (final s in stalls) {
          s.destroy();
        }
        stalls.clear();
        var served = false;
        final sw = Stopwatch()..start();
        while (sw.elapsed < const Duration(seconds: 10)) {
          final (status, body) = await _post(port);
          if (status == 200) {
            expect(body, contains('"ok":true'));
            served = true;
            break;
          }
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
        expect(
          served,
          true,
          reason:
              'after the open-connection count drops the next request is '
              'served - the cap is a gate, not a wall',
        );
      } finally {
        for (final s in stalls) {
          s.destroy();
        }
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'the cap is off by default: idle overflow connections never refuse a '
    'request without the option',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // الافتراضي صفر = مطفأ: السلك بلا الخيار حرفا كما هو — فوق أي
      // عدد من الاتصالات المفتوحة الطلب يُخدم. الشوارك بأصول
      // متمايزة كي لا يصطدم الفاحص بسقف مقاعد الأصل الجديد (موضوع
      // هذا الاختبار بوابات الاتصالات لا حصص الأصول)
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
              perOriginPerMinute: 1000,
            ),
          ),
        config: const BridgeConfig(requestTimeout: Duration(seconds: 5)),
      );
      final port = await srv.start(preferredPort: 0);
      final stalls = <Socket>[];
      try {
        for (var i = 0; i < 6; i++) {
          stalls.add(await _stall(port, origin: 'https://stall$i.example'));
        }
        await Future<void>.delayed(const Duration(milliseconds: 300));
        final (status, body) = await _post(port);
        expect(
          status,
          200,
          reason:
              'no maxOpenConnections option means no connection gate - the '
              'default wire never refuses for open sockets alone',
        );
        expect(body, contains('"ok":true'));
      } finally {
        for (final s in stalls) {
          s.destroy();
        }
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'a negative maxOpenConnections throws ArgumentError at construction',
    () {
      expect(
        () => LocalIntakeServer(
          telemetry: const SilentTelemetry(),
          correlationIdGenerator: _cid,
          onCommand: (_) async => const CommandOutcome(ok: true),
          config: const BridgeConfig(maxOpenConnections: -1),
        ),
        throwsArgumentError,
        reason:
            'a negative cap is a configuration mistake - it must surface '
            'at construction, never as mystery rejects on the wire',
      );
    },
  );

  test(
    'the cap counts the TLS feed too: while a handshake is stuck past '
    'arming a new TLS sender is cut on the wire, and its seat frees for '
    'the next sender',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // مصافحة عالقة بعد التسليح لا يراها عدّ الاتصالات في HttpServer
      // (لم تُسلَّم بعد) — التلقيمة هي التي تعدّها في الحساب نفسه فلا
      // باب جانبي تحت السقف على الباب الآمن
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: _allowlist(),
        config: BridgeConfig(
          maxOpenConnections: 1,
          requestTimeout: const Duration(seconds: 5),
          securityContext: tlsContext(),
        ),
      );
      final hello = await captureClientHello();
      final port = await srv.start(preferredPort: 0);
      Socket? stuck;
      try {
        stuck = await replayClientHello(hello, port);
        await Future<void>.delayed(const Duration(milliseconds: 600));

        // مسبار الحياة: الاتصال الجديد فوق السقف يُقطع قبل التسليح
        // فيموت على السلك — المصافحة الجارية التي تعدّها التلقمة تركب
        // السقف القائم نفسه فلا باب جانبي يحصّنه الباب الآمن
        final refused = await Socket.connect(
          InternetAddress.loopbackIPv4,
          port,
        );
        unawaited(refused.done.catchError((Object _) {}));
        await Future<void>.delayed(const Duration(milliseconds: 300));
        final probe = await wireProbe(refused);
        refused.destroy();
        expect(
          probe,
          startsWith('DEAD'),
          reason:
              'the in-flight handshake the feed counts rides the standing '
              'open-connection cap - the new socket over the cap is cut '
              'before arming and the cut reaches the wire',
        );
        // والعميل الحقيقي لا يكمل مصافحته ما دام السقف ممتلئاً
        final (busy, _) = await _tlsPost(port);
        expect(
          busy,
          -1,
          reason:
              'while the cap holds, a real TLS sender is refused at the '
              'transport gate - it cannot even complete its handshake',
        );

        // فشل المصافحة (موت العميل العالق) ينقص العدّ فيُخدم التالٍ
        stuck.destroy();
        stuck = null;
        var served = false;
        final sw = Stopwatch()..start();
        while (sw.elapsed < const Duration(seconds: 10)) {
          final (status, body) = await _tlsPost(port);
          if (status == 200) {
            expect(body, contains('"ok":true'));
            served = true;
            break;
          }
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
        expect(
          served,
          true,
          reason:
              'the failed handshake freed its seat - the next request over '
              'the TLS door is served',
        );
      } finally {
        stuck?.destroy();
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );
}
