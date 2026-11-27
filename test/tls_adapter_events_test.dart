// شواهد أحداث محوّل النقل الآمن بعد انصراف النظير: الرد المتدفق يبقى
// بلا خطأ غير معالج حين ينصرف النظير أثناء كتابته، والكتابة على مقبس
// مُسلَّم غاب نظيره لا ترمي داخل نداء راجع، وكل كتابة على دفق التسليم
// محروسة بإغلاقه. الحكم في منطقة تلتقط الأخطاء غير المعالجة: الصفر هو
// النجاح، لأن خطأً داخل نداء راجع قاتلٌ في العزلة الرئيسية.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:localhost_bridge/src/tls_handshake_feed.dart'
    show TlsHandshakeFeed;

import 'support/tls_cert.dart';

/// Runs [scene] in a zone that records every uncaught asynchronous error
/// and returns them once the scene settles.
Future<List<Object>> _uncaughtOf(Future<void> Function() scene) async {
  final uncaught = <Object>[];
  await runZonedGuarded(scene, (Object e, StackTrace stackTrace) {
    uncaught.add(e);
  });
  return uncaught;
}

Future<LocalIntakeServer> _streamingServer() async {
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        'adapter-events-${DateTime.now().microsecondsSinceEpoch}',
    onCommand: (cmd) async {
      for (var i = 0; i < 8; i++) {
        cmd.progress?.call({'step': i});
        await Future<void>.delayed(const Duration(milliseconds: 250));
      }
      return const CommandOutcome(ok: true);
    },
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(policy: const OriginPolicy(allowed: ['https://portal.example'])),
    config: BridgeConfig(
      allowStreamingReplies: true,
      securityContext: tlsContext(),
    ),
  );
  await srv.start(preferredPort: 0);
  return srv;
}

/// A TLS feed alone, without the intake: the delivered socket is the
/// transport's own adapter, driven by the test the way a consumer drives it.
Future<(TlsHandshakeFeed, int)> _bareFeed() async {
  final rawDoor = await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final feed = TlsHandshakeFeed(
    raw: rawDoor,
    context: tlsContext(),
    handshakeTimeout: const Duration(seconds: 5),
    openConnectionCap: 0,
    inFlightHandshakeCap: TlsHandshakeFeed.internalHandshakeCap,
    openConnectionTotal: () => 0,
    inFlightHandshakesTotal: () => 0,
    onCut: () {},
    onDelivered: () {},
    onOverHandshakeCap: (int _, int _) {},
    onOverConnectionCap: (int _, int _) {},
  );
  return (feed, rawDoor.port);
}

void main() {
  test('a client that half-closes and then resets during a streaming reply '
      'leaves no uncaught error', () async {
    // طلب يتدفق ردُّه إطاراً كل ربع ثانية، والعميل بعد أول إطار يغلق
    // جهة كتابته ثم يهدم مقبسه — والخادم يكتب بقية الإطارات على اتصال
    // غاب نظيره
    final uncaught = await _uncaughtOf(() async {
      final srv = await _streamingServer();
      final client = await SecureSocket.connect(
        '127.0.0.1',
        srv.port,
        onBadCertificate: (_) => true,
      );
      unawaited(client.done.catchError((Object _) {}));
      final body = utf8.encode('{"data":["BROWSER-LAB"]}');
      client.add(
        utf8.encode(
          'POST / HTTP/1.1\r\n'
          'Host: 127.0.0.1:${srv.port}\r\n'
          'Origin: https://portal.example\r\n'
          'Content-Type: application/json\r\n'
          'X-Bridge-Stream: events\r\n'
          'Content-Length: ${body.length}\r\n'
          '\r\n',
        ),
      );
      client.add(body);
      await Future<void>.delayed(const Duration(milliseconds: 350));
      unawaited(client.close().catchError((Object _) {}));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      client.destroy();
      await Future<void>.delayed(const Duration(seconds: 3));
      await srv.stop(timeout: const Duration(seconds: 5));
    });
    expect(
      uncaught,
      isEmpty,
      reason:
          'a peer that leaves mid-reply is an ordinary network event - '
          'nothing it causes may surface as an uncaught error',
    );
  }, timeout: const Timeout(Duration(seconds: 30)));

  for (final paused in [false, true]) {
    final consumer = paused
        ? 'while its consumer is paused'
        : 'while its consumer listens';
    test('writes on a delivered socket whose peer is gone throw to the '
        'writer only, never inside a stream callback ($consumer)', () async {
      final uncaught = await _uncaughtOf(() async {
        final (feed, port) = await _bareFeed();
        final delivered = Completer<Socket>();
        feed.listen(delivered.complete);
        final client = await SecureSocket.connect(
          '127.0.0.1',
          port,
          onBadCertificate: (_) => true,
        );
        final socket = await delivered.future.timeout(
          const Duration(seconds: 5),
        );
        // مستمع مثل مستمع HttpServer: يوقف نفسه أثناء ردٍّ قائم، فتبقى
        // نهاية الدفق معلَّقة عنده
        final sub = socket.listen(
          (_) {},
          onError: (Object _) {},
          onDone: () {},
        );
        if (paused) sub.pause();
        unawaited(client.close().catchError((Object _) {}));
        await Future<void>.delayed(const Duration(milliseconds: 200));
        client.destroy();
        await Future<void>.delayed(const Duration(milliseconds: 200));
        for (var i = 0; i < 6; i++) {
          try {
            socket.add(<int>[0x41]);
            await socket.flush().timeout(const Duration(milliseconds: 500));
          } on Object {
            // رفض الكاتب نفسه هو العقد القائم: الخطأ يعود لمن كتب
          }
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
        await Future<void>.delayed(const Duration(milliseconds: 400));
        socket.destroy();
        await feed.close();
      });
      expect(
        uncaught,
        isEmpty,
        reason:
            'an error raised on the socket after its stream ended has no '
            'receiver left - dropping it is the only safe course',
      );
    }, timeout: const Timeout(Duration(seconds: 30)));
  }

  test(
    'every write on the delivered stream is guarded by its closed state',
    () {
      // شاهد على المصدر: النافذة التي يصل فيها خطأٌ أو بايتات بعد إغلاق
      // الدفق لا تُصنع بمقبس حقيقي على نحو حتمي، فيُثبت الحراسُ هنا أن كل
      // إضافة على الدفق تنظر إغلاقه أولاً — والكتابة على دفق مغلق ترمي
      // داخل النداء الراجع
      final source = File('lib/src/tls_handshake_feed.dart').readAsStringSync();
      final adapter = source.substring(
        source.indexOf('class _RawSecureAdapter'),
      );
      final writes = adapter
          .split(RegExp(r'\r?\n'))
          .where(
            (line) => RegExp(r'_out\.(add|addError|close)\(').hasMatch(line),
          )
          .toList();
      for (final line in writes) {
        expect(
          line,
          contains('_out.isClosed'),
          reason:
              'a write on the delivered stream must look at its closed '
              'state first: $line',
        );
      }
      expect(
        writes,
        hasLength(5),
        reason:
            'the adapter writes to its delivered stream in five places '
            'alone - data, an error, the end of the raw stream, the '
            "peer's close, and the header-deadline cut - and every one "
            'of them is guarded',
      );
    },
  );
}
