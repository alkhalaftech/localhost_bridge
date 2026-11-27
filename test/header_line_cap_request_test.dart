// شاهد عدم القطع فوق السقف: طلب سليم كامل ترويسته
// Connection: keep-alive مبطّنة بمسافات حتى يتجاوز سطرُها سقف مخزن
// السطر المرشّح (سطر 302 بايتاً فوق سقف 256) — يكتمل الردّ 200 بكامله
// ولا يُقطع الاتصال قبل اكتمال ترويساته، على البابين العادي والآمن.
// والمعروفُ بعد هذا الطلب مكتوب في تعليق الكود حيث السقف: السطر
// الأطول من السقف لا يفهمه الفاحص فلا يعرف حدود ما بعده، وأسوأ الأثر
// قطعُ الاتصال المُبقى عند موعد الترويسات بدل مهلة الخمول — لا عطل
// في المهلة ولا يُشهد له هنا.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/tls_cert.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

// السطر «Connection: keep-alive» = 22 بايتاً، والحشو يرفعه فوق سقف 256
const int _padSpaces = 280;

var _idSeq = 0;

Future<LocalIntakeServer> _start({required bool tls}) async {
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () => 'line-cap-${_idSeq++}',
    onCommand: (_) async => const CommandOutcome(ok: true),
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(
        policy: const OriginPolicy(allowed: ['https://portal.example']),
        token: _t64,
      ),
    config: BridgeConfig(
      headerTimeout: const Duration(seconds: 15),
      securityContext: tls ? tlsContext() : null,
    ),
  );
  await srv.start(preferredPort: 0);
  return srv;
}

List<int> _paddedRequest(String host, String body) => utf8.encode(
  'POST / HTTP/1.1\r\n'
  'Host: $host\r\n'
  'Origin: https://portal.example\r\n'
  'Content-Type: application/json\r\n'
  'Connection: keep-alive${' ' * _padSpaces}\r\n'
  'X-Bridge-Token: $_t64\r\n'
  'Content-Length: ${utf8.encode(body).length}\r\n'
  '\r\n$body',
);

/// One complete exchange on a raw client: sends the request bytes and
/// completes with the reply text once the declared body length arrived;
/// a close or an error before completion is the failure, not a verdict.
Future<String> _exchange(Socket client, List<int> request) {
  final done = Completer<String>();
  final buffer = BytesBuilder(copy: true);
  late final StreamSubscription<List<int>> sub;
  sub = client.listen(
    (chunk) {
      buffer.add(chunk);
      final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
      final sep = text.indexOf('\r\n\r\n');
      if (sep < 0) return;
      final head = text.substring(0, sep);
      final cl = RegExp(
        r'content-length:\s*(\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      // الإتمام بالطول المعلن أو بإتمام الدورة المقطّعة: الردّان
      // المحتملان للخادم (transfer-encoding: chunked هو الرد المعتاد هنا)
      final complete = cl != null
          ? text.length - (sep + 4) >= int.parse(cl.group(1)!)
          : text.endsWith('0\r\n\r\n');
      if (complete) {
        unawaited(sub.cancel());
        if (!done.isCompleted) done.complete(text);
      }
    },
    onDone: () {
      if (!done.isCompleted) {
        done.completeError(
          StateError('the connection closed before the reply completed'),
        );
      }
    },
    onError: (Object e) {
      if (!done.isCompleted) {
        done.completeError(
          StateError('the connection errored before the reply completed: $e'),
        );
      }
    },
  );
  client.add(request);
  return done.future.timeout(const Duration(seconds: 10));
}

void main() {
  for (final tls in [false, true]) {
    final door = tls ? 'secure' : 'plain';
    test('a valid request whose padded Connection line outgrows the 256-byte '
        'reservation cap completes 200 on the $door door and is never cut '
        'before its headers complete', () async {
      final srv = await _start(tls: tls);
      addTearDown(srv.stop);
      final socket = tls
          ? await SecureSocket.connect(
              '127.0.0.1',
              srv.port,
              onBadCertificate: (cert) => true,
            )
          : await Socket.connect(InternetAddress.loopbackIPv4, srv.port);
      unawaited(socket.done.catchError((Object _) {}));
      expect(
        socket.setOption(SocketOption.tcpNoDelay, true),
        true,
        reason: 'the witness client must carry every write to the wire',
      );
      final reply = await _exchange(
        socket,
        _paddedRequest('127.0.0.1:${srv.port}', '{"data":["PRINT 1"]}'),
      );
      final status = int.tryParse(reply.split('\r\n').first.split(' ')[1]);
      // ignore: avoid_print
      print('LINE-CAP-REQUEST door=$door status=$status pad=$_padSpaces');
      expect(
        status,
        200,
        reason:
            'a request line longer than the reservation cap is a shape '
            'the scanner drops, never a connection it cuts - the headers '
            'complete and the exchange serves 200 on the $door door',
      );
      socket.destroy();
    }, timeout: const Timeout(Duration(seconds: 30)));
  }
}
