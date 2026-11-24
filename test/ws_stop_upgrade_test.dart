// شاهد تزامن الإيقاف مع ترقية القناة: stop يغلق القنوات الحية من لقطة
// يأخذها بعد إغلاق المستمعين، والقناة تأخذ خانتها في الحوض قبل ترقيتها
// وتدخل مجموعة الأحياء بعدها. فالشاهد يبدأ stop في أضيق لحظة يراها
// خارجيّ: اللحظة نفسها التي يظهر فيها عدّاد الحوض — والترقية عندئذٍ في
// الطريق أو انتهت للتو — ويتوقع ألا تعيش القناة بعد الإيقاف: يعود stop في
// الحال لا في مهلة الاعتماد، ويقرأ العميل إطار الإغلاق، وتعود العدادات
// صفراً. ويجري على النقلين.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/tls_cert.dart';

String _cid() => 'stop-upgrade-${DateTime.now().microsecondsSinceEpoch}';

/// A raw WebSocket client that answers the server's close frame with one, so
/// the server's close handshake completes instead of waiting for its own
/// deadline.
class _Peer {
  _Peer(this.socket) {
    socket.listen(
      (chunk) {
        _buffer.add(chunk);
        final bytes = _buffer.toBytes();
        if (_replied) return;
        // رأس 102… يأتي أولاً: يُتجاوَز، ثم يُبحث عن إطار الإغلاق (0x88)
        final text = latin1.decode(bytes, allowInvalid: true);
        final head = text.indexOf('\r\n\r\n');
        if (head < 0) return;
        for (var i = head + 4; i < bytes.length; i++) {
          if (bytes[i] == 0x88) {
            _replied = true;
            // إطار إغلاق مقنَّع بطول اثنين يحمل 1000
            socket.add(<int>[
              0x88, 0x82, 0x11, 0x22, 0x33, 0x44, //
              0x03 ^ 0x11, 0xE8 ^ 0x22,
            ]);
            return;
          }
        }
      },
      onDone: _finish,
      onError: (Object _) => _finish(),
    );
  }

  final Socket socket;
  final _buffer = BytesBuilder(copy: true);
  final _closed = Completer<void>();
  var _replied = false;

  void _finish() {
    if (!_closed.isCompleted) _closed.complete();
  }

  void sendUpgrade(int port) {
    final head = StringBuffer()
      ..write('GET /ws HTTP/1.1\r\n')
      ..write('Host: 127.0.0.1:$port\r\n')
      ..write('Upgrade: websocket\r\n')
      ..write('Connection: Upgrade\r\n')
      ..write('Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n')
      ..write('Sec-WebSocket-Version: 13\r\n')
      ..write('Origin: https://portal.example\r\n')
      ..write('Sec-Fetch-Mode: websocket\r\n')
      ..write('Sec-Fetch-Dest: websocket\r\n')
      ..write('Content-Length: 0\r\n\r\n');
    socket.add(utf8.encode(head.toString()));
  }

  /// True once the server closed the channel within [bound].
  Future<bool> closedWithin(Duration bound) async {
    try {
      await _closed.future.timeout(bound);
      return true;
    } on TimeoutException {
      return false;
    }
  }

  void destroy() => socket.destroy();
}

void main() {
  // على SDK لا يعرف dart:io معلمة سقف النقل (تحت 3.13) لا تُسلَّح القناة
  // فترمي عند البناء — ولا ترقية تسبق الإيقاف. تخطٍّ صادق مسمّى كما في
  // شهود القناة القائمة، والشاهد الكامل فوق 3.13 أدناه
  if (!LocalIntakeServer.wsTransportCeilingSupported) {
    test('below Dart 3.13 the channel never arms, so no upgrade can race '
        'the stop - an honest skip here', () {
      expect(LocalIntakeServer.wsTransportCeilingSupported, isFalse);
    });
    return;
  }

  for (final tls in [false, true]) {
    final transport = tls ? 'TLS' : 'plain';

    test('a stop that begins the moment a channel takes its pool slot closes '
        'that channel: it never outlives the stop ($transport)', () async {
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (cmd) async => const CommandOutcome(ok: true),
        wsAuthTimeout: const Duration(seconds: 2),
        protection: IntakeProtection(telemetry: const SilentTelemetry())
          ..update(
            policy: const OriginPolicy(allowed: ['https://portal.example']),
          ),
        config: BridgeConfig(
          wsPath: '/ws',
          securityContext: tls ? tlsContext() : null,
        ),
      );
      await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final peer = _Peer(
        tls
            ? await SecureSocket.connect(
                '127.0.0.1',
                srv.port,
                onBadCertificate: (_) => true,
              )
            : await Socket.connect(InternetAddress.loopbackIPv4, srv.port),
      );
      addTearDown(peer.destroy);
      peer.sendUpgrade(srv.port);
      // القراءة في كل دورة من دورات الأحداث: الخانة تؤخذ قبل ترقية
      // القناة، فظهورها في العدّاد هو أول ما يراه الخارجي منها
      var turns = 0;
      while (srv.counters.wsPreauthPool == 0 && turns < 5000) {
        await Future<void>.delayed(Duration.zero);
        turns++;
      }
      expect(
        srv.counters.wsPreauthPool,
        1,
        reason:
            'the channel holds its pool slot: its upgrade is in '
            'flight or just delivered',
      );
      final sw = Stopwatch()..start();
      final report = await srv.stop(timeout: const Duration(seconds: 6));
      sw.stop();
      expect(
        await peer.closedWithin(const Duration(seconds: 2)),
        true,
        reason:
            'the channel is closed by the stop - the peer reads the '
            'close frame over $transport',
      );
      expect(
        sw.elapsed,
        lessThan(const Duration(seconds: 1)),
        reason:
            'the stop closes the channel at once - it never waits for '
            'the channel auth deadline',
      );
      expect(report.fullyDrained, true);
      expect(report.wsPreauthPoolStillHeld, 0);
      expect(report.stillRunning, 0);
    }, timeout: const Timeout(Duration(seconds: 30)));
  }
}
