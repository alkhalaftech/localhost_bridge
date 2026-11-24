// شواهد القطع بعد التسليم على النقلين: كل قطع يبدؤه الخادم على اتصال وصل
// بالفعل إلى HttpServer يجب أن يبلغ السلك، على النقل العادي وعلى النقل
// الآمن سواء. الشاهد الواحد يجري على المستمعين الاثنين، والحكم بمسبار
// العميل وحده، وعلى مرحلتين: وصول إغلاق جهة الكتابة (نهاية الدفق) داخل
// حدّ مكتوب، ثم رفضُ كتابةٍ بعده بإعادة تعيين — فالإغلاق المؤكد هو
// إغلاق طرف الخادم كله، لا إطفاءَ جهة الكتابة وحدها. والمشاهد أربعة: رفض مبكر فوق جسم معلن لم يصل، وجسم لا يكتمل
// يُقطع عند حدّه، واتصال خامل يغلقه مؤقت الخمول، وstop يغلق اتصالاً
// مُسلَّماً خاملاً.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/tls_cert.dart';

const _listed = 'https://portal.example';

var _idSeq = 0;
String _cid() => 'delivered-cut-${_idSeq++}';

String _transport(bool tls) => tls ? 'TLS' : 'plain';

/// The config of one scene over one transport.
BridgeConfig _config(
  bool tls, {
  Duration idleTimeout = const Duration(seconds: 60),
  Duration requestTimeout = const Duration(seconds: 30),
}) => BridgeConfig(
  securityContext: tls ? tlsContext() : null,
  idleTimeout: idleTimeout,
  requestTimeout: requestTimeout,
);

Future<LocalIntakeServer> _start({
  required bool tls,
  required BridgeConfig config,
  void Function()? onCommand,
}) async {
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: _cid,
    onCommand: (cmd) async {
      onCommand?.call();
      return const CommandOutcome(ok: true);
    },
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(policy: const OriginPolicy(allowed: [_listed])),
    config: config,
  );
  await srv.start(preferredPort: 0);
  return srv;
}

/// A raw POST on one transport that declares its body length and may carry
/// its first bytes. The reply is collected until its declared body is
/// complete, and the peer's close is recorded whenever it arrives.
class _Link {
  _Link(this.socket) {
    unawaited(
      socket.done.catchError((Object _) {
        if (!_refused.isCompleted) _refused.complete();
      }),
    );
    socket.listen(
      (chunk) {
        _buffer.add(chunk);
        _check();
      },
      onDone: () => _finish(),
      onError: (Object _) => _finish(),
    );
  }

  final Socket socket;
  final _buffer = BytesBuilder(copy: true);
  final _answered = Completer<void>();
  final _closed = Completer<void>();
  final _refused = Completer<void>();

  bool get answered => _answered.isCompleted;

  static Future<_Link> open(
    bool tls,
    int port, {
    required int contentLength,
    String origin = _listed,
    List<int> firstBytes = const [],
  }) async {
    final socket = tls
        ? await SecureSocket.connect(
            '127.0.0.1',
            port,
            onBadCertificate: (_) => true,
          )
        : await Socket.connect(InternetAddress.loopbackIPv4, port);
    final link = _Link(socket);
    link.send([
      ...utf8.encode(
        'POST / HTTP/1.1\r\n'
        'Host: 127.0.0.1:$port\r\n'
        'Origin: $origin\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: $contentLength\r\n'
        '\r\n',
      ),
      ...firstBytes,
    ]);
    return link;
  }

  // بلا flush بعد الكتابة: flush يربط الحوض حتى يكتمل، وكل add بعده
  // يرمي «StreamSink is bound to a stream» فيضيع البايت — والكتابة
  // وحدها تخرج فوراً على النقلين
  void send(List<int> bytes) {
    try {
      socket.add(bytes);
    } on SocketException {
      // قطعه الخادم قبل هذه الكتابة: الرد والإغلاق هما الحكم
    }
  }

  String get text => latin1.decode(_buffer.toBytes(), allowInvalid: true);

  String get statusLine => text.split('\r\n').first;

  void _check() {
    if (_answered.isCompleted) return;
    final text = this.text;
    final sep = text.indexOf('\r\n\r\n');
    if (sep < 0) return;
    final m = RegExp(
      r'Content-Length:\s*(\d+)',
      caseSensitive: false,
    ).firstMatch(text.substring(0, sep));
    if (m == null) {
      if (text.endsWith('0\r\n\r\n')) _answered.complete();
      return;
    }
    if (text.length - (sep + 4) >= int.parse(m.group(1)!)) {
      _answered.complete();
    }
  }

  void _finish() {
    if (!_answered.isCompleted) _answered.complete();
    if (!_closed.isCompleted) _closed.complete();
  }

  /// Completes once the reply is complete or the connection is closed.
  Future<void> get answeredFuture => _answered.future;

  /// True when the server end of the stream arrived - end of stream or an
  /// error on it - within [bound]; false while it stays open.
  Future<bool> eofWithin(Duration bound) async {
    try {
      await _closed.future.timeout(bound);
      return true;
    } on TimeoutException {
      return false;
    }
  }

  /// True when the server end is fully closed, not merely shut for writing:
  /// the reply's end of stream arrives within [eofBound], and bytes the
  /// client still writes after it are refused with a reset within
  /// [resetBound]. A server end that only shut its write side keeps
  /// accepting those bytes silently.
  Future<bool> cutWithin({
    required Duration eofBound,
    required Duration resetBound,
  }) async {
    if (!await eofWithin(eofBound)) return false;
    final sw = Stopwatch()..start();
    while (sw.elapsed < resetBound) {
      try {
        socket.add(<int>[0x41]);
        await socket.flush().timeout(const Duration(milliseconds: 200));
      } on Object {
        return true;
      }
      if (_refused.isCompleted) return true;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    return _refused.isCompleted;
  }

  void destroy() => socket.destroy();
}

void main() {
  for (final tls in [false, true]) {
    final transport = _transport(tls);

    group(transport, () {
      test('an early rejection over a declared body that never arrives is '
          'answered, then cut on the wire', () async {
        // رفض بوابة الأصل قبل قراءة الجسم: الرد أولاً، ثم تفريغ محدود
        // لجسم لن يصل، ثم القطع — والقطع هو المختبر
        final srv = await _start(
          tls: tls,
          config: _config(
            tls,
            requestTimeout: const Duration(milliseconds: 700),
          ),
        );
        addTearDown(srv.stop);
        final link = await _Link.open(
          tls,
          srv.port,
          contentLength: 100,
          origin: 'https://stranger.example',
        );
        addTearDown(link.destroy);
        await link.answeredFuture.timeout(const Duration(seconds: 5));
        expect(link.statusLine, contains(' 403 '));
        final cut = await link.cutWithin(
          eofBound: const Duration(seconds: 5),
          resetBound: const Duration(seconds: 3),
        );
        expect(
          cut,
          true,
          reason:
              'after its bounded drain of the unread body the server closes '
              'its end of the connection, and over $transport the close '
              'must reach the wire',
        );
      }, timeout: const Timeout(Duration(seconds: 30)));

      test('a request body that drips is refused 408 at the body limit, then '
          'cut on the wire', () async {
        // بالساعة الحقيقية: خمسة بايتات `["A"]` تصل واحداً كل أربع
        // ثوانٍ على الحدّ الافتراضي — والرد 408 ثم القطع لا مقبس باقٍ
        var entered = 0;
        final srv = await _start(
          tls: tls,
          config: _config(tls),
          onCommand: () => entered++,
        );
        addTearDown(srv.stop);
        final link = await _Link.open(
          tls,
          srv.port,
          contentLength: 5,
          firstBytes: '['.codeUnits,
        );
        addTearDown(link.destroy);
        final sw = Stopwatch()..start();
        for (var i = 1; i < 5 && !link.answered; i++) {
          final due = Duration(seconds: 4 * i);
          while (!link.answered && sw.elapsed < due) {
            await Future<void>.delayed(const Duration(milliseconds: 100));
          }
          if (link.answered) break;
          link.send('["A"]'.codeUnits.sublist(i, i + 1));
        }
        await link.answeredFuture.timeout(const Duration(seconds: 24));
        expect(link.statusLine, contains(' 408 '));
        expect(link.text, contains('"error":"request_timeout"'));
        final cut = await link.cutWithin(
          eofBound: const Duration(seconds: 6),
          resetBound: const Duration(seconds: 3),
        );
        expect(
          cut,
          true,
          reason:
              'a body refused at its limit leaves the connection closed at '
              'the server end, and over $transport the close must reach '
              'the wire',
        );
        expect(entered, 0);
      }, timeout: const Timeout(Duration(seconds: 60)));

      test('an idle delivered connection is closed by the idle timer between '
          'one period and two', () async {
        final srv = await _start(
          tls: tls,
          config: _config(tls, idleTimeout: const Duration(seconds: 1)),
        );
        addTearDown(srv.stop);
        final link = await _Link.open(
          tls,
          srv.port,
          contentLength: 15,
          firstBytes: utf8.encode('["BROWSER-LAB"]'),
        );
        addTearDown(link.destroy);
        await link.answeredFuture.timeout(const Duration(seconds: 5));
        expect(link.statusLine, contains(' 200 '));
        final early = await link.eofWithin(const Duration(milliseconds: 950));
        expect(
          early,
          false,
          reason: 'the idle timer never closes before one period',
        );
        final late = await link.cutWithin(
          eofBound: const Duration(seconds: 5),
          resetBound: const Duration(seconds: 3),
        );
        expect(
          late,
          true,
          reason:
              'the idle timer closes the idle connection, and over '
              '$transport its close must reach the wire',
        );
      }, timeout: const Timeout(Duration(seconds: 30)));

      test('stop closes a delivered idle connection: the peer reads the close '
          'after stop returns', () async {
        final srv = await _start(tls: tls, config: _config(tls));
        addTearDown(srv.stop);
        final link = await _Link.open(
          tls,
          srv.port,
          contentLength: 15,
          firstBytes: utf8.encode('["BROWSER-LAB"]'),
        );
        addTearDown(link.destroy);
        await link.answeredFuture.timeout(const Duration(seconds: 5));
        expect(link.statusLine, contains(' 200 '));
        expect(
          await link.eofWithin(const Duration(milliseconds: 300)),
          false,
          reason: 'the connection is idle and alive before the stop',
        );
        await srv.stop(timeout: const Duration(seconds: 5));
        final cut = await link.cutWithin(
          eofBound: const Duration(seconds: 3),
          resetBound: const Duration(seconds: 3),
        );
        expect(
          cut,
          true,
          reason:
              'stop closes the idle delivered connection, and over '
              '$transport its close must reach the wire',
        );
      }, timeout: const Timeout(Duration(seconds: 30)));
    });
  }
}
