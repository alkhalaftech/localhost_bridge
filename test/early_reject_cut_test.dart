// شاهد القطع بعد الرفض: كل رفض مبكر يرد ثم يقطع الاتصال، وما قبل
// المعالج لا يحجز مقعدا بعد المهلة الكلية للطلب. العناوين بالإنجليزية
// (حزمة منشورة) والسلوك موصوف سلكيا: مقابس خام وأجسام معلنة ناقصة
// التسليم. ووقت المعالج بعدها عقد handlerTimeout وحده — شواهده في
// handler_deadline_contract_test.dart.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

class _Rec extends BridgeTelemetry {
  final warns = <String>[];
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
  }) {
    warns.add(m);
  }

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
  }) async => await body();
}

final _rec = _Rec();
var _idSeq = 0;
String _cid() => 'cut-${_idSeq++}';

Future<LocalIntakeServer> _startServer({
  required IntakeProtection protection,
  Duration requestTimeout = const Duration(milliseconds: 400),
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
}) async {
  final srv = LocalIntakeServer(
    telemetry: _rec,
    correlationIdGenerator: _cid,
    onCommand: onCommand ?? (cmd) async => const CommandOutcome(ok: true),
    protection: protection,
    requestTimeout: requestTimeout,
  );
  await srv.start(preferredPort: 0);
  return srv;
}

IntakeProtection _allowlist({int listedQuota = 0}) {
  final pr = IntakeProtection(telemetry: _rec);
  pr.update(
    policy: OriginPolicy(
      allowed: const ['https://portal.example'],
      listedPerOriginPerMinute: listedQuota,
    ),
  );
  return pr;
}

IntakeProtection _closed() {
  final pr = IntakeProtection(telemetry: _rec);
  pr.update(policy: const OriginPolicy());
  return pr;
}

// اتصال مهاجم: ترويسات كاملة تعلن جسما بطول 100 ثم بايت واحد، والمقبس
// يبقى مفتوحا (لا FIN) — هذا هو حاجز المقعد على الكود غير المصلح.
Future<Socket> _liar(int port, String rawHeaders) async {
  final s = await Socket.connect('127.0.0.1', port);
  s.add(utf8.encode('$rawHeaders\r\nA'));
  return s;
}

String _liarGet(int port) =>
    'GET / HTTP/1.1\r\n'
    'Host: 127.0.0.1:$port\r\n'
    'Content-Length: 100\r\n'
    '\r\n';

// يراقب مقبسا ويسجل هل وصل EOF (القطع من جهة الخادم)
StreamSubscription<List<int>> _watchEof(Socket s, void Function() onEof) {
  late final StreamSubscription<List<int>> sub;
  sub = s.listen((_) {}, onDone: onEof, onError: (Object _) => onEof());
  return sub;
}

// طلب شرعي كامل عبر HttpClient — يعيد (الحالة، الجسم، هل الاتصال باق)
Future<(int, String, bool)> _post(
  int port, {
  String? origin,
  String? token,
  String? contentType,
  String body = '["CMD"]',
  String method = 'POST',
  bool browserHeaders = false,
}) async {
  final client = HttpClient();
  try {
    final req = await client.open(method, '127.0.0.1', port, '/');
    if (origin != null) req.headers.set('Origin', origin);
    if (token != null) req.headers.set('X-Bridge-Token', token);
    if (browserHeaders) {
      req.headers.set('Sec-Fetch-Mode', 'cors');
      req.headers.set('Sec-Fetch-Dest', 'empty');
    }
    req.headers.set(
      HttpHeaders.contentTypeHeader,
      contentType ?? 'application/json',
    );
    final payload = utf8.encode(body);
    req.add(payload);
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text, res.persistentConnection);
  } finally {
    client.close(force: true);
  }
}

void main() {
  tearDown(() async {
    // لا خادم يبقى حيا بين الاختبارات — stop يُنتظر بحد أقصى
  });

  test('sixteen early-rejected connections with an unfinished body cannot '
      'starve the next legitimate request', () async {
    final srv = await _startServer(protection: _allowlist());
    final port = srv.port;
    final liars = <Socket>[];
    try {
      for (var i = 0; i < 16; i++) {
        liars.add(await _liar(port, _liarGet(port)));
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
      final sw = Stopwatch()..start();
      final (status, body, _) = await _post(
        port,
        origin: 'https://portal.example',
      );
      sw.stop();
      expect(status, 200, reason: 'the legitimate request must be served');
      expect(
        sw.elapsed,
        lessThan(const Duration(seconds: 1)),
        reason: 'the legitimate request must be served within a second',
      );
      expect(body, contains('"ok":true'));
    } finally {
      for (final s in liars) {
        s.destroy();
      }
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('every attacker connection is closed after the request timeout with '
      'margin, and the next request is served', () async {
    final srv = await _startServer(protection: _allowlist());
    final port = srv.port;
    final liars = <Socket>[];
    final eofCount = <int>[0];
    final subs = <StreamSubscription<List<int>>>[];
    try {
      for (var i = 0; i < 16; i++) {
        final s = await _liar(port, _liarGet(port));
        liars.add(s);
        subs.add(_watchEof(s, () => eofCount[0]++));
      }
      // المهلة 400ms ونافذة التفريغ لا تزيد عليها — الهامش ضعف المهلة
      await Future<void>.delayed(const Duration(milliseconds: 900));
      expect(
        eofCount[0],
        16,
        reason: 'every attacker connection must be closed by the server',
      );
      final (status, _, _) = await _post(
        port,
        origin: 'https://portal.example',
      );
      expect(status, 200, reason: 'the next request must be served');
    } finally {
      for (final s in subs) {
        await s.cancel();
      }
      for (final s in liars) {
        s.destroy();
      }
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('an origin_pending reply is readable while the body still arrives, '
      'then the connection cuts', () async {
    final pr = IntakeProtection(telemetry: _rec);
    pr.update(
      policy: OriginPolicy(
        onUnknownOrigin: (origin) => Completer<OriginConsent>().future,
        askTimeout: const Duration(minutes: 10),
      ),
    );
    final srv = await _startServer(protection: pr);
    final port = srv.port;
    final client = HttpClient();
    Socket? dribble;
    try {
      // ثلاثة أصول تملى نوافذ الموافقة الثلاث فالأصل الرابع يأخذ
      // origin_pending من سقف النوافذ دون سؤال جديد (بترويستا
      // Sec-Fetch ليعبر فحص شكل المتصفح ويُطلق السؤال فعلا)
      for (final o in [
        'https://a-one.example',
        'https://b-two.example',
        'https://c-three.example',
      ]) {
        final (st, body, _) = await _post(
          port,
          origin: o,
          body: '["CMD"]',
          browserHeaders: true,
        );
        expect(st, 403);
        expect(body, contains('origin_pending'));
      }
      // الطلب الرابع بجسم نحو 900 KiB يُرسل بالتقطير — الرد يجب أن يُقرأ
      // قبل اكتمال الجسم ثم ينقطع الاتصال
      dribble = await Socket.connect('127.0.0.1', port);
      const bodyBytes = 900 * 1024;
      const chunk = 8 * 1024;
      final buffer = BytesBuilder();
      final head = Completer<String>();
      final eof = Completer<void>();
      var bodySent = false;
      late final StreamSubscription<List<int>> sub;
      sub = dribble.listen(
        (c) {
          buffer.add(c);
          if (!head.isCompleted) {
            final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
            final sep = text.indexOf('\r\n\r\n');
            if (sep >= 0) head.complete(text);
          }
        },
        onDone: eof.isCompleted ? null : () => eof.complete(),
        onError: (Object _) {
          if (!eof.isCompleted) eof.complete();
        },
      );
      final raw =
          'POST / HTTP/1.1\r\n'
          'Host: 127.0.0.1:$port\r\n'
          'Origin: https://d-four.example\r\n'
          'Sec-Fetch-Mode: cors\r\n'
          'Sec-Fetch-Dest: empty\r\n'
          'Content-Type: application/json\r\n'
          'Content-Length: $bodyBytes\r\n'
          '\r\n';
      dribble.add(utf8.encode(raw));
      dribble.add(List.filled(chunk, 0x41));
      final headText = await head.future.timeout(
        const Duration(milliseconds: 1500),
        onTimeout: () => '',
      );
      var sent = chunk;
      Future<void> keepDribbling() async {
        try {
          while (sent < bodyBytes && !eof.isCompleted) {
            final n = (bodyBytes - sent).clamp(0, chunk);
            dribble!.add(List.filled(n, 0x41));
            sent += n;
            await Future<void>.delayed(const Duration(milliseconds: 2));
          }
          bodySent = true;
          await dribble!.flush();
        } on Object {
          // القطع من جهة الخادم أثناء التقطير مقبولة
        }
      }

      final bg = keepDribbling();
      expect(
        headText,
        isNotEmpty,
        reason: 'the reply must arrive before the body completes',
      );
      expect(bodySent, isFalse);
      final statusLine = headText.split('\r\n').first;
      expect(statusLine, contains(' 403 '));
      expect(headText.toLowerCase(), contains('access-control-allow-origin'));
      await eof.future.timeout(const Duration(seconds: 3), onTimeout: () {});
      expect(
        eof.isCompleted,
        isTrue,
        reason: 'the connection must cut after the reply',
      );
      // جسم الرد قد يصل في مقطع لاحق للرأس — الرمز يُقرأ من المخزون الكامل
      final fullText = latin1.decode(buffer.toBytes(), allowInvalid: true);
      expect(fullText, contains('origin_pending'));
      await bg.timeout(const Duration(seconds: 3), onTimeout: () {});
      await sub.cancel();
    } finally {
      client.close(force: true);
      dribble?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('a rate-limited listed origin reply is readable with an unread body, '
      'then the connection cuts', () async {
    final srv = await _startServer(protection: _allowlist(listedQuota: 1));
    final port = srv.port;
    Socket? dribble;
    try {
      // الطلب الأول يُقبل ويحجز الحصة (حصة 1/دقيقة)
      final (st0, _, _) = await _post(port, origin: 'https://portal.example');
      expect(st0, 200);
      // الثاني بجسم غير مقروء يُرسل بالتقطير — الرد 429 مقروء مبكرا
      dribble = await Socket.connect('127.0.0.1', port);
      const bodyBytes = 900 * 1024;
      const chunk = 8 * 1024;
      final buffer = BytesBuilder();
      final head = Completer<String>();
      final eof = Completer<void>();
      var bodySent = false;
      late final StreamSubscription<List<int>> sub;
      sub = dribble.listen(
        (c) {
          buffer.add(c);
          if (!head.isCompleted) {
            final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
            final sep = text.indexOf('\r\n\r\n');
            if (sep >= 0) head.complete(text);
          }
        },
        onDone: eof.isCompleted ? null : () => eof.complete(),
        onError: (Object _) {
          if (!eof.isCompleted) eof.complete();
        },
      );
      final raw =
          'POST / HTTP/1.1\r\n'
          'Host: 127.0.0.1:$port\r\n'
          'Origin: https://portal.example\r\n'
          'Content-Type: application/json\r\n'
          'Content-Length: $bodyBytes\r\n'
          '\r\n';
      dribble.add(utf8.encode(raw));
      dribble.add(List.filled(chunk, 0x41));
      final headText = await head.future.timeout(
        const Duration(milliseconds: 1500),
        onTimeout: () => '',
      );
      var sent = chunk;
      Future<void> keepDribbling() async {
        try {
          while (sent < bodyBytes && !eof.isCompleted) {
            final n = (bodyBytes - sent).clamp(0, chunk);
            dribble!.add(List.filled(n, 0x41));
            sent += n;
            await Future<void>.delayed(const Duration(milliseconds: 2));
          }
          bodySent = true;
          await dribble!.flush();
        } on Object {
          // القطع من جهة الخادم أثناء التقطير مقبولة
        }
      }

      final bg = keepDribbling();
      expect(
        headText,
        isNotEmpty,
        reason: 'the reply must arrive before the body completes',
      );
      expect(bodySent, isFalse);
      final statusLine = headText.split('\r\n').first;
      expect(statusLine, contains(' 429 '));
      expect(headText.toLowerCase(), contains('access-control-allow-origin'));
      await eof.future.timeout(const Duration(seconds: 3), onTimeout: () {});
      expect(
        eof.isCompleted,
        isTrue,
        reason: 'the connection must cut after the reply',
      );
      final fullText = latin1.decode(buffer.toBytes(), allowInvalid: true);
      expect(fullText, contains('origin_rate_limited'));
      await bg.timeout(const Duration(seconds: 3), onTimeout: () {});
      await sub.cancel();
    } finally {
      dribble?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('protocol rejections cut the connection after the reply', () async {
    // 405: طريقة مخالفة
    {
      final srv = await _startServer(protection: _allowlist());
      try {
        final (st, body, persistent) = await _post(
          srv.port,
          origin: 'https://portal.example',
          method: 'GET',
          body: '',
        );
        expect(st, 405);
        expect(body, contains('method_not_allowed'));
        expect(
          persistent,
          isFalse,
          reason: 'a rejected request must not keep the connection',
        );
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    }
    // 403 لأصل غير مدرج (الوضع المغلق)
    {
      final srv = await _startServer(protection: _closed());
      try {
        final (st, body, persistent) = await _post(
          srv.port,
          origin: 'https://attacker.example',
        );
        expect(st, 403);
        expect(body, contains('origin_not_listed'));
        expect(persistent, isFalse);
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    }
    // 415 لنوع نموذج مخفي من أصل مدرج
    {
      final srv = await _startServer(protection: _allowlist());
      try {
        final (st, body, persistent) = await _post(
          srv.port,
          origin: 'https://portal.example',
          contentType: 'application/x-www-form-urlencoded',
          body: 'cmd=echo',
        );
        expect(st, 415);
        expect(body, contains('unsupported_media_type'));
        expect(persistent, isFalse);
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    }
    // 400 unsupported_payload_shape: خريطة بلا مفاتيح معروفة
    {
      final srv = await _startServer(protection: _allowlist());
      try {
        final (st, body, persistent) = await _post(
          srv.port,
          origin: 'https://portal.example',
          body: '{"unknown":"x"}',
        );
        expect(st, 400);
        expect(body, contains('unsupported_payload_shape'));
        expect(persistent, isFalse);
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    }
    // 400 empty_payload: قائمة بلا أوامر
    {
      final srv = await _startServer(protection: _allowlist());
      try {
        final (st, body, persistent) = await _post(
          srv.port,
          origin: 'https://portal.example',
          body: '[]',
        );
        expect(st, 400);
        expect(body, contains('empty_payload'));
        expect(persistent, isFalse);
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    }
  }, timeout: const Timeout(Duration(seconds: 60)));
}
