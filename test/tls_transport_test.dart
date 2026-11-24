// نقل TLS على الحلقة الراجعة: المستمع الآمن يُربط عبر التلقيمة حين
// يمرر المضيف securityContext جاهزاً — التلقيمة تقبل خاماً وتسلّح بعد
// بوابة أول سجل وتغذي HttpServer.listenOn بمحوّل فوق RawSecureSocket،
// والحزمة لا تولّد شهادة ولا تثبتها ولا تكتب ملفاً. الشهادة في
// test/support/tls_cert.dart ثابتان مضمنان (يحميان لا شيء، حلقي
// 127.0.0.1 و::1 وlocalhost فقط) ويقبلها عميل TLS بعلم badCertificate —
// لا توليد وقت تشغيل ولا اعتماديات.
//
// الشواهد: طقم السلك الزوجي كامل (باب عادي مقابل باب آمن على المصنع
// نفسه — الحالة والحالة) عبر التلقيمة على البابين، وزوجي ثانٍ على
// ::1 حيث يتوفر، وعائلة الميزانيات الزوجية، ومصافحة TLS لا تكتمل لا
// تحجز مقعداً ولا تصل إلى الخادم أصلاً وتُقطع على السلك عند مهلة
// المصافحة (المسلَّح العالق كذلك)، والمرسل الميت يفرغ مقعده، وصفحة
// الجسر المُخدمة تجاوز أصلها https لا http، والقناة wss، والإطفاء
// الافتراضي حرفاً ورفض توليفة مقبس اليونكس عند البناء.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/tls_cert.dart';

const _timeout = Duration(milliseconds: 700);
const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

SecurityContext _tlsContext() => tlsContext();

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

var _idSeq = 0;
String _counterId() => 'tls-${_idSeq++}';

LocalIntakeServer _make({
  required _Rec rec,
  required IntakeProtection pr,
  int delayMs = 0,
  BridgeConfig config = const BridgeConfig(maxSeatsPerOrigin: 16),
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
  Duration? handlerTimeout,
  Duration? wsAuthTimeout,
}) => LocalIntakeServer(
  telemetry: rec,
  correlationIdGenerator: _counterId,
  onCommand: (cmd) async {
    if (onCommand != null) return onCommand(cmd);
    if (delayMs > 0) {
      await Future<void>.delayed(Duration(milliseconds: delayMs));
    }
    return const CommandOutcome(ok: true);
  },
  protection: pr,
  config: config,
  requestTimeout: _timeout,
  handlerTimeout: handlerTimeout,
  wsAuthTimeout: wsAuthTimeout,
);

IntakeProtection _protection(String mode, _Rec rec) {
  final pr = IntakeProtection(telemetry: rec);
  switch (mode) {
    case 'allowAll':
      pr.update(
        policy: const OriginPolicy(
          allowAllHardened: true,
          requireFetchMetadata: false,
          perOriginPerMinute: 1000,
        ),
      );
    case 'allowlist':
      pr.update(
        policy: const OriginPolicy(allowed: ['https://portal.example']),
      );
    case 'token':
      pr.update(policy: const OriginPolicy(), token: _t64);
  }
  return pr;
}

String _dechunk(String body) {
  final out = StringBuffer();
  var i = 0;
  while (i < body.length) {
    final lineEnd = body.indexOf('\r\n', i);
    if (lineEnd < 0) break;
    final size = int.tryParse(body.substring(i, lineEnd), radix: 16);
    if (size == null || size == 0) break;
    final start = lineEnd + 2;
    if (start + size > body.length) break;
    out.write(body.substring(start, start + size));
    i = start + size + 2;
  }
  return out.toString();
}

// قارئ الرد المشترك: يكتب الطلب على المقبس ويجمع الرد حتى اكتماله
// (حسب طول المحتوى المعلن أو نهاية التأطير المجزأ أو قطع الاتصال) —
// ولا يفترض نصاً صالحاً في أي طرف.
Future<Map<String, Object?>> _drive(Socket socket, String request) async {
  final buffer = BytesBuilder();
  final done = Completer<Map<String, Object?>>();
  void settle() {
    final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    final head = sep < 0 ? text : text.substring(0, sep);
    final bodyRaw = sep < 0 ? '' : text.substring(sep + 4);
    final headers = <String, String>{};
    for (final line in head.split('\r\n').skip(1)) {
      final i = line.indexOf(':');
      if (i > 0) {
        headers[line.substring(0, i).trim().toLowerCase()] = line
            .substring(i + 1)
            .trim();
      }
    }
    final body = headers['transfer-encoding']?.toLowerCase() == 'chunked'
        ? _dechunk(bodyRaw)
        : bodyRaw;
    final statusLine = head.isEmpty ? '' : head.split('\r\n').first;
    done.complete({
      'status': statusLine.isEmpty
          ? -1
          : (int.tryParse(statusLine.split(' ')[1]) ?? -1),
      'headers': headers,
      'body': body,
    });
  }

  late final StreamSubscription<List<int>> sub;
  sub = socket.listen(
    (chunk) {
      buffer.add(chunk);
      if (done.isCompleted) return;
      final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
      final sep = text.indexOf('\r\n\r\n');
      if (sep < 0) return;
      final head = text.substring(0, sep);
      final clMatch = RegExp(
        r'content-length:\s*(\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      final bodyLen = text.length - (sep + 4);
      final chunkedEnd = text.endsWith('0\r\n\r\n');
      final hasCl = clMatch != null && bodyLen >= int.parse(clMatch.group(1)!);
      if (hasCl || chunkedEnd) {
        if (!done.isCompleted) settle();
        sub.cancel();
      }
    },
    onDone: () {
      if (!done.isCompleted) settle();
    },
  );
  socket.add(utf8.encode(request));
  return done.future.timeout(
    const Duration(seconds: 5),
    onTimeout: () => <String, Object?>{
      'status': -2,
      'headers': <String, String>{},
      'body': 'NO-RESPONSE',
    },
  );
}

// مقبض باب عادي: مقبس TCP خام يكتب الطلب المبني يدوياً
Future<Map<String, Object?>> _exchange(
  String address,
  int port,
  String request,
) async {
  final socket = await Socket.connect(address, port);
  final reply = await _drive(socket, request);
  socket.destroy();
  return reply;
}

// مقبض باب آمن: المصافحة TLS كاملة ثم الطلب المبني يدوياً على المقبس
// الآمن نفسه — قبول شهادة النصاب الذاتية بعلم badCertificate حصراً.
Future<Map<String, Object?>> _exchangeTls(
  String address,
  int port,
  String request,
) async {
  final socket = await SecureSocket.connect(
    address,
    port,
    onBadCertificate: (cert) => true,
  );
  final reply = await _drive(socket, request);
  socket.destroy();
  return reply;
}

String _post(
  String host,
  String body, {
  String? origin,
  String? token,
  String? contentType = 'application/json',
  String path = '/',
  Map<String, String> extra = const {},
}) {
  final h = StringBuffer()
    ..writeln('POST $path HTTP/1.1')
    ..writeln('Host: $host');
  if (contentType != null) {
    h.writeln('Content-Type: $contentType');
  }
  h.writeln('Content-Length: ${utf8.encode(body).length}');
  if (origin != null) h.writeln('Origin: $origin');
  if (token != null) h.writeln('X-Bridge-Token: $token');
  extra.forEach((name, value) {
    h.writeln('$name: $value');
  });
  h.write('\r\n');
  return h.toString() + body;
}

const _compareHeaders = <String>[
  'access-control-allow-origin',
  'access-control-allow-headers',
  'access-control-allow-methods',
  'access-control-max-age',
  'vary',
  'retry-after',
  'content-type',
];

void _expectSameWire(
  Map<String, Object?> plain,
  Map<String, Object?> tls,
  String caseName,
) {
  expect(
    tls['status'],
    plain['status'],
    reason:
        '[$caseName] the TLS door must answer the status the plain '
        'door answers',
  );
  expect(
    tls['body'],
    plain['body'],
    reason:
        '[$caseName] the TLS door must answer the body the plain '
        'door answers',
  );
  final ha = plain['headers'] as Map<String, String>;
  final hb = tls['headers'] as Map<String, String>;
  for (final name in _compareHeaders) {
    expect(
      hb[name],
      ha[name],
      reason: '[$caseName] header "$name" must match the plain door',
    );
  }
}

void main() {
  // الطقم الزوجي الكامل: باب عادي مقابل باب آمن على المصنع نفسه —
  // الحالة والحالة — عبر التلقيمة على الباب الرابعي، أو عبر مستمع
  // الـ::1 الاختياري حين overV6. صيغة المضيف في الترويسات وعنوان
  // الاتصال يتبعان الباب.
  Future<void> runCorpusPair({required bool overV6}) async {
    final plainDoor = overV6 ? '::1' : '127.0.0.1';
    String doorHost(int port) => overV6 ? '[::1]:$port' : '127.0.0.1:$port';
    final small = jsonEncode({
      'data': ['SIZE 3', 'CLS', 'TEXT 10,10,3,1,1,1,hello', 'PRINT 1,1'],
    });
    final over = 'x' * (1024 * 1024 + 1);
    const wrapper = 13;
    final at = '{"data":["${'x' * (1024 * 1024 - wrapper)}"]}';
    final malformedOrigin = 'https://portal.example/path';
    final longOrigin = 'https://${'a' * 600}.example';

    for (final mode in ['allowAll', 'allowlist', 'token']) {
      final recA = _Rec();
      final recB = _Rec();
      final plain = _make(
        rec: recA,
        pr: _protection(mode, recA),
        config: BridgeConfig(maxSeatsPerOrigin: 16, listenIPv6Loopback: overV6),
      );
      final tls = _make(
        rec: recB,
        pr: _protection(mode, recB),
        config: BridgeConfig(
          maxSeatsPerOrigin: 16,
          listenIPv6Loopback: overV6,
          securityContext: _tlsContext(),
        ),
      );
      await plain.start(preferredPort: 0);
      await tls.start(preferredPort: 0);
      final pa = plain.port;
      final pb = tls.port;

      Future<void> cap(
        String name,
        String requestForPlain,
        String requestForTls,
      ) async {
        final a = await _exchange(plainDoor, pa, requestForPlain);
        final b = await _exchangeTls(plainDoor, pb, requestForTls);
        _expectSameWire(a, b, '[$mode] $name');
        expect(b['status'], isNot(-2), reason: '[$mode] $name must answer');
      }

      await cap(
        '01_valid_small',
        _post(
          doorHost(pa),
          small,
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          doorHost(pb),
          small,
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '02_get_method',
        'GET / HTTP/1.1\r\nHost: ${doorHost(pa)}\r\n\r\n',
        'GET / HTTP/1.1\r\nHost: ${doorHost(pb)}\r\n\r\n',
      );
      await cap(
        '03_options',
        'OPTIONS / HTTP/1.1\r\nHost: ${doorHost(pa)}\r\n'
            'Origin: https://portal.example\r\n'
            'Access-Control-Request-Method: POST\r\n\r\n',
        'OPTIONS / HTTP/1.1\r\nHost: ${doorHost(pb)}\r\n'
            'Origin: https://portal.example\r\n'
            'Access-Control-Request-Method: POST\r\n\r\n',
      );
      await cap(
        '04_over_limit',
        _post(
          doorHost(pa),
          over,
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          doorHost(pb),
          over,
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '05_at_limit',
        _post(doorHost(pa), at, origin: 'https://portal.example', token: _t64),
        _post(doorHost(pb), at, origin: 'https://portal.example', token: _t64),
      );
      await cap(
        '06_silence_timeout',
        'POST / HTTP/1.1\r\nHost: ${doorHost(pa)}\r\nContent-Length: 500\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n',
        'POST / HTTP/1.1\r\nHost: ${doorHost(pb)}\r\nContent-Length: 500\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n',
      );
      await cap(
        '08_origin_rejected',
        _post(doorHost(pa), small, origin: 'https://evil.com', token: _t64),
        _post(doorHost(pb), small, origin: 'https://evil.com', token: _t64),
      );
      await cap(
        '09_token_wrong',
        _post(
          doorHost(pa),
          small,
          origin: 'https://portal.example',
          token: 'WRONG',
        ),
        _post(
          doorHost(pb),
          small,
          origin: 'https://portal.example',
          token: 'WRONG',
        ),
      );
      await cap(
        '10_token_correct_no_origin',
        _post(doorHost(pa), small, token: _t64),
        _post(doorHost(pb), small, token: _t64),
      );
      await cap(
        '12_host_evil',
        _post('evil.com', small, origin: 'https://portal.example', token: _t64),
        _post('evil.com', small, origin: 'https://portal.example', token: _t64),
      );
      await cap(
        '13_absolute_form',
        'POST http://evil.com/ HTTP/1.1\r\nHost: ${doorHost(pa)}\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n'
            '$small',
        'POST http://evil.com/ HTTP/1.1\r\nHost: ${doorHost(pb)}\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n'
            '$small',
      );
      await cap(
        '14_duplicate_host',
        'POST / HTTP/1.1\r\nHost: first.com\r\nHost: ${doorHost(pa)}\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n'
            '$small',
        'POST / HTTP/1.1\r\nHost: first.com\r\nHost: ${doorHost(pb)}\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n'
            '$small',
      );
      await cap(
        '15_duplicate_origin_header',
        'POST / HTTP/1.1\r\nHost: ${doorHost(pa)}\r\n'
            'Origin: https://portal.example\r\n'
            'Origin: https://portal.example\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n\r\n$small',
        'POST / HTTP/1.1\r\nHost: ${doorHost(pb)}\r\n'
            'Origin: https://portal.example\r\n'
            'Origin: https://portal.example\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n\r\n$small',
      );
      await cap(
        '16_origin_malformed',
        _post(doorHost(pa), small, origin: malformedOrigin, token: _t64),
        _post(doorHost(pb), small, origin: malformedOrigin, token: _t64),
      );
      await cap(
        '17_origin_too_long',
        _post(doorHost(pa), small, origin: longOrigin, token: _t64),
        _post(doorHost(pb), small, origin: longOrigin, token: _t64),
      );
      await cap(
        '18_token_too_long',
        _post(
          doorHost(pa),
          small,
          origin: 'https://portal.example',
          token: 'x' * 1100,
        ),
        _post(
          doorHost(pb),
          small,
          origin: 'https://portal.example',
          token: 'x' * 1100,
        ),
      );
      await cap(
        '19_legacy_token_header_alone',
        _post(
          doorHost(pa),
          small,
          origin: 'https://portal.example',
          extra: {'X-Portal-Token': _t64},
        ),
        _post(
          doorHost(pb),
          small,
          origin: 'https://portal.example',
          extra: {'X-Portal-Token': _t64},
        ),
      );
      await cap(
        '20_empty_payload',
        _post(
          doorHost(pa),
          '{}',
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          doorHost(pb),
          '{}',
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '21_invalid_json',
        _post(
          doorHost(pa),
          'not json at all',
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          doorHost(pb),
          'not json at all',
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '22_unsupported_media_type',
        _post(
          doorHost(pa),
          small,
          origin: 'https://portal.example',
          token: _t64,
          contentType: 'text/plain',
        ),
        _post(
          doorHost(pb),
          small,
          origin: 'https://portal.example',
          token: _t64,
          contentType: 'text/plain',
        ),
      );
      await cap(
        '23_head_reply',
        'HEAD / HTTP/1.1\r\nHost: ${doorHost(pa)}\r\n\r\n',
        'HEAD / HTTP/1.1\r\nHost: ${doorHost(pb)}\r\n\r\n',
      );
      await cap(
        '24_non_root_path_still_reaches_the_handler',
        _post(
          doorHost(pa),
          small,
          origin: 'https://portal.example',
          token: _t64,
          path: '/sub/x',
        ),
        _post(
          doorHost(pb),
          small,
          origin: 'https://portal.example',
          token: _t64,
          path: '/sub/x',
        ),
      );

      // مسمار الخضرة على الباب الآمن: الحالة السليمة تعبر وترد 200
      final ok = await _exchangeTls(
        plainDoor,
        pb,
        _post(
          doorHost(pb),
          small,
          origin: 'https://portal.example',
          token: _t64,
          extra: const {'X-Correlation-Id': 'tls-echo-witness'},
        ),
      );
      expect(ok['status'], 200, reason: '[$mode] the healthy one crosses TLS');
      final okBody = jsonDecode(ok['body'] as String) as Map<String, Object?>;
      expect(okBody['ok'], true);

      // مقارنة أسطر المرصد: البابان يقولان الشيء نفسه
      final warnA = recA.warns.where((w) => w.contains('non-root path'));
      final warnB = recB.warns.where((w) => w.contains('non-root path'));
      expect(
        warnB.length,
        warnA.length,
        reason: '[$mode] the same observer lines land on both doors',
      );

      // إثبات خدمة التلقيمة: مصافحات مكتملة سُلّمت عبر التلقيمة للخادم
      // الآمن حصراً — والباب العادي بلا تلقيمة فلا عدّ مصافحات له
      expect(
        tls.counters.tlsHandshakesDelivered,
        greaterThan(0),
        reason:
            '[$mode] the TLS door rode the handshake feed: completed '
            'handshakes were delivered through it',
      );
      expect(
        plain.counters.tlsHandshakesDelivered,
        0,
        reason: '[$mode] the plain door has no feed - no handshake tally',
      );
      // إيقاف نظيف: الحصاد كامل بلا سطر إعلان — العدّادات تحمل ما قُطع
      expect(
        recB.warns.where((w) => w.contains('TLS handshake')),
        isEmpty,
        reason: '[$mode] a clean stop writes no TLS handshake warning',
      );

      await plain.stop();
      await tls.stop();
    }
  }

  test(
    'the whole wire corpus passes through the TLS feed with the same '
    'status, body, and echo headers the plain listener answers',
    () => runCorpusPair(overV6: false),
  );

  test('the whole wire corpus rides the TLS feed on the optional ::1 '
      'listener too, with the same pair verdicts', () async {
    // ::1 حيث يتوفر حصراً: التخطي صادق مسمّى حيث لا يتوفر
    final bindable =
        await ServerSocket.bind(InternetAddress.loopbackIPv6, 0, v6Only: true)
            .then<bool>((s) {
              s.close();
              return true;
            })
            .catchError((Object _) => false);
    if (!bindable) {
      markTestSkipped(
        '::1 is not available on this host - the second paired run is '
        'genuinely impossible here',
      );
      return;
    }
    await runCorpusPair(overV6: true);
  });

  test(
    'the budget family answers identically through the TLS listener',
    () async {
      final small = jsonEncode({
        'data': ['PRINT 1'],
      });

      Future<void> pair(
        String name, {
        int delayMs = 0,
        BridgeConfig plainConfig = const BridgeConfig(maxSeatsPerOrigin: 16),
        BridgeConfig? tlsConfig,
        Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
        Duration? handlerTimeout,
        required Future<void> Function(int plainPort, int tlsPort) run,
      }) async {
        final recA = _Rec();
        final recB = _Rec();
        final plain = _make(
          rec: recA,
          pr: _protection('token', recA),
          delayMs: delayMs,
          config: plainConfig,
          onCommand: onCommand,
          handlerTimeout: handlerTimeout,
        );
        final tls = _make(
          rec: recB,
          pr: _protection('token', recB),
          delayMs: delayMs,
          config: tlsConfig ?? plainConfig,
          onCommand: onCommand,
          handlerTimeout: handlerTimeout,
        );
        await plain.start(preferredPort: 0);
        await tls.start(preferredPort: 0);
        await run(plain.port, tls.port);
        await plain.stop();
        await tls.stop();
      }

      // سقف بيانات الرد: النجاح فوق السقف يرد 413 reply_data_too_large
      await pair(
        'reply_data_too_large',
        tlsConfig: BridgeConfig(
          maxSeatsPerOrigin: 16,
          securityContext: _tlsContext(),
        ),
        onCommand: (cmd) async =>
            CommandOutcome(ok: true, data: {'blob': 'y' * (64 * 1024 + 1)}),
        run: (pa, pb) async {
          String req(int port) => _post(
            '127.0.0.1:$port',
            small,
            origin: 'https://portal.example',
            token: _t64,
          );
          final a = await _exchange('127.0.0.1', pa, req(pa));
          final b = await _exchangeTls('127.0.0.1', pb, req(pb));
          expect(a['status'], 413);
          _expectSameWire(a, b, 'reply_data_too_large');
        },
      );

      // ميزانية المعالج: تجاوزها يرد 504 handler_timeout
      await pair(
        'handler_timeout',
        delayMs: 400,
        handlerTimeout: const Duration(milliseconds: 100),
        tlsConfig: BridgeConfig(
          maxSeatsPerOrigin: 16,
          securityContext: _tlsContext(),
        ),
        run: (pa, pb) async {
          String req(int port) => _post(
            '127.0.0.1:$port',
            small,
            origin: 'https://portal.example',
            token: _t64,
          );
          final a = await _exchange('127.0.0.1', pa, req(pa));
          final b = await _exchangeTls('127.0.0.1', pb, req(pb));
          expect(a['status'], 504);
          _expectSameWire(a, b, 'handler_timeout');
        },
      );

      // حصة الأصل: مقعد واحد لكل أصل فالثاني من الأصل نفسه origin_seat_limit
      await pair(
        'origin_seat_limit',
        delayMs: 250,
        plainConfig: const BridgeConfig(
          maxConcurrentRequests: 4,
          maxSeatsPerOrigin: 1,
        ),
        tlsConfig: BridgeConfig(
          maxConcurrentRequests: 4,
          maxSeatsPerOrigin: 1,
          securityContext: _tlsContext(),
        ),
        run: (pa, pb) async {
          Future<List<int>> both(
            int port,
            Future<Map<String, Object?>> Function(String req) drive,
          ) async {
            final req = _post(
              '127.0.0.1:$port',
              small,
              origin: 'https://portal.example',
              token: _t64,
            );
            final rs = await Future.wait([drive(req), drive(req)]);
            return rs.map((r) => r['status'] as int).toList()..sort();
          }

          final a = await both(pa, (req) => _exchange('127.0.0.1', pa, req));
          final b = await both(pb, (req) => _exchangeTls('127.0.0.1', pb, req));
          expect(a, [200, 503]);
          expect(b, a, reason: 'the TLS door answers the same pair');
        },
      );
    },
  );

  test('sixteen clients whose TLS handshake never completes hold no seat '
      'and are cut on the wire by the handshake deadline: the next real '
      'request is served and stop stays bounded', () async {
    // الحقيقة الجديدة بعد التلقيمة: ما قبل التسليح مملوك للحزمة — الصامت
    // (بلا أي بايت) يُقتل على السلك عند مهلة المصافحة والمرجع الخام
    // يبلغه، ولا مقعد ولا عدّ اتصالات لحظه الحي كله. والمسلَّح العالق
    // (أكمل أول سجل ثم صمت) كذلك: الساعة الكاملة باقية من لحظة القبول
    // ولا تُعاد بالتسليح، فالقتل يبلغه على السلك عند المهلة نفسها،
    // وstop يحصد الطرفين معاً
    final rec = _Rec();
    final srv = _make(
      rec: rec,
      pr: _protection('token', rec),
      config: BridgeConfig(
        maxSeatsPerOrigin: 16,
        tlsHandshakeTimeout: const Duration(seconds: 1),
        securityContext: _tlsContext(),
      ),
    );
    await srv.start(preferredPort: 0);
    final stalls = <Socket>[];
    for (var i = 0; i < 16; i++) {
      stalls.add(await Socket.connect('127.0.0.1', srv.port));
    }
    // مهلة كافية لو وصلت أي مقبس إلى طبقة HTTP لتظهر في العدادات
    await Future<void>.delayed(const Duration(milliseconds: 400));
    expect(
      srv.counters.activeSeats,
      0,
      reason: 'a stalled handshake never holds a seat',
    );
    // الطلب الحقيقي يعبر وسط الصامتين كأنه وحده
    final port = srv.port;
    final ok = await _exchangeTls(
      '127.0.0.1',
      port,
      _post(
        '127.0.0.1:$port',
        '{"data":["PRINT 1"]}',
        origin: 'https://portal.example',
        token: _t64,
      ),
    );
    expect(ok['status'], 200, reason: 'the real request is served');
    // مهلة المصافحة تفني الصامتين: القطع على السلك يبلغ العميل
    await Future<void>.delayed(const Duration(milliseconds: 800));
    final probe = await wireProbe(stalls.first);
    expect(
      probe,
      startsWith('DEAD'),
      reason:
          'the silent client is destroyed on the wire when the '
          'handshake deadline expires - the cut reaches the peer',
    );
    for (final s in stalls) {
      s.destroy();
    }
    // والتوقف محدود: ما قبل التسليح محصود فوراً في الإيقاف
    final report = await srv.stop().timeout(const Duration(seconds: 3));
    expect(report, isNotNull);
  });

  test('a TLS sender that dies mid-body frees its seat: the next request '
      'is served and stop drains inside the deadline', () async {
    final rec = _Rec();
    final srv = _make(
      rec: rec,
      pr: _protection('token', rec),
      config: BridgeConfig(
        maxSeatsPerOrigin: 16,
        maxConcurrentRequests: 1,
        securityContext: _tlsContext(),
      ),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final port = srv.port;
    // مرسل آمن يعلن جسماً ويموت قبل إكماله: المقعد يجب أن يفرغ
    final dying = await SecureSocket.connect(
      '127.0.0.1',
      port,
      onBadCertificate: (cert) => true,
    );
    dying.add(
      utf8.encode(
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: 500\r\n'
        'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n{',
      ),
    );
    await dying.flush();
    await Future<void>.delayed(const Duration(milliseconds: 120));
    dying.destroy();
    // مهلة الصمت القائمة تقطع الجسم المعلن وتفرغ المقعد — والطلب التالي يخدم
    await Future<void>.delayed(const Duration(milliseconds: 900));
    final next = await _exchangeTls(
      '127.0.0.1',
      port,
      _post(
        '127.0.0.1:$port',
        '{"data":["PRINT 1"]}',
        origin: 'https://portal.example',
        token: _t64,
      ),
    );
    expect(
      next['status'],
      200,
      reason: 'the dead sender freed its seat - the next request is served',
    );
    final report = await srv.stop().timeout(const Duration(seconds: 3));
    expect(report, isNotNull);
  });

  test(
    'the served page rides the https origin: the bridge admits its own '
    'TLS-served page and refuses the http spelling of the same port',
    () async {
      final rec = _Rec();
      final srv = _make(
        rec: rec,
        pr: IntakeProtection(telemetry: rec),
        config: BridgeConfig(
          maxSeatsPerOrigin: 16,
          securityContext: _tlsContext(),
          localPages: const [
            BridgeLocalPage(path: '/ui', content: '<html>tls lab</html>'),
          ],
        ),
      );
      await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final port = srv.port;
      // الصفحة نفسه تُخدم على الباب الآمن
      final page = await _exchangeTls(
        '127.0.0.1',
        port,
        'GET /ui HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n\r\n',
      );
      expect(page['status'], 200, reason: 'the page is served over TLS');
      // أصل الصفحة https:// حصراً يعبر بمسار أصل الجسر المُخدم
      final cross = await _exchangeTls(
        '127.0.0.1',
        port,
        _post(
          '127.0.0.1:$port',
          '{"data":["PRINT 1"]}',
          origin: 'https://127.0.0.1:$port',
        ),
      );
      expect(
        cross['status'],
        200,
        reason: 'the https spelling of the served origin crosses',
      );
      // وصيغة http للمنفذ نفسه أصل مختلف لا تعبر به (فشل الافتراضي مغلقاً)
      final plain = await _exchangeTls(
        '127.0.0.1',
        port,
        _post(
          '127.0.0.1:$port',
          '{"data":["PRINT 1"]}',
          origin: 'http://127.0.0.1:$port',
        ),
      );
      expect(
        plain['status'],
        403,
        reason: 'the http spelling is a different origin under TLS - refused',
      );
    },
  );

  test('the WebSocket channel rides the TLS transport: wss:// without a '
      'credential in the deadline is closed ws_auth_timeout', () async {
    // على SDK لا تعرف dart:io معلمة سقف النقل لا تُسلَّح القناة أصلاً
    // (الرفض عند البناء) فلا قصة wss هنا
    if (!LocalIntakeServer.wsTransportCeilingSupported) {
      markTestSkipped(
        'the channel refuses to arm without a transport ceiling on this '
        'SDK - no wss story here',
      );
      return;
    }
    final rec = _Rec();
    final pr = IntakeProtection(telemetry: rec)
      ..update(
        policy: const OriginPolicy(allowed: ['https://portal.example']),
        token: _t64,
      );
    final srv = _make(
      rec: rec,
      pr: pr,
      wsAuthTimeout: const Duration(milliseconds: 400),
      config: BridgeConfig(
        maxSeatsPerOrigin: 16,
        wsPath: '/ws',
        idleTimeout: const Duration(milliseconds: 400),
        securityContext: _tlsContext(),
      ),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    addTearDown(pr.dispose);
    final client = HttpClient()
      ..badCertificateCallback = (cert, host, port) => true;
    final ws = await WebSocket.connect(
      'wss://127.0.0.1:${srv.port}/ws',
      headers: const {'Origin': 'https://portal.example'},
      customClient: client,
    ).timeout(const Duration(seconds: 5));
    final replies = <String>[];
    final closed = Completer<int?>();
    late final StreamSubscription sub;
    sub = ws.listen(
      (m) => replies.add(m as String),
      onDone: () {
        if (!closed.isCompleted) closed.complete(ws.closeCode);
      },
      onError: (Object _) {
        if (!closed.isCompleted) closed.complete(ws.closeCode);
      },
    );
    await closed.future.timeout(const Duration(seconds: 5));
    await sub.cancel();
    expect(
      replies.single,
      contains('"ws_auth_timeout"'),
      reason: 'the standing auth deadline governs the channel over TLS',
    );
  });

  test('the optional ::1 listener wears the same TLS transport: a command '
      'via [::1] serves like the IPv4 door', () async {
    final rec = _Rec();
    final srv = _make(
      rec: rec,
      pr: _protection('token', rec),
      config: BridgeConfig(
        maxSeatsPerOrigin: 16,
        listenIPv6Loopback: true,
        securityContext: _tlsContext(),
      ),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final port = srv.port;
    final ok4 = await _exchangeTls(
      '127.0.0.1',
      port,
      _post(
        '127.0.0.1:$port',
        '{"data":["PRINT 1"]}',
        origin: 'https://portal.example',
        token: _t64,
      ),
    );
    expect(
      ok4['status'],
      200,
      reason: 'the standing IPv4 door keeps its course under TLS',
    );
    final ok6 = await _exchangeTls(
      '::1',
      port,
      _post(
        '[::1]:$port',
        '{"data":["PRINT 1"]}',
        origin: 'https://portal.example',
        token: _t64,
      ),
    );
    expect(
      ok6['status'],
      200,
      reason: 'the armed ::1 listener wears the same TLS transport',
    );
  });

  test('the option is off by default and refuses the unix-socket '
      'combination at construction', () async {
    // مطفأ افتراضاً: null يبقي الباب بايتات HTTP عادية
    final rec = _Rec();
    final plain = _make(rec: rec, pr: _protection('token', rec));
    await plain.start(preferredPort: 0);
    addTearDown(plain.stop);
    final plainReply = await _exchange(
      '127.0.0.1',
      plain.port,
      'GET / HTTP/1.1\r\nHost: 127.0.0.1:${plain.port}\r\n\r\n',
    );
    expect(
      plainReply['status'],
      405,
      reason: 'the disarmed wire stays plain HTTP, letter identical',
    );
    // توليفة اليونكس: dart:io لا يملك ربطاً آمناً لمقبس يونكس — والرفض
    // عند البناء برسالة التوليفة نفسها (عن حارس المنصة لا الحارس العام)
    // فلا يبقى مستمع صامت-العاري تحت خيار TLS
    await expectLater(
      () => LocalIntakeServer(
        onCommand: (cmd) async => const CommandOutcome(ok: true),
        config: BridgeConfig(
          securityContext: _tlsContext(),
          unixSocketPath: '/tmp/localhost_bridge_tls_conflict.sock',
        ),
      ),
      throwsA(
        isA<ArgumentError>().having(
          (e) => e.message,
          'message',
          contains('securityContext'),
        ),
      ),
      reason:
          'the securityContext + unixSocketPath combination is rejected at '
          'construction with its own message - no listener stays silently '
          'plain under a TLS option',
    );
  });

  test(
    'the wrapper door answers beside the HttpServer.bindSecure '
    'reference door: the reference reads scheme https, a null '
    'certificate, and a loopback connectionInfo, and both doors serve',
    () async {
      // باب مرجعي من المستمع الآمن العام بلا حزمة بينهما: يقرأ الحقائق
      // نفسها التي يبنيها باب الحزمة من المقبس — الشكل والموثق ومعلومات
      // الاتصال — والبابان يخدمان تبادلة حقيقية على الحلقة
      final ref = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        _tlsContext(),
      );
      final seen = <String, Object?>{};
      ref.listen((req) async {
        seen['scheme'] = req.requestedUri.scheme;
        final info = req.connectionInfo;
        seen['remoteIsLoopback'] = info?.remoteAddress.isLoopback;
        seen['hasLocalPort'] = (info?.localPort ?? 0) > 0;
        seen['certificate'] = req.certificate;
        req.response.write('ok');
        await req.response.close();
      });
      addTearDown(() async {
        await ref.close(force: true);
      });

      final rec = _Rec();
      final srv = _make(
        rec: rec,
        pr: _protection('token', rec),
        config: BridgeConfig(
          maxSeatsPerOrigin: 16,
          securityContext: _tlsContext(),
        ),
      );
      await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final port = srv.port;
      final ok = await _exchangeTls(
        '127.0.0.1',
        port,
        _post(
          '127.0.0.1:$port',
          '{"data":["PRINT 1"]}',
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      expect(
        ok['status'],
        200,
        reason: 'the wrapper door serves a real TLS exchange end to end',
      );
      expect(ok['body'], contains('"ok":true'));
      // تبادلة حقيقية على باب المرجع نفسه: حقائقه تُقرأ من طلب عبره حصراً
      final refReply = await _exchangeTls(
        '127.0.0.1',
        ref.port,
        'GET / HTTP/1.1\r\nHost: 127.0.0.1:${ref.port}\r\n\r\n',
      );
      expect(
        refReply['status'],
        200,
        reason: 'the bindSecure reference door serves its own exchange',
      );
      expect(
        seen['scheme'],
        'https',
        reason:
            'the bindSecure reference door reads the https scheme - the '
            'same surface the wrapper door is delivered to answer with',
      );
      expect(
        seen['certificate'],
        isNull,
        reason:
            'no client certificate exists on either door - the reference '
            'request certificate is null and so is the wrapper door fact',
      );
      expect(
        seen['remoteIsLoopback'],
        true,
        reason: 'the reference connectionInfo reads a loopback peer',
      );
      expect(
        seen['hasLocalPort'],
        true,
        reason: 'the reference connectionInfo carries a real local port',
      );
      expect(
        srv.counters.tlsHandshakesDelivered,
        1,
        reason:
            'the wrapper door rode the handshake feed - the delivery path '
            'itself is the one under test',
      );
    },
  );
}
