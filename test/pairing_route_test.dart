// شاهد ج3 الثالث (السلك): مسار الاقتران POST ‏/pair — الصفحة ترسل الرمز
// مع أصلها فتأخذ توكناً مربوطاً بالأصل ومحدود العمر، والرد المقروء بصدى
// CORS دائما (باب الإقلاع: الشيفرة هي البوابة لا الأصل)، والخامل (الاقتران
// مطفأ) يسلك سلوك اليوم حرفاً — المسار يبلغ المعالج كأي مسار آخر.
// عناوين إنجليزية (حزمة منشورة)؛ شاهد الميزانية على الساعة المحقونة.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

final _clockMs = <int>[1_000_000];

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
String _cid() => 'pair-route-${_idSeq++}';

LocalIntakeServer _server({required IntakeProtection pr, required _Rec rec}) =>
    LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: _cid,
      nowMs: () => _clockMs[0],
      onCommand: (_) async => const CommandOutcome(ok: true),
      protection: pr,
    );

IntakeProtection _strictListed(_Rec rec) =>
    IntakeProtection(telemetry: rec, nowMs: () => _clockMs[0])
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          requireOriginWithToken: true,
        ),
        token: _t64,
      )
      ..enablePairing();

Future<(int, String, Map<String, String>)> _send(
  int port, {
  String method = 'POST',
  String path = '/pair',
  String? origin,
  Map<String, String> headers = const {},
  String? body,
}) async {
  final client = HttpClient();
  try {
    final req = await client.open(method, '127.0.0.1', port, path);
    if (origin != null) req.headers.set('Origin', origin);
    headers.forEach(req.headers.set);
    if (body != null) {
      req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      req.add(utf8.encode(body));
    }
    final res = await req.close().timeout(const Duration(seconds: 8));
    final text = await res.transform(utf8.decoder).join();
    final flat = <String, String>{};
    res.headers.forEach((name, values) {
      flat[name.toLowerCase()] = values.join(', ');
    });
    return (res.statusCode, text, flat);
  } finally {
    client.close(force: true);
  }
}

String _pairBody(String code) => '{"pairingCode":"$code"}';

void main() {
  setUp(() {
    _clockMs[0] = 1_000_000;
    _idSeq = 0;
  });

  test('a correct code over POST /pair answers the bound token with a '
      'readable reply: ACAO echo, correlation id, honest expiry', () async {
    final rec = _Rec();
    final pr = _strictListed(rec);
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final offer = pr.startPairing();
    final (status, body, headers) = await _send(
      port,
      origin: 'https://portal.example',
      body: _pairBody(offer.code),
    );
    expect(status, 200, reason: 'the pairing door opens with the code');
    final json = jsonDecode(body) as Map<String, Object?>;
    expect(json['ok'], true);
    expect(json['token'], matches(RegExp(r'^[0-9a-f]{64}$')));
    expect(json['pairingId'], matches(RegExp(r'^[0-9a-f]{16}$')));
    expect(json['expiresInSeconds'], 24 * 60 * 60);
    // الرد المقروء دائما من باب الاقتران: الصفحة تحتاج قراءة توكنها
    expect(headers['access-control-allow-origin'], 'https://portal.example');
    expect(headers['x-correlation-id'], isNotNull);
  });

  test('pairing disabled: POST /pair is nobody special - it reaches the '
      "handler exactly as today's non-root paths do", () async {
    final rec = _Rec();
    final pr = IntakeProtection(telemetry: rec)
      ..update(policy: const OriginPolicy(allowed: ['https://portal.example']));
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final (status, body, _) = await _send(
      port,
      path: '/pair',
      origin: 'https://portal.example',
      body: '["CMD"]',
    );
    // سلوك اليوم حرفا: كل مسار يبلغ المعالج برد 200
    expect(status, 200);
    expect(body, contains('"ok":true'));
    // وقائمة الترويسات المسموحة بلا الترويسة الجديدة — الخامل سلكه ثابت
    final (optStatus, _, optHeaders) = await _send(
      port,
      method: 'OPTIONS',
      origin: 'https://portal.example',
    );
    expect(optStatus, 204);
    expect(
      optHeaders['access-control-allow-headers'],
      'Content-Type, X-Bridge-Token, X-Correlation-Id',
    );
    expect(
      optHeaders['access-control-allow-headers']!,
      isNot(contains('X-Bridge-Pairing')),
    );
  });

  test('pairing enabled: the preflight announces X-Bridge-Pairing', () async {
    final rec = _Rec();
    final pr = _strictListed(rec);
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final (status, _, headers) = await _send(
      port,
      method: 'OPTIONS',
      origin: 'https://portal.example',
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type, x-bridge-pairing',
      },
    );
    expect(status, 204);
    expect(
      headers['access-control-allow-headers'],
      'Content-Type, X-Bridge-Token, X-Correlation-Id, X-Bridge-Pairing',
    );
    // OPTIONS على /pair نفسه يبقى الـ204 القائم
    final (pairOpt, _, pairOptHeaders) = await _send(
      port,
      method: 'OPTIONS',
      path: '/pair',
      origin: 'https://portal.example',
    );
    expect(pairOpt, 204);
    expect(
      pairOptHeaders['access-control-allow-origin'],
      'https://portal.example',
    );
  });

  test('GET /pair is refused method_not_allowed like any non-POST', () async {
    final rec = _Rec();
    final pr = _strictListed(rec);
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final (status, body, _) = await _send(
      port,
      method: 'GET',
      path: '/pair',
      origin: 'https://portal.example',
    );
    expect(status, 405);
    expect(body, contains('"error":"method_not_allowed"'));
  });

  test('a malformed pairing body is refused 400 bad_request, never a '
      'misleading code verdict', () async {
    final rec = _Rec();
    final pr = _strictListed(rec);
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final (missing, missingBody, _) = await _send(
      port,
      origin: 'https://portal.example',
      body: '{"other":"shape"}',
    );
    expect(missing, 400);
    expect(missingBody, contains('"error":"bad_request"'));
    final (notJson, notJsonBody, _) = await _send(
      port,
      origin: 'https://portal.example',
      body: 'just raw text',
    );
    expect(notJson, 400);
    expect(notJsonBody, contains('"error":"bad_request"'));
  });

  test('a wrong code on the wire answers 403 pair_code_invalid - readable, '
      'counted, and the honest budget follows', () async {
    final rec = _Rec();
    final pr = _strictListed(rec);
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    pr.startPairing();
    final before = pr.rejectedCount;
    final (status, body, headers) = await _send(
      port,
      origin: 'https://portal.example',
      body: _pairBody('000001'),
    );
    expect(status, 403);
    expect(body, contains('"error":"pair_code_invalid"'));
    expect(headers['access-control-allow-origin'], 'https://portal.example');
    expect(pr.rejectedCount, before + 1);
    // خمس محاولات خاطئة ثم السادسة: الميزانية على السلك بانتظارها الصادق
    for (var i = 0; i < 4; i++) {
      final (st, b, _) = await _send(
        port,
        origin: 'https://portal.example',
        body: _pairBody('00000${i + 2}'),
      );
      expect(st, 403);
      expect(b, contains('"error":"pair_code_invalid"'));
    }
    final (overStatus, overBody, overHeaders) = await _send(
      port,
      origin: 'https://portal.example',
      body: _pairBody('999999'),
    );
    expect(overStatus, 429);
    expect(overBody, contains('"error":"pair_budget_exceeded"'));
    expect(
      overHeaders['retry-after'],
      isNotNull,
      reason: 'the wire carries the honest session remainder',
    );
  });

  test('an expired code on the wire answers 403 pair_code_expired', () async {
    final rec = _Rec();
    final pr = _strictListed(rec);
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final offer = pr.startPairing();
    _clockMs[0] += 120_001;
    final (status, body, _) = await _send(
      port,
      origin: 'https://portal.example',
      body: _pairBody(offer.code),
    );
    expect(status, 403);
    expect(body, contains('"error":"pair_code_expired"'));
  });

  test('an oversized X-Bridge-Pairing header is refused 400 pairing_too_long '
      'before anything reads it', () async {
    final rec = _Rec();
    final pr = _strictListed(rec);
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final (status, body, headers) = await _send(
      port,
      origin: 'https://portal.example',
      headers: {'X-Bridge-Pairing': 'a.b.${'c' * 300}'},
      body: _pairBody('123456'),
    );
    expect(status, 400);
    expect(body, contains('"error":"pairing_too_long"'));
    expect(
      headers['access-control-allow-origin'],
      isNull,
      reason: 'a wire-shape gate carries no CORS echo, like its siblings',
    );
  });

  test('a duplicated X-Bridge-Pairing header is refused duplicate_header '
      'while the pairing layer is armed', () async {
    final rec = _Rec();
    final pr = _strictListed(rec);
    final srv = _server(pr: pr, rec: rec);
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // ترويستان بقيمتين عبر مقبس خام: عميل dart يطوي المكررات فيكتبهما
    // سطرا واحدا والبوابة لا ترى تعددا — والمقبس الخام هو الذي يريه
    final socket = await Socket.connect('127.0.0.1', port);
    final reply = Completer<String>();
    final buffer = <int>[];
    late final StreamSubscription<List<int>> sub;
    sub = socket.listen(
      (chunk) {
        buffer.addAll(chunk);
        final text = latin1.decode(buffer, allowInvalid: true);
        final sep = text.indexOf('\r\n\r\n');
        if (sep < 0 || reply.isCompleted) return;
        final cl = RegExp(
          r'Content-Length:\s*(\d+)',
          caseSensitive: false,
        ).firstMatch(text.substring(0, sep));
        final bodyLen = text.length - (sep + 4);
        if (cl != null && bodyLen >= int.parse(cl.group(1)!)) {
          reply.complete(text);
        }
      },
      onDone: () {
        if (!reply.isCompleted) {
          reply.complete(latin1.decode(buffer, allowInvalid: true));
        }
      },
    );
    final body = utf8.encode(_pairBody('123456'));
    socket.add(
      utf8.encode(
        'POST /pair HTTP/1.1\r\n'
        'Host: 127.0.0.1:$port\r\n'
        'Origin: https://portal.example\r\n'
        'X-Bridge-Pairing: first.value.here\r\n'
        'X-Bridge-Pairing: second.value.here\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: ${body.length}\r\n'
        '\r\n',
      ),
    );
    socket.add(body);
    final text = await reply.future.timeout(const Duration(seconds: 4));
    await sub.cancel();
    socket.destroy();
    expect(text, contains(' 400 '), reason: 'the single-value gate answers');
    expect(text, contains('"error":"duplicate_header"'));
  });
}
