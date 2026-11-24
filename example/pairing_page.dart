// مثال الاقتران — مضيف يعرض صفحة اقتران حقيقية: يبدأ جلسة اقتران
// (startPairing) ويبين الرمز على قناته هو (الطرفية — الصفحة المحلية
// يقرأها كل برنامج على الجهاز فلا رمز فيها أبداً)، ثم يتلقى من الصفحة
// المقترنة طلباً موقَّعاً بإثبات الاقتران (X-Bridge-Pairing) ويجيب.
// الباب الوحيد هنا: أصل مؤهل + إثبات تملّك — لا توكن مشترك ولا أصل
// وحده يكفي (requireOriginWithToken يجعل الأصل المؤهل بلا إثبات يقرأ
// token_required).
//
// شغّله من جذر الحزمة: dart run example/pairing_page.dart
// ثم من صفحتك على الأصل المدرج: POST /pair بالرمز المعروض ثم وقّع كل
// أمر بالإثبات (شاهد بنية الإثبات في الدالة pairProof أدناه — هي نفسها
// المقتطف الجافسكرپتي في قسم الاقتران بالدليل، مترجمة إلى دارت خالص).
// بلا مستخدم: dart run example/pairing_page.dart --self-check
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

// أصل الصفحة التجريبي — قائمة مغلقة، ولهذا الأصل وحده يفتح باب الاقتران.
const _demoPageOrigin = 'https://desk.example';
// أوامر المثال المغلقة — ما سواه رفض قبل أي أثر.
const _acceptedCommands = {'HELLO'};
// سقف الانتظار على كل فحص — الفشل الصادق أسرع من التعليق.
const _replyBudget = Duration(seconds: 5);

// ما يلي هو رياضيات الإثبات من طرف الصفحة: WebCrypto في المتصفح، وهنا
// نظيرتها بدارت خالص لأن مثالاً لا تبعيات له. SHA-256 ثم HMAC مكتوبة
// من الصفر ومتحقق منها على متجهات RFC 4231 — والفحص الذاتي يثبت
// التطابق الحي: المكتّب المستقل هنا يُقبَل من مدقّق الجسر المكتوب
// منفصلاً في الحزمة.
const List<int> _shaK = [
  0x428a2f98,
  0x71374491,
  0xb5c0fbcf,
  0xe9b5dba5,
  0x3956c25b,
  0x59f111f1,
  0x923f82a4,
  0xab1c5ed5,
  0xd807aa98,
  0x12835b01,
  0x243185be,
  0x550c7dc3,
  0x72be5d74,
  0x80deb1fe,
  0x9bdc06a7,
  0xc19bf174,
  0xe49b69c1,
  0xefbe4786,
  0x0fc19dc6,
  0x240ca1cc,
  0x2de92c6f,
  0x4a7484aa,
  0x5cb0a9dc,
  0x76f988da,
  0x983e5152,
  0xa831c66d,
  0xb00327c8,
  0xbf597fc7,
  0xc6e00bf3,
  0xd5a79147,
  0x06ca6351,
  0x14292967,
  0x27b70a85,
  0x2e1b2138,
  0x4d2c6dfc,
  0x53380d13,
  0x650a7354,
  0x766a0abb,
  0x81c2c92e,
  0x92722c85,
  0xa2bfe8a1,
  0xa81a664b,
  0xc24b8b70,
  0xc76c51a3,
  0xd192e819,
  0xd6990624,
  0xf40e3585,
  0x106aa070,
  0x19a4c116,
  0x1e376c08,
  0x2748774c,
  0x34b0bcb5,
  0x391c0cb3,
  0x4ed8aa4a,
  0x5b9cca4f,
  0x682e6ff3,
  0x748f82ee,
  0x78a5636f,
  0x84c87814,
  0x8cc70208,
  0x90befffa,
  0xa4506ceb,
  0xbef9a3f7,
  0xc67178f2,
];

int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xffffffff;

List<int> _sha256(List<int> message) {
  final padded = <int>[...message, 0x80];
  while (padded.length % 64 != 56) {
    padded.add(0);
  }
  final bits = message.length * 8;
  for (var shift = 56; shift >= 0; shift -= 8) {
    padded.add((bits >> shift) & 0xff);
  }
  final h = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
  ];
  final w = List<int>.filled(64, 0);
  for (var block = 0; block < padded.length; block += 64) {
    for (var t = 0; t < 16; t++) {
      w[t] =
          (padded[block + 4 * t] << 24) |
          (padded[block + 4 * t + 1] << 16) |
          (padded[block + 4 * t + 2] << 8) |
          padded[block + 4 * t + 3];
    }
    for (var t = 16; t < 64; t++) {
      final s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
      final s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & 0xffffffff;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var t = 0; t < 64; t++) {
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ (~e & g);
      final t1 = (hh + s1 + ch + _shaK[t] + w[t]) & 0xffffffff;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = (s0 + maj) & 0xffffffff;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & 0xffffffff;
    }
    h[0] = (h[0] + a) & 0xffffffff;
    h[1] = (h[1] + b) & 0xffffffff;
    h[2] = (h[2] + c) & 0xffffffff;
    h[3] = (h[3] + d) & 0xffffffff;
    h[4] = (h[4] + e) & 0xffffffff;
    h[5] = (h[5] + f) & 0xffffffff;
    h[6] = (h[6] + g) & 0xffffffff;
    h[7] = (h[7] + hh) & 0xffffffff;
  }
  final out = <int>[];
  for (final word in h) {
    out
      ..add((word >> 24) & 0xff)
      ..add((word >> 16) & 0xff)
      ..add((word >> 8) & 0xff)
      ..add(word & 0xff);
  }
  return out;
}

List<int> _hmacSha256(List<int> key, List<int> message) {
  final effective = key.length > 64 ? _sha256(key) : key;
  final block = List<int>.filled(64, 0);
  for (var i = 0; i < effective.length; i++) {
    block[i] = effective[i];
  }
  final inner = <int>[for (final b in block) b ^ 0x36, ...message];
  final outer = <int>[for (final b in block) b ^ 0x5c, ..._sha256(inner)];
  return _sha256(outer);
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

List<int> _hexBytes(String hex) => [
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
];

/// The `X-Bridge-Pairing` value for one request: HMAC-SHA-256 over
/// `v1 / pairingId / stamp / METHOD / path / correlationId`, keyed by the
/// raw bytes of the paired token - the exact proof the bridge verifies.
/// Keep stamps unique: never sign twice in one millisecond.
String pairProof({
  required String pairingId,
  required String pairedTokenHex,
  required String method,
  required String path,
  required String correlationId,
}) {
  final stamp = DateTime.now().millisecondsSinceEpoch;
  final canonical =
      'v1\n$pairingId\n$stamp\n${method.toUpperCase()}\n$path\n'
      '$correlationId';
  final signature = _hex(
    _hmacSha256(_hexBytes(pairedTokenHex), utf8.encode(canonical)),
  );
  return '$pairingId.$stamp.$signature';
}

/// One round trip from the page's seat: real request in, status and body
/// out - the checks below read the wire, never the handler's mind.
Future<(int status, String body, HttpClientResponse reply)> _send(
  HttpClient client,
  int port, {
  required String path,
  String? body,
  Map<String, String> headers = const {},
  String? origin,
}) async {
  final request = await client.openUrl(
    'POST',
    Uri.parse('http://127.0.0.1:$port$path'),
  );
  if (origin != null) request.headers.set('Origin', origin);
  request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
  headers.forEach(request.headers.set);
  if (body != null) request.add(utf8.encode(body));
  final reply = await request.close().timeout(_replyBudget);
  final text = await utf8.decoder.bind(reply).join();
  return (reply.statusCode, text, reply);
}

Future<bool> _runSelfCheck() async {
  var passed = 0;
  var failed = 0;
  void check(String name, bool ok, [String detail = '']) {
    if (ok) {
      passed++;
      stdout.writeln('PASS: $name');
    } else {
      failed++;
      stdout.writeln('FAIL: $name${detail.isEmpty ? '' : ' — $detail'}');
    }
  }

  // البيانات التجريدية داخل المثال: رمز جلسة الاقتران يُقرأ من ما يعرضه
  // المضيف على طرفيته (PairingOffer.code) — كما يقرأه الإنسان على الشاشة
  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(
      policy: const OriginPolicy(
        allowed: [_demoPageOrigin],
        requireOriginWithToken: true,
      ),
    )
    ..enablePairing(
      onPaired: (info) => stdout.writeln(
        '[host] paired ${info.origin} (id ${info.pairingId}, '
        'expires in ${info.expiresInSeconds}s)',
      ),
    );
  final bridge = LocalIntakeServer(
    onCommand: (cmd) async {
      for (final payload in cmd.payloads) {
        if (!_acceptedCommands.contains(payload.trim().toUpperCase())) {
          return const CommandOutcome(
            ok: false,
            errorCode: 'unknown_command',
            errorMessage: 'only HELLO is accepted in this demo',
          );
        }
      }
      return const CommandOutcome(ok: true);
    },
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(36),
    handlerTimeout: _replyBudget,
    protection: protection,
  );
  final port = await bridge.start(preferredPort: 0);
  final client = HttpClient();
  try {
    // العرض: جلسة اقتران حية يبينها المضيف على قنته هو
    final offer = protection.startPairing();
    stdout.writeln(
      '[host] pairing code on the host screen: ${offer.code} '
      '(expires in ${offer.expiresInSeconds}s)',
    );

    final (wrongStatus, wrongBody, _) = await _send(
      client,
      port,
      path: '/pair',
      origin: _demoPageOrigin,
      body: '{"pairingCode":"000000"}',
    );
    check(
      'a wrong code on the pairing door is refused pair_code_invalid, '
          'readable on purpose',
      wrongStatus == 403 && wrongBody.contains('pair_code_invalid'),
      'answered $wrongStatus ${wrongBody.trim()}',
    );

    final (bareStatus, bareBody, _) = await _send(
      client,
      port,
      path: '/',
      origin: _demoPageOrigin,
      body: '["HELLO"]',
    );
    check(
      'the qualified origin without a proof is refused token_required',
      bareStatus == 403 && bareBody.contains('token_required'),
      'answered $bareStatus ${bareBody.trim()}',
    );

    final (pairStatus, pairBody, _) = await _send(
      client,
      port,
      path: '/pair',
      origin: _demoPageOrigin,
      body: '{"pairingCode":"${offer.code}"}',
    );
    final paired = pairStatus == 200
        ? jsonDecode(pairBody) as Map<String, dynamic>
        : <String, dynamic>{};
    check(
      'the displayed code pairs the page: a token bound to its origin '
          'and a pairing id come back',
      pairStatus == 200 &&
          paired['ok'] == true &&
          RegExp(r'^[0-9a-f]{64}$').hasMatch('${paired['token']}') &&
          RegExp(r'^[0-9a-f]{16}$').hasMatch('${paired['pairingId']}'),
      'answered $pairStatus ${pairBody.trim()}',
    );

    // الطلب الموقَّع: إثبات مستقل البناء يُقبَل من مدقّق الجسر
    final signedHeaders = {
      'X-Bridge-Pairing': pairProof(
        pairingId: '${paired['pairingId']}',
        pairedTokenHex: '${paired['token']}',
        method: 'POST',
        path: '/',
        correlationId: 'pair-check-1',
      ),
      'X-Correlation-Id': 'pair-check-1',
    };
    final (signedStatus, signedBody, _) = await _send(
      client,
      port,
      path: '/',
      origin: _demoPageOrigin,
      body: '["HELLO"]',
      headers: signedHeaders,
    );
    check(
      'the signed request crosses: the pairing proof admits the command',
      signedStatus == 200 && signedBody.contains('"ok":true'),
      'answered $signedStatus ${signedBody.trim()}',
    );

    final (replayStatus, replayBody, _) = await _send(
      client,
      port,
      path: '/',
      origin: _demoPageOrigin,
      body: '["HELLO"]',
      headers: signedHeaders,
    );
    check(
      'the same proof never proves twice: the replay is refused '
          'pair_signature_replay',
      replayStatus == 403 && replayBody.contains('pair_signature_replay'),
      'answered $replayStatus ${replayBody.trim()}',
    );
  } finally {
    client.close(force: true);
    await bridge.stop();
  }

  stdout.writeln(
    failed == 0
        ? 'SELF-CHECK PASSED ($passed checks)'
        : 'SELF-CHECK FAILED ($failed of ${passed + failed} checks failed)',
  );
  return failed == 0;
}

Future<void> main(List<String> args) async {
  // وضع الفحص الذاتي: بلا مستخدم وعلى منفذ مؤقت — سطر لكل فحص ورمز
  // خروج 0 عند نجاحها وغير صفر عند فشل أي منها
  if (args.contains('--self-check')) {
    exitCode = await _runSelfCheck() ? 0 : 1;
    return;
  }

  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(
      policy: const OriginPolicy(
        allowed: [_demoPageOrigin],
        requireOriginWithToken: true,
      ),
    )
    ..enablePairing(
      onPaired: (info) => stdout.writeln(
        '[host] paired ${info.origin} (id ${info.pairingId}, '
        'expires in ${info.expiresInSeconds}s)',
      ),
    );
  final server = LocalIntakeServer(
    onCommand: (cmd) async {
      for (final payload in cmd.payloads) {
        if (!_acceptedCommands.contains(payload.trim().toUpperCase())) {
          return const CommandOutcome(
            ok: false,
            errorCode: 'unknown_command',
            errorMessage: 'only HELLO is accepted in this demo',
          );
        }
      }
      return const CommandOutcome(ok: true);
    },
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(36),
    handlerTimeout: _replyBudget,
    protection: protection,
  );

  final port = await server.start(preferredPort: 9340);
  // الرمز يُعرض هنا — على قناة المضيف هو حيث الإنسان وحده يقرأه. صفحة
  // محلية تعرضه ستسلّمه لكل برنامج على الجهاز (اقرأ درس هذا المثال).
  final offer = protection.startPairing();
  stdout
    ..writeln(
      'pairing demo — listening on http://127.0.0.1:$port '
      '(origin $_demoPageOrigin, pairing is the only door)',
    )
    ..writeln(
      'pairing code (valid ${offer.expiresInSeconds}s) — show it only '
      'on the host screen: ${offer.code}',
    )
    ..writeln(
      'from the paired page: POST /pair with {"pairingCode": '
      '"<the code>"} and your Origin, then sign every command with '
      'X-Bridge-Pairing (see pairProof above)',
    )
    ..writeln('Ctrl+C to stop.');

  await ProcessSignal.sigint.watch().first;
  await server.stop();
  stdout.writeln('stopped; bye.');
}
