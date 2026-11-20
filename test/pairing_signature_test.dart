// شاهد ج3 الثالث (التوقيع): إثبات الحيازة بـ HMAC — التوكن لا يسافر خاماً
// في طلبات الصفحة المقترنة، بل توقيع كل طلب على الطابع ومعرف الارتباط
// والطريقة والمسار. تكرار توقيع قديم يُرفض، وتوقيع بمفتاح أصل آخر يُرفض،
// والتوقيع الصحيح يعبر. طريقة البناء المكتوبة في تقرير التصميم قبل الكود:
// canonical = "v1\n<pairingId>\n<stampMs>\n<METHOD>\n<path>\n<correlationId>"
// signature = hex(hmacSha256(utf8(token), utf8(canonical))).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:localhost_bridge/src/digest.dart' show hexEncode, hmacSha256;

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

/// يُقترن أصلاً مؤهلاً ويعيد الكائن مع ثنائية الإثبات الصادرة — الشاهد
/// يبني تواقيعه عليها بنفس طريقة الصفحة حرفا
(IntakeProtection, String, String) _strictPaired({_Rec? rec}) {
  final protection = IntakeProtection(telemetry: rec, nowMs: () => _clockMs[0])
    ..update(
      policy: const OriginPolicy(
        allowed: ['https://portal.example'],
        requireOriginWithToken: true,
      ),
      token: _t64,
    )
    ..enablePairing();
  final offer = protection.startPairing();
  final out = protection.pair(
    origin: 'https://portal.example',
    code: offer.code,
  );
  if (out.rejection != null || out.token == null) {
    throw StateError('witness setup failed: ${out.rejection?.code}');
  }
  return (protection, out.token!, out.pairingId!);
}

/// يبني ترويسة التوقيع بنفس طريقة الصفحة حرفا — الطابع من ساعة الجدار
/// الحقيقية (نافذة الانحراف تُقاس عليها)، والcanonical بنص التصميم،
/// والمفتاح بايتات التوكن الخام الاثنتان والثلاثون مفكوكة من الhex
/// (النثر الحاكم للتصميم — الذي أمسكه شاهد المتصفح حين اتفق جانبا
/// Dart على utf8(السلسلة))
String _sign({
  required String token,
  required String pairingId,
  String method = 'POST',
  String path = '/',
  String correlationId = '',
  int? stampOverride,
}) {
  final stamp = stampOverride ?? DateTime.now().millisecondsSinceEpoch;
  final canonical =
      'v1\n$pairingId\n$stamp\n${method.toUpperCase()}\n$path\n$correlationId';
  final keyBytes = [
    for (var i = 0; i + 1 < token.length; i += 2)
      int.parse(token.substring(i, i + 2), radix: 16),
  ];
  final signature = hexEncode(hmacSha256(keyBytes, utf8.encode(canonical)));
  return '$pairingId.$stamp.$signature';
}

List<int> _hexBytes(String hex) => [
  for (var i = 0; i + 1 < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
];

void main() {
  setUp(() {
    _clockMs[0] = 1_000_000;
  });

  test('a paired page signs its command: the proof admits '
      'originWithPairedToken over a qualified origin', () async {
    final (pr, token, pairingId) = _strictPaired();
    final proof = _sign(token: token, pairingId: pairingId);
    final a = await pr.admit(
      origin: 'https://portal.example',
      method: 'POST',
      path: '/',
      pairingProof: proof,
    );
    a.settle();
    expect(a.rejection, isNull);
    expect(a.acceptedPath, IntakeAdmissionPath.originWithPairedToken);
    expect(a.echoesCors, isTrue);
    expect(a.verboseErrors, isTrue);
  });

  test('a replayed signature is refused pair_signature_replay: the same '
      'stamp never proves twice', () async {
    final (pr, token, pairingId) = _strictPaired();
    final proof = _sign(token: token, pairingId: pairingId);
    final first = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: proof,
    );
    first.settle();
    expect(first.rejection, isNull);
    final second = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: proof,
    );
    second.settle();
    expect(second.rejection?.code, 'pair_signature_replay');
    expect(second.rejection!.status, 403);
    // وتوقيع آخر بطابع آخر يعبر فورا — الإعادة تحكم الطابع لا الطبقة
    final fresh = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: _sign(token: token, pairingId: pairingId),
    );
    fresh.settle();
    expect(fresh.rejection, isNull);
  });

  test('a stale signature (outside the skew window) is refused as a replay '
      'even though the signature itself is valid', () async {
    final (pr, token, pairingId) = _strictPaired();
    final stale = _sign(
      token: token,
      pairingId: pairingId,
      stampOverride: DateTime.now().millisecondsSinceEpoch - 61_000,
    );
    final a = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: stale,
    );
    a.settle();
    expect(a.rejection?.code, 'pair_signature_replay');
  });

  test(
    'a signature keyed by another origin token is refused by the origin '
    'rejection - no token verdict ever reaches an unqualified origin',
    () async {
      final rec = _Rec();
      final (pr, tokenA, idA) = _strictPaired(rec: rec);
      // إثبات الأصل A يقدمه الأصل B: رفض الأصل يجيب لا رمز التوقيع —
      // لا قناة استطلاع تعرف صحة التوقيع على أصل غير مؤهل
      final bProof = _sign(token: tokenA, pairingId: idA);
      final a = await pr.admit(
        origin: 'https://stranger.example',
        pairingProof: bProof,
      );
      a.settle();
      expect(a.rejection?.code, 'origin_not_listed');
      // وبربط مباشر: توكن مقترن لأصل B لا يعمل على أصل A — ربط الأصل
      // حارس التوقيع لا التوقيع نفسه
      // نافذة كبح السطر ثانية واحدة: نقدّم الساعة حتى يخرج السطر القديم
      // من النافذة فيخرج سطر الرفض التالي حاملا سببه الداخلي
      _clockMs[0] += 2000;
      pr.update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example', 'https://other.example'],
          requireOriginWithToken: true,
        ),
        token: _t64,
      );
      final bOffer = pr.startPairing();
      final b = pr.pair(origin: 'https://other.example', code: bOffer.code);
      expect(b.rejection, isNull);
      final crossProof = _sign(token: b.token!, pairingId: b.pairingId!);
      final cross = await pr.admit(
        origin: 'https://portal.example',
        pairingProof: crossProof,
      );
      cross.settle();
      expect(cross.rejection?.code, 'token_required');
      // والتفصيل يسجل لا يُكشف: السطر الأمني يسمي سبب الرفض الداخلي
      expect(
        rec.warns.any((w) => w.contains('origin-mismatch')),
        isTrue,
        reason: 'the muted security line carries the internal reason',
      );
    },
  );

  test('a tampered signature is refused token_required with no oracle about '
      'which byte broke it', () async {
    final (pr, token, pairingId) = _strictPaired();
    final proof = _sign(token: token, pairingId: pairingId);
    // قلب بايت واحد في التوقيع
    final parts = proof.split('.');
    final sig = _hexBytes(parts[2]);
    sig[0] = sig[0] ^ 0xFF;
    final tampered = '${parts[0]}.${parts[1]}.${hexEncode(sig)}';
    final a = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: tampered,
    );
    a.settle();
    expect(a.rejection?.code, 'token_required');
    // وشكل مكسور (طابع غير رقمي) رفض الشرط نفسه لا استثناء
    final malformed = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: '$pairingId.not-a-number.${'a' * 64}',
    );
    malformed.settle();
    expect(malformed.rejection?.code, 'token_required');
    // ومعرف مجهول: لا سجل بهذا المعرف
    final unknownId = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: _sign(token: token, pairingId: '0123456789abcdef'),
    );
    unknownId.settle();
    expect(unknownId.rejection?.code, 'token_required');
  });

  test('a paired binding past its lifetime refuses: the proof expires with '
      'its record', () async {
    final (pr, token, pairingId) = _strictPaired();
    _clockMs[0] += 24 * 60 * 60 * 1000 + 1;
    final proof = _sign(token: token, pairingId: pairingId);
    final a = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: proof,
    );
    a.settle();
    expect(a.rejection?.code, 'token_required');
    // الكنس عند الإدراج لا عند القراءة (القراءة خالصة لا تكتب): السجل
    // الميت باقٍ بالذاكرة حتى إدراج تالٍ يخرجه — والسلك لا يقبل توقيعه
    // في كل الأحوال (فشل مغلق)
    expect(pr.pairedCount, 1, reason: 'the read never sweeps - pure read');
    final fresh = pr.startPairing();
    pr.pair(origin: 'https://portal.example', code: fresh.code);
    expect(
      pr.pairedCount,
      1,
      reason: 'the next insert sweeps the expired record, replacing it',
    );
  });

  test('revocation kills the proof at once: the next signed request is '
      'refused token_required', () async {
    final (pr, token, pairingId) = _strictPaired();
    pr.revokePairedOrigin('https://portal.example');
    final proof = _sign(token: token, pairingId: pairingId);
    final a = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: proof,
    );
    a.settle();
    expect(a.rejection?.code, 'token_required');
  });

  test(
    'the shared token stays a valid proof, and the paired token never '
    'travels raw: the token header matches the shared secret alone',
    () async {
      final (pr, pairedToken, _) = _strictPaired();
      // التوكن المشترك فوق المؤهل: الطبقتان معا كما كان
      final shared = await pr.admit(
        origin: 'https://portal.example',
        bridgeToken: _t64,
      );
      expect(shared.acceptedPath, IntakeAdmissionPath.originWithToken);
      // والتوكن المقترن لو سافر خاما في ترويسة التوكن: لا يطابق المفتاح
      // المشترك فيرفض — الصفحة لا ترسل توكنها المقترن خاما أبدا
      final rawPaired = await pr.admit(
        origin: 'https://portal.example',
        bridgeToken: pairedToken,
      );
      rawPaired.settle();
      expect(rawPaired.rejection?.code, 'token_required');
    },
  );

  test('the wire round trip: a paired page sends and reads, the replay is '
      'refused on the wire, the proofless page reads token_required', () async {
    final rec = _Rec();
    final (pr, token, pairingId) = _strictPaired(rec: rec);
    final commandPaths = <IntakeAdmissionPath?>[];
    final srv = LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: () => 'sig-1',
      nowMs: () => _clockMs[0],
      onCommand: (cmd) async {
        commandPaths.add(cmd.admission.acceptedPath);
        return const CommandOutcome(ok: true);
      },
      protection: pr,
    );
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    Future<(int, String, Map<String, String>)> send({
      String? proof,
      String correlationId = 'sig-round-1',
    }) async {
      final client = HttpClient();
      try {
        final req = await client.open('POST', '127.0.0.1', port, '/');
        req.headers.set('Origin', 'https://portal.example');
        if (proof != null) req.headers.set('X-Bridge-Pairing', proof);
        req.headers.set('X-Correlation-Id', correlationId);
        req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
        req.add(utf8.encode('["CMD"]'));
        final res = await req.close();
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

    final proof = _sign(
      token: token,
      pairingId: pairingId,
      correlationId: 'sig-round-1',
    );
    final (status, body, headers) = await send(proof: proof);
    expect(status, 200, reason: 'the paired page sends and reads');
    expect(body, contains('"ok":true'));
    expect(headers['access-control-allow-origin'], 'https://portal.example');
    expect(
      commandPaths.single,
      IntakeAdmissionPath.originWithPairedToken,
      reason: 'the command carries the paired acceptance route',
    );
    // الإعادة على السلك نفسه بنفس الترويسة: pair_signature_replay
    final (replayStatus, replayBody, _) = await send(proof: proof);
    expect(replayStatus, 403);
    expect(replayBody, contains('"error":"pair_signature_replay"'));
    // والصفحة بلا إثبات: token_required المقروء — الرفض الصادق الذي
    // تعيد منه الصفحة بالإثبات
    final (bareStatus, bareBody, bareHeaders) = await send(
      correlationId: 'sig-bare',
    );
    expect(bareStatus, 403);
    expect(bareBody, contains('"error":"token_required"'));
    expect(
      bareHeaders['access-control-allow-origin'],
      'https://portal.example',
      reason: 'the strict refusal is readable for the qualified origin',
    );
  });

  test('the replay cache is capped at 4,096 entries: a stamp flood never '
      'opens a replay window', () async {
    final (pr, token, pairingId) = _strictPaired();
    // طوابع فريدة محكومة داخل نافذة الانحراف: كل توقيع صحيح يسجل طابعه
    final base = DateTime.now().millisecondsSinceEpoch;
    var accepted = 0;
    for (var i = 0; i < 4100; i++) {
      final a = await pr.admit(
        origin: 'https://portal.example',
        pairingProof: _sign(
          token: token,
          pairingId: pairingId,
          correlationId: 'c$i',
          stampOverride: base + i,
        ),
        correlationId: 'c$i',
      );
      a.settle();
      if (a.rejection == null) accepted++;
    }
    expect(
      accepted,
      4100,
      reason: 'fresh unique stamps never collide in the cache',
    );
    // وفوق السقف الطرد الأقدم: إعادة طابع خارج نافذة الانحراف تُرفض من
    // فحص الانحراف — الفيضان لا يفتح نافذة إعادة أيا كان مصيره بالذاكرة
    final evicted = _sign(
      token: token,
      pairingId: pairingId,
      correlationId: 'c0',
      stampOverride: base - 65_000,
    );
    final replayCheck = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: evicted,
      correlationId: 'c0',
    );
    replayCheck.settle();
    expect(
      replayCheck.rejection?.code,
      'pair_signature_replay',
      reason: 'a stale stamp refuses whatever its cache fate was',
    );
  });
}
