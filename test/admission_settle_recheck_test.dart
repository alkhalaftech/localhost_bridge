// Witnesses of the settle-time re-check: a record's verdict is a pure
// read taken at admission, and the host-owned measure around it may
// hold the request - a concurrent request can consume the one-shot
// facts (the one-time grant, a pairing proof's replay slot, the
// per-origin quota seat, the token guess budget) inside that window.
// The settle step re-reads those facts on the live state: a consumed
// fact flips the record into the standing refusal for the live state,
// so one grant serves one request and one proof passes once. Unit
// witnesses on IntakeProtection plus two full-server witnesses behind
// a telemetry gate that holds the measured body until released.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:localhost_bridge/src/digest.dart' show hexEncode, hmacSha256;
import 'package:test/test.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

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

/// المراقب الحاجز: منفذ القياس يملكه المضيف - هذا التنفيذ ينتظر
/// بوابةَ إطلاقٍ قبل استدعاء body فيُبقي الطلبات المتزامنة محكومة
/// قبل أن تُسوّى أياً منها، والبوابة الفارغة تعني مروراً حرفاً
class _GatedRec extends BridgeTelemetry {
  Completer<void>? gate;
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
  }) {}
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
  }) async {
    final held = gate;
    if (held != null && label == 'intake.handleRequest') {
      await held.future;
    }
    return body();
  }
}

Future<Map<String, Object?>> _post(
  int port, {
  String? origin,
  String? pairingProof,
}) async {
  final client = HttpClient();
  try {
    final req = await client.open('POST', '127.0.0.1', port, '/');
    if (origin != null) req.headers.set('Origin', origin);
    if (pairingProof != null) {
      req.headers.set('X-Bridge-Pairing', pairingProof);
    }
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return {'status': res.statusCode, 'body': jsonDecode(text) as Map};
  } finally {
    client.close(force: true);
  }
}

/// يُقترن أصلاً مؤهلاً ويعيد الثنائية الصادرة - الشاهد يبني تواقيعه
/// بنفس طريقة الصفحة حرفا
(IntakeProtection, String, String) _paired() {
  final protection = IntakeProtection(telemetry: _Rec())
    ..update(
      policy: const OriginPolicy(
        allowed: ['https://portal.example'],
        requireOriginWithToken: true,
        // موضوع هذا الملف إعادة فحص الوقائع لا الحصص - والفيضان
        // هنا بلا حصة كي يبقى المشهد على وقائعه
        listedPerOriginPerMinute: 0,
      ),
      token: _t64,
    )
    ..enablePairing();
  final offer = protection.startPairing();
  final out = protection.pair(
    origin: 'https://portal.example',
    code: offer.code,
  );
  if (out.rejection != null || out.token == null || out.pairingId == null) {
    throw StateError('witness setup failed: ${out.rejection?.code}');
  }
  return (protection, out.token!, out.pairingId!);
}

/// ترويسة التوقيع بنفس طريقة الصفحة حرفا - الطابع من ساعة الجدار
/// الحقيقية (نافذة الانحراف تُقاس عليها)
String _sign({
  required String token,
  required String pairingId,
  String method = 'POST',
  String path = '/',
  String correlationId = '',
}) {
  final stamp = DateTime.now().millisecondsSinceEpoch;
  final canonical =
      'v1\n$pairingId\n$stamp\n${method.toUpperCase()}\n$path\n'
      '$correlationId';
  final keyBytes = [
    for (var i = 0; i + 1 < token.length; i += 2)
      int.parse(token.substring(i, i + 2), radix: 16),
  ];
  final signature = hexEncode(hmacSha256(keyBytes, utf8.encode(canonical)));
  return '$pairingId.$stamp.$signature';
}

void main() {
  test('two concurrent admissions on one allow-once grant accept once: the '
      'twin settles into the live-state refusal', () async {
    final pr = IntakeProtection()
      ..update(
        policy: OriginPolicy(
          requireFetchMetadata: false,
          onUnknownOrigin: (origin) async => OriginConsent.allowOnce,
        ),
      );
    // المنحة تُسلَّح أولاً: سؤال يجاب مرة
    final primer = await pr.admit(origin: 'https://once.example');
    primer.settle();
    await Future<void>.delayed(const Duration(milliseconds: 10));
    // التوأمان يحكمان قبل أن تُسوّى أياً منهما: كلاهما يقرأ المنحة
    final a = await pr.admit(origin: 'https://once.example');
    final b = await pr.admit(origin: 'https://once.example');
    expect(a.acceptedPath, IntakeAdmissionPath.onceGrant);
    expect(b.acceptedPath, IntakeAdmissionPath.onceGrant);
    b.settle(); // يصرف المنحة ويقبل
    expect(b.acceptedPath, IntakeAdmissionPath.onceGrant);
    a.settle(); // إعادة الفحص: المنحة صرفت - الحكم سلوك الطلب الحي
    expect(
      a.acceptedPath,
      isNull,
      reason: 'a one-time grant serves one twin only - the second asks fresh',
    );
    expect(a.rejection?.code, 'origin_pending');
  });

  test('one pairing proof settling twice in parallel accepts once: the twin '
      'settles into the standing replay refusal', () async {
    final (pr, token, pairingId) = _paired();
    // التوقيع على المعرف نفسه الذي يدخل به الطلب — التوقيع يربط
    // الطلب كله
    final proof = _sign(
      token: token,
      pairingId: pairingId,
      correlationId: 'cid-1',
    );
    final a = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: proof,
      method: 'POST',
      path: '/',
      correlationId: 'cid-1',
    );
    final b = await pr.admit(
      origin: 'https://portal.example',
      pairingProof: proof,
      method: 'POST',
      path: '/',
      correlationId: 'cid-1',
    );
    expect(a.acceptedPath, IntakeAdmissionPath.originWithPairedToken);
    expect(b.acceptedPath, IntakeAdmissionPath.originWithPairedToken);
    b.settle(); // يسجل مفتاح الإعادة ويقبل
    expect(b.acceptedPath, IntakeAdmissionPath.originWithPairedToken);
    a.settle(); // إعادة الفحص: المفتاح حاضر - إعادة إثبات
    expect(
      a.acceptedPath,
      isNull,
      reason: 'one proof passes once - the second is a declared replay',
    );
    expect(a.rejection?.code, 'pair_signature_replay');
  });

  test('two concurrent admissions on one quota seat accept once: the twin '
      'settles into the standing rate-limit refusal', () async {
    final pr = IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          listedPerOriginPerMinute: 1,
        ),
      );
    final a = await pr.admit(origin: 'https://portal.example');
    final b = await pr.admit(origin: 'https://portal.example');
    expect(a.acceptedPath, IntakeAdmissionPath.listed);
    expect(b.acceptedPath, IntakeAdmissionPath.listed);
    a.settle(); // يستهلك الخانة الوحيدة
    b.settle(); // إعادة الفحص: الخانة ممتلئة - رفض الانتظار الصادق
    expect(
      b.acceptedPath,
      isNull,
      reason:
          'one quota seat does not serve two concurrent settles on two seats',
    );
    expect(b.rejection?.code, 'origin_rate_limited');
    expect(a.acceptedPath, IntakeAdmissionPath.listed);
  });

  test('concurrent wrong-token attempts settle one stamp each: over the '
      'budget the twin settles into the standing lock', () async {
    final pr = IntakeProtection()
      ..update(policy: const OriginPolicy(), token: _t64);
    // ستة إخفاقات حُكمت قبل أن تُسوّى أياً منها: كلها خططت طابعاً
    final rs = <IntakeAdmission>[
      for (var i = 0; i < 6; i++)
        await pr.admit(
          origin: 'https://stranger.example',
          bridgeToken: 'wrong-token-$i',
        ),
    ];
    for (final r in rs.take(5)) {
      r.settle(); // الخمسة الأولى تختم نافذتها
    }
    final sixth = rs[5];
    sixth.settle(); // إعادة الفحص: النافذة ممتلئة - القفل لا ختم زائد
    expect(sixth.acceptedPath, isNull);
    expect(
      sixth.rejection?.code,
      'token_locked',
      reason:
          'ميزانية التخمين خمس محاولات - السادسة المتزامنة تجيب '
          'بانتظار النافذة لا تطبع فوقها',
    );
  });

  test('a held measure before the gate: two concurrent requests on one '
      'allow-once grant accept exactly one', () async {
    final rec = _GatedRec();
    final pr = IntakeProtection(telemetry: rec)
      ..update(
        policy: OriginPolicy(
          requireFetchMetadata: false,
          onUnknownOrigin: (origin) async => OriginConsent.allowOnce,
        ),
      );
    final srv = LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: () => 'recheck-1',
      protection: pr,
      onCommand: (cmd) async => const CommandOutcome(ok: true),
    );
    final port = await srv.start(preferredPort: 0);
    addTearDown(() async {
      pr.dispose();
      await srv.stop();
    });
    // تجهيز المنحة على السلك: سؤال يجاب مرة
    final prime = await _post(port, origin: 'https://once.example');
    expect(prime['status'], 403);
    expect((prime['body'] as Map)['error'], 'origin_pending');
    await Future<void>.delayed(const Duration(milliseconds: 10));
    // الطلبان المتزامنان عالقان داخل القياس المحجوز قبل بوابة القبول
    rec.gate = Completer<void>();
    final f1 = _post(port, origin: 'https://once.example');
    final f2 = _post(port, origin: 'https://once.example');
    await Future<void>.delayed(const Duration(milliseconds: 60));
    rec.gate!.complete();
    final r1 = await f1;
    final r2 = await f2;
    final statuses = [r1['status'] as int, r2['status'] as int]..sort();
    expect(
      statuses,
      [200, 403],
      reason:
          'a one-time allow grant serves exactly one request no matter '
          'how long the measure is held',
    );
    final refused = r1['status'] == 403 ? r1 : r2;
    expect((refused['body'] as Map)['error'], 'origin_pending');
  });

  test('a held measure before the gate: one pairing proof sent twice in '
      'parallel is accepted once', () async {
    final rec = _GatedRec();
    final pr = IntakeProtection(telemetry: rec)
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          requireOriginWithToken: true,
          listedPerOriginPerMinute: 0,
        ),
        token: _t64,
      )
      ..enablePairing();
    final offer = pr.startPairing();
    final granted = pr.pair(origin: 'https://portal.example', code: offer.code);
    expect(granted.rejection, isNull);
    final proof = _sign(token: granted.token!, pairingId: granted.pairingId!);
    final srv = LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: () => 'recheck-2',
      protection: pr,
      onCommand: (cmd) async => const CommandOutcome(ok: true),
    );
    final port = await srv.start(preferredPort: 0);
    addTearDown(() async {
      pr.dispose();
      await srv.stop();
    });
    // الإثبات نفسه مرتين بالتوازي، وكلاهما عالق داخل القياس المحجوز
    rec.gate = Completer<void>();
    final f1 = _post(
      port,
      origin: 'https://portal.example',
      pairingProof: proof,
    );
    final f2 = _post(
      port,
      origin: 'https://portal.example',
      pairingProof: proof,
    );
    await Future<void>.delayed(const Duration(milliseconds: 60));
    rec.gate!.complete();
    final r1 = await f1;
    final r2 = await f2;
    final statuses = [r1['status'] as int, r2['status'] as int]..sort();
    expect(
      statuses,
      [200, 403],
      reason:
          'one pairing proof passes exactly once no matter how long '
          'the measure is held',
    );
    final refused = r1['status'] == 403 ? r1 : r2;
    expect((refused['body'] as Map)['error'], 'pair_signature_replay');
  });
}
