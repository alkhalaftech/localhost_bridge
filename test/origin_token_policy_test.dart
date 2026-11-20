// شاهد ج3 الأول: خيار السياسة الذي يشترط الأصل والتوكن معاً — الأصل المؤهل
// بلا توكن يُرفض، والتوكن الصحيح من أصل آخر لا يفتح باباً ولا يكشف صحته،
// والاجتماع يقبل بمسار originWithToken، والـpreflight لترويسة التوكن يُجاب
// للأصل المؤهل، والخيار مطفأ افتراضياً فسلوك اليوم حرفاً.
// عناوين إنجليزية (حزمة منشورة)؛ الوحدة على IntakeProtection.admit والسلك
// عبر خادم حقيقي كامل.
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

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

Future<(int, String, Map<String, String>)> _exchange(
  int port, {
  String method = 'POST',
  String? origin,
  String? token,
  Map<String, String> headers = const {},
  bool includeFetchMetadata = true,
}) async {
  final client = HttpClient();
  try {
    final req = await client.open(method, '127.0.0.1', port, '/');
    if (origin != null) req.headers.set('Origin', origin);
    if (token != null) req.headers.set('X-Bridge-Token', token);
    headers.forEach(req.headers.set);
    if (method == 'POST') {
      req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      if (includeFetchMetadata) {
        req.headers.set('Sec-Fetch-Mode', 'cors');
        req.headers.set('Sec-Fetch-Dest', 'empty');
      }
      req.add(utf8.encode('["CMD"]'));
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

void main() {
  test(
    'requireOriginWithToken: a qualified origin without the token is refused '
    'token_required',
    () async {
      final rec = _Rec();
      final pr = IntakeProtection(telemetry: rec)
        ..update(
          policy: const OriginPolicy(
            allowed: ['https://portal.example'],
            requireOriginWithToken: true,
          ),
          token: _t64,
        );
      final a = await pr.admit(origin: 'https://portal.example');
      a.settle();
      expect(a.rejection, isNotNull);
      expect(a.rejection!.code, 'token_required');
      expect(a.rejection!.status, 403);
      expect(a.acceptedPath, isNull);
      // الصفحة المقروءة: الأصل المؤهل يرى صدى CORS فيقرأ رمز رفضه
      expect(a.echoesCors, isTrue);
    },
  );

  test(
    'requireOriginWithToken: a wrong token over a qualified origin is refused '
    'token_required and stamps the miss window',
    () async {
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(
            allowed: ['https://portal.example'],
            requireOriginWithToken: true,
          ),
          token: _t64,
        );
      final a = await pr.admit(
        origin: 'https://portal.example',
        bridgeToken: 'WRONG-wrong-wrong-wrong-wrong-wrong-wrong-1',
      );
      a.settle();
      expect(a.rejection?.code, 'token_required');
      // الخامس يُقفل الميزانية كالعادة: النافذة إشارة عن التخمين الخاطئ
      for (var i = 0; i < 4; i++) {
        final more = await pr.admit(
          origin: 'https://portal.example',
          bridgeToken: 'WRONG-wrong-wrong-wrong-wrong-wrong-wrong-$i',
        );
        more.settle();
      }
      final sixth = await pr.admit(
        origin: 'https://portal.example',
        bridgeToken: 'WRONG-wrong-wrong-wrong-wrong-wrong-wrong-6',
      );
      sixth.settle();
      // فوق الميزانية الرفض برمز القفل لا رمز الشرط — نافذة الإخفاق
      // إشارة عن التوكن المشترك لا عن الشرط الجديد
      expect(sixth.rejection?.code, 'token_locked');
      // والصحيح فوق الميزانية نفسها يعبر (عقد ج4 باقٍ داخل الشرط الجديد)
      final correct = await pr.admit(
        origin: 'https://portal.example',
        bridgeToken: _t64,
      );
      correct.settle();
      expect(correct.rejection, isNull);
      expect(correct.acceptedPath, IntakeAdmissionPath.originWithToken);
    },
  );

  test(
    'requireOriginWithToken: the correct token from another origin is refused '
    'by the origin rejection alone - no token oracle for unqualified origins',
    () async {
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(
            allowed: ['https://portal.example'],
            requireOriginWithToken: true,
          ),
          token: _t64,
        );
      // الأصل B يحمل التوكن الصحيح للأصل A: الرفض برمز الأصل لا رمز الشرط —
      // لو أجاب الشرط لكشفنا صحة التوكن على أصل غير مؤهل (قناة استطلاع)
      final a = await pr.admit(
        origin: 'https://stranger.example',
        bridgeToken: _t64,
      );
      a.settle();
      expect(a.rejection?.code, 'origin_not_listed');
      expect(a.echoesCors, isFalse);
      // وبلا أصل أصلاً لا يفتح التوكن باباً في هذا الوضع
      final noOrigin = await pr.admit(bridgeToken: _t64);
      noOrigin.settle();
      expect(noOrigin.rejection?.code, 'origin_not_listed');
      expect(noOrigin.acceptedPath, isNull);
    },
  );

  test('requireOriginWithToken: origin and the shared token together accept '
      'originWithToken with the echo and the host text', () async {
    final pr = IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          requireOriginWithToken: true,
        ),
        token: _t64,
      );
    final a = await pr.admit(
      origin: 'https://portal.example',
      bridgeToken: _t64,
    );
    expect(a.rejection, isNull);
    expect(a.acceptedPath, IntakeAdmissionPath.originWithToken);
    expect(a.echoesCors, isTrue);
    expect(a.verboseErrors, isTrue);
  });

  test('requireOriginWithToken: the token header preflight is answered for the '
      'admitted origin, never for a stranger', () async {
    final rec = _Rec();
    final pr = IntakeProtection(telemetry: rec)
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          requireOriginWithToken: true,
        ),
        token: _t64,
      );
    final srv = LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: () => 'otp-1',
      onCommand: (_) async => const CommandOutcome(ok: true),
      protection: pr,
    );
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final (status, _, headers) = await _exchange(
      port,
      method: 'OPTIONS',
      origin: 'https://portal.example',
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type, x-bridge-token',
      },
    );
    expect(status, 204);
    expect(headers['access-control-allow-origin'], 'https://portal.example');
    expect(headers['access-control-allow-headers'], contains('X-Bridge-Token'));
    final (strangerStatus, _, strangerHeaders) = await _exchange(
      port,
      method: 'OPTIONS',
      origin: 'https://stranger.example',
      headers: {'Access-Control-Request-Method': 'POST'},
    );
    expect(strangerStatus, 204);
    expect(strangerHeaders['access-control-allow-origin'], isNull);
  });

  test('requireOriginWithToken on the full wire: the listed page without the '
      'token reads 403 token_required, and the forged-origin tokenless local '
      'request is refused', () async {
    final rec = _Rec();
    final pr = IntakeProtection(telemetry: rec)
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          requireOriginWithToken: true,
        ),
        token: _t64,
      );
    final srv = LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: () => 'otp-2',
      onCommand: (cmd) async {
        // المعالج لا يرى شيئاً مرفوضاً — العدّاد يثبت ذلك من طرف الشاهد
        return const CommandOutcome(ok: true);
      },
      protection: pr,
    );
    final port = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final (status, body, headers) = await _exchange(
      port,
      origin: 'https://portal.example',
    );
    expect(status, 403);
    expect(body, contains('"error":"token_required"'));
    // الصفحة المقروءة: الصدى حاضر ليقرأ رمزها ويعيد بعده بالإثبات
    expect(headers['access-control-allow-origin'], 'https://portal.example');
    // والأصل المزوَّر بلا توكن (برنامج محلي) يُرد برمز الأصل
    final (forgedStatus, forgedBody, forgedHeaders) = await _exchange(
      port,
      origin: 'https://portal.example',
    );
    expect(forgedStatus, 403);
    expect(forgedBody, contains('"error":"token_required"'));
    expect(forgedHeaders['retry-after'], isNull);
  });

  test(
    'the flag off by default: a listed origin still admits with no token and '
    'a correct token alone still admits - today\u0027s wire letter by letter',
    () async {
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          token: _t64,
        );
      final listed = await pr.admit(origin: 'https://portal.example');
      expect(listed.rejection, isNull);
      expect(listed.acceptedPath, IntakeAdmissionPath.listed);
      final tokenAlone = await pr.admit(
        origin: 'https://stranger.example',
        bridgeToken: _t64,
      );
      expect(tokenAlone.rejection, isNull);
      expect(tokenAlone.acceptedPath, IntakeAdmissionPath.token);
    },
  );

  test(
    'requireOriginWithToken over allow-all: every https origin qualifies but '
    'still needs the token proof',
    () async {
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(
            allowAllHardened: true,
            requireFetchMetadata: false,
            requireOriginWithToken: true,
          ),
          token: _t64,
        );
      final unproven = await pr.admit(origin: 'https://any.example');
      unproven.settle();
      expect(unproven.rejection?.code, 'token_required');
      final proven = await pr.admit(
        origin: 'https://any.example',
        bridgeToken: _t64,
      );
      expect(proven.rejection, isNull);
      expect(proven.acceptedPath, IntakeAdmissionPath.originWithToken);
    },
  );
}
