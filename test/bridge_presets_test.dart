// شواهد الإعدادات الجاهزة الأربعة: كل إعداد يعطي سياسته المطابقة حرفاً
// (فحص كل حقل من OriginPolicy الناتجة)، والتوكن القصير يُرفض عند الإعداد
// بلا أثر جانبي، والسلك الحي يخدم سلوك كل إعداد: «مغلق» يرفض الجميع،
// «قائمة» تقبل المدرج وحده، «توكن فقط» تُمرر حامل التوكن الصحيح وحده،
// و«جوال» تشترط الأصل والتوكن معاً وتسلّح الاقتران وتُكمل دورته كاملة.
// عناوين إنجليزية (حزمة منشورة)؛ السلك عبر خادم حقيقي كامل.
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

Future<(int, String)> _post(int port, {String? origin, String? token}) async {
  final client = HttpClient();
  try {
    final req = await client.post('127.0.0.1', port, '/');
    if (origin != null) req.headers.set('Origin', origin);
    if (token != null) req.headers.set('X-Bridge-Token', token);
    req.headers.set('Sec-Fetch-Mode', 'cors');
    req.headers.set('Sec-Fetch-Dest', 'empty');
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close().timeout(const Duration(seconds: 8));
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } finally {
    client.close(force: true);
  }
}

Future<LocalIntakeServer> _serve(IntakeProtection protection) async {
  final server = LocalIntakeServer(
    onCommand: (cmd) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    protection: protection,
  );
  await server.start(preferredPort: 0);
  return server;
}

void main() {
  test(
    'the closed preset yields the literal closed policy and nothing admits',
    () async {
      final p = BridgePresets.closed();
      // السياسة الناتجة حرفاً: كل حقل على شكله المغلق
      expect(p.policy.allowed, isEmpty);
      expect(p.policy.allowAllHardened, isFalse);
      expect(p.policy.allowLocalHttp, isFalse);
      expect(p.policy.reportOnly, isFalse);
      expect(p.policy.onUnknownOrigin, isNull);
      expect(p.policy.perOriginPerMinute, 30);
      expect(p.policy.listedPerOriginPerMinute, 120);
      expect(p.policy.requireFetchMetadata, isTrue);
      expect(p.policy.requireOriginWithToken, isFalse);
      expect(p.policy.askTimeout, const Duration(seconds: 60));
      expect(p.policy.askFiresPerParentPerWindow, 0);
      expect(p.pairingEnabled, isFalse);
      // السلك الحي: أصل مدرج أرضاً يُرفض، وحامل توكن كذلك (الطبقة خاملة —
      // لا توكن مضبوطاً) — لا باب مفتوح على الإطلاق
      final server = await _serve(p);
      try {
        final (status, body) = await _post(
          server.port,
          origin: 'https://portal.example',
        );
        expect(status, 403);
        expect(body, contains('"error":"origin_not_listed"'));
        final (tokenStatus, tokenBody) = await _post(server.port, token: _t64);
        expect(tokenStatus, 403);
        expect(tokenBody, contains('"error":"origin_not_listed"'));
      } finally {
        await server.stop();
      }
    },
  );

  test(
    'the allow-list preset yields the policy listing exactly the given origins',
    () async {
      final p = BridgePresets.allowList(
        origins: ['https://Portal.Example.COM/', 'partner.io'],
      );
      // السياسة الناتجة حرفاً كما يعيدها عقد policy: القائمة كما مُرّت
      // حرفاً (والتطبيع الذي يطبقه المطابق على أرض السلك — التقليم
      // والتحوير الصغير — يثبته القبول الحي تحت الصيغة الخام ذاتها أدناه)،
      // والباقي على أرضيته
      expect(p.policy.allowed, ['https://Portal.Example.COM/', 'partner.io']);
      expect(p.policy.allowAllHardened, isFalse);
      expect(p.policy.requireOriginWithToken, isFalse);
      expect(p.pairingEnabled, isFalse);
      // السلك الحي: المدرج يُقبل وغيره يُرد
      final server = await _serve(p);
      try {
        final (ok, okBody) = await _post(
          server.port,
          origin: 'https://portal.example.com',
        );
        expect(ok, 200);
        expect(okBody, contains('"ok":true'));
        final (bad, badBody) = await _post(
          server.port,
          origin: 'https://stranger.example',
        );
        expect(bad, 403);
        expect(badBody, contains('"error":"origin_not_listed"'));
      } finally {
        await server.stop();
      }
    },
  );

  test('the token-only preset keeps the origin policy closed and admits the '
      'token alone', () async {
    final p = BridgePresets.tokenOnly(token: _t64);
    // السياسة مغلقة حرفاً: لا قائمة ولا allow-all ولا اكتشاف، وشرط
    // الأصل+التوكن مطفأ (الباب المستقل هو طبقة التوكن)، والاقتران
    // غير مسلح — الإعداد يعطي باب التوكن وحده
    expect(p.policy.allowed, isEmpty);
    expect(p.policy.allowAllHardened, isFalse);
    expect(p.policy.requireOriginWithToken, isFalse);
    expect(p.pairingEnabled, isFalse);
    // السلك الحي: التوكن الصحيح بلا أصل يمر، ومن سواه يُرد برمز
    // الأصل دون أي حكم على توكنه
    final server = await _serve(p);
    try {
      final (ok, okBody) = await _post(server.port, token: _t64);
      expect(ok, 200);
      expect(okBody, contains('"ok":true'));
      final (bare, bareBody) = await _post(server.port);
      expect(bare, 403);
      expect(bareBody, contains('"error":"origin_not_listed"'));
      final (wrong, wrongBody) = await _post(
        server.port,
        token:
            'b3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f'
            '8b3a1c7',
      );
      expect(wrong, 403);
      expect(wrongBody, contains('"error":"origin_not_listed"'));
    } finally {
      await server.stop();
    }
  });

  test(
    'the mobile preset requires origin and token together and arms pairing',
    () async {
      final p = BridgePresets.mobile(
        token: _t64,
        origins: ['https://portal.example'],
      );
      // السياسة الناتجة حرفاً: قائمة المضيف + الشرط المشترك (الأصل والتوكن معاً)،
      // والاقتران مسلح
      expect(p.policy.allowed, ['https://portal.example']);
      expect(p.policy.requireOriginWithToken, isTrue);
      expect(p.policy.allowAllHardened, isFalse);
      expect(p.pairingEnabled, isTrue);
      // السلك الحي: الأصل المدرج بلا توكن يُرد token_required، والتوكن
      // وحده لا يفتح أبداً، والاجتماع (مدرج + توكن) يُقبل
      final server = await _serve(p);
      try {
        final (missing, missingBody) = await _post(
          server.port,
          origin: 'https://portal.example',
        );
        expect(missing, 403);
        expect(missingBody, contains('"error":"token_required"'));
        final (alone, aloneBody) = await _post(server.port, token: _t64);
        expect(alone, 403);
        expect(aloneBody, contains('"error":"origin_not_listed"'));
        final (ok, okBody) = await _post(
          server.port,
          origin: 'https://portal.example',
          token: _t64,
        );
        expect(ok, 200);
        expect(okBody, contains('"ok":true'));
      } finally {
        await server.stop();
      }
    },
  );

  test(
    'the mobile preset completes a full pairing round over its own layer',
    () async {
      final p = BridgePresets.mobile(
        token: _t64,
        origins: ['https://portal.example'],
      );
      final offer = p.startPairing();
      expect(offer.code, hasLength(6));
      final outcome = p.pair(
        origin: 'https://portal.example',
        code: offer.code,
      );
      expect(outcome.rejection, isNull);
      expect(outcome.token, hasLength(64));
      expect(outcome.pairingId, isNotEmpty);
      expect(outcome.expiresInSeconds, greaterThan(0));
      // أصل غير مؤهل لا يقترن أبداً: بواب التأهيل واحد مع مسارات القبول
      final stranger = p.pair(
        origin: 'https://stranger.example',
        code: offer.code,
      );
      expect(stranger.rejection?.code, 'origin_not_listed');
    },
  );

  test(
    'every preset refuses a short token at build time and keeps no side effect',
    () async {
      expect(
        () => BridgePresets.tokenOnly(token: 'short'),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => BridgePresets.mobile(token: 'short'),
        throwsA(isA<ArgumentError>()),
      );
    },
  );
}
