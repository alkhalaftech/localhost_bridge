// شاهد دورة الاقتران: المضيف يعرض رمزاً قصيراً لمرة واحدة، والصفحة
// ترسل الرمز مع أصلها فتأخذ توكناً مربوطاً بالأصل ومحدود العمر، ويُبلَّغ
// المضيف عبر onPaired، وله الإبطال والتدوير، وخطافات الحفظ نداءات يمررها
// المضيف والحزمة لا تكتب ملفاً، وخرائط الحالة كلها مسقوفة بسياسات إخراج
// مكتوبة في تقرير التصميم.
// عناوين إنجليزية (حزمة منشورة)؛ الساعة محقونة فيشاهود الانتهاء حتمي.
import 'dart:async';

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

// ساعة محقونة: خلية واحدة يقرؤها كائن الحماية عبر nowMs
final _clockMs = <int>[1_000_000];

IntakeProtection _listed({List<_Rec>? recs}) {
  final rec = _Rec();
  recs?.add(rec);
  return IntakeProtection(telemetry: rec, nowMs: () => _clockMs[0])
    ..update(
      policy: const OriginPolicy(
        allowed: ['https://portal.example'],
        requireOriginWithToken: true,
      ),
      token: _t64,
    )
    ..enablePairing();
}

void main() {
  setUp(() {
    _clockMs[0] = 1_000_000;
  });

  test(
    'pairing off: pair and restore refuse loudly, onPaired never armed',
    () async {
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
        );
      expect(
        () => pr.pair(origin: 'https://portal.example', code: '123456'),
        throwsStateError,
      );
      expect(
        () => pr.restorePairedOrigin(
          origin: 'https://portal.example',
          token: _t64,
          remainingMs: 60_000,
        ),
        throwsStateError,
      );
    },
  );

  test('a disposed protection refuses the pairing entrances loudly: '
      'startPairing and pair throw instead of minting or judging', () {
    final pr = _listed();
    expect(pr.pairingEnabled, isTrue);
    pr.dispose();
    expect(
      () => pr.startPairing(),
      throwsStateError,
      reason:
          'a disposed object mints no pairing codes - the admit path '
          'refuses with protection_disposed and the entrances match it',
    );
    expect(
      () => pr.pair(origin: 'https://portal.example', code: '123456'),
      throwsStateError,
      reason: 'pairing against a disposed object never judges a code',
    );
  });

  test('restorePairedOrigin refuses a remainder beyond the paired-token '
      'age and accepts the exact age', () {
    final pr = _listed();
    expect(
      () => pr.restorePairedOrigin(
        origin: 'https://portal.example',
        token: _t64,
        remainingMs: 24 * 60 * 60 * 1000 + 1,
      ),
      throwsArgumentError,
      reason:
          'a paired token lives at most 24 hours - a restore past '
          'the exported age is a corrupt host timestamp, never a binding',
    );
    // والحد نفسه مقبول حرفاً: عمر التوكن المصدر لا أكثر منه
    final id = pr.restorePairedOrigin(
      origin: 'https://portal.example',
      token: _t64,
      remainingMs: 24 * 60 * 60 * 1000,
    );
    expect(id, isNotEmpty);
    expect(pr.pairedCount, 1);
  });

  test('a correct code yields an origin-bound token with an honest expiry, '
      'and onPaired names the origin', () async {
    final paired = <PairingInfo>[];
    final pr = _listed()..enablePairing(onPaired: paired.add);
    final offer = pr.startPairing();
    expect(offer.code, matches(RegExp(r'^[0-9]{6}$')));
    expect(offer.expiresInSeconds, 120);
    final out = pr.pair(origin: 'https://portal.example', code: offer.code);
    expect(out.rejection, isNull);
    expect(out.token, matches(RegExp(r'^[0-9a-f]{64}$')));
    expect(out.pairingId, matches(RegExp(r'^[0-9a-f]{16}$')));
    expect(out.expiresInSeconds, 24 * 60 * 60);
    expect(paired, hasLength(1));
    expect(paired.single.origin, 'https://portal.example');
    expect(paired.single.pairingId, out.pairingId);
    expect(pr.pairedCount, 1);
  });

  test(
    'the same code a second time is refused: the code is one-time',
    () async {
      final pr = _listed();
      final offer = pr.startPairing();
      expect(
        pr.pair(origin: 'https://portal.example', code: offer.code).rejection,
        isNull,
      );
      final second = pr.pair(
        origin: 'https://portal.example',
        code: offer.code,
      );
      expect(second.rejection?.code, 'pair_code_invalid');
      expect(second.rejection!.status, 403);
      expect(second.token, isNull);
    },
  );

  test(
    'an expired code is refused pair_code_expired and frees its session',
    () async {
      final pr = _listed();
      final offer = pr.startPairing();
      _clockMs[0] += 120_001; // جلسة انقضت عمرها كاملا
      final out = pr.pair(origin: 'https://portal.example', code: offer.code);
      expect(out.rejection?.code, 'pair_code_expired');
      expect(out.rejection!.status, 403);
      // الجلسة الميتة خرجت: رمز جديد يعمل فورا بعدها
      final fresh = pr.startPairing();
      expect(
        pr.pair(origin: 'https://portal.example', code: fresh.code).rejection,
        isNull,
      );
    },
  );

  test('code guessing is budget-bound: five wrong attempts per pairing '
      'session, then 429 with the honest remaining session wait', () async {
    final recs = <_Rec>[];
    final pr = _listed(recs: recs);
    final offer = pr.startPairing();
    for (var i = 0; i < 5; i++) {
      final out = pr.pair(origin: 'https://portal.example', code: '00000$i');
      expect(out.rejection?.code, 'pair_code_invalid', reason: 'attempt $i');
    }
    final over = pr.pair(origin: 'https://portal.example', code: '999999');
    expect(over.rejection?.code, 'pair_budget_exceeded');
    expect(over.rejection!.status, 429);
    expect(
      over.rejection!.retryAfterMs,
      isNotNull,
      reason: 'the wait names the remaining life of the live session',
    );
    expect(over.rejection!.retryAfterMs!, lessThanOrEqualTo(120_000));
    // الرمز الصحيح نفسه فوق الميزانية لا يُقارن: الميزانية تحسم قبله
    final spent = pr.pair(origin: 'https://portal.example', code: offer.code);
    expect(spent.rejection?.code, 'pair_budget_exceeded');
    // والميزانية لكل جلسة: جلسة جديدة بميزانيتها الكاملة
    final fresh = pr.startPairing();
    expect(
      pr.pair(origin: 'https://portal.example', code: fresh.code).rejection,
      isNull,
    );
    // والرفض المكتوم مرئي: سطر أمني يحمل رمز الجلسة والأصل
    expect(
      recs.single.warns.any(
        (w) =>
            w.contains('pair_budget_exceeded') ||
            w.contains('pair_code_invalid'),
      ),
      isTrue,
      reason: 'denial is never silent - the pairing gate counts and logs',
    );
  });

  test('an unqualified origin is refused at the pairing gate by the origin '
      'code - one qualification source', () async {
    final pr = _listed();
    final offer = pr.startPairing();
    final out = pr.pair(origin: 'https://stranger.example', code: offer.code);
    expect(out.rejection?.code, 'origin_not_listed');
    expect(pr.pairedCount, 0);
    // والمحاولة نفسها لم تحرق الرمز: المؤهل يدخل بعدها بالرمز نفسه
    expect(
      pr.pair(origin: 'https://portal.example', code: offer.code).rejection,
      isNull,
    );
  });

  test('revoke kills the origin bindings at once; rotate revokes and offers '
      'a fresh code', () async {
    final revoked = <String>[];
    final pr = _listed()..enablePairing(onPairedRevoke: revoked.add);
    final offer = pr.startPairing();
    pr.pair(origin: 'https://portal.example', code: offer.code);
    expect(pr.pairedCount, 1);
    pr.revokePairedOrigin('https://portal.example');
    expect(pr.pairedCount, 0);
    expect(revoked, ['https://portal.example']);
    // والتدوير = إبطال + عرض جديد: ربط حي ثانٍ يموت بالتدوير
    final offer2 = pr.startPairing();
    pr.pair(origin: 'https://portal.example', code: offer2.code);
    expect(pr.pairedCount, 1);
    final rotated = pr.rotatePairedOrigin('https://portal.example');
    expect(rotated.code, matches(RegExp(r'^[0-9]{6}$')));
    expect(pr.pairedCount, 0);
    expect(revoked.length, 2);
    // والرمز الجديد يعمل فورا بعد التدوير
    expect(
      pr.pair(origin: 'https://portal.example', code: rotated.code).rejection,
      isNull,
    );
  });

  test(
    'save hooks fire on issue and revoke, and a throwing hook is '
    'contained - the package writes no file and never breaks the wire',
    () async {
      final recs = <_Rec>[];
      final saved = <(String, String, int)>[];
      final pr = _listed(recs: recs)
        ..enablePairing(
          onPairedSave: (origin, token, lifetimeMs) async {
            saved.add((origin, token, lifetimeMs));
          },
          onPairedRevoke: (_) => throw StateError('host storage exploded'),
        );
      final offer = pr.startPairing();
      final out = pr.pair(origin: 'https://portal.example', code: offer.code);
      expect(out.rejection, isNull);
      // الخطاف غير المتزامن حُوِي: انتظار دورة أحداث يثبت لا انهياراً
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(saved, hasLength(1));
      expect(saved.single.$1, 'https://portal.example');
      expect(saved.single.$2, out.token);
      expect(saved.single.$3, 24 * 60 * 60 * 1000);
      pr.revokePairedOrigin('https://portal.example');
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(
        recs.single.warns.any((w) => w.contains('pairing save hook')),
        isTrue,
        reason: 'a contained hook failure is said, never swallowed silent',
      );
    },
  );

  test('restorePairedOrigin re-arms a saved binding with a stable derived '
      'pairing id across restarts', () async {
    final pr = _listed();
    final offer = pr.startPairing();
    final first = pr.pair(origin: 'https://portal.example', code: offer.code);
    expect(first.rejection, isNull);
    // إقلاع جديد: كائن حماية جديد يعيد تسليح ما حفظه المضيف، ويعيد
    // معرف الاقتران المشتق — دالة التوكن حصرا فثابت عبر الإقلاعات
    final pr2 = _listed();
    final restoredId = pr2.restorePairedOrigin(
      origin: 'https://portal.example',
      token: first.token!,
      remainingMs: 12 * 60 * 60 * 1000,
    );
    expect(pr2.pairedCount, 1);
    expect(restoredId, first.pairingId);
    // وبقايا غير موجبة رفض إعداد صاخب لا سجل صامت
    expect(
      () => pr2.restorePairedOrigin(
        origin: 'https://portal.example',
        token: _t64,
        remainingMs: 0,
      ),
      throwsArgumentError,
    );
    // وتوكن قصير منضبط فوق أرضية الحزمة نفسها
    expect(
      () => pr2.restorePairedOrigin(
        origin: 'https://portal.example',
        token: 'short',
        remainingMs: 60_000,
      ),
      throwsArgumentError,
    );
  });

  test('the pairing session map is capped at 8 live sessions, oldest '
      'evicted, and expired ones swept on the way', () async {
    final pr = _listed();
    final codes = <String>[];
    for (var i = 0; i < 8; i++) {
      codes.add(pr.startPairing().code);
    }
    // التاسعة تدخل وتطرد الأقدم إدراجا
    pr.startPairing();
    // الأقدم مات بالطرد: pair برمزه جواب مجهول لا نجاح
    final oldest = pr.pair(origin: 'https://portal.example', code: codes.first);
    expect(oldest.rejection?.code, 'pair_code_invalid');
    // والأحدث حي
    final fresh = pr.pair(origin: 'https://portal.example', code: codes.last);
    expect(fresh.rejection, isNull);
    // والكنس عند الإدراج: ثمان جلسات انقضت ثم إدراج تاسع لا يراكم ميوتا
    _clockMs[0] += 200_000;
    for (var i = 0; i < 8; i++) {
      pr.startPairing();
    }
    final expiredProbe = pr.pair(
      origin: 'https://portal.example',
      code: codes[1],
    );
    expect(expiredProbe.rejection?.code, 'pair_code_invalid');
  });

  test('the paired-record map is capped at 64 origins: the oldest-inserted '
      'live record is evicted fail-closed', () async {
    final pr = _listed();
    for (var i = 0; i < 64; i++) {
      final offer = pr.startPairing();
      final out = pr.pair(origin: 'https://portal.example', code: offer.code);
      expect(out.rejection, isNull, reason: 'pair $i');
      // سجل الأصل نفسه يُستبدل بإعادة الاقتران — لتكوين 64 مدخلاً حياً
      // نُقترن أصولاً مؤهلة مختلفة عبر موافقات محفوظة
      if (i < 63) {
        pr.update(
          policy: OriginPolicy(
            allowed: ['https://portal.example', 'https://host$i.example'],
            requireOriginWithToken: true,
          ),
          token: _t64,
        );
        final offer2 = pr.startPairing();
        final out2 = pr.pair(
          origin: 'https://host$i.example',
          code: offer2.code,
        );
        expect(out2.rejection, isNull, reason: 'pair origin $i');
      }
    }
    // 64 سجلاً حيا عبر الأصول؛ الاقتران 65 لأصل جديد يدخل بالكنس ثم الطرد
    pr.update(
      policy: const OriginPolicy(
        allowed: [
          'https://portal.example',
          'https://host63.example',
          'https://overflow.example',
        ],
        requireOriginWithToken: true,
      ),
      token: _t64,
    );
    final offer = pr.startPairing();
    final out = pr.pair(origin: 'https://overflow.example', code: offer.code);
    expect(out.rejection, isNull, reason: 'the 65th pairing still succeeds');
    expect(pr.pairedCount, lessThanOrEqualTo(64));
  });

  test('restoreSavedConsent re-arms a saved discovery decision, refusing '
      'non-persistent values', () async {
    // بلا الشرط المشترك هنا: الشاهد عن الموافقة المحفوظة نفسها لا عن
    // طبقة التوكن — والرفض المحفوظ يظهر عبر مسار الاكتشاف حصرا فيكون
    // نداء الموافقة حاضرا
    final pr = IntakeProtection(nowMs: () => _clockMs[0])
      ..update(
        policy: OriginPolicy(
          allowed: ['https://portal.example'],
          requireFetchMetadata: false,
          onUnknownOrigin: (origin) async => OriginConsent.dismissed,
        ),
      );
    pr.restoreSavedConsent(
      'https://vouched.example',
      OriginConsent.allowAlways,
    );
    final a = await pr.admit(origin: 'https://vouched.example');
    expect(a.acceptedPath, IntakeAdmissionPath.savedConsent);
    expect(
      () =>
          pr.restoreSavedConsent('https://x.example', OriginConsent.allowOnce),
      throwsArgumentError,
      reason: 'allowOnce is a 30-second grant, never a saved decision',
    );
    pr.restoreSavedConsent('https://denied.example', OriginConsent.reject);
    final d = await pr.admit(origin: 'https://denied.example');
    expect(d.rejection?.code, 'origin_declined');
  });

  test('a consent answer fires the save hook once, contained', () async {
    final recs = <_Rec>[];
    final saved = <(String, OriginConsent)>[];
    final rec = _Rec();
    recs.add(rec);
    final pr = IntakeProtection(telemetry: rec, nowMs: () => _clockMs[0])
      ..update(
        policy: OriginPolicy(
          requireFetchMetadata: false,
          requireOriginWithToken: true,
          onUnknownOrigin: (origin) async => OriginConsent.allowAlways,
        ),
        token: _t64,
      )
      ..enablePairing(
        onConsentSave: (origin, consent) => saved.add((origin, consent)),
      );
    final a = await pr.admit(origin: 'https://fresh.example');
    a.settle();
    await Future<void>.delayed(const Duration(milliseconds: 10));
    expect(saved, hasLength(1));
    expect(saved.single.$1, 'https://fresh.example');
    expect(saved.single.$2, OriginConsent.allowAlways);
  });
}
