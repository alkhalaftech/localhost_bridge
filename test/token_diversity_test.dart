// شاهد فحص تنوع التوكن في update(): أرضية الطول البالغة 32 بايتاً
// باقية، وفوقها فحص تنوع المحارف — التوكن فقير التنوع (أقل من ثمانية
// محارف مختلفة، كثلاثين مثلاً متطابقة) يُرمى ArgumentError وقت الإعداد
// لا تحذيراً يمر، ورمي الإعداد بلا أثر جانبي فمن يلتقطه يبقى على حالته
// السابق. ناتج المولّد يمر دائماً (ألف توكن مولد كلها تعبر)، والحالة
// المحفوظة الشرعية عند الترقية لا تُرفض في updateFromSaved — تحذير
// واحد يسمي التدوير ويبقى التوكن عاملاً.
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

void main() {
  test('update() throws for 32 identical bytes', () {
    final p = IntakeProtection();
    expect(
      () => p.update(token: 'a' * 32),
      throwsArgumentError,
      reason: 'a repeated-character token is guessable at a glance',
    );
    // والرمي بلا أثر: التقاطه يبقى على الحالة السابقة (لا طبقة نصف حية)
    expect(p.policy, const OriginPolicy());
  });

  test('update() throws for a two-character token', () {
    final p = IntakeProtection();
    expect(() => p.update(token: 'ab'), throwsArgumentError);
  });

  test('the diversity error names the distinct-character floor', () {
    final p = IntakeProtection();
    Object? caught;
    try {
      p.update(token: 'a' * 32);
    } catch (e) {
      caught = e;
    }
    expect(caught, isArgumentError);
    expect('$caught', contains('distinct'));
  });

  test('seven distinct characters throw; exactly eight pass', () {
    final p = IntakeProtection();
    expect(
      () => p.update(token: 'abcdefg' * 10),
      throwsArgumentError,
      reason: 'seven distinct characters sit below the floor',
    );
    final atFloor = IntakeProtection()..update(token: 'abcdefgh' * 8);
    // والطبقة الفعالة عند الأرضية بالضبط: التوكن الصحيح يعبر
    expect(atFloor.policy, const OriginPolicy());
  });

  test('one thousand generated tokens all pass update()', () {
    final p = IntakeProtection();
    for (var i = 0; i < 1000; i++) {
      p.update(token: generateBridgeToken());
    }
    // والمولد نفسه على شكله الموثق: 64 محرفاً hex — الحارس المجاور له
    // في bridge_token_test يثبت الشكل والتميز الزوجي
    expect(p.policy, const OriginPolicy());
  });

  test('updateFromSaved keeps a legitimate saved low-diversity token active '
      'with one rotation warning', () {
    final rec = _Rec();
    final p = IntakeProtection(telemetry: rec)
      ..updateFromSaved(savedMode: 'token', token: 'a' * 64);
    // لا رفض لحالة محفوظة شرعية عند الترقية: التوكن باقٍ عاملاً
    expect(
      p.check(origin: null, bridgeToken: 'a' * 64),
      completion(isNull),
      reason: 'the upgrade must not switch the saved layer off',
    );
    // والتحذير واحد يسمي الضعف والتدوير
    final diversityWarns = rec.warns
        .where((w) => w.contains('distinct'))
        .toList();
    expect(diversityWarns, hasLength(1));
    expect(diversityWarns.single, contains('generateBridgeToken'));
  });

  test('a policy update on the same object keeps the inherited saved token '
      'working - the diversity floor never locks the host out of updates', () {
    // السلسلة الحية كاملة على الكائن نفسه: إقلاع من حالة محفوظة بتوكن
    // طويل فقير التنوع (يُقبل بتحذير تدوير)، ثم update() سياسةً بلا
    // token — التوكن الموروث معفى من أرضية التنوع فلا يرمي الخطأ،
    // والطبقة باقية فعالة بعده: من يعفي الإقلاع لا يحبس التحديث
    final rec = _Rec();
    final p = IntakeProtection(telemetry: rec)
      ..updateFromSaved(savedMode: 'token', token: 'a' * 64);
    // تحديث السياسة وحده على الكائن نفسه: لا ArgumentError مهما كان
    // تنوع التوكن الموروث
    p.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
    // والطبقة باقية فعالة: التوكن المحفوظ نفسه يعبر بعد التحديث
    expect(
      p.admit(origin: null, bridgeToken: 'a' * 64).then((a) => a.acceptedPath),
      completion(IntakeAdmissionPath.token),
      reason: 'the inherited saved token stays the live secret',
    );
    // وupdate() بتوكن صريح فقير التنوع باقٍ يرفض — الإعفاء للموروث حصراً
    expect(
      () => p.update(token: 'a' * 64),
      throwsArgumentError,
      reason: 'an explicitly passed low-diversity token is still refused',
    );
    // والالتقاط يبقى على التوكن الموروث: الطبقة لم تُمس بالرمي
    expect(
      p.admit(origin: null, bridgeToken: 'a' * 64).then((a) => a.acceptedPath),
      completion(IntakeAdmissionPath.token),
    );
  });
}
