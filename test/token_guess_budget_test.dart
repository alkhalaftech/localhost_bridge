// شاهد نافذة إخفاق التوكن بعد ج4: النافذة إشارة لا رافض — التوكن
// الصحيح يُقارن ويُقبل أياً كان تاريخ الإخفاقات من أي مرسل وبأصل أو
// بلا أصل، والمطابقة تصفر النافذة فيبدأ احتساب الميزانية من جديد.
// ميزانية التخمين الخاطئ ثابت داخلي باسم بوحدة مكتوبة: خمس محاولات
// توكن خاطئة في نافذة الستين ثانية — لكل أصل حده وللمرسل بلا أصل
// حدُّه المشترك الصريح. فوق الميزانية يُرد الخاطئ 429 token_locked
// بانتظار صادق ويكتب سطر سجل أمني مكبوحاً واحداً في الثانية بالعدد.
// token_locked لا يُنتج للتوكن الصحيح أبداً. الساعة المحقونة تحكم
// كل توقيت فلا نوم ولا اعتماد على زمن الحائط.
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

void main() {
  test('after any number of wrong tokens from any sender, the correct token '
      'is accepted in the next request', () async {
    var now = 0;
    final p = IntakeProtection(nowMs: () => now)..update(token: _t64);
    // خمسمائة إخفاق من أصل واحد وخمسمائة بلا أصل في الثانية نفسها:
    // كلا النافذتين تصلان الميزانية والصحيح القادم لا يُرفض من أيهما
    for (var i = 0; i < 500; i++) {
      final r = await p.check(
        origin: 'https://flooder.example',
        portalToken: 'WRONG$i',
      );
      expect(r!.code, isNot('accepted'), reason: 'unlisted origin is refused');
    }
    for (var i = 0; i < 500; i++) {
      await p.check(origin: null, portalToken: 'WRONG$i');
    }
    // الصحيح من المرسل المفيض نفسه: يُقارن ويُقبل — النافذة لا ترفضه
    expect(
      await p.check(origin: 'https://flooder.example', portalToken: _t64),
      isNull,
      reason: 'the correct token is accepted whatever the failure history',
    );
    // والصحيح بلا أصل فوق النافذة المشتركة المفيضة: يُقبل كذلك
    expect(
      await p.check(origin: null, portalToken: _t64),
      isNull,
      reason: 'the shared originless window never refuses the correct token',
    );
    // والصحيح من أصل لم يخفق قط: يُقبل كما كان
    expect(
      await p.check(origin: 'https://innocent.example', portalToken: _t64),
      isNull,
    );
  });

  test(
    'a thousand wrong tokens in one injected second write exactly one '
    'budget line, and the next second writes the line with the muted count',
    () async {
      var now = 0;
      final rec = _Rec();
      final p = IntakeProtection(nowMs: () => now, telemetry: rec)
        ..update(token: _t64);
      for (var i = 0; i < 1000; i++) {
        await p.check(origin: null, portalToken: 'W$i');
      }
      final budgetLines = rec.warns
          .where((w) => w.contains('guess budget'))
          .toList();
      expect(budgetLines, hasLength(1), reason: 'one line within the second');
      expect(budgetLines.single, contains('5 wrong token attempts'));
      expect(budgetLines.single, contains('60 seconds'));
      // والسطر التالي بعد النافذة يحمل عدد المكتوم — حجم الفيضان مرئي
      now += 1001;
      await p.check(origin: null, portalToken: 'W-late');
      final after = rec.warns.where((w) => w.contains('guess budget'));
      expect(after, hasLength(2));
      expect(after.last, contains('+994 more suppressed'));
    },
  );

  test(
    'above the budget a wrong token answers token_locked with the honest '
    'wait, and the correct token clears the window so the budget restarts',
    () async {
      var now = 0;
      final p = IntakeProtection(nowMs: () => now)..update(token: _t64);
      for (var i = 0; i < 5; i++) {
        await p.check(origin: 'https://a.example', portalToken: 'W');
        now++;
      }
      // السادس الخاطئ فوق الميزانية: 429 بانتظار صادق — خمسة إخفاقات
      // طازجة داخل نافذة الستين ثانية فالبقية نحو ستين ثانية
      final sixth = await p.check(
        origin: 'https://a.example',
        portalToken: 'W',
      );
      now++;
      expect(sixth!.status, 429);
      expect(sixth.code, 'token_locked');
      expect(
        sixth.retryAfterMs,
        greaterThanOrEqualTo(55_000),
        reason: 'the wait names the real remainder of the budget window',
      );
      // والصحيح يعبر ويصفر النافذة فتبدأ الميزانية من جديد: الإخفاقات
      // الخمسة التالية لا تقفل — القفلة من السادس بعد التصوير لا من الأول
      expect(
        await p.check(origin: 'https://a.example', portalToken: _t64),
        isNull,
        reason: 'a match clears the miss window',
      );
      for (var i = 0; i < 5; i++) {
        final r = await p.check(origin: 'https://a.example', portalToken: 'W');
        now++;
        expect(r!.code, isNot('token_locked'), reason: 'the budget restarted');
      }
      final lockedAgain = await p.check(
        origin: 'https://a.example',
        portalToken: 'W',
      );
      expect(lockedAgain!.code, 'token_locked');
    },
  );
}
