// شاهد سقف خرائط النوافذ: إدراج فوق السقف يطرد أقدم نافذة إدراجاً
// بطابور الترتيب، ومفتاح الطلب الجاري لا يُطرد فقفل التوكن يبقى
// يتكون تحت الفيضان. الساعة المحقونة تحكم كل توقيت فلا نوم ولا
// اعتماد على زمن الحائط — والفيضان 10,000 إدراجاً يبلغ السقف الداخلي.
import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

// توكن اختبار مولد الشكل (64 محرفا hex) — بيانات مجردة لا سر
const _token =
    'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

void main() {
  test(
    'the token-miss map is hard-capped: the oldest-inserted window is evicted by the flood',
    () async {
      var now = 0;
      final p = IntakeProtection(nowMs: () => now)..update(token: _token);
      // خمسة إخفاقات من أصل ثابت: مدخله هو الأقدم في الخريطة
      for (var i = 0; i < 5; i++) {
        await p.check(origin: 'https://fixed.example', bridgeToken: 'WRONG');
        now++;
      }
      // فيضان يبلغ السقف: الإدراج الأخير فوق السقف يطرد الأقدم إدراجاً
      for (var i = 0; i < 10000; i++) {
        await p.check(origin: 'https://flood$i.example', bridgeToken: 'WRONG');
        now++;
      }
      // ذاكرة الأصل الثابت خرجت مع نافذته المطرودة: خمسة إخفاقات جديدة
      // لا تقفل — كانت الإخفاقات الخمس القديمة تكفي وحدها للقفل
      for (var i = 0; i < 5; i++) {
        final r = await p.check(
          origin: 'https://fixed.example',
          bridgeToken: 'WRONG',
        );
        now++;
        expect(
          r!.code,
          isNot('token_locked'),
          reason: 'the pre-flood misses left with the evicted oldest window',
        );
      }
      // والنافذة الجديدة تقفل من السادس — السقف حصر الخريطة لا القفل
      final sixth = await p.check(
        origin: 'https://fixed.example',
        bridgeToken: 'WRONG',
      );
      now++;
      expect(sixth!.code, 'token_locked');
    },
  );

  test(
    'the origin quota map is hard-capped: the oldest-inserted window is evicted by the flood',
    () async {
      var now = 0;
      final p = IntakeProtection(nowMs: () => now)
        ..update(
          policy: const OriginPolicy(
            allowAllHardened: true,
            perOriginPerMinute: 3,
          ),
        );
      const fixed = 'https://fixed.example';
      // حصة الأصل الثابت تمتلئ: ثلاثة مقبولة والرابع مرفوض بلا أثر
      for (var i = 0; i < 3; i++) {
        expect(
          await p.check(origin: fixed, fetchMode: 'cors', fetchDest: 'empty'),
          isNull,
        );
        now++;
      }
      final over = await p.check(
        origin: fixed,
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      now++;
      expect(over!.code, 'origin_rate_limited');
      // فيضان يبلغ السقف: نافذة الأصل الثابت (الأقدم) تخرج بالطرد
      for (var i = 0; i < 10000; i++) {
        await p.check(
          origin: 'https://flood$i.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        now++;
      }
      // حساب الحصة القديم ذهب مع النافذة المطرودة: ثلاثة تمر من جديد
      for (var i = 0; i < 3; i++) {
        final r = await p.check(
          origin: fixed,
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        now++;
        expect(
          r,
          isNull,
          reason:
              'the pre-flood quota state left with the evicted oldest window',
        );
      }
      // والنافذة الجديدة تحصر الحصة من الرابع — السقف حصر الخريطة لا الحصة
      final reLimited = await p.check(
        origin: fixed,
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      now++;
      expect(reLimited!.code, 'origin_rate_limited');
    },
  );

  test(
    'during an eviction flood a fixed origin still locks: five misses then the sixth answers 429',
    () async {
      var now = 0;
      final p = IntakeProtection(nowMs: () => now)..update(token: _token);
      // امتلاء السقف أولا، ثم إخفاقات الأصل الثابت متقطعة بفيضان
      // متواصل: كل إدراج فوق السقف يطرد الأقدم، والأصل الثابت يُعاد
      // إدراجه آخر الطابور عند طرد نافذته فتتقدم الفيضانات نحوه ولا
      // تبلغه قبل إخفاقه السادس — القفل يتكون تحت الفيضان نفسه
      for (var i = 0; i < 10000; i++) {
        await p.check(origin: 'https://fill$i.example', bridgeToken: 'WRONG');
        now++;
      }
      Future<void> chunk(int n, String tag) async {
        for (var i = 0; i < n; i++) {
          await p.check(origin: 'https://$tag$i.example', bridgeToken: 'WRONG');
          now++;
        }
      }

      await p.check(origin: 'https://fixed.example', bridgeToken: 'WRONG');
      now++;
      await chunk(2000, 'waveA');
      await p.check(origin: 'https://fixed.example', bridgeToken: 'WRONG');
      now++;
      await chunk(2000, 'waveB');
      await p.check(origin: 'https://fixed.example', bridgeToken: 'WRONG');
      now++;
      await chunk(2000, 'waveC');
      await p.check(origin: 'https://fixed.example', bridgeToken: 'WRONG');
      now++;
      await chunk(2000, 'waveD');
      // الفيضان يصرف كل ما يسبق الأصل الثابت فيصير أولاً: إخفاقه
      // الخامس هنا هو لحظة الطلب الجاري — نافذته حية لا يطرد عندها
      await chunk(1999, 'waveE');
      await p.check(origin: 'https://fixed.example', bridgeToken: 'WRONG');
      now++;
      // والسادس يرد القفل رغم الفيضان المحيط
      final sixth = await p.check(
        origin: 'https://fixed.example',
        bridgeToken: 'WRONG',
      );
      now++;
      expect(sixth!.code, 'token_locked');
    },
  );
}
