// حصة المدرج الافتراضية: القيمة الموجبة (120/دقيقة) هي الافتراضية،
// والصفر يبقى الخيار الصريح الموثق «بلا حصة». الصدق يقاس بالانتظار
// الحرفي: ما بعد Retry-After يُقبل وما قبله يُرد. العناوين
// بالإنجليزية (حزمة منشورة) والساعة محقونة فالحسم حتمي لا موقوت.
import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

void main() {
  test(
    'the shipped listed-path budget is 120 per origin per minute: the '
    '121st request inside the window answers 429 origin_rate_limited',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      var now = 0;
      final p = IntakeProtection(nowMs: () => now);
      // السياسة الافتراضية حصرا: لا قيمة صريحة للحصة — الافتراضية هي
      // الموضوع
      p.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
      expect(
        p.policy.listedPerOriginPerMinute,
        120,
        reason:
            'a listed origin ships with a positive budget - zero was the '
            'old default that left a compromised listed page unbounded',
      );

      Future<void> oneAccepted() async {
        final a = await p.admit(
          origin: 'https://portal.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(a.rejection, isNull, reason: 'inside the budget the page sends');
        a.settle();
      }

      for (var i = 0; i < 120; i++) {
        await oneAccepted();
      }

      final over = await p.admit(
        origin: 'https://portal.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      final rejection = over.rejection;
      expect(
        rejection,
        isNotNull,
        reason: 'the default budget refuses the 121st request in the window',
      );
      expect(rejection!.status, 429);
      expect(rejection.code, 'origin_rate_limited');
      expect(
        rejection.retryAfterMs,
        isNotNull,
        reason: 'the refusal carries the honest wait, not a fixed guess',
      );

      // الصدق بالاتجاه المثبت في حارس الحصة: الانتظار المعلن لا يقل
      // عن بقايا النافذة الحقيقية، وعند الرأس المعلن نفسه يُقبل
      // الطلب — انتظارٌ يكفي حتماً لا رقم شكلي
      expect(
        rejection.retryAfterMs,
        greaterThanOrEqualTo(60_000),
        reason:
            'the announced wait covers the whole quota window - the page '
            'that waits it is certain to be admitted',
      );
      now += rejection.retryAfterMs!;
      final retried = await p.admit(
        origin: 'https://portal.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      expect(
        retried.rejection,
        isNull,
        reason:
            'waiting exactly Retry-After admits the retry - the announced '
            'wait is the honest remainder of the window',
      );
      retried.settle();
    },
  );

  test(
    'zero stays a legal explicit choice: a policy written with 0 keeps '
    'listed origins unquotaed',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      var now = 0;
      final p = IntakeProtection(nowMs: () => now);
      // الصفر الخيار الصريح الموثق: يمر التحقق ويُبقي المدرج بلا حصة
      p.update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          listedPerOriginPerMinute: 0,
        ),
      );
      expect(p.policy.listedPerOriginPerMinute, 0);
      for (var i = 0; i < 130; i++) {
        final a = await p.admit(
          origin: 'https://portal.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(
          a.rejection,
          isNull,
          reason: 'explicit zero means unquotaed - past 120 nothing refuses',
        );
        a.settle();
        now += 400;
      }
    },
  );
}
