// ميزانية الأسئلة الجديدة لكل نطاق أب بجانب السقف العام: أبٌ يدوّر
// نطاقاته الفرعية يُكبَح هو وحده بلا طابع على السقف العام، فيبقى سؤال
// الأصول البريئة مفتوحاً — والسقف العام نفسه يبقى حاكماً عبر الآباء
import 'dart:async';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

void main() {
  group('per-parent ask budget beside the global ceiling', () {
    test('a site rotating a deeper level shares one parent budget', () async {
      var asked = 0;
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            askFiresPerParentPerWindow: 1,
            requireFetchMetadata: false,
            onUnknownOrigin: (origin) {
              asked++;
              return Future<OriginConsent>.value(OriginConsent.dismissed);
            },
          ),
        );
      // تدوير المستوى الثاني: x.r1 وx.r2 وr3 كلها تحت evil.example — أب
      // واحد وميزانية واحدة، فالسؤال الثاني والثالث يُكبحان بلا سؤال
      final a1 = await p.admit(origin: 'https://x.r1.evil.example');
      expect(a1.rejection?.code, 'origin_pending');
      a1.settle();
      await pumpEventQueue();
      final a2 = await p.admit(origin: 'https://x.r2.evil.example');
      expect(
        a2.rejection?.code,
        'origin_parent_rate_limited',
        reason: 'a rotated second level is still the same parent',
      );
      a2.settle();
      await pumpEventQueue();
      final a3 = await p.admit(origin: 'https://r3.evil.example');
      expect(a3.rejection?.code, 'origin_parent_rate_limited');
      a3.settle();
      await pumpEventQueue();
      expect(asked, 1, reason: 'one fire for the whole parent');
      // والزوج الذي كان يُعدّ أبوين: مضيف تحت قمة مسجلة والقمة ذات
      // المقطعين — آخر مقطعين واحد، فميزانية واحدة
      final a4 = await p.admit(origin: 'https://s.shop.example.com');
      expect(a4.rejection?.code, 'origin_pending');
      a4.settle();
      await pumpEventQueue();
      final a5 = await p.admit(origin: 'https://example.com');
      expect(
        a5.rejection?.code,
        'origin_parent_rate_limited',
        reason: 'the registrable apex and its subdomains share one parent',
      );
      a5.settle();
      await pumpEventQueue();
      expect(asked, 2, reason: 'two parents: evil.example and example.com');
      p.dispose();
    });

    test(
      'a question from another site still fires while one parent is spent',
      () async {
        var asked = 0;
        final p = IntakeProtection(nowMs: () => 0)
          ..update(
            policy: OriginPolicy(
              askFiresPerParentPerWindow: 1,
              requireFetchMetadata: false,
              onUnknownOrigin: (origin) {
                asked++;
                return Future<OriginConsent>.value(OriginConsent.dismissed);
              },
            ),
          );
        for (final host in const ['x.r1.evil.example', 'x.r2.evil.example']) {
          final a = await p.admit(origin: 'https://$host');
          a.settle();
          await pumpEventQueue();
        }
        expect(asked, 1);
        // موقع آخر لا علاقة له: سؤاله يُفتح، فالكبح على الأب لا على السقف
        // العام
        final other = await p.admit(origin: 'https://unrelated.org');
        expect(other.rejection?.code, 'origin_pending');
        other.settle();
        await pumpEventQueue();
        expect(asked, 2, reason: 'the other site keeps its question');
        p.dispose();
      },
    );

    test('ten subdomain questions of one parent no longer starve an '
        'unrelated origin', () async {
      var asked = 0;
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            askFiresPerParentPerWindow: 3,
            requireFetchMetadata: false,
            onUnknownOrigin: (origin) {
              asked++;
              return Future<OriginConsent>.value(OriginConsent.dismissed);
            },
          ),
        );
      // عشرة نطاقات فرعية متدوّرة لأب واحد: ميزانية الأب تحد أسئلته هو
      // وحده فثلاثة أسئلة تُفتح (origin_pending) والسبع الباقية تُجاب
      // برمز ميزانية الأب الخاص بلا سؤال جديد
      for (var i = 0; i < 10; i++) {
        final a = await p.admit(origin: 'https://s$i.rotate.example');
        expect(
          a.rejection?.code,
          i < 3 ? 'origin_pending' : 'origin_parent_rate_limited',
        );
        a.settle();
        await pumpEventQueue();
      }
      expect(
        asked,
        3,
        reason:
            'the parent budget bounds this parent at three fires - '
            'the rest of its rotation opens nothing',
      );
      // أصل لا علاقة له: سؤاله يُفتح — الأب المكبوح لم يستهلك السقف العام
      final a = await p.admit(origin: 'https://unrelated.org');
      expect(a.rejection?.code, 'origin_pending');
      a.settle();
      await pumpEventQueue();
      expect(
        asked,
        4,
        reason: 'the unrelated origin still gets its own question',
      );
      p.dispose();
    });

    test('the global ceiling still holds across many parents', () async {
      var asked = 0;
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            askFiresPerParentPerWindow: 2,
            requireFetchMetadata: false,
            onUnknownOrigin: (origin) {
              asked++;
              return Future<OriginConsent>.value(OriginConsent.dismissed);
            },
          ),
        );
      // خمسة آباء بسؤالين لكلٍّ: العشرة تُفتح كاملة فالسقف العام هو الذي
      // يمتلئ هنا لا ميزانية أي أب وحده
      for (var i = 0; i < 5; i++) {
        for (var j = 0; j < 2; j++) {
          final a = await p.admit(origin: 'https://h$j.p$i.example');
          expect(a.rejection?.code, 'origin_pending');
          a.settle();
          await pumpEventQueue();
        }
      }
      expect(asked, 10, reason: 'five parents fill the global ten together');
      // الحادي عشر من أب جديد بضمير ميزانية فارغ: السقف العام يصمد
      final a = await p.admit(origin: 'https://fresh.p5.example');
      expect(a.rejection?.code, 'origin_pending');
      a.settle();
      await pumpEventQueue();
      expect(
        asked,
        10,
        reason: 'the global ceiling bounds every parent once it is spent',
      );
      p.dispose();
    });

    test(
      'suppressed parent questions spend none of the global budget',
      () async {
        var asked = 0;
        final p = IntakeProtection(nowMs: () => 0)
          ..update(
            policy: OriginPolicy(
              askFiresPerParentPerWindow: 1,
              requireFetchMetadata: false,
              onUnknownOrigin: (origin) {
                asked++;
                return Future<OriginConsent>.value(OriginConsent.dismissed);
              },
            ),
          );
        // سؤال الأب الأول يُفتح بـorigin_pending وتسعُ أسئلة تالية لنطاقاته
        // تُكبح برمز ميزانية الأب الخاص بلا طابع على السقف العام — الكبح
        // حصر على الأب لا استهلاك للسقف
        for (var i = 0; i < 10; i++) {
          final a = await p.admit(origin: 'https://h$i.one.example');
          expect(
            a.rejection?.code,
            i == 0 ? 'origin_pending' : 'origin_parent_rate_limited',
          );
          a.settle();
          await pumpEventQueue();
        }
        expect(asked, 1, reason: 'one fire for the whole parent');
        // تسعة آباء بريئة تسعة أسئلة لهم: السقف العام (عشرة) ما زال يتسع
        for (var i = 0; i < 9; i++) {
          final a = await p.admit(origin: 'https://clean$i.org');
          expect(a.rejection?.code, 'origin_pending');
          a.settle();
          await pumpEventQueue();
        }
        expect(
          asked,
          10,
          reason:
              'nine suppressed questions left the global budget intact - '
              'the nine clean parents get their questions',
        );
        // العاشر يصطاد السقف العام الممتلئ الآن
        final a = await p.admit(origin: 'https://late.org');
        expect(a.rejection?.code, 'origin_pending');
        a.settle();
        await pumpEventQueue();
        expect(asked, 10, reason: 'the global ceiling holds at ten');
        p.dispose();
      },
    );

    test('a two-label host and an IP address parent themselves', () async {
      var asked = 0;
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            askFiresPerParentPerWindow: 1,
            requireFetchMetadata: false,
            onUnknownOrigin: (origin) {
              asked++;
              return Future<OriginConsent>.value(OriginConsent.dismissed);
            },
          ),
        );
      // نطاق بأربعة مقاطع: أبوه آخر مقطعين
      final a1 = await p.admit(origin: 'https://s.shop.example.com');
      a1.settle();
      await pumpEventQueue();
      expect(a1.rejection?.code, 'origin_pending');
      // شقيقٌ تحت الأب نفسه: ميزانية الأب تُكبحه برمزها الخاص
      final a2 = await p.admit(origin: 'https://api.shop.example.com');
      a2.settle();
      await pumpEventQueue();
      expect(a2.rejection?.code, 'origin_parent_rate_limited');
      expect(
        asked,
        1,
        reason:
            'both subdomains share the example.com '
            'parent budget',
      );
      // المضيف ذو المقطعين أبٌ لنفسه: سؤاله مستقل عن ميزانية أي موقع آخر
      final a3 = await p.admit(origin: 'https://example.org');
      a3.settle();
      await pumpEventQueue();
      expect(a3.rejection?.code, 'origin_pending');
      // والعنوان أبٌ لنفسه: سؤالاه مستقلان عن كل النطاقات
      final a4 = await p.admit(origin: 'https://93.184.216.34');
      a4.settle();
      await pumpEventQueue();
      expect(a4.rejection?.code, 'origin_pending');
      final a5 = await p.admit(origin: 'https://10.1.2.3');
      a5.settle();
      await pumpEventQueue();
      expect(a5.rejection?.code, 'origin_pending');
      expect(
        asked,
        4,
        reason:
            'a two-label host and each IP literal are their own parent - '
            'their questions never share a budget with a name suffix',
      );
      p.dispose();
    });

    test(
      'zero keeps the global-only ceiling and a negative value throws',
      () async {
        var asked = 0;
        final p = IntakeProtection(nowMs: () => 0)
          ..update(
            policy: OriginPolicy(
              requireFetchMetadata: false,
              onUnknownOrigin: (origin) {
                asked++;
                return Future<OriginConsent>.value(OriginConsent.dismissed);
              },
            ),
          );
        expect(
          () => p.update(
            policy: const OriginPolicy(askFiresPerParentPerWindow: -1),
          ),
          throwsArgumentError,
          reason:
              'a negative budget is a configuration mistake refused at '
              'update time',
        );
        // الافتراضي صفر: سلوك السقف العام وحده كما كان — عشرة أسئلة من أب
        // واحد تُفتح كلها ثم يُسدّ ما بعدها
        for (var i = 0; i < 10; i++) {
          final a = await p.admit(origin: 'https://s$i.legacy.example');
          expect(a.rejection?.code, 'origin_pending');
          a.settle();
          await pumpEventQueue();
        }
        expect(asked, 10, reason: 'the off budget leaves today\'s behavior');
        final a = await p.admit(origin: 'https://unrelated.org');
        expect(a.rejection?.code, 'origin_pending');
        a.settle();
        await pumpEventQueue();
        expect(
          asked,
          10,
          reason: 'with the budget off the global ceiling alone decides',
        );
        p.dispose();
      },
    );

    test(
      'the suppressed question reads its own code with the honest '
      'parent-window wait - the global ceiling keeps origin_pending',
      () async {
        var asked = 0;
        final p = IntakeProtection(nowMs: () => 0)
          ..update(
            policy: OriginPolicy(
              askFiresPerParentPerWindow: 1,
              requireFetchMetadata: false,
              onUnknownOrigin: (origin) {
                asked++;
                return Future<OriginConsent>.value(OriginConsent.dismissed);
              },
            ),
          );
        // سؤال الأب الأول يُفتح بالرمز العام، وشقيقه تحت الميزانية نفسها
        // يقرأ رمز الأب الخاص بحالته وبقايا نافذة الأب الصادقة
        final first = await p.admit(origin: 'https://a.gate.example');
        expect(first.rejection?.code, 'origin_pending');
        expect(first.rejection?.status, 403);
        first.settle();
        await pumpEventQueue();
        final suppressed = await p.admit(origin: 'https://b.gate.example');
        expect(suppressed.rejection?.code, 'origin_parent_rate_limited');
        expect(
          suppressed.rejection?.status,
          429,
          reason:
              'the parent budget is a rate budget, so its code answers '
              'with the quota family status',
        );
        expect(
          suppressed.rejection?.retryAfterMs,
          isNotNull,
          reason: 'the suppression carries the honest parent-window remainder',
        );
        expect(suppressed.rejection!.retryAfterMs!, greaterThanOrEqualTo(1000));
        suppressed.settle();
        await pumpEventQueue();
        // سقف العام لا يتغير حرفاً: الأصل البريء يفتح سؤاله بالرمز العام
        final fresh = await p.admit(origin: 'https://fresh.org');
        expect(
          fresh.rejection?.code,
          'origin_pending',
          reason: 'the global ceiling keeps its own standing code',
        );
        fresh.settle();
        await pumpEventQueue();
        expect(
          asked,
          2,
          reason:
              'two fires: the parent head and the fresh '
              'origin - the suppression fired nothing',
        );
        p.dispose();
      },
    );
  });
}
