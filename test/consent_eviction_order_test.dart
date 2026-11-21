// ترتيب الإخلاء عند سقف الموافقات المحفوظة: الرفض يُخلَّى قبل السماح
// الدائم — قرار رفض أرخص خسارة من موافقة علقها المستخدم، والسقف بلا
// أي رفض يبقى يُخلّي الأقدم كما كان
import 'dart:async';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

void main() {
  group('the consents-cap eviction order', () {
    test(
      'a new denial evicts the oldest denial, never the old always-allow',
      () async {
        var asked = 0;
        final p = IntakeProtection(nowMs: () => 0)
          ..update(
            policy: OriginPolicy(
              requireFetchMetadata: false,
              askTimeout: const Duration(minutes: 10),
              onUnknownOrigin: (origin) {
                asked++;
                return Future<OriginConsent>.value(OriginConsent.dismissed);
              },
            ),
          );
        // السماح الدائم القديم أول الإدراج، ثم رفض واحد، ثم ملء حتى السقف
        p.restoreSavedConsent(
          'https://approved.example',
          OriginConsent.allowAlways,
        );
        p.restoreSavedConsent('https://denied.example', OriginConsent.reject);
        for (var i = 0; i < 998; i++) {
          p.restoreSavedConsent(
            'https://fill$i.example',
            OriginConsent.allowAlways,
          );
        }
        // الرفض الجديد يملأ الخانة 1001: السقف يُخلي أقدم رفض لا السماح القديم
        p.restoreSavedConsent('https://newdeny.example', OriginConsent.reject);
        // السماح القديم باقٍ: يُقبل من ذاكرته بلا سؤال
        final a = await p.admit(origin: 'https://approved.example');
        expect(
          a.rejection,
          isNull,
          reason:
              'the user-approved origin keeps its remembered consent - '
              'a denial is the cheaper loss',
        );
        a.settle();
        expect(asked, 0, reason: 'no new question for the kept consent');
        // الرفض الجديد محفوظ كرفض
        final d = await p.admit(origin: 'https://newdeny.example');
        expect(d.rejection?.code, 'origin_declined');
        d.settle();
        expect(asked, 0);
        // أقدم رفض هو المُخلَّى حصراً: سؤاله يُفتح من جديد
        final r = await p.admit(origin: 'https://denied.example');
        expect(
          r.rejection?.code,
          'origin_pending',
          reason:
              'the oldest denial left the session memory - its origin is '
              'asked anew',
        );
        r.settle();
        await pumpEventQueue();
        expect(asked, 1);
        // إعادة حفظ رفض المُخلَّى تعمل بنظافة الطابور: رفضاً ثانية بلا أثر
        // شبح في الترتيب
        p.restoreSavedConsent('https://denied.example', OriginConsent.reject);
        final r2 = await p.admit(origin: 'https://denied.example');
        expect(r2.rejection?.code, 'origin_declined');
        r2.settle();
        p.dispose();
      },
    );

    test('a cap with no denial still evicts the oldest always-allow', () async {
      var asked = 0;
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            askTimeout: const Duration(minutes: 10),
            onUnknownOrigin: (origin) {
              asked++;
              return Future<OriginConsent>.value(OriginConsent.dismissed);
            },
          ),
        );
      // ألف قرار سماح بلا أي رفض: الأقدم يخرج كما في السلوك القائم
      p.restoreSavedConsent(
        'https://oldest.example',
        OriginConsent.allowAlways,
      );
      for (var i = 0; i < 999; i++) {
        p.restoreSavedConsent(
          'https://allow$i.example',
          OriginConsent.allowAlways,
        );
      }
      p.restoreSavedConsent(
        'https://newest.example',
        OriginConsent.allowAlways,
      );
      // الأقدم المُخلَّى يُسأل من جديد
      final o = await p.admit(origin: 'https://oldest.example');
      expect(
        o.rejection?.code,
        'origin_pending',
        reason:
            'with no denial in the cap the fallback evicts the oldest '
            'allow as before',
      );
      o.settle();
      await pumpEventQueue();
      expect(asked, 1);
      // الأحدث باقٍ بذاكرته
      final n = await p.admit(origin: 'https://newest.example');
      expect(n.rejection, isNull);
      n.settle();
      expect(asked, 1);
      p.dispose();
    });
  });
}
