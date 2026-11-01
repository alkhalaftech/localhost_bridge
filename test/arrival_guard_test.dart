// اختبار حارس الوصول — الترتيب الحرج الثلاثي شرطاً أخضر حرفياً:
// ترتيب الفحوص مُجمَّد؛ أي إعادة ترتيب تكسر هذه الشواهد.
import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

void main() {
  group('critical check order (frozen)', () {
    test(
      'flood returns before fingerprint is recorded — map does not grow',
      () {
        final g = ArrivalGuard();
        const fp = 'fp-x';
        // طلبان شرعيان يملآن النافذة حتى حدّها (2)
        g.decide(
          const ArrivalFacts(
            elapsedMs: 0,
            fingerprint: fp,
            maxPerMinute: 2,
            dupWindowMs: 8000,
            maxDupPerMinute: 3,
          ),
        );
        g.decide(
          const ArrivalFacts(
            elapsedMs: 50,
            fingerprint: 'fp-b',
            maxPerMinute: 2,
            dupWindowMs: 8000,
            maxDupPerMinute: 3,
          ),
        );
        // الثالث يفيض (3 > 2) — بصمته الجديدة fp-flood
        final d = g.decide(
          const ArrivalFacts(
            elapsedMs: 100,
            fingerprint: 'fp-flood',
            maxPerMinute: 2,
            dupWindowMs: 8000,
            maxDupPerMinute: 3,
          ),
        );
        expect(d, isA<ReviewArrival>());
        expect((d as ReviewArrival).reason, 'flood');
        expect(
          d.dups,
          0,
          reason: 'dups witness: general overflow passes 0 to the review log',
        );
        // الجوهر: البصمة لم تُسجَّل (recentInMinute null ⟵ '?')
        expect(
          d.recentInMinute,
          isNull,
          reason: 'overflow is counted before the fingerprint is recorded',
        );
        expect(g.recentInMinuteOf('fp-flood'), isNull);
      },
    );

    test(
      'request number maxPerMinute counts itself (increment before compare)',
      () {
        final g = ArrivalGuard();
        const facts = ArrivalFacts(
          elapsedMs: 0,
          fingerprint: 'fp',
          maxPerMinute: 3,
          dupWindowMs: 8000,
          maxDupPerMinute: 50,
        );
        // 3 طلبات: الثالث (رقم maxPerMinute) مقبول لأن الفيض عند >
        for (var i = 0; i < 3; i++) {
          final d = g.decide(facts);
          expect(
            d,
            isA<AcceptArrival>(),
            reason: 'request ${i + 1} is accepted',
          );
        }
        // الرابع يفيض
        final d4 = g.decide(
          const ArrivalFacts(
            elapsedMs: 10,
            fingerprint: 'fp2',
            maxPerMinute: 3,
            dupWindowMs: 8000,
            maxDupPerMinute: 50,
          ),
        );
        expect(d4, isA<ReviewArrival>());
      },
    );

    test('dups=3 within window: fourth decision is ReviewArrival', () {
      final g = ArrivalGuard();
      const facts = ArrivalFacts(
        elapsedMs: 0,
        fingerprint: 'same',
        maxPerMinute: 100,
        dupWindowMs: 8000,
        maxDupPerMinute: 3,
      );
      for (var i = 0; i < 3; i++) {
        final d = g.decide(facts);
        expect(d, isA<AcceptArrival>());
      }
      final d4 = g.decide(facts);
      expect(d4, isA<ReviewArrival>(), reason: 'the fourth in dupLoop');
      final r4 = d4 as ReviewArrival;
      expect(r4.reason, 'dupLoop');
      expect(
        r4.dups,
        3,
        reason:
            'dups witness: the repeat passes the three recentDups to the review log',
      );
      expect(
        d4.recentInMinute,
        4,
        reason:
            'reads the state after the decision (as the live host logs it) - the fourth sees 4',
      );
    });
  });

  group('limits and boundaries', () {
    test('window 60_000: stamps outside it are pruned', () {
      final g = ArrivalGuard();
      const base = ArrivalFacts(
        elapsedMs: 0,
        fingerprint: 'fp',
        maxPerMinute: 100,
        dupWindowMs: 8000,
        maxDupPerMinute: 50,
      );
      g.decide(base);
      g.decide(
        const ArrivalFacts(
          elapsedMs: 61_000,
          fingerprint: 'fp',
          maxPerMinute: 100,
          dupWindowMs: 8000,
          maxDupPerMinute: 50,
        ),
      );
      expect(
        g.recentInMinuteOf('fp'),
        1,
        reason: 'the first stamp was trimmed (61s > 60s)',
      );
    });

    test('map cap 500: idle fingerprints are evicted', () {
      final g = ArrivalGuard();
      // خطوة 1000ms: fp-0 عند 0 وfp-500 عند 500_000 — البصمات القديمة
      // خارجة نافذة الدقيقة فتُقلَم عند تشغيل السقف (المفتاح 501)
      for (var i = 0; i <= 500; i++) {
        g.decide(
          ArrivalFacts(
            elapsedMs: i * 1000,
            fingerprint: 'fp-$i',
            maxPerMinute: 1000,
            dupWindowMs: 8000,
            maxDupPerMinute: 50,
          ),
        );
      }
      expect(
        g.recentInMinuteOf('fp-0'),
        isNull,
        reason:
            'the oldest fingerprint was evicted past 500 (idle outside the window)',
      );
    });

    test('comparison is > not >= (strict boundary)', () {
      final g = ArrivalGuard();
      // maxPerMinute=1: الطلب الأول يقبل (1 > 1 خطأ)؛ الثاني يفيض (2 > 1)
      const f1 = ArrivalFacts(
        elapsedMs: 0,
        fingerprint: 'a',
        maxPerMinute: 1,
        dupWindowMs: 8000,
        maxDupPerMinute: 9,
      );
      expect(g.decide(f1), isA<AcceptArrival>());
      expect(
        g.decide(
          const ArrivalFacts(
            elapsedMs: 1,
            fingerprint: 'b',
            maxPerMinute: 1,
            dupWindowMs: 8000,
            maxDupPerMinute: 9,
          ),
        ),
        isA<ReviewArrival>(),
      );
    });
  });

  group('amortized O(1) pruning — measurement', () {
    ArrivalGuard stressed() => ArrivalGuard();

    // نافذة ممتلئة دوما (60k طابع) + خريطة فوق سقفها (700 بصمة/500)
    // وسقف فيض مرتفع: أثقل تشغيل للتقليم — المسح الكامل القديم كان
    // يجعل كل decide تمسح 60k طابعا فتنمو الكلفة تربيعيا.
    ArrivalFacts factsAt(int i) => ArrivalFacts(
      elapsedMs: i,
      fingerprint: 'fp-${i % 700}',
      maxPerMinute: 100_000,
      dupWindowMs: 50,
      maxDupPerMinute: 3,
    );

    void run(int count) {
      final g = stressed();
      for (var i = 0; i < count; i++) {
        g.decide(factsAt(i));
      }
    }

    test(
      '100k consecutive decide calls: second half fights no growing state',
      () {
        // عينتا 10k و100k بالنص، والنصفان للكشف عن التباطؤ التراكمي
        final sw10 = Stopwatch()..start();
        run(10_000);
        sw10.stop();

        final sw = Stopwatch()..start();
        final g = stressed();
        for (var i = 0; i < 50_000; i++) {
          g.decide(factsAt(i));
        }
        final firstHalfMs = sw.elapsedMilliseconds;
        for (var i = 50_000; i < 100_000; i++) {
          g.decide(factsAt(i));
        }
        final totalMs = sw.elapsedMilliseconds;
        final secondHalfMs = totalMs - firstHalfMs;
        // ignore: avoid_print
        print(
          'BENCH 10k=${sw10.elapsedMilliseconds}ms '
          '100k-total=${totalMs}ms first-half=$firstHalfMs '
          'second-half=$secondHalfMs',
        );
        expect(
          secondHalfMs < firstHalfMs * 3 + 50,
          isTrue,
          reason:
              'تقليم المقدمة يجعل الكلفة موزعة: النصف الثاني لا '
              'يصارع قائمة تنمو (المسح الكامل القديم كان يفجر النسبة)',
        );
        expect(
          totalMs,
          lessThan(15_000),
          reason: '100k decisions in reasonable time - no quadratic buildup',
        );
      },
    );

    test('determinism is correctness: decisions unchanged after rebuild', () {
      final g = stressed();
      // 700 بصمة × 5 جولات: كل بصمة ترى 4 تكرارات سابقة ضمن النافذة
      // (stamps 700ms apart, window 60s) — fifth round per fingerprint
      // تتجاوز maxDupPerMinute=3 فتراجَع
      var reviews = 0;
      for (var i = 0; i < 700 * 5; i++) {
        final d = g.decide(factsAt(i));
        if (d is ReviewArrival) reviews++;
      }
      expect(
        reviews,
        1400,
        reason:
            'النافذة 60s تحتفظ بالحدوث الخمسة كلها (تباعد 700ms) '
            'فالرابع والخامس لكل بصمة مراجَعان — 2×700 — الدلالة كما '
            'كانت والمسح الكامل القديم يعطي العدد نفسه',
      );
    });
  });
}
