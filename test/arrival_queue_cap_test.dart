// سقوف طوابير حارس الوصول: طابور الإيصالات وطابور كل بصمة كانا ينموان
// بنداء واحد لكل نداء داخل النافذة الواحدة بلا سقف — مئة ألف نداء
// تنمو الذاكرة معها. السقف مشتق من حد الدقيقة نفسه (زائد خانة واحدة
// لأن الإضافة قبل المقارنة تسجل الوصول حتى وهو الحكم فيضاناً)،
// والقص من المقدمة يحفظ الأحدث فالحكم متطابق حرفياً بعد القص:
// min(N, الحد+1) > الحد ⟺ N > الحد. والوصول الذي يُحكم عليه فيضاناً
// ما زال يُسجَّل قبل الحكم فما زال يمدد حالة الفيضان كما كانت،
// والحالة تنتهي بنافذتها كما كانت.
import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

ArrivalFacts _solo(int i) => ArrivalFacts(
  elapsedMs: i,
  fingerprint: 'solo',
  maxPerMinute: 1000000,
  dupWindowMs: 3599999,
  maxDupPerMinute: 500,
);

void main() {
  test(
    'a hundred thousand decide calls in one window keep every verdict identical and hold the fingerprint queue at the per-minute limit plus one',
    timeout: const Timeout(Duration(seconds: 180)),
    () {
      final g = ArrivalGuard(windowMs: 3600000, maxFingerprints: 500);
      var accepts = 0;
      var dupLoops = 0;
      ArrivalDecision? last;
      for (var i = 0; i < 100000; i++) {
        final d = g.decide(_solo(i));
        if (d is AcceptArrival) {
          accepts++;
        } else {
          dupLoops++;
        }
        last = d;
      }
      expect(
        accepts,
        500,
        reason:
            'verdicts stay identical: the first maxDupPerMinute arrivals '
            'accept and every arrival after that is still judged dupLoop',
      );
      expect(dupLoops, 99500, reason: 'the loop verdict count does not move');
      expect(
        g.recentInMinuteOf('solo'),
        501,
        reason:
            'the fingerprint queue is held to the per-minute limit plus one - '
            'memory no longer grows with the call rate inside one window',
      );
      // القرار الأخير حلقة تكرار حامل للعدّادين المقيدين — الصلب يقرأهما
      final r = last as ReviewArrival;
      expect(
        r.dups,
        lessThanOrEqualTo(501),
        reason:
            'reported counts cap at the limit plus one so the review log '
            'cannot inflate under a sustained loop',
      );
      expect(
        r.recentInMinute,
        lessThanOrEqualTo(501),
        reason: 'the reported recent-in-minute reads the same bounded queue',
      );
    },
  );

  test(
    'an arrival judged flood still extends the flood state after the cap, and the state still expires exactly with its window',
    () {
      final g = ArrivalGuard(windowMs: 60000, maxFingerprints: 500);
      ArrivalFacts f(int t) => ArrivalFacts(
        elapsedMs: t,
        fingerprint: 'fp',
        maxPerMinute: 2,
        dupWindowMs: 59000,
        maxDupPerMinute: 50,
      );
      expect(g.decide(f(0)), isA<AcceptArrival>());
      expect(g.decide(f(1)), isA<AcceptArrival>());
      expect(g.decide(f(2)), isA<ReviewArrival>());
      expect(g.decide(f(3)), isA<ReviewArrival>());
      // داخل نافذة آخر وصول فيضان لكن خارج نافذة القبولين الأوائل:
      // الحالة باقية لأن الوصولين المحكومين فيضاناً سُجِّلا — بلا
      // تسجيلهما كانت الطابور قد فرغت بعد التقليم فأجاب قبولاً
      final d = g.decide(f(60002));
      expect(
        d,
        isA<ReviewArrival>(),
        reason:
            'the recorded flood arrivals still extend the flood state - the '
            'cap never un-registers them',
      );
      expect((d as ReviewArrival).reason, 'flood');
      // بعد نافذة آخر وصول تعود الحالة فارغة كما كانت
      expect(
        g.decide(f(60004)),
        isA<AcceptArrival>(),
        reason: 'the flood state still expires exactly with its window',
      );
    },
  );
}
