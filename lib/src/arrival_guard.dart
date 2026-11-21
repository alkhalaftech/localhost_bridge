// حارس الوصول — صنف يملك حالته: الحقائق تدخل والقرار يخرج
// sealed؛ لا nowMs خاماً (elapsedMs لكل طلب من ساعة مونوتونيك
// يملكها المضيف) ولا maxConcurrent (يبقى بالمضيف عند _inFlight).
//
// الترتيب الثلاثي مُجمَّد ومشهَد بـ arrival_guard_test:
// 1) الفيض يعود قبل تسجيل البصمة (الخريطة لا تنمو أثناءه).
// 2) الطلب رقم maxPerMinute يحسب نفسه (add قبل المقارنة).
// 3) dups يُحسب قبل إضافة الطابع الحالي؛ الرابع ضمن النافذة ⟵ تدقيق.
//
// التقليم من مقدمة الطوابير O(1) موزعة — صحته بشرط الرتابة:
// الاستدعاءات تصل بترتيب elapsedMs رتيبا تصاعديا (ساعة مونوتونية
// واحدة للمضيف) فالمنتهي صداها دائما بادئة الطابور، وكل عنصر يُزال
// مرة واحدة على الأكثر. مضيف يكسر الرتابة يحصل على تقليم أقل (عدّادات
// أعلى) لا أوسع — الاتجاه الآمن نحو التشديد لا التساهل.
//
// والطوابير نفسها مسقوفة مشتقا من حد الدقيقة (زائد خانة واحدة
// للإضافة قبل المقارنة) فالحالة كلها محدودة داخل النافذة الواحدة،
// والقص من المقدمة يحفظ الأحدث فالأحكام الثلاثة مجمدة كما كانت.
library;

import 'dart:collection';

/// Arrival facts as the host records them at request time.
class ArrivalFacts {
  /// Builds the facts for one arrival - all five values are required: the
  /// host reads its own clock and computes its own fingerprint, so the
  /// guard never sees payloads.
  const ArrivalFacts({
    required this.elapsedMs,
    required this.fingerprint,
    required this.maxPerMinute,
    required this.dupWindowMs,
    required this.maxDupPerMinute,
  });

  /// Monotonic time for one request (never mixed with the wall clock).
  final int elapsedMs;

  /// A ready fingerprint - the package never sees payloads (the host computes it).
  final String fingerprint;

  /// The global arrivals-per-minute limit enforced through this guard:
  /// arrival number maxPerMinute + 1 inside the guard's [ArrivalGuard.windowMs]
  /// is judged `flood` (the arrival counts itself).
  final int maxPerMinute;

  /// The window in milliseconds inside which repeats of one fingerprint
  /// count as duplicates for [ArrivalGuard] - the `dupLoop` verdict itself
  /// is measured in the guard's own [ArrivalGuard.windowMs].
  final int dupWindowMs;

  /// The per-fingerprint repeat limit: stamp number maxDupPerMinute + 1
  /// for one fingerprint inside the window is judged `dupLoop`.
  final int maxDupPerMinute;
}

/// The closed decision - its review reason stays explicit (a declared enrichment over the current count).
sealed class ArrivalDecision {
  const ArrivalDecision({required this.recentInMinute});

  /// Times this fingerprint was seen within the window - int? so null prints
  /// as '?', matching the host's live log. Held to the fingerprint's
  /// per-minute limit plus one: under a sustained loop it reads that
  /// bound, not the raw arrival rate.
  final int? recentInMinute;
}

/// The accept verdict: the arrival passes both the global rate check and
/// the fingerprint's duplicate check.
final class AcceptArrival extends ArrivalDecision {
  /// Builds the verdict with the duplicate count and the fingerprint's
  /// recent-in-minute figure.
  const AcceptArrival({required this.dups, required super.recentInMinute});

  /// Repeats of this fingerprint inside [ArrivalFacts.dupWindowMs] at
  /// accept time - 0 on a first sighting. Bounded by
  /// [ArrivalFacts.maxDupPerMinute] plus one: a sustained loop reports
  /// that bound, not the raw repeat rate.
  final int dups;
}

/// The review verdict: the arrival is refused for now - `flood` when the
/// global per-minute rate is exceeded, `dupLoop` when one fingerprint
/// repeats past its limit. What a reviewed arrival sees on the wire is
/// the host's decision.
final class ReviewArrival extends ArrivalDecision {
  /// Builds the verdict; [dups] defaults to 0 because a `flood` verdict
  /// carries no duplicate count.
  const ReviewArrival({
    required this.reason,
    required super.recentInMinute,
    this.dups = 0,
  });

  /// Why the arrival was refused: `'flood'` or `'dupLoop'` - no other
  /// value is ever produced.
  final String reason; // 'flood' | 'dupLoop'

  /// Repeats inside the window at rejection time (0 on general overflow) -
  /// feeds the host's review log. Bounded by the fingerprint's
  /// per-minute limit plus one, so a sustained loop reports that bound.
  final int dups;
}

/// The host's arrival guard: a stateful sliding-window rate gate over raw
/// arrival facts. Every verdict is one of three - accept, `flood` (more
/// than [ArrivalFacts.maxPerMinute] arrivals inside [windowMs]), or
/// `dupLoop` (more than [ArrivalFacts.maxDupPerMinute] stamps of one
/// fingerprint inside [windowMs]). It keeps no payload data: fingerprints
/// and monotonic stamps only. Tracked fingerprints are capped at
/// [maxFingerprints], and idle ones are swept oldest-insertion-first at
/// most once per 1000 ms.
class ArrivalGuard {
  /// Builds a guard with the given sliding window and fingerprint cap -
  /// defaults: a [windowMs] of 60000 ms and [maxFingerprints] of 500.
  ArrivalGuard({this.windowMs = 60_000, this.maxFingerprints = 500});

  /// The queue caps derive from the per-minute limits - one slot above
  /// each limit, because the arrival is recorded before the verdict
  /// compares (the increment-before-compare contract), so even an
  /// arrival judged flood stays registered and the queue needs that
  /// slot for the verdict to stay identical after capping:
  /// min(N, limit+1) > limit is true exactly when N > limit. Trimming
  /// from the front keeps the newest arrivals, so a sustained flood
  /// keeps the queue exactly at the cap (the flood state stays armed)
  /// while memory no longer grows with the call rate inside one
  /// window. Internal - no option exposes it.
  static const int _capOverLimit = 1;

  /// The sliding window in milliseconds every rate count is measured in:
  /// stamps older than this are trimmed before each verdict (default 60000).
  final int windowMs;

  /// Cap on fingerprints tracked at once (default 500). Crossing it sweeps
  /// idle fingerprints oldest-insertion-first, at most one sweep per 1000
  /// ms; a fingerprint with stamps inside [windowMs] survives the sweep.
  final int maxFingerprints;

  final Queue<int> _receipts = ListQueue<int>();
  final Map<String, Queue<int>> _fingerprints = <String, Queue<int>>{};

  int _nextSweepMs = 0;

  /// Key insertion order - idle entries are trimmed oldest-first (one pass at most).
  final Queue<String> _keyOrder = ListQueue<String>();

  /// Times this fingerprint's queue currently holds - bounded by the
  /// per-minute limit plus one, so a sustained loop reads that bound
  /// instead of the raw arrival rate.
  int? recentInMinuteOf(String fingerprint) {
    final times = _fingerprints[fingerprint];
    if (times == null || times.isEmpty) return null;
    return times.length;
  }

  /// Records one arrival and returns its verdict.
  ///
  /// The arrival is registered before the verdict compares: the request
  /// that crosses [ArrivalFacts.maxPerMinute] counts itself, and one that
  /// crosses [ArrivalFacts.maxDupPerMinute] likewise. `flood` is returned
  /// when the global receipts inside [windowMs] exceed
  /// [ArrivalFacts.maxPerMinute]; `dupLoop` when this fingerprint's stamps
  /// inside [windowMs] exceed [ArrivalFacts.maxDupPerMinute] -
  /// [AcceptArrival.dups] counts the subset also inside
  /// [ArrivalFacts.dupWindowMs].
  ArrivalDecision decide(ArrivalFacts f) {
    // (1) تقليم البادئة المنتهية ثم التسجيل؛ فيض النافذة يعود قبل لمس
    // البصمات — الخريطة لا تنمو أثناءه. وبعد التسجيل سقف الطابور
    // المشتق: حد الدقيقة زائد خانة واحدة — القص من المقدمة يحفظ
    // الأحدث فالوصول المحكوم فيضاناً يبقى مسجلا والحالة باقية،
    // والذاكرة لا تنمو بمعدل النداءات داخل النافذة الواحدة. والحكم
    // متطابق حرفيا بعد القص: min(N, الحد+1) > الحد ⟺ N > الحد.
    while (_receipts.isNotEmpty && f.elapsedMs - _receipts.first > windowMs) {
      _receipts.removeFirst();
    }
    _receipts.addLast(f.elapsedMs);
    while (_receipts.length > f.maxPerMinute + _capOverLimit) {
      _receipts.removeFirst();
    }
    if (_receipts.length > f.maxPerMinute) {
      return ReviewArrival(
        reason: 'flood',
        recentInMinute: recentInMinuteOf(f.fingerprint),
        dups: 0,
      );
    }

    // (2) بصمات الطلب: تقليم بادئتها، وdups قبل إضافة الحالي
    var times = _fingerprints[f.fingerprint];
    if (times == null) {
      times = ListQueue<int>();
      _fingerprints[f.fingerprint] = times;
      _keyOrder.addLast(f.fingerprint);
    } else {
      while (times.isNotEmpty && f.elapsedMs - times.first > windowMs) {
        times.removeFirst();
      }
    }
    var recentDups = 0;
    for (final t in times) {
      if (f.elapsedMs - t <= f.dupWindowMs) recentDups++;
    }
    times.addLast(f.elapsedMs);
    // سقف طابور البصمة نفسه: حد الدقيقة زائد خانة واحدة — القص من
    // المقدمة يحفظ الأحدث (أقربها للتو) فحساب dups والأحكام كما هي،
    // والتكرار الحلقي المستمر لا ينمو معه الطابور.
    while (times.length > f.maxDupPerMinute + _capOverLimit) {
      times.removeFirst();
    }

    // (3) سقف الخريطة — قص الخاملين من أقدم الإدراج، دورة واحدة
    // كأقصى كي لا يلف الطابور بلا نهاية عندما يكون
    // الوسطاء كلهم أحياء؛ الحي يدور للمؤخرة فيبقى بالطابور مرة واحدة
    // فلا تسرب، والقص لا يمس حيا قط.
    if (_fingerprints.length > maxFingerprints && f.elapsedMs >= _nextSweepMs) {
      _nextSweepMs = f.elapsedMs + 1000;
      var attempts = _keyOrder.length;
      while (_fingerprints.length > maxFingerprints && attempts-- > 0) {
        final oldest = _keyOrder.removeFirst();
        final ts = _fingerprints[oldest];
        if (ts == null) continue; // قُصّ سابقا
        if (ts.isEmpty || f.elapsedMs - ts.last > windowMs) {
          _fingerprints.remove(oldest);
        } else {
          _keyOrder.addLast(oldest);
        }
      }
    }

    if (times.length > f.maxDupPerMinute) {
      return ReviewArrival(
        reason: 'dupLoop',
        recentInMinute: recentInMinuteOf(f.fingerprint),
        dups: recentDups,
      );
    }
    return AcceptArrival(
      dups: recentDups,
      recentInMinute: recentInMinuteOf(f.fingerprint),
    );
  }
}
