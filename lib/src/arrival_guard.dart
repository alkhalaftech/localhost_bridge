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
library;

import 'dart:collection';

/// Arrival facts as the host records them at request time.
class ArrivalFacts {
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

  final int maxPerMinute;
  final int dupWindowMs;
  final int maxDupPerMinute;
}

/// The closed decision - its review reason stays explicit (a declared enrichment over the current count).
sealed class ArrivalDecision {
  const ArrivalDecision({required this.recentInMinute});

  /// Times this fingerprint was seen within the window - int? so null prints
  /// as '?', matching the host's live log.
  final int? recentInMinute;
}

final class AcceptArrival extends ArrivalDecision {
  const AcceptArrival({required this.dups, required super.recentInMinute});
  final int dups;
}

final class ReviewArrival extends ArrivalDecision {
  const ReviewArrival({
    required this.reason,
    required super.recentInMinute,
    this.dups = 0,
  });
  final String reason; // 'flood' | 'dupLoop'

  /// Repeats inside the window at rejection time (0 on general overflow) -
  /// feeds the host's review log.
  final int dups;
}

class ArrivalGuard {
  ArrivalGuard({this.windowMs = 60_000, this.maxFingerprints = 500});

  final int windowMs;
  final int maxFingerprints;

  final Queue<int> _receipts = ListQueue<int>();
  final Map<String, Queue<int>> _fingerprints = <String, Queue<int>>{};

  int _nextSweepMs = 0;

  /// Key insertion order - idle entries are trimmed oldest-first (one pass at most).
  final Queue<String> _keyOrder = ListQueue<String>();

  int? recentInMinuteOf(String fingerprint) {
    final times = _fingerprints[fingerprint];
    if (times == null || times.isEmpty) return null;
    return times.length;
  }

  ArrivalDecision decide(ArrivalFacts f) {
    // (1) تقليم البادئة المنتهية ثم التسجيل؛ فيض النافذة يعود قبل لمس
    // البصمات — الخريطة لا تنمو أثناءه
    while (_receipts.isNotEmpty && f.elapsedMs - _receipts.first > windowMs) {
      _receipts.removeFirst();
    }
    _receipts.addLast(f.elapsedMs);
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

    // (3) سقف الخريطة — قص الخاملين من أقدم الإدراج (كان 500 حرفيا
    // دورة واحدة كأقصى كي لا يلف الطابور بلا نهاية عندما يكون
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
