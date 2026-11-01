import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:math';

import 'bridge_telemetry.dart';

/// Optional protection for the local command intake - host-configured.
///
/// The default risk (the allow-all value): a 127.0.0.1 intake accepting POST
/// from any page the user visits - the browser sends the request even when
/// CORS blocks reading the reply, so any site could fire its command at once.
/// - The allowlist: only pages from a host-defined origin list are accepted
/// (the Origin header is enforced by the browser and cannot be forged by
/// JavaScript - the right barrier against cross-site pages; local clients
/// outside the browser are outside the threat model anyway).
/// - Discovery (onUnknownOrigin): a new origin is put to the host exactly
/// once - always allow, allow once, or deny - so the list grows on
/// knowledge, not guessing.
/// - The token layer: an X-Portal-Token header matching a shared secret - an
/// integrated client proves itself with it and crosses without browser
/// headers (server-side integrations, or when origins multiply).
/// The host's answer to an unknown-origin question. [allowAlways] and
/// [reject] are remembered for the session, [allowOnce] grants a single
/// retry window, and [dismissed] closes the question without a decision:
/// nothing is remembered and the origin is asked again on its next request
/// (use it when the question was displaced, its window expired, or the
/// session ended before the user answered).
enum OriginConsent { allowAlways, allowOnce, reject, dismissed }

/// Origin policy - the single concept left after the open mode was merged in:
/// the list rules; allow-all is its widest value with the hardening attached; discovery grows it. Closed by default (an empty list denies all).
class OriginPolicy {
  const OriginPolicy({
    this.allowed = const [],
    this.allowAllHardened = false,
    this.allowLocalHttp = false,
    this.reportOnly = false,
    this.onUnknownOrigin,
    this.perOriginPerMinute = 30,
    this.listedPerOriginPerMinute = 0,
    this.requireFetchMetadata = true,
    this.askTimeout = const Duration(seconds: 60),
  });

  /// Accepted entries - a full origin (https://host) or a bare host, and the
  /// pattern `*.example.com` accepts subdomains (not the root itself).
  final List<String> allowed;

  /// Allow-all - a candidly revealing name for the riskiest value: origin,
  /// send-method, and quota hardening always ride along, so bare-open never returns.
  final bool allowAllHardened;

  /// Development exception: accept http://localhost and 127.0.0.1 on the
  /// allow-all path (local dev pages usually have no https).
  final bool allowLocalHttp;

  /// Watch mode: the origin quota is logged as a would-reject instead of
  /// rejecting, to measure its effect on a live gate first. Request-shape
  /// hardening (a valid HTTPS Origin plus the fetch-mode checks) always
  /// rejects, watching included: no legitimate fetch caller can ever fail
  /// those checks, so watching them measures nothing while leaving silent
  /// sends (hidden forms, beacons, no-cors) open.
  final bool reportOnly;

  /// Auto discovery: an unlisted origin asks the host once; without it an
  /// unlisted origin is rejected with an explicit code, never silently accepted.
  final Future<OriginConsent> Function(String origin)? onUnknownOrigin;

  /// Per-origin requests-per-minute quota, on the allow-all path only
  /// (sane values that never break a legitimate gate and bound one origin's damage).
  final int perOriginPerMinute;

  /// Optional per-origin quota for the listed path - 0 (the default) keeps
  /// listed origins unquotaed; a positive value bounds a compromised listed
  /// origin's flood over the shared seats. Rejections use the same
  /// `origin_rate_limited` code as the allow-all quota.
  final int listedPerOriginPerMinute;

  /// Refuse requests that carry no `Sec-Fetch-Mode: cors` /
  /// `Sec-Fetch-Dest: empty` on the browser paths (allow-all and discovery).
  /// On by default: a browser without Fetch Metadata can otherwise send
  /// silently (write-side) even through the hardening. Turn it off only if
  /// you serve headerless non-browser clients through the browser paths —
  /// the token layer returns before the shape checks, so token integrations
  /// are never affected either way.
  final bool requireFetchMetadata;

  /// Timeout of the single discovery question - without it an unanswered
  /// window would hold a seat forever (injectable for tests).
  final Duration askTimeout;
}

/// The intake rejection - the code is the developer contract, the message neutral English.
class IntakeRejection {
  const IntakeRejection(
    this.status,
    this.code,
    this.message, {
    this.retryAfterMs,
  });

  /// 403 for denial, 429 for the origin quota.
  final int status;
  final String code;
  final String message;

  /// The honest wait for THIS rejection in milliseconds - the remainder of
  /// the window that caused it (token lockout, per-origin quota, or the
  /// new-question budget). The server emits it as the Retry-After header
  /// (seconds, rounded up); null keeps the caller's own default.
  final int? retryAfterMs;
}

/// Migration of old saved values - 'open' is retired, so reading it is an
/// unknown value: close + warn (details in [updateFromSaved]).

class IntakeProtection {
  /// [nowMs] is an injectable test clock (lock, grant, and quota windows);
  /// the default is an internal monotonic clock owned by the object.
  IntakeProtection({this.telemetry, int Function()? nowMs}) : _nowMs = nowMs {
    if (nowMs == null) _clock.start();
  }

  /// Injected test time - or null to use [_clock].
  final int Function()? _nowMs;

  int get _now => _nowMs?.call() ?? _clock.elapsedMilliseconds;

  /// Security log seam: the host adapts AppLogger - default mutes, never drops behavior.
  final BridgeTelemetry? telemetry;

  OriginPolicy _policy = const OriginPolicy();
  List<String> _allowed = const [];
  String _token = '';

  // عدّاد المرفوضات للعرض في شاشة التشخيص — الرؤية جزء من الحماية
  int _rejectedCount = 0;

  /// Called after every rejection so the counter refreshes live in the UI -
  /// with no subscriber (the protection object also runs inside the intake with no UI).
  void Function()? onRejected;

  /// Discovery decisions kept for the session (always-allow / deny) - the
  /// host may persist them across sessions if it wants.
  final Map<String, OriginConsent> _consents = <String, OriginConsent>{};

  /// The pending question is unified: two concurrent requests for a new
  /// origin ask the host once, not twice.
  final Map<String, Future<OriginConsent>> _pendingAsks =
      <String, Future<OriginConsent>>{};

  /// One-shot grants: origin -> expiry of a short-lived single-request grant.
  /// Insertion sweeps expired entries once the map crosses
  /// [_maxOnceGrants]: an answered-but-never-retried grant must not live
  /// for the whole session.
  final Map<String, int> _onceGrants = <String, int>{};
  static const _maxOnceGrants = 64;
  final Set<Timer> _askTimers = <Timer>{};

  /// The controller is dormant - a late reply after dispose is ignored.
  bool _disposed = false;

  /// Policy generation - every update bumps it and every window carries its
  /// launch generation, so a reply given under an old policy never applies (TOCTOU).
  int _policyGeneration = 0;
  static const _onceGrantWindowMs = 30_000;

  /// Cap on questions pending together - beyond it an automatic reject:
  /// consent windows must not become a way to hold seats and exhaust the user.
  static const _maxPendingAsks = 3;

  /// Cap on NEW questions over time - the pending cap bounds a moment (three
  /// windows together), not a timeline: one site rotating subdomains could
  /// open question windows without end. Over the budget the request still
  /// gets origin_pending, but no question fires until stamps age out.
  static const _maxAskFiresPerWindow = 10;
  static const _askBudgetWindowMs = 600_000;
  final Queue<int> _askFireStamps = Queue<int>();

  /// Cap on discovery decisions kept in the session (without one they grow unbounded).
  static const _maxConsents = 1000;
  final Queue<String> _consentOrder = ListQueue<String>();

  /// Persist a discovery decision (always-allow and deny) within the map cap -
  /// used alike by the awaiter and the standalone listener of a late reply.
  void _rememberConsent(String key, OriginConsent decision) {
    if (decision == OriginConsent.allowOnce) return;
    if (!_consents.containsKey(key)) {
      _consentOrder.addLast(key);
      if (_consentOrder.length > _maxConsents) {
        _consents.remove(_consentOrder.removeFirst());
      }
    }
    _consents[key] = decision;
  }

  /// Token-guessing lockout - the window is per-origin for web requests (a
  /// guessing origin locks only itself: a collective web window let any
  /// visited site lock the bridge for the legitimate origin), one shared
  /// window for originless requests (local integrations), and the map
  /// capped by idle entries exactly like the origin quota windows below.
  final Map<String, Queue<int>> _tokenMissWindows = <String, Queue<int>>{};
  final Queue<String> _tokenMissOrder = ListQueue<String>();
  int _nextTokenSweepMs = 0;
  static const _tokenLockThreshold = 5;
  static const _tokenLockWindowMs = 60_000;
  static const _maxTokenMissWindows = 1000;

  /// The entropy floor a configured portal token must meet (UTF-8 bytes):
  /// update() refuses anything shorter - see the guard there.
  static const _minTokenBytes = 32;
  final Queue<int> _anonTokenMisses = Queue<int>();

  /// Origin quota windows: stamps trimmed from the front of a queue, and the
  /// map itself capped by its idle entries, cleared oldest-insertion-first in
  /// one pass (the same pattern as ArrivalGuard).
  final Map<String, Queue<int>> _originWindows = <String, Queue<int>>{};
  final Queue<String> _windowOrder = ListQueue<String>();
  final Stopwatch _clock = Stopwatch()..start();

  static const _windowMs = 60_000;
  static const _maxOriginWindows = 1000;
  int _nextWindowSweepMs = 0;

  OriginPolicy get policy => _policy;
  int get rejectedCount => _rejectedCount;

  void _countRejection() {
    _rejectedCount++;
    onRejected?.call();
  }

  /// Update the policy and its layers - takes effect at once (the server reads live state).
  ///
  /// An omitted field keeps its current layer: a policy-only call leaves the
  /// token active and a token-only call leaves the allowlist intact - pass an
  /// explicit empty token ('') or const OriginPolicy() to clear a layer.
  /// Every call starts a fresh policy generation (a pending consent answer
  /// never applies under the policy it was asked under). Applying a changed
  /// origin policy revokes remembered grants and once-grants; remembered
  /// denials live for the session, and a token-only or empty call touches no
  /// origin decision (persisting decisions across sessions is the host's
  /// business).
  ///
  /// Throws [ArgumentError] for a configured token below the entropy floor
  /// ([_minTokenBytes] UTF-8 bytes) BEFORE anything is applied, so a host
  /// that catches the error keeps its previous protection state untouched.
  /// The error names the offending length, never the token itself.
  void update({OriginPolicy? policy, String? token}) {
    // الحقل المفقود يبقى على حاله: تحديثُ حقلٍ واحدٍ كان يطفئ الطبقة
    // الأخرى بصمت (من ضبط توكنا ثم حدّث القائمة فقد سرّه، والعكس)
    final effectivePolicy = policy ?? _policy;
    final effectiveToken = token ?? _token;
    // القصير قابل للتخمين — رفض وقت الإعداد لا تحذير يمر: طبقة أسرار
    // مسرحية أسوأ من غيابها. الفحص قبل _apply كي يكون الرمي بلا أثر
    // جانبي — من يلتقطه يبقى على حالته السابقة لا على طبقة خاملة
    final tokenBytes = utf8.encode(effectiveToken.trim()).length;
    if (tokenBytes > 0 && tokenBytes < _minTokenBytes) {
      throw ArgumentError.value(
        tokenBytes,
        'token',
        'is $tokenBytes bytes (UTF-8) - a portal token needs at least '
            '$_minTokenBytes random bytes (generatePortalToken produces one); '
            'a short token is guessable from a web page',
      );
    }
    _apply(policy: effectivePolicy, token: effectiveToken);
    _warnDeadAllowlistEntries();
    // حارس طول التوكن: ما تجاوز الحشوة يُقارن ببادئته فقط في
    // _fixedTimeEquals — تحذير أمني + عدّاد، وبلا أي تغيير لنتيجة
    // المطابقة (صفر سلك).
    final configuredBytes = utf8.encode(_token).length;
    if (configuredBytes > _tokenComparePad) {
      // تحذير إعداد لا رفض طلب — لا يلوث عدّاد المرفوضات
      telemetry?.warn(
        'portal token length $tokenBytes bytes (UTF-8) exceeds the '
        'comparison pad ($_tokenComparePad) — the whole token is still '
        'compared, but every extra byte widens the fixed-time loop; '
        'prefer a token of at most $_tokenComparePad bytes',
        category: BridgeCategory.security,
      );
    }
    if (effectivePolicy.allowAllHardened) {
      // الخيار الفاضح لا يُفعَّل بصمت
      telemetry?.warn(
        'intake policy: allow-all-hardened is ACTIVE'
        '${effectivePolicy.reportOnly ? ' (report-only)' : ''} — every HTTPS '
        'page reaching this host may send commands (hardened: origin, fetch '
        'mode, per-origin quota)',
        category: BridgeCategory.security,
      );
    }
  }

  /// Apply-only, without the save-time warnings - [updateFromSaved] passes
  /// through here so every startup does not re-warn about a bad entry saved
  /// once (it is said once at save time and its trace stays in the log).
  void _apply({required OriginPolicy policy, String token = ''}) {
    // هل تغيرت قرارات الأصل فعلاً؟ التوكن طبقة مستقلة لا تعنيها،
    // والمقارنة على ما يصنع قرار الأصل حصراً (القائمة المطبعة
    // والأعلام وحضور خطاف السؤال — هويته لا تغير معنى الموافقة،
    // والحواصف والمهل أدوات تنفيذ لا مضمون قرارات)
    final originDecisionsChanged = !_sameOriginDecisions(_policy, policy);
    // الجيل يزاد هنا وحدها: كل مسار يغير السياسة (update وupdateFromSaved)
    // يبطل جوابات نوافذ الجيل السابق — كان updateFromSaved يتخطى الزيادة
    _policyGeneration++;
    _policy = policy;
    _allowed = _normalizeAllowed(policy.allowed);
    _token = token.trim();
    if (!originDecisionsChanged) return;
    // المنح تموت مع سياستها (سحب التضييق يعمل)، والرفض قرار المستخدم
    // على الأصل لا على السياسة فيبقى للجلسة كما يعد الدليل — وحارس
    // الجيل أعلاه يُسقط الجوابات المعلقة فلا يبقى إلا المخزّن
    _onceGrants.clear();
    _consents.removeWhere((_, consent) => consent != OriginConsent.reject);
    _consentOrder.removeWhere((key) => !_consents.containsKey(key));
  }

  /// Normalize a raw allowlist the way [_apply] stores it: trimmed,
  /// lower-cased, trailing slashes stripped, blanks dropped. The path after
  /// the host survives as-is - an entry with a path never matches a browser
  /// Origin, and [_warnDeadAllowlistEntries] says so at save time.
  static List<String> _normalizeAllowed(List<String> origins) => origins
      .map((o) => o.trim().toLowerCase().replaceAll(_trailingSlashes, ''))
      .where((o) => o.isNotEmpty)
      .toList();

  /// Do the two policies decide origins the same way? The token is
  /// deliberately excluded (its layer is independent of origin decisions),
  /// the consent callback is compared by availability rather than identity
  /// (rebuilding the same closure must not read as a policy change), and
  /// quotas and timeouts are enforcement knobs, not decision content.
  bool _sameOriginDecisions(OriginPolicy a, OriginPolicy b) {
    if (a.allowAllHardened != b.allowAllHardened) return false;
    if (a.allowLocalHttp != b.allowLocalHttp) return false;
    if ((a.onUnknownOrigin == null) != (b.onUnknownOrigin == null)) {
      return false;
    }
    final left = _normalizeAllowed(a.allowed).toSet();
    final right = _normalizeAllowed(b.allowed).toSet();
    return left.length == right.length && left.containsAll(right);
  }

  /// An entry with a path is dead on arrival: 'portal.example.com/labels'
  /// never equals the origin 'https://portal.example.com' the browser sends
  /// (Origin carries no path), so the entry works 'sometimes' in the user's
  /// eyes and never in fact. Warn at save time so the failure is discovered in
  /// settings themselves, not by losing a first command.
  void _warnDeadAllowlistEntries() {
    for (final raw in _allowed) {
      // مدخل كامل بمخطط http: يقبل حرفيا (يحمل مخططه) لكنه شبه ميت
      // خارج localhost — ينذر كمدخل المسار الميت
      if (raw.startsWith('http://')) {
        telemetry?.warn(
          'allowlist entry "$raw" uses http:// — only safe for '
          'localhost development; use the bare host or https:// for '
          'public portals',
          category: BridgeCategory.security,
        );
      }
      final bareOrigin = _bareOrigin.hasMatch(raw);
      if (raw.contains('/') && !bareOrigin) {
        telemetry?.warn(
          'allowlist entry "$raw" contains a path — Origin never carries '
          'one, so this entry will never match. Enter the full origin '
          '(https://host) or the bare host alone',
          category: BridgeCategory.security,
        );
      }
      // النمط العريض: لاحقة من مقطعين أو أقل (ك*.com و*.shop.example)
      // تطابق كل النطاقات الفرعية لجذر كامل — تحذير لا رفض، فمن قصد
      // النمط يعرف (التقدير تقريبي بلا قائمة اللواحق العامة)
      if (raw.startsWith('*.')) {
        final labels = raw
            .substring(2)
            .split('.')
            .where((l) => l.isNotEmpty)
            .length;
        if (labels <= 2) {
          telemetry?.warn(
            'allowlist entry "$raw" matches every subdomain of a broad '
            'root — prefer the explicit hosts you need',
            category: BridgeCategory.security,
          );
        }
      }
    }
  }

  /// Update from a saved value (prefs): 'allowlist' and 'token' are known;
  /// complete absence (first run) is a clean close with no warning; an
  /// unknown one (including the retired 'open') closes with a warning and a
  /// counter - capability is never widened silently.
  void updateFromSaved({
    required String? savedMode,
    List<String> allowedOrigins = const [],
    String token = '',
  }) {
    final known =
        savedMode == null || savedMode == 'allowlist' || savedMode == 'token';
    if (!known) {
      _countRejection();
      telemetry?.warn(
        'saved intake mode "$savedMode" is unknown ("open" was removed '
        'in the policy rework) — falling back to the closed default and '
        'recording the incident, never silently widening access',
        category: BridgeCategory.security,
      );
    }
    // التوكن القصير المحفوظ خامل لا مفعل: update() يرفضه عند الحفظ،
    // ومسار الإقلاع لا ينهار بحلقة رمي — تُطفأ الطبقة (فشل مغلق) مع
    // تحذير واحد عال الصوت
    final savedTokenBytes = utf8.encode(token.trim()).length;
    var effectiveToken = token;
    if (savedTokenBytes > 0 && savedTokenBytes < _minTokenBytes) {
      effectiveToken = '';
      telemetry?.warn(
        'saved portal token is short ($savedTokenBytes bytes) and stays '
        'inert - the token layer is off until a fresh '
        '$_minTokenBytes-byte token is saved (fail-closed, not a crash '
        'loop)',
        category: BridgeCategory.security,
      );
    }
    // _apply لا update: تحذيرات الحفظ تقال مرة عند الحفظ فقط،
    // لا مع كل إقلاع يعيد تحميل المدخل نفسه
    _apply(
      policy: savedMode == 'allowlist'
          ? OriginPolicy(allowed: allowedOrigins)
          : const OriginPolicy(),
      token: effectiveToken,
    );
  }

  /// The two patterns are compiled once - they used to be rebuilt on every
  /// settings update (one of them per request on the normalize path). They
  /// are static now: normalize uses them from the hot paths too.
  static final RegExp _trailingSlashes = RegExp(r'/+$');
  static final RegExp _bareOrigin = RegExp(r'^[a-z]+://[^/]+$');

  /// Is the origin listed? - full match, bare host, or `*.domain` pattern
  /// (the pattern covers subdomains only; the root must be listed explicitly).
  bool _isListed(String? origin) {
    if (origin == null || origin.isEmpty) return false;
    if (_consents[normalize(origin)] == OriginConsent.allowAlways) {
      return true;
    }
    final uri = Uri.tryParse(origin);
    if (uri == null || uri.host.isEmpty) return false;
    final host = uri.host.toLowerCase();
    // المدخلان المجرد والنمطي يطابقان
    // https حصرا (أو المضيف المحلي عند allowLocalHttp): قبول http لهما
    // كان انحدارا يعيد ثغرة الشبكة العامة — والمدخل الكامل يحمل مخططه
    // فمطابقته واعية للمخطط أصلا
    final schemeOk =
        uri.scheme == 'https' ||
        (_policy.allowLocalHttp &&
            uri.scheme == 'http' &&
            (host == 'localhost' || host == '127.0.0.1' || host == '::1'));
    final normalized = normalize(origin);
    for (final entry in _allowed) {
      if (entry == normalized) return true;
      // المدخل «*.» بلا جذر كان يقبل أي مضيف
      // بخاتمة نقطة (أصل متصفحي مشروع) — النمط يُشترط له جذر
      if (schemeOk && entry == host) return true;
      if (schemeOk && entry.startsWith('*.') && entry.length > 2) {
        final suffix = entry.substring(1); // '.example.com'
        if (host.endsWith(suffix) && host.length > suffix.length) {
          return true;
        }
      }
    }
    return false;
  }

  static String normalize(String origin) =>
      origin.toLowerCase().replaceAll(_trailingSlashes, '');

  /// A valid browser origin - the basis for the discovery question (asking
  /// about sandbox/null or http origins is meaningless).
  bool _validBrowserOrigin(String origin) {
    final uri = Uri.tryParse(origin);
    return uri != null && uri.scheme == 'https' && uri.host.isNotEmpty;
  }

  /// Accept the request - null means allowed; [IntakeRejection] carries status,
  /// code, and message. Order: the token layer passes on its own, then the list,
  /// then allow-all with its hardening, then discovery or an explicit reject.
  Future<IntakeRejection?> check({
    String? origin,
    String? portalToken,
    String? fetchMode,
    String? fetchDest,
  }) async {
    // الخمول التام قرارا نهائيا على كل المسارات (لا نصف حي): المدرج
    // والتوكن والحصص كلها تتوقف — برمز مستقل لا يوهم المطور بأن
    // إدراج الأصل ينفع
    if (_disposed) {
      return const IntakeRejection(
        503,
        'protection_disposed',
        'The protection object is disposed — create a new one',
      );
    }
    // (0) طبقة التوكن المستقلة. القفل يفحص قبل المقارنة: المقفول يُرد
    // 429 حتى بتوكن صحيح (كان الصحيح يُقبل بعد القفل فلا يوقف التخمين)
    // — والصحيح من نافذة غير مقفولة يصفرها ويعبر فورا.
    if (_token.isNotEmpty && portalToken != null && portalToken.isNotEmpty) {
      final now = _now;
      final window = _tokenMissWindow(origin, now);
      if (window.length >= _tokenLockThreshold) {
        // القفل يمنع المقارنة وحدها: التوكن يُعامل كأنه غائب وتُقيَّم
        // سياسة الأصول — البوابة المدرجة تعبر رغم إخفاقات مهاجم مجهول،
        // ومن ترفضه السياسة أصلًا يُرَدّ 429 (لا 403: كان يحاول التخمين)
        final verdict = await _checkBeyondToken(origin, fetchMode, fetchDest);
        if (verdict == null) return null;
        // الرأس الصادق: بقايا نافذة القفل نفسها — أقدم إخفاق يخرج من
        // النافذة فتنكسر، فانتظار الذكرى لا «ثانيتين» لكل الرفوض
        final lockWaitMs = window.isEmpty
            ? _tokenLockWindowMs
            : _tokenLockWindowMs - (now - window.first) + 500;
        return IntakeRejection(
          429,
          'token_locked',
          'Too many failed token attempts — retry after a short wait',
          retryAfterMs: lockWaitMs < 1000 ? 1000 : lockWaitMs,
        );
      }
      if (_fixedTimeEquals(portalToken, _token)) {
        window.clear();
        return null;
      }
      window.addLast(now);
    }

    return _checkBeyondToken(origin, fetchMode, fetchDest);
  }

  /// The miss window a token attempt counts against: per-origin for web
  /// requests, the shared originless window for local integrations. The
  /// per-origin map is swept by idle entries at the same cap and pacing as
  /// the quota windows (one pass at most, once a second at most).
  Queue<int> _tokenMissWindow(String? origin, int now) {
    if (origin == null) {
      while (_anonTokenMisses.isNotEmpty &&
          now - _anonTokenMisses.first > _tokenLockWindowMs) {
        _anonTokenMisses.removeFirst();
      }
      return _anonTokenMisses;
    }
    final key = normalize(origin);
    var window = _tokenMissWindows[key];
    if (window == null) {
      window = Queue<int>();
      _tokenMissWindows[key] = window;
      _tokenMissOrder.addLast(key);
    }
    while (window.isNotEmpty && now - window.first > _tokenLockWindowMs) {
      window.removeFirst();
    }
    if (_tokenMissWindows.length > _maxTokenMissWindows &&
        now >= _nextTokenSweepMs) {
      _nextTokenSweepMs = now + 1000;
      var attempts = _tokenMissOrder.length;
      while (_tokenMissWindows.length > _maxTokenMissWindows &&
          attempts-- > 0) {
        final oldest = _tokenMissOrder.removeFirst();
        final ts = _tokenMissWindows[oldest];
        if (ts == null) continue;
        final idle = ts.isEmpty || now - ts.last > _tokenLockWindowMs;
        if (idle) {
          _tokenMissWindows.remove(oldest);
        } else {
          _tokenMissOrder.addLast(oldest);
        }
      }
    }
    return window;
  }

  /// Acceptance after the token layer: the list, then allow-all with its hardening, then discovery.
  Future<IntakeRejection?> _checkBeyondToken(
    String? origin,
    String? fetchMode,
    String? fetchDest,
  ) async {
    // (1) القائمة — المدرج يعبر (ومنه من حُفظ سماحه الدائم بالاكتشاف)،
    // ومع حصة اختيارية إن فعّلها المضيف: المدرج المخترق وحده من
    // يملأ المقاعد بلا حد، فالحصة هنا تحصر ضرره بنافذته ولا تمس
    // بقية المدرجين
    if (_isListed(origin)) {
      final listedQuota = _policy.listedPerOriginPerMinute;
      if (listedQuota > 0) {
        final quota = _originQuotaVerdict(origin, listedQuota);
        if (quota != null) {
          // وضع المراقبة يحرس الحصتين معاً — حصة المدرج حصة كحصة
          // «الكل»: تُسجل كان-سيرفض ويُخدم الطلب
          if (!_policy.reportOnly) return quota;
          telemetry?.warn(
            'intake report-only: would reject — ${quota.code}: '
            '${quota.message} (origin=${origin ?? 'none'})',
            category: BridgeCategory.security,
          );
        }
      }
      return null;
    }

    // (2) مسار «الكل» — تحصيناته ملازمة له. فحوص شكل الطلب (أصل صالح
    // + ترويستا Sec-Fetch) تنفَّذ دائماً حتى في وضع المراقبة: لا fetch
    // شرعيا يفشلها قط فمراقبتها لا تقيس شيئا، وإعفاؤها يفتح الإرسال
    // الصامت (نموذج مخفي/beacon بلا حاجة لقراءة الرد). الوضع المراقب
    // يُعفّي الحصة وحدها — هي محل القياس يوم التبديل.
    if (_policy.allowAllHardened) {
      final blocked = _browserRequestBlocked(origin, fetchMode, fetchDest);
      if (blocked != null) return blocked;
      final quota = _originQuotaVerdict(origin);
      if (quota == null) return null;
      if (_policy.reportOnly) {
        telemetry?.warn(
          'intake report-only: would reject — ${quota.code}: '
          '${quota.message} (origin=${origin ?? 'none'})',
          category: BridgeCategory.security,
        );
        return null;
      }
      return quota;
    }

    // (3) الاكتشاف — أصل متصفحي صالح غير مدرج يسأل المضيف مرة (شرط 4).
    // تحصينات المتصفح أولا: لا يُسأل
    // المستخدم عن نموذج مخفي ولا عن أصل غير https — السؤال للمتصفح
    // الصادق وحده، ونافذته مهلوسة ومسقوفة كي لا تكون وسيلة إغراق
    if (_policy.onUnknownOrigin != null &&
        origin != null &&
        origin.isNotEmpty &&
        _validBrowserOrigin(origin)) {
      final preBlocked = _browserRequestBlocked(origin, fetchMode, fetchDest);
      if (preBlocked != null) return preBlocked;
      final key = normalize(origin);
      final remembered = _consents[key];
      if (remembered == OriginConsent.reject) {
        return const IntakeRejection(
          403,
          'origin_declined',
          'The host declined this origin',
        );
      }
      // منحة سماح-مرة: طلب واحد خلال نافذتها القصيرة ثم تُستهلك — لا
      // تمرير دفعي لكل المنتظرين (جواب واحد كان يجيز حتى حد المقاعد)
      final grant = _onceGrants[key];
      if (grant != null) {
        _onceGrants.remove(key);
        if (_now <= grant) return null;
      }
      // السؤال غير المعطِّل: الطلب يطلق النافذة ويعود فورا — لا منتظر
      // يمسك مقعد خادم (ستة عشر منتظراً كانوا يعطلون المدرج دقيقة
      // كاملة)، والنافذة تبقى محجوزة حتى الجواب أو أقصى عمرها.
      // السقف هنا وحده — بعد المنحة والمرفوض المحفوظ كي لا يحجبهما
      // مهاجم يشغل النوافذ الثلاث (كان الفحص المبكر يحجبهما)
      if (_pendingAsks.length >= _maxPendingAsks) {
        return const IntakeRejection(
          403,
          'origin_pending',
          'Too many consent windows are open — answer or dismiss '
              'them, then retry',
        );
      }
      // ميزانية الأسئلة الجديدة زمنيا: سقف النوافذ الثلاث يقيد اللحظة
      // لا الزمن — تدوير النطاقات الفرعية يفتح أسئلة بلا نهاية. فوق
      // الميزانية يعود origin_pending بلا سؤال جديد حتى يفرغ كبارها
      final fireNow = _now;
      while (_askFireStamps.isNotEmpty &&
          fireNow - _askFireStamps.first > _askBudgetWindowMs) {
        _askFireStamps.removeFirst();
      }
      if (_askFireStamps.length >= _maxAskFiresPerWindow) {
        // بقايا نافذة الميزانية نفسها (عشر دقائق): أقدم سؤال يخرج منها
        // فتتفرغ خانة — الرأس يقول الانتظار الحقيقي لا ثابتاً مضللا
        final budgetWaitMs =
            _askBudgetWindowMs - (fireNow - _askFireStamps.first) + 500;
        return IntakeRejection(
          403,
          'origin_pending',
          'Too many consent questions lately — retry after a short wait',
          retryAfterMs: budgetWaitMs < 1000 ? 1000 : budgetWaitMs,
        );
      }
      _fireAsk(key, origin);
      return const IntakeRejection(
        403,
        'origin_pending',
        'Consent requested — retry shortly after the host answers '
            '(see Retry-After)',
      );
    }

    // (4) لا مدرج ولا «كل» — الرفض الصريح بلا صمت
    if (_policy.onUnknownOrigin != null) {
      return const IntakeRejection(
        403,
        'origin_unknown',
        'Origin is not listed and cannot be confirmed — '
            'no discovery callback is available for non-browser requests',
      );
    }
    return IntakeRejection(
      403,
      'origin_not_listed',
      'Origin $origin is not on the allowed list',
    );
  }

  /// Launch a question window or join the open one's queue - without waiting.
  /// The slot is deleted only on matching identity (an old awaiter never deletes
  /// a newer question), and the max timeout closes the silent window for others.
  void _fireAsk(String key, String origin) {
    if (_disposed || _pendingAsks.containsKey(key)) return;
    Future<OriginConsent> ask;
    try {
      ask = _policy.onUnknownOrigin!(origin);
    } catch (e) {
      // رد نداء يرمي متزامنا: نافذة منهارة كالحوار المنهار — لا 500،
      // والإطلاق نفسه يستهلك ميزانية الزمن: نداء معطوب لا يُستدعى بلا
      // نهاية فوق ميزانية الأسئلة السليمة
      _askFireStamps.addLast(_now);
      telemetry?.error(
        'consent callback threw synchronously',
        error: e,
        category: BridgeCategory.security,
      );
      return;
    }
    final generation = _policyGeneration;
    _pendingAsks[key] = ask;
    // ختم الإطلاق هنا وحده: الالتحاق بنافذة حية أو رد نداء رامٍ لا
    // يستهلك ميزانية الزمن — السؤال الجديد فقط هو المحسوب
    _askFireStamps.addLast(_now);
    ask
        .then((answer) {
          _removeAskIfIdentical(key, ask);
          // بعد dispose لا يغيّر جواب شيئا — الكائن خامل
          if (_disposed) return;
          // جواب تحت سياسة سابقة لا يطبق على اللاحقة
          if (generation != _policyGeneration) return;
          // سؤال أُغلق بلا قرار: لا ذاكرة ولا منحة — الأصل يُسأل
          // مرة أخرى عند طلبه التالي (المضيف أزاحه أو ماتت نافذته)
          if (answer == OriginConsent.dismissed) return;
          if (answer == OriginConsent.allowOnce) {
            // الكنس عند الإدراج: المنتهية (نافذتها 30ث) تُطرد فلا ينمو
            // المخطط بلا حد في الجلسات الطويلة — سقف ميسور فوق الواقعي
            if (_onceGrants.length >= _maxOnceGrants) {
              _onceGrants.removeWhere((_, expiry) => _now > expiry);
            }
            _onceGrants[key] = _now + _onceGrantWindowMs;
          } else {
            _rememberConsent(key, answer);
          }
        })
        .catchError((Object _) {
          // حوار المضيف انهار: النافذة تنقضي بلا أثر
          _removeAskIfIdentical(key, ask);
        });
    _askTimers.add(
      Timer(_policy.askTimeout, () {
        _askTimers.removeWhere((t) => !t.isActive);
        _removeAskIfIdentical(key, ask);
      }),
    );
  }

  void _removeAskIfIdentical(String key, Future<OriginConsent> ask) {
    if (identical(_pendingAsks[key], ask)) _pendingAsks.remove(key);
  }

  /// The fixed origin and send-method checks - the discovery path shares them before asking the user.
  IntakeRejection? _browserRequestBlocked(
    String? origin,
    String? fetchMode,
    String? fetchDest,
  ) {
    // أصل صالح — الطلب غير المتصفحي يستعمل طبقة التوكن
    if (origin == null || origin.isEmpty || origin == 'null') {
      return const IntakeRejection(
        403,
        'origin_blocked',
        'A valid HTTPS Origin header is required '
            'in allow-all mode',
      );
    }
    final uri = Uri.tryParse(origin);
    final isHttps = uri != null && uri.scheme == 'https';
    final isLocalHttp =
        _policy.allowLocalHttp &&
        uri != null &&
        uri.scheme == 'http' &&
        (uri.host == 'localhost' ||
            uri.host == '127.0.0.1' ||
            uri.host == '::1');
    if (!isHttps && !isLocalHttp) {
      return const IntakeRejection(
        403,
        'origin_blocked',
        'Only HTTPS origins are accepted in allow-all mode '
            '(non-browser integrations should use the token layer)',
      );
    }
    // طريقة الإرسال — النموذج المخفي وbeacon وno-cors أغلقتها
    // المتصفحات عن القراءة لكن إرسالها يصل؛ غياب الترويسة يمر
    // (متصفح قديم أو عميل غير متصفح — هؤلاء على التوكن أصلا)،
    // إلا حين يطلب المضيف الترويسات صراحة فيغلق باب المتصفحات
    // القديمة على المسارين المتصفحيين
    if (_policy.requireFetchMetadata) {
      if (fetchMode == null || fetchMode.isEmpty || fetchMode != 'cors') {
        return const IntakeRejection(
          403,
          'cross_site_blocked',
          'Cross-site request blocked: Sec-Fetch-Mode must be "cors"',
        );
      }
      if (fetchDest == null || fetchDest.isEmpty || fetchDest != 'empty') {
        return const IntakeRejection(
          403,
          'cross_site_blocked',
          'Cross-site request blocked: Sec-Fetch-Dest must be "empty"',
        );
      }
      return null;
    }
    if (fetchMode != null && fetchMode.isNotEmpty && fetchMode != 'cors') {
      return const IntakeRejection(
        403,
        'cross_site_blocked',
        'Cross-site request blocked: Sec-Fetch-Mode must be "cors"',
      );
    }
    if (fetchDest != null && fetchDest.isNotEmpty && fetchDest != 'empty') {
      return const IntakeRejection(
        403,
        'cross_site_blocked',
        'Cross-site request blocked: Sec-Fetch-Dest must be "empty"',
      );
    }
    return null;
  }

  /// Per-origin quota - a queue trimmed from the front (each stamp removed
  /// once, and the push happens before the compare so the request itself counts).
  IntakeRejection? _originQuotaVerdict(String? origin, [int? limitOverride]) {
    if (origin == null) return null;
    final key = normalize(origin);
    final now = _now;
    var window = _originWindows[key];
    if (window == null) {
      window = Queue<int>();
      _originWindows[key] = window;
      _windowOrder.addLast(key);
    }
    while (window.isNotEmpty && now - window.first > _windowMs) {
      window.removeFirst();
    }
    window.addLast(now);
    // إخلاء نوافذ الخاملين عند تجاوز السقف — دورة واحدة كأقصى، وبمعدل
    // مرة في الثانية حصرا: حين يكون الأحياء فوق السقف لا يلف كل طلب
    // الطابور كاملا (نطاقات فرعية كافية لذلك)
    if (_originWindows.length > _maxOriginWindows &&
        now >= _nextWindowSweepMs) {
      _nextWindowSweepMs = now + 1000;
      var attempts = _windowOrder.length;
      while (_originWindows.length > _maxOriginWindows && attempts-- > 0) {
        final oldest = _windowOrder.removeFirst();
        final ts = _originWindows[oldest];
        if (ts == null) continue;
        final idle = ts.isEmpty || now - ts.last > _windowMs;
        if (idle) {
          _originWindows.remove(oldest);
        } else {
          _windowOrder.addLast(oldest);
        }
      }
    }
    if (window.length > (limitOverride ?? _policy.perOriginPerMinute)) {
      // بقايا نافذة الحصة: أقدم طلب يخرج منها فتفرغ خانة للتابع
      final quotaWaitMs = window.isEmpty
          ? _windowMs
          : _windowMs - (now - window.first) + 500;
      return IntakeRejection(
        429,
        'origin_rate_limited',
        'Rate limit exceeded for this origin — retry after a short wait',
        retryAfterMs: quotaWaitMs < 1000 ? 1000 : quotaWaitMs,
      );
    }
    return null;
  }

  /// CORS echo for the allowed only: the listed (including the always-approved)
  /// or a valid https origin on the allow-all path - anyone else gets no ACAO
  /// header at all, so the browser blocks reading the reply: echoing to everyone
  /// equaled '*' and would open token guessing from any page.
  bool echoesCorsFor(String? origin) {
    if (origin == null || origin.isEmpty) return false;
    if (_isListed(origin)) return true;
    // أصل الاكتشاف الصالح: الصدى ضروري له — بدونه يمنع المتصفح
    // الpreflight فلا يصل السؤال أبدا (ترويسات ما قبل الفحص كانت
    // تغلق مسار الموافقة نفسه) — والمرفوض لا يرى
    if (_policy.onUnknownOrigin != null &&
        _validBrowserOrigin(origin) &&
        _consents[normalize(origin)] != OriginConsent.reject) {
      return true;
    }
    if (!_policy.allowAllHardened) return false;
    final uri = Uri.tryParse(origin);
    if (uri == null || uri.host.isEmpty) return false;
    if (uri.scheme == 'https') return true;
    final host = uri.host.toLowerCase();
    return _policy.allowLocalHttp &&
        uri.scheme == 'http' &&
        (host == 'localhost' || host == '127.0.0.1' || host == '::1');
  }

  /// Detailed host messages for the trusted only - a correct token or a listed
  /// origin; the allow-all path sees the code without the host text.
  bool verboseErrorsFor(String? origin, String? portalToken) {
    if (_token.isNotEmpty &&
        portalToken != null &&
        portalToken.isNotEmpty &&
        _fixedTimeEquals(portalToken, _token)) {
      return true;
    }
    return _isListed(origin);
  }

  /// A rejection from outside the protection patterns (host authorities) goes
  /// through the same counter and log path - denial is never silent.
  void noteRejection(String reason, [String? origin]) {
    _countRejection();
    logRejection(reason, origin);
  }

  void logRejection(String? reason, String? origin) {
    // عدم الصمت مع كبح الطوفان: سطر واحد في الثانية كحد أقصى بنمط خنق
    // معرف الارتباط — كل رفض يعدّ عدّا (فوق) والسطر يخرج بما كُتم بعده
    final now = _now;
    if (now < _nextRejectionLogMs) {
      _suppressedRejections++;
      return;
    }
    final suffix = _suppressedRejections > 0
        ? ' (+$_suppressedRejections suppressed)'
        : '';
    _suppressedRejections = 0;
    _nextRejectionLogMs = now + _rejectionLogPacingMs;
    telemetry?.warn(
      'intake rejected a request (protection active): ${reason ?? ''} '
      '— origin=${origin ?? 'none'}$suffix',
      category: BridgeCategory.security,
    );
  }

  /// Rejection-log throttling: at most one line per second — a flood lives
  /// in the counter, not in the log.
  static const _rejectionLogPacingMs = 1000;
  int _nextRejectionLogMs = 0;
  int _suppressedRejections = 0;

  /// Release transient resources - cancels the window timers so command-line
  /// tools are not held until the longest timeout expires. Call it when done.
  void dispose() {
    _disposed = true;
    for (final t in _askTimers) {
      t.cancel();
    }
    _askTimers.clear();
    _pendingAsks.clear();
  }

  /// Constant-time comparison - no timing leak of length or first-diff position.
  ///
  /// Checking length before the loop leaked the token length early: a reject
  /// at a different length returned faster than a matching one, handing the
  /// attacker a length ordering that spares full guessing. The iteration count
  /// here is fixed for any input (the minimum pad or the longer side's length,
  /// whichever is greater) and the length itself folds into the accumulator
  /// like any positional difference - reject time never depends on input content.
  /// All bytes compare: a difference past the minimum pad is caught, and different tokens never collide.
  static const _tokenComparePad =
      256; // حشوة الدنيا — الحلقة تمتد لطول أطول الطرفين إن زاد

  bool _fixedTimeEquals(String a, String b) {
    final ab = utf8.encode(a);
    final bb = utf8.encode(b);
    var diff = ab.length ^ bb.length;
    // الحلقة تغطي أطول الطرفين كاملا: القصر على الحشوة وحدها كان يسمح
    // بمرور توكن صحيح-البادئة فقط (سر قصير بعد بادئة طويلة يمر) — والفرق
    // في الطول يدخل المقارنة من البداية فيغلق الطريق الثالث
    final pad = _tokenComparePad > ab.length ? _tokenComparePad : ab.length;
    for (var i = 0; i < pad; i++) {
      diff |= (i < ab.length ? ab[i] : 0) ^ (i < bb.length ? bb[i] : 0);
    }
    return diff == 0;
  }
}

/// Strong portal-token generator - 32 random bytes from Random.secure in hex
/// (64 chars): no dependencies, and it meets the recommended strength bar.
String generatePortalToken() {
  final rnd = Random.secure();
  return List.generate(
    32,
    (_) => rnd.nextInt(256),
  ).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
