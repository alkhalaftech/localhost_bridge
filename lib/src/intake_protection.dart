import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:math';

import 'bridge_telemetry.dart';

/// The host's answer to an unknown-origin question. [allowAlways] and
/// [reject] are remembered for the session, [allowOnce] grants a single
/// retry inside a 30-second window, and [dismissed] closes the question
/// without a decision: nothing is remembered and the origin is asked
/// again on its next request (use it when the question was displaced, its
/// window expired, or the session ended before the user answered).
enum OriginConsent { allowAlways, allowOnce, reject, dismissed }

/// Origin policy - the single concept left after the open mode was merged in:
/// the list rules; allow-all is its widest value with the hardening attached; discovery grows it. Closed by default (an empty list denies all).
class OriginPolicy {
  /// Builds the policy - every field is optional and defaults to the
  /// closed shape: an empty `allowed` list with no allow-all and no
  /// discovery callback, a per-origin quota of 30 requests/minute on the
  /// allow-all path only, listed origins unquotaed, Fetch Metadata
  /// required, and a 60-second consent-question timeout.
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

  /// Timeout of a single discovery question - a window left unanswered is
  /// closed after this long, freeing its place among the 3 open-question
  /// slots (injectable for tests).
  final Duration askTimeout;
}

/// The intake rejection - the code is the developer contract, the message neutral English.
class IntakeRejection {
  /// Builds the rejection: [status] is the HTTP status on the wire, [code]
  /// the developer-facing `error` field, [message] its `message` field,
  /// and [retryAfterMs] the honest wait this rejection carries (null keeps
  /// the caller's own default).
  const IntakeRejection(
    this.status,
    this.code,
    this.message, {
    this.retryAfterMs,
  });

  /// 403 for denial, 429 for the origin quota.
  final int status;

  /// The stable developer contract for the rejection - one of the codes
  /// this class produces (`origin_not_listed`, `origin_pending`,
  /// `origin_declined`, `origin_unknown`, `origin_rate_limited`,
  /// `token_locked`, `cross_site_blocked`, `origin_blocked`,
  /// `protection_disposed`). The message text may change; the code does
  /// not.
  final String code;

  /// The package's constant neutral English sentence for the rejection -
  /// safe to show a developer, carrying no host details.
  final String message;

  /// The honest wait for THIS rejection in milliseconds - the remainder of
  /// the window that caused it (token lockout, per-origin quota, or the
  /// new-question budget). The server emits it as the Retry-After header
  /// (seconds, rounded up); null keeps the caller's own default.
  final int? retryAfterMs;
}

/// Optional protection for the local command intake - host-configured.
///
/// The default risk (the allow-all value): a 127.0.0.1 intake accepting POST
/// from any page the user visits - the browser sends the request even when
/// CORS blocks reading the reply, so any site could fire its command at once.
/// - The allowlist: only pages from a host-defined origin list are accepted
/// (the Origin header is enforced by the browser and cannot be forged by
/// JavaScript - the right barrier against cross-site pages; it is no wall
/// against programs on the same machine, which SECURITY.md documents as a
/// stated residual).
/// - Discovery (onUnknownOrigin): a new origin is put to the host exactly
/// once - always allow, allow once, or deny - so the list grows on
/// knowledge, not guessing.
/// - The token layer: an X-Portal-Token header matching a shared secret - an
/// integrated client proves itself with it and crosses without browser
/// headers (server-side integrations, or when origins multiply).
///
/// The remembered state is bounded: discovery decisions kept for the
/// session are capped at 1,000 (oldest evicted), one-time grants at 64,
/// consent questions open at once at 3, and new questions at 10 per
/// 10 minutes.
class IntakeProtection {
  /// [nowMs] is an injectable test clock (lock, grant, and quota windows);
  /// the default is an internal monotonic clock owned by the object.
  IntakeProtection({this.telemetry, int Function()? nowMs}) : _nowMs = nowMs {
    if (nowMs == null) _clock.start();
  }

  /// Injected test time - or null to use [_clock].
  final int Function()? _nowMs;

  int get _now => _nowMs?.call() ?? _clock.elapsedMilliseconds;

  /// Security log seam: the host adapts its own logger - default mutes,
  /// never drops behavior.
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

  /// Per-origin question sequence - bumped on every new question fired for
  /// that origin. An answer applies only while its number is still the
  /// latest for the origin, so an expired window's late reply cannot
  /// override a newer question's decision; a late reply with no newer
  /// question keeps its number and is still the last word - unless the cap
  /// evicted that number as the oldest key with no live question, in which
  /// case the late reply is ignored and the origin is asked anew on its
  /// next request. The applied number is deleted, the map's own insertion
  /// order is the queue (a new key at the [_maxConsents] cap evicts the
  /// oldest key with no live question), and dispose clears it.
  final Map<String, int> _askSequence = <String, int>{};

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
  /// window for originless requests (local integrations), and idle windows
  /// swept once a second exactly like the origin quota windows below.
  final Map<String, Queue<int>> _tokenMissWindows = <String, Queue<int>>{};
  final Queue<String> _tokenMissOrder = ListQueue<String>();
  int _nextTokenSweepMs = 0;
  static const _tokenLockThreshold = 5;
  static const _tokenLockWindowMs = 60_000;

  /// The length floor a configured portal token must meet (UTF-8 bytes):
  /// update() refuses anything shorter - see the guard there.
  static const _minTokenBytes = 32;
  final Queue<int> _anonTokenMisses = Queue<int>();

  /// Origin quota windows: stamps trimmed from the front of a queue, and the
  /// map itself cleared of its idle entries oldest-insertion-first in one
  /// pass, once a second at most (the same pattern as ArrivalGuard).
  final Map<String, Queue<int>> _originWindows = <String, Queue<int>>{};
  final Queue<String> _windowOrder = ListQueue<String>();
  final Stopwatch _clock = Stopwatch()..start();

  static const _windowMs = 60_000;
  int _nextWindowSweepMs = 0;

  /// Hard cap on each per-origin window map (the token-miss map and the
  /// quota map alike): the idle sweeps alone cannot bound them - a local
  /// sender rotating unique origins creates entries faster than their
  /// windows expire, so the maps track the rotation rate and the memory
  /// with it, past what a mobile host process survives. Crossing the cap
  /// evicts the oldest-inserted entry through the same order queue each
  /// sweep drives; the in-flight request's own key is never an eviction
  /// candidate, so the stamp the request is about to record always lands
  /// in a live window and the token lockout still forms under the flood.
  static const _maxOriginWindows = 10000;

  /// The policy currently in force - replaced live by [update] and
  /// [updateFromSaved]. Read it to mirror settings UI state; admission
  /// decisions keep reading this same live object per request.
  OriginPolicy get policy => _policy;

  /// Every rejection counted so far - origin and token policy decisions
  /// and host-authority rejects alike ([noteRejection] counts too).
  /// The wire behavior never reads it; [onRejected] refreshes it live in
  /// a UI.
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
  /// A call that changes the origin decisions starts a fresh policy
  /// generation, so a pending consent answer never applies under the policy
  /// it was asked under; a token-only call or one re-applying the same
  /// decisions keeps the generation and pending answers stay alive.
  /// Applying a changed origin policy revokes remembered grants and
  /// once-grants; remembered denials live for the session, and a token-only
  /// or empty call touches no origin decision (persisting decisions across
  /// sessions is the host's business).
  ///
  /// Throws [ArgumentError] for a configured token below the length floor
  /// of 32 UTF-8 bytes BEFORE anything is applied, so a host that catches
  /// the error keeps its previous protection state untouched.
  /// The error names the offending length, never the token itself.
  /// The policy's numbers are validated the same way and at the same point:
  /// a negative quota and a non-positive ask timeout are configuration
  /// mistakes that must surface at setup, never as mystery rejects or
  /// instantly-closed questions on the wire.
  void update({OriginPolicy? policy, String? token}) {
    // الحقل المفقود يبقى على حاله: تحديثُ حقلٍ واحدٍ لا يطفئ الطبقة
    // الأخرى — ضبط التوكن وحده لا يمس القائمة، والعكس
    final effectivePolicy = policy ?? _policy;
    final effectiveToken = token ?? _token;
    _validatePolicyNumbers(effectivePolicy);
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
    // حارس طول التوكن: المقارنة الزمنية-الثابتة تغطي السر المضبوط
    // كاملاً في _fixedTimeEquals (الحلقة تمتد على الحشوة الدنيا وطول
    // السر المضبوط وحده — زيادة توكن المرسل تُطوى في المُراكِم) — هنا
    // تحذير وتدقيق فقط بلا أي تغيير لنتيجة المطابقة (صفر سلك).
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

  /// Rejects non-positive quota values and a non-positive ask timeout at
  /// update() time, before anything is applied. Each corrupt value would
  /// otherwise fail every request in its own silent way: a negative
  /// per-origin quota is above every window length (the request itself
  /// counts first), so it answers 429 to every request, and a zero ask
  /// timeout closes every consent question before any answer can arrive.
  /// Zero [OriginPolicy.listedPerOriginPerMinute] stays legal - it is the
  /// documented "listed origins are unquotaed" default.
  void _validatePolicyNumbers(OriginPolicy policy) {
    if (policy.perOriginPerMinute <= 0) {
      throw ArgumentError.value(
        policy.perOriginPerMinute,
        'policy.perOriginPerMinute',
        'must be positive - a value below one rejects every request',
      );
    }
    if (policy.listedPerOriginPerMinute < 0) {
      throw ArgumentError.value(
        policy.listedPerOriginPerMinute,
        'policy.listedPerOriginPerMinute',
        'must not be negative - 0 keeps listed origins unquotaed',
      );
    }
    if (policy.askTimeout <= Duration.zero) {
      throw ArgumentError.value(
        policy.askTimeout,
        'policy.askTimeout',
        'must be positive - a value at or below zero closes every consent '
            'question instantly',
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
    _policy = policy;
    _allowed = _normalizeAllowed(policy.allowed);
    _token = token.trim();
    if (!originDecisionsChanged) return;
    // الجيل يزاد هنا وحده حين تتغير قرارات الأصل فعلاً: جواب نافذة
    // قرارٌ على الأصل، والتحديث الذي لا يغير القرارات (التوكن وحده
    // أو السياسة ذاتها) لا يهدم أجوبة نوافذ حية. وupdateFromSaved
    // يمر من هنا بحكم تغييره القرارات (الإقلاع يبدل السياسة) فيبقى
    // حارس الجيل قائماً على مساره
    _policyGeneration++;
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
      .map((o) => _stripTrailingSlashes(o.trim().toLowerCase()))
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
  /// counter - capability is never widened silently. [savedMode] is a closed
  /// list no matter what the host passes: any value outside {null,
  /// 'allowlist', 'token'} lands on the closed default, never on a wider
  /// mode read back out of storage.
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

  /// A static compiled pattern: the hot paths use it directly.
  static final RegExp _bareOrigin = RegExp(r'^[a-z]+://[^/]+$');

  /// Strips every trailing '/' in one backward scan. The regex sweep this
  /// replaces matched `/+$` from every start position, so a long run of
  /// slashes that does NOT reach the end (one trailing non-slash character)
  /// squared the work on the run's length - and the raw Origin reached that
  /// sweep before any admission decision. The output is identical for every
  /// input: the final run of slashes is removed, nothing else is.
  static String _stripTrailingSlashes(String s) {
    var end = s.length;
    while (end > 0 && s.codeUnitAt(end - 1) == 0x2F) {
      end--;
    }
    return end == s.length ? s : s.substring(0, end);
  }

  /// The one Origin wire shape this intake accepts: `scheme://host[:port]`,
  /// plus the trailing slashes [normalize] strips. Userinfo (`@`), a path,
  /// a query, a fragment, and any space or control character fail the
  /// check: browsers never send those forms, so only a hand-crafted value
  /// carries them, and it must not become a map key, a consent question,
  /// or a telemetry context. The check is not an acceptance decision - the
  /// scheme policy and the list still decide after it. Used by this
  /// package's server, not a stable host-facing interface.
  static bool isWellFormedOrigin(String origin) {
    final stripped = _stripTrailingSlashes(origin);
    // محرف تحكم لا يصير أصلاً مهما وقع في الشكل — الفحص على مدى
    // المحارف المضبوطة نفسه الذي يعقم السجل
    for (final rune in stripped.runes) {
      if (_isControlChar(rune)) return false;
    }
    return _originShape.hasMatch(stripped);
  }

  /// `scheme://host[:port]` in one match: a letter-led scheme, then either
  /// a bracketed IP-literal host or a plain host that cannot carry the
  /// grammar the shape refuses (no `@`, `/`, `?`, `#`, no `:` outside
  /// brackets, no whitespace), then an optional numeric port. Trailing
  /// slashes are stripped by the caller, not matched here.
  static final RegExp _originShape = RegExp(
    r'^[A-Za-z][A-Za-z0-9+.\-]*://'
    r'(?:\[[0-9A-Fa-f:.]+\]|[^\[\]:/?#@\s][^\[\]:/?#@\s]*)'
    r'(?::\d+)?$',
  );

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
    // يعيد ثغرة الشبكة العامة — والمدخل الكامل يحمل مخططه
    // فمطابقته واعية للمخطط أصلا
    final schemeOk =
        uri.scheme == 'https' ||
        (_policy.allowLocalHttp &&
            uri.scheme == 'http' &&
            (host == 'localhost' || host == '127.0.0.1' || host == '::1'));
    final normalized = normalize(origin);
    for (final entry in _allowed) {
      if (entry == normalized) return true;
      // المدخل «*.» بلا جذر يطابق أي مضيف
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

  /// Lower-cases an Origin value and strips trailing slashes - the canonical
  /// key for every per-origin window in this object. Used by this package's
  /// server, not a stable host-facing interface.
  static String normalize(String origin) =>
      _stripTrailingSlashes(origin.toLowerCase());

  /// A valid browser origin - the basis for the discovery question (asking
  /// about sandbox/null or http origins is meaningless).
  bool _validBrowserOrigin(String origin) {
    final uri = Uri.tryParse(origin);
    return uri != null && uri.scheme == 'https' && uri.host.isNotEmpty;
  }

  /// Accept the request - null means allowed; [IntakeRejection] carries status,
  /// code, and message. Order: the token layer passes on its own, then the list,
  /// then allow-all with its hardening, then discovery or an explicit reject.
  /// Used by this package's server, not a stable host-facing interface.
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
    // 429 حتى بتوكن صحيح — فلا مقارنة صحيحة تسقط حاجز القفل عن التخمين
    // — والصحيح من نافذة غير مقفولة يصفرها ويعبر فورا.
    if (_token.isNotEmpty && portalToken != null && portalToken.isNotEmpty) {
      final now = _now;
      final window = _tokenMissWindow(origin, now);
      if (window.length >= _tokenLockThreshold) {
        // القفل يمنع المقارنة وحدها: التوكن يُعامل كأنه غائب وتُقيَّم
        // سياسة الأصول — البوابة المدرجة تعبر رغم إخفاقات مهاجم مجهول،
        // ومن ترفضه السياسة أصلًا يُرَدّ 429 (لا 403: كان يحاول التخمين).
        // والسؤال الجديد لا يُفتح من وراء القفل: mayAskConsent=false
        // يمنع فروع الاكتشاف من إطلاق نافذة موافقة لطلب مقفل
        final verdict = await _checkBeyondToken(
          origin,
          fetchMode,
          fetchDest,
          mayAskConsent: false,
        );
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
  /// per-origin map is swept by idle entries at the same pacing as the
  /// quota windows (one pass at most, once a second at most).
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
      // السقف الصلب للخريطة: إدراج فوق السقف يطرد الأقدم إدراجاً بطابور
      // الترتيب نفسه الذي يقوده الكنس. مفتاح الطلب الجاري ليس مرشحاً
      // للطرد: هو آخر الطابور حديثاً وأولُه الأقدم، والحارس يوقف الطرد
      // عنده إن تناقض الترتيب — فطابع هذا الطلب لا يتيم في طابور
      // منفصل عن الخريطة وقفل التوكن يبقى يتكون تحت الفيضان
      while (_tokenMissWindows.length > _maxOriginWindows &&
          _tokenMissOrder.isNotEmpty) {
        final oldest = _tokenMissOrder.first;
        if (oldest == key) break;
        _tokenMissOrder.removeFirst();
        _tokenMissWindows.remove(oldest);
      }
    }
    while (window.isNotEmpty && now - window.first > _tokenLockWindowMs) {
      window.removeFirst();
    }
    // الكنس الدوري للخاملين: مرة كل ثانية كأقصى — نافذة انقضت لا تبقى
    // مقيدة. مفتاح الطلب الجاري محصَّن: الطابور يُمسك من هنا وحتى
    // إضافة الطابع في check (مقطع مزامن بلا انتظار) فإخلاؤه الآن يتيم
    // الطابع القادم ويكسر تكوين القفل ذاته
    if (_tokenMissWindows.isNotEmpty && now >= _nextTokenSweepMs) {
      _nextTokenSweepMs = now + 1000;
      var attempts = _tokenMissOrder.length;
      while (attempts-- > 0) {
        final oldest = _tokenMissOrder.removeFirst();
        final ts = _tokenMissWindows[oldest];
        final idle =
            oldest != key &&
            (ts == null || ts.isEmpty || now - ts.last > _tokenLockWindowMs);
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
  ///
  /// [mayAskConsent] is false behind the token lockout: a locked request
  /// whose origin the policy does not accept is refused without opening a
  /// new consent question - the caller answers `429 token_locked` for it.
  Future<IntakeRejection?> _checkBeyondToken(
    String? origin,
    String? fetchMode,
    String? fetchDest, {
    bool mayAskConsent = true,
  }) async {
    // (1) القائمة — المدرج يعبر (ومنه من حُفظ سماحه الدائم بالاكتشاف)،
    // ومع حصة اختيارية إن فعّلها المضيف: المدرج المخترق وحده من
    // يملأ المقاعد بلا حد، فالحصة هنا تحصر ضرره بنافذته ولا تمس
    // بقية المدرجين
    if (_isListed(origin)) {
      // ترويستا الإرسال الحاضرتان بقيمة مخالفة نموذج مخفي أو إرسال
      // no-cors بلا شك — تُرفضان هنا كالمسارين المتصفحيين
      // (نموذج text/plain يمر بوابة الأنواع المسموحة فيغلقه هذا
      // الفحص). غيابهما يبقى ممراً هنا: العملاء غير المتصفحات المدرجة
      // لا يرسلونهما
      final mismatched = _fetchMetadataMismatch(fetchMode, fetchDest);
      if (mismatched != null) return mismatched;
      final listedQuota = _policy.listedPerOriginPerMinute;
      if (listedQuota > 0) {
        final quota = _originQuotaVerdict(origin, listedQuota);
        if (quota != null) {
          // وضع المراقبة يحرس الحصتين معاً — حصة المدرج حصة كحصة
          // «الكل»: تُسجل كان-سيرفض ويُخدم الطلب
          if (!_policy.reportOnly) return quota;
          telemetry?.warn(
            'intake report-only: would reject — ${quota.code}: '
            '${quota.message} (origin=${originForLog(origin) ?? 'none'})',
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
          '${quota.message} (origin=${originForLog(origin) ?? 'none'})',
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
      // تمرير دفعي لكل المنتظرين (الجواب الواحد لا يجيز غير الطلب
      // الذي استهلكها)
      final grant = _onceGrants[key];
      if (grant != null) {
        _onceGrants.remove(key);
        if (_now <= grant) return null;
      }
      // السؤال غير المعطِّل: الطلب يطلق النافذة ويعود فورا — لا منتظر
      // يمسك مقعد خادم (المقاعد الستة عشر ميزانية العمل الحي كلها:
      // من يمسك مقعداً بلا عمل يعطل المدرج إلى المهلة الكلية)،
      // والنافذة تبقى محجوزة حتى الجواب أو أقصى عمرها.
      // السقف هنا وحده — بعد المنحة والمرفوض المحفوظ كي لا يحجبهما
      // مهاجم يشغل النوافذ الثلاث
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
      // الطلب المقفل لا يفتح سؤال موافقة جديداً: نوافذ الموافقة لا تُطلَق
      // من وراء قفل تخمين التوكن حتى لو كانت ميزانية الأسئلة تسمح —
      // رفضه هنا غير صفري فيحوله الاستدعاءُ المقفلُ إلى 429 token_locked
      if (!mayAskConsent) {
        return const IntakeRejection(
          403,
          'origin_pending',
          'The origin is locked; no new consent question opens for it',
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
    // الأصل قيمة يتحكم فيها الخصم: الرسالة ثابتة بلا استيفاء — القيمة
    // تجري في حقل origin= المعقم وحده (الخادم يمرر الرسالة سبباً إلى
    // noteRejection فأي قيمة خام هنا تُنسخ حرفياً إلى السجل)
    return const IntakeRejection(
      403,
      'origin_not_listed',
      'Origin is not on the allowed list',
    );
  }

  /// Launch a question window or join the open one's queue - without waiting.
  /// The slot is deleted only on matching identity (an old awaiter never deletes
  /// a newer question), and the max timeout closes the silent window for others.
  /// The host callback receives the normalized origin (lowercase scheme and
  /// host, the port if present) - never the raw header value: the window must
  /// read the same canonical form the keys and the list matching use.
  void _fireAsk(String key, String origin) {
    if (_disposed || _pendingAsks.containsKey(key)) return;
    Future<OriginConsent> ask;
    try {
      // النافذة ترى الأصل المطبَّع حصراً — القيمة الخام يتحكم فيها
      // الخصم ولا تصل قرار المضيف، والمفتاح مطبَّع أصلاً فيعود الجواب
      // على الشكل نفسه الذي خُزِّن به
      ask = _policy.onUnknownOrigin!(normalize(origin));
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
    // رقم السؤال للأصل يزيد عند كل إطلاق فعلي (الالتحاق بنافذة حية لا
    // يطلق شيئاً فلا يزيد): جواب نافذة انتهت ثم أُزيلت بسؤال أحدث للأصل
    // نفسه لا يطبق فوق قرار الأحدث، والمتأخر بلا سؤال أحدث يبقى رقمه
    // باقياً فيطبق. الخريطة نفسها هي الطابور (LinkedHashMap يحفظ ترتيب
    // الإدراج: الإسناد لمفتاح موجود لا يحرك موضعه والجديد يلحق بالآخر)
    // وتفرغ عند dispose
    if (!_askSequence.containsKey(key) && _askSequence.length >= _maxConsents) {
      // عند بلوغ السقف يُطرد أقدم مفتاح بترتيب الإدراج ليس له سؤال حي
      // في _pendingAsks — رقمه إما طُبق فمحاً أو نافذته فاتت بلا جواب.
      // وإن لم يوجد (النظري محصور بعدد الأسئلة الحية) فلا طرد: النمو
      // يبقى محدوداً بعدد الحي وحده فوق السقف
      String? evict;
      for (final k in _askSequence.keys) {
        if (!_pendingAsks.containsKey(k)) {
          evict = k;
          break;
        }
      }
      if (evict != null) _askSequence.remove(evict);
    }
    final seq = (_askSequence[key] ?? 0) + 1;
    _askSequence[key] = seq;
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
          // جواب نافذة أزالها سؤال أحدث للأصل نفسه لا يطبق: رقمه لم يبق
          // الأخير — وتطبيق الجواب يمحو رقمه فلا يطبق مرتين
          if (_askSequence[key] != seq) return;
          _askSequence.remove(key);
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
    return _fetchMetadataMismatch(fetchMode, fetchDest);
  }

  /// The send-method mismatch alone: a present `Sec-Fetch-Mode` other than
  /// `cors`, or a present `Sec-Fetch-Dest` other than `empty`, is a hidden
  /// form or a no-cors send everywhere - the listed path included, where
  /// the check stands on its own. Absence is the caller's business: the
  /// browser paths reject it behind [OriginPolicy.requireFetchMetadata],
  /// and the listed path keeps accepting it (headerless non-browser
  /// clients listed by the host).
  IntakeRejection? _fetchMetadataMismatch(
    String? fetchMode,
    String? fetchDest,
  ) {
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
  /// once, and the push happens before the compare so the request itself
  /// counts). A rejected request's stamp is withdrawn right away, so
  /// rejections never occupy the window and the honest wait is measured
  /// from the oldest admitted request; watching passes through the same
  /// branch, so a would-reject leaves no stamp either.
  IntakeRejection? _originQuotaVerdict(String? origin, [int? limitOverride]) {
    if (origin == null) return null;
    final key = normalize(origin);
    final now = _now;
    var window = _originWindows[key];
    if (window == null) {
      window = Queue<int>();
      _originWindows[key] = window;
      _windowOrder.addLast(key);
      // السقف الصلب للخريطة بنمط خريطة التوكن أعلاه: إدراج فوق السقف
      // يطرد الأقدم إدراجاً بطابور الترتيب، ومفتاح الطلب الجاري ليس
      // مرشحاً للطرد أبداً. نافذة حية قد يخرجها فيضان التدوير — وهي
      // متخطَّف معلن لا جديد عليه: الأصل الذي يدوّر أصولاً فريدة
      // يتجاوز الحصة والقفل أصلاً، فما يخرجه الطرد هنا هو حساب حصة
      // أصل قديم لا يدير إلا الفيضان نفسه
      while (_originWindows.length > _maxOriginWindows &&
          _windowOrder.isNotEmpty) {
        final oldest = _windowOrder.first;
        if (oldest == key) break;
        _windowOrder.removeFirst();
        _originWindows.remove(oldest);
      }
    }
    while (window.isNotEmpty && now - window.first > _windowMs) {
      window.removeFirst();
    }
    window.addLast(now);
    // الكنس الدوري للخاملين: مرة كل ثانية كأقصى — نافذة انقضت لا تبقى
    // مقيدة. مفتاح الطلب الجاري محصَّن بالترتيب نفسه: ختمه أُضيف قبل
    // هذه الكتلة فآخر طوابعه طازج لا يعد خاملاً أبداً
    if (_originWindows.isNotEmpty && now >= _nextWindowSweepMs) {
      _nextWindowSweepMs = now + 1000;
      var attempts = _windowOrder.length;
      while (attempts-- > 0) {
        final oldest = _windowOrder.removeFirst();
        final ts = _originWindows[oldest];
        final idle = ts == null || ts.isEmpty || now - ts.last > _windowMs;
        if (idle) {
          _originWindows.remove(oldest);
        } else {
          _windowOrder.addLast(oldest);
        }
      }
    }
    if (window.length > (limitOverride ?? _policy.perOriginPerMinute)) {
      // الرفض لا يشغل الحصة: طابعه يُسحب فور الرفض فتبقى النافذة بطول
      // الحصة، وبقايا الانتظار تُحسب من أقدم طابع مقبول — العميل
      // الملتزم بـ Retry-After يُقبل بعد انتظاره بالضبط. الوضع المراقب
      // يمر من الفرع نفسه فكان-سيرفض لا يترك أثراً في النافذة، ونافذة
      // إخفاق التوكن لا تمس — هي عتبة قفل لا حصة
      window.removeLast();
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

  /// CORS echo for the allowed only: the listed (including the
  /// always-approved), a valid https origin on the allow-all path, and —
  /// with a consent callback configured — discovery origins: any valid
  /// browser origin not yet declined, whose preflight must be answered or
  /// the browser never sends the request the consent question needs.
  /// Anyone else gets no ACAO header at all, so the browser blocks reading
  /// the reply: echoing to everyone equaled '*' and would open token
  /// guessing from any page.
  /// Used by this package's server, not a stable host-facing interface.
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
  /// origin; the allow-all path sees the code without the host text. One
  /// verdict per request: while the token failure window (the origin's, or
  /// the shared originless one) is locked, the token counts as absent here
  /// too - this decision never compares a token whose window [check] is
  /// refusing on, so a locked origin cannot probe the token through the
  /// host error text.
  /// Used by this package's server, not a stable host-facing interface.
  bool verboseErrorsFor(String? origin, String? portalToken) {
    if (!_tokenWindowLocked(origin) &&
        _token.isNotEmpty &&
        portalToken != null &&
        portalToken.isNotEmpty &&
        _fixedTimeEquals(portalToken, _token)) {
      return true;
    }
    return _isListed(origin);
  }

  /// Whether the token-guessing lock for [origin]'s window - per origin, or
  /// the shared originless one - is engaged right now. Read-only on purpose:
  /// the admission path in [check] owns the state, so a verdict reader adds
  /// no stamps and creates no map entries; expired stamps simply do not count.
  bool _tokenWindowLocked(String? origin) {
    final now = _now;
    final Iterable<int> stamps;
    if (origin == null) {
      stamps = _anonTokenMisses;
    } else {
      final window = _tokenMissWindows[normalize(origin)];
      if (window == null) return false;
      stamps = window;
    }
    var live = 0;
    for (final ts in stamps) {
      if (now - ts <= _tokenLockWindowMs) live++;
    }
    return live >= _tokenLockThreshold;
  }

  /// A rejection from outside the protection patterns (host authorities) goes
  /// through the same counter and log path - denial is never silent.
  /// Used by this package's server, not a stable host-facing interface.
  void noteRejection(String reason, [String? origin]) {
    _countRejection();
    logRejection(reason, origin);
  }

  /// Writes one throttled security-log line for a rejection (the counter
  /// lives in [noteRejection]): at most one line per second, with the
  /// suppressed count folded into the next emitted line. Used by this
  /// package's server, not a stable host-facing interface.
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
      '— origin=${originForLog(origin) ?? 'none'}$suffix',
      category: BridgeCategory.security,
    );
  }

  /// The logged (and telemetry-context) form of an Origin header: control
  /// characters in the C0 and C1 ranges are stripped so a hostile value
  /// cannot forge extra log lines, and the result is capped so a bloated
  /// value cannot inflate every throttled line or measurement context.
  /// Logging-only: the counter and the admission decision still see the
  /// real value.
  static const _maxLoggedOriginChars = 200;

  /// C0 covers U+0000 to U+001F and C1 covers U+007F to U+009F - the
  /// ranges a hostile header value could use to forge extra log lines.
  static bool _isControlChar(int rune) =>
      rune <= 0x1F || rune == 0x7F || (rune >= 0x80 && rune <= 0x9F);

  /// The one sanitizing pass every Origin value takes on its way to
  /// telemetry: rejection log lines and the request measurement context
  /// alike carry this form, never the raw header. Used by this package's
  /// server, not a stable host-facing interface.
  static String? originForLog(String? origin) {
    if (origin == null) return null;
    final cleaned = String.fromCharCodes(
      origin.runes.where((r) => !_isControlChar(r)),
    );
    return cleaned.length > _maxLoggedOriginChars
        ? cleaned.substring(0, _maxLoggedOriginChars)
        : cleaned;
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
    _askSequence.clear();
  }

  /// Constant-time comparison - no timing leak of length or first-diff position.
  ///
  /// Checking length before the loop leaked the token length early: a reject
  /// at a different length returned faster than a matching one, handing the
  /// attacker a length ordering that spares full guessing. The iteration count
  /// here is fixed for any input: the minimum pad or the configured secret's
  /// length, whichever is greater - never the supplied value's length, so the
  /// loop never grows with what the caller sends (a token past the header
  /// length cap never reaches this at all). The length difference still folds
  /// into the accumulator like any positional difference - reject time never
  /// depends on input content - and supplied bytes beyond the loop land in the
  /// accumulator too, so a longer token with a correct prefix is still caught.
  /// All secret bytes compare: a difference inside the secret is caught, and
  /// different tokens never collide.
  static const _tokenComparePad =
      256; // حشوة الدنيا — الحلقة تمتد لطول السر المضبوط إن زاد

  bool _fixedTimeEquals(String supplied, String secret) {
    final ab = utf8.encode(supplied);
    final bb = utf8.encode(secret);
    var diff = ab.length ^ bb.length;
    // الحلقة على الحشوة الدنيا وطول السر المضبوط وحدهما — لا على طول
    // القيمة المرسلة: كلفة المقارنة لا تنمو بطول المرسل، وفرق الطول
    // يدخل المُراكِم من البداية فيرفض الزائد والناقص معاً، وبايتات
    // القيمة المرسلة فوق مدى الحلقة تسقط فيه هي أيضاً
    final pad = _tokenComparePad > bb.length ? _tokenComparePad : bb.length;
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
