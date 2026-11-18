import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:math';

import 'bridge_telemetry.dart';
import 'digest.dart';

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
    this.requireOriginWithToken = false,
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

  /// Require BOTH facts together on every qualified origin: an admitted
  /// origin AND a token bound to it. Off by default - the default keeps the
  /// token as an independent path and the origin paths open, wire-identical
  /// to previous releases. On, the mode closes the two one-legged doors:
  /// a qualified origin without a valid token answers `403 token_required`,
  /// and the token alone - correct or not, from an unqualified origin or
  /// with no Origin at all - never admits (the origin rejection answers it,
  /// never a token verdict, so a wrong-origin sender learns nothing about
  /// its token). The proof that satisfies the mode is the shared token
  /// (constant-time compared, as always) or a paired origin-bound token
  /// presented as an HMAC signature (the pairing layer). The preflight for
  /// the token header keeps its usual echo decision: a qualified origin's
  /// preflight is answered, so its page can read `token_required` and
  /// retry with the proof. With the mode on, headerless non-browser clients
  /// have no door at all - run them on a separate listener (or turn the
  /// mode off there), and pair browser pages through the pairing layer.
  final bool requireOriginWithToken;

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

/// The acceptance route one request took through the protection layers -
/// the recorded value in [IntakeAdmission.acceptedPath]. Six routes exist
/// and an accepted admission names exactly one: the host's list, a saved
/// always-allow consent from discovery, a consumed one-time grant, the
/// hardened allow-all path, a correct token alone, or a correct token over
/// a listed origin.
enum IntakeAdmissionPath {
  /// The origin matches the host's allowlist (full origin, bare host, or
  /// `*.domain` pattern).
  listed,

  /// Discovery answered `allowAlways` for this origin earlier and the
  /// decision is still remembered for the session.
  savedConsent,

  /// A discovery `allowOnce` grant was valid and this request consumed it.
  onceGrant,

  /// The hardened allow-all path with its origin and send-method hardening.
  allowAll,

  /// The token alone admitted the request: a correct token over an origin
  /// the policy does not qualify (or with no Origin at all).
  token,

  /// Both layers agreed: a correct token over a listed origin.
  originWithToken,

  /// The pairing proof agreed: a valid origin-bound HMAC signature over a
  /// qualified origin - the page proves possession of its paired token
  /// without ever sending it. Added at the enum's end; a host switch that
  /// must know every route reads this value explicitly.
  originWithPairedToken,
}

/// The one admission record for one request - the single projection of the
/// protection state that replaces the per-question probes. Built by
/// [IntakeProtection.admit]; every field is final and settled at build
/// time, so the caller reads the record and never probes the protection
/// object again for this request.
///
/// The projection is deliberately side-effect free: a caller that never
/// calls [settle] leaves no state behind - that is what keeps preflights,
/// shape-gate rejects, and busy rejects stamp-free. [settle] lands the
/// decision's state effects exactly where the old admission gate stood.
class IntakeAdmission {
  const IntakeAdmission._({
    required this.rejection,
    required this.acceptedPath,
    required this.echoesCors,
    required this.verboseErrors,
    required this.origin,
    required this.normalizedOrigin,
    required this.path,
    _AdmissionDecision? decision,
    IntakeProtection? owner,
  }) : _decision = decision,
       _owner = owner;

  /// The hand-built placeholder for a [TrustedCommand] constructed outside
  /// the intake (host tests): no rejection, no path, no decisions - and
  /// [settle] and [noteAuthorityReject] refuse it loudly.
  static const IntakeAdmission unrecorded = IntakeAdmission._(
    rejection: null,
    acceptedPath: null,
    echoesCors: false,
    verboseErrors: false,
    origin: null,
    normalizedOrigin: null,
    path: null,
  );

  /// The policy rejection when the request was refused - null when it was
  /// accepted. The status, code, and message are the wire contract the
  /// caller replies with.
  final IntakeRejection? rejection;

  /// The route that accepted the request - null when [rejection] is
  /// non-null.
  final IntakeAdmissionPath? acceptedPath;

  /// Whether the reply to this request may carry the CORS echo. For an
  /// accepted request this is the qualified-origin decision; for a
  /// rejection it folds the consent-question rule (always echo) and the
  /// wait-budget rule (echo when the origin qualifies) into one recorded
  /// value.
  final bool echoesCors;

  /// Whether the reply may carry host error text for this sender - a
  /// correct token (whose miss window is not locked) or a listed origin.
  final bool verboseErrors;

  /// The Origin request fact this admission was built from - the value the
  /// counter and the security log key this request by.
  final String? origin;

  /// [origin] lower-cased with trailing slashes stripped - the canonical
  /// key every per-origin window in the protection uses.
  final String? normalizedOrigin;

  /// The request path fact this admission was built from.
  final String? path;

  final _AdmissionDecision? _decision;
  final IntakeProtection? _owner;

  /// Lands this admission's state effects - the token miss stamp or miss
  /// window clear, the quota stamp (or its withdrawal on a rejection), the
  /// one-time grant consumption, the consent question, the report-only
  /// would-reject line, and the counted, throttled security line for a
  /// rejection. The server calls it exactly once, at the acceptance gate;
  /// a request answered from a pure read (preflight, shape-gate reject,
  /// busy reject) never settles, so it leaves no state behind - the same
  /// property the old gate position gave.
  ///
  /// Throws [StateError] on a hand-built [IntakeAdmission.unrecorded] or a
  /// second settle of the same record.
  void settle() {
    final owner = _owner;
    final decision = _decision;
    if (owner == null || decision == null) {
      throw StateError(
        'this admission was not built by IntakeProtection.admit - '
        'nothing to settle',
      );
    }
    if (decision.settled) {
      throw StateError(
        'this admission was already settled - one settle per request',
      );
    }
    decision.settled = true;
    owner._applyDecision(decision, origin);
    // طابع الإثبات الموثق يسجل هنا حصرا — الإسقاط الخالص قرأه لا كتبه
    final replayKey = decision.pairReplayKey;
    if (replayKey != null) {
      owner._recordPairReplay(replayKey, decision.stampMs);
    }
    final rejection = decision.rejection;
    if (rejection != null) {
      // العد والسطر الأمني هنا حصراً كما كانت noteRejection من الخادم في
      // موضع بوابة القبول — check القديمة لا تعد أبداً. وسبب فشل الإثبات
      // الداخلي يسمى في السطر المكبوح لا في الرد
      final detail = decision.pairFailure == null
          ? ''
          : ' (pairing proof: ${decision.pairFailure})';
      owner._noteAuthority(
        '${rejection.code}: ${rejection.message}$detail',
        origin,
      );
    }
  }

  /// Counts and logs a rejection decided outside the protection patterns -
  /// the host-authority rejects - through the same counter and throttled
  /// security line the protection's own rejections use: denial is never
  /// silent. Throws [StateError] on a hand-built
  /// [IntakeAdmission.unrecorded].
  void noteAuthorityReject(String reason) {
    final owner = _owner;
    if (owner == null || _decision == null) {
      throw StateError(
        'this admission was not built by IntakeProtection.admit - '
        'no counter behind it',
      );
    }
    owner._noteAuthority(reason, origin);
  }
}

/// The recorded decision one admission projection produced - the verdict
/// plus the deferred state effects [IntakeAdmission.settle] lands.
/// Internal to this library: the record exposes the fields, never the
/// effect bookkeeping.
class _AdmissionDecision {
  _AdmissionDecision({
    required this.rejection,
    required this.acceptedPath,
    required this.echoesCors,
    required this.verboseErrors,
    required this.stampMs,
    required this.key,
    this.tokenAttempt = false,
    this.tokenCompared = false,
    this.tokenMatched = false,
    this.tokenMissStamped = false,
    this.tokenBudgetSpent = false,
    this.quotaLimit = 0,
    this.grantExisted = false,
    this.reachedAskTrim = false,
    this.fireAsk = false,
    this.reportOnlyLine,
    this.pairReplayKey,
    this.pairFailure,
  });

  final IntakeRejection? rejection;
  final IntakeAdmissionPath? acceptedPath;
  final bool echoesCors;
  final bool verboseErrors;

  /// The projection's clock reading - every stamp settle lands carries it,
  /// so the effects match what the old inline gate wrote at this position.
  final int stampMs;

  /// The canonical origin key for the grant and the ask (empty when the
  /// request carried no origin).
  final String key;

  /// Whether the token block ran (a token was supplied and a secret is
  /// configured) - its window fetch owns the periodic sweep, exactly like
  /// the old gate.
  final bool tokenAttempt;

  /// Whether the token was compared - false when the header was absent,
  /// so an absent token is never compared; the comparison runs whatever
  /// the miss-window history.
  final bool tokenCompared;

  /// Whether the comparison matched - a match clears the miss window.
  final bool tokenMatched;

  /// Whether the wrong-token miss lands a stamp on settle - under the
  /// budget every miss counts; above it nothing stamps, so the window
  /// drains honestly and the announced wait stays true.
  final bool tokenMissStamped;

  /// Whether the request presented a wrong token above the spent budget -
  /// settle writes the muted budget line for it.
  final bool tokenBudgetSpent;

  /// The quota limit that governed the branch (0 = the branch ran no
  /// quota) - settle re-runs the same mutating quota call so the stamp, or
  /// its withdrawal on a would-reject, lands as before.
  final int quotaLimit;

  /// A one-time grant existed for the origin (valid or expired) - settle
  /// consumes it either way, like the old gate.
  final bool grantExisted;

  /// The discovery branch reached the ask-budget trim point - settle runs
  /// the real trim there.
  final bool reachedAskTrim;

  /// The consent question fires on settle.
  final bool fireAsk;

  /// The full report-only would-reject line - settle warns it verbatim.
  final String? reportOnlyLine;

  /// The replay-cache key a verified pairing proof records on settle -
  /// `(pairingId, stamp)`; null when no verified proof rode the request.
  final String? pairReplayKey;

  /// The internal reason a pairing proof failed (malformed, unknown id,
  /// expired, origin mismatch, signature) - it names the muted security
  /// line on settle and never travels the wire: the wire sees
  /// token_required alone for every invalid-proof shape.
  final String? pairFailure;

  /// One-shot guard: a record settles once.
  bool settled = false;
}

/// The after-the-token-layer projection - verdict plus the branch effect
/// flags, mirroring the acceptance order branch by branch.
class _BeyondOutcome {
  IntakeRejection? rejection;
  IntakeAdmissionPath? accepted;
  int quotaLimit = 0;
  bool grantExisted = false;
  bool reachedAskTrim = false;
  bool fireAsk = false;
  String? reportOnlyLine;
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
/// - The token layer: an X-Bridge-Token header matching a shared secret - an
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

  /// Token-guessing budget windows - per-origin for web requests (a
  /// guessing origin spends only its own budget), one shared window for
  /// originless requests (local integrations), and idle windows swept once
  /// a second exactly like the origin quota windows below.
  final Map<String, Queue<int>> _tokenMissWindows = <String, Queue<int>>{};
  final Queue<String> _tokenMissOrder = ListQueue<String>();
  int _nextTokenSweepMs = 0;

  /// The wrong-guess budget, in wrong token attempts per budget window:
  /// a sender that spends it - an origin its five attempts, or the shared
  /// originless window - gets `429 token_locked` for further wrong tokens
  /// until the window drains, while the correct token is compared and
  /// accepted whatever the failure history. The window is a signal about
  /// wrong guesses (a counter, a muted security line, a refusal for wrong
  /// guesses above the budget), never a refusal of the verified token.
  /// Internal constants with their unit written here - no public option.
  static const _tokenGuessBudget = 5;

  /// The budget window length in milliseconds - the unit of
  /// [_tokenGuessBudget] is wrong attempts per this window.
  static const _tokenBudgetWindowMs = 60_000;

  /// The length floor a configured bridge token must meet (UTF-8 bytes):
  /// update() refuses anything shorter - see the guard there.
  static const _minTokenBytes = 32;

  /// The character-diversity floor a configured token must meet: below it
  /// (fewer than 8 distinct characters — a repeated-character token is
  /// guessable at a glance) update() refuses at set time. The floor sits
  /// far below what a random 64-hex generator produces (the symbols are 16
  /// and 64 draws practically never fall below 15 distinct), so generated
  /// tokens never trip it. Internal constant - no public option. The check
  /// lives in update() alone: a legitimately saved state keeps loading at
  /// startup with a rotation warning (see updateFromSaved).
  static const _minTokenDistinctChars = 8;

  /// The `X-Bridge-Token` header length cap the intake enforces on the
  /// wire, in UTF-8 bytes: the same number the server's token-length gate
  /// refuses with `400 token_too_long` before any comparison. update()
  /// refuses a configured token over this ceiling with the same number,
  /// so a correct token that every request would reject at the gate can
  /// never sit configured silently - the constant-time comparison would
  /// never see it. One constant, both sides of the wire. The value is
  /// internal, the name public, so a host configuring tokens can read the
  /// ceiling it must stay under.
  static const maxBridgeTokenHeaderBytes = 1024;
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

  // ══ طبقة الاقتران — الحالة والسقوف مكتوبة في تقرير التصميم قبل الكود ══

  /// Cap on live pairing sessions (a session = one displayed code): a
  /// host shows one at a time; eight bounds the broadcast abuse and the
  /// memory with it. The ninth insert evicts the oldest-inserted session,
  /// and expired ones are swept on every insert and every read.
  static const _maxPairingSessions = 8;

  /// The life of one pairing session (and its code), in milliseconds -
  /// short by design: the user reads the code from the host screen now.
  static const _pairingTtlMs = 120_000;

  /// The wrong-code guess budget, in wrong code attempts per pairing
  /// session (the unit is written here): every wrong attempt is charged to
  /// every live session - a guess could have been aimed at any of them -
  /// so once a session has absorbed the budget, further attempts against
  /// it answer `429 pair_budget_exceeded` with the session's honest
  /// remainder. Per-session, never per-origin: on loopback the address is
  /// one, and a per-origin split would hand a multi-page attacker one
  /// fresh budget per forged origin. Above the budget the code is not
  /// compared at all - the budget decides first, so the answer never
  /// tells how close a guess was.
  static const _pairGuessBudget = 5;

  /// Cap on paired-origin records (one binding per paired token): expired
  /// records are swept on insert; a 65th insert into a full house evicts
  /// the oldest-inserted LIVE record - fail-closed: the evicted page's
  /// signatures stop verifying and it re-pairs. The ceiling is the worst
  /// case for memory, never the flood.
  static const _maxPairedOrigins = 64;

  /// The life of a paired token, in milliseconds - 24 hours: long enough
  /// for a workday, bounded so no secret lives forever in page code. The
  /// host revokes or rotates earlier at will; after expiry the page
  /// re-pairs.
  static const _pairedTokenTtlMs = 86_400_000;

  /// The sessions map - insertion order IS the eviction queue (a
  /// LinkedHashMap assigns to an existing key without moving it).
  final Map<String, _PairingSession> _pairingSessions =
      <String, _PairingSession>{};

  /// The paired records keyed by sha256(token) hex - the raw token bytes
  /// never become a lookup key.
  final Map<String, _PairedRecord> _pairedRecords = <String, _PairedRecord>{};

  /// The pairing-id index: derived id -> record (its ceiling is the
  /// records cap by construction).
  final Map<String, _PairedRecord> _pairingIdIndex = <String, _PairedRecord>{};

  /// Whether the pairing layer is armed: the host turns it on once
  /// through [enablePairing], which is also where the callbacks arrive.
  bool _pairingArmed = false;

  /// Whether the pairing layer is armed right now.
  bool get pairingEnabled => _pairingArmed;

  /// Fired once per successful pairing with the bound origin.
  void Function(PairingInfo info)? onPaired;

  /// Save hook (brought in [enablePairing]): the host persists the paired
  /// token for its own storage - the package writes no file and never
  /// waits on the hook; a throwing hook is contained and said, never
  /// allowed to break the wire.
  Future<void> Function(String origin, String token, int lifetimeMs)?
  onPairedSave;

  /// Save hook (brought in [enablePairing]): the host drops its persisted
  /// copy when a binding is revoked (explicitly or by rotation).
  void Function(String origin)? onPairedRevoke;

  /// Save hook (brought in [enablePairing]): the host persists a discovery
  /// decision (allowAlways or reject) the moment it is remembered.
  void Function(String origin, OriginConsent consent)? onConsentSave;

  /// Arms the pairing layer: `POST /pair` starts answering on the server,
  /// bound tokens start counting, and the host's callbacks take their
  /// seats. Calling it again re-arms with the new callbacks (the state
  /// maps survive); [disablePairing] closes the route and drops the
  /// bindings.
  void enablePairing({
    void Function(PairingInfo info)? onPaired,
    Future<void> Function(String origin, String token, int lifetimeMs)?
    onPairedSave,
    void Function(String origin)? onPairedRevoke,
    void Function(String origin, OriginConsent consent)? onConsentSave,
  }) {
    _pairingArmed = true;
    this.onPaired = onPaired;
    this.onPairedSave = onPairedSave;
    this.onPairedRevoke = onPairedRevoke;
    this.onConsentSave = onConsentSave;
  }

  /// Disarms the pairing layer and drops every binding: pages paired so
  /// far must pair again. The route stops answering; the wire contracts
  /// of everything else are untouched.
  void disablePairing() {
    _pairingArmed = false;
    onPaired = null;
    onPairedSave = null;
    onPairedRevoke = null;
    onConsentSave = null;
    _pairingSessions.clear();
    _pairedRecords.clear();
    _pairingIdIndex.clear();
  }

  /// Creates a new one-time code for the host to display. No origin
  /// involved here - the qualification gate lives in [pair], where the
  /// page's origin arrives.
  PairingOffer startPairing() {
    if (!_pairingArmed) {
      throw StateError('pairing is not enabled - call enablePairing first');
    }
    _sweepPairingSessions();
    final rnd = Random.secure();
    final code = rnd.nextInt(1_000_000).toString().padLeft(6, '0');
    // الطرد عند السقف: الأقدم إدراجاً يخرج (الخريطة نفسها الطابور)
    while (_pairingSessions.length >= _maxPairingSessions) {
      _pairingSessions.remove(_pairingSessions.keys.first);
    }
    _pairingSessions[code] = _PairingSession(code, _now + _pairingTtlMs);
    return PairingOffer(code: code, expiresInSeconds: _pairingTtlMs ~/ 1000);
  }

  /// The pairing gate: the page's origin must qualify under the current
  /// policy (one qualification source - the same list / allow-all /
  /// remembered consent the admission paths read), then the code decides.
  /// Every wrong attempt is charged to every live session; the code is
  /// one-time; the issued token is bound to this origin, expires in 24
  /// hours, and is revocable and rotatable by the host. Rejections here
  /// count and log through the same throttled path as every other
  /// rejection - denial is never silent.
  PairingOutcome pair({String? origin, required String code}) {
    if (!_pairingArmed) {
      throw StateError('pairing is not enabled - call enablePairing first');
    }
    final key = origin == null ? '' : normalize(origin);
    // بوابة التأهيل أولاً: غير المؤهل يُجاب برمز الأصل ولا يحرق الرمز
    // ولا ميزانية الجلسة — مصدر تأهيل واحد لا اثنان
    if (!_pairingQualified(origin)) {
      _noteAuthority('pairing refused: origin_not_listed', origin);
      return const PairingOutcome.rejected(
        IntakeRejection(
          403,
          'origin_not_listed',
          'Origin is not on the allowed list',
        ),
      );
    }
    // مقارنة الرمز سادة المقارنة الزمنية-الثابتة: الميزانية لكل جلسة هي
    // الحارس (خمس محاولات فأقل فضاء الرمز)، ومقارنة الزمن-الثابت هنا
    // كانت ستلوث عدّاد مقارنات التوكن بشاهد قبوله. البحث يشمل الجلسة
    // المنتهية بعد — رمز معروف انتهى عمره يُجاب برمز الانتهاء لا برمز
    // المجهول، ثم تموت الجلسة هنا
    _PairingSession? matched;
    for (final session in _pairingSessions.values) {
      if (session.code == code) {
        matched = session;
        break;
      }
    }
    if (matched != null && _now > matched.expiresAtMs) {
      _pairingSessions.remove(matched.code);
      _noteAuthority('pairing refused: pair_code_expired', origin);
      return const PairingOutcome.rejected(
        IntakeRejection(
          403,
          'pair_code_expired',
          'This pairing code has expired — ask the host for a new one',
        ),
      );
    }
    if (matched == null) {
      // ما لا يطابق حيّاً: الكنس أولا فيخرج الموتى قبل التسعير
      _sweepPairingSessions();
      // محاولة خاطئة تُحسب على كل جلسة حية — كان يمكن أن تستهدف أيّها.
      // الحكم قبل التسعير: المنفق هو من بلغ الميزانية قبل هذه المحاولة،
      // فالمحاولات الخمس كلها تُجاب invalid والسادسة وحدها 429
      var allSpent = _pairingSessions.isNotEmpty;
      for (final session in _pairingSessions.values) {
        if (session.wrongAttempts < _pairGuessBudget) allSpent = false;
      }
      var longestRemainderMs = 0;
      for (final session in _pairingSessions.values) {
        session.wrongAttempts++;
        final remainder = session.expiresAtMs - _now;
        if (remainder > longestRemainderMs) longestRemainderMs = remainder;
      }
      if (allSpent) {
        _noteAuthority(
          'pairing refused: pair_budget_exceeded '
          '($_pairGuessBudget wrong code attempts per pairing session)',
          origin,
        );
        return PairingOutcome.rejected(
          IntakeRejection(
            429,
            'pair_budget_exceeded',
            'Too many wrong pairing codes — retry after a short wait',
            retryAfterMs: longestRemainderMs < 1000 ? 1000 : longestRemainderMs,
          ),
        );
      }
      _noteAuthority('pairing refused: pair_code_invalid', origin);
      return const PairingOutcome.rejected(
        IntakeRejection(
          403,
          'pair_code_invalid',
          'Unknown or already-used pairing code',
        ),
      );
    }
    // الميزانية تحسم قبل أي مقارنة إضافية: فوقها الجواب لا يكشف قرب
    // المحاولة من الهدف
    if (matched.wrongAttempts >= _pairGuessBudget) {
      final remainder = matched.expiresAtMs - _now;
      _noteAuthority(
        'pairing refused: pair_budget_exceeded '
        '($_pairGuessBudget wrong code attempts per pairing session)',
        origin,
      );
      return PairingOutcome.rejected(
        IntakeRejection(
          429,
          'pair_budget_exceeded',
          'Too many wrong pairing codes — retry after a short wait',
          retryAfterMs: remainder < 1000 ? 1000 : remainder,
        ),
      );
    }
    // النجاح: الجلسة تموت بالاستهلاك (الرمز لمرة واحدة)، والتوكن المربوط
    // يولد من مولده المستقل — لا اشتقاق من المفتاح المشترك إطلاقاً
    _pairingSessions.remove(matched.code);
    final token = generateBridgeToken();
    final digest = hexEncode(sha256(utf8.encode(token)));
    final id = digest.substring(0, 16);
    final existing = _pairingIdIndex[id];
    if (existing != null && existing.digest != digest) {
      // التصادم عملياً مستحيل (64 مدخلاً على فضاء 64 بتاً) — لكن الفشل
      // الصاخب أفضل من حفظ ربط غامض
      telemetry?.error(
        'pairing id collision on issue - refusing this pairing loudly',
        category: BridgeCategory.security,
      );
      return const PairingOutcome.rejected(
        IntakeRejection(
          403,
          'pair_code_invalid',
          'Unknown or already-used pairing code',
        ),
      );
    }
    _insertPairedRecord(
      _PairedRecord(
        origin: key,
        token: token,
        digest: digest,
        issuedAtMs: _now,
        expiresAtMs: _now + _pairedTokenTtlMs,
      ),
    );
    onPaired?.call(
      PairingInfo(
        origin: key,
        pairingId: id,
        expiresInSeconds: _pairedTokenTtlMs ~/ 1000,
      ),
    );
    _containHook(() {
      final hook = onPairedSave;
      if (hook == null) return null;
      return Future<void>.sync(() => hook(key, token, _pairedTokenTtlMs));
    }, origin: key);
    return PairingOutcome.paired(
      token: token,
      pairingId: id,
      expiresInSeconds: _pairedTokenTtlMs ~/ 1000,
    );
  }

  /// Revokes every binding of one origin at once: its signatures stop
  /// verifying in the very next admission, and the revoke hook carries the
  /// origin to the host's storage.
  void revokePairedOrigin(String origin) {
    final key = normalize(origin);
    final dead = _pairedRecords.keys
        .where((digest) => _pairedRecords[digest]!.origin == key)
        .toList();
    for (final digest in dead) {
      final record = _pairedRecords.remove(digest);
      if (record != null) _pairingIdIndex.remove(record.pairingId);
    }
    if (dead.isNotEmpty) {
      telemetry?.warn(
        'paired origin revoked: every binding of this origin is dead '
        '— its page must pair again',
        category: BridgeCategory.security,
      );
      _containHook(() {
        onPairedRevoke?.call(key);
        return null;
      }, origin: key);
    }
  }

  /// Rotation = revoke + a fresh offer: the host displays the new code,
  /// the page pairs again, the old bindings stay dead.
  PairingOffer rotatePairedOrigin(String origin) {
    revokePairedOrigin(origin);
    return startPairing();
  }

  /// Re-arms a persisted binding after a host restart: same token, same
  /// derived pairing id, whatever lifetime the host's own timestamps say
  /// is left. Returns the derived pairing id (identical to the one the
  /// original pairing issued - it is a function of the token alone). A
  /// non-positive remainder or a token below the length floor throws
  /// [ArgumentError] - a loud setup error, never a silent entry.
  String restorePairedOrigin({
    required String origin,
    required String token,
    required int remainingMs,
  }) {
    if (!_pairingArmed) {
      throw StateError('pairing is not enabled - call enablePairing first');
    }
    final bytes = utf8.encode(token.trim()).length;
    if (remainingMs <= 0) {
      throw ArgumentError.value(
        remainingMs,
        'remainingMs',
        'must be positive - an expired binding is not restored',
      );
    }
    if (bytes < _minTokenBytes) {
      throw ArgumentError.value(
        bytes,
        'token',
        'is $bytes bytes (UTF-8) - a paired token needs at least '
            '$_minTokenBytes bytes, as generateBridgeToken produces',
      );
    }
    final digest = hexEncode(sha256(utf8.encode(token.trim())));
    final id = digest.substring(0, 16);
    final existing = _pairingIdIndex[id];
    if (existing != null && existing.digest != digest) {
      throw ArgumentError.value(
        id,
        'pairingId',
        'collides with a different binding - refusing loudly instead of '
            'storing an ambiguous record',
      );
    }
    _insertPairedRecord(
      _PairedRecord(
        origin: normalize(origin),
        token: token.trim(),
        digest: digest,
        issuedAtMs: _now,
        expiresAtMs: _now + remainingMs,
      ),
    );
    return id;
  }

  /// Re-arms a persisted discovery decision after a host restart: only the
  /// two persistent values are accepted - `allowOnce` is a 30-second
  /// grant by contract and [ArgumentError] says so, `dismissed` stores
  /// nothing by contract.
  void restoreSavedConsent(String origin, OriginConsent consent) {
    if (consent == OriginConsent.allowOnce) {
      throw ArgumentError.value(
        consent,
        'consent',
        'allowOnce is a short one-request grant, never a saved decision - '
            'the origin will be asked again',
      );
    }
    if (consent == OriginConsent.dismissed) {
      throw ArgumentError.value(
        consent,
        'consent',
        'dismissed closes a question with no decision - nothing is stored',
      );
    }
    _rememberConsent(normalize(origin), consent);
  }

  /// How many paired-origin records are armed right now - the read-only
  /// counter a settings UI reads; the wire behavior never does.
  int get pairedCount => _pairedRecords.length;

  /// Does this origin qualify for pairing under the current policy? The
  /// same qualification the admission paths grant: the list (with its
  /// remembered always-allow consents), or the hardened allow-all shape.
  /// Discovery is deliberately absent: an origin whose question is still
  /// open has not been vouched for yet.
  bool _pairingQualified(String? origin) {
    if (origin == null || origin.isEmpty || origin == 'null') return false;
    if (_isListed(origin)) return true;
    if (!_policy.allowAllHardened) return false;
    final uri = Uri.tryParse(origin);
    if (uri == null || uri.host.isEmpty) return false;
    if (uri.scheme == 'https') return true;
    final host = uri.host.toLowerCase();
    return _policy.allowLocalHttp &&
        uri.scheme == 'http' &&
        (host == 'localhost' || host == '127.0.0.1' || host == '::1');
  }

  /// Sweeps expired sessions - on every insert and every read.
  void _sweepPairingSessions() {
    final now = _now;
    _pairingSessions.removeWhere((_, session) => now > session.expiresAtMs);
  }

  /// Inserts a paired record under the cap: expired records swept first,
  /// then the oldest-inserted live record is evicted fail-closed.
  void _insertPairedRecord(_PairedRecord record) {
    final now = _now;
    _pairedRecords.removeWhere(
      (digest, existing) => now > existing.expiresAtMs,
    );
    final previous = _pairedRecords[record.digest];
    if (previous != null) {
      // إعادة ربط نفس التوكن (استعادة أو إعادة اقتران) تستبدل السجل لا
      // تكرره، وفهرس المعرف يبقى على الأحدث
      _pairingIdIndex.remove(previous.pairingId);
      _pairedRecords.remove(record.digest);
    }
    while (_pairedRecords.length >= _maxPairedOrigins) {
      final oldestDigest = _pairedRecords.keys.first;
      final oldest = _pairedRecords.remove(oldestDigest);
      if (oldest != null && _pairingIdIndex[oldest.pairingId] == oldest) {
        _pairingIdIndex.remove(oldest.pairingId);
      }
    }
    _pairedRecords[record.digest] = record;
    _pairingIdIndex[record.pairingId] = record;
  }

  /// Runs a save hook with its failures contained: the hook belongs to the
  /// host's storage, so its crash is said once (telemetry) and never
  /// allowed to break the pairing or revocation path. A null return means
  /// the body ran synchronously.
  void _containHook(Future<void>? Function() body, {required String origin}) {
    Future<void>? work;
    try {
      work = body();
    } catch (e) {
      telemetry?.warn(
        'pairing save hook threw synchronously (origin='
        '${originForLog(origin) ?? 'none'}) — the binding is live in '
        'memory; the host storage missed it',
        category: BridgeCategory.security,
      );
      return;
    }
    if (work != null) {
      unawaited(
        work.catchError((Object e) {
          telemetry?.warn(
            'pairing save hook failed (origin='
            '${originForLog(origin) ?? 'none'}) — the binding is live in '
            'memory; the host storage missed it: $e',
            category: BridgeCategory.security,
          );
        }),
      );
    }
  }

  // ══ إثبات الحيازة — التحقق من توقيع HMAC وباب الإعادة ══

  /// The accepted stamp-skew window in milliseconds: the page stamps its
  /// signature with its own wall clock, and the server accepts what stays
  /// within one minute of its own. Both clocks read the same machine on
  /// loopback, so honest skew is microseconds - the window exists for
  /// embedded clocks, not for patience.
  static const _pairStampSkewMs = 60_000;

  /// The replay-cache window in milliseconds - double the skew window with
  /// margin: a stamp either sits inside the skew (the cache is young
  /// enough to remember it) or outside it (freshness refuses before the
  /// cache matters). No third case.
  static const _pairReplayWindowMs = 120_000;

  /// Cap on replay-cache entries (pairingId + stamp keys): the oldest
  /// inserted is evicted past it. The cache ceiling is the worst case for
  /// memory, never an open replay door - a stamp outside the skew window
  /// refuses whatever its cache fate was.
  static const _maxPairReplayEntries = 4096;

  /// The replay cache: `(pairingId.stamp)` -> first-seen reading. The
  /// projection reads it (a pure read); settle records into it.
  final Map<String, int> _pairReplay = <String, int>{};
  int _nextPairReplaySweepMs = 0;

  /// The proof's wire shape: `pairingId(16 hex).stamp(digits).signature
  /// (64 hex)` - everything else is malformed before any lookup.
  static final RegExp _pairProofShape = RegExp(
    r'^([0-9a-f]{16})\.([0-9]{1,16})\.([0-9a-f]{64})$',
  );

  /// The outcome of one proof verification - pure, no state touched. The
  /// internal failure name travels the muted security line only.
  _PairCheck _verifyPairProof(
    String? raw,
    String? origin,
    String key,
    String method,
    String path,
    String correlationId,
    int now,
  ) {
    if (raw == null || raw.isEmpty) {
      return _PairCheck.bad('missing');
    }
    final match = _pairProofShape.firstMatch(raw);
    if (match == null) {
      return _PairCheck.bad('malformed');
    }
    final id = match.group(1)!;
    final stampText = match.group(2)!;
    final sigHex = match.group(3)!;
    final record = _pairingIdIndex[id];
    if (record == null) {
      return _PairCheck.bad('unknown-id');
    }
    if (now > record.expiresAtMs) {
      return _PairCheck.bad('token-expired');
    }
    if (key.isEmpty || record.origin != key) {
      return _PairCheck.bad('origin-mismatch');
    }
    // نافذة الانحراف على ساعة الجدار: الطابع epoch من ساعة الصفحة
    final stampMs = int.parse(stampText);
    final serverEpoch = DateTime.now().millisecondsSinceEpoch;
    if ((serverEpoch - stampMs).abs() > _pairStampSkewMs) {
      return _PairCheck.bad('stale', replay: true);
    }
    final replayKey = '$id.$stampText';
    if (_pairReplay.containsKey(replayKey)) {
      return _PairCheck.bad('reused-stamp', replay: true);
    }
    // الرسالة الموقعة بنص التصميم الحرفي — الطريقة والمسار ومعرف
    // الارتباط تربط التوقيع بطلبه فيلا نقل توقيع صالح إلى أمر آخر
    final canonical =
        'v1\n$id\n$stampText\n${method.toUpperCase()}\n$path\n'
        '$correlationId';
    final expected = hmacSha256(
      utf8.encode(record.token),
      utf8.encode(canonical),
    );
    final supplied = _hexToBytes(sigHex);
    if (supplied == null || !fixedTimeEquals(expected, supplied)) {
      return _PairCheck.bad('signature');
    }
    return _PairCheck.ok(record, replayKey);
  }

  /// Sixty-four hex characters to 32 bytes - null on anything else (the
  /// proof's regex has already guaranteed hex, so this is belt and
  /// suspenders).
  static List<int>? _hexToBytes(String hex) {
    if (hex.length != 64) return null;
    final out = List<int>.filled(32, 0);
    for (var i = 0; i < 32; i++) {
      final high = int.tryParse(hex[i * 2], radix: 16);
      final low = int.tryParse(hex[i * 2 + 1], radix: 16);
      if (high == null || low == null) return null;
      out[i] = high * 16 + low;
    }
    return out;
  }

  /// Records a verified proof's stamp on settle - the projection's pure
  /// read never writes here. Expired entries sweep at most once a second,
  /// and the cap evicts the oldest-inserted key.
  void _recordPairReplay(String replayKey, int now) {
    if (_pairReplay.isNotEmpty && now >= _nextPairReplaySweepMs) {
      _nextPairReplaySweepMs = now + 1000;
      _pairReplay.removeWhere((_, seen) => now - seen > _pairReplayWindowMs);
    }
    while (_pairReplay.length >= _maxPairReplayEntries) {
      _pairReplay.remove(_pairReplay.keys.first);
    }
    _pairReplay[replayKey] = now;
  }

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
  /// of 32 UTF-8 bytes, or over the [maxBridgeTokenHeaderBytes] header cap
  /// the intake enforces on the wire (such a token would be refused by
  /// every request before any comparison - a correct secret that can
  /// never match must not sit configured silently), BEFORE anything is
  /// applied, so a host that catches the error keeps its previous
  /// protection state untouched.
  /// The character-diversity floor refuses the same way, for a token the
  /// call passes explicitly; a token INHERITED from the current state
  /// (a policy-only call) is exempt - it is the same legitimately saved
  /// state [updateFromSaved] loads with a rotation warning, and refusing
  /// it here would lock a host out of every policy update until it
  /// rotated the key.
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
        'is $tokenBytes bytes (UTF-8) - a bridge token needs at least '
            '$_minTokenBytes random bytes (generateBridgeToken produces one); '
            'a short token is guessable from a web page',
      );
    }
    // سقف ترويسة التوكن: توكن مضبوط فوق ما تقبله الترويسة على السلك
    // يستحيل مطابقته — كل طلب حامل له يُرد token_too_long قبل أي
    // مقارنة فيظل سرٌّ صحيح منضبطاً بلا أثر (نقض عملي لـ«الصحيح لا
    // يُرفض أبداً»). الرفض وقت الإعداد بلا أثر جانبي كأخويه، والرسالة
    // تسمي البديل
    if (tokenBytes > maxBridgeTokenHeaderBytes) {
      throw ArgumentError.value(
        tokenBytes,
        'token',
        'is $tokenBytes bytes (UTF-8) - over the '
            '$maxBridgeTokenHeaderBytes-byte header cap the intake '
            'enforces on the wire (token_too_long), so no request could '
            'ever match it; use generateBridgeToken, whose tokens sit '
            'far below the cap',
      );
    }
    // فحص التنوع فوق أرضية الطول: توكن متطابق المحارف أو فقيرها قابل
    // للتخمين بنظرة واحدة — الرفض وقت الإعداد بلا أثر جانبي كأخيه
    // الطولي، والرمي قبل _apply فمن يلتقطه يبقى على حالته السابقة.
    // والأرضية على المُمرَّر صراحةً حصراً: التوكن الموروث (استدعاء بلا
    // token على كائن أُقلع من حالة محفوظة شرعية) هو ذاته ما أعفاها
    // updateFromSaved من الرفض عند الإقلاع بتحذير تدوير — ورفُضه هنا
    // كان يحبس المضيف خارج كل تحديث سياسة حتى يدوّر المفتاح، فينقلب
    // الإعفاء المعلن فخاً صامتاً
    final distinctChars = effectiveToken.trim().runes.toSet().length;
    if (token != null &&
        tokenBytes >= _minTokenBytes &&
        distinctChars < _minTokenDistinctChars) {
      throw ArgumentError.value(
        distinctChars,
        'token',
        'has only $distinctChars distinct characters - a token this '
            'repetitive is guessable at a glance; use generateBridgeToken '
            'or another random source (the floor is '
            '$_minTokenDistinctChars distinct characters)',
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
        'bridge token length $tokenBytes bytes (UTF-8) exceeds the '
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
        'saved bridge token is short ($savedTokenBytes bytes) and stays '
        'inert - the token layer is off until a fresh '
        '$_minTokenBytes-byte token is saved (fail-closed, not a crash '
        'loop)',
        category: BridgeCategory.security,
      );
    }
    // فحص التنوع لا يرفض الحالة المحفوظة الشرعية عند الترقية: توكن محفوظ
    // طويل لكن فقير التنوع يبقى عاملاً كما أُقلع من الإصدار السابق —
    // تحذير واحد يسمي الضعف والتدوير، والرفض وقت الضبط في update() حصراً
    final savedDistinct = effectiveToken.trim().runes.toSet().length;
    if (savedTokenBytes >= _minTokenBytes &&
        savedDistinct < _minTokenDistinctChars) {
      telemetry?.warn(
        'saved bridge token has only $savedDistinct distinct characters '
        '(the floor is $_minTokenDistinctChars) and stays active - rotate '
        'it with generateBridgeToken; update() now refuses such tokens at '
        'set time',
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
  ///
  /// Port semantics are per entry form, and this is the settled contract:
  /// a full origin entry matches the exact origin string the browser
  /// sends - scheme, host, and port exactly as written, so an entry for a
  /// non-default port must carry that port and an entry without a port
  /// matches only the portless form (a browser omits default ports, so
  /// `https://host` is what `https://host:443` pages send). A bare-host
  /// entry matches the host name alone on ANY port, and a `*.domain`
  /// entry matches its subdomains on ANY port: the page's port is chosen
  /// by whoever serves the page, so the bare and wildcard forms gate on
  /// the domain while the full form pins the origin. All forms keep the
  /// scheme rule below (https, or local http under allowLocalHttp).
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
  /// key for every per-origin window in this object.
  /// Kept for hosts until the planned removal: the admission record carries
  /// the canonical form as [IntakeAdmission.normalizedOrigin].
  @Deprecated(
    'Read IntakeAdmission.normalizedOrigin from the record built by '
    'admit() (removal planned in 0.3.0)',
  )
  static String normalize(String origin) =>
      _stripTrailingSlashes(origin.toLowerCase());

  /// A valid browser origin - the basis for the discovery question (asking
  /// about sandbox/null or http origins is meaningless).
  bool _validBrowserOrigin(String origin) {
    final uri = Uri.tryParse(origin);
    return uri != null && uri.scheme == 'https' && uri.host.isNotEmpty;
  }

  /// Accept the request - null means allowed; [IntakeRejection] carries
  /// status, code, and message. Order: the token layer passes on its own,
  /// then the list, then allow-all with its hardening, then discovery or an
  /// explicit reject.
  /// Kept for hosts until the planned removal: the package's own server
  /// builds the admission record with [admit] instead.
  @Deprecated(
    'Build the one admission record with admit() and read its rejection '
    'field - the record carries the verdict, the CORS echo, and the '
    'verbose-error decision together (removal planned in 0.3.0)',
  )
  Future<IntakeRejection?> check({
    String? origin,
    String? bridgeToken,
    String? fetchMode,
    String? fetchDest,
  }) async {
    // الإهمال يبقى بالسلوك القديم حرفاً: الإسقاط ثم إرضاء أثره فوراً في
    // هذا الموضع (طوابع النوافذ واستهلاك المنحة والسؤال وتحذيرات
    // المراقبة) — بلا عدّ: عدّ الرفض كان من خارج check (noteRejection من
    // الخادم) وما زال
    final decision = _project(origin, bridgeToken, fetchMode, fetchDest);
    _applyDecision(decision, origin);
    return decision.rejection;
  }

  /// The one admission step: projects the whole request decision against
  /// the live policy state in a single pass and returns the record. No
  /// state is touched here - the projection is a pure read; the caller
  /// lands the effects with [IntakeAdmission.settle] at its acceptance
  /// gate, so requests answered from the record alone (a preflight, a
  /// shape-gate reject, a busy reject) leave no stamps, no grants, no
  /// questions, and no rejection lines behind.
  ///
  /// The token is compared at most once per request: the comparison happens
  /// here and its outcome is recorded, so the verbose-error decision reads
  /// the record instead of ever comparing again.
  ///
  /// [pairingProof] is the raw `X-Bridge-Pairing` value - verified here
  /// under [OriginPolicy.requireOriginWithToken] against the armed pairing
  /// records, its replay recorded on settle. [method] and [correlationId]
  /// bind the proof to the request it signs (the canonical string carries
  /// both), so a captured proof cannot be transplanted to another verb,
  /// path, or story.
  Future<IntakeAdmission> admit({
    String? origin,
    String? bridgeToken,
    String? fetchMode,
    String? fetchDest,
    String path = '/',
    String? pairingProof,
    String method = 'POST',
    String correlationId = '',
  }) async {
    final decision = _project(
      origin,
      bridgeToken,
      fetchMode,
      fetchDest,
      pairingProof: pairingProof,
      method: method,
      path: path,
      correlationId: correlationId,
    );
    return IntakeAdmission._(
      rejection: decision.rejection,
      acceptedPath: decision.acceptedPath,
      echoesCors: decision.echoesCors,
      verboseErrors: decision.verboseErrors,
      origin: origin,
      normalizedOrigin: origin == null ? null : normalize(origin),
      path: path,
      decision: decision,
      owner: this,
    );
  }

  /// The pure decision projection behind both [admit] and the deprecated
  /// [check]: one pass over the token layer and the acceptance order,
  /// recording the verdict and the branch effects - and never mutating a
  /// thing.
  _AdmissionDecision _project(
    String? origin,
    String? bridgeToken,
    String? fetchMode,
    String? fetchDest, {
    String? pairingProof,
    String method = 'POST',
    String path = '/',
    String correlationId = '',
  }) {
    final now = _now;
    final key = origin == null ? '' : normalize(origin);

    // الخمول التام قرارا نهائيا على كل المسارات (لا نصف حي): المدرج
    // والتوكن والحصص كلها تتوقف — برمز مستقل لا يوهم المطور بأن
    // إدراج الأصل ينفع، وبلا أثر تسوية إطلاقاً
    if (_disposed) {
      return _AdmissionDecision(
        rejection: const IntakeRejection(
          503,
          'protection_disposed',
          'The protection object is disposed — create a new one',
        ),
        acceptedPath: null,
        echoesCors: false,
        verboseErrors: false,
        stampMs: now,
        key: key,
      );
    }

    var tokenAttempt = false;
    var tokenCompared = false;
    var tokenMatched = false;
    // ميزانية التخمين منفقة لهذا الطلب؟ تُحسب داخل طبقة التوكن وتُقرأ
    // عند بناء القرار (طابع الإخفاق وسطر الميزانية لا يُطلعان إلا بها)
    var budgetSpent = false;
    IntakeRejection? rejection;
    IntakeAdmissionPath? accepted;
    final beyond = _BeyondOutcome();
    // إثبات الاقتران: يتحقق كسولا في موضع القرار حصرا (أصل مؤهل تحت
    // الشرط) — بلا شرط ولا إثبات لا تحقق ولا أثر إطلاقا
    _PairCheck? proofCheck;
    var pairReplayKey = '';
    var pairFailure = '';
    _PairCheck resolveProof() {
      final existing = proofCheck;
      if (existing != null) return existing;
      final checked = _verifyPairProof(
        pairingProof,
        origin,
        key,
        method,
        path,
        correlationId,
        now,
      );
      proofCheck = checked;
      return checked;
    }

    // (0) طبقة التوكن المستقلة — قراءة خالصة. المقارنة تجري دائماً: لا
    // نافذة إخفاق تسقط المقارنة عن التوكن الصحيح فالصحيح يُقارن ويُقبل
    // أياً كان تاريخ الإخفاقات، والمطابقة تصفر النافذة عند التسوية.
    // وفوق ميزانية التخمين الخاطئ لا يفتح الخاطئ سؤال موافقة ولا يُقبل
    // إلا بتأهل الأصل — وإلا فرفض الانتظار الصادق بلا طابع جديد فالنافذة
    // تنكسر بصدق. والمقارنة مرة واحدة على الأكثر لكل طلب هنا
    // شرط الأصل والتوكن معاً: المطفأ سلكُ اليوم حرفاً؛ والمفعّل يقلب
    // معنى الطبقتين على الأصل المؤهل — المؤهل يطلب إثباتاً، والتوكن
    // وحده لا يفتح أصلاً غير مؤهل (رفض الأصل يجيب فلا يتكلم التوكن)
    final requireBoth = _policy.requireOriginWithToken;
    if (_token.isNotEmpty && bridgeToken != null && bridgeToken.isNotEmpty) {
      tokenAttempt = true;
      tokenCompared = true;
      tokenMatched = _fixedTimeEquals(bridgeToken, _token);
      final liveMisses = _liveTokenMisses(origin, now);
      budgetSpent = liveMisses.length >= _tokenGuessBudget;
      if (tokenMatched && !requireBoth) {
        // الصحيح يعبر فورا على كل نافذة — مسار القبول: التوكن وحده على
        // أصل غير مؤهل، والطبقتان معاً على أصل مدرج
        accepted = _isListed(origin)
            ? IntakeAdmissionPath.originWithToken
            : IntakeAdmissionPath.token;
      } else {
        _projectBeyondToken(
          origin,
          key,
          fetchMode,
          fetchDest,
          now: now,
          mayAskConsent: !budgetSpent,
          out: beyond,
        );
        if (!tokenMatched &&
            budgetSpent &&
            (beyond.accepted == null || requireBoth)) {
          // الرأس الصادق: بقايا نافذة الميزانية نفسها — أقدم إخفاق يخرج
          // منها فتنكسر، فانتظار الذكرى لا «ثانيتين» لكل الرفوض. وتحت
          // الشرط الجديد يبقى الخاطئ فوق الميزانية محروساً بالإشارة نفسها
          // أياً كان حكم الأصل — نافذة الإخفاق إشارة عن التوكن المشترك
          final budgetWaitMs = liveMisses.isEmpty
              ? _tokenBudgetWindowMs
              : _tokenBudgetWindowMs - (now - liveMisses.first) + 500;
          rejection = IntakeRejection(
            429,
            'token_locked',
            'Too many failed token attempts — retry after a short wait',
            retryAfterMs: budgetWaitMs < 1000 ? 1000 : budgetWaitMs,
          );
        } else if (requireBoth && beyond.accepted != null) {
          if (tokenMatched) {
            // المؤهل والإثبات المشترك معاً — مسار الطبقتين كما كان
            accepted = IntakeAdmissionPath.originWithToken;
          } else if (_pairingArmed) {
            // التوكن المشترك خاطئ لكن إثبات اقتران قد يكون حاضرا: يتحقق
            // كسولا هنا — الصحيح يقبل بالمسار المقترن، والإعادة يعود
            // برمزها الصادق، وسواهما token_required بلا تفصيل يوهم
            final proof = resolveProof();
            if (proof.ok) {
              accepted = IntakeAdmissionPath.originWithPairedToken;
              pairReplayKey = proof.replayKey!;
            } else if (proof.replay) {
              rejection = const IntakeRejection(
                403,
                'pair_signature_replay',
                'This pairing signature was already used — sign a fresh '
                    'request',
              );
              accepted = null;
              pairFailure = proof.fail!;
              beyond
                ..grantExisted = false
                ..quotaLimit = 0
                ..fireAsk = false
                ..reportOnlyLine = null;
            } else {
              rejection = const IntakeRejection(
                403,
                'token_required',
                'A token is required for this origin',
              );
              accepted = null;
              pairFailure = proof.fail!;
              beyond
                ..grantExisted = false
                ..quotaLimit = 0
                ..fireAsk = false
                ..reportOnlyLine = null;
            }
          } else {
            // المؤهل بلا إثبات صالح: token_required — والقراءة خالصة
            // تبقى خالصة: أثر الاستحقاق المسجل (المنحة وطابع الحصة
            // والسؤال وسطر المراقبة) يُصفَّر فلا تسوية تترك شيئاً لطلب
            // لم يثبت نفسه
            rejection = const IntakeRejection(
              403,
              'token_required',
              'A token is required for this origin',
            );
            accepted = null;
            beyond
              ..grantExisted = false
              ..quotaLimit = 0
              ..fireAsk = false
              ..reportOnlyLine = null;
          }
        } else {
          rejection = beyond.rejection;
          accepted = beyond.accepted;
        }
      }
    } else {
      _projectBeyondToken(
        origin,
        key,
        fetchMode,
        fetchDest,
        now: now,
        mayAskConsent: true,
        out: beyond,
      );
      if (requireBoth && beyond.accepted != null && _pairingArmed) {
        // المؤهل بلا ترويسة توكن مشترك: إثبات الاقتران هو الباب —
        // بنفس الأحكام الثلاثة للفرع أعلاه حرفا
        final proof = resolveProof();
        if (proof.ok) {
          accepted = IntakeAdmissionPath.originWithPairedToken;
          pairReplayKey = proof.replayKey!;
        } else if (proof.replay) {
          rejection = const IntakeRejection(
            403,
            'pair_signature_replay',
            'This pairing signature was already used — sign a fresh request',
          );
          accepted = null;
          pairFailure = proof.fail!;
          beyond
            ..grantExisted = false
            ..quotaLimit = 0
            ..fireAsk = false
            ..reportOnlyLine = null;
        } else {
          rejection = const IntakeRejection(
            403,
            'token_required',
            'A token is required for this origin',
          );
          accepted = null;
          pairFailure = proof.fail!;
          beyond
            ..grantExisted = false
            ..quotaLimit = 0
            ..fireAsk = false
            ..reportOnlyLine = null;
        }
      } else if (requireBoth && beyond.accepted != null) {
        // المؤهل بلا إثبات أصلاً والاقتران غير مسلح: نفس الرمز وبنفس
        // صفاء القراءة — لا أثر استحقاق يسجل لطلب بلا إثبات
        rejection = const IntakeRejection(
          403,
          'token_required',
          'A token is required for this origin',
        );
        accepted = null;
        beyond
          ..grantExisted = false
          ..quotaLimit = 0
          ..fireAsk = false
          ..reportOnlyLine = null;
      } else {
        rejection = beyond.rejection;
        accepted = beyond.accepted;
      }
    }

    // صدى CORS: قرار الأهلية الخام نفسه الذي كانت echoesCorsFor تجيبه —
    // هو ما تقرأه بوابات الخادم (الترويسة المكررة والانشغال والمهيّأ)
    // والقبول معاً؛ وقاعدة طيّ الرفض (السؤال دائماً ورفض الانتظار
    // للمؤهل) قاعدة قراءة ردٍّ تطبقها بوابة القبول من حقول السجل نفسها
    final echoesCors = echoesCorsFor(origin);
    // نص الخطأ: توكن صحيح (على نافذة غير مقفولة — المقارنة أعلاه دليلها)
    // أو أصل مدرج؛ يُقرأ من السجل فلا مقارنة ثانية على أي طلب
    final verboseErrors = (tokenCompared && tokenMatched) || _isListed(origin);

    return _AdmissionDecision(
      rejection: rejection,
      acceptedPath: accepted,
      echoesCors: echoesCors,
      verboseErrors: verboseErrors,
      stampMs: now,
      key: key,
      tokenAttempt: tokenAttempt,
      tokenCompared: tokenCompared,
      tokenMatched: tokenMatched,
      // طابع الإخفاق تحت الميزانية حصراً: فوقها لا طابع جديد فالنافذة
      // تنكسر بالانتظار المعلن لا بفيض يعيد تسليحها
      tokenMissStamped: tokenCompared && !tokenMatched && !budgetSpent,
      tokenBudgetSpent: tokenCompared && !tokenMatched && budgetSpent,
      quotaLimit: beyond.quotaLimit,
      grantExisted: beyond.grantExisted,
      reachedAskTrim: beyond.reachedAskTrim,
      fireAsk: beyond.fireAsk,
      reportOnlyLine: beyond.reportOnlyLine,
      pairReplayKey: pairReplayKey.isEmpty ? null : pairReplayKey,
      pairFailure: pairFailure.isEmpty ? null : pairFailure,
    );
  }

  /// The after-the-token-layer projection into [out] - the acceptance order
  /// branch by branch (list, allow-all, discovery, explicit reject) with
  /// every state effect recorded, none performed.
  void _projectBeyondToken(
    String? origin,
    String key,
    String? fetchMode,
    String? fetchDest, {
    required int now,
    required bool mayAskConsent,
    required _BeyondOutcome out,
  }) {
    // (1) القائمة — المخزّن دائماً (موافقة الاكتشاف المحفوظة) قبل الأنماط
    if (_isListed(origin)) {
      final listedViaConsent =
          origin != null && _consents[key] == OriginConsent.allowAlways;
      // ترويستا الإرسال الحاضرتان بقيمة مخالفة نموذج مخفي أو إرسال
      // no-cors بلا شك — تُرفضان هنا كالمسارين المتصفحيين
      final mismatched = _fetchMetadataMismatch(fetchMode, fetchDest);
      if (mismatched != null) {
        out.rejection = mismatched;
        return;
      }
      final listedQuota = _policy.listedPerOriginPerMinute;
      if (listedQuota > 0) {
        final wouldReject = _quotaWouldReject(origin, listedQuota, now);
        out.quotaLimit = listedQuota;
        if (wouldReject != null) {
          if (!_policy.reportOnly) {
            out.rejection = wouldReject;
            return;
          }
          out.reportOnlyLine =
              'intake report-only: would reject — ${wouldReject.code}: '
              '${wouldReject.message} (origin=${originForLog(origin) ?? 'none'})';
        }
      }
      out.accepted = listedViaConsent
          ? IntakeAdmissionPath.savedConsent
          : IntakeAdmissionPath.listed;
      return;
    }

    // (2) مسار «الكل» — تحصيناته ملازمة له، والوضع المراقب يُعفّي الحصة
    // وحدها
    if (_policy.allowAllHardened) {
      final blocked = _browserRequestBlocked(origin, fetchMode, fetchDest);
      if (blocked != null) {
        out.rejection = blocked;
        return;
      }
      out.quotaLimit = _policy.perOriginPerMinute;
      final wouldReject = _quotaWouldReject(origin, null, now);
      if (wouldReject != null) {
        if (_policy.reportOnly) {
          out.reportOnlyLine =
              'intake report-only: would reject — ${wouldReject.code}: '
              '${wouldReject.message} (origin=${originForLog(origin) ?? 'none'})';
          out.accepted = IntakeAdmissionPath.allowAll;
          return;
        }
        out.rejection = wouldReject;
        return;
      }
      out.accepted = IntakeAdmissionPath.allowAll;
      return;
    }

    // (3) الاكتشاف — أصل متصفحي صالح غير مدرج يسأل المضيف مرة، وتحصينات
    // المتصفح أولا، والمنحة والسقوف بترتيبها القديم
    if (_policy.onUnknownOrigin != null &&
        origin != null &&
        origin.isNotEmpty &&
        _validBrowserOrigin(origin)) {
      final preBlocked = _browserRequestBlocked(origin, fetchMode, fetchDest);
      if (preBlocked != null) {
        out.rejection = preBlocked;
        return;
      }
      final remembered = _consents[key];
      if (remembered == OriginConsent.reject) {
        out.rejection = const IntakeRejection(
          403,
          'origin_declined',
          'The host declined this origin',
        );
        return;
      }
      // منحة سماح-مرة: طلب واحد خلال نافذتها القصيرة ثم تُستهلك —
      // والمنتهية تُستهلك أيضاً كاليوم ثم يعبر الطلب إلى السقوف
      final grant = _onceGrants[key];
      if (grant != null) {
        out.grantExisted = true;
        if (now <= grant) {
          out.accepted = IntakeAdmissionPath.onceGrant;
          return;
        }
      }
      if (_pendingAsks.length >= _maxPendingAsks) {
        out.rejection = const IntakeRejection(
          403,
          'origin_pending',
          'Too many consent windows are open — answer or dismiss '
              'them, then retry',
        );
        return;
      }
      out.reachedAskTrim = true;
      final liveFires = _liveAskFires(now);
      if (liveFires.length >= _maxAskFiresPerWindow) {
        final budgetWaitMs = _askBudgetWindowMs - (now - liveFires.first) + 500;
        out.rejection = IntakeRejection(
          403,
          'origin_pending',
          'Too many consent questions lately — retry after a short wait',
          retryAfterMs: budgetWaitMs < 1000 ? 1000 : budgetWaitMs,
        );
        return;
      }
      // الطلب المقفل لا يفتح سؤال موافقة جديداً
      if (!mayAskConsent) {
        out.rejection = const IntakeRejection(
          403,
          'origin_pending',
          'The origin is locked; no new consent question opens for it',
        );
        return;
      }
      out.fireAsk = true;
      out.rejection = const IntakeRejection(
        403,
        'origin_pending',
        'Consent requested — retry shortly after the host answers '
            '(see Retry-After)',
      );
      return;
    }

    // (4) لا مدرج ولا «كل» — الرفض الصريح بلا صمت
    if (_policy.onUnknownOrigin != null) {
      out.rejection = const IntakeRejection(
        403,
        'origin_unknown',
        'Origin is not listed and cannot be confirmed — '
            'no discovery callback is available for non-browser requests',
      );
      return;
    }
    out.rejection = const IntakeRejection(
      403,
      'origin_not_listed',
      'Origin is not on the allowed list',
    );
  }

  /// Lands the recorded decision's state effects - the exact mutations the
  /// old inline gate performed at this position, in the same order, driven
  /// by the recorded branch flags against the same (un interleave-able)
  /// state. Pure reads never reach here.
  void _applyDecision(_AdmissionDecision d, String? origin) {
    final now = d.stampMs;
    if (d.tokenAttempt) {
      // الجلب نفسه يجري إنشاء النافذة وكنسها الدوري كما في بوابة القديم،
      // والمطابقة تصفر النافذة، والإخفاق تحت الميزانية يُختم وفوقها لا
      // طابع جديد — والسطر الأمني المكبوح بالعدد يخرج للإخفاق فوق
      // الميزانية من هنا حصراً (التسوية) لا من الإسقاط الخالص
      final window = _tokenMissWindow(origin, now);
      if (d.tokenMatched) {
        window.clear();
      } else if (d.tokenMissStamped) {
        window.addLast(now);
      }
      if (d.tokenBudgetSpent) {
        _warnGuessBudget(origin, window);
      }
    }
    if (d.quotaLimit > 0) {
      // الحكم المسجل هو المعتمد: هذه الدالة هنا لأثرها (الطابع أو سحبه
      // مع التقليم والكنس الدوري) لا لحكمها
      _originQuotaVerdict(origin, d.quotaLimit, now);
    }
    if (d.grantExisted) {
      _onceGrants.remove(d.key);
    }
    if (d.reachedAskTrim) {
      // تقليم ميزانية الأسئلة الجديدة — نفس المشي من الأمام بنفس الشرط
      while (_askFireStamps.isNotEmpty &&
          now - _askFireStamps.first > _askBudgetWindowMs) {
        _askFireStamps.removeFirst();
      }
    }
    if (d.fireAsk) {
      _fireAsk(d.key, origin!);
    }
    final line = d.reportOnlyLine;
    if (line != null) {
      telemetry?.warn(line, category: BridgeCategory.security);
    }
  }

  /// The shared counter+log path: the protection's own rejections (from
  /// [IntakeAdmission.settle]) and the host-authority ones (via
  /// [IntakeAdmission.noteAuthorityReject]) alike.
  void _noteAuthority(String reason, String? origin) {
    _countRejection();
    logRejection(reason, origin);
  }

  /// Read-only peek at the live (unexpired) stamps of [origin]'s miss
  /// window - the same front-trim walk the mutating fetch performs, without
  /// creating the window or touching the sweep bookkeeping.
  List<int> _liveTokenMisses(String? origin, int now) {
    final Queue<int>? window = origin == null
        ? _anonTokenMisses
        : _tokenMissWindows[normalize(origin)];
    if (window == null) return const <int>[];
    final live = <int>[];
    var trimming = true;
    for (final ts in window) {
      if (trimming && now - ts > _tokenBudgetWindowMs) continue;
      trimming = false;
      live.add(ts);
    }
    return live;
  }

  /// The muted security line for a wrong-token request above the spent
  /// budget: at most one line per second, and the next admitted line
  /// carries the muted count — the flood lives in the window counter,
  /// not in the log. The line names the live attempt count, the unit
  /// (attempts within the last 60 seconds), and the truth that matters:
  /// the correct token is still accepted.
  static const _guessBudgetWarnPacingMs = 1000;
  int _nextGuessBudgetWarnMs = 0;
  int _suppressedGuessBudgetWarns = 0;

  void _warnGuessBudget(String? origin, Queue<int> window) {
    final now = _now;
    if (now < _nextGuessBudgetWarnMs) {
      _suppressedGuessBudgetWarns++;
      return;
    }
    final suppressed = _suppressedGuessBudgetWarns;
    _suppressedGuessBudgetWarns = 0;
    _nextGuessBudgetWarnMs = now + _guessBudgetWarnPacingMs;
    final suffix = suppressed > 0 ? ' (+$suppressed more suppressed)' : '';
    telemetry?.warn(
      'token guess budget spent: ${window.length} wrong token attempts '
      'within the last 60 seconds from origin=${originForLog(origin) ?? 'none'} '
      '— the correct token is still accepted; further wrong tokens answer '
      '429 token_locked until the window drains$suffix',
      category: BridgeCategory.security,
    );
  }

  /// Read-only peek at the per-origin quota verdict: the same front-trim,
  /// stamp, and compare the mutating quota call performs - no window
  /// creation, no sweep, no stamp.
  IntakeRejection? _quotaWouldReject(
    String? origin,
    int? limitOverride,
    int now,
  ) {
    if (origin == null) return null;
    final window = _originWindows[normalize(origin)];
    final limit = limitOverride ?? _policy.perOriginPerMinute;
    var live = 0;
    int? firstLive;
    var trimming = true;
    if (window != null) {
      for (final ts in window) {
        if (trimming && now - ts > _windowMs) continue;
        trimming = false;
        firstLive ??= ts;
        live++;
      }
    }
    if (live + 1 > limit) {
      // بقايا نافذة الحصة: أقدم طلب حي يخرج منها فتفرغ خانة للتابع
      final quotaWaitMs = firstLive == null
          ? _windowMs
          : _windowMs - (now - firstLive) + 500;
      return IntakeRejection(
        429,
        'origin_rate_limited',
        'Rate limit exceeded for this origin — retry after a short wait',
        retryAfterMs: quotaWaitMs < 1000 ? 1000 : quotaWaitMs,
      );
    }
    return null;
  }

  /// Read-only peek at the live ask-fire stamps - the same front-trim walk
  /// the mutating budget trim performs.
  List<int> _liveAskFires(int now) {
    final live = <int>[];
    var trimming = true;
    for (final ts in _askFireStamps) {
      if (trimming && now - ts > _askBudgetWindowMs) continue;
      trimming = false;
      live.add(ts);
    }
    return live;
  }

  /// The miss window a token attempt counts against: per-origin for web
  /// requests, the shared originless window for local integrations. The
  /// per-origin map is swept by idle entries at the same pacing as the
  /// quota windows (one pass at most, once a second at most).
  Queue<int> _tokenMissWindow(String? origin, int now) {
    if (origin == null) {
      while (_anonTokenMisses.isNotEmpty &&
          now - _anonTokenMisses.first > _tokenBudgetWindowMs) {
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
    while (window.isNotEmpty && now - window.first > _tokenBudgetWindowMs) {
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
            (ts == null || ts.isEmpty || now - ts.last > _tokenBudgetWindowMs);
        if (idle) {
          _tokenMissWindows.remove(oldest);
        } else {
          _tokenMissOrder.addLast(oldest);
        }
      }
    }
    return window;
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
            // خطاف حفظ الموافقة: قرار المستخدم للجلسة، والحفظ ملك المضيف —
            // محتوى الخطأ كما بقية الخطافات لا انهيار مسار الجواب
            _containHook(() {
              final hook = onConsentSave;
              if (hook == null) return null;
              hook(key, answer);
              return null;
            }, origin: key);
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
  /// branch, so a would-reject leaves no stamp either. [nowOverride] lets
  /// the settle path stamp with the projection's own clock reading.
  IntakeRejection? _originQuotaVerdict(
    String? origin, [
    int? limitOverride,
    int? nowOverride,
  ]) {
    if (origin == null) return null;
    final key = normalize(origin);
    final now = nowOverride ?? _now;
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
  /// Kept for hosts until the planned removal: the admission record
  /// carries the decision as [IntakeAdmission.echoesCors] instead.
  @Deprecated(
    'Read IntakeAdmission.echoesCors from the record built by admit() '
    '(removal planned in 0.3.0)',
  )
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

  /// Detailed host messages for the trusted only - a verified token or a
  /// listed origin; the allow-all path sees the code without the host text.
  /// One verdict per request: the comparison ran once in the projection and
  /// this decision reads the same outcome, so a verified sender keeps the
  /// host text whatever the miss-window history - the window is a signal
  /// about wrong guesses, never a refusal of the verified token.
  /// Kept for hosts until the planned removal: the admission record
  /// carries the decision as [IntakeAdmission.verboseErrors] - built with
  /// the single comparison [admit] already ran - so no caller compares a
  /// second time.
  @Deprecated(
    'Read IntakeAdmission.verboseErrors from the record built by admit() '
    '(removal planned in 0.3.0)',
  )
  bool verboseErrorsFor(String? origin, String? bridgeToken) {
    if (_token.isNotEmpty &&
        bridgeToken != null &&
        bridgeToken.isNotEmpty &&
        _fixedTimeEquals(bridgeToken, _token)) {
      return true;
    }
    return _isListed(origin);
  }

  /// A rejection from outside the protection patterns (host authorities) goes
  /// through the same counter and log path - denial is never silent.
  /// Kept for hosts until the planned removal: the admission record counts
  /// its own rejections on [IntakeAdmission.settle], and rejections decided
  /// outside the protection go through
  /// [IntakeAdmission.noteAuthorityReject].
  @Deprecated(
    'The admission record counts and logs its own rejections on settle(); '
    'for rejections decided outside the protection use '
    'IntakeAdmission.noteAuthorityReject (removal planned in 0.3.0)',
  )
  void noteRejection(String reason, [String? origin]) {
    _noteAuthority(reason, origin);
  }

  /// Writes one throttled security-log line for a rejection (the counter
  /// lives in [noteRejection]): at most one line per second, with the
  /// suppressed count folded into the next emitted line.
  /// Kept for hosts until the planned removal: the admission record writes
  /// its rejection line on settle, and
  /// [IntakeAdmission.noteAuthorityReject] routes the external ones here.
  @Deprecated(
    'The admission record writes the rejection line on settle(); for '
    'rejections decided outside the protection use '
    'IntakeAdmission.noteAuthorityReject (removal planned in 0.3.0)',
  )
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
    // خرائط الاقتران الثلاث تخرج مع الكائن: جلسات وسجلات وفهرس — لا بقاء
    // لحالة اقتران بعد الإغلاق، وذاكرة الإعادة رابعتها
    _pairingSessions.clear();
    _pairedRecords.clear();
    _pairingIdIndex.clear();
    _pairReplay.clear();
  }

  /// How many constant-time token comparisons this object has run since
  /// construction. Observability seam - the read-only counter that pins the
  /// admission contract "a token is compared at most once per request": the
  /// projection compares once and the record carries the outcome, so a full
  /// server request over the admission path lands exactly one here. A test
  /// reads deltas across requests; the wire behavior never reads it.
  int _tokenComparisons = 0;

  /// The read-only count of token comparisons so far - see
  /// [_tokenComparisons].
  int get tokenComparisonCount => _tokenComparisons;

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
    _tokenComparisons++;
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

/// Strong bridge-token generator - 32 random bytes from Random.secure in hex
/// (64 chars): no dependencies, and it meets the recommended strength bar.
String generateBridgeToken() {
  final rnd = Random.secure();
  return List.generate(
    32,
    (_) => rnd.nextInt(256),
  ).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// The verdict of one pairing-proof verification: either the verified
/// record with its replay key, or a named internal failure (and whether
/// that failure is the replay shape the wire answers
/// `pair_signature_replay` to).
class _PairCheck {
  _PairCheck.ok(_PairedRecord this.record, String this.replayKey)
    : fail = null,
      replay = false;

  _PairCheck.bad(String this.fail, {this.replay = false})
    : record = null,
      replayKey = null;

  final _PairedRecord? record;
  final String? replayKey;
  final String? fail;
  final bool replay;

  bool get ok => record != null;
}

/// One live pairing session - a displayed code and its expiry, plus the
/// wrong-attempt budget it absorbs (every wrong attempt anywhere is
/// charged here too).
class _PairingSession {
  _PairingSession(this.code, this.expiresAtMs);

  final String code;
  final int expiresAtMs;
  int wrongAttempts = 0;
}

/// One armed pairing binding - the token bound to the origin it paired
/// from, keyed by its digest in the maps. [pairingId] is derived from the
/// token digest alone, so a host restart that restores the token restores
/// the id with it.
class _PairedRecord {
  _PairedRecord({
    required this.origin,
    required this.token,
    required this.digest,
    required this.issuedAtMs,
    required this.expiresAtMs,
  });

  final String origin;
  final String token;
  final String digest;
  final int issuedAtMs;
  final int expiresAtMs;

  /// The public pairing identifier the page presents - the first 16 hex
  /// characters of sha256(token).
  String get pairingId => digest.substring(0, 16);
}

/// A short one-time pairing code the host displays to the user - what the
/// page sends (with its Origin) to receive its origin-bound token.
/// [expiresInSeconds] is the honest life of the offer.
class PairingOffer {
  /// Builds the offer - the protection constructs it, the host displays
  /// [code].
  const PairingOffer({required this.code, required this.expiresInSeconds});

  /// Six decimal digits from a secure random source - readable aloud,
  /// typeable from a screen.
  final String code;

  /// How long the offer lives, in seconds - after it the code is refused
  /// `pair_code_expired` and its session is gone.
  final int expiresInSeconds;
}

/// What the host is told when a page pairs - the origin that paired, the
/// pairing id the page will present, and the honest token lifetime. The
/// raw token itself travels through the save hook only: the host persists
/// it (its own storage), the package never writes a file.
class PairingInfo {
  /// Builds the info - the protection constructs it for [IntakeProtection.
  /// enablePairing]'s onPaired callback.
  const PairingInfo({
    required this.origin,
    required this.pairingId,
    required this.expiresInSeconds,
  });

  /// The normalized origin the bound token is locked to.
  final String origin;

  /// The public pairing identifier the page presents in
  /// `X-Bridge-Pairing` - derived from the token alone, so it survives a
  /// host restart whenever the token does.
  final String pairingId;

  /// The token's full lifetime in seconds (the host can revoke or rotate
  /// it earlier at any moment).
  final int expiresInSeconds;
}

/// The answer of one pairing attempt - either the rejection (status, code,
/// message on the wire) or the issued binding. Exactly one side is set.
class PairingOutcome {
  /// Builds a rejected attempt.
  const PairingOutcome.rejected(this.rejection)
    : token = null,
      pairingId = null,
      expiresInSeconds = null;

  /// Builds a paired attempt.
  const PairingOutcome.paired({
    required this.token,
    required this.pairingId,
    required this.expiresInSeconds,
  }) : rejection = null;

  /// The pairing gate's rejection - null when the attempt paired.
  final IntakeRejection? rejection;

  /// The origin-bound token (64 hex characters) - null on a rejection. It
  /// signs requests (never travels raw after pairing day), expires on its
  /// own, and is revocable and rotatable by the host.
  final String? token;

  /// The public pairing identifier for the token - null on a rejection.
  final String? pairingId;

  /// The token lifetime in seconds - null on a rejection.
  final int? expiresInSeconds;
}
