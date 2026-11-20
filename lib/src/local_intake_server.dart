import 'dart:async';
import 'dart:convert';
import 'dart:typed_data' show BytesBuilder;

import 'dart:io';

import 'bridge_config.dart';
import 'bridge_telemetry.dart';
import 'intake_invariants.dart';
import 'intake_protection.dart';
import 'intake_rejections.dart';
import 'trusted_command.dart';

/// Body over the byte cap - an internal exception that tells the 413 reject
/// apart from other read errors, so the intake replies with the honest code, never a silent truncation.
class _BodyTooLargeException implements Exception {
  const _BodyTooLargeException();
}

/// The outcome of one body read: either a complete body, or the rejection
/// error - which is only handed back AFTER the unread remainder was
/// drained (or the bounded patience ran out): closing over unread data
/// makes the framework destroy the connection, and Linux and macOS answer
/// that destroy with a reset that throws the reply away.
class _BodyOutcome {
  _BodyOutcome.ok(this.body) : error = null;
  _BodyOutcome.rejected(this.error) : body = null;

  final String? body;
  final Object? error;
}

/// A known JSON shape that is not a usable command envelope (a Map with no
/// known wrapper keys, or one carrying more than one of them at once - an
/// ambiguous envelope that must not be resolved silently by the key order):
/// an honest reject with its own code, not a misleading empty_payload for a
/// non-empty body.
class _UnsupportedPayloadShapeException implements Exception {
  const _UnsupportedPayloadShapeException();
}

/// The bridge's own handler budget - a private marker thrown by the budget
/// timeout alone, never by a handler: a TimeoutException raised inside the
/// handler itself keeps the plain internal-error path instead of a misleading
/// gateway-timeout reply with orphan bookkeeping it never used.
class _HandlerBudgetExceeded implements Exception {
  const _HandlerBudgetExceeded();
}

/// Failure to reserve any listen port - a plain [Exception]: a failed bind
/// is an environmental condition (another process holds the ports), caught
/// by `on Exception` handlers without the Error semantics Dart reserves
/// for programming mistakes.
class IntakeBindException implements Exception {
  /// Builds the exception; [message] names the failed bind and the last
  /// error seen across the tried ports.
  IntakeBindException(this.message);

  /// A failed port bind is an environmental condition (another process
  /// holds the ports), not a programming mistake - Dart Errors are not
  /// meant to be caught, so this stays a plain Exception for `on Exception`
  /// handlers.
  final String message;

  @override
  String toString() => 'IntakeBindException: $message';
}

/// Internal reusable warning throttle: the first message of each time
/// window is admitted and everything else arriving inside the window is
/// muted, and the next admitted message carries the muted count so the
/// flood's size stays visible in the log. The clock is injected, so tests
/// drive the windows deterministically. Internal - no option exposes it.
class _WarnThrottle {
  _WarnThrottle({required int Function() nowMs, required int windowMs})
    : _nowMs = nowMs,
      _windowMs = windowMs,
      // ما قبل الأبدية: أول نداء يمر حتماً على أي ساعة غير سالبة
      _lastAdmitMs = -windowMs;

  final int Function() _nowMs;
  final int _windowMs;
  int _lastAdmitMs;

  /// The count muffled inside the current window, carried by the next
  /// admitted line.
  int _muted = 0;

  /// Returns the line to warn now - [message] itself for the first hit of
  /// a window, [message] plus the muted count once the window has elapsed -
  /// or null while the window still holds.
  String? admit(String message) {
    final now = _nowMs();
    if (now - _lastAdmitMs < _windowMs) {
      _muted++;
      return null;
    }
    final muted = _muted;
    _muted = 0;
    _lastAdmitMs = now;
    return muted == 0 ? message : '$message (+$muted more suppressed)';
  }
}

/// A local HTTP intake server for external portals.
///
/// Listens on 127.0.0.1 only (no network exposure) on a configurable port
/// with fallbacks when busy, and answers with CORS headers for the origins it
/// allowed, so portal https pages can send commands straight from the
/// browser. Errors always come back with clear messages - no silent failure.
///
/// Resource limits (body cap / timeout / seat cap) apply in every protection
/// mode - even allow-all - because they are what makes accepting any site memory-safe.
class LocalIntakeServer {
  /// Builds the server. [onCommand], [telemetry], and
  /// [correlationIdGenerator] are required; [protection] defaults to an
  /// [IntakeProtection] wired to this server's telemetry, and [config]
  /// defaults to `const BridgeConfig()`. Non-positive caps or timeouts -
  /// in [config], [requestTimeout], or [handlerTimeout] - throw
  /// [ArgumentError] here at construction, never as mystery rejects on
  /// the wire. [nowMs] is an injectable monotonic test clock.
  LocalIntakeServer({
    int Function()? nowMs,
    required this.onCommand,
    required this.telemetry,
    required this.correlationIdGenerator,
    IntakeProtection? protection,
    this.config = const BridgeConfig(),
    this.requestTimeout,
    this.handlerTimeout,
  }) : _nowMs = nowMs,
       protection = protection ?? IntakeProtection(telemetry: telemetry) {
    _validateLimits();
  }

  /// Non-positive caps and timeouts are rejected loudly here: each of them
  /// would otherwise fail every request in its own silent way (a zero element
  /// cap rejects all container bodies, a zero seat cap answers 503 to
  /// everyone, a zero timeout cuts every request short), and a configuration
  /// mistake must surface at construction, not as mystery rejects on the wire.
  void _validateLimits() {
    void require(bool ok, String name, Object? value) {
      if (!ok) {
        throw ArgumentError.value(value, name, 'must be positive');
      }
    }

    require(
      config.maxBodyBytes > 0,
      'config.maxBodyBytes',
      config.maxBodyBytes,
    );
    require(
      config.maxConcurrentRequests > 0,
      'config.maxConcurrentRequests',
      config.maxConcurrentRequests,
    );
    require(
      config.maxJsonElements > 0,
      'config.maxJsonElements',
      config.maxJsonElements,
    );
    require(
      config.maxJsonDepth > 0,
      'config.maxJsonDepth',
      config.maxJsonDepth,
    );
    require(
      config.requestTimeout > Duration.zero,
      'config.requestTimeout',
      config.requestTimeout,
    );
    require(
      config.idleTimeout > Duration.zero,
      'config.idleTimeout',
      config.idleTimeout,
    );
    if (requestTimeout != null) {
      require(
        requestTimeout! > Duration.zero,
        'requestTimeout',
        requestTimeout,
      );
    }
    require(
      config.handlerTimeout > Duration.zero,
      'config.handlerTimeout',
      config.handlerTimeout,
    );
    if (handlerTimeout != null && handlerTimeout!.isNegative) {
      throw ArgumentError.value(
        handlerTimeout,
        'handlerTimeout',
        'must not be negative - Duration.zero is the named '
            'noHandlerTimeout constant (no deadline), and a positive value '
            'is the budget itself',
      );
    }
  }

  /// Called with every trusted command the package hands to the registered host.
  final TrustedCommandHandler onCommand;

  /// The measurement and log seam: the host adapts its own logger, keeping
  /// intake latency and classification alive.
  final BridgeTelemetry telemetry;

  /// Correlation-id generator - required with no default: the host passes its own.
  final String Function() correlationIdGenerator;

  /// Optional intake protection (open/allowlist/token) - read live on every
  /// request so a settings change takes effect without restarting the listener.
  /// The default one is built with this server's telemetry so its security
  /// log (allow-all warnings, rejection lines) is not muted; a passed one
  /// carrying no telemetry warns once at [start] with directions to wire it.
  final IntakeProtection protection;

  /// The total pre-handler deadline and the full-body receive timeout -
  /// injected directly for tests; the default comes from
  /// config.requestTimeout (the value's single source of truth).
  final Duration? requestTimeout;

  /// The effective timeout: the parameter when given, else the package setting.
  late final Duration effectiveTimeout =
      requestTimeout ?? config.requestTimeout;

  /// The explicit "no handler deadline" marker: pass it to [handlerTimeout]
  /// to run handlers unbounded - the pre-0.2.0 meaning of null, which now
  /// selects the configured default budget instead. The value is
  /// `Duration.zero`; a zero budget would cut every handler instantly, so
  /// the value itself carries no other meaning and the constant owns it
  /// honestly. A negative duration stays an [ArgumentError] at
  /// construction.
  static const Duration noHandlerTimeout = Duration.zero;

  /// Host-side handler budget - the deadline over the command handler
  /// itself. Three states:
  /// - null (the default): the configured budget applies -
  ///   [BridgeConfig.handlerTimeout] (30 seconds shipped). A handler
  ///   running past the budget is answered `504 handler_timeout`, its
  ///   seat is freed, and the still-running work becomes a counted
  ///   orphan; [stop] awaits orphans up to the same budget and the
  ///   remainder is announced and reported, never silently outliving the
  ///   stop.
  /// - [noHandlerTimeout] (the named constant, `Duration.zero`): no
  ///   handler deadline at all - the pre-0.2.0 null meaning, kept
  ///   available under an explicit name for hosts whose commands may
  ///   legitimately run unbounded.
  /// - any positive duration: that budget.
  /// A negative value throws [ArgumentError] at construction. A
  /// `TimeoutException` raised inside the handler itself is NOT a budget
  /// expiry: it keeps the plain internal-error path (the bridge budget
  /// carries its own private marker), and a late result (if one arrives)
  /// is dropped with no orphan error - Dart does not cancel futures, and
  /// the response settled first.
  final Duration? handlerTimeout;

  /// The handler budget in force: the explicit parameter when given (the
  /// [noHandlerTimeout] constant meaning none), else the configured
  /// default [BridgeConfig.handlerTimeout]. The single read for every
  /// budget decision - the 504 reply, the orphan accounting, and the
  /// stop-time orphan grace all derive from it.
  Duration? get effectiveHandlerTimeout {
    final explicit = handlerTimeout;
    if (explicit == null) return config.handlerTimeout;
    if (explicit == Duration.zero) return null;
    return explicit;
  }

  /// Injectable defaults - caps, idle time, and extraHosts authorities; the
  /// single source of truth for the numbers (no duplicated static constants).
  final BridgeConfig config;

  /// Local host authorities - computed at bind time from the actual port.
  Set<String> _authorities = const <String>{};

  /// A monotonic clock owned by the server - every body deadline derives from
  /// it, so system clock jumps neither kill the absolute guard nor extend it.
  /// An injectable test clock (body timeout and id-warning throttle); the
  /// default is an internal monotonic one.
  final int Function()? _nowMs;
  final Stopwatch _clock = Stopwatch()..start();
  int get _now => _nowMs?.call() ?? _clock.elapsedMilliseconds;

  /// The cap label for 413 messages - derived from the setting: the default
  /// reads "1 MiB" verbatim, so the wire changes only when the setting itself
  /// does.
  late final String _mbLabel =
      config.maxBodyBytes >= 1024 * 1024 &&
          config.maxBodyBytes % (1024 * 1024) == 0
      ? '${config.maxBodyBytes ~/ (1024 * 1024)} MiB'
      : '${config.maxBodyBytes}B';

  /// Bounded patience for discarding an unread body after an early
  /// rejection, never longer than the request timeout it lives under.
  static const _discardPatience = Duration(seconds: 2);
  late final Duration _discardWindow = effectiveTimeout < _discardPatience
      ? effectiveTimeout
      : _discardPatience;
  int get _discardBudgetBytes => config.maxBodyBytes * 4;

  /// The short yield between the total deadline firing and the connection
  /// cut: the body's own absolute deadline (the same value, armed moments
  /// after this one) owns the body-read phase and answers `408` first, so
  /// the cut waits this long and lands only if the request still hangs
  /// past it. Internal - no option exposes it.
  static const _totalCutYield = Duration(milliseconds: 250);

  /// Safety net for every managed close: a close that has not completed
  /// within the drain window gets its socket detached and destroyed - the
  /// same pattern the total deadline cut uses (a short yield, then the cut,
  /// and a close that already claimed the socket keeps its course
  /// untouched). A clean reply never reaches this: the body was consumed
  /// and the error body is small. Internal - no option exposes it.
  late final Duration _closeGuardWindow = _discardWindow;

  int _activeRequests = 0;

  /// Handlers still running after their request already timed out (504) and
  /// left - the seat model does not see them, but the work is real: a local
  /// Dart app's command could outlive stop() unless counted. Seats plus
  /// orphans are one live-work budget, and stop() drains the orphans up to
  /// the handler budget.
  int _orphanHandlers = 0;

  /// Armed when stop() arrives while orphans still run - completed when the
  /// last orphan settles.
  Completer<void>? _orphanDrain;

  /// An in-progress start guards the race: two parallel start calls would both
  /// see no server and bind two - the first leaking live with no reference.
  bool _starting = false;

  /// The future of the in-progress start - stop awaits it so a live server is
  /// never orphaned behind a stop that returned before the bind settled.
  Future<int>? _startingFuture;

  /// Armed when stop arrives mid-start - completes when the last seat drains.
  Completer<void>? _drain;

  /// Set for the whole drain of a stop (seats and orphans) - a start called
  /// in that window awaits it before binding, so the new generation never
  /// shares the seat counter with the old one mid-drain.
  Future<void>? _stoppingFuture;

  HttpServer? _server;
  int _port = 0;

  /// The bound port while listening, and `0` when not - including after a
  /// `start()` that failed on a post-bind step: a stale bound number would
  /// point callers at a listener that no longer exists.
  int get port => _port;

  /// Whether a bound server is live right now: true between a successful
  /// [start] and the [stop] that unbinds it, false before, during a
  /// failing start, during a drain, and after a mid-start failure whose
  /// orphan was closed. [port] is 0 whenever this is false.
  bool get isListening => _server != null;

  /// Starts listening - tries the preferred port, then the fallbacks.
  ///
  /// The returned future rejects with [IntakeBindException] (a plain
  /// Exception - a failed bind is an environmental condition) when every
  /// port fails, and with [StateError] when already listening or mid-start.
  /// When a previous [stop] is still draining (in-flight replies, or
  /// orphaned handlers awaiting their grace), start waits for that drain to
  /// settle before binding - the generations never share the seat counter.
  /// With a handler budget in force (the default, or an explicit value)
  /// that wait is bounded by the orphan grace: the budget frees stuck
  /// seats with `504` and [stop] retires whatever orphans remain at its
  /// return, so a restart never inherits the previous generation's
  /// orphans into its own live-work budget. Only the explicit
  /// [noHandlerTimeout] constant makes a never-completing handler hold
  /// the drain - and a start called during it - until the handler
  /// settles. Every rejection travels through the
  /// returned future - none is thrown synchronously - so
  /// `start(...).catchError(...)`, `start(...).then(..., onError: ...)`
  /// and `await start(...)` inside a `try/catch` all observe the same
  /// contract on every path.
  Future<int> start({
    required int preferredPort,
    List<int> fallbacks = const [],
  }) {
    if (_server != null || _starting) {
      // The rejection travels through the returned future, never thrown
      // synchronously: a synchronous throw escapes a caller's
      // .catchError/.then(onError) on the result - there is no result to
      // attach them to. The StateError contract is identical on every path.
      return Future<int>.error(
        StateError(
          _server != null
              ? 'intake server already listening on port $_port'
              : 'intake server start already in progress',
        ),
        StackTrace.current,
      );
    }
    _starting = true;
    Future<int> started;
    try {
      started = telemetry.measure<int>('intake.start', () async {
        // فراغ جارٍ: البدء ينتظر تخلّي الجيل القديم كاملاً (مقاعده
        // ويتاماه) قبل الربط — جيلان يتشاركان عدّاد المقاعد يجعلان
        // طلبات الجيل الجديد تُرد 503 بلا انشغال حقيقي. بلا ميزانية
        // معالج ومعالج لا يكمل لا يتحرر المقعد أبداً فيعلق البدء هنا
        // إلى الأبد — والانتظار بنمط _startingFuture الذي ينتظر به
        // stop البدءَ الجاري.
        final draining = _stoppingFuture;
        if (draining != null) {
          await draining;
        }
        final candidates = [preferredPort, ...fallbacks];
        Object? lastError;
        for (final candidate in candidates) {
          try {
            _server = await HttpServer.bind(
              InternetAddress.loopbackIPv4,
              candidate,
            );
            // المنفذ الفعلي المُسند (يُصحّح عيب إعادة 0 عند طلب منفذ عشوائي
            // — والطلب الصريح يساوي الفعلي فلا فرق سلكياً)
            _port = _server!.port;
            _authorities = computeAuthorities(_port, config.extraHosts);
            _warnExtraHosts(config.extraHosts);
            // سجل الحماية الصامت: حماية ممررة بلا مرصد تبتلع تحذيرات
            // الأمن (allow-all وأسطر الرفض) في null — الخادم يقولها مرة
            // واحدة بمرصده هو مع طريق الوصل، أما الافتراضية فبُنيت
            // بمرصد الخادم نفسه فلا تحذير عليها.
            if (protection.telemetry == null) {
              telemetry.warn(
                'intake protection carries no telemetry — its security log '
                'is muted; pass the same telemetry to '
                'IntakeProtection(telemetry: ...) that you gave the server',
                category: BridgeCategory.security,
              );
            }
            // الاتصالات بلا طلب نشط (keep-alive صامتة أو توقف المرسل قبل
            // اكتمال الترويسات) تُغلق بعد المهلة بدل حجزها إلى الأبد؛
            // جسم طلب نشط تحرسه [requestTimeout] أعلى
            _server!.idleTimeout = config.idleTimeout;
            _server!.listen(
              _handle,
              onError: (Object error) => telemetry.error(
                'intake server error',
                error: error,
                category: BridgeCategory.network,
              ),
            );
            telemetry.info(
              'intake listening on 127.0.0.1:$_port'
              '${candidate != preferredPort ? " (fallback)" : ""}',
              category: BridgeCategory.network,
            );
            return _port;
          } catch (e) {
            lastError = e;
            // المستمع اليتيم: الربط نجح ثم رمت خطوة إقلاع لاحقة (تحذير
            // الحماية أو listen أو سطر الإقلاع) — المقبس يبقى يستمع بلا
            // مرجع بعد إحلال المرشح التالي، وإن فشل كل المرشحين بقي
            // _server غير صفري فيصطدم الإقلاع التالي بـStateError. أغلق
            // المربوط وأصفّر الحالة قبل المرشح التالي.
            final orphan = _server;
            if (orphan != null) {
              _server = null;
              // والمنفذ يتبع الخادم إلى الصفر: رقم قديم فوق خادم لم
              // يعد موجوداً كذبة يستند إليها المستدعي (عقد port)
              _port = 0;
              await orphan.close(force: true);
            }
            telemetry.warn(
              'port $candidate unavailable (${e.runtimeType}), '
              'trying fallback',
              category: BridgeCategory.network,
            );
          }
        }
        throw IntakeBindException('failed to bind any listen port: $lastError');
      });
    } catch (_) {
      // measure نفسها رمت متزامنة (تنفيذ مضيف معطوب) — لا نحبس الحارس
      _starting = false;
      rethrow;
    }
    _startingFuture = started;
    return started.whenComplete(() {
      _starting = false;
      _startingFuture = null;
    });
  }

  /// Stops listening - a graceful close, not an amputation: listening stops at
  /// once, in-flight replies finish (force used to cut them mid-send), then
  /// the seats are awaited until drained; orphaned handlers (timed out of
  /// their seat but still running) are awaited up to the handler budget and
  /// the remainder is announced instead of silently outliving the stop. A
  /// [start] issued while this drain is still running waits for it, so the
  /// new generation binds only after the old one has fully stopped.
  Future<void> stop() async {
    // بداية جارية: ينتظر حسمها أولا — الرد
    // الفوري يدع الربط يكتمل خادما يتيما بعد عودة stop
    final pendingStart = _startingFuture;
    if (pendingStart != null) {
      try {
        await pendingStart;
      } catch (_) {
        // فشل البدء: لا خادم لإيقافه — الحسم وحده مقصود
      }
    }
    // فراغ جارٍ من نداء آخر: ينضم لمستقبله بدل أن يمشي المسار ثانية —
    // المسلّحان المشتركان (_drain و_orphanDrain) لا يُطحنان
    final inFlight = _stoppingFuture;
    if (inFlight != null) {
      return inFlight;
    }
    // مستقبل الفراغ يُسلَّح قبل أول انتظار: بداية تستدعى في نافذة
    // الفراغ تنتظره كاملاً — لا يربط جيل جديد فوق كشّاف لم يفض ولا
    // يتشارك عدّاد المقاعد مع الجيل القديم
    final settled = Completer<void>();
    _stoppingFuture = settled.future;
    try {
      final server = _server;
      _server = null;
      _port = 0;
      await server?.close();
      while (_activeRequests > 0) {
        // أعد استخدام المسلح: نداءان متداخلان لstop
        // يطحن الثاني _drain فيبقى الأول معلقا على مستقبل لا يكتمل
        final drained = _drain ??= Completer<void>();
        await drained.future;
        _drain = null;
      }
      _drain = null;
      // اليتامى: مقاعدهم فرغت برد 504 لكن عملهم حي — stop ينتظرهم
      // حتى الميزانية الفعالة نفسها (الافتراضية من config أو الصريحة)،
      // والباقي فوقها يُعلن بعدّه لا يُترك صامتا
      final grace = effectiveHandlerTimeout;
      if (_orphanHandlers > 0 && grace != null) {
        final orphaned = _orphanDrain ??= Completer<void>();
        try {
          await orphaned.future.timeout(grace);
        } on TimeoutException {
          telemetry.warn(
            'intake stopped with $_orphanHandlers orphan handler(s) still '
            'running',
            category: BridgeCategory.network,
          );
        }
      }
    } finally {
      _stoppingFuture = null;
      settled.complete();
    }
  }

  /// One orphaned handler settled - ring the drain bell when it was the last.
  void _orphanSettled() {
    _orphanHandlers--;
    if (_orphanHandlers <= 0) {
      _orphanHandlers = 0;
      final bell = _orphanDrain;
      _orphanDrain = null;
      bell?.complete();
    }
  }

  /// The internal Origin length cap, not a public option: every real
  /// browser origin (scheme, host, port) sits far below it, while an
  /// unbounded value becomes a map key, a consent question, a handler
  /// field, and a telemetry context before any policy decision sees it.
  /// Over the cap the value is refused here - before the single-header
  /// gate makes any CORS decision and before anything else reads it.
  static const _maxOriginChars = 1024;

  /// The internal `X-Bridge-Pairing` length cap in UTF-8 bytes: a well
  /// formed proof is `id.stamp.signature` - 16 hex, up to 16 digits, and a
  /// 64-hex signature, plus the two separators - sitting far below this
  /// ceiling; anything over it is a hostile value refused before any
  /// parsing. Gated on the pairing layer being armed, like the header's
  /// other gates.
  static const _maxPairingHeaderBytes = 256;

  /// The pairing route - the one path the intake answers specially while
  /// the pairing layer is armed. Disarmed, it is no path at all: it rides
  /// the ordinary non-root behavior (a warning and the handler), wire
  /// letter identical to previous releases.
  static const _pairingPath = '/pair';

  /// The internal `X-Bridge-Token` length cap in UTF-8 bytes (not
  /// characters): the constant-time comparison in the protection layer runs
  /// over the configured secret, so a bloated token is nothing but wasted
  /// work for the intake - refused here before any comparison, any token
  /// miss window, any rejection counter, and any policy decision. A wire
  /// shape reject like `origin_too_long`: outside the protection counter
  /// and its log, no CORS echo. The Origin gates settle first - a request
  /// carrying both a hostile Origin and an oversized token answers from the
  /// Origin gate - and this gate precedes the single-value header gate and
  /// the method gate, the same order the Origin gates keep. Real tokens
  /// (`generateBridgeToken` produces 64 hex characters) sit far below it.
  static const _maxTokenHeaderBytes =
      IntakeProtection.maxBridgeTokenHeaderBytes;

  /// The pacing window in milliseconds for every throttled warning line
  /// (the reserved-path observation, the seat-busy reject, the
  /// orphan-budget reject, the handler timeout, and the total-deadline
  /// cut): at most one line per second of the injected clock, and the
  /// next admitted line carries the muted count. Internal - no option
  /// exposes it.
  static const _warnThrottleWindowMs = 1000;

  /// The cap on the request path inside a warning line: control characters
  /// in the C0 and C1 ranges are stripped and the rest capped at this many
  /// characters, so a bloated or forged request line cannot inflate the
  /// throttled warning. Internal - no option exposes it.
  static const _maxWarnedPathChars = 128;

  /// The throttle for the reserved-path warning - owned by this server
  /// instance so the injected clock drives it deterministically.
  late final _WarnThrottle _pathWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );

  /// One throttle per warning position so a flood at one position never
  /// mutes another: the seat-busy reject, the orphan-budget reject, the
  /// handler timeout, and the total-deadline cut. Each is owned by this
  /// server instance so the injected clock drives them deterministically.
  late final _WarnThrottle _busyWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );
  late final _WarnThrottle _orphanBusyWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );
  late final _WarnThrottle _handlerTimeoutWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );
  late final _WarnThrottle _totalDeadlineWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );

  /// One throttle for the legacy-token-header warning so its flood never
  /// mutes another position's line: the first request carrying the retired
  /// header name admits the line, the rest of its window is muted, and the
  /// next admitted line carries the muted count.
  late final _WarnThrottle _legacyTokenHeaderWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );

  /// The warn-line form of a request path: control characters in the C0
  /// and C1 ranges are stripped so a hostile request line cannot forge
  /// extra log lines, and the result is capped at [_maxWarnedPathChars]
  /// so a bloated path cannot inflate the throttled warning.
  static String _pathForWarn(String path) {
    final cleaned = String.fromCharCodes(
      path.runes.where(
        (r) => !(r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F)),
      ),
    );
    return cleaned.length > _maxWarnedPathChars
        ? cleaned.substring(0, _maxWarnedPathChars)
        : cleaned;
  }

  Future<void> _handle(HttpRequest request) async {
    final response = request.response;
    _corsHeaders(response);
    // رد HEAD بلا جسم: الطلب الوحيد الذي يُحظر فيه المحتوى على السلك —
    // كل ردود المقبس الخام له تحمل الرأس وحده (التأطيرية تبقى للعلم)
    final headOnly = request.method == 'HEAD';
    try {
      // سقف طول الأصل: القيمة يتحكم فيها الخصم وتصير مفاتيح خرائط
      // وأسئلة موافقة وحقول معالج وسياق قياس قبل أي قرار سياسة —
      // الأطول من السقف يُرد هنا قبل أن يراه أي كود آخر. رفض شكل
      // بروتوكولي كترويسة مكررة: خارج عدّاد الحماية وسجلها، وبلا
      // قرار CORS على هذا الطريق حصراً (لا صدى قبل الرفض).
      final earlyOrigin = _firstHeader(request, 'Origin');
      if (earlyOrigin != null && earlyOrigin.length > _maxOriginChars) {
        response.headers.set(
          'X-Correlation-Id',
          _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
        );
        await _replyRejection(
          response,
          code: 'origin_too_long',
          message:
              'Origin header exceeds the allowed length '
              '($_maxOriginChars characters)',
          bodyFullyRead: false,
          headOnly: headOnly,
        );
        return;
      }
      // بوابة شكل الأصل: المتصفح لا يرسل إلا scheme://host[:port] وما
      // بعدها شرطات ختامية يحدثها التطبيع — معلومات المستخدم والمسار
      // والاستعلام والجزء والمسافات ومحارف التحكم قيمة يصنعها الخصم لا
      // صفحة، فتُرد هنا قبل أي خريطة أو سطر سجل أو نداء موافقة أو صدى
      // CORS أو سياق قياس. رفض شكل بروتوكولي كسقف الطول قبله: خارج
      // عدّاد الحماية وسجلها. حسم الترتيب بين الرفضين: المعتل طولاً
      // وشكلاً معاً يُجاب origin_too_long. والقيمة الحرفية null
      // (وغياب الترويسة) بمعاملتهما اليوم خارج هذه البوابة.
      if (earlyOrigin != null &&
          earlyOrigin.isNotEmpty &&
          earlyOrigin != 'null' &&
          !IntakeProtection.isWellFormedOrigin(earlyOrigin)) {
        response.headers.set(
          'X-Correlation-Id',
          _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
        );
        await _replyRejection(
          response,
          code: 'origin_malformed',
          message: 'Origin header must be scheme://host[:port]',
          bodyFullyRead: false,
          headOnly: headOnly,
        );
        return;
      }
      // الاسم المتقاعد لا يُقبل قبولاً: من يحمله وحده يُعامل كطلب بلا
      // توكن فلا تبلغ قيمته خطوة القبول إطلاقاً، وسطر تحذير مكبوح واحد
      // في النافذة يسمّي الاسم الجديد فيعرف المطور سبب رفض توكنه —
      // الكبح بنمط بقية أسطر التحذير: سطر واحد في الثانية كأقصى والعقد
      // التالي يحمل عدد المكتوم. ذكر الاسم المتقاعد هنا كشفُه حصراً:
      // هذان الموضعان هما الوحيدان المسموح لهما بحمل الاسم في lib كله
      final legacyTokenHeader = _firstHeader(request, 'X-Portal-Token');
      if (legacyTokenHeader != null) {
        final line = _legacyTokenHeaderWarnThrottle.admit(
          'the X-Portal-Token header is not accepted — send the token in '
          'X-Bridge-Token',
        );
        if (line != null) {
          telemetry.warn(line, category: BridgeCategory.security);
        }
      }
      // سقف طول ترويسة التوكن: القيمة المبالغ فيها تبلغ المقارنة
      // الزمنية-الثابتة فتكلّف حلقة بطولها في كل طلب — تُرد هنا قبل أي
      // مقارنة أو نافذة إخفاق أو عدّاد رفض أو قرار سياسة. الحساب بايتات
      // UTF-8 لا محارف، وردُّها بنمط أخويه من بوابتي الأصل: رفض شكل
      // بروتوكولي خارج العدّاد والسجل وبلا صدى CORS، وبوابتا الأصل
      // تحكمان قبله فالمعتل في الترويستين معاً يُجاب من بوابة الأصل
      final earlyToken = _firstHeader(request, 'X-Bridge-Token');
      if (earlyToken != null &&
          utf8.encode(earlyToken).length > _maxTokenHeaderBytes) {
        response.headers.set(
          'X-Correlation-Id',
          _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
        );
        await _replyRejection(
          response,
          code: 'token_too_long',
          message:
              'X-Bridge-Token header exceeds the allowed length '
              '($_maxTokenHeaderBytes bytes)',
          bodyFullyRead: false,
          headOnly: headOnly,
        );
        return;
      }
      // سقف ترويسة توقيع الاقتران بنمط أخيه التوكن: القيمة المتضخمة لا
      // تبلغ أي محلل أو مقارنة — والبوابة بشرط تفعيل الاقتران حصرا فالخامل
      // سلكه حرفا كما هو (الترويسة مجهولة لا تقرأ في الإعداد الافتراضي)
      final earlyPairing = _firstHeader(request, 'X-Bridge-Pairing');
      if (protection.pairingEnabled &&
          earlyPairing != null &&
          utf8.encode(earlyPairing).length > _maxPairingHeaderBytes) {
        response.headers.set(
          'X-Correlation-Id',
          _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
        );
        await _replyRejection(
          response,
          code: 'pairing_too_long',
          message:
              'X-Bridge-Pairing header exceeds the allowed length '
              '($_maxPairingHeaderBytes bytes)',
          bodyFullyRead: false,
          headOnly: headOnly,
        );
        return;
      }
      // مدخل القبول الواحد: مرة واحدة لكل طلب، بعد بوابات الشكل وقبل أي
      // قراءة أخرى للحماية — الإسقاط خالص لا يخلف أثراً فالمهيّأ
      // (OPTIONS) والطريقة المخالفة والمنشغل والمرفوض بالمضيف يمرّون
      // بلا طوابع ولا أسئلة ولا سطور كما اليوم، ومن يقرأ قراراً
      // متعلقاً بالحماية بعد هنا يقرأ السجل وحده (صدى CORS ونص الخطأ
      // ومسار القبول والرفض) ولا يلمس كائن الحماية ثانية
      final admission = await protection.admit(
        origin: earlyOrigin,
        bridgeToken: earlyToken,
        fetchMode: _firstHeader(request, 'Sec-Fetch-Mode'),
        fetchDest: _firstHeader(request, 'Sec-Fetch-Dest'),
        path: request.uri.path,
        // إثبات الاقتران وحقائق توقيعه يمرران كما وردا — canonical
        // التوقيع يربط الطريقة ومعرف الارتباط بالقيمة الواردة الخام لا
        // المنظفة، فالصفحة توقع على ما أرسلت لا على ما أعاد الخادم
        pairingProof: earlyPairing,
        method: request.method,
        correlationId: _firstHeader(request, 'X-Correlation-Id') ?? '',
      );
      // الترويسات أحادية الدلالة: تعدد قيمها طلب ملغوب صريح
      // 400 وقطع، بدل استثناء valueغير الملتقط الذي يعلق المقبس بلا
      // رد أصلا. Host مستثنى: محلل dart يطويه. وترويسة توقيع الاقتران
      // تنضم للقائمة عند تسليح الطبقة حصرا — الخامل لا يقرأها أصلا
      for (final name
          in protection.pairingEnabled
              ? const [
                  'x-correlation-id',
                  'origin',
                  'x-bridge-token',
                  'x-bridge-pairing',
                ]
              : const ['x-correlation-id', 'origin', 'x-bridge-token']) {
        if ((request.headers[name] ?? const <String>[]).length > 1) {
          // كل رفض يحمل معرف ارتباط — هنا توليد دائم لأن القيمة
          // الواردة نفسها هي الملغوبة
          response.headers.set('X-Correlation-Id', correlationIdGenerator());
          _echoCors(
            response,
            _firstHeader(request, 'Origin'),
            admitted: admission.echoesCors,
          );
          await _replyRejection(
            response,
            code: 'duplicate_header',
            message:
                'Header "$name" was sent more than once — send '
                'exactly one value',
            bodyFullyRead: false,
            headOnly: headOnly,
          );
          return;
        }
      }

      // سلطات المضيف المحلي: الحارس الواحد فوق كل الطرق — يغطي
      // OPTIONS و405 وما بعدهما؛ لا يحجز مقعداً؛ والمنع غير صامت (شرط
      // صريح): يمر بمسار العدّاد والسجل الأمني نفسه.
      final verdict = checkAuthority(
        hostHeader: _firstHeader(request, HttpHeaders.hostHeader),
        requestUriIsAbsolute: request.uri.isAbsolute,
        authorities: _authorities,
      );
      if (verdict != AuthorityVerdict.allow) {
        // حادثة كاملة: الرفض يحمل معرف ارتباط ككل رد آخر.
        final cid = _sanitizeCorrelationId(
          _firstHeader(request, 'X-Correlation-Id'),
        );
        response.headers.set('X-Correlation-Id', cid);
        final reason = verdict == AuthorityVerdict.rejectAbsoluteForm
            ? 'The request line carries an absolute URI — not accepted by this bridge'
            : 'Request Host is not allowed — this bridge accepts localhost only';
        // The immediate cut over the unread body is intentional: this reply
        // answers a DNS-rebinding attempt (or an absolute-form probe), not a
        // page this bridge needs to reach - delivering it is not required,
        // and the destroy after the flushed reply can still lose it on Linux
        // and macOS. Accepted loss for this path alone - and no socket is
        // left behind either way.
        admission.noteAuthorityReject(reason);
        await _replyRejection(
          response,
          // القطع الفوري الموثق يقرأه من السجل لا من هذا الموضع
          code: 'blocked_by_protection',
          message: reason,
          bodyFullyRead: false,
          headOnly: headOnly,
        );
        return;
      }

      // (سقف الاتصالات) فوق السقف نرد فورا — فيضان طلبات متزامنة
      // يضاعف ذروة الذاكرة (كل طلب جسم يقرأ حتى سقف الجسم) بلا حاجز
      if (_activeRequests >= config.maxConcurrentRequests) {
        // كبح السطر: تحت الضغط يكتب كل رفض انشغال سطرا واحدا في
        // الثانية على الأكثر بالساعة المحقونة، والسطر التالي بعد
        // النافذة يحمل عدد المكتوم كي يبقى حجم الفيضان مرئيا. الرفض
        // نفسه على السلك لكل طلب.
        final line = _busyWarnThrottle.admit(
          'intake busy: $_activeRequests concurrent requests — rejecting',
        );
        if (line != null) {
          telemetry.warn(line, category: BridgeCategory.network);
        }
        final busyOrigin = _firstHeader(request, 'Origin');
        // الرفض يحمل معرف ارتباط ككل رد آخر — الانشغال كذلك: الصفحة
        // تعيد المحاولة وتحتاج ربط رفضها بمحاولتها
        response.headers.set(
          'X-Correlation-Id',
          _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
        );
        _echoCors(response, busyOrigin, admitted: admission.echoesCors);
        // The busy reject is an immediate cut on purpose: a saturated server
        // spends no drain windows. The reply is written to the detached
        // socket and the connection is destroyed at once - the platform
        // reset can still swallow this 503 while the body stays unread, and
        // the retrying client reads it as the retryable network error it
        // already looks like. That loss stays accepted and documented for
        // this path alone; the 413 gate keeps the draining terminate, and no
        // socket survives the busy reply either way.
        await _replyRejection(
          response,
          // القطع الفوري الموثق يقرأه من السجل لا من هذا الموضع
          code: 'server_busy',
          message: 'The server is busy right now — please retry shortly',
          bodyFullyRead: false,
          headOnly: headOnly,
        );
        return;
      }
      _activeRequests++;
      try {
        await _handleRequest(request, response, admission);
      } finally {
        _activeRequests--;
        if (_activeRequests <= 0) {
          // إشارة فراغ المقاعد لمن ينتظرها في stop
          final drain = _drain;
          _drain = null;
          if (drain != null && !drain.isCompleted) drain.complete();
        }
      }
    } catch (error, stack) {
      // شبكة الأمان: أي استثناء ناجٍ يرى ردا ويُغلق الاتصال
      // لا مقبس معلق أبدا. قد يكون الرد أُغلق قبلا فتفشل الكتابة الثانية؛
      // وتبقى محاولة الإغلاق قائمة في كل الأحوال.
      telemetry.error(
        'intake handler crashed',
        error: error,
        stackTrace: stack,
        category: BridgeCategory.network,
      );
      await _reply(
        response,
        status: HttpStatus.internalServerError,
        json: const {
          'ok': false,
          'error': 'internal',
          'message': 'Internal server error',
        },
        bodyFullyRead: true,
        // شبكة الأمان حصراً: فشل الرد يليه إغلاق ثانٍ تحت الحارس —
        // داخل مخرج الرد الواحد لا في يد هذا المسار
        safetyRetry: true,
      );
    }
  }

  Future<void> _handleRequest(
    HttpRequest request,
    HttpResponse response,
    IntakeAdmission admission,
  ) async {
    // نكرّم ترويسة البوابة إن أرسلت X-Correlation-Id،
    // وإلا نولّد UUID v4 هنا عند الاستقبال — من هذه النقطة يخيط
    // المعرف القصة كاملة: سجلات الاستقبال ← الترحيل ← سجل المهام ←
    // تقرير النتيجة للخادم. الترويسة تُردّ للبوابة كي تملك هي أيضا
    // خيط القصة نفسه.
    final correlationId = _sanitizeCorrelationId(
      _firstHeader(request, 'X-Correlation-Id'),
    );
    response.headers.set('X-Correlation-Id', correlationId);

    // زمن استجابة البوابة كاملاً تحت قياس واحد — القصة من
    // الاستقبال إلى الرد. العلم يرافق المهلة الكلية: يظل حياً في طور
    // ما قبل المعالج ويُطفأ عند استدعاء onCommand (أدناه)
    var totalDeadlineLive = true;
    final work = telemetry.measure<void>(
      'intake.handleRequest',
      () async {
        try {
          final origin = _firstHeader(request, 'Origin');
          if (request.method == 'OPTIONS') {
            _echoCors(response, origin, admitted: admission.echoesCors);
            // الرد على المقبس الخام: جسم الـpreflight قد يكون معلناً وغير
            // مكتمل، والإغلاق المُدار فوقه يعلق بلا رد ولا قطع أبداً —
            // الـ204 يُكتب على المقبس المنتزع ثم تُقطع الوصلة ويُفرَّغ
            // البقية بالتفريغ المحدود في خلفية بلا مقعد.
            await _reply(
              response,
              status: HttpStatus.noContent,
              json: null,
              bodyFullyRead: false,
            );
            return;
          }
          if (request.method != 'POST') {
            // قطع بعد الرد: الطريقة المخالفة قد تحمل جسما معلنا وغير
            // مكتمل — إغلاق الرد المُدار فوقه يعلق close() على مرسل لا
            // يكمل فيحجز المقعد حتى المهلة الكلية (تحرر متأخر بلا رد)،
            // والهدم عند الإغلاق يبتلع الرد على لينكس/ماك.
            // مسار المقبس الخام: الرد يُكتب ويُغسل أولا ثم يُقطع، والجسم
            // غير المقروء يُفرَّغ بالصبر المحدود في خلفية بلا مقعد.
            await _replyRejection(
              response,
              code: 'method_not_allowed',
              message: 'Send the command as a POST request',
              bodyFullyRead: false,
              headOnly: request.method == 'HEAD',
            );
            return;
          }

          // بوابة الاقتران: POST على /pair والطبقة مسلحة حصرا — بلا
          // تسوية لسجل قبول عادي (الطلب لا ينفذ أمرا) ولا تحذير مسار
          // غير جذري (مسار مسجل). الخامل يمر من تحت الفرع لسلوك اليوم
          // حرفا: تحذير المسار ثم المعالج.
          if (request.uri.path == _pairingPath && protection.pairingEnabled) {
            await _handlePairing(request, response);
            return;
          }

          // تحذير المسار غير الجذري: كل POST على مسار آخر يُقال
          // للمضيف مرة في الثانية على الأكثر بالساعة المحقونة، والسطر
          // التالي بعد النافذة يحمل عدد المكتوم كي يبقى حجم الاستعمال
          // مرئياً. مرصد لا بوابة: الطلب كما هو يبلغ المعالج ولا يتغير
          // شيء على السلك، والموضع قبل قرار الحماية كي لا يعتمد التحذير
          // على وضعها. المسار قيمة من سطر الطلب فيمر بالتحجيم قبل السطر.
          if (request.uri.path != '/') {
            final line = _pathWarnThrottle.admit(
              'intake POST on a non-root path '
              '("${_pathForWarn(request.uri.path)}") — it still reaches the '
              'handler; commands belong on "/"',
            );
            if (line != null) {
              telemetry.warn(line, category: BridgeCategory.network);
            }
          }

          // بوابة القبول: الحكم مبني من مدخل القبول الواحد منذ بوابات
          // الشكل، والتسوية هنا حصراً تهبط أثره في الموضع نفسه الذي كانت
          // تجريه check القديمة (طوابع النوافذ، استهلاك المنحة، السؤال،
          // تحذيرات المراقبة، وعدّ الرفض وسطره الأمني). كل من رُفض قبله
          // — المهيّأ والطريقة المخالفة والمنشغل ومرفوض المضيف — لم
          // يُسوِّ فلم يخلف شيئاً
          admission.settle();
          final rejection = admission.rejection;
          if (rejection != null) {
            // الرأس الصادق: بقايا النافذة التي رفضت الطلب كما قاسها
            // الحماية؛ الثابت 2 يبقى للسؤال المفتوح وحده (المستخدم قد
            // يجيب فورا فلا يُستعار له رأس دقائق)
            final waitMs =
                rejection.retryAfterMs ??
                (rejection.code == 'origin_pending' ? 2000 : null);
            if (waitMs != null) {
              response.headers.set('Retry-After', '${(waitMs / 1000).ceil()}');
            }
            // The page must read the code and the honest Retry-After to
            // retry: the consent question always echoes (its own ask fired
            // the request), and every rejection carrying a wait budget
            // (per-origin quota or token lockout) echoes when the origin
            // qualifies for one - without ACAO the browser hides both from
            // the retrying page and Retry-After loses its meaning.
            // token_required وpair_signature_replay ينضمان لعموم القراءة:
            // هما سؤال القبول نفسه الموجه لصفحة الأصل المؤهل (أعِد
            // بالإثبات / وقّع طلباً جديداً) — وبوابة التأهيل (الصدى الخام
            // المسجل) تبقي الأجنبي أعمى عنهما
            final echoesCors =
                rejection.code == 'origin_pending' ||
                (rejection.retryAfterMs != null && admission.echoesCors) ||
                ((rejection.code == 'token_required' ||
                        rejection.code == 'pair_signature_replay') &&
                    admission.echoesCors);
            if (echoesCors) {
              _echoCors(response, origin, admitted: true);
            }
            // الرد على المقبس الخام لا الرد المُدار: الجسم لم يُقرأ بعد،
            // وإغلاق الرد المُدار فوقه يعلق close() على مرسل لا يكمل فيحجز
            // المقعد، أو يهدم الاتصال فيبتلع الرد الذي يجب أن تقرأه الصفحة
            // (origin_pending وحملة Retry-After ذات صدى CORS). الترويسات
            // المضبوطة أعلاه (Retry-After وصدى CORS ومعرف الارتباط) تُنسخ
            // كما هي، والقطع بعد غسل الرد بتفريغ محدود بلا حجز مقعد.
            await _replyRejection(
              response,
              code: rejection.code,
              message: rejection.message,
              bodyFullyRead: false,
            );
            return;
          }
          // الصدى بعد القبول للمؤهل وحده — قراءة من السجل: التوكن
          // يقبل عميلاً غير متصفحي أصله غير مدرج فلا يرى ACAO (لا يقرأه)،
          // والمتصفح غير المؤهل لا يصل أصلاً لغياب صدى الpreflight
          _echoCors(response, origin, admitted: admission.echoesCors);
          // الرسائل التفصيلية للمضيف المعتمد حصرا — قراءة من السجل (حسمها
          // الإسقاط بمقارنة التوكن الواحدة) — ومسار «الكل»
          // يرى الرمز بلا نص المضيف (منع كشف معلومات المضيف لأي أصل)
          final verboseErrors = admission.verboseErrors;

          // بوابة نوع المحتوى بعد القبول حصرا: الغريب لا يرى 415 قبل أن
          // ترفضه سياسة الأصول فلا يتسرب شكل السياسة — النموذج المخفي
          // في الصفحات يرسل أنواع النماذج فيُرد قبل قراءة أي بايت
          final rawContentType = _firstHeader(
            request,
            HttpHeaders.contentTypeHeader,
          );
          if (rawContentType != null && rawContentType.trim().isNotEmpty) {
            final mediaType = rawContentType
                .split(';')
                .first
                .trim()
                .toLowerCase();
            if (!config.allowedContentTypes.contains(mediaType)) {
              // قطع بعد الرد كما في بقية الرفوض المبكرة: الجسم غير مقروء
              // والإغلاق المُدار فوقه يعلق أو يهدم — المقبس الخام يرد ثم يقطع.
              await _replyRejection(
                response,
                code: 'unsupported_media_type',
                message:
                    'Content-Type must be one of: '
                    '${config.allowedContentTypes.join(', ')}',
                bodyFullyRead: false,
              );
              return;
            }
          }

          // رفض مبكر من Content-Length: `>` حصراً وبشرط غياب
          // الترميز المقطوع — الجسم الكاذب الواعد يظل محروساً بالعدّاد أدناه
          final te = _firstHeader(request, HttpHeaders.transferEncodingHeader);
          final cl = request.contentLength;
          if ((te == null || te.isEmpty) && cl > config.maxBodyBytes) {
            await _replyRejection(
              response,
              code: 'payload_too_large',
              message: 'Request body exceeds the allowed limit ($_mbLabel)',
              bodyFullyRead: false,
            );
            return;
          }
          // قراءة الجسم بحدوده: عدّاد بايتات تراكمي يقطع بـ413 عند
          // التجاوز (لا اقتطاع صامت يفك UTF-8 ناقصا) ومهلة تحرس الطلب
          // المعلق، ثم فك UTF-8 واحد بعد حسم الحجم — بناء سلسلة الجسم
          // كاملة قبل الحسم يفتح باب الضخّم بعدها (trim + jsonDecode +
          // toString) فيتضاعف استهلاك الذاكرة بلا حارس تطبيقي
          final outcome = await _readBody(request);
          if (outcome.error != null) {
            await _replyBodyError(response, outcome.error!);
            return;
          }
          final body = outcome.body!;
          if (!_jsonShapeWithinLimits(
            body,
            config.maxJsonElements,
            config.maxJsonDepth,
          )) {
            await _replyRejection(
              response,
              code: 'payload_too_complex',
              message:
                  'Request body has too many JSON elements or is '
                  'nested too deeply (over ${config.maxJsonElements} '
                  'elements or ${config.maxJsonDepth} deep) — send fewer, '
                  'shallower elements',
              bodyFullyRead: true,
            );
            return;
          }
          final List<String> payloads;
          try {
            payloads = _extractPayloads(body);
          } on _UnsupportedPayloadShapeException {
            // رفض شكل الحمولة يقطع الاتصال بعد الرد — الجسم مقروء كاملا
            // فالإغلاق المُدار نظيف وحسم الاتصال معه فلا يبقى مقبول رفضا
            // مع اتصال حي.
            await _replyRejection(
              response,
              code: 'unsupported_payload_shape',
              message:
                  'JSON body has a known-but-unsupported '
                  'shape (object without known command keys)',
              bodyFullyRead: true,
            );
            return;
          }
          if (payloads.isEmpty) {
            await _replyRejection(
              response,
              code: 'empty_payload',
              message: 'No valid command payload found in the request',
              bodyFullyRead: true,
            );
            return;
          }

          final source = _firstHeader(request, 'Origin') ?? 'unknown-origin';
          // سقف العمل الحي عند المعالج: المقاعد وحدها لا تحرس شيئا بعد
          // مهلة المعالج — اليتامى ما زالوا يعملون فعلا، فالميزانية
          // المقاعد+اليتامى معا، وفوقها يُرد 503 قبل استدعاء معالج جديد
          if (_activeRequests + _orphanHandlers >
              config.maxConcurrentRequests) {
            // كبح السطر نفسه: فيض رفض اليتامى يكتب سطرا واحدا في
            // الثانية على الأكثر، والسطر التالي بعد النافذة يحمل
            // عدد المكتوم، والرفض نفسه لكل طلب.
            final line = _orphanBusyWarnThrottle.admit(
              'intake busy: $_orphanHandlers orphan handler(s) still '
              'running — rejecting before invoking another',
            );
            if (line != null) {
              telemetry.warn(line, category: BridgeCategory.network);
            }
            await _replyRejection(
              response,
              code: 'server_busy',
              message: 'The server is busy right now — please retry shortly',
              bodyFullyRead: true,
            );
            return;
          }
          // المعرف يمر للمتحكم عبر خريطة الترويسات (مفتاح صغير
          // كالبقية) — بلا تغيير توقيع الدالة أو مستهلكيها.
          // آخر ما قبل المعالج: المهلة الكلية تُلغى عند هذا الاستدعاء
          // قبل تنفيذ المعالج — وقت المعالج عقد handlerTimeout وحده:
          // null بلا مهلة إطلاقاً (المعالج يمسك مقعده إلى أن يكمل)،
          // والقيمة تحرر المقعد برد 504 ويُعدّ المعالج يتيماً —
          // والنتيجة المتأخرة تُهمل.
          totalDeadlineLive = false;
          final commandFuture = onCommand(
            TrustedCommand(
              source: source,
              payloads: payloads,
              headers: {
                ..._stringHeaders(request),
                'x-correlation-id': correlationId,
              },
              correlationId: correlationId,
              admission: admission,
            ),
          );
          final CommandOutcome result;
          final handlerBudget = effectiveHandlerTimeout;
          try {
            result = handlerBudget == null
                ? await commandFuture
                : await commandFuture.timeout(
                    handlerBudget,
                    // ميزانية الجسر بعلامة خاصة: كل TimeoutException
                    // أخرى (رمى المعالجُ نفسه) تعود لمسار 500 العام
                    onTimeout: () => throw const _HandlerBudgetExceeded(),
                  );
          } on _HandlerBudgetExceeded {
            commandFuture.ignore();
            // اليتيم ما زال يعمل فعلا: يُعدّ ضمن ميزانية العمل الحي،
            // وفراغه يدق جرس تفريغ stop — then بمعالج خطأ فارغ كي لا
            // يُحيى خطأه المتأخر (تجاهلُ ignore للمستقبل الأصلي وحده)
            _orphanHandlers++;
            commandFuture.then<void>(
              (_) => _orphanSettled(),
              onError: (_) => _orphanSettled(),
            );
            // كبح السطر نفسه: موجة معالجات بطيئة تكتب تحذيرا واحدا في
            // الثانية على الأكثر، والسطر التالي بعد النافذة يحمل عدد
            // المكتوم، ورد 504 نفسه لكل طلب.
            final line = _handlerTimeoutWarnThrottle.admit(
              'intake handler timeout — seat released, late result ignored',
            );
            if (line != null) {
              telemetry.warn(line, category: BridgeCategory.network);
            }
            await _replyRejection(
              response,
              code: 'handler_timeout',
              message: 'The command handler exceeded its time budget',
              bodyFullyRead: true,
            );
            return;
          }

          await _reply(
            response,
            status: result.ok ? HttpStatus.ok : HttpStatus.internalServerError,
            json: {
              'ok': result.ok,
              if (!result.ok)
                'error': result.errorCode ?? config.fallbackErrorCode,
              // نص المضيف للمعتمدين حصرا — الرمز عقد الجميع
              if (!result.ok && verboseErrors)
                'message': result.errorMessage ?? 'Command execution failed',
            },
            bodyFullyRead: true,
          );
        } catch (error, stack) {
          telemetry.error(
            'intake handler crashed',
            error: error,
            stackTrace: stack,
            category: BridgeCategory.network,
          );
          await _reply(
            response,
            status: HttpStatus.internalServerError,
            json: const {
              'ok': false,
              'error': 'internal',
              'message': 'Internal server error',
            },
            bodyFullyRead: true,
          );
        }
      },
      context: {
        'method': request.method,
        // القيمة الوحيدة يتحكم فيها الخصم في هذا السياق تمر بالتعقيم
        // نفسه الذي يمر به سجل الرفض (originForLog): محارف التحكم تُحذف
        // والقيمة تُقص إلى سقفه — فلا يحمل سياق القياس عند المضيف قيمةً
        // خاماً أطول من سطر السجل ولا قابلة لتزوير أسطر. القيمة هنا عبرت
        // بوابتي الطول والشكل فسليمة الأصل، والتعقيم حارسُ السقف والسطر
        // لا قرار قبول، وغياب الترويسة يظل 'unknown' كما كان.
        'origin':
            IntakeProtection.originForLog(_firstHeader(request, 'Origin')) ??
            'unknown',
        'correlationId': correlationId,
      },
    );
    // احتواء الخطأ المتأخر: بعد احتراق المهلة الكلية يستمر التنفيذ
    // الداخلي (لا إلغاء لمستقبلات Dart) وقد يرمي عند محاولة الرد على
    // مقبس انتُزع — الاستماع الفارغ يمنع الخطأ اليتيم، والخطأ قبل
    // القطع يمر من مستقبِل المهلة إلى مسار الشبكة الأماني.
    var settled = false;
    unawaited(work.catchError((Object _, StackTrace _) {}));
    unawaited(work.whenComplete(() => settled = true));
    // المهلة الكلية لما قبل المعالج: مسلحة عند دخول _handleRequest بقيمة
    // requestTimeout وتُلغى عند استدعاء onCommand. رفض ما قبل الجسم يقطع
    // اليوم على المقبس المنتزع من غيرها كلُّه، فما تحرسه هنا بقية الطور
    // المعلق: نداء الموافقة الذي لا يُجاب، وأي توقف بين البوابات وقراءة
    // الجسم بمهلها القائمة. وقت المعالج بعدها عقد handlerTimeout وحده،
    // ومعالج بلا قيمة يمسك مقعده إلى أن يكمل فيبقى هذا الانتظار معلقا
    // معه عمدا.
    // المقعد يتحرر بعودة الانتظار من هنا في طور ما قبل المعالج، أما
    // القطع فتنتظر يَناً قصيراً:
    // مهلة الجسم المطلقة (القيمة نفسها ومسلحة قبل هذه بلحظة) صاحبة
    // الحكم في طور قراءة الجسم وردّها 408 أولى من القطع الجاف.
    await work.timeout(
      effectiveTimeout,
      onTimeout: () async {
        // أُلغيت المهلة قبل بدء المعالج: لا قطع كلية على طور المعالج —
        // الانتظار يستمر إلى حسم العمل الحقيقي، وميزانية المعالج
        // (handlerTimeout) هي الحارس الوحيد فوقه
        if (!totalDeadlineLive) {
          await work;
          return;
        }
        // كبح السطر نفسه: فيض طلبات معلقة يحرق مهلتها كلها في لحظة
        // واحدة — مرة في الثانية على الأكثر، والسطر التالي بعد النافذة
        // يحمل عدد المكتوم، والقطع نفسه لكل طلب.
        final line = _totalDeadlineWarnThrottle.admit(
          'intake request exceeded its total deadline before its handler '
          'started ($effectiveTimeout) — connection cut',
        );
        if (line != null) {
          telemetry.warn(line, category: BridgeCategory.network);
        }
        await Future<void>.delayed(_totalCutYield);
        if (settled) return;
        // القطع عبر البدأة الواحدة — مهلة القطع الكلية لا تكتب قطعها
        // بيدها، وهي ليست رداً (لا تكتب شيئاً) فليست من مخرج الرد
        await _cutResponseSocket(response);
      },
    );
  }

  /// The shared body-error mapping - one home for the four body rejections
  /// (the cap, the deadline, the broken UTF-8, the parser's framing), used
  /// by the command path and the pairing route alike so neither drifts.
  /// An unknown error is rethrown: a socket failure mid-body is not a wire
  /// shape, and it belongs to the safety net.
  Future<void> _replyBodyError(HttpResponse response, Object error) async {
    if (error is _BodyTooLargeException) {
      // الرفض سُلّم لحظة تجاوز السقف، والرد الآن على مسار «الرد
      // أولاً» نفسه الذي تسلكه بوابات ما قبل الجسم: يُكتب على
      // المقبس المنتزع ويُغسل ويُغلق جهة الكتابة، والبقية تُفرَّغ
      // بالحدود القائمة في خلفية بلا مقعد. الاستثناء
      // الموثق في README يبقى لمن لا يتوقف ولا يقرأ — لكن لا
      // مسار يقطع قبل كتابة الرد.
      await _replyRejection(
        response,
        code: 'payload_too_large',
        message: 'Request body exceeds the allowed limit ($_mbLabel)',
        bodyFullyRead: false,
      );
    } else if (error is TimeoutException) {
      // المهلة توقف الاشتراك (لا تلغيه) — الرد المُدار يمر فوق
      // الجسم الموقوف ثم يغلق تحت الحارس
      await _replyRejection(
        response,
        code: 'request_timeout',
        message: 'Timed out waiting for the complete request body',
        bodyFullyRead: true,
      );
    } else if (error is FormatException) {
      await _replyRejection(
        response,
        code: 'invalid_utf8',
        message: 'The request body is not valid UTF-8',
        bodyFullyRead: true,
      );
    } else if (error is HttpException) {
      // خطأ المحلل على الحافة: HttpException الذي يبلغ هذه النقطة
      // هو من طبقة محلل dart:io حول شكل الرسالة الواردة حصراً —
      // المحلل يسلّم أخطاء تأطير الجسم (مثل Content-Length مع
      // Transfer-Encoding فيقرأ الجسم تأطير chunked فيرمي على سطر
      // حجم معتل) وانقطاع الوسط إلى تيار الجسم عبر مسار أخطاء
      // الجسم في مصدر المحلل، ولا يرمي منطقنا HttpException هنا
      // (رموزنا الثلاثة أعلاه). رفض شكل سلكي يُرد 400 ويُقطع على
      // المقبس الخام بنمط الرفض المبكر: لا شبكة أمان فيصير 500
      // وسجل انهيار على خطأ شكل من العميل، ولا اتصال باقٍ بعد الرد.
      await _replyRejection(
        response,
        code: 'bad_request',
        message: 'The HTTP parser rejected this request',
        bodyFullyRead: false,
      );
    } else {
      // خطأ مقبس أثناء الجسم ليس علة صيغة عند العميل: يُطلق
      // ليصله مسار الشبكة الأماني (500 ثابت وسجل انهيار).
      throw error;
    }
  }

  /// The pairing route handler: reads the bounded body, hands the code to
  /// the protection's gate, and answers with the bound token - or with the
  /// gate's rejection. The reply always echoes CORS: this is the bootstrap
  /// door - the code is the gate, not the origin, and the page cannot pair
  /// (or learn a failure) unless the answer is readable. It never settles
  /// a command admission (the request runs no command) and never fires the
  /// non-root path warning (a registered route, not a stray path).
  Future<void> _handlePairing(
    HttpRequest request,
    HttpResponse response,
  ) async {
    response.headers.set(
      'X-Correlation-Id',
      _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
    );
    _echoCors(response, _firstHeader(request, 'Origin'), admitted: true);
    final outcome = await _readBody(request);
    if (outcome.error != null) {
      await _replyBodyError(response, outcome.error!);
      return;
    }
    String? code;
    try {
      final decoded = jsonDecode(outcome.body!);
      if (decoded is Map) {
        final value = decoded['pairingCode'];
        if (value is String) code = value;
      }
    } on FormatException {
      // جسم ليس JSON: رمز مجهول شكلا — رفض الشكل العام لا حكم رمز
    }
    if (code == null) {
      await _replyRejection(
        response,
        code: 'bad_request',
        message: 'Send {"pairingCode": "<the code the host displays>"} as JSON',
        bodyFullyRead: true,
      );
      return;
    }
    final result = protection.pair(
      origin: _firstHeader(request, 'Origin'),
      code: code,
    );
    final rejection = result.rejection;
    if (rejection != null) {
      final waitMs = rejection.retryAfterMs;
      if (waitMs != null) {
        response.headers.set('Retry-After', '${(waitMs / 1000).ceil()}');
      }
      await _replyRejection(
        response,
        code: rejection.code,
        message: rejection.message,
        bodyFullyRead: true,
      );
      return;
    }
    await _reply(
      response,
      status: HttpStatus.ok,
      json: {
        'ok': true,
        'token': result.token!,
        'pairingId': result.pairingId!,
        'expiresInSeconds': result.expiresInSeconds!,
      },
      bodyFullyRead: true,
    );
  }

  /// Reads the body with a cumulative byte counter: hitting the cap or the
  /// deadline stops reading at once (never a silent truncation); total silence
  /// is cut by the stream timeout while slow dripping is cut by the absolute
  /// deadline - one timer armed at the read start settles the timeout on its
  /// own, and a completion arriving after the deadline is rejected too, so an
  /// event pace under the silence window cannot stretch the read past its
  /// budget. UTF-8 after the size is settled: no string above the cap is ever built.
  ///
  /// Stopping pauses the subscription instead of cancelling it: cancelling a
  /// body subscription makes HttpServer destroy the connection at once and
  /// swallow the reply before delivery (measured directly on HttpServer).
  /// Every rejection handed back here takes the reply-first route the
  /// pre-body gates take: the reply is written and flushed on the detached
  /// socket, then the unread remainder drains bounded in the background
  /// (no seat), then the connection is destroyed. The over-cap rejection
  /// in particular is handed back at the crossing moment - the reply
  /// precedes every drain byte, and no path cuts before the reply is on
  /// the wire; only a sender that never reads the reply keeps the
  /// documented loss window of the README's honest exceptions.
  Future<_BodyOutcome> _readBody(HttpRequest request) async {
    // copy:false: لا نسخة عند add — النسخة الوحيدة عند
    // takeBytes؛ ومخازن مقاطس dart:io طازجة لكل حدث فلا مشاركة
    final builder = BytesBuilder(copy: false);
    // أساس مونوتوني لكل طلب — لا wall-clock يتجمّد أو يقفز.
    final deadlineMs = _now + effectiveTimeout.inMilliseconds;
    final done = Completer<_BodyOutcome>();
    StreamSubscription? subscription;
    // الموعد المطلق مؤقّت واحد يبدأ مع القراءة: فحص onData وحده
    // يقبل جسماً يكتمل بعد موعده (onDone بلا فحص) ومهلة الصمت تقيس بين
    // حدثين لا مجموع العمر — المؤقت يحسم بالموعد أياً كان إيقاع
    // وصول الأحداث، ويلغى في كل طريق حسم.
    Timer? deadlineTimer;
    var settled = false;

    void settle(Object? error, [String? body]) {
      if (settled) return;
      // كل حسم يلغي مؤقت الموعد — التفريغ بعده يملك مؤقته الخاص
      deadlineTimer?.cancel();
      deadlineTimer = null;
      if (error == null) {
        settled = true;
        done.complete(_BodyOutcome.ok(body!));
        return;
      }
      // الرفض يحرر المخزن في الحال — لا ينتظر خروج النطاق. وكل الرفوض
      // من هنا على المسار نفسه: إيقاف مؤقت لا إلغاء — الإلغاء يهدم
      // الاتصال (المقاس على HttpServer) فيبتلع الرد قبل كتابته، والإيقاف
      // يوقف الاستهلاك فينتزع مخرج الرد المقبس ويصغي هو (تفريغ محدود
      // في خلفية بلا مقعد) ثم يقطع. ورفض العدّاد (413) يُسلَّم لحظة
      // تجاوز السقف لا بعد التفريغ: الرد أولاً ثم تفريغ البقية
      // بالحدود القائمة ثم القطع — تصميم «الرد أولاً» نفسه الذي تسلكه
      // بوابات ما قبل الجسم، فلا مسار يقطع قبل كتابة الرد. والمهلة
      // والانقطاع كذلك: المرسل الصامت لم يترك بيانات غير مقروءة أصلاً،
      // والمقطر الذي عبر الموعد المطلق قد يترك بايتات في الطريق
      // تُفرَّغ محدوداً بعد الرد.
      settled = true;
      subscription?.pause();
      done.complete(_BodyOutcome.rejected(error));
    }

    // مؤقت الموعد يُسند قبل الاستماع — رده يحسم عبر settle مهما كان
    // إيقاع الأحداث، والفحص داخل onData يبقى مختصراً للإيقاف الباكر.
    deadlineTimer = Timer(effectiveTimeout, () {
      settle(
        TimeoutException('request body deadline exceeded', effectiveTimeout),
      );
    });
    subscription = request
        .timeout(effectiveTimeout)
        .listen(
          (chunk) {
            if (_now >= deadlineMs) {
              settle(
                TimeoutException(
                  'request body deadline exceeded',
                  effectiveTimeout,
                ),
              );
              return;
            }
            builder.add(chunk);
            if (builder.length > config.maxBodyBytes) {
              settle(const _BodyTooLargeException());
            }
          },
          onDone: () {
            // الاكتمال بعد الموعد رفض مهلة لا قبول متأخر — onDone بلا
            // هذا الفحص يمرر جسماً عجز موعده كاملاً إلى الفك
            if (_now >= deadlineMs) {
              settle(
                TimeoutException(
                  'request body deadline exceeded',
                  effectiveTimeout,
                ),
              );
              return;
            }
            try {
              settle(null, utf8.decode(builder.takeBytes()));
            } on FormatException catch (e) {
              settle(e);
            }
          },
          onError: (Object error) {
            settle(error);
          },
        );
    return done.future;
  }

  /// Reason phrases for the hand-built status line of the raw-socket
  /// terminate - every code that reaches it: the 413 Content-Length gate,
  /// and every pre-body reject whose body was never read (405, the origin
  /// shape and token gates, duplicate headers, the Host-authority reject,
  /// the busy 503, the 204 preflight) - all of them cut the connection
  /// after the reply, and none of them leaves a socket behind. The fallback
  /// covers any emergency code that ever reaches this path.
  static const _terminateReasons = <int, String>{
    HttpStatus.requestEntityTooLarge: 'Payload Too Large',
    HttpStatus.methodNotAllowed: 'Method Not Allowed',
    HttpStatus.badRequest: 'Bad Request',
    HttpStatus.forbidden: 'Forbidden',
    HttpStatus.unsupportedMediaType: 'Unsupported Media Type',
    HttpStatus.tooManyRequests: 'Too Many Requests',
    HttpStatus.serviceUnavailable: 'Service Unavailable',
    HttpStatus.noContent: 'No Content',
  };

  /// مخرج الرد الواحد: كل رد في الخادم يمر من هنا حصراً، وطريقة الإغلاق
  /// تحسم من حقيقة واحدة: هل قُرئ الجسم كاملاً؟
  /// - المقروء ([bodyFullyRead]) يُغلق بالطريقة المُدارة تحت حارسها؛
  ///   والرفضُ منه يحسم الاتصال ([forceConnectionClose]) في لا يبقى مقبول
  ///   رفضاً مع اتصال حي.
  /// - غير المقروء يمرّ بالمقبس المنتزع: بالتفريغ المحدود، أو بالقطع
  ///   الفوري للمسارين الموثقين حصراً ([immediateCut]: الانشغال وHost) —
  ///   الرد اليدوي نفسه يُكتب ويُغسل وإغلاق الكتابة أولاً، ثم إما نافذة
  ///   التفريغ بلا مقعد أو الدمّر حالاً، ولا ناجي من الاثنين؛ أو بلا جسم
  ///   ([json] = null) للـ204.
  /// لا مسار ردٍّ يختار إغلاقه بنفسه بعد اليوم — القرار كلُّه هنا من
  /// الحقيقة الواحدة، والقيم (الحالة والجسم) تمر من المواضع إليه.
  Future<void> _reply(
    HttpResponse response, {
    required int status,
    required Map<String, Object>? json,
    required bool bodyFullyRead,
    bool forceConnectionClose = false,
    bool immediateCut = false,
    bool safetyRetry = false,
    bool headOnly = false,
  }) async {
    if (!bodyFullyRead) {
      if (json == null) {
        // الـ204 بلا جسم: الترويسات الجارية تُنسخ والتأطيرية Content-Length: 0
        try {
          final socket = await _detachAndReply(response, status, null);
          _discardDetached(socket);
        } on Object {
          // العميل انقطع قبل الرد أو أثناءه: الدمّر تم من الداخل
        }
        return;
      }
      final body = utf8.encode(jsonEncode(json));
      try {
        final socket = await _detachAndReply(
          response,
          status,
          body,
          headOnly: headOnly,
        );
        if (immediateCut) {
          socket.destroy();
        } else {
          _discardDetached(socket);
        }
      } on Object {
        // العميل انقطع قبل الرد أو أثناءه: الدمّر تم من الداخل
      }
      return;
    }
    // الإغلاق المُدار تحت حارسه
    if (forceConnectionClose) {
      response.persistentConnection = false;
    }
    if (safetyRetry) {
      try {
        response.statusCode = status;
        response.write(jsonEncode(json!));
        await _closeGuarded(response);
      } on Object {
        // شبكة _handle الأمانية حصراً: الرد فشل — الإغلاق الثاني تحت
        // الحارس نفسه يمتلكه مخرج الرد لا يدُ هذا المسار
        try {
          await _closeGuarded(response);
        } on Object {
          // والثاني فشل أيضاً: لا ثالث ممكن — الدمّر تم من الداخل
        }
      }
      return;
    }
    response.statusCode = status;
    response.write(jsonEncode(json!));
    await _closeGuarded(response);
  }

  /// بدأة القطع الواحدة: انتزاع المقبس ودمّره — تشترك فيها مهلة القطع
  /// الكلية وحارس الإغلاق المُدار، فلا واحد منهما يكتب قطعه بيده. ليست
  /// رداً (لا تكتب شيئاً) فليست من مخرج الرد، وهي أخيراً على كل حال:
  /// الرد المغلق أو المنتزع سابقاً لا قطعة ثانية له.
  Future<void> _cutResponseSocket(HttpResponse response) async {
    try {
      final socket = await response.detachSocket(writeHeaders: false);
      socket.destroy();
    } on Object {
      // الرد أغلق أو انتُزع من قبل — لا قطعة إضافية ممكنة
    }
  }

  /// مخرج الرفض: يقرأ سطر رمزه من سجل الرموز الواحد — الحالة والقطع
  /// الفوري من السجل حصراً لا من الموضع — ثم يُنعطي مخرج الرد به، وطريقة
  /// الإغلاق تبقى من حقيقة قراءة الجسم فيه. رمزٌ بلا سجل انحراف بنيوي:
  /// يُرفع صوتاً فلا رد صامت بترميز مغلوط.
  Future<void> _replyRejection(
    HttpResponse response, {
    required String code,
    required String message,
    required bool bodyFullyRead,
    bool headOnly = false,
  }) async {
    final spec = intakeRejectionRegistry[code];
    if (spec == null) {
      throw StateError('unregistered intake rejection code: $code');
    }
    await _reply(
      response,
      status: spec.status,
      json: {'ok': false, 'error': code, 'message': message},
      bodyFullyRead: bodyFullyRead,
      forceConnectionClose: bodyFullyRead,
      immediateCut: spec.immediateCut,
      headOnly: headOnly,
    );
  }

  /// The shared raw-socket reply: detaches the socket, builds the head from
  /// the current response headers - framing headers are rebuilt here (for a
  /// JSON body from the exact body length; for the empty 204 as
  /// `Content-Length: 0`, the same framing the managed close writes) -
  /// writes the head and the body, flushes, and closes the write side.
  /// Throws after destroying when the sender was gone mid-reply: the caller
  /// has nothing left to drain in that case.
  Future<Socket> _detachAndReply(
    HttpResponse response,
    int status,
    List<int>? body, {
    bool headOnly = false,
  }) async {
    final socket = await response.detachSocket(writeHeaders: false);
    try {
      // الرد اليدوي بنفس شكل الرد المُدار: نفس الجسم، ونفس الترويسات
      // الجارية عدا التأطيرية التي تُبنى هنا من طول الجسم الفعلي.
      final head = StringBuffer()
        ..write(
          'HTTP/1.1 $status ${_terminateReasons[status] ?? 'Rejected'}'
          '\r\n',
        );
      response.headers.forEach((name, values) {
        final lower = name.toLowerCase();
        if (lower == HttpHeaders.contentLengthHeader ||
            lower == HttpHeaders.transferEncodingHeader ||
            (body != null && lower == HttpHeaders.contentTypeHeader)) {
          return;
        }
        for (final value in values) {
          head.write('$name: $value\r\n');
        }
      });
      if (body != null) {
        head
          ..write(
            '${HttpHeaders.contentTypeHeader}: '
            'application/json; charset=utf-8\r\n',
          )
          ..write('${HttpHeaders.contentLengthHeader}: ${body.length}\r\n');
      } else {
        // الـ204 بلا جسم ويحمل Content-Length: 0 — نفس التأطير الذي
        // يكتبه الرد المُدار، فلا يتغير شكل الـpreflight على السلك
        head.write('${HttpHeaders.contentLengthHeader}: 0\r\n');
      }
      head.write('${HttpHeaders.connectionHeader}: close\r\n\r\n');

      // الرد أولاً ثم إغلاق جهة الكتابة: الفين يصل قبل أي شيء آخر، وجهة
      // القراءة باقية كما قيس (التفريغ بعده يرى الجسم كاملاً حتى onDone).
      socket.add(utf8.encode(head.toString()));
      // رد HEAD بلا جسم على السلك حصراً (المشرّع: لا محتوى في رد HEAD
      // أبداً) — التأطيرية Content-Length تبقى طول الجسم الذي كان سيُكتب
      // لعلم القارئ، والبايتات لا تُكتب والاتصال يُغلق بعدها
      if (body != null && !headOnly) socket.add(body);
      await socket.flush();
      await socket.close();
      return socket;
    } on Object {
      // العميل انقطع قبل الرد أو أثناءه: لا ما يوصَل ولا جسم يُفرَّغ —
      // الدمّر الوحيد المتبقّي
      socket.destroy();
      rethrow;
    }
  }

  /// The bounded drain of an already-replied detached socket, run detached
  /// from its caller - it holds no concurrency seat. Counts and drops bytes
  /// until the sender finishes (onDone), the socket errors, or either bound
  /// trips (the discard window, the four-body budget); the destroy lands
  /// only at that end, because destroying over unread data resets the
  /// connection and can swallow the reply that already went out.
  void _discardDetached(Socket socket) {
    final drained = Completer<void>();
    try {
      var seen = 0;
      final budget = _discardBudgetBytes;
      final deadlineMs = _now + _discardWindow.inMilliseconds;
      late final StreamSubscription<List<int>> sub;
      // late: يُسند قبل أي رد نداء (لا تسليم بين الإسناد والاستماع) —
      // والإغلاق يحتاجه معرفاً قبل سطر التعريف.
      late final Timer window;
      void finish() {
        window.cancel();
        unawaited(sub.cancel());
        if (!drained.isCompleted) drained.complete();
      }

      window = Timer(_discardWindow, finish);
      sub = socket.listen(
        (chunk) {
          seen += chunk.length;
          if (seen > budget || _now >= deadlineMs) {
            finish();
            return;
          }
        },
        onDone: finish,
        onError: (Object _) => finish(),
      );
    } on Object {
      // فشل إسناد الاستماع — لا تفريغ؛ الحسم هنا يودّي إلى الدمّر أدناه
      if (!drained.isCompleted) drained.complete();
    }
    unawaited(drained.future.then((_) => socket.destroy()));
  }

  /// One linear pass over the body counting JSON structural pressure: every
  /// `{`, `[`, and `,` outside a string is one decoded node or element, so a
  /// body of empty elements cannot amplify into many parsed objects. Strings
  /// carrying braces and commas count nothing, and a body not starting with a
  /// container (raw command text) is never counted at all: only container
  /// shapes amplify. The same pass tracks nesting depth (openers raise it,
  /// closers lower it) against [depthCap] - either limit rejects before
  /// jsonDecode ever runs.
  bool _jsonShapeWithinLimits(String body, int elementCap, int depthCap) {
    var i = 0;
    final n = body.length;
    while (i < n &&
        (body[i] == ' ' ||
            body[i] == '\t' ||
            body[i] == '\n' ||
            body[i] == '\r')) {
      i++;
    }
    if (i >= n || (body[i] != '{' && body[i] != '[')) return true;
    var inString = false;
    var count = 0;
    var depth = 0;
    for (; i < n; i++) {
      final c = body[i];
      if (inString) {
        if (c == r'\') {
          i++;
        } else if (c == '"') {
          inString = false;
        }
        continue;
      }
      if (c == '"') {
        inString = true;
      } else if (c == '{' || c == '[') {
        if (++count > elementCap) return false;
        if (++depth > depthCap) return false;
      } else if (c == '}' || c == ']') {
        depth--;
      } else if (c == ',') {
        if (++count > elementCap) return false;
      }
    }
    return true;
  }

  /// Any non-loopback entry in extraHosts (a public DNS name, a
  /// private-network address like 192.168.x.x or fe80::1, or a bare
  /// dotless name like `printer`) is the host's explicit opt-out of the
  /// DNS-rebinding guard for that one name - say it once at startup so the
  /// decision is visible in the log, not silent in the config. A dotless
  /// name warns too: "has no dot" proves nothing about where it resolves -
  /// a single-label name can land on a search domain or an mDNS network at
  /// a machine that is not this one, which is exactly the rebinding risk
  /// the guard exists for. Local means a literal: `localhost`, a bracketed
  /// `::1`, or an address that parses inside the loopback range - a `127.`
  /// text prefix would silence the warning for public names that merely
  /// resolve to loopback (`127.0.0.1.nip.io`), which is exactly the opt-out
  /// that must be said.
  void _warnExtraHosts(List<String> extraHosts) {
    for (final raw in extraHosts) {
      final host = raw.trim().toLowerCase();
      final asAddress = InternetAddress.tryParse(host);
      final isLocal =
          host == 'localhost' ||
          host == '[::1]' ||
          (asAddress != null && asAddress.isLoopback);
      if (host.isNotEmpty && !isLocal) {
        telemetry.warn(
          'extraHosts entry "$host" is not a loopback literal — listing it '
          'opts that one name out of the DNS-rebinding guard; make sure it '
          'resolves to this machine and you control it',
          category: BridgeCategory.security,
        );
      }
    }
  }

  /// Unpacks the shapes portals commonly send: a list of strings (gzip+base64
  /// or raw commands), a single string, or a JSON wrapper carrying a data
  /// field. A wrapper carrying more than one of the configured keys at once
  /// is an ambiguous envelope: it raises the unsupported-shape reject instead
  /// of being resolved silently by the key order.
  ///
  /// The JSON path (the common one) with no extra full-body copy: jsonDecode
  /// already tolerates surrounding whitespace so no trim precedes it, and
  /// non-string elements are skipped instead of a toString on any type met.
  List<String> _extractPayloads(String body) {
    try {
      final decoded = jsonDecode(body);
      if (decoded is List) {
        return [
          for (final e in decoded)
            if (e is String && e.isNotEmpty) e,
        ];
      }
      // نص JSON: يُفك اقتباسه ويستعمل — إرساله خاما يطبع علامتي
      // الاقتباس نفسها مع أن العقد يعد بسلسلة مجردة
      if (decoded is String) {
        return decoded.isEmpty ? const [] : [decoded];
      }
      if (decoded is Map) {
        // غلاف ملتبس: أكثر من مفتاح تغليف مضبوط حاضر في جسم واحد — حسمُه
        // بترتيب المفاتيح يفقد أوامر الأخرى برد ناجح، فيُرفع استثناء
        // الشكل المستقل ويُرد 400 unsupported_payload_shape ولا يصل
        // المعالج شيء. الحكم بعدد المفاتيح الحاضرة لا بقيمها.
        var presentWrapperKeys = 0;
        for (final key in config.payloadWrapperKeys) {
          if (decoded.containsKey(key)) presentWrapperKeys++;
        }
        if (presentWrapperKeys > 1) {
          throw const _UnsupportedPayloadShapeException();
        }
        // مفاتيح التغليف من الإعداد: الافتراضية محايدة، ومفتاح مجالٍ
        // يضيفه صاحبه بنفسه فلا تحمل الحزمة معجم كل مجال
        for (final key in config.payloadWrapperKeys) {
          final value = decoded[key];
          if (value is List) {
            return [
              for (final e in value)
                if (e is String && e.isNotEmpty) e,
            ];
          }
          if (value is String && value.isNotEmpty) return [value];
        }
        // وصلنا Map بلا مفتاح معروف: شكل معلوم ليس أمرا — لا يبتلعه
        // المصيد العام بل يعلو ليرد برمز الشكل المستقل
        throw const _UnsupportedPayloadShapeException();
      }
      // رقم أو منطقي أو null: أمر خام مطابقة نصية — استمر للخام
    } on _UnsupportedPayloadShapeException {
      rethrow;
    } catch (_) {
      // ليس JSON — نص خام مباشر
    }
    // مسار النص الخام وحده يُقلَّص (توافق السلوك القديم للبوابات التي
    // ترسل لغات أوامر نصية، وغالبا بأسطر ختامية)
    final trimmed = body.trim();
    return trimmed.isEmpty ? const [] : [trimmed];
  }

  Map<String, String> _stringHeaders(HttpRequest request) {
    return {
      'origin': _firstHeader(request, 'Origin') ?? '',
      'user-agent': _firstHeader(request, HttpHeaders.userAgentHeader) ?? '',
    };
  }

  /// ACAO echo for accepted requests (and a qualified origin's preflight) with
  /// Vary; the rejected never see the header at all - no probing channel.
  void _echoCors(
    HttpResponse response,
    String? origin, {
    required bool admitted,
  }) {
    if (admitted && origin != null) {
      response.headers.set('Access-Control-Allow-Origin', origin);
      response.headers.set('Vary', 'Origin');
      response.headers.set('Access-Control-Max-Age', '600');
      // المتصفح لا يكشف ترويسات غير القائمة الآمنة — هاتان ليستا منها
      response.headers.set(
        'Access-Control-Expose-Headers',
        'Retry-After, X-Correlation-Id',
      );
    }
  }

  /// Reads the first value without throwing: headers.value throws HttpException
  /// on multiple values while the list does not, and duplication is already
  /// settled by the single-value header gate in _handle above.
  String? _firstHeader(HttpRequest request, String name) {
    final values = request.headers[name];
    if (values == null || values.isEmpty) return null;
    return values.first;
  }

  /// An incoming correlation id is honored only within the contract: up to 128
  /// chars of [A-Za-z0-9._-]. Anything else (bloat or control characters) is
  /// replaced with a generated one, logged by the original value's length only,
  /// never its text. Replace, not reject: an honest gate does not break on a diagnostic header.
  static final RegExp _cidAllowed = RegExp(r'^[A-Za-z0-9._-]{1,128}$');

  /// Last rejected-id warning - at most one warning per second, and the next
  /// warning carries the muted count so the attack's size stays visible.
  int _lastCidWarnMs = -100_000;
  int _suppressedCidWarns = 0;

  String _sanitizeCorrelationId(String? incoming) {
    if (incoming != null && _cidAllowed.hasMatch(incoming)) {
      return incoming;
    }
    final now = _now;
    if (incoming != null && incoming.isNotEmpty) {
      if (now - _lastCidWarnMs >= 1000) {
        _lastCidWarnMs = now;
        final suppressed = _suppressedCidWarns;
        _suppressedCidWarns = 0;
        telemetry.warn(
          'intake correlation id rejected (length '
          '${incoming.length}${suppressed > 0 ? ", +$suppressed more suppressed" : ""}) '
          '— replaced with a generated one',
          category: BridgeCategory.network,
        );
      } else {
        _suppressedCidWarns++;
      }
    }
    return correlationIdGenerator();
  }

  /// CORS headers for the allowed only: echo of the requester's origin with
  /// Vary - the disallowed get no ACAO at all, so the browser blocks reading
  /// (echoing to everyone equaled '*'); Max-Age trims https-portal preflights.
  /// The allowed-header list extends with the pairing proof header only
  /// while the pairing layer is armed - the disarmed wire is letter
  /// identical to previous releases.
  void _corsHeaders(HttpResponse response) {
    // البوابات صفحات https تتصل بـ http محلي — CORS صريح إلزامي.
    // الصدى (ACAO) يقرر لاحقا بعد حسم القبول أو عند الpreflight — لا
    // هنا: رفض قابل القراءة يعطي المهاجم قناة استطلاع
    response.headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    response.headers.set(
      'Access-Control-Allow-Headers',
      protection.pairingEnabled
          ? 'Content-Type, X-Bridge-Token, X-Correlation-Id, '
                'X-Bridge-Pairing'
          : 'Content-Type, X-Bridge-Token, X-Correlation-Id',
    );
    response.headers.contentType = ContentType.json;
  }

  /// The managed close with its safety net: the close is the course for
  /// every reply over a consumed body, and the guard only covers the
  /// residual hang - a close that has not completed within the drain window
  /// gets its socket detached and destroyed, so no abandoned close can hold
  /// a live socket past its window. A close that already claimed the socket
  /// keeps its course untouched (the detach throws and is swallowed), and a
  /// late error from the pending close is consumed here instead of surfacing
  /// as an orphan zone error. القطع عبر بدأة القطع الواحدة لا بيده.
  Future<void> _closeGuarded(HttpResponse response) async {
    final closing = response.close();
    try {
      await closing.timeout(_closeGuardWindow);
      return;
    } on TimeoutException {
      await Future<void>.delayed(_totalCutYield);
      await _cutResponseSocket(response);
      unawaited(closing.catchError((Object _, StackTrace _) {}));
    }
  }
}
