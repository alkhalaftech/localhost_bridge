import 'dart:async';
import 'dart:convert';
import 'dart:typed_data' show BytesBuilder;

import 'dart:io';

import 'bridge_config.dart';
import 'bridge_telemetry.dart';
import 'intake_invariants.dart';
import 'intake_protection.dart';
import 'trusted_command.dart';

/// Body over the byte cap - an internal exception that tells the 413 reject
/// apart from other read errors, so the intake replies with the honest code, never a silent truncation.
class _BodyTooLargeException implements Exception {
  const _BodyTooLargeException();
}

/// A known JSON shape that is not a command (a Map with no known keys): an
/// honest reject with its own code, not a misleading empty_payload for a non-empty body.
class _UnsupportedPayloadShapeException implements Exception {
  const _UnsupportedPayloadShapeException();
}

/// Failure to reserve any listen port - a plain [Exception]: a failed bind
/// is an environmental condition (another process holds the ports), caught
/// by `on Exception` handlers without the Error semantics Dart reserves
/// for programming mistakes.
class IntakeBindException implements Exception {
  IntakeBindException(this.message);

  /// A failed port bind is an environmental condition (another process
  /// holds the ports), not a programming mistake - Dart Errors are not
  /// meant to be caught, so this stays a plain Exception for `on Exception`
  /// handlers.
  final String message;

  @override
  String toString() => 'IntakeBindException: $message';
}

/// A local HTTP intake server for external portals.
///
/// Listens on 127.0.0.1 only (no network exposure) on a configurable port
/// with fallbacks when busy, and answers with CORS headers for the origins it
/// allowed, so portal https pages can send label commands straight from the
/// browser. Errors always come back with clear messages - no silent failure.
///
/// Resource limits (body cap / timeout / seat cap) apply in every protection
/// mode - even allow-all - because they are what makes accepting any site memory-safe.
class LocalIntakeServer {
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
       protection = protection ?? IntakeProtection() {
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
    if (handlerTimeout != null) {
      require(
        handlerTimeout! > Duration.zero,
        'handlerTimeout',
        handlerTimeout,
      );
    }
  }

  /// Called with every trusted command the package hands to the registered host.
  final TrustedCommandHandler onCommand;

  /// The measurement and log seam: the host adapts AppLogger, keeping intake latency and classification alive.
  final BridgeTelemetry telemetry;

  /// Correlation-id generator - required with no default: the host passes its own.
  final String Function() correlationIdGenerator;

  /// Optional intake protection (open/allowlist/token) - read live on every
  /// request so a settings change takes effect without restarting the listener.
  final IntakeProtection protection;

  /// Full-body receive timeout - injected directly for tests; the default comes
  /// from config.requestTimeout (the value's single source of truth).
  final Duration? requestTimeout;

  /// The effective timeout: the parameter when given, else the package setting.
  late final Duration effectiveTimeout =
      requestTimeout ?? config.requestTimeout;

  /// Host-side handler timeout - null (the default) changes nothing at all; a
  /// value frees the processing seat from a never-ending handler with a 504
  /// handler_timeout reply - and a late result (if one arrives) is dropped with
  /// no orphan error: Dart does not cancel futures, and the response settled first.
  final Duration? handlerTimeout;

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
  /// reads "1MB" verbatim, so the wire changes only when the setting itself does.
  late final String _mbLabel =
      config.maxBodyBytes >= 1024 * 1024 &&
          config.maxBodyBytes % (1024 * 1024) == 0
      ? '${config.maxBodyBytes ~/ (1024 * 1024)}MB'
      : '${config.maxBodyBytes}B';

  int _activeRequests = 0;

  /// Handlers still running after their request already timed out (504) and
  /// left - the seat model does not see them, but the work is real: printing
  /// could outlive stop() unless counted. Seats plus orphans are one live-work
  /// budget, and stop() drains the orphans up to the handler budget.
  int _orphanHandlers = 0;

  /// Armed when stop() arrives while orphans still run - completed when the
  /// last orphan settles.
  Completer<void>? _orphanDrain;

  /// An in-progress start guards the race: two parallel start calls would both
  /// see no server and bind two - the first leaking live with no reference.
  bool _starting = false;

  /// The future of the in-progress start - stop awaits it so a live server is
  /// never orphaned (an immediate reply used to leave the bind finishing behind it).
  Future<int>? _startingFuture;

  /// Armed when stop arrives mid-start - completes when the last seat drains.
  Completer<void>? _drain;

  HttpServer? _server;
  int _port = 0;

  int get port => _port;
  bool get isListening => _server != null;

  /// Starts listening - tries the preferred port, then the fallbacks. Throws
  /// [IntakeBindException] (a plain Exception - a failed bind is an
  /// environmental condition) when every port fails, and [StateError] when
  /// already listening or mid-start.

  Future<int> start({
    required int preferredPort,
    List<int> fallbacks = const [],
  }) {
    if (_server != null || _starting) {
      throw StateError(
        _server != null
            ? 'intake server already listening on port $_port'
            : 'intake server start already in progress',
      );
    }
    _starting = true;
    Future<int> started;
    try {
      started = telemetry.measure<int>('intake.start', () async {
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
            telemetry.warn(
              'port $candidate busy, trying fallback',
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
  /// the remainder is announced instead of silently outliving the stop.
  Future<void> stop() async {
    // بداية جارية: ينتظر حسمها أولا — الرد
    // الفوري كان يدع الربط يكتمل خادما يتيما بعد عودة stop
    final pendingStart = _startingFuture;
    if (pendingStart != null) {
      try {
        await pendingStart;
      } catch (_) {
        // فشل البدء: لا خادم لإيقافه — الحسم وحده مقصود
      }
    }
    final server = _server;
    _server = null;
    _port = 0;
    await server?.close();
    while (_activeRequests > 0) {
      // أعد استخدام المسلح: نداءان متداخلان لstop
      // كان الثاني يطحن _drain فيبقى الأول معلقا على مستقبل لا يكتمل
      final drained = _drain ??= Completer<void>();
      await drained.future;
      _drain = null;
    }
    _drain = null;
    // اليتامى: مقاعدهم فرغت برد 504 لكن عملهم حي — stop كان يعود
    // وهي تطبع بعده؛ الآن تنتظر حتى ميزانية المعالج نفسها، والباقي
    // فوقها يُعلن بعدّه لا يُترك صامتا
    final grace = handlerTimeout;
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

  Future<void> _handle(HttpRequest request) async {
    final response = request.response;
    _corsHeaders(response);
    try {
      // الترويسات أحادية الدلالة: تعدد قيمها طلب ملغوب صريح
      // 400 وقطع، بدل استثناء valueغير الملتقط الذي يعلّق المقبس بلا
      // رد أصلا (حادثة سابقة: UNCAUGHT-IN-ZONE + مقبس معلق). Host
      // مستثنى: محلل dart يطويه (شاهد 14_duplicate_host).
      for (final name in const [
        'x-correlation-id',
        'origin',
        'x-portal-token',
      ]) {
        if ((request.headers[name] ?? const <String>[]).length > 1) {
          // كل رفض يحمل معرف ارتباط — هنا توليد دائم لأن القيمة
          // الواردة نفسها هي الملغوبة
          response.headers.set('X-Correlation-Id', correlationIdGenerator());
          _echoCors(
            response,
            _firstHeader(request, 'Origin'),
            admitted: protection.echoesCorsFor(_firstHeader(request, 'Origin')),
          );
          await _terminate(
            response,
            HttpStatus.badRequest,
            'duplicate_header',
            'Header "$name" was sent more than once — send exactly one value',
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
        protection.noteRejection(reason, _firstHeader(request, 'Origin'));
        await _json(response, HttpStatus.forbidden, {
          'ok': false,
          'error': 'blocked_by_protection',
          'message': reason,
        });
        return;
      }

      // (سقف الاتصالات) فوق السقف نرد فورا — فيضان طلبات متزامنة كان
      // يضاعف ذروة الذاكرة (كل طلب جسم يقرأ حتى سقف الجسم) بلا حاجز
      if (_activeRequests >= config.maxConcurrentRequests) {
        telemetry.warn(
          'intake busy: $_activeRequests concurrent requests — rejecting',
          category: BridgeCategory.network,
        );
        final busyOrigin = _firstHeader(request, 'Origin');
        // الرفض يحمل معرف ارتباط ككل رد آخر — الانشغال كذلك: الصفحة
        // تعيد المحاولة وتحتاج ربط رفضها بمحاولتها
        response.headers.set(
          'X-Correlation-Id',
          _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
        );
        _echoCors(
          response,
          busyOrigin,
          admitted: protection.echoesCorsFor(busyOrigin),
        );
        await _terminate(
          response,
          HttpStatus.serviceUnavailable,
          'server_busy',
          'The server is busy right now — please retry shortly',
        );
        return;
      }
      _activeRequests++;
      try {
        await _handleRequest(request, response);
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
      try {
        await _json(response, HttpStatus.internalServerError, {
          'ok': false,
          'error': 'internal',
          'message': 'Internal server error',
        });
      } catch (_) {
        try {
          await response.close();
        } catch (_) {}
      }
    }
  }

  Future<void> _handleRequest(
    HttpRequest request,
    HttpResponse response,
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

    // زمن استجابة البوابة كاملاً داخل Registry — كان هذا الغلاف
    // الوحيد غير المقاس في سلسلة الاستقبال.
    await telemetry.measure<void>(
      'intake.handleRequest',
      () async {
        try {
          final origin = _firstHeader(request, 'Origin');
          if (request.method == 'OPTIONS') {
            _echoCors(
              response,
              origin,
              admitted: protection.echoesCorsFor(origin),
            );
            response.statusCode = HttpStatus.noContent;
            await response.close();
            return;
          }
          if (request.method != 'POST') {
            await _json(response, HttpStatus.methodNotAllowed, {
              'ok': false,
              'error': 'method_not_allowed',
              'message': 'Send the command as a POST request',
            });
            return;
          }

          // حماية المدخل (سياسة الأصول الموحدة): الفحص قبل
          // قراءة الجسم؛ الرفض يحمل حالته ورمزه (الرمز عقد المطور)
          final portalToken = _firstHeader(request, 'X-Portal-Token');
          final rejection = await protection.check(
            origin: origin,
            portalToken: portalToken,
            fetchMode: _firstHeader(request, 'Sec-Fetch-Mode'),
            fetchDest: _firstHeader(request, 'Sec-Fetch-Dest'),
          );
          if (rejection != null) {
            protection.noteRejection(rejection.message, origin);
            // الرأس الصادق: بقايا النافذة التي رفضت الطلب كما قاسها
            // الحماية؛ الثابت 2 يبقى للسؤال المفتوح وحده (المستخدم قد
            // يجيب فورا فلا يُستعار له رأس دقائق)
            final waitMs =
                rejection.retryAfterMs ??
                (rejection.code == 'origin_pending' ? 2000 : null);
            if (waitMs != null) {
              response.headers.set('Retry-After', '${(waitMs / 1000).ceil()}');
            }
            // السؤال غير المعطِّل: الصفحة تعيد المحاولة بعد لحظة
            if (rejection.code == 'origin_pending') {
              _echoCors(response, origin, admitted: true);
            }
            await _json(response, rejection.status, {
              'ok': false,
              'error': rejection.code,
              'message': rejection.message,
            });
            return;
          }
          _echoCors(response, origin, admitted: true);
          // الرسائل التفصيلية للمضيف المعتمد حصرا — مسار «الكل»
          // يرى الرمز بلا نص المضيف (منع كشف معلومات المضيف لأي أصل)
          final verboseErrors = protection.verboseErrorsFor(
            origin,
            portalToken,
          );

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
              await _json(response, HttpStatus.unsupportedMediaType, {
                'ok': false,
                'error': 'unsupported_media_type',
                'message':
                    'Content-Type must be one of: '
                    '${config.allowedContentTypes.join(', ')}',
              });
              return;
            }
          }

          // رفض مبكر من Content-Length: `>` حصراً وبشرط غياب
          // الترميز المقطوع — الجسم الكاذب الواعد يظل محروساً بالعدّاد أدناه
          final te = _firstHeader(request, HttpHeaders.transferEncodingHeader);
          final cl = request.contentLength;
          if ((te == null || te.isEmpty) && cl > config.maxBodyBytes) {
            await _terminate(
              response,
              HttpStatus.requestEntityTooLarge,
              'payload_too_large',
              'Request body exceeds the allowed limit ($_mbLabel)',
            );
            return;
          }
          // قراءة الجسم بحدوده: عدّاد بايتات تراكمي يقطع بـ413 عند
          // التجاوز (لا اقتطاع صامت يفك UTF-8 ناقصا) ومهلة تحرس الطلب
          // المعلق، ثم فك UTF-8 واحد بعد حسم الحجم — المسار القديم كان
          // يبني سلسلة الجسم كاملة أولا ثم يضخّمها (trim + jsonDecode +
          // toString) فتتضاعف الذاكرة قبل أي حارس تطبيقي
          String body;
          try {
            body = await _readBody(request);
          } on _BodyTooLargeException {
            await _terminate(
              response,
              HttpStatus.requestEntityTooLarge,
              'payload_too_large',
              'Request body exceeds the allowed limit ($_mbLabel)',
            );
            return;
          } on TimeoutException {
            await _terminate(
              response,
              HttpStatus.requestTimeout,
              'request_timeout',
              'Timed out waiting for the complete request body',
            );
            return;
          } on FormatException {
            await _terminate(
              response,
              HttpStatus.badRequest,
              'invalid_utf8',
              'The request body is not valid UTF-8',
            );
            return;
          }
          if (!_jsonShapeWithinLimits(
            body,
            config.maxJsonElements,
            config.maxJsonDepth,
          )) {
            await _terminate(
              response,
              HttpStatus.requestEntityTooLarge,
              'payload_too_complex',
              'Request body has too many JSON elements or is nested too '
                  'deeply (over ${config.maxJsonElements} elements or '
                  '${config.maxJsonDepth} deep) — send fewer, shallower '
                  'elements',
            );
            return;
          }
          final List<String> payloads;
          try {
            payloads = _extractPayloads(body);
          } on _UnsupportedPayloadShapeException {
            await _json(response, HttpStatus.badRequest, {
              'ok': false,
              'error': 'unsupported_payload_shape',
              'message':
                  'JSON body has a known-but-unsupported '
                  'shape (object without known command keys)',
            });
            return;
          }
          if (payloads.isEmpty) {
            await _json(response, HttpStatus.badRequest, {
              'ok': false,
              'error': 'empty_payload',
              'message': 'No valid command payload found in the request',
            });
            return;
          }

          final source = _firstHeader(request, 'Origin') ?? 'unknown-portal';
          // سقف العمل الحي عند المعالج: المقاعد وحدها لا تحرس شيئا بعد
          // مهلة المعالج — اليتامى ما زالوا يعملون فعلا، فالميزانية
          // المقاعد+اليتامى معا، وفوقها يُرد 503 قبل استدعاء معالج جديد
          if (_activeRequests + _orphanHandlers >
              config.maxConcurrentRequests) {
            telemetry.warn(
              'intake busy: $_orphanHandlers orphan handler(s) still '
              'running — rejecting before invoking another',
              category: BridgeCategory.network,
            );
            await _terminate(
              response,
              HttpStatus.serviceUnavailable,
              'server_busy',
              'The server is busy right now — please retry shortly',
            );
            return;
          }
          // المعرف يمر للمتحكم عبر خريطة الترويسات (مفتاح صغير
          // كالبقية) — بلا تغيير توقيع الدالة أو مستهلكيها.
          // المعالج تحت مهلة اختيارية: null لا يمس شيئا؛
          // والقيمة تحرر المقعد برد 504 — والنتيجة المتأخرة تُهمل.
          final commandFuture = onCommand(
            TrustedCommand(
              source: source,
              payloads: payloads,
              headers: {
                ..._stringHeaders(request),
                'x-correlation-id': correlationId,
              },
              correlationId: correlationId,
            ),
          );
          final CommandOutcome result;
          try {
            result = handlerTimeout == null
                ? await commandFuture
                : await commandFuture.timeout(handlerTimeout!);
          } on TimeoutException {
            // null يعني لا مهلة أصلا: TimeoutException
            // هنا رمى المعالجُ نفسه فيعود لمساره الأصلي (500 internal)
            // زاوية كانت تنقض «null صفر-تغيير حرفيا»
            if (handlerTimeout == null) rethrow;
            commandFuture.ignore();
            // اليتيم ما زال يعمل فعلا: يُعدّ ضمن ميزانية العمل الحي،
            // وفراغه يدق جرس تفريغ stop — then بمعالج خطأ فارغ كي لا
            // يُحيى خطأه المتأخر (ignore كان يخص المستقبل الأصلي وحده)
            _orphanHandlers++;
            commandFuture.then<void>(
              (_) => _orphanSettled(),
              onError: (_) => _orphanSettled(),
            );
            telemetry.warn(
              'intake handler timeout — seat released, late result ignored',
              category: BridgeCategory.network,
            );
            await _terminate(
              response,
              HttpStatus.gatewayTimeout,
              'handler_timeout',
              'The command handler exceeded its time budget',
            );
            return;
          }

          await _json(
            response,
            result.ok ? HttpStatus.ok : HttpStatus.internalServerError,
            {
              'ok': result.ok,
              if (!result.ok)
                'error': result.errorCode ?? config.fallbackErrorCode,
              // نص المضيف للمعتمدين حصرا — الرمز عقد الجميع
              if (!result.ok && verboseErrors)
                'message': result.errorMessage ?? 'Command execution failed',
            },
          );
        } catch (error, stack) {
          telemetry.error(
            'intake handler crashed',
            error: error,
            stackTrace: stack,
            category: BridgeCategory.network,
          );
          await _json(response, HttpStatus.internalServerError, {
            'ok': false,
            'error': 'internal',
            'message': 'Internal server error',
          });
        }
      },
      context: {
        'method': request.method,
        'origin': _firstHeader(request, 'Origin') ?? 'unknown',
        'correlationId': correlationId,
      },
    );
  }

  /// Reads the body with a cumulative byte counter: hitting the cap or the
  /// deadline stops reading at once (never a silent truncation); total silence
  /// is cut by the stream timeout while slow dripping is cut by a per-request
  /// monotonic deadline. UTF-8 after the size is settled: no string above the cap is ever built.
  ///
  /// Stopping pauses the subscription instead of cancelling it: cancelling a
  /// body subscription makes HttpServer destroy the connection at once and
  /// swallow the reply before delivery (measured directly on HttpServer), while
  /// an unconsumed body lets the reply through and then closes - the reject contract itself: honest reply plus cut.
  Future<String> _readBody(HttpRequest request) async {
    // copy:false: لا نسخة عند add — النسخة الوحيدة عند
    // takeBytes؛ ومخازن مقاطس dart:io طازجة لكل حدث فلا مشاركة
    final builder = BytesBuilder(copy: false);
    // أساس مونوتوني لكل طلب — لا wall-clock يتجمّد أو يقفز.
    final deadlineMs = _now + effectiveTimeout.inMilliseconds;
    final done = Completer<String>();
    StreamSubscription? subscription;
    var settled = false;

    void settle(Object? error, [String? body]) {
      if (settled) return;
      settled = true;
      subscription?.pause();
      if (error != null) {
        // الرفض يحرر المخزن في الحال — لا ينتظر خروج النطاق
        builder.clear();
        done.completeError(error);
      } else {
        done.complete(body!);
      }
    }

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
            try {
              settle(null, utf8.decode(builder.takeBytes()));
            } on FormatException catch (e) {
              settle(e);
            }
          },
          onError: (Object error) => settle(error),
        );
    return done.future;
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

  /// A non-loopback name in extraHosts (a public DNS name, or a
  /// private-network address like 192.168.x.x) is the host's explicit
  /// opt-out of the DNS-rebinding guard for that one name - say it once at
  /// startup so the decision is visible in the log, not silent in the
  /// config. Local means a literal: `localhost`, a bracketed `::1`, or an
  /// address that parses inside the loopback range - a `127.` text prefix
  /// would silence the warning for public names that merely resolve to
  /// loopback (`127.0.0.1.nip.io`), which is exactly the opt-out that
  /// must be said.
  void _warnExtraHosts(List<String> extraHosts) {
    for (final raw in extraHosts) {
      final host = raw.trim().toLowerCase();
      final asAddress = InternetAddress.tryParse(host);
      final isLocal =
          host == 'localhost' ||
          host == '[::1]' ||
          (asAddress != null && asAddress.isLoopback);
      if (host.contains('.') && !isLocal) {
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
  /// or raw commands), a single string, or a JSON wrapper carrying a data field.
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
      // نص JSON: يُفك اقتباسه ويستعمل — إرساله خاما كان يطبع علامتي
      // الاقتباس نفسها مع أن العقد يعد بسلسلة مجردة
      if (decoded is String) {
        return decoded.isEmpty ? const [] : [decoded];
      }
      if (decoded is Map) {
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
    // ترسل أوامر TSPL نصا، وغالبا بأسطر ختامية)
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

  /// Last evicted-id warning - at most one warning per second: a local attacker
  /// sending hostile ids without a cap used to flood the log. The next warning
  /// carries the muted count so the attack's size stays visible.
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
  void _corsHeaders(HttpResponse response) {
    // البوابات صفحات https تتصل بـ http محلي — CORS صريح إلزامي.
    // الصدى (ACAO) يقرر لاحقا بعد حسم القبول أو عند الpreflight — لا
    // هنا: رفض قابل القراءة يعطي المهاجم قناة استطلاع
    response.headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    response.headers.set(
      'Access-Control-Allow-Headers',
      'Content-Type, X-Portal-Token, X-Correlation-Id',
    );
    response.headers.contentType = ContentType.json;
  }

  Future<void> _json(
    HttpResponse response,
    int status,
    Map<String, Object> body,
  ) async {
    response.statusCode = status;
    response.write(jsonEncode(body));
    await response.close();
  }

  /// A final reply after which the connection is cut - limit errors (413/408/503)
  /// close it so the sender cannot keep pushing an already-rejected request.
  Future<void> _terminate(
    HttpResponse response,
    int status,
    String code,
    String message,
  ) async {
    response.persistentConnection = false;
    await _json(response, status, {
      'ok': false,
      'error': code,
      'message': message,
    });
  }
}
