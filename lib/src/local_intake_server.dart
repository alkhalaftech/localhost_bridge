import 'dart:async';
import 'dart:convert';
import 'dart:math' show Random;
import 'dart:typed_data' show BytesBuilder, Uint8List;

import 'dart:io';

import 'bridge_config.dart';
import 'bridge_telemetry.dart';
import 'intake_invariants.dart';
import 'intake_protection.dart';
import 'intake_rejections.dart';
import 'tls_handshake_feed.dart';
import 'trusted_command.dart';

/// Body over the byte cap - an internal exception that tells the 413 reject
/// apart from other read errors, so the intake replies with the honest code, never a silent truncation.
class _BodyTooLargeException implements Exception {
  const _BodyTooLargeException();
}

/// Binary body over the internal binary ceiling - the same 413 family as
/// [_BodyTooLargeException] with its own honest message naming the
/// binary cap, not the byte cap.
class _BinaryBodyTooLargeException implements Exception {
  const _BinaryBodyTooLargeException();
}

/// A non-string or empty-string element inside a JSON command list while
/// the strict-items option is on: the whole request is refused instead of
/// the default silent drop of the offending element.
class _StrictPayloadItemException implements Exception {
  const _StrictPayloadItemException();
}

/// A body sent as `application/json` that failed JSON decoding while the
/// declared-type strictness option is on.
class _InvalidJsonException implements Exception {
  const _InvalidJsonException();
}

/// A body that reached the raw-text fallback path while the JSON-only
/// option is on - a decode failure under any type, or a JSON scalar
/// (number, boolean, null) that arrives as raw command text.
class _NonJsonBodyException implements Exception {
  const _NonJsonBodyException();
}

/// The outcome of one body read: either a complete body (text for the
/// JSON/raw path, bytes for the binary path), or the rejection error -
/// which is only handed back AFTER the unread remainder was drained (or
/// the bounded patience ran out): closing over unread data makes the
/// framework destroy the connection, and Linux and macOS answer that
/// destroy with a reset that throws the reply away.
class _BodyOutcome {
  _BodyOutcome.text(String text) : body = text, binary = null, error = null;
  _BodyOutcome.bytes(Uint8List bytes)
    : body = null,
      binary = bytes,
      error = null;
  _BodyOutcome.rejected(this.error) : body = null, binary = null;

  final String? body;
  final Uint8List? binary;
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

/// قيما المرسلة من انتظار أول رسالة على القناة — قيمُ حدٍّ لا رسالة:
/// المهلة انقضت أو النظير رحل قبل أي رسالة
enum _WsAuthMarker { timeout, gone }

/// One working orphan: the budget-expired command future holds a ticket
/// from creation to settlement, so a stop can retire the whole still-
/// working generation at its return with per-ticket routing (a retired
/// ticket's settlement decrements the retired pool, never the active one
/// a new generation is budgeted against). The ticket carries the
/// command's cancel signal so the cooperative fires stay addressable per
/// orphan.
class _OrphanTicket {
  _OrphanTicket(this.signal);

  /// The command's own cancel signal - fired at the budget expiry, and
  /// removed from the live set when the future settles either way.
  final CommandCancelSignal signal;

  /// Set once, at the stop's return that retires this generation.
  bool retired = false;
}

/// What one [LocalIntakeServer.stop] left still working when it returned -
/// a reading, not a handle. A fully drained stop reports zeros; a stop
/// bounded by its [LocalIntakeServer.stop] timeout (or by the orphan
/// grace) reports the remainder, so the caller never guesses whether work
/// outlived the stop.
class BridgeStopReport {
  const BridgeStopReport._({
    required this.seatsStillActive,
    required this.orphanHandlersStillRunning,
  });

  /// Requests still holding a seat when the stop returned. Seats are real
  /// work on live sockets, so they are never silently dropped - the count
  /// lets a bounded stop own that honestly.
  final int seatsStillActive;

  /// Orphaned handlers (budget-expired work) still running when the stop
  /// returned, across generations: orphans retired at an earlier stop's
  /// return count here while they are still working.
  final int orphanHandlersStillRunning;

  /// Seats plus orphans still working at the return.
  int get stillRunning => seatsStillActive + orphanHandlersStillRunning;

  /// Whether nothing was left working at the return.
  bool get fullyDrained => stillRunning == 0;

  @override
  String toString() =>
      'BridgeStopReport(seatsStillActive: $seatsStillActive, '
      'orphanHandlersStillRunning: $orphanHandlersStillRunning)';
}

/// A read-only snapshot of the intake's live-work and rejection counters -
/// what a host dashboard reads: the seats in use, the working orphans
/// (current and retired generations), and the rejections by wire code with
/// the two overlapping tallies (protocol shape and pairing). Values are
/// copied at snapshot time; the rejection map cannot be written.
class BridgeCounters {
  const BridgeCounters._({
    required this.activeSeats,
    required this.orphanHandlers,
    required this.retiredOrphanHandlers,
    required this.tlsHandshakesInFlight,
    required this.tlsSocketsCut,
    required this.tlsHandshakesDelivered,
    required this.rejectionsByCode,
    required this.protocolShapeRejections,
    required this.pairingRejections,
  });

  /// Requests holding a seat right now.
  final int activeSeats;

  /// Orphaned handlers (budget-expired work) still running, across
  /// generations: the current generation's orphans plus the retired ones.
  final int orphanHandlers;

  /// The subset of [orphanHandlers] retired at a previous stop's return -
  /// visible here, never counted against the live-work budget.
  final int retiredOrphanHandlers;

  /// TLS handshakes in flight right now on the secure listener: sockets
  /// accepted but still before their first record completes, plus
  /// sockets handed to the TLS engine whose handshake has not settled.
  /// A socket that completed its handshake is delivered to the intake
  /// and counted by the open-connection number instead - the feed stops
  /// counting it the moment it is delivered, so the two tallies never
  /// double-count one socket.
  final int tlsHandshakesInFlight;

  /// Sockets the TLS feed has cut on the wire since the server was
  /// built, cumulative: the non-handshake first byte, the over-cap
  /// declared record length, the first-record timeout, the over-cap
  /// accept, and stop's pre-arming harvest all land here. A peer that
  /// disconnects on its own is not a cut, and a delivered handshake is
  /// never a cut.
  final int tlsSocketsCut;

  /// TLS handshakes completed and delivered to the intake since the
  /// server was built, cumulative - the proof the secure door served
  /// through the feed.
  final int tlsHandshakesDelivered;

  /// Every rejection answered since the server was built, by wire code -
  /// counted at the single reply exit, so no path can bypass the tally.
  final Map<String, int> rejectionsByCode;

  /// Rejections answered by the pre-admission wire-shape gates and the
  /// HTTP parser reject (`origin_too_long`, `origin_malformed`,
  /// `token_too_long`, `pairing_too_long`, `duplicate_header`, and
  /// `bad_request` from the parser) - exactly the codes the protection
  /// layer's rejection counter never sees. An overlapping view over
  /// [rejectionsByCode], not a partition.
  final int protocolShapeRejections;

  /// Pairing refusals: everything answered on the pairing route, plus the
  /// pairing-family codes refused off the route (the `pairing_too_long`
  /// gate and the command-path `pair_signature_replay`). An overlapping
  /// view over [rejectionsByCode], not a partition.
  final int pairingRejections;
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

/// The verdict of one host-fed channel message: an accepted
/// [TrustedCommand] or the rejection with the standing wire codes.
/// Exactly one of [command] and [rejection] is non-null; [admission]
/// carries the admission record (its [IntakeAdmission.originTrust]
/// included) for every verdict that passed the wire-shape gates, and is
/// null only for the shape-gate rejects that run before admission - the
/// same split the HTTP wire keeps.
///
/// The grade the origin carried lives in the record only: nothing on
/// this result, and nothing the host may put on its channel, is shaped
/// by it beyond the decision itself.
class HostFeedResult {
  const HostFeedResult._({
    required this.command,
    required this.rejection,
    required this.admission,
  });

  /// The accepted command - non-null exactly when the message passed
  /// every check. Executing it is the host's job: the feed holds no
  /// seat for it, and the command carries a live cancel signal the host
  /// owns (the server's stop cannot fire it).
  final TrustedCommand? command;

  /// The refusal - the same [IntakeRejection] contract the HTTP wire
  /// answers with: the status the same fact would carry on HTTP, the
  /// registered code, the neutral message, and the honest wait when one
  /// applies. The host forwards it over its own channel in its own
  /// shape; the package writes nothing anywhere.
  final IntakeRejection? rejection;

  /// The admission record behind the verdict - null only when a
  /// wire-shape gate refused before admission ran (the origin and token
  /// gates), mirroring the HTTP order where those rejects carry no
  /// record.
  final IntakeAdmission? admission;

  /// Whether the message was accepted ([command] non-null).
  bool get accepted => command != null;
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

/// What a host pins its clients against - the read-only identity of one
/// bridge instance: the port actually bound, the stable random instance id
/// ([LocalIntakeServer.instanceId] - constant across pause and resume), and
/// the protocol version this package speaks on its wire.
class BridgeInstanceInfo {
  /// Builds the identity snapshot.
  const BridgeInstanceInfo({
    required this.port,
    required this.instanceId,
    required this.protocolVersion,
  });

  /// The port the listener is actually bound on - the corrected value when
  /// the host asked for a random port, never the requested one.
  final int port;

  /// The instance id the host pins its paired clients against - 32 hex
  /// characters of secure random, generated once at server construction and
  /// stable across pause/resume and across restarts of the same object.
  final String instanceId;

  /// The protocol version this instance speaks.
  final String protocolVersion;

  /// The wire-contract version this package speaks: the reply contract
  /// (`{"ok": ...}` with the standing error codes) and its admission
  /// shape. It names the wire contract, not the package release - it moves
  /// only when the wire contract itself does.
  static const String bridgeProtocolVersion = '0.2.0';
}

/// A local HTTP intake server for external portals.
///
/// Listens on loopback only (127.0.0.1 by default, with the optional `::1`
/// and unix-socket listeners each armed explicitly and off by default) on a
/// configurable port with fallbacks when busy, and answers with CORS headers
/// for the origins it allowed, so portal https pages can send commands
/// straight from the browser. Errors always come back with clear messages -
/// no silent failure.
///
/// Resource limits (body cap / timeout / seat cap) apply in every protection
/// mode - even allow-all - because they are what makes accepting any site memory-safe.
class LocalIntakeServer {
  /// Builds the server. Only [onCommand] is required: [telemetry]
  /// defaults to the line-writing [PrintTelemetry] (the security warnings
  /// reach stderr, never swallowed by a missing sink) and
  /// [correlationIdGenerator] defaults to the internal secure-random
  /// generator; [protection] defaults to an [IntakeProtection] wired to
  /// this server's telemetry, and [config] defaults to
  /// `const BridgeConfig()`. Non-positive caps or timeouts - in
  /// [config], [requestTimeout], or [handlerTimeout] - throw
  /// [ArgumentError] here at construction, never as mystery rejects on
  /// the wire. [nowMs] is an injectable monotonic test clock.
  LocalIntakeServer({
    int Function()? nowMs,
    required this.onCommand,
    this.telemetry = const PrintTelemetry(),
    this.correlationIdGenerator = _defaultCorrelationId,
    IntakeProtection? protection,
    this.config = const BridgeConfig(),
    this.requestTimeout,
    this.handlerTimeout,
    this.wsAuthTimeout,
    this.onOrphanSettled,
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
    if (config.maxOpenConnections < 0) {
      throw ArgumentError.value(
        config.maxOpenConnections,
        'config.maxOpenConnections',
        'must not be negative - 0 is the named off value',
      );
    }
    if (config.maxErrorMessageLength < 0) {
      throw ArgumentError.value(
        config.maxErrorMessageLength,
        'config.maxErrorMessageLength',
        'must not be negative - 0 is the named off value',
      );
    }
    // مهلة أول سجل TLS بنطاق صريح: تحت الثانية يقطع مصافحات حقيقية على
    // شبكة بطيئة، وفوق الدقيقة يعيد فتح نافذة الصامت التي أغلقها الحد —
    // والقيمة خارج النطاق خطأ إعداد يُقال عند البناء لا مفاجأة على السلك
    if (config.tlsFirstRecordTimeout < const Duration(seconds: 1) ||
        config.tlsFirstRecordTimeout > const Duration(seconds: 60)) {
      throw ArgumentError.value(
        config.tlsFirstRecordTimeout,
        'config.tlsFirstRecordTimeout',
        'must be between one second and sixty seconds - below the floor it '
            'cuts real handshakes on slow networks, above the ceiling it '
            're-opens the silent-client window the bound exists to close',
      );
    }
    if (config.maxSeatsPerOrigin < 1) {
      throw ArgumentError.value(
        config.maxSeatsPerOrigin,
        'config.maxSeatsPerOrigin',
        'must be positive - a value below one refuses every origin its '
            'own seats; raise it toward maxConcurrentRequests to widen a '
            "sender's share (the global cap still binds first)",
      );
    }
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
    if (wsAuthTimeout != null && wsAuthTimeout! <= Duration.zero) {
      throw ArgumentError.value(
        wsAuthTimeout,
        'wsAuthTimeout',
        'must be positive - omit it to use the package internal '
            'WebSocket auth deadline',
      );
    }
    final wsPath = config.wsPath;
    if (wsPath != null) {
      if (wsPath.isEmpty || !wsPath.startsWith('/')) {
        throw ArgumentError.value(
          wsPath,
          'config.wsPath',
          'must be a non-empty path starting with "/" (the WebSocket '
              'channel stays off entirely while wsPath is null)',
        );
      }
      if (wsPath == _pairingPath) {
        throw ArgumentError.value(
          wsPath,
          'config.wsPath',
          'collides with the pairing route "/pair" - choose another path '
              'so both registered routes stay unambiguous',
        );
      }
    }
    // نقل TLS ومقبس يونكس معاً رفضٌ وقت البناء: dart:io لا يملك ربطاً
    // آمناً لمقبس يونكس، ومستمع يبقى عارياً بصمت تحت خيار TLS يوعد
    // الحماية وهو لا يوصلها - فلا تُقبل التوليفة أصلاً
    if (config.securityContext != null && config.unixSocketPath != null) {
      throw ArgumentError.value(
        config.unixSocketPath,
        'config.unixSocketPath',
        'carries no TLS in dart:io - it cannot be combined with '
            'config.securityContext, which would leave one listener '
            'silently plain under a TLS option; pass one or the other',
      );
    }
    // القناة بلا سقف نقل لا تُسلَّح: معلمة الطول المعلن على ترقية
    // WebSocketTransformer دخلت dart:io في 3.13 حصراً، وعلى SDK أقدم
    // لا حد للذاكرة على الإطارات فتسليح القناة رفضٌ صاخب وقت البناء —
    // لا ترقية بلا سقف ولا مسار رجوع، والبدء يفشل عند البناء قبل أي
    // مستمع أو طلب
    if (config.wsPath != null && !wsTransportCeilingSupported) {
      throw ArgumentError.value(
        config.wsPath,
        'config.wsPath',
        'needs dart:io 3.13+ - WebSocketTransformer.upgrade gained its '
            'maxPayloadLength transport ceiling in Dart 3.13, and this '
            'SDK ("${Platform.version}") has no frame length ceiling, so '
            'the channel refuses to arm without a memory limit; upgrade '
            'the SDK or leave wsPath null (every non-channel path works '
            'unchanged)',
      );
    }
    // الصفحات المحلية: null هو الإيقاف حصراً - القائمة الفارغة ليست وضع
    // إيقاف بل خطأ إعداد يُقال صاخباً عند البناء قبل أي طلب على السلك
    final pages = config.localPages;
    if (pages != null) {
      if (pages.isEmpty) {
        throw ArgumentError.value(
          pages,
          'config.localPages',
          'is empty - null is the off value; list at least one page or '
              'leave the option at null',
        );
      }
      final seen = <String>{};
      for (final page in pages) {
        final path = page.path;
        if (path.isEmpty || !path.startsWith('/')) {
          throw ArgumentError.value(
            path,
            'config.localPages.path',
            'must be a non-empty path starting with "/"',
          );
        }
        if (path == _pairingPath) {
          throw ArgumentError.value(
            path,
            'config.localPages.path',
            'collides with the pairing route "/pair" - choose another '
                'path so both registered routes stay unambiguous',
          );
        }
        if (!seen.add(path)) {
          throw ArgumentError.value(
            path,
            'config.localPages.path',
            'is registered twice - two pages on one path build an '
                'ambiguous lookup table',
          );
        }
        if (page.contentType.trim().isEmpty) {
          throw ArgumentError.value(
            page.contentType,
            'config.localPages.contentType',
            'must be a non-empty media type',
          );
        }
      }
      if (wsPath != null && pages.any((page) => page.path == wsPath)) {
        throw ArgumentError.value(
          wsPath,
          'config.wsPath',
          'collides with a registered local page path - choose another '
              'path so both registered routes stay unambiguous',
        );
      }
    }
    // صفحة الصحة: null هو الإيقاف حصراً - القيمة المسلحة مسار واضح لا يصطدم
    // بأي مسار مسجل، والصدم يُقال صاخباً عند البناء قبل أي طلب على السلك
    final health = config.healthPath;
    if (health != null) {
      if (health.isEmpty || !health.startsWith('/') || health == '/') {
        throw ArgumentError.value(
          health,
          'config.healthPath',
          'must be a non-empty path starting with "/" and different from '
              'the command root "/" (null is the off value)',
        );
      }
      if (health == _pairingPath) {
        throw ArgumentError.value(
          health,
          'config.healthPath',
          'collides with the pairing route "/pair" - choose another '
              'path so both registered routes stay unambiguous',
        );
      }
      if (wsPath != null && health == wsPath) {
        throw ArgumentError.value(
          health,
          'config.healthPath',
          'collides with the WebSocket channel path - choose another '
              'path so both registered routes stay unambiguous',
        );
      }
      if (pages != null && pages.any((page) => page.path == health)) {
        throw ArgumentError.value(
          health,
          'config.healthPath',
          'collides with a registered local page path - choose another '
              'path so both registered routes stay unambiguous',
        );
      }
    }
    // مقبس يونكس: خيار لينكس وماك حصرا - على Windows لا مقابس يونكس في
    // dart:io أصلا فالقيمة المسلحة خطأ إعداد يُرمى عند البناء، والمسار
    // الفارغ (أو بحرف NUL) كذلك في كل المنصات
    final unixPath = config.unixSocketPath;
    if (unixPath != null) {
      if (unixPath.isEmpty || unixPath.contains('\x00')) {
        throw ArgumentError.value(
          unixPath,
          'config.unixSocketPath',
          'must be a non-empty filesystem path without a NUL byte '
              '(null is the off value)',
        );
      }
      if (Platform.isWindows) {
        throw ArgumentError.value(
          unixPath,
          'config.unixSocketPath',
          'is a Linux/macOS option - unix domain sockets are not part of '
              'dart:io on Windows; leave it at null',
        );
      }
    }
  }

  /// Called with every trusted command the package hands to the registered host.
  final TrustedCommandHandler onCommand;

  /// The measurement and log seam: the host adapts its own logger, keeping
  /// intake latency and classification alive. Optional - the default is
  /// the line-writing [PrintTelemetry], so a host that passes none still
  /// hears the security warnings (they reach stderr) instead of running
  /// muted; pass your own sink to route the lines elsewhere.
  final BridgeTelemetry telemetry;

  /// Correlation-id generator - the host may pass its own; the default is
  /// the internal secure-random generator below, so the host passes
  /// nothing to get unique ids. Only requests that carry no
  /// `X-Correlation-Id` reach it - an incoming id is honored verbatim and
  /// never passes through the generator.
  final String Function() correlationIdGenerator;

  /// The internal default correlation-id generator: a wall-clock stamp and
  /// a secure-random draw, so two calls in the same microsecond still
  /// differ. One string per call, no state, no dependency beyond dart:.
  static String _defaultCorrelationId() =>
      '${DateTime.now().microsecondsSinceEpoch.toRadixString(36)}-'
      '${Random.secure().nextInt(0x7fffffff).toRadixString(36)}';

  /// Optional intake protection (open/allowlist/token) - read live on every
  /// request so a settings change takes effect without restarting the listener.
  /// The default one is built with this server's telemetry so its security
  /// log (allow-all warnings, rejection lines) is not muted; a passed one
  /// carrying no telemetry warns once at [start] with directions to wire it.
  final IntakeProtection protection;

  /// The WebSocket auth-deadline override (tests inject it) - the deadline
  /// the first message of a connection must arrive within. Null selects the
  /// package internal constant; a non-positive value throws [ArgumentError]
  /// at construction.
  final Duration? wsAuthTimeout;

  /// The effective first-message deadline of the WebSocket channel: the
  /// explicit parameter when given, else the internal constant.
  late final Duration effectiveWsAuthDeadline =
      wsAuthTimeout ?? _wsAuthDeadlineDefault;

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

  /// Called once per orphaned-handler settlement - the budget-expired
  /// work that finished after its seat was freed, whether still current-
  /// generation or retired at a stop's return. Runs on the settle path:
  /// a throw inside it is contained (telemetry.error) and never breaks
  /// the wire or the drain bookkeeping.
  final void Function()? onOrphanSettled;

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

  /// Live seats per sender bucket - the key is the normalized Origin
  /// (`IntakeAdmission.normalizedOrigin`) and `''` is the shared bucket of
  /// the requests that carried no Origin header. The map is bounded by
  /// the seats themselves (one entry per held seat, emptied on release),
  /// so it cannot grow past [BridgeConfig.maxConcurrentRequests].
  final Map<String, int> _seatsByOrigin = <String, int>{};

  /// Handlers still running after their request already timed out (504) and
  /// left - the seat model does not see them, but the work is real: a local
  /// Dart app's command could outlive stop() unless counted. Seats plus
  /// current-generation orphans are one live-work budget, and stop() drains
  /// the orphans up to the handler budget.
  int _activeOrphans = 0;

  /// Working orphans retired at a stop's return: the previous generation's
  /// orphans never count against a new generation's live-work budget, but
  /// they stay visible in the public orphan counter until they settle.
  int _retiredOrphans = 0;

  /// One ticket per working orphan - the budget-expired command future
  /// keeps it so a stop can retire the whole generation at its return
  /// (per-ticket routing: a retired ticket's settlement leaves the retired
  /// pool, not the active one).
  final Set<_OrphanTicket> _pendingOrphans = <_OrphanTicket>{};

  /// The cancel signals of every command still holding a seat or working
  /// as an orphan - stop fires them all so cooperative handlers wrap up
  /// and free their work inside the drain instead of finishing into a
  /// reply nobody reads. Removal rides the command future's own
  /// completion, so a crashing handler leaks nothing.
  final Set<CommandCancelSignal> _liveSignals = <CommandCancelSignal>{};

  /// Armed when stop() arrives while orphans still run - completed when the
  /// last orphan settles.
  Completer<void>? _orphanDrain;

  /// The rejection tally by wire code - written at the single reply exit
  /// only, so no rejection path can bypass the count.
  final Map<String, int> _rejectionsByCode = <String, int>{};
  int _protocolShapeRejections = 0;
  int _pairingRejections = 0;

  /// The wire-shape codes: the pre-admission gates that never reach the
  /// protection counter (plus the parser's `bad_request`, flagged at its
  /// call site - the pairing route reuses the code for a body fact, and
  /// that one is not a wire shape).
  static const _protocolShapeRejectionCodes = <String>{
    'origin_too_long',
    'origin_malformed',
    'token_too_long',
    'pairing_too_long',
    'duplicate_header',
  };

  /// The pairing-family codes: refused on the pairing route and off it
  /// (the length gate rides every request, and the replay refusal rides
  /// the command path).
  static const _pairingRejectionCodes = <String>{
    'pair_code_invalid',
    'pair_code_expired',
    'pair_budget_exceeded',
    'pair_signature_replay',
    'pairing_too_long',
  };

  // عدّادا التلقمة تراكميان على الخادم لا على الجيل: القطع والسلامات
  // يبقيان عبر stop/start كي يقرأ المضيف تراكم الجسر كله لا الجيل الأخير
  int _tlsSocketsCut = 0;
  int _tlsHandshakesDelivered = 0;

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

  /// تلقمة النقل الآمن للمستمع الأساسي: موجودة حين سياق TLS مسلَّح
  /// — وإغلاق HttpServer يمر منها فيحصد ما قبل التسليح في كل مسار
  TlsHandshakeFeed? _feed;

  /// The optional `::1` listener - bound only while
  /// [BridgeConfig.listenIPv6Loopback] is armed and the bind succeeded.
  HttpServer? _serverV6;

  /// تلقمة النقل الآمن لمستمع الـ::1 الاختياري — نقل الباب الأول نفسه
  TlsHandshakeFeed? _feedV6;

  /// The optional unix-socket listener - bound only while
  /// [BridgeConfig.unixSocketPath] is armed and the bind and its
  /// owner-only permission guard both succeeded.
  HttpServer? _serverUnix;

  /// The filesystem path of the socket this instance actually created -
  /// the only path a stop may unlink, and only while it still names a
  /// unix domain socket.
  String? _unixSocketPath;

  /// The port a [pause] remembered for its [resume] - null when the server
  /// is not paused. A successful resume or a fresh [start] clears it; a
  /// failed resume keeps it so the host can retry when the port frees.
  int? _pausedPort;

  /// The pinning identity of this instance - generated once at
  /// construction from secure random, stable across pause/resume and
  /// across stop/start generations of the same object.
  final String _instanceId = _generateInstanceId();

  /// 32 hex characters of secure random - 128 bits, no counter and no
  /// timestamp inside, so the id carries no structure to mine.
  static String _generateInstanceId() {
    final rng = Random.secure();
    return List<String>.generate(
      16,
      (_) => rng.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
  }

  /// The pinning identity of this bridge instance - stable across
  /// [pause]/[resume] and across stop/start generations (it is the
  /// instance's, not a generation's). Generated from secure random at
  /// construction.
  String get instanceId => _instanceId;

  /// The read-only identity snapshot: the actual bound port, the stable
  /// instance id, and the protocol version. Available while a listener is
  /// bound - the actual port is a bound fact, so a paused or stopped
  /// server throws [StateError] here ([instanceId] stays readable at
  /// every moment).
  BridgeInstanceInfo get instanceInfo {
    if (_port == 0) {
      throw StateError(
        'instanceInfo needs a bound listener - the actual port reads only '
        'while the server is listening; instanceId stays readable',
      );
    }
    return BridgeInstanceInfo(
      port: _port,
      instanceId: _instanceId,
      protocolVersion: BridgeInstanceInfo.bridgeProtocolVersion,
    );
  }

  /// The bound port while listening, and `0` when not - including after a
  /// `start()` that failed on a post-bind step: a stale bound number would
  /// point callers at a listener that no longer exists.
  int get port => _port;

  /// Whether a bound server is live right now: true between a successful
  /// [start] and the [stop] that unbinds it, false before, during a
  /// failing start, during a drain, and after a mid-start failure whose
  /// orphan was closed. [port] is 0 whenever this is false.
  bool get isListening => _server != null;

  /// The read-only counter snapshot: seats in use, working orphans across
  /// generations, the TLS feed's in-flight handshakes with its cut and
  /// delivered tallies, and the rejections by wire code with the
  /// protocol-shape and pairing tallies. Read it anytime - it never
  /// touches the wire.
  BridgeCounters get counters => BridgeCounters._(
    activeSeats: _activeRequests,
    orphanHandlers: _activeOrphans + _retiredOrphans,
    retiredOrphanHandlers: _retiredOrphans,
    tlsHandshakesInFlight:
        (_feed?.ongoingHandshakes ?? 0) + (_feedV6?.ongoingHandshakes ?? 0),
    tlsSocketsCut: _tlsSocketsCut,
    tlsHandshakesDelivered: _tlsHandshakesDelivered,
    rejectionsByCode: Map.unmodifiable(Map<String, int>.of(_rejectionsByCode)),
    protocolShapeRejections: _protocolShapeRejections,
    pairingRejections: _pairingRejections,
  );

  /// Feeds one message from a non-HTTP channel through the same single
  /// admission step and the same payload checks the HTTP wire runs, and
  /// hands back an accepted [TrustedCommand] or the rejection with the
  /// standing wire codes - the channels the host feeds directly (an
  /// Android `WebMessageListener` message, an iOS
  /// `WKScriptMessage`, a native client, a browser extension's native
  /// messaging pipe) never grow a second copy of the protection logic.
  ///
  /// The order is the HTTP order, minus the HTTP-only facts: the
  /// wire-shape gates first (origin length and form, token and pairing
  /// lengths - counted as protocol-shape rejections, no admission record
  /// behind them, exactly like the pre-admission gates), then
  /// [IntakeProtection.admit] with the origin and its
  /// [OriginTrustLevel], the token if the channel carried one, and the
  /// correlation id; then the record settles at the acceptance gate
  /// (quota stamps, token-miss stamps, consent questions, and the
  /// counted, throttled security line land exactly as they do for POST);
  /// then the message body passes the standing body limit, the JSON
  /// complexity and shape options, and the payload extraction - the same
  /// codes the HTTP body answers; finally the live-work budget answers
  /// `server_busy` like every other channel. There is no Host header and
  /// no content type on a host-fed channel, so the host-authority gate
  /// and the media gate have no fact to read and do not run.
  ///
  /// [originTrust] is required whenever an origin is passed: the grade is
  /// how much the platform vouches for the value
  /// ([OriginTrustLevel.platformVerified] for a WebView/WebKit callback,
  /// [OriginTrustLevel.browserHeader] for a value read from a
  /// browser-controlled header). An origin with the
  /// [OriginTrustLevel.none] grade throws [ArgumentError] - an origin no
  /// one vouches for is never admitted wearing a browser trust it does
  /// not hold - and an origin-less client passes `origin: null` with
  /// [OriginTrustLevel.none] and crosses by its token alone, or is
  /// refused by the origin paths like any headerless request.
  ///
  /// [body] is the raw message text exactly as the channel delivered it -
  /// JSON or raw command text, judged by the same extraction contract as
  /// the wire. [correlationId] empty (the default) generates one, like an
  /// HTTP request without the header; a value passes the same
  /// sanitization an inbound header gets. The result's rejection carries
  /// the same status, code, message, and honest wait the HTTP wire would
  /// answer this fact with; every rejection is counted by the single
  /// rejection counter, and the verdict's trust grade lives only in
  /// [HostFeedResult.admission] - never on anything this call produces
  /// for a reply.
  ///
  /// The method never touches the network and writes nothing anywhere:
  /// delivering the verdict, and executing an accepted command, are the
  /// host's job over its own channel.
  Future<HostFeedResult> acceptHostFeed({
    required String body,
    required String? origin,
    required OriginTrustLevel originTrust,
    String? token,
    String? pairingProof,
    String correlationId = '',
  }) async {
    // تناقض النداء عيب برمجي لا رفض مرسل: أصل بلا درجة موثقة لا يلبس
    // درجة ترويسة متصفح أبدا، وبلا أصل فلا درجة ترويسة ولا درجة منصة
    if (origin != null && originTrust == OriginTrustLevel.none) {
      throw ArgumentError.value(
        origin,
        'originTrust',
        'is OriginTrustLevel.none while an origin value is present - an '
            'origin no one vouches for is never admitted as a browser '
            'header; pass platformVerified (or browserHeader) or omit the '
            'origin and cross by the token alone',
      );
    }
    if (origin == null && originTrust != OriginTrustLevel.none) {
      throw ArgumentError.value(
        originTrust,
        'originTrust',
        'names a trust grade while origin is null - an absent origin has '
            'no grade but OriginTrustLevel.none',
      );
    }
    // بوابات الشكل البروتوكولي بترتيب السلك نفسه: قبل أي سجل قبول،
    // وبالعدّ من العدّاد الواحد وبحالتها من سجل الرموز لا من الموضع
    if (origin != null && origin.length > _maxOriginChars) {
      final spec = _noteRejection('origin_too_long');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'origin_too_long',
          'The origin exceeds the allowed length '
              '($_maxOriginChars characters)',
        ),
        admission: null,
      );
    }
    if (origin != null &&
        origin.isNotEmpty &&
        origin != 'null' &&
        !IntakeProtection.isWellFormedOrigin(origin)) {
      final spec = _noteRejection('origin_malformed');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'origin_malformed',
          'The origin must be scheme://host[:port]',
        ),
        admission: null,
      );
    }
    if (token != null && utf8.encode(token).length > _maxTokenHeaderBytes) {
      final spec = _noteRejection('token_too_long');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'token_too_long',
          'The token exceeds the allowed length '
              '($_maxTokenHeaderBytes bytes)',
        ),
        admission: null,
      );
    }
    if (protection.pairingEnabled &&
        pairingProof != null &&
        utf8.encode(pairingProof).length > _maxPairingHeaderBytes) {
      final spec = _noteRejection('pairing_too_long');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'pairing_too_long',
          'The pairing proof exceeds the allowed length '
              '($_maxPairingHeaderBytes bytes)',
        ),
        admission: null,
      );
    }
    // خطوة القبول الواحدة نفسها: الأصل بدرجته والتوكن والاقتران
    // ومعرف الارتباط، ثم التسوية عند بوابة القبول تهبط أثرها كما
    // يهبط لأي طلب HTTP (طوابع الحصص والإخفاق والسؤال وعدّ الرفض
    // وسطره الأمني) — لا نسخة حماية ثانية
    final cid = _sanitizeCorrelationId(
      correlationId.isEmpty ? null : correlationId,
    );
    final admission = await protection.admit(
      origin: origin,
      bridgeToken: token,
      path: '/',
      pairingProof: pairingProof,
      method: 'POST',
      correlationId: cid,
      originTrust: originTrust,
    );
    admission.settle();
    final rejection = admission.rejection;
    if (rejection != null) {
      // عدّ الخادم من العدّاد الواحد لا بيده — سجل القبول عدّ أثره
      // وحده (عدّاد الحماية والسطر الأمني)
      _noteRejection(rejection.code);
      return HostFeedResult._(
        command: null,
        rejection: rejection,
        admission: admission,
      );
    }
    // فحوص الحمولة نفسها بترتيب القناة النصية: سقف الجسم ثم تعقيد
    // JSON ثم خيار الشكل ثم الاستخراج ثم الفراغ — كل رفض بالرمز
    // المسجل وبحالته من السجل
    if (utf8.encode(body).length > config.maxBodyBytes) {
      final spec = _noteRejection('payload_too_large');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'payload_too_large',
          'The message body exceeds the allowed limit ($_mbLabel)',
        ),
        admission: admission,
      );
    }
    if (!_jsonShapeWithinLimits(
      body,
      config.maxJsonElements,
      config.maxJsonDepth,
    )) {
      final spec = _noteRejection('payload_too_complex');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'payload_too_complex',
          'Message has too many JSON elements or is nested too deeply '
              '(over ${config.maxJsonElements} elements or '
              '${config.maxJsonDepth} deep) — send fewer, shallower '
              'elements',
        ),
        admission: admission,
      );
    }
    if (config.requireValidJsonShape && !_jsonShapeComplete(body)) {
      final spec = _noteRejection('malformed_json_shape');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'malformed_json_shape',
          'Message claims a JSON container shape but is not structurally '
              'complete — send the whole JSON document',
        ),
        admission: admission,
      );
    }
    final List<String> payloads;
    try {
      payloads = _extractPayloads(body, declaredJson: false);
    } on _UnsupportedPayloadShapeException {
      final spec = _noteRejection('unsupported_payload_shape');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'unsupported_payload_shape',
          'JSON message has a known-but-unsupported shape (object without '
              'known command keys)',
        ),
        admission: admission,
      );
    } on _StrictPayloadItemException {
      final spec = _noteRejection('invalid_payload_item');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'invalid_payload_item',
          'Command list carries a non-string or empty element (strict '
              'item checking is on)',
        ),
        admission: admission,
      );
    } on _InvalidJsonException {
      final spec = _noteRejection('invalid_json');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'invalid_json',
          'The message is not valid JSON',
        ),
        admission: admission,
      );
    } on _NonJsonBodyException {
      final spec = _noteRejection('non_json_body');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'non_json_body',
          'This channel accepts JSON messages only — send the command as '
              'JSON',
        ),
        admission: admission,
      );
    }
    if (payloads.isEmpty) {
      final spec = _noteRejection('empty_payload');
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'empty_payload',
          'No valid command payload found in the message',
        ),
        admission: admission,
      );
    }
    // سقف العمل الحي: بوابته نفسها في الرد الواحد والقناة النصية —
    // اليتامى والمقاعد ميزانية واحدة فوق كل القنوات
    if (_activeRequests + _activeOrphans > config.maxConcurrentRequests) {
      // العدّ من العدّاد الواحد حصراً ثم الكبح بنمط بقية أسطر السعة
      final spec = _noteRejection('server_busy');
      final line = _orphanBusyWarnThrottle.admit(
        'intake busy: $_activeOrphans orphan handler(s) still running — '
        'rejecting before invoking another',
      );
      if (line != null) {
        telemetry.warn(line, category: BridgeCategory.network);
      }
      return HostFeedResult._(
        command: null,
        rejection: IntakeRejection(
          spec.status,
          'server_busy',
          'The server is busy right now — please retry shortly',
        ),
        admission: admission,
      );
    }
    final command = TrustedCommand(
      source: origin ?? 'unknown-origin',
      payloads: payloads,
      headers: {'x-correlation-id': cid},
      correlationId: cid,
      admission: admission,
      // إشارة حية يملكها المضيف: لم تُسجَّل في سلسلة الخادم فلا stop
      // يشعلها — تنفيذ الأمر وشغلانه خارج عقد التغذية
      cancellation: CommandCancelSignal(),
    );
    return HostFeedResult._(
      command: command,
      rejection: null,
      admission: admission,
    );
  }

  /// Processes one request forwarded from the host's own `dart:io` HTTP
  /// server, through the full standing protection - the same gates in the
  /// same order as [start]'s private listener, and the same reply cutting:
  /// every rejection is written to the detached socket, flushed, and the
  /// connection is closed (or destroyed, for the documented immediate-cut
  /// codes) exactly as the private server does. The host keeps its server
  /// and its routing: only the requests the host forwards here reach the
  /// bridge, so another route of the host server is never touched by it.
  ///
  /// [hostPort] is the port the host's server actually listens on (`its
  /// `port` value) - the local host authorities are computed from it, so
  /// the `Host` header of a forwarded request names that port and passes
  /// the authority gate exactly as it would on the private server.
  ///
  /// The one added transport fact is the peer: a host server may be bound
  /// to `0.0.0.0`, and the bridge must keep its loopback guarantee on its
  /// own. The peer guard is the FIRST gate: a forwarded request whose
  /// remote address is not loopback is refused with the standing `403
  /// blocked_by_protection` code - no header is read, no log line is
  /// written, and no warning budget is spent; the rejection is counted
  /// only in the rejection-codes counter, an in-memory number that
  /// helps the host see the attempts - a remote party never writes
  /// into the bridge's security log, so the denial is silent by design
  /// and carries a generated correlation id only. No new wire code is
  /// minted for it, and the cut over the detached socket matches the
  /// standing immediate-cut shape.
  /// An IPv4-mapped IPv6 peer (`::ffff:127.0.0.1`, what a dual-stack host
  /// bind delivers for an IPv4 loopback caller) counts as loopback: the
  /// mapping is unwrapped and the v4 bytes are judged alone. An
  /// unreadable peer fact is treated as not-loopback - the guard fails
  /// closed.
  ///
  /// The open-connection cap ([BridgeConfig.maxOpenConnections]) guards the
  /// bridge's own listener and has no fact to read here - the host owns the
  /// accept loop - so the seat budget
  /// ([BridgeConfig.maxConcurrentRequests], per-origin shares, and the
  /// live-work cap) is the budget that binds on this path. A request held
  /// mid-flight holds its seat exactly as on the private server, so
  /// [stop] waits for it inside its drain. The method never touches
  /// [_server] and works whether or not [start] has been called; the host
  /// remains responsible for not forwarding new requests after it has
  /// decided to shut down.
  Future<void> handleHostRequest(HttpRequest request, {required int hostPort}) {
    // سلطات Host تُبنى من منفذ خادم المضيف لا من منفذ الجسر الخاص: طلب
    // الباب المركب يحمل Host بالمنفذ الذي يسمعه المضيف فعلاً
    final routeAuthorities = computeAuthorities(hostPort, config.extraHosts);
    return _handle(request, authorities: routeAuthorities, mounted: true);
  }

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
  /// contract on every path. A start issued while paused succeeds and
  /// supersedes the pause: the remembered port is forgotten (a new
  /// generation binds its own address), and [resume] afterwards reads
  /// `not paused`.
  Future<int> start({
    required int preferredPort,
    List<int> fallbacks = const [],
  }) {
    final pending = _bindPrecondition();
    if (pending != null) {
      // The rejection travels through the returned future, never thrown
      // synchronously: a synchronous throw escapes a caller's
      // .catchError/.then(onError) on the result - there is no result to
      // attach them to. The StateError contract is identical on every path.
      return Future<int>.error(pending, StackTrace.current);
    }
    return _runBind(
      () => _bindGeneration(
        preferredPort: preferredPort,
        fallbacks: fallbacks,
        resuming: false,
      ),
    );
  }

  /// Reopens the listeners a [pause] closed - on the remembered port, with
  /// no fallbacks: a resume that moved ports silently would break every
  /// client pinned to the address, so the same port is the contract. When
  /// another process took the remembered port meanwhile, the future
  /// rejects with [IntakeBindException] whose message names the fact (the
  /// remembered port and `taken`) - the pause state survives the failed
  /// resume, so the host can retry once the port frees. The optional
  /// listeners rebind too, exactly as their options arm them: a `::1`
  /// bind failure warns and continues on `127.0.0.1` alone (the same rule
  /// as [start]), and a unix-socket bind or permission-guard failure fails
  /// the whole resume. The instance id and every other server state carry
  /// across untouched - resume is a new generation of the same instance.
  /// The error contract mirrors [start]: [StateError] through the returned
  /// future when the server is listening, mid-start, or not paused at all.
  Future<int> resume() {
    final pausedPort = _pausedPort;
    if (pausedPort == null) {
      return Future<int>.error(
        StateError(
          'intake server is not paused - resume follows pause; call start '
          'for a fresh generation',
        ),
        StackTrace.current,
      );
    }
    final pending = _bindPrecondition();
    if (pending != null) {
      return Future<int>.error(pending, StackTrace.current);
    }
    return _runBind(
      () => _bindGeneration(
        preferredPort: pausedPort,
        fallbacks: const [],
        resuming: true,
      ),
    );
  }

  /// The shared StateError precondition for [start] and [resume] - null
  /// when a bind may proceed, the standing error when already listening or
  /// mid-start (the same two facts for both entry points).
  StateError? _bindPrecondition() {
    if (_server != null || _starting) {
      return StateError(
        _server != null
            ? 'intake server already listening on port $_port'
            : 'intake server start already in progress',
      );
    }
    return null;
  }

  /// The shared bind tail of [start] and [resume]: guards the starting
  /// flag across the measure boundary so a synchronous telemetry failure
  /// never strands the gate (the same guard start has always kept).
  Future<int> _runBind(Future<int> Function() bind) {
    _starting = true;
    Future<int> started;
    try {
      started = bind();
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

  /// مجموع الاتصالات المفتوحة عبر المستمعين كلها زائد المصافحات الجارية
  /// في التلقيمتين: حساب سقف الخيار الذي يقرؤه باب القبول وباب الطلب
  /// معاً — سقف واحد لا باب جانبي يحصّنه
  int _openConnectionTotal() =>
      (_server?.connectionsInfo().total ?? 0) +
      (_serverV6?.connectionsInfo().total ?? 0) +
      (_serverUnix?.connectionsInfo().total ?? 0) +
      (_feed?.ongoingHandshakes ?? 0) +
      (_feedV6?.ongoingHandshakes ?? 0);

  /// المصافحات الجارية في التلقيمتين وحصراً: سقف 64 الداخلي حين يكون
  /// خيار الاتصالات مطفأً — فالمسلَّم ليس مصافحة جارية أبداً ولا يعدّه
  /// هذا السقف، وعدّه في مجموع الاتصالات حيث يحدّه خيار المضيف وحده
  int _inFlightHandshakesTotal() =>
      (_feed?.ongoingHandshakes ?? 0) + (_feedV6?.ongoingHandshakes ?? 0);

  /// تلقمة جديدة فوق مستمع خام: سقفا القبول — سقف الخيار فوق المجموع
  /// الكلي مسلَّفاً، والسقف الداخلي 64 فوق الجاري حصراً والخيار مطفأً
  /// (العالق بعد التسليح لا يقدر الخادم على تحريره أبداً فيستحق سقفاً
  /// أضيق من المقابس القابلة للكنس)
  TlsHandshakeFeed _newTlsFeed(ServerSocket raw) => TlsHandshakeFeed(
    raw: raw,
    context: config.securityContext!,
    firstRecordTimeout: config.tlsFirstRecordTimeout,
    openConnectionCap: config.maxOpenConnections,
    inFlightHandshakeCap: TlsHandshakeFeed.internalHandshakeCap,
    openConnectionTotal: _openConnectionTotal,
    inFlightHandshakesTotal: _inFlightHandshakesTotal,
    onCut: () => _tlsSocketsCut++,
    onDelivered: () => _tlsHandshakesDelivered++,
    onOverHandshakeCap: _noteHandshakeCapLine,
    onOverConnectionCap: _noteAcceptCapLine,
  );

  /// سطر كبح السقف الداخلي: بنمط بقية أسطر السعة — سطر واحد في الثانية
  /// على الأكثر بالساعة المحقونة، والسطر التالي يحمل عدد المكتوم،
  /// وموضع مستقل فلا يكتم فيض موضعٍ تحذيرَ موضعٍ آخر، والعدّ الذي
  /// يقوله عدّ المصافحات الجارية حصراً بما يسمّي حقيقته
  void _noteHandshakeCapLine(int inFlightNow, int cap) {
    final line = _handshakeCapWarnThrottle.admit(
      'intake TLS handshake limit: $inFlightNow handshakes in flight over '
      'the cap of $cap — cutting the new socket',
    );
    if (line != null) {
      telemetry.warn(line, category: BridgeCategory.network);
    }
  }

  /// سطر كبح سقف الخيار عند القبول: العدّ مجموع اتصالات مفتوحة (مسلَّمة
  /// وجارية معاً) بالتسمية نفسها التي يقولها باب الطلب — لا مصافحات
  /// جارية فالمسلَّم ليس جارياً
  void _noteAcceptCapLine(int openNow, int cap) {
    final line = _acceptCapWarnThrottle.admit(
      'intake TLS accept limit: $openNow open connections over the cap of '
      '$cap — cutting the new socket',
    );
    if (line != null) {
      telemetry.warn(line, category: BridgeCategory.network);
    }
  }

  /// The generation bind itself: waits out a draining stop, tries the
  /// candidate ports, arms the optional listeners, and wires every bound
  /// listener to the same handler. `resuming` only shapes the failure
  /// message - the remembered port is named as taken, so the host reads
  /// the exact fact and can decide to retry.
  Future<int> _bindGeneration({
    required int preferredPort,
    required List<int> fallbacks,
    required bool resuming,
  }) {
    return telemetry.measure<int>('intake.start', () async {
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
      // فحص مجلد مقبس اليونكس مرة واحدة قبل حلقة المرشحين: حكمه لا
      // يعتمد على المنفذ فيجيب البدء فوراً برسالة تسمي المجلد — لا
      // عائقُ منفذٍ يحرق المرشحين مرشحاً مرشحاً ولا خلاصة «فشل ربط كل
      // المنافذ» تخفي حقيقة المجلد
      final unixPath = config.unixSocketPath;
      if (unixPath != null) {
        _refusePermissiveUnixParent(unixPath);
      }
      final candidates = [preferredPort, ...fallbacks];
      Object? lastError;
      final tls = config.securityContext;
      for (final candidate in candidates) {
        try {
          // النقل يتبع الخيار: بلا سياق الربط HTTP العادي حرفاً كما كان،
          // ومع سياق جاهز من المضيف يُربط المستمع الخام على العنوان الحلقي
          // نفسه وتغذي التلقيمة HttpServer.listenOn بعد بوابة أول سجل —
          // TLS ينتهي تحت طبقة HTTP فلا عقد سلك يتغير، والصامت والمزيّف
          // يُقطعان قبل التسليح حيث يصل التدمير إلى السلك
          if (tls == null) {
            _server = await HttpServer.bind(
              InternetAddress.loopbackIPv4,
              candidate,
            );
          } else {
            final raw = await ServerSocket.bind(
              InternetAddress.loopbackIPv4,
              candidate,
            );
            final feed = _newTlsFeed(raw);
            _feed = feed;
            _server = HttpServer.listenOn(feed);
          }
          // المنفذ الفعلي المُسند (يُصحّح عيب إعادة 0 عند طلب منفذ عشوائي
          // — والطلب الصريح يساوي الفعلي فلا فرق سلكياً)
          _port = _server!.port;
          await _armListenersAtBind();
          // أي ربط ناجح ينسى المنفذ المعلق: البدء الجديد جيل يملك
          // عنوانه هو — والاستئناف الناجح يُنهي حالة الإيقاف بحسمها
          if (_pausedPort != null) {
            _pausedPort = null;
          }
          telemetry.info(
            'intake listening on 127.0.0.1:$_port'
            '${_serverV6 != null ? ' and [::1]:$_port' : ''}'
            '${_serverUnix != null ? ' and unix socket '
                      '$_unixSocketPath' : ''}'
            '${candidate != preferredPort ? ' (fallback)' : ''}',
            category: BridgeCategory.network,
          );
          return _port;
        } catch (e) {
          lastError = e;
          // المستمع اليتيم: الربط نجح ثم رمت خطوة إقلاع لاحقة (ربط
          // الـ::1 الاختياري الفاشل بعنف، أو مقبس يونكس فشل حارس
          // صلاحياته، أو تحذير الحماية أو listen أو سطر الإقلاع) —
          // المقبس يبقى يستمع بلا مرجع بعد إحلال المرشح التالي، وإن
          // فشل كل المرشحين بقي _server غير صفري فيصطدم الإقلاع
          // التالي بـStateError. أغلق كل المربوط وأصفّر الحالة قبل
          // المرشح التالي.
          final orphan = _server;
          if (orphan != null) {
            _server = null;
            final orphanFeed = _feed;
            // والتلقمة تتبع الخادم إلى الصفر معه: إغلاقها هو الذي يحصد
            // ما قبل التسليح (listenOn لا يغلق الممرَّر له) وترك مرجعها
            // يستدعي عدّاً على باب لم يعد موجوداً
            _feed = null;
            // والمنفذ يتبع الخادم إلى الصفر: رقم قديم فوق خادم لم
            // يعد موجوداً كذبة يستند إليها المستدعي (عقد port)
            _port = 0;
            await orphan.close(force: true);
            await orphanFeed?.close();
          }
          final orphanV6 = _serverV6;
          if (orphanV6 != null) {
            _serverV6 = null;
            final orphanFeedV6 = _feedV6;
            _feedV6 = null;
            await orphanV6.close(force: true);
            await orphanFeedV6?.close();
          }
          final orphanUnix = _serverUnix;
          if (orphanUnix != null) {
            _serverUnix = null;
            await _removeUnixSocketFile();
            await orphanUnix.close(force: true);
          }
          telemetry.warn(
            'port $candidate unavailable (${e.runtimeType}), '
            'trying fallback',
            category: BridgeCategory.network,
          );
        }
      }
      throw IntakeBindException(
        resuming
            ? 'failed to resume: the remembered port $preferredPort is '
                  'taken - another listener holds it, or the bind failed '
                  '($lastError)'
            : 'failed to bind any listen port: $lastError',
      );
    });
  }

  /// The post-bind arming shared by [start] and [resume] - the whole
  /// listener set derives from the port actually bound: the host
  /// authorities (widened with the `::1` spellings only when that optional
  /// listener actually bound), the armed local pages, and the listener
  /// wiring for every bound transport. The optional `::1` listener fails
  /// softly (a loud warning, the service stays on `127.0.0.1` alone -
  /// the primary listener's contract stands); the optional unix listener
  /// fails hard (no unguarded socket ever serves - a bind or
  /// permission-guard failure throws and the generation bind fails).
  Future<void> _armListenersAtBind() async {
    _authorities = computeAuthorities(_port, config.extraHosts);
    final tls = config.securityContext;
    if (config.listenIPv6Loopback) {
      try {
        // مستمع الـ::1 يرتدي نقل المستمع الأول نفسه: بلا سياق HTTP عادي،
        // ومع سياق جاهز التلقمة نفسها — بابٌ واحد لا ينشق نقله
        HttpServer v6;
        if (tls == null) {
          v6 = await HttpServer.bind(
            InternetAddress.loopbackIPv6,
            _port,
            v6Only: true,
          );
        } else {
          final rawV6 = await ServerSocket.bind(
            InternetAddress.loopbackIPv6,
            _port,
            v6Only: true,
          );
          final feedV6 = _newTlsFeed(rawV6);
          _feedV6 = feedV6;
          v6 = HttpServer.listenOn(feedV6);
        }
        _serverV6 = v6;
        // توسعة السلطات في الربط نفسه: صيغتا الـ::1 اسمتما عنواناً حياً
        // حصراً والمستمع مربوط فعلاً — ومطفأً تبقى المجموعة حرفاً كما هي
        _authorities = computeAuthorities(
          _port,
          config.extraHosts,
          ipv6Loopback: true,
        );
      } catch (e) {
        telemetry.warn(
          'the optional ::1 listener failed to bind ($_port): '
          '${e.runtimeType} — continuing on 127.0.0.1 alone',
          category: BridgeCategory.network,
        );
      }
    }
    final unixPath = config.unixSocketPath;
    if (unixPath != null) {
      final unix = await HttpServer.bind(
        InternetAddress(unixPath, type: InternetAddressType.unix),
        0,
      );
      final guarded = await _enforceUnixOwnerOnly(unixPath);
      if (!guarded) {
        await unix.close(force: true);
        // ملف المقبس الذي وُلد هنا يُرفع بالمسار الفعلي لا بحقل الحالة:
        // الحقل لا يُضبط إلا بعد نجاح الحارس فنداؤه بحقه كان سيترك
        // الملف يحتل المسار فيعجز كل بدء تالٍ عنه. والعقد الآمن نفسه:
        // لا يُمس إلا ما كان مقبس مجال يونكس — والرفع الصريح يجعل
        // نظافة المسار عقداً تملكه الحزمة لا سلوكاً يوفره غيرها صامتاً
        await _deleteUnixSocketFileAt(unixPath);
        // الفشل مغلقاً: مقبس بلا حاجز صلاحياته لا يخدم أبداً — البدء
        // كله يفشل صاخباً بدل نصف مستمع مكشوف، والرسالة تسمّي الأداة
        // بالمسار الذي يناديها الحارس كي يعرف المضيف أين الدواء
        throw IntakeBindException(
          'failed to guard the unix socket "$unixPath" with owner-only '
          'permissions - /bin/chmod is missing or refused, and the '
          'listener does not serve an unguarded socket',
        );
      }
      _serverUnix = unix;
      _unixSocketPath = unixPath;
    }
    _warnExtraHosts(config.extraHosts);
    // تسليح أصول الصفحة المحلية عند الربط حصراً: المجموعة من
    // المنفذ الفعلي المُسند (لا المطلوب)، وإحلالٌ عند كل ربط
    // فيقرأ البدءُ الجديد مجموعتَه لا أصل ربطٍ سابق — والمخطط يتبع
    // النقل: صفحة على باب TLS أصلها https وحصراً
    protection.armBridgeServedOrigins(
      config.localPages == null
          ? const <String>{}
          : bridgeServedOrigins(_port, secure: tls != null),
    );
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
    // جسم طلب نشط تحرسه [requestTimeout] أعلى — وعلى كل مستمع
    // مربوط: النقل الثلاثة كلها تخدم نفس المعالج ونفس الحواجز
    for (final listener in [_server!, ?_serverV6, ?_serverUnix]) {
      listener.idleTimeout = config.idleTimeout;
      listener.listen(
        _handle,
        onError: (Object error) => telemetry.error(
          'intake server error',
          error: error,
          category: BridgeCategory.network,
        ),
      );
    }
  }

  /// بوابة مجلد المقبس الأب: حكمٌ لا يعتمد على المنفذ يُصدر مرة واحدة
  /// قبل حلقة مرشحي المنافذ — المجلد المتساهل (للمجموعة أو الآخرين ركن
  /// فيه) يجيب البدء فوراً برسالة تسمي المجلد ومطلوب التضييق؛ والمقبس
  /// يولد بصلاحيات العملية ثم يضاق إلى المالك وحده في اللحظة التالية
  /// فالنافذة بين الولادة والتضييق تسدّ بأن يولد حصراً في مجلد لا
  /// يعبره سوى المالك. والمضبوط يمرّ بلا مسّ
  void _refusePermissiveUnixParent(String unixPath) {
    final parentDir = File(unixPath).parent.path;
    if (_unixDirOwnerOnly(parentDir)) {
      return;
    }
    throw IntakeBindException(
      'the unix socket parent directory "$parentDir" carries group or '
      'other permissions - tighten it to owner-only (mode 0700) so '
      'the socket is unreachable between its creation and its own '
      'restriction',
    );
  }

  /// قراءة صلاحيات المجلد الحامل للمقبس قبل الربط: المالك وحده يعبره —
  /// الرجوع false في كل عائق (المجلد غائب، أو ليس مجلداً، أو القراءة
  /// غير مقنعة) فيفشل الربط مغلقاً. نداء واحد قبل كل ربط.
  bool _unixDirOwnerOnly(String path) {
    try {
      final stat = Directory(path).statSync();
      if (stat.type != FileSystemEntityType.directory) {
        return false;
      }
      // ‏0x3F = بتات المجموعة والآخرين في صيغة posix الصلاحية
      return (stat.mode & 0x3F) == 0;
    } on Object {
      return false;
    }
  }

  /// حاجز المقبس اليونكس: chmod 0600 بمسار الأداة الكامل ثم التحقق
  /// بقراءة الصلاحيات الفعلية من الملف - الرجوع false في كل عائق (الأداة
  /// غائبة عن مسارها الثابت، أو رميت، أو القراءة غير مقنعة) فيفشل الربط
  /// مغلقاً ولا يخدم الجسر مقبساً مفتوحاً على غير المالك. نداء واحد عند
  /// كل ربط. والمسار الكامل مقصود: نداء اسم مجرد يمر عبر PATH فيورّث
  /// حارساً يمكن إزاحته بترتيب PATH الموروث — المسار الثابت يقطع ذلك
  Future<bool> _enforceUnixOwnerOnly(String path) async {
    try {
      final result = await Process.run('/bin/chmod', <String>['600', path]);
      if (result.exitCode != 0) {
        return false;
      }
      final stat = File(path).statSync();
      if (stat.type != FileSystemEntityType.unixDomainSock) {
        return false;
      }
      // ‏0x3F = بتات المجموعة والآخرون - المالك وحده يملك المقبس
      return (stat.mode & 0x3F) == 0;
    } on Object {
      return false;
    }
  }

  /// رفع ملف المقبس اليونكس الذي أنشأته هذه الحالة حصراً - المسار
  /// يُحذف فقط ما دام مقبس مجال يونكس؛ ملفاً استُبدل به (أي نوع آخر) لا
  /// تمسّه الحزمة أبداً (لا تحذف الحزمة ما لم تنشئه). الفشل محتوى: مسار
  /// غائب أو مرفوع سابقاً لا يكسر الإيقاف.
  Future<void> _removeUnixSocketFile() async {
    final path = _unixSocketPath;
    if (path == null) {
      return;
    }
    _unixSocketPath = null;
    await _deleteUnixSocketFileAt(path);
  }

  /// الرفع الآمن بمسار صريح — العقد نفسه: مقبس مجال يونكس وحده يُرفع،
  /// وغيره لا يُمس، والغائب أو المستبدل لا يكسر شيئاً. يُنادى بمسار
  /// الربط الفعلي في مسار فشل الحارس حيث حقل الحالة ما يزال فارغاً
  Future<void> _deleteUnixSocketFileAt(String path) async {
    try {
      final stat = File(path).statSync();
      if (stat.type == FileSystemEntityType.unixDomainSock) {
        await File(path).delete();
      }
    } on Object {
      // المسار غائب أو استُبدل: لا حذف ولا فشل إيقاف
    }
  }

  /// Pauses the listeners the way a mobile app backgrounds: the remembered
  /// port and the instance identity stay inside the server, every bound
  /// listener closes under the same graceful drain a [stop] runs (in-flight
  /// replies finish, seats are awaited, orphans get their budget), and
  /// [resume] reopens on the same port with the same instance id. The
  /// error contract mirrors [stop]'s siblings: [StateError] through the
  /// returned future when the server is already paused or nothing is
  /// bound (and a start still in flight is awaited first, exactly as
  /// [stop] awaits it).
  Future<void> pause() async {
    if (_pausedPort != null) {
      throw StateError('intake server is already paused - resume reopens it');
    }
    final pendingStart = _startingFuture;
    if (pendingStart != null) {
      try {
        await pendingStart;
      } catch (_) {
        // فشل البدء: لا مستمع لإيقافه — الحسم وحده مقصود
      }
    }
    if (_server == null && _serverV6 == null && _serverUnix == null) {
      throw StateError('intake server is not listening - nothing to pause');
    }
    final rememberedPort = _port;
    await stop();
    _pausedPort = rememberedPort;
  }

  /// Stops listening - a graceful close, not an amputation: listening stops
  /// at once, in-flight replies finish, the seats are awaited until
  /// drained, and orphaned handlers (timed out of their seat but still
  /// running) are awaited up to the handler budget - the remainder is
  /// announced in a warning and named in the returned [BridgeStopReport],
  /// never silently outliving the stop. At the return every still-working
  /// orphan is retired to the previous generation: it stops counting
  /// against the live-work budget and a following [start] serves the new
  /// generation from a clean budget, while the retired orphans stay
  /// visible in the public orphan counter until they settle.
  ///
  /// With [timeout] given, the whole drain - the graceful close, the seat
  /// wait, and the orphan grace - is bounded by it: stop returns inside
  /// the deadline (a listener that has not closed gracefully by then is
  /// force-closed so no socket is left behind), and the drain continues in
  /// the background with the report telling what still runs. With no
  /// timeout the drain is waited out fully, as before. A [start] issued
  /// while this drain is still inside its call waits for it, so the new
  /// generation binds only after the stop returned. A joining call that
  /// lands on a stop still in flight returns that stop's outcome; a call
  /// after it returned takes its own bounded pass.
  Future<BridgeStopReport> stop({Duration? timeout}) async {
    if (timeout != null && timeout.isNegative) {
      throw ArgumentError.value(
        timeout,
        'timeout',
        'must not be negative - omit it for the full drain',
      );
    }
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
      await inFlight;
      return _stopSnapshot();
    }
    // مستقبل الفراغ يُسلَّح قبل أول انتظار: بداية تستدعى في نافذة
    // الفراغ تنتظر عودة stop لا نضب اليتامى — والعودة داخل المهلة
    // تُحرر البوابة فلا يعلق جيل جديد على يتامى الجيل القديم
    final settled = Completer<void>();
    _stoppingFuture = settled.future;
    // الإلغاء التعاوني عند الإيقاف: كل معالج حي (مقعداً أو يتماً)
    // يقرأ الإشارة إن شاء فيغلف عمله فيفرغ داخل الفراغ بدل أن يكمل
    // في رد لن يقرأه أحد
    for (final signal in _liveSignals.toList()) {
      signal.cancel();
    }
    var timedOut = false;
    // الموعد الكلي للمهلة المطلوبة: يحكم الإغلاق الرشيق والمقاعد
    // واليتامى معا؛ وبلا مهلة يبقى الانتظار الكامل كما كان
    final deadlineMs = timeout == null ? null : _now + timeout.inMilliseconds;
    try {
      final server = _server;
      final serverV6 = _serverV6;
      final serverUnix = _serverUnix;
      final feed = _feed;
      final feedV6 = _feedV6;
      _server = null;
      _feed = null;
      _serverV6 = null;
      _feedV6 = null;
      _serverUnix = null;
      _port = 0;
      // الإيقاف الكامل ينسى المنفذ المعلق: بعده لا استئناف يملك عنواناً
      // — والبدء الجديد يربط جيلاً جديداً من الصفر
      _pausedPort = null;
      if (server != null && deadlineMs != null) {
        try {
          await server.close().timeout(_remaining(deadlineMs));
        } on TimeoutException {
          timedOut = true;
          // من لم يفض بclose الرشيق داخل المهلة يُقطع قسرا — لا مقبس
          // يستمع بعد عودة stop
          unawaited(
            server.close(force: true).catchError((Object _, StackTrace _) {}),
          );
        }
      } else {
        await server?.close();
      }
      // المستمعان الاختياريان بنمط الرشيق نفسه: إغلاق رشيق تحت المهلة
      // (أو كاملاً بلا مهلة) وقسوة قسرية عند التعليق — طلب حي على
      // الـ::1 أو مقبس يونكس يمسك مقعده فينتظره الفراغ كالـIPv4
      await _closeListener(serverV6, deadlineMs);
      await _closeListener(serverUnix, deadlineMs);
      // والمرجعان الخامان يُغلقان بيد الحزمة حصراً: listenOn لا يغلق
      // ServerSocket الممرَّر له (_closeServer=false في dart:io) — فإغلاق
      // التلقمة هو الذي يوقف القبول ويحصد ما قبل التسليح في كل مسار
      await feed?.close();
      await feedV6?.close();
      if (serverUnix != null) {
        // ملف المقبس الذي أنشأته الحالة هذه يُرفع بعد الإغلاق: بداية
        // تالية على المسار نفسه تعيد الربط نظيفة بلا ملف عالق
        await _removeUnixSocketFile();
      }
      // العالق بعد التسليح: الإعلان لا الصمت — dart:io لا وسيلة قتل
      // تصل السلك بعد تسليح المحرك فلا يحصده stop (وما قبل التسليح
      // حصدته التلقيمة عبر إغلاق المستمعين)، والعدّ الصاخب هو الحقيقة
      // الكاملة المتاحة، وسطر واحد يُكتب فقط حين العدد فوق الصفر
      final stuckHandshakes =
          (feed?.stuckArmingAtClose ?? 0) + (feedV6?.stuckArmingAtClose ?? 0);
      if (stuckHandshakes > 0) {
        telemetry.warn(
          'intake stopped with $stuckHandshakes TLS handshake(s) stuck '
          'past arming - the TLS engine holds their sockets and no cut '
          'reaches them',
          category: BridgeCategory.network,
        );
      }
      // قناة الويب سوكيت الحية: كل مقبس مفتوح يمسك مقعداً كطلب حي —
      // الإغلاق بالتوازي كله، وكل قناة تحت ما تبقى من الموعد الكلي:
      // قناة لا تحسم إغلاقها بانقضاء ما تبقى لا تمسك الإيقاف خارج
      // مهلته — تُرك إغلاقها في الخلفية وتُعلن عدّاً صاخباً بدل انتظار
      // بلا سقف أو صمت كاذب. وبلا مهلة يبقى الانتظار الكامل كله بالتوازي.
      // الفشل هنا محتوى: قناة ماتت قبل الإغلاق حسم مسارها نفسه وحده
      final sockets = _liveWsSockets.toList();
      if (sockets.isNotEmpty) {
        Future<bool> settle(WebSocket ws) {
          final closing = ws
              .close(WebSocketStatus.goingAway, 'server stopping')
              .then<bool>((_) => true, onError: (Object _) => true);
          if (deadlineMs == null) {
            return closing;
          }
          return closing.timeout(
            _remaining(deadlineMs),
            onTimeout: () => false,
          );
        }

        final settled = await Future.wait(<Future<bool>>[
          for (final ws in sockets) settle(ws),
        ]);
        final stragglers = settled.where((done) => !done).length;
        if (stragglers > 0) {
          // الإعلان لا الصمت: قنوات لم تحسم إغلاقها حتى عودة الإيقاف —
          // dart:io لا يكشف مقبس القناة المرفوع بلا واجهة قطع قسري،
          // فالعدّ الصاخب هو الحقيقة الكاملة المتاحة
          telemetry.warn(
            'intake stopped with $stragglers websocket channel(s) still '
            'closing past the deadline',
            category: BridgeCategory.network,
          );
        }
      }
      while (_activeRequests > 0) {
        // أعد استخدام المسلح: نداءان متداخلان لstop
        // يطحن الثاني _drain فيبقى الأول معلقا على مستقبل لا يكتمل
        final drained = _drain ??= Completer<void>();
        if (deadlineMs == null) {
          await drained.future;
          _drain = null;
          continue;
        }
        final remaining = deadlineMs - _now;
        if (remaining <= 0) {
          timedOut = true;
          break;
        }
        try {
          await drained.future.timeout(Duration(milliseconds: remaining));
        } on TimeoutException {
          timedOut = true;
          break;
        }
        _drain = null;
      }
      _drain = null;
      // اليتامى: مقاعدهم فرغت برد 504 لكن عملهم حي — stop ينتظرهم حتى
      // الميزانية الفعالة (الافتراضية من config أو الصريحة) وسقف المهلة
      // أيهما أقرب، والباقي فوقها يُعلن بعدّه ويظهر في التقرير لا يُترك
      // صامتا
      final grace = effectiveHandlerTimeout;
      if (_activeOrphans + _retiredOrphans > 0 && grace != null) {
        final orphaned = _orphanDrain ??= Completer<void>();
        var wait = grace;
        if (deadlineMs != null) {
          final remaining = deadlineMs - _now;
          if (remaining <= 0) {
            timedOut = true;
          } else if (remaining < grace.inMilliseconds) {
            wait = Duration(milliseconds: remaining);
          }
        }
        if (!timedOut) {
          try {
            await orphaned.future.timeout(wait);
          } on TimeoutException {
            timedOut = true;
          }
        }
      }
    } finally {
      // التقاعد عند العودة: يتامى هذا الجيل لا يحملهم جيل تالٍ في
      // ميزانية العمل الحي، ويبقون في عدّاد العرض حتى يسكنوا.
      // المتقاعد في stop سابقة (لا يزال يعمل فعلاً) يُتخطى — العلم
      // عليه حقيقاً فعدّه الثانية ازدواج يورث شبحاً لا يمحوه سوى
      // استقرار لا يُعدّ شيئاً
      for (final ticket in _pendingOrphans.toList()) {
        if (ticket.retired) continue;
        ticket.retired = true;
        _retiredOrphans++;
      }
      _activeOrphans = 0;
      final stillWorking = _activeOrphans + _retiredOrphans;
      if (timedOut || stillWorking > 0) {
        telemetry.warn(
          'intake stopped with $stillWorking orphan handler(s) still '
          'running',
          category: BridgeCategory.network,
        );
      }
      _stoppingFuture = null;
      settled.complete();
    }
    return _stopSnapshot();
  }

  /// The snapshot a stop returns: what was still working at the return
  /// moment, read from the live counters.
  BridgeStopReport _stopSnapshot() => BridgeStopReport._(
    seatsStillActive: _activeRequests,
    orphanHandlersStillRunning: _activeOrphans + _retiredOrphans,
  );

  /// إغلاق مستمع اختياري بنمط الرشيق نفسه الذي يسلكه المستمع الأساسي:
  /// إغلاق رشيق تحت المهلة الكلية إن وُجدت (وقسوة قسرية عند تعليقه)،
  /// وكامل بلا مهلة في غير ذلك. null يعني غير مربوط فلا شيء.
  Future<void> _closeListener(HttpServer? listener, int? deadlineMs) async {
    if (listener == null) {
      return;
    }
    if (deadlineMs != null) {
      try {
        await listener.close().timeout(_remaining(deadlineMs));
      } on TimeoutException {
        unawaited(
          listener.close(force: true).catchError((Object _, StackTrace _) {}),
        );
      }
      return;
    }
    await listener.close();
  }

  /// Milliseconds left before [deadlineMs], floored at zero -
  /// `Future.timeout(Duration.zero)` fires at once, which is exactly the
  /// expired-deadline reading.
  Duration _remaining(int deadlineMs) {
    final rest = deadlineMs - _now;
    return rest <= 0 ? Duration.zero : Duration(milliseconds: rest);
  }

  /// One orphaned handler settled - leaves its pool, rings the drain bell
  /// when the last one settled, and tells the host's callback (contained:
  /// a throwing callback is said once in the telemetry, never breaks the
  /// wire or the drain).
  void _settleOrphan(_OrphanTicket ticket) {
    _pendingOrphans.remove(ticket);
    if (ticket.retired) {
      _retiredOrphans--;
      if (_retiredOrphans < 0) _retiredOrphans = 0;
    } else {
      _activeOrphans--;
      if (_activeOrphans < 0) _activeOrphans = 0;
    }
    if (_activeOrphans + _retiredOrphans == 0) {
      final bell = _orphanDrain;
      _orphanDrain = null;
      bell?.complete();
    }
    final callback = onOrphanSettled;
    if (callback != null) {
      try {
        callback();
      } catch (e, s) {
        telemetry.error(
          'onOrphanSettled callback threw - contained, the drain keeps '
          'its course',
          error: e,
          stackTrace: s,
          category: BridgeCategory.network,
        );
      }
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

  /// سقف بيانات الرد المرتجعة للصفحة، بالبايتات الفعلية بعد ترميز JSON -
  /// ثابت داخلي غير قابل للضبط بنمط سقفي الترويسات أعلاه، لا خيار جديد.
  /// فوقه تُرد النتيجة كلها برمزها المسجل ولا قصّ صامت: القص يكذب على
  /// الصفحة (إيصال مقطوع أسوأ من غيابه)، والرفض الصريح يُخبرها بالسبب.
  /// 64KiB أوسع من أي إيصال أمر حقيقي (نصه ورقمه وحالته) وأضيق من أن
  /// يهدم ردٌّ واحد صفحةَ المرسل أو ينفخ سطر الرد وحده.
  static const int _maxReplyDataBytes = 64 * 1024;

  /// السقف الداخلي للجسم الثنائي بالبايتات - ثابت مسمّى عمداً لا خيار:
  /// ملف صورة أو PDF مع أمر يقع تحتّه بامتياز، وما فوقه شكل هجومي لا
  /// استعمال معروف له. فَوْقه يُرد `413 payload_too_large` باسم السقف
  /// الثنائي حصراً، والقيمة أضيق من سقف الجسم العام (maxBodyBytes) لأن
  /// تسليم البايتات الخام للمعالج حمولة أكبر من نص يعالَج بالفك نفسه.
  static const int _maxBinaryBodyBytes = 256 * 1024;

  /// اسم السقف الثنائي كما يظهر على السلك في رد 413 - مشتق من الثابت
  /// لا مكتوب بيده، فلا يكذب الرد لو تغيّر الثابت يوماً.
  static final String _binaryCapLabel = '${_maxBinaryBodyBytes ~/ 1024} KiB';

  /// السقف الداخلي لرسالة قناة الويب سوكيت بالبايتات - ثابت مسمّى عمداً
  /// لا خيار، بنمط سقف الجسم الثنائي: رسالة القناة أمرٌ وحمولتها
  /// النصية عادة، وما فوقه شكل هجومي لا استعمال معروف له. السقف يفحص
  /// عند التسليم فيحمل ردُّ الإغلاق إطاره الإفصاحي برمز القناة المسجل
  /// (المحول نفسه أعمى الإفصاح: إطار فوق سقفه يغلق بالنقل الميت 1002
  /// بلا إطار يُقرأ).
  static const int _maxWsMessageBytes = 256 * 1024;

  /// اسم سقف رسالة القناة كما يظهر في رد الإغلاق — مشتق من الثابت.
  static final String _wsMessageCapLabel = '${_maxWsMessageBytes ~/ 1024} KiB';

  /// سقف إطارات النقل عند المحول — ثابت داخلي أوسع من سقف الرسالة:
  /// ذاكرته هي حاجز الضخم الوحيد قبل التسليم (dart:io يخزن الإطار
  /// كاملاً قبل تسليمه) فيحتصر التخزين الأعظمي على هذا الرقم، وما
  /// فوقه يرميه المحول عند الطول المعلن قبل بايتات الحمولة فلا
  /// تخزين إطلاقاً. السقفان معاً: السقف الواسع يحمي الذاكرة، والسقف
  /// الضيق هو العقد الذي يحمل إطاره الإفصاحي على السلك.
  static const int _wsTransportFrameCeiling = 2 * 1024 * 1024;

  /// هل يعرف dart:io الجاري معلمة سقف النقل للترقية؟ المعلمة
  /// (`maxPayloadLength`) على `WebSocketTransformer.upgrade` دخلت
  /// dart:io في 3.13 حصراً — والإصدار يُقرأ من `Platform.version` ويُقارن
  /// بالحد، ونسخة غير مقروءة تعني عدم الدعم (فشل مغلقاً). حارس البناء
  /// يقرأ هذا العلم: قناة بلا سقف نقل لا تُسلَّح أصلاً، فلا يعمل الجسر
  /// قناةً بلا حد للذاكرة ولا مسارَ رجوع لها.
  static bool get wsTransportCeilingSupported => _wsCeilingSupported;

  static final bool _wsCeilingSupported = _detectWsTransportCeiling();

  static bool _detectWsTransportCeiling() {
    final match = RegExp(r'^(\d+)\.(\d+)').firstMatch(Platform.version);
    if (match == null) {
      return false;
    }
    final major = int.parse(match.group(1)!);
    final minor = int.parse(match.group(2)!);
    return major > 3 || (major == 3 && minor >= 13);
  }

  /// ترقية القناة بالسقف المعلن: `Function.apply` لا معلمة مسماة ثابتة
  /// في النص كي تترجم الحزمة على أرضية 3.8 المعلنة — وحارس البناء يضمن
  /// أن القناة لا تُسلَّح إلا حيث تعرف dart:io المعلمة، فلا مسار رجوع
  /// هنا إطلاقاً: كل فشل ترقية يمر للموضع المنادي كرفض سلكي حرفي.
  static Future<WebSocket> _upgradeChannel(HttpRequest request) {
    return Function.apply(
          WebSocketTransformer.upgrade,
          [request],
          const <Symbol, Object>{
            #compression: CompressionOptions.compressionOff,
            #maxPayloadLength: _wsTransportFrameCeiling,
          },
        )
        as Future<WebSocket>;
  }

  /// مهلة انتظار أول رسالة اعتماد على القناة — ثابت داخلي لا خيار:
  /// اتصال بلا اعتماد يمسك مقعده كي لا يجوع غيره، والمهلة القصيرة
  /// تحصّر نافذة ذلك المسك. فوقها يُغلق الاتصال برمز القناة المسجل.
  /// الاختبارات تحقن قيمة أقصر عبر [wsAuthTimeout].
  static const Duration _wsAuthDeadlineDefault = Duration(seconds: 10);

  /// النبض الداخلي للقناة: dart:io يرسل pings على هذه الوترة ويقطع
  /// النظير الميت الذي لا يجيب — يبقي مقابس الـNAT والمسارات الخاملة
  /// حية ويميت المقبض الميت قبل أن يمسك مقعده طويلاً. ثابت داخلي لا
  /// خيار، ومهلة الخمول القابلة للضبط (config.idleTimeout) هي التي
  /// تحسم رسالةً صامتة فوق اتصال حي.
  static const Duration _wsHeartbeat = Duration(seconds: 30);

  /// مقابس القناة الحية: كل واحد يمسك مقعداً (السقوف قائمة فوقها —
  /// لا سقف قناة ثانٍ بجوارها)، وstop يغلقها رشيقياً كي يحسم مستقبل
  /// مساراتها داخل نافذة الفراغ ولا يبقى مقعد ولا مقبس بعد العودة.
  final Set<WebSocket> _liveWsSockets = <WebSocket>{};

  /// The pairing route - the one path the intake answers specially while
  /// the pairing layer is armed. Disarmed, it is no path at all: it rides
  /// the ordinary non-root behavior (a warning and the handler), wire
  /// letter identical to previous releases.
  static const _pairingPath = '/pair';

  /// The armed local pages by exact path - empty while the option is
  /// off, so the page lookup below never fires and every GET keeps its
  /// standing 405. The lookup is a whole-string match against
  /// `request.uri.path`: there is no prefix walk and no filesystem
  /// anywhere behind it - the pages live in the host's memory.
  late final Map<String, BridgeLocalPage> _localPages =
      config.localPages == null
      ? const <String, BridgeLocalPage>{}
      : <String, BridgeLocalPage>{
          for (final page in config.localPages!) page.path: page,
        };

  /// The page's strict CSP: nothing loads from anywhere except the
  /// page's own inline script and style (a single in-memory page has no
  /// other files to load), and connections go to the bridge's own origin
  /// only (`connect-src 'self'` - the page's door to its server).
  /// Framing, form action, and base-uri injection are dead: the page is
  /// a display surface the host authored, not a loader.
  static const String _pageSecurityCsp =
      "default-src 'none'; script-src 'unsafe-inline'; "
      "style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; "
      "form-action 'none'; frame-ancestors 'none'";

  /// The loopback origins the bridge itself serves pages from - both
  /// spellings the browser may show in the address bar of the page URL,
  /// in the scheme the bound transport actually speaks: `https://` when a
  /// [BridgeConfig.securityContext] is armed, `http://` otherwise (the
  /// default, letter identical to previous releases). The admission reads
  /// them through the protection's armed set (an exact, port-bound
  /// normalized match), so the page's own origin crosses on its explicit
  /// path while any other loopback origin stays exactly where the policy
  /// keeps it.
  static Set<String> bridgeServedOrigins(
    int boundPort, {
    bool secure = false,
  }) => <String>{
    if (secure) ...<String>[
      'https://127.0.0.1:$boundPort',
      'https://localhost:$boundPort',
    ] else ...<String>[
      'http://127.0.0.1:$boundPort',
      'http://localhost:$boundPort',
    ],
  };

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
  late final _WarnThrottle _connCapWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );
  late final _WarnThrottle _handshakeCapWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );
  late final _WarnThrottle _acceptCapWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );
  late final _WarnThrottle _originBusyWarnThrottle = _WarnThrottle(
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

  /// كبح تحذير حالة الرفض غير الصالحة من المعالج: قيمة خارج 400..499
  /// تُتجاهل والسلوك الافتراضي يبقى، والسطر يُقال مرة في الثانية على
  /// الأكثر كي لا يغرق سجل المضيف معالجٌ معطوب.
  late final _WarnThrottle _refusalStatusWarnThrottle = _WarnThrottle(
    nowMs: () => _now,
    windowMs: _warnThrottleWindowMs,
  );

  /// كبح أسطر إغلاق القناة: فيض إغلاقات الاعتماد والسقوف سطر واحد في
  /// الثانية على الأكثر بالساعة المحقونة، والسطر التالي بعد النافذة
  /// يحمل عدد المكتوم كي يبقى حجم المحاولة مرئياً.
  late final _WarnThrottle _wsCloseWarnThrottle = _WarnThrottle(
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

  Future<void> _handle(
    HttpRequest request, {
    Set<String>? authorities,
    bool mounted = false,
  }) async {
    final response = request.response;
    _corsHeaders(response);
    // رد HEAD بلا جسم: الطلب الوحيد الذي يُحظر فيه المحتوى على السلك —
    // كل ردود المقبس الخام له تحمل الرأس وحده (التأطيرية تبقى للعلم)
    final headOnly = request.method == 'HEAD';
    try {
      // حارس الطرف البعيد أول بوابة على التركيب حصرا: خادم المضيف قد
      // يكون مربوطاً على 0.0.0.0 والجسر ضامنُ loopback على نفسه — حكم
      // الطرف يسبق كل فحص ترويسة وكل سطر قياس: لا قراءة ترويسة ولا سطر
      // سجل ولا صرف من ميزانية التحذير، والرفض يُعدّ في عدّاد رموز
      // الرفض فقط (رقم ذاكرة يعين المضيف على رؤية المحاولات) ومعرفُه
      // مولَّد حصرا (قراءة ترويسة الطرف نفسها فحص لا يسبقه
      // الحكم). الطرف غير المقروء قرارُ رفض: الحارس يفشل مغلقاً، والرمز
      // القائم يحمل الرفض (لا رمز جديد)، والقطع الفوري الموثق يقرأه من
      // السجل لا من هذا الموضع
      if (mounted) {
        final remote = request.connectionInfo?.remoteAddress;
        if (!_isLoopbackPeer(remote)) {
          response.headers.set('X-Correlation-Id', correlationIdGenerator());
          await _replyRejection(
            response,
            code: 'blocked_by_protection',
            message:
                'Request peer is not loopback — this mounted bridge accepts '
                'local callers only',
            bodyFullyRead: false,
            headOnly: headOnly,
          );
          return;
        }
      }
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
      // ومسار القبول والرفض) ولا يلمس كائن الحماية ثانية. ومصافحة
      // القناة وحدها تؤجل اعتمادها (لا ترويسة توكن في مصافحة متصفح —
      // لهذا وُلدت القناة) فالأصل المؤهل يعبر الترقية والاعتماد باب
      // أول رسالتها
      final wsHandshake = _isWsHandshake(request);
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
        deferCredential: wsHandshake,
        // على هذا السلك الترويسة هي المنصة الموثقة: الأصل هنا من
        // ترويسة متصفح أو غائب كليا — الدرجة تُدوَّن في سجل القبول
        // ولا تظهر على أي رد
        originTrust: earlyOrigin == null
            ? OriginTrustLevel.none
            : OriginTrustLevel.browserHeader,
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
      // صريح): يمر بمسار العدّاد والسجل الأمني نفسه. التركيب يحمل
      // سلطات منفصلة مبنية من منفذ خادم المضيف.
      final verdict = checkAuthority(
        hostHeader: _firstHeader(request, HttpHeaders.hostHeader),
        requestUriIsAbsolute: request.uri.isAbsolute,
        authorities: authorities ?? _authorities,
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

      // (سقف الاتصالات المفتوحة — خياري) dart:io لا يحدّ المقابس
      // المقبولة (الخاملة منها أيضا)، وفوق الخيار يُرد الفائض فورا
      // ويُخدم الطلب بعد هبوط العدد. الصفر مطفأ فالسلك بلا الخيار
      // حرفاً كما هو، والعد يشمل الاتصال الحامل للطلب نفسه — وعلى
      // كل المستمعين المربوطين (الـ::1 ومقبس يونكس الاختياريان
      // يحسبان في السقف ذاته) ومعهم المصافحات الجارية في التلقيمة
      // فلا باب جانبي يحصّنه فوق الباب الآمن
      final openConnectionCap = config.maxOpenConnections;
      if (openConnectionCap > 0) {
        final openNow = _openConnectionTotal();
        if (openNow > openConnectionCap) {
          // كبح السطر بنمط بقية أسطر السعة: سطر واحد في الثانية على
          // الأكثر بالساعة المحقونة، والسطر التالي يحمل عدد المكتوم
          final line = _connCapWarnThrottle.admit(
            'intake connection limit: $openNow open connections over the '
            'cap of $openConnectionCap — rejecting',
          );
          if (line != null) {
            telemetry.warn(line, category: BridgeCategory.network);
          }
          response.headers.set(
            'X-Correlation-Id',
            _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
          );
          _echoCors(
            response,
            _firstHeader(request, 'Origin'),
            admitted: admission.echoesCors,
          );
          // القطع الفوري الموثق يقرأه من السجل لا من هذا الموضع
          await _replyRejection(
            response,
            code: 'server_busy',
            message: 'The server is busy right now — please retry shortly',
            bodyFullyRead: false,
            headOnly: headOnly,
          );
          return;
        }
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
      // (سقف المقاعد لكل أصل) الأصل المطبَّع يأتي من سجل القبول، ومن
      // لا يرسل أصلاً دلو واحد مشترك بسقف مثله. البوابة داخل
      // المقاعد العامة: الخادم الممتلئ يرد server_busy أولا، وسقف
      // الأصل لا يخصم من مقاعد أصل آخر — كل مرسل محدود بدلو هو
      final seatOriginKey = admission.normalizedOrigin ?? '';
      if ((_seatsByOrigin[seatOriginKey] ?? 0) >= config.maxSeatsPerOrigin) {
        // كبح السطر نفسه: فيض رفض حصص الأصول سطر واحد في الثانية
        // على الأكثر، والسطر التالي بعد النافذة يحمل عدد المكتوم،
        // والرفض نفسه على السلك لكل طلب
        final line = _originBusyWarnThrottle.admit(
          'intake origin seat limit: '
          '${_seatsByOrigin[seatOriginKey] ?? 0} held seats for one sender '
          '(cap ${config.maxSeatsPerOrigin}) — rejecting',
        );
        if (line != null) {
          telemetry.warn(line, category: BridgeCategory.network);
        }
        response.headers.set(
          'X-Correlation-Id',
          _sanitizeCorrelationId(_firstHeader(request, 'X-Correlation-Id')),
        );
        // الصفحة تقرأ رمزها وتحاول لاحقا: صدى الرفض للمؤهل كالانشغال
        _echoCors(
          response,
          _firstHeader(request, 'Origin'),
          admitted: admission.echoesCors,
        );
        await _replyRejection(
          response,
          // القطع الفوري الموثق يقرأه من السجل لا من هذا الموضع
          code: 'origin_seat_limit',
          message: 'This origin holds its full seat share — retry shortly',
          bodyFullyRead: false,
          headOnly: headOnly,
        );
        return;
      }
      _activeRequests++;
      _seatsByOrigin[seatOriginKey] = (_seatsByOrigin[seatOriginKey] ?? 0) + 1;
      try {
        await _handleRequest(
          request,
          response,
          admission,
          wsHandshake,
          mounted,
        );
      } finally {
        _activeRequests--;
        final originLeft = (_seatsByOrigin[seatOriginKey] ?? 1) - 1;
        if (originLeft <= 0) {
          _seatsByOrigin.remove(seatOriginKey);
        } else {
          _seatsByOrigin[seatOriginKey] = originLeft;
        }
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
    bool wsHandshake,
    bool mounted,
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
          // قناة الويب سوكيت: مسار المضيف وترقية مصافحة حاضرتان والخيار
          // مسلّح حصرا — غير ذلك يمر من تحت الفرع لسلوك اليوم حرفاً
          // (405 كأي طلب غير POST). والمهلة الكلية تُلغى هنا: عمر
          // الاتصال عقد مهلته الخاصة (الاعتماد والخمول) لا مهلة الطلب
          if (wsHandshake) {
            totalDeadlineLive = false;
            await _handleWebSocket(request, response, admission, origin);
            return;
          }
          // الصفحة المحلية: GET على مسار مسجل حصراً وعلى مستمع الجسر
          // نفسه - التركيب يجيبه المضيف لمساراته هو فالصفحة لا تجيب
          // هناك (405 كأي غير POST). المشاهدة قراءة حرة لا تسوّي سجل
          // قبول ولا تقرأ قراره كالـ204 والـ405، والرد على المقبس
          // المنتزع بنمط بقية الردود المبكرة لأن جسم GET لا يُقرأ
          if (!mounted && request.method == 'GET') {
            final page = _localPages[request.uri.path];
            if (page != null) {
              await _replyPage(response, page);
              return;
            }
            // صفحة الصحة: GET على المسار المسلح حصراً وعلى مستمع الجسر
            // نفسه (405 على التركيب كأي GET) - تمر بالبوابة نفسها
            // بتسويتها كاملة فتقرأ القرار لا الصمت، وتجيب الأصل المقبول
            // وحده: بلا رقم إصدار ولا تفاصيل كي لا تصير قناة بصمات
            final healthPath = config.healthPath;
            if (healthPath != null && request.uri.path == healthPath) {
              await _handleHealthPage(request, response, admission);
              return;
            }
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
          // يُسوِّ فلم يخلف شيئاً. وفرع الرفض نفسه مشترك مع صفحة
          // الصحة (مساعد واحد لا نسخة ثانية)
          admission.settle();
          if (await _answerGateRejection(response, admission, origin)) {
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
          // في الصفحات يرسل أنواع النماذج فيُرد قبل قراءة أي بايت.
          // نوع الجسم الثنائي يدخل المسموحات بذات البوابة والخيار مسلّح
          // حصرا: مطفأً يبقى 415 كما كان حرفاً.
          final rawContentType = _firstHeader(
            request,
            HttpHeaders.contentTypeHeader,
          );
          String? mediaType;
          if (rawContentType != null && rawContentType.trim().isNotEmpty) {
            mediaType = rawContentType.split(';').first.trim().toLowerCase();
            final typeAdmitted =
                config.allowedContentTypes.contains(mediaType) ||
                (config.acceptBinaryBodies &&
                    mediaType == 'application/octet-stream');
            if (!typeAdmitted) {
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
          // مسار الجسم الثنائي: الخيار مسلّح والنوع المعلن ثنائي حصرا
          final isBinaryBody =
              config.acceptBinaryBodies &&
              mediaType == 'application/octet-stream';

          // رفض مبكر من Content-Length: `>` حصراً وبشرط غياب
          // الترميز المقطوع — الجسم الكاذب الواعد يظل محروساً بالعدّاد أدناه.
          // السقف الثنائي الأضيق يفحص أولا للطلب الثنائي: الرد باسم سقفه
          // هو الحكم الأول فوقه
          final te = _firstHeader(request, HttpHeaders.transferEncodingHeader);
          final cl = request.contentLength;
          final declaredLength = (te == null || te.isEmpty);
          if (declaredLength && cl > config.maxBodyBytes) {
            await _replyRejection(
              response,
              code: 'payload_too_large',
              message: 'Request body exceeds the allowed limit ($_mbLabel)',
              bodyFullyRead: false,
            );
            return;
          }
          if (isBinaryBody && declaredLength && cl > _maxBinaryBodyBytes) {
            await _replyRejection(
              response,
              code: 'payload_too_large',
              message:
                  'Binary request body exceeds the internal binary cap '
                  '($_binaryCapLabel)',
              bodyFullyRead: false,
            );
            return;
          }
          // قراءة الجسم بحدوده: عدّاد بايتات تراكمي يقطع بـ413 عند
          // التجاوز (لا اقتطاع صامت يفك UTF-8 ناقصا) ومهلة تحرس الطلب
          // المعلق، ثم فك UTF-8 واحد بعد حسم الحجم — بناء سلسلة الجسم
          // كاملة قبل الحسم يفتح باب الضخّم بعدها (trim + jsonDecode +
          // toString) فيتضاعف استهلاك الذاكرة بلا حارس تطبيقي. المسار
          // الثنائي يقرأ بايتات خاما بلا أي فك نص
          final outcome = await _readBody(request, binary: isBinaryBody);
          if (outcome.error != null) {
            await _replyBodyError(response, outcome.error!);
            return;
          }
          final List<String> payloads;
          final Uint8List? binaryBytes;
          if (isBinaryBody) {
            // الجسم الثنائي: البايتات تسلَّم كما وصلت — لا فك JSON ولا
            // فك UTF-8 ولا بوابات الحمولة النصية، وسقفه الداخلي حسمه
            // هنا (عداد القراءة يقطع أولا عند التجاوز أثناء الوصول)
            binaryBytes = outcome.binary!;
            payloads = const [];
            if (binaryBytes.length > _maxBinaryBodyBytes) {
              await _replyRejection(
                response,
                code: 'payload_too_large',
                message:
                    'Binary request body exceeds the internal binary cap '
                    '($_binaryCapLabel)',
                bodyFullyRead: true,
              );
              return;
            }
            // بوابة اسم الأمر: التسليم الثنائي اسمه في X-Command حصراً —
            // بلا اسمٍ (أو باسمٍ أعمى من فراغات) لا يوجد أمر يُسلَّم فالجسم
            // يُرد كيفما كان حجمه، والفارغ بلا اسمٍ على القرار ذاته: قاعدة
            // واحدة بلا استثناء حجم كما يرد النصُّ الخام الفارغ بـ
            // empty_payload. الحكم بعد سقف الجسم: سقف الحجم يبقى الحكم
            // الأول فوق الطلب الثنائي
            if ((_firstHeader(request, 'X-Command') ?? '').trim().isEmpty) {
              await _replyRejection(
                response,
                code: 'command_required',
                message:
                    'A binary body must name its command in the '
                    'X-Command header',
                bodyFullyRead: true,
              );
              return;
            }
          } else {
            binaryBytes = null;
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
            // فحص الشكل (خيار): جسم يعاهده شكل حاوية ولا يكتمل بنيا —
            // فتحة بلا غالق أو سلسلة بلا نهاية — يُرد قبل الفك لا يسقط
            // خاماً. المطفأ يمر للسلوك القائم حرفاً
            if (config.requireValidJsonShape && !_jsonShapeComplete(body)) {
              await _replyRejection(
                response,
                code: 'malformed_json_shape',
                message:
                    'Request body claims a JSON container shape but is not '
                    'structurally complete (an unclosed bracket or string) '
                    '— send the whole JSON document',
                bodyFullyRead: true,
              );
              return;
            }
            try {
              payloads = _extractPayloads(
                body,
                declaredJson: mediaType == 'application/json',
              );
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
            } on _StrictPayloadItemException {
              // العناصر الصارمة: عنصر غير نصي أو فارغ في قائمة الأوامر
              // يرفض الطلب كله بدل السقوط الصامت — الجسم مقروء فالإغلاق
              // المُدار نظيف
              await _replyRejection(
                response,
                code: 'invalid_payload_item',
                message:
                    'Command list carries a non-string or empty element '
                    '(strict item checking is on)',
                bodyFullyRead: true,
              );
              return;
            } on _InvalidJsonException {
              // النوع المعلن application/json والجسم مكسور: عقد النوع
              // المصرَّح يُحمَل على مرسله بدل مساره الخام
              await _replyRejection(
                response,
                code: 'invalid_json',
                message:
                    'Request body was sent as application/json but is not '
                    'valid JSON',
                bodyFullyRead: true,
              );
              return;
            } on _NonJsonBodyException {
              // وضع JSON فقط: كل مسار النص الخام مرفوض — فك مكسور بنوع
              // آخر، أو رقم/منطقي/null، أو نص خام مجرد
              await _replyRejection(
                response,
                code: 'non_json_body',
                message:
                    'This server accepts JSON bodies only — send the '
                    'command as JSON',
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
          }

          final source = _firstHeader(request, 'Origin') ?? 'unknown-origin';
          // سقف العمل الحي عند المعالج: المقاعد وحدها لا تحرس شيئا بعد
          // مهلة المعالج — اليتامى ما زالوا يعملون فعلا، فالميزانية
          // المقاعد+يتامى الجيل الحي معا (يتامى الأجيال المتقاعدة لا
          // يدخلون هذا العدّ)، وفوقها يُرد 503 قبل استدعاء معالج جديد
          if (_activeRequests + _activeOrphans > config.maxConcurrentRequests) {
            // كبح السطر نفسه: فيض رفض اليتامى يكتب سطرا واحدا في
            // الثانية على الأكثر، والسطر التالي بعد النافذة يحمل
            // عدد المكتوم، والرفض نفسه لكل طلب.
            final line = _orphanBusyWarnThrottle.admit(
              'intake busy: $_activeOrphans orphan handler(s) still '
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
          // قبل تنفيذ المعالج — وقت المعالج عقد الميزانية وحدها:
          // null يطلب الافتراضية من config، والثابت المسماة بلا مهلة
          // إطلاقاً (المعالج يمسك مقعده إلى أن يكمل)، والقيمة الصريحة
          // تحرر المقعد برد 504 ويُعدّ المعالج يتيماً — والنتيجة
          // المتأخرة تُهمل.
          totalDeadlineLive = false;
          // إشارة الإلغاء التعاوني لهذا الأمر: حية لكل أمر، وتخرج من
          // الأحياء عند حسم المستقبل أيّاً كان حسمه (نتيجة أو رمي) —
          // فلا تسرب ولا إشعال لميت
          final cancelSignal = CommandCancelSignal();
          _liveSignals.add(cancelSignal);
          // الرد المتدفق: خيار للأمر يطلبه مرسل الطلب بترويسته، والمطفأ
          // يترك السلك حرفاً كما هو (الترويسة مجهولة لا تقرأ). المطلوب
          // يفصل المقبس للإطارات قبل استدعاء المعالج كي يجد sinksه
          // جاهزاً من أول نداء
          final streamRequested =
              config.allowStreamingReplies &&
              (_firstHeader(request, 'X-Bridge-Stream') ?? '')
                      .trim()
                      .toLowerCase() ==
                  'events';
          if (streamRequested) {
            await _runStreamingReply(
              request: request,
              response: response,
              cancelSignal: cancelSignal,
              // سجل القبول نفسه يخيط الأمر كما في الرد الواحد — مسار
              // التسليم لا يغيّر حقيقة الطلب المسجلة
              admission: admission,
              payloads: payloads,
              binaryBytes: binaryBytes,
              source: source,
              verboseErrors: verboseErrors,
              correlationId: correlationId,
            );
            return;
          }
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
              cancellation: cancelSignal,
              binaryPayload: binaryBytes,
            ),
          );
          unawaited(
            // سلسلة تمتص خطأ المستقبل: whenComplete المجرد يعيد خطأ
            // المعالج المرمي كخطأ غير معالَج يهرب إلى الـzone — وthen
            // بمعالجي القيمة والخطأ يبتلعه هنا حصراً (الخطأ نفسه ما
            // زال يصل مسار الـ500 من await الأصلي عادة)
            commandFuture.then<void>(
              (_) => _liveSignals.remove(cancelSignal),
              onError: (Object _, StackTrace _) =>
                  _liveSignals.remove(cancelSignal),
            ),
          );
          final (awaited, budgetExpired) = await _awaitCommandFuture(
            commandFuture,
            cancelSignal,
          );
          if (budgetExpired || awaited == null) {
            await _replyRejection(
              response,
              code: 'handler_timeout',
              message: 'The command handler exceeded its time budget',
              bodyFullyRead: true,
            );
            return;
          }
          final result = awaited;

          // بيانات الرد المرتجعة: النجاح حصرا (فشل الأمر عقد الخطأ لا
          // بيانات)، والقياس بالترميز الفعلي UTF-8 بعد jsonEncode، وفوق
          // السقف الداخلي تُرد النتيجة كلها بالرمز المسجل من مخرج الرفض
          // الواحد — عدّها في العدادات تلقائي، ولا قصّ صامت ولا بيانات
          // مقطوعة تصل الصفحة. أي قيمة لا يرميها jsonEncode تهبط مسار
          // internal العام (الcatch المرحلي نفسه) وسببها الحقيقي على
          // telemetry المضيف.
          final Object? pageData = result.ok ? result.data : null;
          if (pageData != null &&
              utf8.encode(jsonEncode(pageData)).length > _maxReplyDataBytes) {
            await _replyRejection(
              response,
              code: 'reply_data_too_large',
              message:
                  'The command succeeded, but its reply data is over the '
                  '$_maxReplyDataBytes-byte page cap - the result is '
                  'refused whole, never truncated',
              bodyFullyRead: true,
            );
            return;
          }
          // نص المضيف تحت سقفه (خيار): السقف بالبايتات على السلك (UTF-8)
          // لا بالمحارف — النص متعدد البايتات كان يعبر السقف البايتي
          // المتوهم بعدد محارفه، والقص الآن عند حدّ محرفٍ كامل حصراً فلا
          // يسافر نصفُ محرفٍ قط (المحرف متعدد البايتات لا يُجزأ: إما
          // كله أو يسقط كله)، والرمز وشكل الرد لا يمسّهما القص، والمطفأ
          // (وصفر) يمرر النص كله، والسالب رماه بناء الخادم
          var hostMessage = result.errorMessage ?? 'Command execution failed';
          final messageCap = config.maxErrorMessageLength;
          if (messageCap > 0) {
            final encoded = utf8.encode(hostMessage);
            if (encoded.length > messageCap) {
              var cut = messageCap;
              // الرجوع من حدّ البايتات إلى بداية المحرف: بايتُ تتمة
              // (10xxxxxx) يعني وقوفاً وسط محرفٍ فيتراجع القصُّ إلى
              // بدايته فيسقط المحرف كله لا نصفه
              while (cut > 0 && (encoded[cut] & 0xC0) == 0x80) {
                cut--;
              }
              hostMessage = utf8.decode(encoded.sublist(0, cut));
            }
          }
          // حالة الرفض المعلّمة من المعالج (خيار): داخل 400..499 تصل
          // السلك بدل الـ500 الافتراضي، وخارجها تُتجاهل بتحذير مكبوح —
          // والمطفأ يجعل العلامة كلها خاملة فيبقى 500 كما كان حرفاً
          var outcomeStatus = result.ok
              ? HttpStatus.ok
              : HttpStatus.internalServerError;
          final markedRefusal = config.acceptHandlerRefusal
              ? result.refusalStatus
              : null;
          if (!result.ok && markedRefusal != null) {
            if (markedRefusal >= 400 && markedRefusal <= 499) {
              outcomeStatus = markedRefusal;
            } else {
              final line = _refusalStatusWarnThrottle.admit(
                'handler refusal status $markedRefusal is outside '
                '400..499 — ignored, the failure answers 500',
              );
              if (line != null) {
                telemetry.warn(line, category: BridgeCategory.network);
              }
            }
          }
          await _reply(
            response,
            status: outcomeStatus,
            json: {
              'ok': result.ok,
              if (!result.ok)
                'error': result.errorCode ?? config.fallbackErrorCode,
              // نص المضيف للمعتمدين حصرا — الرمز عقد الجميع
              if (!result.ok && verboseErrors) 'message': hostMessage,
              // بيانات المضيف للصفحة: فوق السقف رُفض الرد كله أعلاه
              'data': ?pageData,
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
    if (error is _BinaryBodyTooLargeException) {
      // سقف الجسم الثنائي الداخلي: نفس عائلة 413 والرد أولاً على
      // المقبس المنتزع كما أخوته، والرسالة تسمي السقف الثنائي لا
      // سقف البايتات العام — كلٌّ يقرأ سقفه الصادق
      await _replyRejection(
        response,
        code: 'payload_too_large',
        message:
            'Binary request body exceeds the internal binary cap '
            '($_binaryCapLabel)',
        bodyFullyRead: false,
      );
    } else if (error is _BodyTooLargeException) {
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
        // خطأ محلل = شكل بروتوكولي في العداد؛ bad_request على مسار
        // الاقتران (حقيقة جسم) لا يدخل عداد الشكل
        protocolShape: true,
      );
    } else {
      // خطأ مقبس أثناء الجسم ليس علة صيغة عند العميل: يُطلق
      // ليصله مسار الشبكة الأماني (500 ثابت وسجل انهيار).
      throw error;
    }
  }

  /// فرع رفض بوابة القبول - مسار واحد مشترك بين الرد الواحد (الأوامر)
  /// وصفحة الصحة كي لا يتشعب شكل الرفض: الرأس الصادق Retry-After بقاعدة
  /// الثابت 2 للسؤال المفتوح حصراً، وصدى CORS المؤهل (السؤال دوماً؛
  /// وكل رفض ذي ميزانية انتظار للواصل؛ وtoken_required
  /// وpair_signature_replay لعموم القراءة المؤهلة)، والرد على المقبس
  /// الخام بنمط بقية الرفض المبكر (الجسم غير مقروء فالرد أولاً ثم
  /// التفريغ المحدود بلا حجز مقعد). false يعني لا رفض فالمسار يكمل.
  Future<bool> _answerGateRejection(
    HttpResponse response,
    IntakeAdmission admission,
    String? origin, {
    bool headOnly = false,
  }) async {
    final rejection = admission.rejection;
    if (rejection == null) {
      return false;
    }
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
    await _replyRejection(
      response,
      code: rejection.code,
      message: rejection.message,
      bodyFullyRead: false,
      headOnly: headOnly,
    );
    return true;
  }

  /// صفحة الصحة المسلحة: التسوية الكاملة لبسطة القبول نفسها (الأثر يهبط
  /// كما يهبط لأي طلب — طوابع الحصص والسؤال وعدّ الرفض) ثم الرد: المقبول
  /// وحده يقرأ `{"ok":true}` حرفاً — بلا رقم إصدار ولا عدّادات ولا
  /// تفاصيل، فالصفحة فحص حياة لا قناة بصمات — وغير المقبول يقرأ رفض
  /// البوابة بلا صدى فيخفيه المتصفح كله. جسم GET لا يُقرأ على هذا المسار
  /// فيمر الرد على المقبس المنتزع بنمط بقية الردود المبكرة.
  Future<void> _handleHealthPage(
    HttpRequest request,
    HttpResponse response,
    IntakeAdmission admission,
  ) async {
    final origin = _firstHeader(request, 'Origin');
    admission.settle();
    if (await _answerGateRejection(response, admission, origin)) {
      return;
    }
    _echoCors(response, origin, admitted: admission.echoesCors);
    await _reply(
      response,
      status: HttpStatus.ok,
      json: const {'ok': true},
      bodyFullyRead: false,
    );
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
        // حقيقة جسم على مسار الاقتران — تدخل عداد الاقتران لا عداد الشكل
        pairingRoute: true,
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
        // كل رفض على مسار الاقتران يدخل عداد الاقتران برمزه
        pairingRoute: true,
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

  /// Whether this request is a WebSocket handshake on the channel's path:
  /// the option armed, a GET on exactly the configured path, and the
  /// upgrade head (the upgrade token plus a client key) present. Anything
  /// else on the path rides the standing behavior (a plain GET reads 405
  /// like every non-POST).
  bool _isWsHandshake(HttpRequest request) {
    final path = config.wsPath;
    if (path == null) return false;
    if (request.method != 'GET' || request.uri.path != path) return false;
    final upgrade = _firstHeader(request, HttpHeaders.upgradeHeader);
    if (upgrade == null || upgrade.trim().toLowerCase() != 'websocket') {
      return false;
    }
    final key = _firstHeader(request, 'Sec-WebSocket-Key');
    return key != null && key.trim().isNotEmpty;
  }

  /// إغلاق قناة برمزها المسجل: الإطار الأخير بعقد الرفض ثم الإغلاق
  /// برمز الإطار الشبكي المناسب — والعدّ من العداد الواحد، والرمز
  /// بلا سجل انحراف بنيوي يُرفع صوتاً فلا إغلاق صامت بترميز مغلوط.
  Future<void> _wsCloseWithCode(
    WebSocket ws,
    String code,
    String message, {
    int wireCloseCode = WebSocketStatus.policyViolation,
  }) async {
    _noteRejection(code);
    final line = _wsCloseWarnThrottle.admit(
      'intake channel close: $code — the connection closed with the '
      'literal code',
    );
    if (line != null) {
      telemetry.warn(line, category: BridgeCategory.security);
    }
    try {
      // الإطار نصي حصراً: رسالة القناة String تصل طرف dart:io إطار
      // نصٍّ لا ثنائي، فتقرأها الصفحة كنص
      ws.add(
        jsonEncode(<String, Object?>{
          'ok': false,
          'error': code,
          'message': message,
        }),
      );
      await ws.close(wireCloseCode, code);
    } on Object {
      // القناة ماتت قبل الإطار أو أثناءه — لا إغلاق ثانٍ ممكن
    }
  }

  /// مسار القناة كله داخل مقعد واحد: المصافحة عبر خطوة القبول الواحدة
  /// (الرفض قبل الترقية برمز السلك الحرفي)، والترقية بسقف الرسالة
  /// مرّ للمحول نفسه وبلا ضغط (قناة أوامر لا تخدم ضغطاً لمختلط
  /// أسرارها)، ثم الاعتماد بأول رسالة في مهلتها — التوكن أو إثبات
  /// الاقتران، وقدحه خطوة القبول نفسها بنداء ثانٍ عليها لا منطق
  /// حماية ثانٍ — ثم حلقة الرسائل: الواردة أوامر بفحوص الحمولة نفسها
  /// والصادرة أحداث يرسلها المضيف. سقف الاتصالات هو المقاعد القائمة
  /// نفسها: الاتصال الحي مقعد واحد من السقف العام ومن حصة أصله.
  Future<void> _handleWebSocket(
    HttpRequest request,
    HttpResponse response,
    IntakeAdmission admission,
    String? origin,
  ) async {
    // بوابة القبول: التسوية عند موضعها نفسه كما في الرد الواحد —
    // الرفض قبل الترقية برمز السلك الحرفي ولا ترقية لأصل غير مقبول.
    // والاعتماد مؤجَّل هنا لا مطلوب: المتصفح لا يرسل ترويسة توكن في
    // المصافحة أصلاً — لهذا وُلدت القناة — فالأصل المؤهل يعبر الترقية
    // والاعتماد نفسه هو باب أول رسالتها (demandCredential هناك)
    admission.settle();
    final rejection = admission.rejection;
    if (rejection != null) {
      await _replyRejection(
        response,
        code: rejection.code,
        message: rejection.message,
        bodyFullyRead: false,
      );
      return;
    }
    final WebSocket ws;
    try {
      ws = await _upgradeChannel(request);
    } on Object {
      // ترقية رفضها المحول (ترويسة ناقصة أو شكل مخالف): رفض شكل
      // سلكي يُرد قبل أي شيء آخر
      await _replyRejection(
        response,
        code: 'bad_request',
        message:
            'The WebSocket upgrade was refused — send a valid '
            'handshake (Upgrade: websocket with a client key)',
        bodyFullyRead: false,
        protocolShape: true,
      );
      return;
    }
    ws.pingInterval = _wsHeartbeat;
    _liveWsSockets.add(ws);
    try {
      await _wsSession(ws, origin);
    } finally {
      _liveWsSockets.remove(ws);
    }
  }

  /// جلست القناة على مشتركٍ واحد — dart:io WebSocket دفق اشتراكٍ
  /// وحيد فلا استماع ثانٍ: أول رسالة هي الاعتماد (توكن أو إثبات
  /// اقتران في مهلتها — وإلا الإغلاق بالرمز المسجل)، وما بعدها
  /// أوامر بفحوص الحمولة نفسها تُسلسل بترتيب وصولها، والاتصال كله
  /// حي تحت مهلة الخمول القابلة للضبط ونبض المحول الداخلي.
  Future<void> _wsSession(WebSocket ws, String? origin) async {
    final firstMessage = Completer<Object?>();
    var firstArrived = false;
    var authAccepted = false;
    IntakeAdmission? auth;
    var gone = false;
    Timer? authTimer;
    Timer? idle;
    Future<void> chain = Future<void>.value();
    final sessionDone = Completer<void>();

    void armIdle() {
      idle?.cancel();
      idle = Timer(config.idleTimeout, () {
        unawaited(
          _wsCloseWithCode(
            ws,
            'ws_idle_timeout',
            'No message arrived within the idle timeout '
                '(${config.idleTimeout.inSeconds}s)',
          ),
        );
      });
    }

    void endSession() {
      gone = true;
      authTimer?.cancel();
      idle?.cancel();
      chain.whenComplete(() {
        if (!sessionDone.isCompleted) sessionDone.complete();
      });
    }

    late final StreamSubscription sub;
    final preOpen = <Object?>[];
    sub = ws.listen(
      (message) {
        if (gone) return;
        if (!firstArrived) {
          // أول رسالة = الاعتماد: حلقة الأوامر لا تلمس قبل حسمها
          firstArrived = true;
          authTimer?.cancel();
          if (!firstMessage.isCompleted) firstMessage.complete(message);
          return;
        }
        if (!authAccepted) {
          // وصلت أثناء حسم الاعتماد: تُخزن بالترتيب ولا تُسقط —
          // العميل أرسل اعتماده وأمره متتاليين على القناة نفسها
          preOpen.add(message);
          return;
        }
        armIdle();
        chain = chain.then<void>((_) async {
          if (gone || auth == null) return;
          try {
            await _wsHandleMessage(ws, message, auth);
          } on Object {
            // عطل كتابة الرد: القناة ماتت — onDone/onError يجيبان موتها
          }
        });
      },
      onError: (Object e) {
        if (!firstArrived) {
          firstArrived = true;
          authTimer?.cancel();
          if (e is WebSocketException) {
            // إطار فوق سقف النقل قبل أي رسالة: المحول رمى على الطول
            // المعلن وأغلق النقل بنفسه — الرفض المسجل يعدّ هنا والسطر
            // المكبوط يسمّيه، ولا إطار إفصاح فوق نقلٍ ميت
            _noteRejection('ws_message_too_large');
            final line = _wsCloseWarnThrottle.admit(
              'intake channel close: ws_message_too_large — the transport '
              'refused the declared frame length',
            );
            if (line != null) {
              telemetry.warn(line, category: BridgeCategory.security);
            }
          }
          if (!firstMessage.isCompleted) {
            firstMessage.complete(_WsAuthMarker.gone);
          }
          endSession();
          return;
        }
        endSession();
      },
      onDone: () {
        if (!firstArrived) {
          firstArrived = true;
          authTimer?.cancel();
          if (!firstMessage.isCompleted) {
            firstMessage.complete(_WsAuthMarker.gone);
          }
        }
        endSession();
      },
    );

    authTimer = Timer(effectiveWsAuthDeadline, () {
      if (!firstArrived) {
        firstArrived = true;
        if (!firstMessage.isCompleted) {
          firstMessage.complete(_WsAuthMarker.timeout);
        }
      }
    });

    final first = await firstMessage.future;
    if (first == _WsAuthMarker.gone) {
      // رحل قبل أي رسالة: لا إغلاق مطلوب ولا أثر يُعدّ
      unawaited(sub.cancel());
      return;
    }
    if (first == _WsAuthMarker.timeout) {
      await _wsCloseWithCode(
        ws,
        'ws_auth_timeout',
        'No credential arrived within the auth deadline '
            '(${effectiveWsAuthDeadline.inSeconds}s) — the first message '
            'must carry the token or the pairing signature',
      );
      unawaited(sub.cancel());
      return;
    }
    // رسالة الاعتماد: كائن JSON بحقل توكن أو إثبات لا الاثنين —
    // وغير ذلك إغلاقُ اعتمادٍ فاسد بالرمز المسجل
    String? authToken;
    String? authProof;
    var authCid = '';
    var authShapeValid = false;
    if (first is String && utf8.encode(first).length > _maxWsMessageBytes) {
      await _wsCloseWithCode(
        ws,
        'ws_message_too_large',
        'The message is over the internal channel cap '
            '($_wsMessageCapLabel)',
        wireCloseCode: WebSocketStatus.messageTooBig,
      );
      unawaited(sub.cancel());
      return;
    }
    if (first is String) {
      try {
        final decoded = jsonDecode(first);
        if (decoded is Map) {
          final tokenValue = decoded['token'];
          final proofValue = decoded['pairing'];
          final cidValue = decoded['correlationId'];
          final tokenOk = tokenValue is String && tokenValue.isNotEmpty;
          final proofOk = proofValue is String && proofValue.isNotEmpty;
          if (tokenOk != proofOk) {
            // واحدٌ لا اثنان ولا صفر
            authShapeValid = true;
            if (tokenOk) {
              authToken = tokenValue;
            } else {
              authProof = proofValue;
            }
            if (cidValue is String) {
              authCid = _sanitizeCorrelationId(cidValue);
            }
          }
        }
      } on FormatException {
        // ليس JSON: اعتماد فاسد شكلاً
      }
    }
    if (!authShapeValid) {
      await _wsCloseWithCode(
        ws,
        'ws_auth_invalid',
        'The first message must be a JSON object carrying exactly one '
            'credential: "token" or "pairing"',
      );
      unawaited(sub.cancel());
      return;
    }
    // الاعتماد بنفس خطوة القبول: نداء admit ثانٍ على الأصل نفسه
    // بالاعتماد الذي حملته الرسالة، وتسويته يهبط أثره كأي طلب
    // (طوابع الإخفاق والقفل والحصص وأسطر الأمن) — لا منطق حماية
    // ثانٍ. وطلب الاعتماد إلزامياً هنا: الأصل المؤهل وحده لا يفتح
    // قناة (demandCredential يجعل الإثبات باباً مفحوصاً حتماً)
    final authAdmission = await protection.admit(
      origin: origin,
      bridgeToken: authToken,
      pairingProof: authProof,
      path: config.wsPath ?? '/',
      method: 'WS',
      correlationId: authCid,
      demandCredential: true,
    );
    authAdmission.settle();
    if (authAdmission.acceptedPath == null) {
      // رفض الاعتماد برمزه الحقيقي من السجل: token_required
      // وtoken_locked وpair_signature_replay وأخواتها
      await _wsCloseWithCode(
        ws,
        authAdmission.rejection!.code,
        authAdmission.rejection!.message,
      );
      unawaited(sub.cancel());
      return;
    }
    // اعتمدت: القناة مفتوحة — المخزون من ما قبل الفتح يجري أولاً
    // بترتيب وصوله ثم الأوامر الحية على المشترك نفسه حتى موتها
    final sessionAuth = authAdmission;
    auth = sessionAuth;
    authAccepted = true;
    armIdle();
    for (final queued in preOpen) {
      chain = chain.then<void>((_) async {
        if (gone) return;
        try {
          await _wsHandleMessage(ws, queued, sessionAuth);
        } on Object {
          // عطل كتابة الرد: القناة ماتت — onDone/onError يجيبان موتها
        }
      });
    }
    preOpen.clear();
    await sessionDone.future;
    unawaited(sub.cancel());
    idle?.cancel();
  }

  /// رسالة واحدة من القناة: فحوص الحمولة نفسها ثم تسليم الأمر ثم رد
  /// بعقد الرد القائم. الإطار الثنائي ليس نصاً فلا أمر فيه — رفض
  /// المحتوى الصادق يبقى على القناة ويبقيها مفتوحة، والرسائل فوق
  /// سقف المحول لا تصل هنا أصلاً (يرمي المحول عند الطول المعلن).
  /// سجل قبول الاعتماد هو من يخيط الأمر: أصل المصدر ونصُّ الأخطاء
  /// المسموح به يقرآن منه لا من إسقاط ثانٍ.
  Future<void> _wsHandleMessage(
    WebSocket ws,
    Object? message,
    IntakeAdmission auth,
  ) async {
    final verbose = auth.verboseErrors;
    if (message is! String) {
      // إطار ثنائي: القناة تحمل أوامر JSON نصية حصراً
      _noteRejection('non_json_body');
      try {
        ws.add(
          jsonEncode(<String, Object?>{
            'ok': false,
            'error': 'non_json_body',
            'message': 'This channel accepts JSON text messages only',
          }),
        );
      } on Object {
        // القناة ماتت وسط الرد — الحلقة تجيب موتها
      }
      return;
    }
    // سقف الرسالة عند التسليم: بايتات UTF-8 فوق السقف تُغلق برمزها
    // المسجل بإطاره الإفصاحي (سقف النقل الواسع أضيق من هذا أن يمرّ
    // ضخمُ حقيقةً — والفحص هنا هو العقد الذي يقرأه السلك)
    final body = message;
    if (utf8.encode(body).length > _maxWsMessageBytes) {
      await _wsCloseWithCode(
        ws,
        'ws_message_too_large',
        'The message is over the internal channel cap '
            '($_wsMessageCapLabel)',
        wireCloseCode: WebSocketStatus.messageTooBig,
      );
      return;
    }
    if (!_jsonShapeWithinLimits(
      body,
      config.maxJsonElements,
      config.maxJsonDepth,
    )) {
      _noteRejection('payload_too_complex');
      try {
        ws.add(
          jsonEncode(<String, Object?>{
            'ok': false,
            'error': 'payload_too_complex',
            'message':
                'Message has too many JSON elements or is nested too '
                'deeply (over ${config.maxJsonElements} elements or '
                '${config.maxJsonDepth} deep) — send fewer, shallower '
                'elements',
          }),
        );
      } on Object {
        // القناة ماتت وسط الرد
      }
      return;
    }
    if (config.requireValidJsonShape && !_jsonShapeComplete(body)) {
      _noteRejection('malformed_json_shape');
      try {
        ws.add(
          jsonEncode(<String, Object?>{
            'ok': false,
            'error': 'malformed_json_shape',
            'message':
                'Message claims a JSON container shape but is not '
                'structurally complete — send the whole JSON document',
          }),
        );
      } on Object {
        // القناة ماتت وسط الرد
      }
      return;
    }
    final List<String> payloads;
    try {
      payloads = _extractPayloads(body, declaredJson: false);
    } on _UnsupportedPayloadShapeException {
      // والعدّ من _wsReplyOnce وحده — لا عدّ مزدوج هنا كما في empty_payload
      return _wsReplyOnce(
        ws,
        'unsupported_payload_shape',
        'JSON message has a known-but-unsupported shape (object without '
            'known command keys)',
      );
    } on _StrictPayloadItemException {
      // والعدّ من _wsReplyOnce وحده
      return _wsReplyOnce(
        ws,
        'invalid_payload_item',
        'Command list carries a non-string or empty element (strict item '
            'checking is on)',
      );
    } on _InvalidJsonException {
      // بلا نوع معلن المسار الخام هو أصلاً حكم الرسالة — غير قابل
      // للوصول هنا، والتصيد البنيوي باقٍ. والعدّ من _wsReplyOnce وحده
      return _wsReplyOnce(ws, 'invalid_json', 'The message is not valid JSON');
    } on _NonJsonBodyException {
      // والعدّ من _wsReplyOnce وحده
      return _wsReplyOnce(
        ws,
        'non_json_body',
        'This channel accepts JSON messages only — send the command as JSON',
      );
    }
    if (payloads.isEmpty) {
      // والعدّ من _wsReplyOnce وحده — لا عدّ مزدوج هنا
      return _wsReplyOnce(
        ws,
        'empty_payload',
        'No valid command payload found in the message',
      );
    }
    // سقف العمل الحي: نفس بوابته في الرد الواحد — اليتامى والمقاعد
    // ميزانية واحدة، وفوقها الرفض برمزه والقناة تبقى حية لأمرٍ تالٍ
    if (_activeRequests + _activeOrphans > config.maxConcurrentRequests) {
      // والعدّ من _wsReplyOnce وحده
      final line = _orphanBusyWarnThrottle.admit(
        'intake busy: $_activeOrphans orphan handler(s) still running — '
        'rejecting before invoking another',
      );
      if (line != null) {
        telemetry.warn(line, category: BridgeCategory.network);
      }
      return _wsReplyOnce(
        ws,
        'server_busy',
        'The server is busy right now — please retry shortly',
      );
    }
    // تسليم الأمر: إشارة إلغاء حية، وسلسلة الإشارات الحية نفسها،
    // وميزانية المعالج نفسها — اليتم بعدها حساب الرد الواحد حرفاً
    final cancelSignal = CommandCancelSignal();
    _liveSignals.add(cancelSignal);
    final correlationId = correlationIdGenerator();
    final commandFuture = onCommand(
      TrustedCommand(
        source: auth.origin ?? 'unknown-origin',
        payloads: payloads,
        headers: {'x-correlation-id': correlationId},
        correlationId: correlationId,
        admission: auth,
        cancellation: cancelSignal,
      ),
    );
    unawaited(
      commandFuture.then<void>(
        (_) => _liveSignals.remove(cancelSignal),
        onError: (Object _, StackTrace _) => _liveSignals.remove(cancelSignal),
      ),
    );
    final (awaited, budgetExpired) = await _awaitCommandFuture(
      commandFuture,
      cancelSignal,
    );
    Map<String, Object?> reply;
    if (budgetExpired || awaited == null) {
      reply = <String, Object?>{
        'ok': false,
        'error': 'handler_timeout',
        'message': 'The command handler exceeded its time budget',
      };
    } else {
      reply = _contractFrame(awaited, verbose);
    }
    try {
      ws.add(jsonEncode(reply));
    } on Object {
      // القناة ماتت وسط الرد — الحلقة تجيب موتها
    }
  }

  /// رد رفضٍ واحد على القناة — العدّ من العداد الواحد والكتابة محصورة
  void _wsReplyOnce(WebSocket ws, String code, String message) {
    _noteRejection(code);
    try {
      ws.add(
        // الإطار نصي حصراً — String على dart:io يسير إطار نصٍّ
        jsonEncode(<String, Object?>{
          'ok': false,
          'error': code,
          'message': message,
        }),
      );
    } on Object {
      // القناة ماتت وسط الرد
    }
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
  ///
  /// [binary] reads raw bytes: no UTF-8 decode ever runs (a binary file is
  /// not text - an image or PDF carries bytes no decoder may touch), the
  /// completion settles with the bytes whole, and the counter cuts at the
  /// internal binary ceiling with the binary-cap 413.
  Future<_BodyOutcome> _readBody(
    HttpRequest request, {
    bool binary = false,
  }) async {
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

    void settle(Object? error, [Object? body]) {
      if (settled) return;
      // كل حسم يلغي مؤقت الموعد — التفريغ بعده يملك مؤقته الخاص
      deadlineTimer?.cancel();
      deadlineTimer = null;
      if (error == null) {
        settled = true;
        done.complete(
          body is Uint8List
              ? _BodyOutcome.bytes(body)
              : _BodyOutcome.text(body! as String),
        );
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
            } else if (binary && builder.length > _maxBinaryBodyBytes) {
              // سقف الثنائي الأضيق: يقطع لحظة تجاوزه برسالة سقفه هو
              settle(const _BinaryBodyTooLargeException());
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
              // المسار الثنائي: البايتات كما هي بلا أي فك نص — ملف صورة
              // أو PDF يحمل بايتات لا يمسّها مفكك
              settle(
                null,
                binary ? builder.takeBytes() : utf8.decode(builder.takeBytes()),
              );
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
    HttpStatus.ok: 'OK',
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

  /// عدّاد الرفض الواحد: يقرأ سطر الرمز من سجل الرموز الواحد — رمزٌ بلا
  /// سجل انحراف بنيوي يُرفع صوتاً فلا رفض صامت بترميز مغلوط — ثم يعدّه
  /// في عدّادات الخادم الثلاثة (بالرمز، وشكل بروتوكولي، واقتران؛
  /// الأخيران منظران متداخلان فوق الأول لا قسمة حصرية). كل رفض يعدّ
  /// من هنا حصراً: ردود HTTP من مخرج الرفض، ورفض القنوات غير الـHTTP
  /// (إطار إغلاق القناة أو إطار التدفق الأخير) من ندائه المباشر —
  /// عدّاد واحد لا مسار يعدّ بيده.
  IntakeRejectSpec _noteRejection(
    String code, {
    bool protocolShape = false,
    bool pairingRoute = false,
  }) {
    final spec = intakeRejectionRegistry[code];
    if (spec == null) {
      throw StateError('unregistered intake rejection code: $code');
    }
    _rejectionsByCode[code] = (_rejectionsByCode[code] ?? 0) + 1;
    if (protocolShape || _protocolShapeRejectionCodes.contains(code)) {
      _protocolShapeRejections++;
    }
    if (pairingRoute || _pairingRejectionCodes.contains(code)) {
      _pairingRejections++;
    }
    return spec;
  }

  /// مخرج الرفض: يقرأ سطر رمزه من سجل الرموز الواحد — الحالة والقطع
  /// الفوري من السجل حصراً لا من الموضع — ثم يُنعطي مخرج الرد به، وطريقة
  /// الإغلاق تبقى من حقيقة قراءة الجسم فيه. والعدّ من عدّاد الرفض
  /// الواحد لا بيده.
  Future<void> _replyRejection(
    HttpResponse response, {
    required String code,
    required String message,
    required bool bodyFullyRead,
    bool headOnly = false,
    bool protocolShape = false,
    bool pairingRoute = false,
  }) async {
    final spec = _noteRejection(
      code,
      protocolShape: protocolShape,
      pairingRoute: pairingRoute,
    );
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

  /// رد الصفحة المحلية: الترويسات الأمنية الأربع تُضبط على كائن الرد
  /// قبل الانتزاع فتُنسخ في الرأس اليدوي، والنوع المعلن هو ما مرّره
  /// المضيف لا النوع الافتراضي، والجسم نص الصفحة حرفاً من الذاكرة. جسم
  /// GET لا يُقرأ على هذا المسار فيُكتب الرد أولاً على المقبس المنتزع
  /// ثم يُفرَّغ الباقي بالصبر المحدود في خلفية بلا مقعد - نفس شكل
  /// إغلاق ردود بوابة الطريقة.
  Future<void> _replyPage(HttpResponse response, BridgeLocalPage page) async {
    final headers = response.headers;
    // CSP الصارمة وحارسا التأطير والتحويل: الصفحة سطح عرض كتبه المضيف
    // لا مُحمِّل - لا شيء يُجلب من أي مكان إلا سكربتها ونمطها المضمّنان
    // والوصل لأصل الجسر نفسه حصراً
    headers.set('Content-Security-Policy', _pageSecurityCsp);
    headers.set('X-Frame-Options', 'DENY');
    headers.set('Referrer-Policy', 'no-referrer');
    // النوع المعلن لا يُقلب: nosniff يمنع التخمين فوق ما أعلنه المضيف
    headers.set('X-Content-Type-Options', 'nosniff');
    try {
      final socket = await _detachAndReply(
        response,
        HttpStatus.ok,
        utf8.encode(page.content),
        bodyContentType: page.contentType,
      );
      _discardDetached(socket);
    } on Object {
      // العميل انقطع قبل الرد أو أثناءه: الدمّر تم من الداخل
    }
  }

  /// انتظار مستقبل الأمر بميزانية المعالج — الماكينة واحدة لكل مسار
  /// تسليم (الرد الواحد والتدفق معاً) فلا يتشعب حساب اليتامى: انتهاء
  /// الميزانية يشعل إشارة الإلغاء كي يغلف المعالج عمله إن شاء، ويجعل
  /// المستقبل مستهلكاً (لا خطأ يتيم يهرب للـzone)، ويُعدّ اليتيم ضمن
  /// ميزانية العمل الحي بتذكرة حية يدق فراغها جرس تفريغ stop، ويكبح
  /// سطر التحذير بنمط بقية الأسطر. أما الرد (504 أو إطار التدفق
  /// الأخير) فقرار المسار لا هذا الانتظار.
  ///
  /// العائد: النتيجة عند اكتمالها والرقم false، أو زوج فارغ مع true
  /// عند احتراق الميزانية — وكل TimeoutException أخرى (رمى المعالج
  /// نفسه) تمر من المسار العام (مسار 500) كي لا تلبس بميزانية الجسر.
  Future<(CommandOutcome?, bool)> _awaitCommandFuture(
    Future<CommandOutcome> commandFuture,
    CommandCancelSignal cancelSignal,
  ) async {
    final handlerBudget = effectiveHandlerTimeout;
    try {
      final result = handlerBudget == null
          ? await commandFuture
          : await commandFuture.timeout(
              handlerBudget,
              onTimeout: () => throw const _HandlerBudgetExceeded(),
            );
      return (result, false);
    } on _HandlerBudgetExceeded {
      cancelSignal.cancel();
      // تجاهلُ ignore للمستقبل الأصلي وحده — then بمعالج خطأ فارغ كي
      // لا يُحيى خطأه المتأخر بعد ما صار يتماً
      commandFuture.ignore();
      final ticket = _OrphanTicket(cancelSignal);
      _pendingOrphans.add(ticket);
      _activeOrphans++;
      commandFuture.then<void>(
        (_) => _settleOrphan(ticket),
        onError: (_) => _settleOrphan(ticket),
      );
      final line = _handlerTimeoutWarnThrottle.admit(
        'intake handler timeout — seat released, late result ignored',
      );
      if (line != null) {
        telemetry.warn(line, category: BridgeCategory.network);
      }
      return (null, true);
    }
  }

  /// مسار الرد المتدفق: المقبس ينفصل مرة واحدة برأس text/event-stream
  /// من بدأة الرد الواحد، ثم إطارات التقدم تُكتب فوقه بنداءات sink
  /// المعالج، والإطار الأخير (result) يحمل عقد الرد القائم كله — نفس
  /// سقف بيانات الرد ونفس القص ونفس الرموز، فلا عقد ثانٍ للتدفق.
  /// إغلاق الصفحة للاتصال يبلغ المعالج إشارة الإلغاء ولا يبقى مقعد
  /// ولا مقبس: المشاهد على المقبس يشعل الإشارة ويدمر ما بقي، والمقعد
  /// يتحرر بحسم مستقبل المعالج كما في الرد الواحد.
  Future<void> _runStreamingReply({
    required HttpRequest request,
    required HttpResponse response,
    required CommandCancelSignal cancelSignal,
    required IntakeAdmission admission,
    required List<String> payloads,
    required Uint8List? binaryBytes,
    required String source,
    required bool verboseErrors,
    required String correlationId,
  }) async {
    final Socket socket;
    try {
      socket = await _detachAndReply(
        response,
        HttpStatus.ok,
        null,
        streamBody: true,
      );
    } on Object {
      // العميل رحل قبل الرأس: لا قناة تُفتح ولا أثر يُعدّ
      return;
    }
    // حي القناة وجهةُ موتها وجهان: [alive] يعني قبول sink للإطارات
    // (يخمد عند الرفض أو الرحيل)، و[gone] يعني المقبس نفسه مات
    // (دمار أو عطل أو انتهاء جهة قراءة العميل) — التمييز يحفظ إطار
    // الرفض فوق مقبس حي رغم خمود الsink. انتهاء جهة القراءة في هذا
    // الاتجاه رحيلٌ لا نصفُ إغلاقٍ: جسم الطلب قُرئ كاملاً قبل التدفق
    // فلا شيء ينتظره العميل من جهة إرساله، وفينُه وسط التدفق توديعُ
    // صفحة رحلت — الإشعال يبلغ المعالج فيغلف، والدمّر يمنع بقايا
    // (والمقاس: HttpClient لا يغلق إرساله بعد الجسم — الشاهد حي
    // يقيس الإطارات كاملة فوق نفس المقبس بعد الفين الوهمي المزعوم)
    var alive = true;
    var gone = false;
    StreamSubscription<List<int>>? watch;
    void markGone() {
      if (gone) return;
      gone = true;
      alive = false;
      cancelSignal.cancel();
      unawaited(watch?.cancel());
      socket.destroy();
    }

    watch = socket.listen(
      (_) {},
      onDone: markGone,
      onError: (Object _) => markGone(),
    );
    // سلسلة الكتابة الواحدة: إطار يُكتب ويُغسل ثم الإطار الذي يليه —
    // dart:io يربط الSink بالغسل الجاري (flush يُبقيه مقيّداً حتى
    // يكتمل) فيرفض أي إضافة أو غسل فوق غسلٍ حي، والسلسلة تحفظ الغسل
    // التدريجي (الصفحة تقرأ كل إطار لحظته) مع حفظ الترتيب نفسه
    Future<void> writes = Future<void>.value();
    void send(String frame) {
      writes = writes.then<void>((_) async {
        // الحارس على [gone] لا [alive]: الإطار المقبول قبل خمود الsink
        // يكتب ولو جاء خموده في نفس الموجة — المقبس الميت وحده يلغي
        if (gone) return;
        try {
          socket.add(utf8.encode(frame));
          await socket.flush();
        } on Object {
          // الطرف رحل وسط الإطار: قناة ميتة يبلغ عنها عطل الكتابة
          markGone();
        }
      });
    }

    // حسم القناة بعد آخر إطار: إغلاق جهة الكتابة (الفين) ثم التفريغ
    // المحدود الباقي بلا مقعد — نمط حسم الرد الواحد نفسه. انقطاع
    // الطرف قبل الإطار يجعل الدمّر وحده الباقي؛ فلا مقبس يبقى بعد
    // الإطار في الحالين
    Future<void> finishFrame(Map<String, Object?> json) async {
      await writes;
      if (gone) {
        // المقبس مات قبل النتيجة: لا إطار يُكتب ولا تفريغ لمقبس ميت
        return;
      }
      // الsink يخمد من هنا: آخر إطار للقناة يمر الآن
      alive = false;
      try {
        await watch?.cancel();
      } on Object {
        // المشاهد رحل سابقاً — الكتابة تحكم بعدها
      }
      try {
        socket.add(utf8.encode('event: result\ndata: ${jsonEncode(json)}\n\n'));
        await socket.flush();
        await socket.close();
      } on Object {
        // الطرف رحل قبل الإطار أو أثناءه: الدمّر تم من الداخل أو تم هنا
        socket.destroy();
        return;
      }
      // جسم الطلب قُرئ كاملاً قبل التدفق — لا بقايا مرسل، والتفريغ هنا
      // انتظار الطرف أن يفض قراءته ثم الدمّر تحت الحدود القائمة
      _discardDetached(socket);
    }

    // sink التقدم: كل نداء إطار واحد في سلسلة الكتابة، وترتيب
    // النداءات هو ترتيب الإطارات على السلك. القيمة غير القابلة للفك
    // ترمي عند النداء — عقدُ المعالج هو المخل ولا يبتلع هنا؛ وفوق
    // سقف الحدث تنتهي القناة بالرفض المسجل وتُشعل الإشارة ويخمد
    // الsink — القناة ماتت فالتغليف هو الطلب الصادق
    void sink(Object? data) {
      if (!alive) return;
      final encoded = jsonEncode(data);
      if (utf8.encode(encoded).length > _maxReplyDataBytes) {
        _noteRejection('progress_data_too_large');
        final wasAlive = alive;
        alive = false;
        cancelSignal.cancel();
        if (wasAlive) {
          unawaited(
            finishFrame(<String, Object?>{
              'ok': false,
              'error': 'progress_data_too_large',
              'message':
                  'A progress report is over the $_maxReplyDataBytes-byte '
                  'event cap - the stream ends here and the command is '
                  'asked to wrap up',
            }),
          );
        }
        return;
      }
      send('event: progress\ndata: $encoded\n\n');
    }

    final commandFuture = onCommand(
      TrustedCommand(
        source: source,
        payloads: payloads,
        headers: {
          ..._stringHeaders(request),
          'x-correlation-id': correlationId,
        },
        correlationId: correlationId,
        // سجل القبول الواحد: المسار المتدفق يسلّم ما سلّمه الرد
        // الواحد — المسار المقبول ودرجة ترويسة الأصل حقيقتا الطلب
        admission: admission,
        cancellation: cancelSignal,
        binaryPayload: binaryBytes,
        progress: sink,
      ),
    );
    unawaited(
      // سلسلة تمتص خطأ المستقبل نفس ما يفعلها الرد الواحد — الخطأ
      // الأصلي يبلغ مسار الإطار الأخير من await الأصلي عادة
      commandFuture.then<void>(
        (_) => _liveSignals.remove(cancelSignal),
        onError: (Object _, StackTrace _) => _liveSignals.remove(cancelSignal),
      ),
    );
    final (awaited, budgetExpired) = await _awaitCommandFuture(
      commandFuture,
      cancelSignal,
    );
    // الإطار الأخير بعقد الرد القائم: مهلة الميزانية تقرأ رمزها
    // المسجل، والنجاح يحمل بياناته بسقف الرد نفسه — فوقه الرفض كله
    // بإطار الرفض لا قصّ صامت، والفشل يحمل رمز المعالج ونصه للمعتمدين
    // مع القص البايتي نفسه. حالة الرفض المعلَّمة لا معنى لها على
    // التدفق (رأسه 200 حتمي) فتظل خاملة بإطار الفشل القائم
    Map<String, Object?> frame;
    if (budgetExpired || awaited == null) {
      _noteRejection('handler_timeout');
      frame = <String, Object?>{
        'ok': false,
        'error': 'handler_timeout',
        'message': 'The command handler exceeded its time budget',
      };
    } else {
      frame = _contractFrame(awaited, verboseErrors);
    }
    await finishFrame(frame);
  }

  /// إطار عقد الرد من نتيجة المعالج — واحد للتدفق وللقناة معاً: سقف بيانات الرد يرفض النتيجة
  /// كلها بالرمز المسجل (وعدّه من العداد الواحد)، ونص المضيف يُقص
  /// بالحد البايتي نفسه عند محرف كامل، والبيانات تحمل كما في الرد
  /// الواحد حرفاً.
  Map<String, Object?> _contractFrame(
    CommandOutcome result,
    bool verboseErrors,
  ) {
    if (result.ok) {
      final pageData = result.data;
      if (pageData != null &&
          utf8.encode(jsonEncode(pageData)).length > _maxReplyDataBytes) {
        _noteRejection('reply_data_too_large');
        return <String, Object?>{
          'ok': false,
          'error': 'reply_data_too_large',
          'message':
              'The command succeeded, but its reply data is over the '
              '$_maxReplyDataBytes-byte page cap - the result is refused '
              'whole, never truncated',
        };
      }
      return <String, Object?>{'ok': true, 'data': ?pageData};
    }
    var hostMessage = result.errorMessage ?? 'Command execution failed';
    final messageCap = config.maxErrorMessageLength;
    if (messageCap > 0) {
      final encoded = utf8.encode(hostMessage);
      if (encoded.length > messageCap) {
        var cut = messageCap;
        // الرجوع من حدّ البايتات إلى بداية المحرف — المحرف كله أو
        // يسقط كله، نفس قاعدة الرد الواحد
        while (cut > 0 && (encoded[cut] & 0xC0) == 0x80) {
          cut--;
        }
        hostMessage = utf8.decode(encoded.sublist(0, cut));
      }
    }
    return <String, Object?>{
      'ok': false,
      'error': result.errorCode ?? config.fallbackErrorCode,
      if (verboseErrors) 'message': hostMessage,
    };
  }

  /// The shared raw-socket reply: detaches the socket, builds the head from
  /// the current response headers - framing headers are rebuilt here (for a
  /// JSON body from the exact body length; for the empty 204 as
  /// `Content-Length: 0`, the same framing the managed close writes) -
  /// writes the head and the body, flushes, and closes the write side.
  /// Throws after destroying when the sender was gone mid-reply: the caller
  /// has nothing left to drain in that case.
  ///
  /// [streamBody] hands the socket back with the head only and the write
  /// side still open - the streaming reply writes its frames over the same
  /// socket and closes it when the last frame is out. The head carries the
  /// given content type in place of the response's own (a stream is not
  /// JSON) and no length at all: the body ends when the write side closes,
  /// which the `Connection: close` the head always carries already
  /// announces to the reader.
  Future<Socket> _detachAndReply(
    HttpResponse response,
    int status,
    List<int>? body, {
    bool headOnly = false,
    bool streamBody = false,
    String streamContentType = 'text/event-stream',
    String bodyContentType = 'application/json; charset=utf-8',
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
            ((body != null || streamBody) &&
                lower == HttpHeaders.contentTypeHeader)) {
          return;
        }
        for (final value in values) {
          head.write('$name: $value\r\n');
        }
      });
      if (body != null) {
        head
          ..write('${HttpHeaders.contentTypeHeader}: $bodyContentType\r\n')
          ..write('${HttpHeaders.contentLengthHeader}: ${body.length}\r\n');
      } else if (streamBody) {
        // التدفق: النوع المعلن هو نوع القناة، وبلا طول إطلاقاً — الجسم
        // ينتهي بإغلاق جهة الكتابة الذي يعلنه سطر Connection: close،
        // والإطارات تُكتب فوق المقبس نفسه بعد عودته
        head.write('${HttpHeaders.contentTypeHeader}: $streamContentType\r\n');
      } else {
        // الـ204 بلا جسم ويحمل Content-Length: 0 — نفس التأطير الذي
        // يكتبه الرد المُدار، فلا يتغير شكل الـpreflight على السلك
        head.write('${HttpHeaders.contentLengthHeader}: 0\r\n');
      }
      head.write('${HttpHeaders.connectionHeader}: close\r\n\r\n');

      // الرد أولاً ثم إغلاق جهة الكتابة: الفين يصل قبل أي شيء آخر، وجهة
      // القراءة باقية كما قيس (التفريغ بعده يرى الجسم كاملاً حتى onDone).
      // والتدفق وحده يعيد المقبس بجهة الكتابة مفتوحة — إطاراته تُكتب
      // بعد العودة والإغلاق قرار نهايته لا ولادة أنه.
      socket.add(utf8.encode(head.toString()));
      // رد HEAD بلا جسم على السلك حصراً (المشرّع: لا محتوى في رد HEAD
      // أبداً) — التأطيرية Content-Length تبقى طول الجسم الذي كان سيُكتب
      // لعلم القارئ، والبايتات لا تُكتب والاتصال يُغلق بعدها
      if (body != null && !headOnly) socket.add(body);
      await socket.flush();
      if (!streamBody) await socket.close();
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

  /// Structural completeness for container-shaped bodies - the shape-check
  /// option's scanner. Same leading-shape rule as the complexity scan
  /// above: a body not starting with `{` or `[` is raw-text territory and
  /// always complete (never scanned). A container that ends with an opener
  /// still unclosed, or inside a string never terminated, cannot decode
  /// and the option refuses it before jsonDecode runs - instead of the
  /// default raw fallthrough. Gross truncation only: a body that scans
  /// complete but still fails decoding stays on the ordinary paths (the
  /// declared-type and JSON-only options own those).
  bool _jsonShapeComplete(String body) {
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
        depth++;
      } else if (c == '}' || c == ']') {
        depth--;
      }
    }
    return !inString && depth == 0;
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
  /// non-string elements are skipped instead of a toString on any type met -
  /// unless the strict-items option is on, when the first non-string or
  /// empty element raises the strict reject instead of the silent drop.
  ///
  /// [declaredJson] tells whether the sender declared `application/json`:
  /// a decoding failure under that declared type raises the invalid-json
  /// reject when its option is on. The raw-text fallback (a decode failure
  /// under any other type, or a JSON number, boolean, or null body)
  /// raises the non-json-body reject when the JSON-only option is on -
  /// otherwise it stays the standing raw-text delivery.
  List<String> _extractPayloads(String body, {required bool declaredJson}) {
    try {
      final decoded = jsonDecode(body);
      if (decoded is List) {
        // العناصر الصارمة: أول عنصر غير نصي أو فارغ يرفع الرفض بدل
        // سقوطه صامتا — المطفأ يبقي السلوك القائم حرفاً
        if (config.strictPayloadItems) {
          for (final e in decoded) {
            if (e is! String || e.isEmpty) {
              throw const _StrictPayloadItemException();
            }
          }
        }
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
            // القاعدة الصارمة نفسها على قوائم الغلاف
            if (config.strictPayloadItems) {
              for (final e in value) {
                if (e is! String || e.isEmpty) {
                  throw const _StrictPayloadItemException();
                }
              }
            }
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
    } on _StrictPayloadItemException {
      rethrow;
    } on FormatException {
      // فك مكسور: النوع المعلن application/json يحمل عقد فك صادقا
      // فخياره يرفض هنا — وغيره يسقط للمسار الخام أدناه حيث يملك
      // وضع JSON فقط حكمه
      if (config.rejectInvalidJson && declaredJson) {
        throw const _InvalidJsonException();
      }
    } catch (_) {
      // ليس JSON — نص خام مباشر
    }
    // مسار النص الخام: وضع JSON فقط يرفضه كله (فك مكسور بنوع آخر،
    // أو رقم/منطقي/null، أو نص خام مجرد) — والمطفأ يسلّمه كما كان
    if (config.requireJsonBodies) {
      throw const _NonJsonBodyException();
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
      // اسم الأمر للتسليم الثنائي: يمر مع الخيار مسلّحا حصرا — المطفأ
      // يبقي خريطة الترويسات حرفاً كما هي بلا مفتاح جديد
      if (config.acceptBinaryBodies)
        'x-command': _firstHeader(request, 'X-Command') ?? '',
      // طلب التدفق يمر للمعالج بنفس النمط: مع خياره حصرا وإلا فالترويسة
      // مجهولة لا تقرأ والخريطة حرفاً كما هي
      if (config.allowStreamingReplies)
        'x-bridge-stream': _firstHeader(request, 'X-Bridge-Stream') ?? '',
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

  /// حارس طرف التركيب: هل الطرف البعيد loopback؟ قراءة dart:io على
  /// isLoopback لا تفكّ الصيغة المطبوعة IPv4-mapped IPv6 — الطرف
  /// ‎::ffff:127.0.0.1 الذي يسلّمه الربطُ الثنائي الطبقة لنداء IPv4
  /// loopback يقرأ false مقيساً — فتُفكّ الصيغة هنا وتحكم بايتات IPv4
  /// وحدها بنفس قراءة 127/8 التي يقرأ بها dart:io نفسه. بلا حقيقة طرف
  /// العبرةُ رفض: الحارس يفشل مغلقاً.
  bool _isLoopbackPeer(InternetAddress? address) {
    if (address == null) return false;
    if (address.isLoopback) return true;
    final raw = address.rawAddress;
    if (address.type == InternetAddressType.IPv6 && raw.length == 16) {
      var mapped = true;
      for (var i = 0; i < 10; i++) {
        if (raw[i] != 0) {
          mapped = false;
          break;
        }
      }
      if (mapped && raw[10] == 0xff && raw[11] == 0xff) {
        return raw[12] == 127;
      }
    }
    return false;
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
  /// while the pairing layer is armed, and with the binary command-name
  /// header only while the binary-body option is on - the disarmed wire is
  /// letter identical to previous releases.
  void _corsHeaders(HttpResponse response) {
    // البوابات صفحات https تتصل بـ http محلي — CORS صريح إلزامي.
    // الصدى (ACAO) يقرر لاحقا بعد حسم القبول أو عند الpreflight — لا
    // هنا: رفض قابل القراءة يعطي المهاجم قناة استطلاع
    response.headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    // ترويسة اسم الأمر للجسم الثنائي تدخل القائمة مع الخيار مسلّحا حصرا
    // — المطفأ يبقي القائمة حرفاً كما هي
    final allowedHeaders = <String>[
      'Content-Type',
      'X-Bridge-Token',
      'X-Correlation-Id',
      if (protection.pairingEnabled) 'X-Bridge-Pairing',
      if (config.acceptBinaryBodies) 'X-Command',
      if (config.allowStreamingReplies) 'X-Bridge-Stream',
    ];
    response.headers.set(
      'Access-Control-Allow-Headers',
      allowedHeaders.join(', '),
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
