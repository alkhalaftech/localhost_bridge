library;

import 'dart:io' show IOSink, stderr, stdout;

/// The measurement and logging seam.
///
/// The host adapts its own logger over this interface, keeping the intake latency
/// gauge (via measure), the RSS delta, classification, and stacks alive -
/// where a plain string typedef would have dropped them all.
abstract class BridgeTelemetry {
  /// Const constructor - the class carries no state, so adapters may keep
  /// theirs const too.
  const BridgeTelemetry();

  /// One neutral progress line - e.g. the `intake listening on
  /// 127.0.0.1:PORT` line at bind time. Called on live startup and request
  /// paths, so an implementation should write quickly and never throw.
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  });

  /// One caution line: the throttled capacity warnings (busy rejects, the
  /// orphan and handler-timeout lines, the total-deadline cut, the
  /// non-root path observer) and the security lines - policy changes,
  /// throttled rejection lines, the allow-all activation, the token
  /// length advisory. The wire behavior never depends on these lines.
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  });

  /// One failure line with the error and its stack - listener errors and
  /// handler crashes land here. This package never calls it with a null
  /// [error].
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  });

  /// Measures and records the duration of [body] - the gauge's single home.
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  });
}

/// The log category a line is filed under - `network` for transport and
/// capacity lines, `security` for origin, token, and policy lines.
enum BridgeCategory { network, security }

/// A silent wrapper for tests and logger-less environments (mute, never drop behavior).
class SilentTelemetry extends BridgeTelemetry {
  /// Const constructor - the shared silent instance can be `const`.
  const SilentTelemetry();

  /// Drops the line - nothing is written anywhere.
  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  /// Drops the line - every security warning included, so a host running
  /// this wrapper sees none of them; the wire behavior is unchanged.
  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  /// Drops the line - nothing is written anywhere.
  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) async => await body();
}

/// The line-writing default - the telemetry a server carries when the host
/// passes none, so the security warnings (policy activations, lockouts,
/// the muted-protection notice) and the failure lines are never swallowed
/// by a missing sink. Info lines go to stdout; warn and error lines go to
/// stderr with the error and its stack appended. A host that wants the
/// lines elsewhere passes its own [BridgeTelemetry] instead - the wire
/// behavior never depends on any of these lines, exactly like
/// [SilentTelemetry] drops them without touching behavior.
class PrintTelemetry extends BridgeTelemetry {
  /// Const constructor - the class carries no state, so the shared const
  /// instance works like `const PrintTelemetry()`.
  const PrintTelemetry();

  /// The sink info lines write to - stdout, overridable in tests that
  /// capture output.
  IOSink get out => stdout;

  /// The sink warn and error lines write to - stderr, overridable in
  /// tests that capture output.
  IOSink get err => stderr;

  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    out.writeln('[bridge] $message');
  }

  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    err.writeln('[bridge warn/$category] $message');
  }

  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    err.writeln('[bridge error/$category] $message');
    if (error != null) err.writeln(error);
    if (stackTrace != null) err.writeln(stackTrace);
  }

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) async => await body();
}
