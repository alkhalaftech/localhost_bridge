/// The measurement and logging seam.
///
/// The host adapts AppLogger over this interface, keeping the intake latency
/// gauge (via measure), the RSS delta, classification, and stacks alive -
/// where a plain string typedef would have dropped them all.
abstract class BridgeTelemetry {
  const BridgeTelemetry();

  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  });
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  });
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

enum BridgeCategory { network, security }

/// A silent wrapper for tests and logger-less environments (mute, never drop behavior).
class SilentTelemetry extends BridgeTelemetry {
  const SilentTelemetry();

  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

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
