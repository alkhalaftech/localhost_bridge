// localhost_bridge example - a complete host in pure Dart (zero deps).
// Run it, then send a fetch POST from any admitted https page, or try:
// curl -X POST -H "Origin: https://demo.example" -H "Content-Type: application/json" -d '{"data":["hello"]}' http://127.0.0.1:9100/
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:localhost_bridge/localhost_bridge.dart';

/// A v4-style correlation id from Random.secure - no package needed.
String newCorrelationId() {
  final rnd = Random.secure();
  final b = List<int>.generate(16, (_) => rnd.nextInt(256));
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant
  final h = b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  return '${h.substring(0, 8)}-${h.substring(8, 12)}-'
      '${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}';
}

/// A quick local gauge with no external logger - swap in your real one for production.
final _requests = <String>[];

class ConsoleTelemetry extends BridgeTelemetry {
  const ConsoleTelemetry();

  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    stdout.writeln('[info/$category] $message');
  }

  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    stdout.writeln('[warn/$category] $message');
  }

  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    stderr.writeln('[error/$category] $message ($error)');
  }

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) async {
    final sw = Stopwatch()..start();
    try {
      return await body();
    } finally {
      stdout.writeln('[measure] $label ${sw.elapsedMilliseconds}ms');
    }
  }
}

void main() async {
  final server = LocalIntakeServer(
    // The handler - the bridge is payload-agnostic: commands are strings,
    // their meaning is yours alone. This one refuses anything outside a
    // small allowlist (payloads are always untrusted).
    onCommand: (cmd) async {
      const allowed = {'PING', 'HELLO'};
      for (final payload in cmd.payloads) {
        final command = payload.trim().toUpperCase();
        if (!allowed.contains(command)) {
          return const CommandOutcome(
            ok: false,
            errorCode: 'unknown_command',
            errorMessage: 'only PING and HELLO are accepted here',
          );
        }
      }
      _requests.add('${cmd.correlationId} from ${cmd.source}');
      return const CommandOutcome(ok: true);
    },
    telemetry: const ConsoleTelemetry(),
    correlationIdGenerator: newCorrelationId,
    handlerTimeout: const Duration(seconds: 5),
    protection: IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          // Closed by default - this list is your contract with the gates.
          allowed: ['https://demo.example'],
          allowAllHardened: false,
        ),
      ),
  );

  final port = await server.start(preferredPort: 9100);
  stdout
    ..writeln('localhost_bridge example — listening on http://127.0.0.1:$port')
    ..writeln(
      'try: curl -X POST -H "Origin: https://demo.example" '
      '-H "Content-Type: application/json" '
      '-d \'{"data":["HELLO"]}\' http://127.0.0.1:$port/',
    )
    ..writeln('unknown origins are rejected with a stable error code');

  await ProcessSignal.sigint.watch().first;
  await server.stop();
  stdout.writeln(
    'served ${_requests.length} accepted commands; bye '
    '(${jsonEncode(_requests.take(3))})',
  );
}
