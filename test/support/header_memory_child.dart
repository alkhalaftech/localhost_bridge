// خادم قياس الذاكرة في عملية مستقلة: يربط باباً عادياً بمهلة ترويسات
// ومهلة طلب 30 ثانية ويطبع منفذه، ثم يجيب على كل سطر "rss" من مدخلاته
// بقراءة `ProcessInfo.currentRss` الحالية، و"quit" يوقفه. عملاء القياس
// يعيشون في العملية الأم حصراً فذاكرتهم لا تدخل في القراءة - وهذا هو
// المقاس كما قيس عند مراجعة الحصة: عملية خادم مستقلة تُقرأ من خارجها.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

Future<void> main() async {
  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(
      policy: const OriginPolicy(allowed: ['https://portal.example']),
      token: generateBridgeToken(),
    );
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () => 'memory-child',
    protection: protection,
    onCommand: (_) async => const CommandOutcome(ok: true),
    config: const BridgeConfig(
      headerTimeout: Duration(seconds: 30),
      requestTimeout: Duration(seconds: 30),
      idleTimeout: Duration(seconds: 60),
    ),
  );
  final port = await srv.start(preferredPort: 0);
  stdout.writeln('PORT $port');
  await stdout.flush();
  final lines = stdin.transform(utf8.decoder).transform(const LineSplitter());
  await for (final line in lines) {
    final command = line.trim();
    if (command == 'rss') {
      stdout.writeln('RSS ${ProcessInfo.currentRss}');
      await stdout.flush();
    } else if (command == 'quit') {
      break;
    }
  }
  await srv.stop();
}
