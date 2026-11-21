// مثال localhost_bridge — مضيف كامل بدارت صرفة (صفر تبعيات).
// شغّله ثم أرسل POST بـfetch من صفحة https مقبولة، أو جرّب السطر التالي
// على المنفذ المطبوع (start() يخدم المنفذ المفضل فقط إن لم يكن مشغولاً
// بغيره — الصفحة تقرأ المنفذ الذي أعاده من عنوان فتح الصفحة):
// curl -X POST -H "Origin: https://demo.example" -H "Content-Type: application/json" -d '{"data":["hello"]}' http://127.0.0.1:$PORT/
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

// سقف داخلي مسمّى لسجل العرض: القائمة عدّاد عرض تجريبي لا دفتر تنفيذ
// (للتنفيذ المضمون مرة واحدة انظر example/idempotent_handler.dart) —
// عند السقف يُسقط الأقدم إدراجاً كي لا ينمو السجل بلا حد في جلسة طويلة.
const _maxRequestLogEntries = 64;

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
    // المعالج — الجسر لا يفهم الحمولات: الأوامر نصوص ومعناها لك وحدك.
    // هذا المعالج يرفض كل ما خرج عن قائمة صغيرة (الحمولات غير موثوقة
    // دائماً)، والسجل أدناه عرض تجريبي مسقوف لا دفتر حماية.
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
      if (_requests.length >= _maxRequestLogEntries) {
        _requests.removeAt(0); // الأقدم أولاً — عرض لا حماية
      }
      _requests.add('${cmd.correlationId} from ${cmd.source}');
      return const CommandOutcome(ok: true);
    },
    telemetry: const ConsoleTelemetry(),
    correlationIdGenerator: newCorrelationId,
    handlerTimeout: const Duration(seconds: 5),
    protection: IntakeProtection(telemetry: const ConsoleTelemetry())
      ..update(
        policy: const OriginPolicy(
          // مغلق افتراضياً — هذه القائمة عقدك مع البوابات.
          allowed: ['https://demo.example'],
          allowAllHardened: false,
          // صفر يترك المدرجين بلا حصة فيظل فيض أصلٍ مدرج ممسكاً المقاعد
          // ما دامت طلباته قائمة — والقيمة الموجبة تحصره بالرمز نفسه 429.
          listedPerOriginPerMinute: 120,
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
    'served ${_requests.length} accepted commands (log capped at '
    '$_maxRequestLogEntries, oldest dropped); bye '
    '(${jsonEncode(_requests.take(3))})',
  );
}
