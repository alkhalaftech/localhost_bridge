// أمر التجربة: جسر حي بسياسة «توكن فقط» خلال دقيقة من سطر الأوامر.
// يولّد توكنه بنفسه ويطبعه مع المنفذ وسطر أمر حقيقي جاهز وطريقة الإيقاف،
// فيجرّب المضيف الحزمة دون أن يكتب سطر إعداد واحد. الحكم صارم: لا يفتح
// allow-all ولا يسلح الاكتشاف، ولا يقبل وسيطاً يفتحهما — كل وسيط يجاوز
// --port يُرفض رفضاً صاخباً قبل أي ربط، فأمر التجربة يبقى على أضيق
// أبواب الحزمة مهما مرّر إليه من يستدعيه.

import 'dart:async';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

/// The demo's only option: the preferred port (`--port 9100`). Any other
/// argument - and any flag that would open allow-all or discovery among
/// them - refuses loudly before anything binds: the demo stays on the
/// token-only preset whatever the caller passes.
///
/// Returns the preferred port, or null for the automatic (ephemeral) one.
int? parseDemoPort(List<String> args) {
  if (args.isEmpty) return null;
  final arg = args.first;
  if (arg != '--port') {
    // كل وسيط آخر رفض صاخب — لا خيار يفتح أبواباً هنا إطلاقاً
    throw ArgumentError(
      'unknown argument "$arg": the demo serves the token-only preset '
      '(a generated token is the only door) and never opens allow-all '
      'or discovery; the only option it accepts is --port <n>',
    );
  }
  if (args.length < 2) {
    throw ArgumentError(
      '--port needs a numeric value; the demo serves the token-only '
      'preset and accepts only --port <n>',
    );
  }
  final value = int.tryParse(args[1]);
  if (value == null || value < 0 || value > 65535) {
    throw ArgumentError(
      '--port needs a port number between 0 and 65535; the demo '
      'serves the token-only preset and accepts only --port <n>',
    );
  }
  if (args.length > 2) {
    throw ArgumentError(
      'unknown argument "${args[2]}": the demo serves the token-only '
      'preset and accepts only --port <n>',
    );
  }
  return value;
}

Future<void> main(List<String> args) async {
  final int? preferredPort;
  try {
    preferredPort = parseDemoPort(args);
  } on ArgumentError catch (e) {
    // الرفض الصاخب: على stderr وبرمز خروج لا صمت
    stderr.writeln('bridge_demo: ${e.message}');
    exitCode = 64;
    return;
  }

  final token = generateBridgeToken();
  final server = LocalIntakeServer(
    // معالج التجربة: يرد الأوامر كما وردت في data، فيرى المجرّب
    // الرحلة كاملة على السلك الحي
    onCommand: (cmd) async => CommandOutcome(ok: true, data: cmd.payloads),
    protection: BridgePresets.tokenOnly(
      token: token,
      // نفس مخرج الخادم الافتراضي: التحذيرات الأمنية تُطبع لا تُكتم
      telemetry: const PrintTelemetry(),
    ),
  );

  final int port;
  try {
    port = await server.start(preferredPort: preferredPort ?? 0);
  } catch (e) {
    stderr.writeln('bridge_demo: the bridge could not start: $e');
    exitCode = 66;
    return;
  }

  stdout.writeln('localhost_bridge demo - the token-only preset');
  stdout.writeln('token: $token');
  stdout.writeln('port: $port');
  stdout.writeln('try it (a real command over the live bridge):');
  stdout.writeln(
    '  curl -X POST http://127.0.0.1:$port/ '
    '-H "Content-Type: application/json" '
    '-H "X-Bridge-Token: $token" '
    '-d \'{"data":["ping"]}\'',
  );
  stdout.writeln('stop: press Ctrl+C (the listener drains and closes cleanly)');
  stdout.writeln('waiting for commands ...');

  // الإيقاف النظيف: SIGINT يصرّف الفراغ الرشيق نفسه الذي يديره stop —
  // sigint قابل للمراقبة على ويندوز أيضاً (sigterm هو غير المتاح هناك)،
  // ودون مراقبة ناجحة يبقى Ctrl+C يقتل العملية كما تعرفها المنصة
  StreamSubscription<ProcessSignal>? sigint;
  try {
    sigint = ProcessSignal.sigint.watch().listen((_) async {
      sigint?.cancel();
      await server.stop();
      exit(0);
    });
  } on SignalException {
    // المنصة لا تسمح بمراقبة الإشارة: الإيقاف يبقى ممكناً بأدواتها
  }

  // عزل اشتراك الإشارة عن أخطاء المتقدم: خطأ في قناة الإشارة لا يسقط
  // الجسر الذي يخدم
  await sigint?.asFuture<void>().catchError((_) {});
}
