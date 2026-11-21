// شاهد المحاكي — pause/resume على Android: يشغّل تركيب المختبر نفسه على
// المضيف (جسر بصفحة صحة مسلحة + صفحة مختبر + مجمّع تقارير) ويطبع أوامر
// adb بالمنافذ الفعلية، ثم يقود دورة الخلفية-ثم-العودة بنفسه: يعلّق
// المستمع في يوقفه والصفحة تقرأ الفشل الحي، ويستأنفه على المنفذ نفسه
// فيقرأ الصفحة عودة الخدمة — والأحكام الثلاثة تُقرأ من تقارير الصفحة
// ويحسم PASS/INCOMPLETE بخروج واضح.
//
// لماذا أداة مستقلة؟ الإيقاف/الاستئناف سلوك دورة حياة المضيف لا المتصفح:
// الصفحة على كروم المحاكي تجسد «الخلفية ثم العودة» بمراقبة /health دورياً
// في حين تُعلّق الأداة المستمع وتُعيد ربطه على المنفذ نفسه — أمر adb
// وحيد يخفي كروم (HOME) وآخر يعيده، والمنفذ الفعلي ثابت طوال الدورة.
//
// الاستعمال حرفيا (من جذر الحزمة، والمحاكي حي وadb في PATH):
//   dart run tool/emulator_pause_resume_lab.dart \
//       --pause-after-ms 8000 --resume-after-ms 8000
// يطبع أربعة أسطر تنفيذية بالترتيب؛ نفّذها على المضيف لحظة طباعتها:
//   adb reverse tcp:<جسر> tcp:<جسر> && adb reverse tcp:<صفحة> tcp:<صفحة>
//   adb shell am start -a android.intent.action.VIEW -d "http://127.0.0.1:<صفحة>/?report=1"
//   (لحظة سطر PAUSE) adb shell input keyevent KEYCODE_HOME
//   (لحظة سطر RESUME) adb shell am start -a android.intent.action.VIEW -d "http://127.0.0.1:<صفحة>/?report=1"
// الأعلام:
//   --pause-after-ms N   مهلة قبل تعليق المستمع بعد أول نتيجة صحة حية (افتراضي 8000)
//   --resume-after-ms N  مهلة التعليق قبل الاستئناف على المنفذ نفسه (افتراضي 8000)
//   --timeout-ms N       سقف انتظار أعلام الصفحة كاملة (افتراضي 180000)
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

String _page({required int bridgePort}) =>
    '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>localhost_bridge pause/resume lab</title></head>
<body>
<pre id="lab-results"></pre>
<script>
'use strict';
const BRIDGE = 'http://127.0.0.1:$bridgePort';
const results = document.getElementById('lab-results');
const marks = [];
function mark(line) {
  if (marks.length && marks[marks.length - 1] === line) return;
  marks.push(line);
  results.textContent += line + '\\n';
}
async function report() {
  try {
    await fetch('/lab-report', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({marks: marks}),
    });
  } catch (e) {}
}
(async () => {
  mark('EMU-PAGE-ORIGIN:' + location.origin);
  setInterval(report, 700);
  for (;;) {
    let phase = 'open';
    try {
      const phaseRes = await fetch('/lab-phase');
      phase = (await phaseRes.json()).phase;
    } catch (e) {}
    let health = 'FAIL';
    try {
      const res = await fetch(BRIDGE + '/health');
      health = res.ok ? 'OK' : 'HTTP-' + res.status;
    } catch (e) {
      health = 'FAIL';
    }
    mark('PAUSE-RESUME:PHASE:' + phase + ':HEALTH:' + health);
    await new Promise(r => setTimeout(r, 400));
  }
})();
</script>
</body>
</html>
''';

int _intArg(List<String> args, String name, int fallback) {
  final i = args.indexOf(name);
  if (i < 0 || i + 1 >= args.length) return fallback;
  return int.tryParse(args[i + 1]) ?? fallback;
}

Future<void> main(List<String> args) async {
  final pauseAfterMs = _intArg(args, '--pause-after-ms', 8000);
  final resumeAfterMs = _intArg(args, '--resume-after-ms', 8000);
  final timeoutMs = _intArg(args, '--timeout-ms', 180000);

  var phase = 'open';
  final reports = <Map<String, Object?>>[];
  // التصريح قبل تسجيل مستمع صفحة المختبر: الرد يقرأ المنفذ الفعلي للجسر
  // لحظة الطلب لا لحظة التسجيل
  LocalIntakeServer? bridge;
  final pageServer = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final pagePort = pageServer.port;
  pageServer.listen((request) async {
    if (request.uri.path == '/lab-report' && request.method == 'POST') {
      final body = await utf8.decoder.bind(request).join();
      try {
        reports.add((jsonDecode(body) as Map).cast<String, Object?>());
      } on FormatException {
        reports.add(<String, Object?>{'marks': <Object?>[]});
      }
      request.response.headers.contentType = ContentType.json;
      request.response.write('{"ok":true}');
      await request.response.close();
      return;
    }
    if (request.uri.path == '/lab-phase') {
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({'phase': phase}));
      await request.response.close();
      return;
    }
    if (request.uri.path != '/') {
      request.response.statusCode = HttpStatus.notFound;
      await request.response.close();
      return;
    }
    request.response.headers.contentType = ContentType.html;
    request.response.write(_page(bridgePort: bridge!.port));
    await request.response.close();
  });

  final protection = IntakeProtection(telemetry: const SilentTelemetry());
  // أصل الصفحة المدرج حصراً وبلا حصة دقيقة: الاستطلاع الدوري (~3/ث) فوق
  // الحصة المدرجة الافتراضية فيتجيّب 429 وسط الدورة — والإدراج هو ما
  // يجعل /health تجيب الصفحة بصدى CORS فتقرأ نتيجتها
  protection.update(
    policy: OriginPolicy(
      allowed: ['http://127.0.0.1:$pagePort'],
      listedPerOriginPerMinute: 0,
    ),
  );
  bridge = LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        'emu-${DateTime.now().microsecondsSinceEpoch}',
    protection: protection,
    config: const BridgeConfig(healthPath: '/health'),
  );
  final bridgePort = await bridge.start(preferredPort: 0);
  final instanceId = bridge.instanceId;

  stdout.writeln(
    'EMULATOR-PAUSE-RESUME: the lab is up - run these on the '
    'host, in order, at the moment each line prints:',
  );
  stdout.writeln(
    '  adb reverse tcp:$bridgePort tcp:$bridgePort && '
    'adb reverse tcp:$pagePort tcp:$pagePort',
  );
  stdout.writeln(
    '  adb shell am start -a android.intent.action.VIEW '
    '-d "http://127.0.0.1:$pagePort/?report=1"',
  );
  stdout.writeln(
    'waiting for the first live health read (Ctrl+C to '
    'abort)... pause-after-ms=$pauseAfterMs resume-after-ms=$resumeAfterMs '
    'timeout-ms=$timeoutMs',
  );

  final seen = <String>{};
  void collect() {
    for (final r in reports) {
      for (final m in (r['marks'] as List? ?? const [])) {
        seen.add(m.toString());
      }
    }
  }

  // المرحلة 1: أول قراءة صحة حية من الصفحة قبل أي تعليق
  final deadline = DateTime.now().add(Duration(milliseconds: timeoutMs));
  while (!seen.contains('PAUSE-RESUME:PHASE:open:HEALTH:OK')) {
    if (DateTime.now().isAfter(deadline)) {
      stdout.writeln(
        'EMULATOR-PAUSE-RESUME: INCOMPLETE - no live health '
        'read arrived; check the adb reverse commands above',
      );
      exit(1);
    }
    await Future<void>.delayed(const Duration(milliseconds: 500));
    collect();
  }
  stdout.writeln(
    'EMULATOR-PAUSE-RESUME: the page reads the bridge live - '
    'backgrounding now: run this on the host',
  );
  stdout.writeln('  adb shell input keyevent KEYCODE_HOME');

  // المرحلة 2: تعليق المستمع - الصفحة تقرأ الفشل الحي على المنفذ نفسه
  await Future<void>.delayed(Duration(milliseconds: pauseAfterMs));
  phase = 'paused';
  await bridge.pause();
  stdout.writeln(
    'EMULATOR-PAUSE-RESUME: PAUSE - the listener is closed now (port '
    '$bridgePort remembered, instance $instanceId kept)',
  );

  // المرحلة 3: الاستئناف على المنفذ نفسه - الصفحة تقرأ عودة الخدمة
  await Future<void>.delayed(Duration(milliseconds: resumeAfterMs));
  final resumedPort = await bridge.resume();
  phase = 'resumed';
  stdout.writeln(
    'EMULATOR-PAUSE-RESUME: RESUME - listening again on port $resumedPort'
    '${resumedPort == bridgePort ? ' (the same port)' : ' (PORT MOVED - a '
              'failure)'}: bring Chrome back',
  );
  stdout.writeln(
    '  adb shell am start -a android.intent.action.VIEW '
    '-d "http://127.0.0.1:$pagePort/?report=1"',
  );

  const wanted = <String>[
    'PAUSE-RESUME:PHASE:open:HEALTH:OK',
    'PAUSE-RESUME:PHASE:paused:HEALTH:FAIL',
    'PAUSE-RESUME:PHASE:resumed:HEALTH:OK',
  ];
  var pass = false;
  while (DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 500));
    collect();
    pass = wanted.every(seen.contains);
    if (pass) break;
  }
  await bridge.stop();
  await pageServer.close(force: true);
  if (pass) {
    stdout.writeln(
      'EMULATOR-PAUSE-RESUME: PASS - the page read the live bridge, the '
      'paused refusal (connection refused), and the resumed service on '
      'the same port, with the instance id kept',
    );
    exit(0);
  }
  stdout.writeln(
    'EMULATOR-PAUSE-RESUME: INCOMPLETE - the three marks did not all '
    'arrive; seen=${seen.where((m) => m.startsWith('PAUSE-RESUME:')).take(10).toList()}',
  );
  exit(1);
}
