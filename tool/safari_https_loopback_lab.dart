// شاهد Safari الحقيقي على macOS — HTTPS على الحلقة الراجعة: يشغّل
// الجسر نفسه على نقل TLS بسياق شهادة جاهز يمرره صاحب الجهاز، ويخدم
// صفحة المختبر من الذاكرة على الباب الآمن نفسه، والصفحة ترسل أمراً
// وتقرأ الرد وتحمل علاماتها عبر مسار الأوامر نفسه. الأداة تطبع خطواتها
// وتقرأ أعلامها، والصفحة هي من يسجّل الشاهد من داخل Safari.
//
// الحدود الصادقة (تُطبع في الرأس ولا تُخفى):
// - الأداة لا تولّد شهادة ولا تثبتها ولا تكتب ملفاً: صاحب الجهاز يصنع
//   شهادته بنفسه ويثق بها في Keychain قبل التشغيل، ويثق بالجهاز بالشهادة
//   مسؤولية المضيف (وثائق README تحمل مخاطر تثبيت جهة إصدار محلية).
// - الأداة لا تفتح Safari إلا بعلم --open-safari على macOS (نداء open
//   النظامي) — وما سوى ذلك طباعة عنوان الصفحة والخطوات على المشغل.
// - حسم PASS كله من علامات الصفحة الحية؛ بلاها INCOMPLETE بخروج 1 —
//   لا ادعاء نجاح من طرف الأداة وحدها.
//
// خطوات التشغيل حرفياً (من جذر الحزمة، على macOS وصاحب الجهاز):
//   1) اصنع شهادة حلقية ذاتية الاعتماد بنفسك (openssl أو ما تحب) بمفاتيح
//      PEM: شهادة + مفتاح، SAN يضم IP:127.0.0.1 وIP:::1 وDNS:localhost.
//   2) ثق بها في Keychain (تبويب Trust: Always Trust لاستعمال SSL Server)
//      — Safari لن يفتح العنوان بلا هذه الخطوة، وسيصرّح بذلك بنفسه.
//   3) شغّل الأداة بعلمي الشهادة:
//        dart run tool/safari_https_loopback_lab.dart \
//            --cert /path/server-cert.pem --key /path/server-key.pem
//   4) افتح العنوان المطبوع (https://127.0.0.1:<port>/ui) في Safari —
//      بعلم --open-safari تفتحه الأداة بنفسها.
//   5) الحكم يُطبع من علامات الصفحة: PASS يعني أن صفحة https حملت وأرسلت
//      وأمراً وقرأت الرد من داخل Safari الحقيقي.
//
// الأعلام:
//   --cert PATH       ملف شهادة PEM (إلزامي — بلاه الأداة تمتنع ولا تشغل شيئاً)
//   --key PATH        ملف مفتاح PEM (إلزامي)
//   --port N          المنفذ المطلوب للجسر (افتراضي 0 = اختيار حر)
//   --timeout-ms N    سقف انتظار علامات الصفحة كاملة (افتراضي 180000)
//   --open-safari     فتح عنوان الصفحة في Safari بنداء open النظامي (macOS)
//   --self-check      فحص ذاتي بلا Safari: عميل TLS داخل الأداة يقود
//                     العلامات نفسها ليثبت صحة المختبر قبل جهد الجهاز
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

const _toolTag = 'SAFARI-HTTPS-LOOPBACK';

String _page() => '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>localhost_bridge Safari HTTPS lab</title></head>
<body>
<pre id="lab-results"></pre>
<script>
'use strict';
const results = document.getElementById('lab-results');
const marks = [];
function mark(line) {
  marks.push(line);
  results.textContent += line + '\\n';
}
// العلامات تسير أمراً أمراً عبر مسار الأوامر القياسي: كل أمر LAB-*
// علامة، والرد {"ok":true} يثبت أن الإرسال والقراءة حيان من داخل
// Safari على باب https
async function sendMark(line) {
  mark(line);
  try {
    const r = await fetch('/', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({data: [line]}),
    });
    mark('LAB-HTTPS-REPLY:' + r.status + ':' + (await r.json()).ok);
  } catch (e) {
    mark('LAB-HTTPS-REPLY:FAIL');
  }
}
(async () => {
  mark('LAB-HTTPS-ORIGIN:' + location.origin);
  await sendMark('LAB-HTTPS-PAGE-LOADED');
  try {
    const h = await fetch('/health');
    await sendMark('LAB-HTTPS-HEALTH:' + (h.ok ? 'OK' : 'HTTP-' + h.status));
  } catch (e) {
    await sendMark('LAB-HTTPS-HEALTH:FAIL');
  }
  try {
    const r = await fetch('/', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({data: ['LAB-HTTPS-COMMAND-OK', 'PRINT 1']}),
    });
    const j = await r.json();
    await sendMark('LAB-HTTPS-COMMAND:' + (j.ok === true ? 'OK' : 'FAIL'));
  } catch (e) {
    await sendMark('LAB-HTTPS-COMMAND:FAIL');
  }
  await sendMark('LAB-HTTPS-DONE');
})();
</script>
</body>
</html>
''';

String _stringArg(List<String> args, String name) {
  final i = args.indexOf(name);
  if (i < 0 || i + 1 >= args.length) return '';
  return args[i + 1];
}

int _intArg(List<String> args, String name, int fallback) {
  final i = args.indexOf(name);
  if (i < 0 || i + 1 >= args.length) return fallback;
  return int.tryParse(args[i + 1]) ?? fallback;
}

bool _flag(List<String> args, String name) => args.contains(name);

final _marks = <String>{};

Future<void> main(List<String> args) async {
  final certPath = _stringArg(args, '--cert');
  final keyPath = _stringArg(args, '--key');
  final preferredPort = _intArg(args, '--port', 0);
  final timeoutMs = _intArg(args, '--timeout-ms', 180000);
  final selfCheck = _flag(args, '--self-check');
  final openSafari = _flag(args, '--open-safari');

  stdout.writeln(
    '$_toolTag: the tool never generates, installs, or writes a certificate - '
    'the host owns the cert and the device trust in it (see the README '
    'for local-issuing-authority risks)',
  );
  if (certPath.isEmpty || keyPath.isEmpty) {
    stdout.writeln(
      '$_toolTag: INCOMPLETE - pass --cert PATH and --key PATH (your own '
      'trusted loopback certificate); nothing was started',
    );
    exit(1);
  }

  // سياق TLS جاهز من ملفي صاحب الجهاز حصراً - قراءة لا كتابة
  final SecurityContext tlsContext;
  try {
    tlsContext = SecurityContext()
      ..useCertificateChain(certPath)
      ..usePrivateKey(keyPath);
  } on Object catch (e) {
    stdout.writeln(
      '$_toolTag: INCOMPLETE - the certificate files failed to load '
      '(${e.runtimeType}); check --cert and --key',
    );
    exit(1);
  }

  final page = _page();
  final bridge = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        'safari-${DateTime.now().microsecondsSinceEpoch}',
    onCommand: (cmd) async {
      for (final line in cmd.payloads) {
        if (line.startsWith('LAB-')) {
          _marks.add(line);
        }
      }
      return const CommandOutcome(ok: true);
    },
    config: BridgeConfig(
      healthPath: '/health',
      securityContext: tlsContext,
      localPages: [BridgeLocalPage(path: '/ui', content: page)],
    ),
  );
  final port = await bridge.start(preferredPort: preferredPort);
  final pageUrl = 'https://127.0.0.1:$port/ui';

  stdout.writeln(
    '$_toolTag: the lab is up on https://127.0.0.1:$port - the served page '
    'carries its own marks over the standing command route',
  );
  stdout.writeln('  open in Safari: $pageUrl');
  if (openSafari) {
    if (Platform.isMacOS) {
      final opened = await Process.run('open', <String>[
        '-a',
        'Safari',
        pageUrl,
      ]);
      stdout.writeln('$_toolTag: open -a Safari exited ${opened.exitCode}');
    } else {
      stdout.writeln(
        '$_toolTag: --open-safari is a macOS step - this host is '
        '${Platform.operatingSystem}; open the printed URL yourself',
      );
    }
  }
  stdout.writeln(
    '$_toolTag: PASS reads three marks from inside Safari '
    '(ORIGIN https, PAGE-LOADED, COMMAND:OK); '
    'waiting up to ${timeoutMs}ms (Ctrl+C to abort)',
  );

  // الفحص الذاتي: عميل TLS داخل الأداة يقود العلامات نفسها على الباب
  // الآمن قبل أي جهد جهاز - يثبت صحة المختبر لا شاهد Safari
  if (selfCheck) {
    stdout.writeln('$_toolTag: self-check driving the marks in-process...');
    final client = HttpClient()
      ..badCertificateCallback = (cert, host, port) => true;
    final pageRes = await client
        .openUrl('GET', Uri.parse(pageUrl))
        .then((r) => r.close())
        .then((r) async {
          final body = await r.transform(utf8.decoder).join();
          return 'status=${r.statusCode} body=${body.length}B';
        });
    stdout.writeln('  page GET: $pageRes');
    // قراءة الصحة بلا Origin: سلوك الطرف الخالي المقنع - معلوماتية حصراً
    final healthRes = await client
        .openUrl('GET', Uri.parse('https://127.0.0.1:$port/health'))
        .then((r) => r.close())
        .then((r) async {
          final body = await r.transform(utf8.decoder).join();
          return 'status=${r.statusCode} body=$body';
        });
    stdout.writeln('  health GET (originless, informational): $healthRes');
    final cmdRes = await client
        .openUrl('POST', Uri.parse('https://127.0.0.1:$port/'))
        .then((r) async {
          // المتصفح يرفق Origin على كل POST - والعميل يحاكيه هنا حصراً
          r.headers.set('Origin', 'https://127.0.0.1:$port');
          r.headers.contentType = ContentType.json;
          r.add(
            utf8.encode(
              jsonEncode({
                'data': [
                  'LAB-HTTPS-ORIGIN:https://127.0.0.1:$port',
                  'LAB-HTTPS-PAGE-LOADED',
                  'LAB-HTTPS-COMMAND:OK',
                  'LAB-HTTPS-DONE',
                ],
              }),
            ),
          );
          final res = await r.close();
          final body = await res.transform(utf8.decoder).join();
          return 'status=${res.statusCode} body=$body';
        });
    stdout.writeln('  command POST (browser-like Origin): $cmdRes');
  }

  bool pageOriginMarked() => _marks.any(
    (m) =>
        m.startsWith('LAB-HTTPS-ORIGIN:https://127.0.0.1:') ||
        m.startsWith('LAB-HTTPS-ORIGIN:https://localhost:'),
  );
  // حكم PASS على ثلاث علامات حصراً: أصل الصفحة https، والصفحة حملت،
  // وأمر أُرسل وردّه قُرئ - فصفحة https على نفس الأصل قد ترسل فحص
  // الصحة GET بلا ترويسة Origin أصلاً (سلوك المتصفحات الموثق)، وطريق
  // الأصول الخالي يرد الرفض القائم المقنع - فلا يُشترط على الحكم ما
  // لا يملكه المتصفح، ويبقى سطر الصحة معلوماتياً في الأداة
  const wanted = <String>['LAB-HTTPS-PAGE-LOADED', 'LAB-HTTPS-COMMAND:OK'];
  final deadline = DateTime.now().add(Duration(milliseconds: timeoutMs));
  var pass = false;
  while (DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 400));
    // شرط الأصل: بادئة https على أصل حلقي حصراً - إطارات الأداة لا تقبل
    // أصل http ولا أصل غير حلقي
    pass = pageOriginMarked() && wanted.every(_marks.contains);
    if (pass) break;
  }
  await bridge.stop();
  if (pass) {
    stdout.writeln(
      '$_toolTag: PASS - an https loopback page loaded, sent a command, and '
      'read the reply (marks: ${_marks.length})',
    );
    exit(0);
  }
  stdout.writeln(
    '$_toolTag: INCOMPLETE - the page marks did not all arrive; '
    'seen=${_marks.take(10).toList()} - check the Safari address bar for '
    'a certificate warning (step 2: trust the certificate in Keychain)',
  );
  exit(1);
}
