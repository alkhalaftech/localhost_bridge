// مختبر المتصفح الحقيقي: كروم/كروميوم النظامي بلا واجهة يثبت سيناريوهات
// ما قبل الاقتران من داخل متصفح فعلٍ — صفحة بالتوكن القائم ترسل أمراً
// وتقرأ الرد، وصفحة بلا اعتراف لا ترى حكماً مقروءاً بينما السلك يحمل الرمز
// الحرفي، والpreflight يعلن ترويسة التوكن بالاسم الجديد وحده.
// صفر اعتماديات: المتصفح هو ما لدى الجهاز من Chrome/Chromium (وBRIDGE_BROWSER
// تجاوز صريح للمسار)، وبلا متصفح يتخطى المختبر نفسه كله ويسبّب التخطي بدل
// أن يتظاهر بالنجاح.
//
// طريقة الإطلاق من المصادر الرسمية للمتصفح:
// - developer.chrome.com/docs/chromium/headless — الوضع بلا واجهة موحّد
//   مع الوضعي منذ Chrome 112، والعلم --headless.
// - developer.chrome.com/docs/automation-and-testing/headless-cli —
//   --dump-dom يطبع DOM الصفحة المتسلسل إلى stdout بعد تنفيذ سكربتاتها،
//   و--virtual-time-budget يقدّم الزمن الافتراضي حتى ينفد كي تُلتقط الصفحة
//   بعد عملها غير المتزامن، و--timeout سقف انتظار حقيقي قبل الالتقاط.
// - github.com/actions/runner-images (Ubuntu2404-Readme.md) — صورة
//   ubuntu-latest تحمل Google Chrome وChromium مثبتين، وعليها تشغّل
//   وظيفة CI المختبرَ فعلياً.
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

final (String?, String?, int?) _labBrowser = _discoverBrowser();

/// مسار المتصفح المكتشف، أو null إن لم يوجد — حينها كل الاختبارات تتخطى
final String? _browserPath = _labBrowser.$1;

/// سبب التخطي الصادق، أو null إن وُجد متصفح فيعمل الاختبار فعلاً
final String? _skipReason = _labBrowser.$2;

/// رقم الإصدار الأكبر للمتصفح المكتشف إن قرأ — سيناريو Local Network
/// Access يحتاج علم محاكاة الفضاء الذي وُلد بعد M146
final int? _browserMajor = _labBrowser.$3;

/// Locates a real Chrome/Chromium for the lab: the BRIDGE_BROWSER override
/// first, then PATH, then the standard install locations. Returns the
/// path, the honest skip reason when nothing is found, and the browser's
/// major version when it can be read (the Local Network Access scenario
/// needs the address-space override flag born after M146).
(String?, String?, int?) _discoverBrowser() {
  int? majorOf(String path) {
    try {
      final out = Process.runSync(path, const ['--version']);
      final m = RegExp(r'(\d+)\.').firstMatch(out.stdout as String);
      return m == null ? null : int.tryParse(m.group(1)!);
    } on Object {
      return null;
    }
  }

  final override = Platform.environment['BRIDGE_BROWSER']?.trim();
  if (override != null && override.isNotEmpty) {
    if (File(override).existsSync()) return (override, null, majorOf(override));
    return (
      null,
      'BRIDGE_BROWSER="$override" does not exist on this host - the lab '
          'needs a real Chrome/Chromium executable at that path',
      null,
    );
  }
  // البحث في PATH: الأسماء المعتادة، وباللاحقة التنفيذية على ويندوز
  final names = Platform.isWindows
      ? <String>['google-chrome.exe', 'chrome.exe', 'chromium.exe']
      : <String>[
          'google-chrome',
          'google-chrome-stable',
          'chromium',
          'chromium-browser',
        ];
  final pathEnv = Platform.environment['PATH'] ?? '';
  for (final dir in pathEnv.split(Platform.isWindows ? ';' : ':')) {
    if (dir.trim().isEmpty) continue;
    for (final name in names) {
      final candidate = '$dir${Platform.pathSeparator}$name';
      if (File(candidate).existsSync()) {
        return (candidate, null, majorOf(candidate));
      }
    }
  }
  // المواضع القياسية للتثبيت حين لا يكون المتصفح على PATH
  final localAppData = Platform.environment['LOCALAPPDATA'];
  final programFiles = Platform.environment['PROGRAMFILES'];
  final programFilesX86 = Platform.environment['PROGRAMFILES(X86)'];
  final wellKnown = <String>[
    if (Platform.isWindows) ...[
      if (programFiles != null)
        '$programFiles\\Google\\Chrome\\Application\\chrome.exe',
      if (programFilesX86 != null)
        '$programFilesX86\\Google\\Chrome\\Application\\chrome.exe',
      if (localAppData != null)
        '$localAppData\\Google\\Chrome\\Application\\chrome.exe',
      if (programFiles != null)
        '$programFiles\\Chromium\\Application\\chrome.exe',
      if (localAppData != null)
        '$localAppData\\Chromium\\Application\\chrome.exe',
    ],
    if (Platform.isMacOS) ...[
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
    ],
    if (Platform.isLinux) ...[
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
      '/snap/bin/chromium',
    ],
  ];
  for (final candidate in wellKnown) {
    if (File(candidate).existsSync()) {
      return (candidate, null, majorOf(candidate));
    }
  }
  return (
    null,
    'no Chrome/Chromium on this host (searched PATH and the standard '
        'install locations; set BRIDGE_BROWSER to the browser path to run '
        'here) - the lab then runs where a system browser exists, such as '
        'the CI browser-lab job whose image ships Google Chrome',
    null,
  );
}

/// The lab page: one canonical page served from a real page origin on
/// 127.0.0.1 (a different origin than the bridge - the ports differ), so
/// every call crosses real CORS machinery. Each scenario block writes a
/// single `LAB-*` verdict line into the page DOM; the dumped DOM is the
/// evidence the tests assert on.
String _labPage({
  required int admittedBridgePort,
  required int defaultBridgePort,
  required String token,
}) =>
    '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>localhost_bridge browser lab</title></head>
<body>
<pre id="lab-results"></pre>
<script>
'use strict';
const ADMITTED_BRIDGE = 'http://127.0.0.1:$admittedBridgePort';
const DEFAULT_BRIDGE = 'http://127.0.0.1:$defaultBridgePort';
const TOKEN = '$token';
const results = document.getElementById('lab-results');
function mark(line) { results.textContent += line + '\\n'; }

async function postJson(bridge, extraHeaders) {
  const headers = Object.assign({'Content-Type': 'application/json'},
                                extraHeaders);
  return fetch(bridge, {method: 'POST', headers, body: '["BROWSER-LAB"]'});
}

(async () => {
  mark('LAB-PAGE-ORIGIN:' + location.origin);
  // Scenario 1: the tokened page. Content-Type application/json plus
  // X-Bridge-Token make the browser preflight first, so a readable verdict
  // here is only reachable if that preflight crossed.
  try {
    const res = await postJson(ADMITTED_BRIDGE, {
      'X-Bridge-Token': TOKEN,
      'X-Correlation-Id': 'lab-tokened-1',
    });
    const body = await res.json().catch(() => null);
    mark('LAB-TOKENED:' + res.status + ':' +
         (body && body.ok === true ? 'true' : 'false') + ':' +
         (body && body.error ? body.error : 'no-error'));
  } catch (browserError) {
    mark('LAB-TOKENED:THREW');
  }
  // Scenario 3, browser side: the preflight endpoint itself answers an
  // OPTIONS round trip from the page origin.
  try {
    const res = await fetch(ADMITTED_BRIDGE,
                            {method: 'OPTIONS', mode: 'cors'});
    mark('LAB-OPTIONS:' + res.status + ':' + res.type);
  } catch (browserError) {
    mark('LAB-OPTIONS:THREW');
  }
  // Scenario 3, negative control: a request header the bridge never
  // allows must make the browser itself fail the preflighted call - if
  // this line ever reports a status, the browser did not really consult
  // the preflight.
  try {
    const res = await postJson(ADMITTED_BRIDGE, {'X-Lab-NotAllowed': '1'});
    mark('LAB-NOPREFLIGHT:' + res.status);
  } catch (browserError) {
    mark('LAB-NOPREFLIGHT:BLOCKED-BY-PREFLIGHT');
  }
  // Scenario 2, browser side: the unpaired page against the default
  // bridge. The refusal carries no CORS echo, so the browser shows no
  // verdict at all - that is the designed unreadable refusal, and a
  // readable verdict here would be a regression the lab must catch.
  try {
    const res = await postJson(DEFAULT_BRIDGE, {});
    let body = null;
    try { body = await res.json(); } catch (e) {}
    mark('LAB-UNPAIRED:READ:' + res.status + ':' +
         (body && body.error ? body.error : 'unreadable'));
  } catch (browserError) {
    mark('LAB-UNPAIRED:BLOCKED-NO-VERDICT');
  }
})();
</script>
</body>
</html>
''';

var _labIdSeq = 0;

/// The lab's correlation ids: short, distinct, honest to the wire contract
String _labCorrelationId() => 'lab-${_labIdSeq++}';

/// Starts a bridge on an ephemeral loopback port; when [token] is given it
/// is set as the accepted token alongside the listed [allowedOrigin].
Future<(LocalIntakeServer, int)> _startBridge({
  String? allowedOrigin,
  String? token,
}) async {
  final protection = IntakeProtection(telemetry: const SilentTelemetry());
  protection.update(
    policy: OriginPolicy(allowed: [?allowedOrigin]),
    token: token,
  );
  final bridge = LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: _labCorrelationId,
    protection: protection,
  );
  final port = await bridge.start(preferredPort: 0);
  return (bridge, port);
}

/// The dumped DOM with CRLF endings normalized, so marker assertions match
/// the rendered verdict lines (each ends with a newline) and never the
/// literal marker text inside the page's own script source
String _flat(String dom) => dom.replaceAll('\r\n', '\n');

/// Drives the real browser headlessly over the lab page and returns the
/// dumped DOM: scripts run, virtual time advances the page's async work,
/// then the serialized DOM is printed to stdout. When BRIDGE_LAB_EVIDENCE_DIR
/// is set, the full dump is also written there verbatim (one file per call).
Future<String> _dumpDom(
  String url,
  String evidenceFile, {
  List<String> extraArgs = const [],
}) async {
  final userDataDir = await Directory.systemTemp.createTemp(
    'bridge-browser-lab-',
  );
  try {
    final result = await Process.run(
      _browserPath!,
      <String>[
        '--headless',
        // بلا واجهة لا سياق رسومي مطلوب — أعلم صريح كي لا يعلق إقلاع GPU
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-extensions',
        // إعدادات مستخدم فارغة حديثة: لا تفضيلات سابقة تقرأ في الحكم
        '--user-data-dir=${userDataDir.path}',
        // ثبات معروف على لينكس في الحاويات: ذاكرة مشتركة صغيرة تعطل الجلسة
        '--disable-dev-shm-usage',
        ...extraArgs,
        // الوثائق الرسمية (انظر ترويسة الملف)
        '--dump-dom',
        '--virtual-time-budget=20000',
        '--timeout=30000',
        url,
      ],
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    ).timeout(const Duration(seconds: 90));
    final dom = result.stdout as String;
    if (result.exitCode != 0) {
      final err = (result.stderr as String).trim();
      fail(
        'headless browser exited ${result.exitCode}; stderr: '
        '${err.length > 400 ? err.substring(0, 400) : err}',
      );
    }
    final evidenceDir = Platform.environment['BRIDGE_LAB_EVIDENCE_DIR'];
    if (evidenceDir != null && evidenceDir.trim().isNotEmpty) {
      // الدليل يُبنى إن لم يوجد (recursive) — مطلب الدليل لا يُسقط
      // إثبات المتصفح بفشل مسار
      Directory(evidenceDir).createSync(recursive: true);
      File('$evidenceDir/$evidenceFile').writeAsStringSync(dom);
    }
    return dom;
  } finally {
    // ملف المستخدم المؤقت يُحذف بأفضل جهد وانتظار كامل: الحذف غير
    // المنتظر يجعل خطأه يتيماً على المعزل فيُلصق باختبار عشوائي،
    // والمتصفح على ويندوز قد يمسك مقبضاً متأخراً لحظة الحذف (Access
    // denied) — انتظار قصير ثم محاولة ثانية منتظرة، وبقايا النظام
    // المؤقت مقصودة إن فشلت الاثنتان
    try {
      await userDataDir.delete(recursive: true);
    } on IOException {
      try {
        await Future<void>.delayed(const Duration(milliseconds: 250));
        await userDataDir.delete(recursive: true);
      } on IOException {
        // بقايا مقصودة في مجلد النظام المؤقت
      }
    }
  }
}

/// A completed wire exchange as the test reads it: status, body text, and
/// the response headers (names lowercased by HttpClient).
typedef _Exchange = (int status, String body, Map<String, String> headers);

Future<_Exchange> _send(
  int port, {
  String method = 'POST',
  String? origin,
  Map<String, String> headers = const {},
  String body = '["BROWSER-LAB"]',
}) async {
  final client = HttpClient();
  try {
    final request = await client.openUrl(
      method,
      Uri.parse('http://127.0.0.1:$port/'),
    );
    if (origin != null) request.headers.set('Origin', origin);
    headers.forEach(request.headers.set);
    if (method == 'POST') {
      request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      request.headers.set('Sec-Fetch-Mode', 'cors');
      request.headers.set('Sec-Fetch-Dest', 'empty');
      request.add(utf8.encode(body));
    }
    final response = await request.close().timeout(const Duration(seconds: 8));
    final text = await utf8.decoder.bind(response).join();
    final flat = <String, String>{};
    response.headers.forEach((name, values) {
      flat[name.toLowerCase()] = values.join(', ');
    });
    return (response.statusCode, text, flat);
  } finally {
    client.close(force: true);
  }
}

void main() {
  // الحاوية المشتركة: صفحة من أصل حقيقي + جسر مقبول + جسر افتراضي (لا
  // قائمة ولا توكن) — سيناريوهات المختبر الثلاثة كلها على الصفحة نفسها،
  // وكل اختبار يصحح علامات سيناريوه هو وحده. بوضع [tokenOnlyAdmitted]
  // يُبنى الجسر المقبول بالتوكن وحده بلا قائمة: مسار التوكن هو الباب
  // الوحيد على السلك، والصفحة لا تستطيع عبوره أصلاً (لا صدى يُجاب
  // في هذا الوضع بالعقد الموثق) فالشاهد يثبت الوجهين.
  Future<
    (HttpServer, LocalIntakeServer, LocalIntakeServer, int, int, int, String)
  >
  lab({bool tokenOnlyAdmitted = false}) async {
    final token = generateBridgeToken();
    // الجسر المقبول يُبنى على أصل الصفحة قبل أن تُخدم الصفحة: المنفذ
    // المعمى في HTML يحتاج منافذ الجسور جاهزة أولاً
    final pageServer = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final (admitted, admittedPort) = await _startBridge(
      allowedOrigin: tokenOnlyAdmitted
          ? null
          : 'http://127.0.0.1:${pageServer.port}',
      token: token,
    );
    final (defaultBridge, defaultPort) = await _startBridge();
    final html = _labPage(
      admittedBridgePort: admittedPort,
      defaultBridgePort: defaultPort,
      token: token,
    );
    pageServer.listen((request) async {
      if (request.uri.path != '/') {
        request.response.statusCode = HttpStatus.notFound;
        await request.response.close();
        return;
      }
      request.response.headers.contentType = ContentType.html;
      request.response.write(html);
      await request.response.close();
    });
    return (
      pageServer,
      admitted,
      defaultBridge,
      pageServer.port,
      admittedPort,
      defaultPort,
      token,
    );
  }

  test('the token scenario runs on a token-only bridge: the token is the '
      'only wire door, and the browser page cannot cross it (nothing is '
      'echoed)', () async {
    // جسر السيناريو بوضع «توكن فقط»: أصل الصفحة غير مدرج فالعبور على
    // السلك يحتاج التوكن حصراً — وبدونه أو بخاطئ لا باب. الصفحة
    // المتصفحية لا تستطيع العبور أصلاً في هذا الوضع بالعقد الموثق
    // (لا صدى يُجاب فالمتصفح يحجب) — فهذا ما يثبته السطر أيضاً،
    // والتوكن يبقى طريق المرسل غير المتصفحي هنا
    final (pageServer, admitted, _, pagePort, admittedPort, _, token) =
        await lab(tokenOnlyAdmitted: true);
    addTearDown(pageServer.close);
    addTearDown(admitted.stop);
    final dom = _flat(
      await _dumpDom(
        'http://127.0.0.1:$pagePort/',
        'j121-scenario1-tokened-dom.txt',
      ),
    );
    expect(
      dom,
      contains('LAB-TOKENED:THREW\n'),
      reason:
          'a token-only bridge echoes nothing, so the browser blocks '
          'the tokened call - the token stays a non-browser path here '
          'exactly as the contract states',
    );
    // السلك من طرف الاختبار: التوكن هو الباب الوحيد — به يعبر، وبغيره
    // أو بخاطئ يُرد عدم الإدراج
    final (status, body, _) = await _send(
      admittedPort,
      origin: 'http://127.0.0.1:$pagePort',
      headers: {'X-Bridge-Token': token},
    );
    expect(status, 200, reason: 'the correct token is the only door');
    expect(body, contains('"ok":true'));
    final (noTokenStatus, noTokenBody, _) = await _send(
      admittedPort,
      origin: 'http://127.0.0.1:$pagePort',
    );
    expect(noTokenStatus, 403, reason: 'without the token there is no door');
    expect(noTokenBody, contains('"error":"origin_not_listed"'));
    final (wrongStatus, wrongBody, _) = await _send(
      admittedPort,
      origin: 'http://127.0.0.1:$pagePort',
      headers: {'X-Bridge-Token': 'wrong-token-value-wrong-token-value12'},
    );
    expect(wrongStatus, 403, reason: 'a wrong token opens no door');
    expect(wrongBody, contains('"error":"origin_not_listed"'));
  }, skip: _skipReason);

  test('an unpaired page is refused: the browser sees no verdict while the '
      'wire carries the literal code', () async {
    final (pageServer, _, defaultBridge, pagePort, _, defaultPort, _) =
        await lab();
    addTearDown(pageServer.close);
    addTearDown(defaultBridge.stop);
    final dom = _flat(
      await _dumpDom(
        'http://127.0.0.1:$pagePort/',
        'j121-scenario2-unpaired-dom.txt',
      ),
    );
    expect(
      dom,
      contains('LAB-UNPAIRED:BLOCKED-NO-VERDICT\n'),
      reason: 'the unpaired page gets no readable verdict at all',
    );
    // التوكيد الموجب: سطر البادئة الوحيد في كل الـDOM هو سطر الحجب —
    // أي سطر مقروء آخر (LAB-UNPAIRED:READ:...) حكمٌ قابل للقراءة
    // فيكون قناة استطلاع الحماية قد فُتحت
    final unpairedLines = RegExp(
      '^LAB-UNPAIRED:.*\$',
      multiLine: true,
    ).allMatches(dom).map((m) => m.group(0)!).toList();
    expect(
      unpairedLines,
      ['LAB-UNPAIRED:BLOCKED-NO-VERDICT'],
      reason:
          'the blocked verdict is the ONLY line carrying the prefix - a '
          'readable refusal for an unpaired origin would be a recon '
          'channel the protection must never open',
    );
    // السلك يحمل الرمز الحرفي من الطرف نفسه في الجولة نفسها
    final (status, body, headers) = await _send(
      defaultPort,
      origin: 'http://127.0.0.1:$pagePort',
    );
    expect(status, 403);
    expect(body, contains('"error":"origin_not_listed"'));
    expect(
      headers['access-control-allow-origin'],
      isNull,
      reason:
          'the refusal carries no CORS echo - that is why the '
          'browser shows no verdict',
    );
  }, skip: _skipReason);

  test('the browser preflight round trip announces the token header and the '
      'echo carries the new name alone', () async {
    final (pageServer, admitted, _, pagePort, admittedPort, _, _) = await lab();
    addTearDown(pageServer.close);
    addTearDown(admitted.stop);
    final dom = _flat(
      await _dumpDom(
        'http://127.0.0.1:$pagePort/',
        'j121-scenario3-preflight-dom.txt',
      ),
    );
    expect(
      dom,
      contains('LAB-OPTIONS:204:cors\n'),
      reason: 'the preflight endpoint answers the page origin',
    );
    expect(
      dom,
      contains('LAB-NOPREFLIGHT:BLOCKED-BY-PREFLIGHT\n'),
      reason:
          'a header the bridge never allows is stopped by the '
          'browser itself - the preflight is really consulted',
    );
    expect(
      dom,
      isNot(contains('LAB-NOPREFLIGHT:2')),
      reason: 'the not-allowed-header call never crossed',
    );
    // البروْفلايت الحقيقي كما يرسله المتصفح، والصدى بايتاً بايتاً
    final (status, _, headers) = await _send(
      admittedPort,
      method: 'OPTIONS',
      origin: 'http://127.0.0.1:$pagePort',
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type, x-bridge-token',
      },
    );
    expect(status, 204);
    expect(
      headers['access-control-allow-origin'],
      'http://127.0.0.1:$pagePort',
    );
    expect(
      headers['access-control-allow-headers'],
      'Content-Type, X-Bridge-Token, X-Correlation-Id',
      reason: 'the allowed-header list carries the new name alone',
    );
    expect(
      headers['access-control-allow-headers']!,
      isNot(contains('X-Portal-Token')),
    );
    // وأصل غير مدرج: بلا صدى أصلاً، فالمتصفح يحجب حكماً له
    final (strangerStatus, _, strangerHeaders) = await _send(
      admittedPort,
      method: 'OPTIONS',
      origin: 'https://stranger.example',
      headers: {'Access-Control-Request-Method': 'POST'},
    );
    expect(strangerStatus, 204);
    expect(strangerHeaders['access-control-allow-origin'], isNull);
  }, skip: _skipReason);

  test(
    'a page Chrome maps to public cannot reach the loopback bridge '
    'without the Local Network Access permission',
    () async {
      // سيناريو Local Network Access بالزوج الحاسم على الصفحة نفسها:
      // بعلم محاكاة الفضاء (--ip-address-space-overrides، وثيقة كروم
      // الرسمية لمصادر LNA) تُعامل صفحة المختبر كصفحة من الإنترنت،
      // وإرسالها إلى جسر loopback يحتاج إذن local-network-access
      // الذي لا يمنحه headless فيحجب المتصفح الإرسال كلياً. وبلا العلم
      // تعبر الصفحة نفسها على الجسر نفسه — فالفرق الوحيد بين الجولتين
      // هو فحص LNA لا الجسر. العلم وُلد بعد M146 فالمتصفح الأقدم يتخطى
      // الصادق
      final (pageServer, admitted, _, pagePort, admittedPort, _, token) =
          await lab();
      addTearDown(pageServer.close);
      addTearDown(admitted.stop);
      final blocked = _flat(
        await _dumpDom(
          'http://127.0.0.1:$pagePort/',
          'j124-lna-public-dom.txt',
          extraArgs: [
            '--ip-address-space-overrides=127.0.0.1:$pagePort=public',
          ],
        ),
      );
      expect(
        blocked,
        contains('LAB-TOKENED:THREW\n'),
        reason:
            'the public-mapped page needs the local-network-access '
            'permission to reach a loopback bridge - headless grants none, '
            'so the browser blocks the send entirely',
      );
      final control = _flat(
        await _dumpDom(
          'http://127.0.0.1:$pagePort/',
          'j124-lna-control-dom.txt',
        ),
      );
      expect(
        control,
        contains('LAB-TOKENED:200:true:no-error\n'),
        reason:
            'the same page and bridge cross without the mapping - the pair '
            'proves the block is the LNA check, not the bridge',
      );
      // وجواب الإذن ليس طريقاً بديلاً للجسر: من عبر بلا إذن (تحكم) يُقبل
      // بالسياسة نفسها التي تُجيب صفحة loopback العادية
      final (status, body, _) = await _send(
        admittedPort,
        origin: 'http://127.0.0.1:$pagePort',
        headers: {'X-Bridge-Token': token},
      );
      expect(status, 200);
      expect(body, contains('"ok":true'));
    },
    skip:
        _skipReason ??
        (_browserMajor == null || _browserMajor! < 146
            ? 'the Local Network Access scenario needs the '
                  '--ip-address-space-overrides era (born after M146): no '
                  'usable browser, or one too old to simulate a public page '
                  'reaching loopback'
            : null),
  );
}
