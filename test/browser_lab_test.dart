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
// - كتب رموز كروميوم (chrome/common/chrome_switches.cc في شجرة
//   source.chromium.org) — ‏--ignore-certificate-errors مفتاح الأتمتة
//   الذي يجعل جلسة الاختبار العابرة تقبل شهادة الاختبار الذاتية لصفحة
//   https: الجلسة بلا واجهة وبملف مستخدم عابر يزور صفحات المختبر حصراً
// - github.com/actions/runner-images (Ubuntu2404-Readme.md) — صورة
//   ubuntu-latest تحمل Google Chrome وChromium مثبتين، وعليها تشغّل
//   وظيفة CI المختبرَ فعلياً.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

import 'support/tls_cert.dart' show captureClientHello;
import 'support/webdriver_client.dart';

final (String?, String?, int?) _labBrowser = _discoverBrowser();

// مسار المتصفح المكتشف، أو null إن لم يوجد — حينها كل الاختبارات تتخطى
final String? _browserPath = _labBrowser.$1;

// سبب التخطي الصادق، أو null إن وُجد متصفح فيعمل الاختبار فعلاً —
// وعلى SDK لا تعرف dart:io معلمة سقف النقل لا تُسلَّح القناة أصلاً
// (الرفض عند البناء) وسلك المختبر كله يركب القناة فلا مشهد له هنا
final String? _skipReason =
    _labBrowser.$2 ??
    (LocalIntakeServer.wsTransportCeilingSupported
        ? null
        : 'the channel refuses to arm without a transport ceiling below '
              'Dart 3.13 - every lab scene rides the channel');

// رقم الإصدار الأكبر للمتصفح المكتشف إن قرأ — سيناريو Local Network
// Access لا يُشغَّل تحت الإصدار 146 حتى يُثبت تشغيله دونه (اسم العلم
// موجود في ثنائيي محركي 134 و145، فالحدُّ حدُّ إثباتٍ لا حدُّ وجود)
final int? _browserMajor = _labBrowser.$3;

// مختبر Firefox على عميل WebDriver نفسه: geckodriver هو المشغّل،
// وFirefox بلا واجهة ب Moz:firefoxOptions، والاكتشاف نفسه الذي لكروم
// (تجاوز بالبيئة، ثم PATH، ثم المواضع القياسية) وبلا مشغّل تخطٍّ صادق
// مسمّى — والمشغّل الوحيد الذي يثبته المشغّل الأخضر هو ما على صورة
// المهمة. ونسخة Firefox تُقرأ من firefox --version لكوابح الجسم
// المتدفق (من 161 فأعلى)، وتُطبع أيضاً من قدرات الجلسة في كل جولة
final (String?, String?, int?) _firefoxLab = _discoverFirefox();
final String? _geckoDriverPath = _firefoxLab.$1;
final String? _firefoxSkipReason = _firefoxLab.$2;
final int? _firefoxMajor = _firefoxLab.$3;

// تخطي مشهدَي القناة الفايرفوكسيين فوق سقف نقل القناة: على SDK لا تعرف
// dart:io معلمة سقف النقل لا تُسلَّح القناة أصلاً (الرفض عند البناء)
final String? _firefoxChannelSkip =
    LocalIntakeServer.wsTransportCeilingSupported
    ? null
    : 'the channel refuses to arm without a transport ceiling below '
          'Dart 3.13 - the firefox channel scenes ride the channel';

/// Locates geckodriver and reads the Firefox major version for the
/// streamed-body floor: the BRIDGE_GECKODRIVER override first, then
/// PATH, then the standard locations; the version comes from
/// `firefox --version` (the BRIDGE_FIREFOX override first). Returns the
/// driver path, the honest skip reason when the pair is unusable, and
/// the major version when it can be read.
(String?, String?, int?) _discoverFirefox() {
  String? driverPath;
  final driverOverride = Platform.environment['BRIDGE_GECKODRIVER']?.trim();
  if (driverOverride != null && driverOverride.isNotEmpty) {
    if (File(driverOverride).existsSync()) driverPath = driverOverride;
  } else {
    final exe = Platform.isWindows ? 'geckodriver.exe' : 'geckodriver';
    final pathEnv = Platform.environment['PATH'] ?? '';
    for (final dir in pathEnv.split(Platform.isWindows ? ';' : ':')) {
      if (dir.trim().isEmpty) continue;
      final candidate = '$dir${Platform.pathSeparator}$exe';
      if (File(candidate).existsSync()) {
        driverPath = candidate;
        break;
      }
    }
    if (driverPath == null) {
      for (final candidate in <String>[
        if (Platform.isMacOS) '/usr/local/bin/geckodriver',
        '/usr/bin/geckodriver',
        '/usr/local/bin/geckodriver',
      ]) {
        if (File(candidate).existsSync()) {
          driverPath = candidate;
          break;
        }
      }
    }
  }
  if (driverPath == null) {
    return (
      null,
      'no geckodriver on this host (searched BRIDGE_GECKODRIVER, PATH '
          'and the standard locations; set BRIDGE_GECKODRIVER to the '
          'driver path to run here) - the firefox scenes run where the '
          'driver exists, such as the CI browser-lab job',
      null,
    );
  }
  // نسخة Firefox من المتصفح نفسه: التجاوز بالبيئة ثم الاسم المعتاد
  final binaryOverride = Platform.environment['BRIDGE_FIREFOX']?.trim();
  final names = Platform.isWindows
      ? <String>['firefox.exe']
      : <String>[
          'firefox',
          if (Platform.isMacOS)
            '/Applications/Firefox.app/Contents/MacOS/firefox',
        ];
  int? major;
  void tryVersion(String path) {
    if (major != null) return;
    try {
      final out = Process.runSync(path, const ['--version']);
      major = int.tryParse(
        RegExp(r'(\d+)\.').firstMatch(out.stdout as String)?.group(1) ?? '',
      );
    } on Object {
      // متصفح لا يجيب --version: لا كوابح نسخة، فالمشهد المحدود بالنسخة يتخطى
    }
  }

  if (binaryOverride != null && binaryOverride.isNotEmpty) {
    if (File(binaryOverride).existsSync()) tryVersion(binaryOverride);
  } else {
    final pathEnv = Platform.environment['PATH'] ?? '';
    for (final dir in pathEnv.split(Platform.isWindows ? ';' : ':')) {
      if (dir.trim().isEmpty) continue;
      for (final name in names) {
        final candidate = '$dir${Platform.pathSeparator}$name';
        if (File(candidate).existsSync()) tryVersion(candidate);
      }
    }
    for (final candidate in names) {
      if (candidate.contains(Platform.pathSeparator) &&
          File(candidate).existsSync()) {
        tryVersion(candidate);
      }
    }
  }
  if (major == null) {
    return (
      driverPath,
      'firefox is expected at the usual places but its version could not '
          'be read (firefox --version) - the firefox scenes need a real '
          'Firefox to prove anything',
      null,
    );
  }
  return (driverPath, null, major);
}

/// Locates a real Chrome/Chromium for the lab: the BRIDGE_BROWSER override
/// first, then PATH, then the standard install locations. Returns the
/// path, the honest skip reason when nothing is found, and the browser's
/// major version when it can be read (the Local Network Access scenario
/// is not run below browser version 146 until a run below it is proven).
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
  String? pairingCode,
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
const PAIRING_CODE = '${pairingCode ?? ''}';
// وضع التقرير (?report=1): العلامات تعود إلى مجمع صفحة المختبر نفسه —
// القناة التي يقرأها شاهد المحاكي (dump-dom لا يعمل على كروم Android)
const REPORT = new URLSearchParams(location.search).get('report') === '1';
const results = document.getElementById('lab-results');
const marks = [];
function mark(line) { marks.push(line); results.textContent += line + '\\n'; }

async function postJson(bridge, extraHeaders) {
  const headers = Object.assign({'Content-Type': 'application/json'},
                                extraHeaders);
  return fetch(bridge, {method: 'POST', headers, body: '["BROWSER-LAB"]'});
}

// توقيع الصفحة بنفس طريقة التصميم حرفا: HMAC-SHA-256 عبر WebCrypto فوق
// canonical = "v1\\n<pairingId>\\n<stamp>\\n<method>\\n<path>\\n<cid>" —
// 127.0.0.1 سياق آمن فcrypto.subtle متاح على http الحلقي
async function signProof(tokenHex, pairingId, method, path, correlationId) {
  const stamp = Date.now();
  const canonical = 'v1\\n' + pairingId + '\\n' + stamp + '\\n' +
                    method + '\\n' + path + '\\n' + correlationId;
  const keyBytes = new Uint8Array(
      tokenHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey(
      'raw', keyBytes, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign(
      'HMAC', key, new TextEncoder().encode(canonical));
  const sigHex = Array.from(new Uint8Array(sig))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  return pairingId + '.' + stamp + '.' + sigHex;
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
  // Scenario 5 (pairing): الصفحة المقترنة كاملة الدورة — الاقتران بالرمز
  // المعروض، ثم التوقيع، ثم الأمر الموقَّع، ثم إعادة التوقيع نفسه، ثم
  // الصفحة بلا إثبات. يشتغل حين يحمل الجسر رمز عرض فقط
  if (PAIRING_CODE !== '') {
    try {
      const pairRes = await fetch(ADMITTED_BRIDGE + '/pair', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({pairingCode: PAIRING_CODE}),
      });
      const pairBody = await pairRes.json().catch(() => null);
      if (pairRes.status === 200 && pairBody && pairBody.token) {
        const proof = await signProof(
            pairBody.token, pairBody.pairingId, 'POST', '/', 'lab-paired-1');
        const signed = await postJson(ADMITTED_BRIDGE, {
          'X-Bridge-Pairing': proof,
          'X-Correlation-Id': 'lab-paired-1',
        });
        const signedBody = await signed.json().catch(() => null);
        mark('LAB-PAIRED:' + signed.status + ':' +
             (signedBody && signedBody.ok === true ? 'true' : 'false'));
        // إعادة التوقيع نفسه: الطابع نفسه لا يثبت مرتين — والمتصفح
        // يقرأ الرمز الحرفي من الرفض القابل للقراءة
        const replay = await postJson(ADMITTED_BRIDGE, {
          'X-Bridge-Pairing': proof,
          'X-Correlation-Id': 'lab-paired-1',
        });
        const replayBody = await replay.json().catch(() => null);
        mark('LAB-PAIRED-REPLAY:' + replay.status + ':' +
             (replayBody && replayBody.error ? replayBody.error
                                             : 'no-error'));
        // الصفحة نفسها بلا إثبات: الرفض الصادق المقروء تعيد منه
        const bare = await postJson(ADMITTED_BRIDGE, {
          'X-Correlation-Id': 'lab-bare-1',
        });
        const bareBody = await bare.json().catch(() => null);
        mark('LAB-STRICT-BARE:' + bare.status + ':' +
             (bareBody && bareBody.error ? bareBody.error : 'no-error'));
      } else {
        mark('LAB-PAIRED:' + pairRes.status + ':' +
             (pairBody && pairBody.error ? pairBody.error : 'unreadable'));
      }
    } catch (browserError) {
      mark('LAB-PAIRED:THREW');
    }
  }
  // وضع التقرير: العلامات كلها تعود إلى مجمع المختبر على أصل الصفحة —
  // آخر نداء في الصفحة كي تجمع كل ما سبقها
  if (REPORT) {
    try {
      await fetch('/lab-report', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({marks: marks}),
      });
      mark('LAB-REPORTED');
    } catch (browserError) {
      mark('LAB-REPORT:THREW');
    }
  }
})();
</script>
</body>
</html>
''';

/// The streaming-body lab page: a page on the lab's page origin first sends
/// an ordinary tokened POST - the control, which must read 200 on the same
/// browser for the refusals to mean anything - and then tries to send a
/// `ReadableStream` request body (`duplex: 'half'`) to the admitted bridge
/// twice: once with headers that force a CORS preflight, once as a simple
/// request. Each attempt writes one verdict line: `THREW:` and the error
/// name when the browser refused the call itself, or `READ:` and the
/// status when the request crossed and came back - the crossing this page
/// exists to detect. In `?report=1` mode the marks return to the lab's
/// collector.
String _streamBodyPage({required int bridgePort, required String token}) =>
    '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>localhost_bridge streaming body lab</title></head>
<body>
<pre id="lab-results"></pre>
<script>
'use strict';
const BRIDGE = 'http://127.0.0.1:$bridgePort';
const TOKEN = '$token';
// وضع التقرير (?report=1): القناة التي يقرأها شاهد المحاكي
const REPORT = new URLSearchParams(location.search).get('report') === '1';
const results = document.getElementById('lab-results');
const marks = [];
function mark(line) { marks.push(line); results.textContent += line + '\\n'; }
function streamed(text) {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) { controller.enqueue(bytes); controller.close(); }
  });
}
async function attempt(label, init) {
  try {
    const res = await fetch(BRIDGE, init);
    let body = null;
    try { body = await res.json(); } catch (e) {}
    mark('LAB-STREAMBODY-' + label + ':READ:' + res.status + ':' +
         (body && body.error ? body.error
                             : (body && body.ok === true ? 'ok' : 'unreadable')));
  } catch (browserError) {
    mark('LAB-STREAMBODY-' + label + ':THREW:' +
         (browserError && browserError.name ? browserError.name : 'unknown'));
  }
}
(async () => {
  mark('LAB-STREAMBODY-PAGE-ORIGIN:' + location.origin);
  // الشاهد الموجب: جسم عادي بالترويسات نفسها يعبر ويقرأ 200 — بدونه لا
  // يعني رفضُ الجسم المتدفق شيئاً
  await attempt('CONTROL', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Bridge-Token': TOKEN},
    body: '["BROWSER-LAB"]',
  });
  // بترويسات تفرض خيار CORS أولاً
  await attempt('PREFLIGHT', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Bridge-Token': TOKEN},
    body: streamed('["BROWSER-LAB"]'),
    duplex: 'half',
  });
  // وطلب بسيط بلا ترويسات مخصصة
  await attempt('SIMPLE', {
    method: 'POST',
    headers: {'Content-Type': 'text/plain'},
    body: streamed('["BROWSER-LAB"]'),
    duplex: 'half',
  });
  if (REPORT) {
    try {
      await fetch('/lab-report', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({marks: marks}),
      });
      mark('LAB-REPORTED');
    } catch (browserError) {
      mark('LAB-REPORT:THREW');
    }
  }
})();
</script>
</body>
</html>
''';

// مرصد أسطر الأمن والشبكة أثناء تحقيقات القناة — يطبع لسجل الاختبار
// كي تُقرأ قصة الخادم جانب المتصفح
class _RecordingTelemetry extends BridgeTelemetry {
  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    stderr.writeln('LAB-TEL-INFO: $message');
  }

  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    stderr.writeln('LAB-TEL-WARN: $message');
  }

  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    stderr.writeln('LAB-TEL-ERROR: $message :: $error');
  }

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) async => await body();
}

var _labIdSeq = 0;

/// The lab's correlation ids: short, distinct, honest to the wire contract
String _labCorrelationId() => 'lab-${_labIdSeq++}';

/// Starts a bridge on an ephemeral loopback port; when [token] is given it
/// is set as the accepted token alongside the listed [allowedOrigin].
/// With [paired] the origin+token requirement is on and the pairing layer
/// is armed - the page pairs with the displayed code and signs.
Future<(LocalIntakeServer, int)> _startBridge({
  String? allowedOrigin,
  String? token,
  bool paired = false,
  void Function()? onCommand,
}) async {
  final protection = IntakeProtection(telemetry: const SilentTelemetry());
  protection.update(
    policy: OriginPolicy(
      allowed: [?allowedOrigin],
      requireOriginWithToken: paired,
    ),
    token: token,
  );
  if (paired) protection.enablePairing();
  final bridge = LocalIntakeServer(
    onCommand: (_) async {
      onCommand?.call();
      return const CommandOutcome(ok: true);
    },
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

// شهادة الاختبار الذاتية لخادم صفحة https — ولّدتا محلياً لهذا المختبر
// (منحنى P-256 وSAN لـ127.0.0.1 وlocalhost) وتحمي لا شيء: غرضها أن يكون
// أصل الصفحة أصل https حقيقياً لقصة Local Network Access لا أن يُبنى
// عليها ثقة، وجلسة المتصفح العابرة تقبلها بعلم الأتمتة الموثق في
// ترويسة الملف
const String _labTlsCertPem = r'''
-----BEGIN CERTIFICATE-----
MIIBvzCCAWWgAwIBAgIUOyM1NSWvcU6oQ49nLN9wRQpDv+IwCgYIKoZIzj0EAwIw
JzElMCMGA1UEAwwcbG9jYWxob3N0X2JyaWRnZS1icm93c2VyLWxhYjAeFw0yNjEx
MjExNjQ3MDZaFw0zNjExMTgxNjQ3MDZaMCcxJTAjBgNVBAMMHGxvY2FsaG9zdF9i
cmlkZ2UtYnJvd3Nlci1sYWIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASJvQTP
SUhnm6eT5kY8jPqr8xP8FAVc7PAO4yjG2blRS3kC0XGicPh5ycVpDb6LLcPDT2OX
yDq1NVXrBH5Ef8Eeo28wbTAdBgNVHQ4EFgQUyrHrMY1F+e4mcJIiqMe5qIT3HkYw
HwYDVR0jBBgwFoAUyrHrMY1F+e4mcJIiqMe5qIT3HkYwDwYDVR0TAQH/BAUwAwEB
/zAaBgNVHREEEzARhwR/AAABgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSAAwRQIg
ZvIBbf2uTLL0PU2dyEblwGjUsWj3oHbg6lpIUbe73pYCIQDFB/sZcc5jgswG/DTS
ez0vqobphpac8Cq35pWY0zDYlQ==
-----END CERTIFICATE-----
''';

const String _labTlsKeyPem = r'''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs1pUXrOinr++i5pu
ms39DvXUA3h9za/ADPwAGdXvSFqhRANCAASJvQTPSUhnm6eT5kY8jPqr8xP8FAVc
7PAO4yjG2blRS3kC0XGicPh5ycVpDb6LLcPDT2OXyDq1NVXrBH5Ef8Ee
-----END PRIVATE KEY-----
''';

// سياق TLS لخادم الصفحة الآمن من ملفَّي التثبيت أعلاه — خادم https
// حقيقي يدور على حلقي ويخدم صفحة المختبر
SecurityContext _labTlsContext() => SecurityContext()
  ..useCertificateChainBytes(utf8.encode(_labTlsCertPem))
  ..usePrivateKeyBytes(utf8.encode(_labTlsKeyPem));

// سقف الالتقاط الذي يُسلَّم للمتصفح نفسه (‏--timeout): بعده يفرغ ما تحمله
// الصفحة مهما بلغ انتظارها. وجولة المتصفح الواحدة (إقلاعها وسقفها وخروجها)
// تنتظر [_browserRunWait] كلها قانوناً، فمهلة الاختبار الافتراضية (ثلاثون
// ثانية) لا تصلح لمشهد ينتظر جولة قد لا تُحسم قبل سقف الالتقاط نفسه:
// تسقط المشهد قبل وصول ما التقطه، ثم يكتب جسمه بعد سقوطه على جسر أوقفه
// teardown فيظهر خطأ ثانٍ (اتصال مرفوض) هو أثر السقوط لا علة ثانية.
// فكل مشهد ينتظر متصفحاً يُعلن بباب [scene] وحده، وهو يسلّم الميزانية
// [_sceneBudget]، والشاهد في آخر الملف يقرأ المصدر ويُسقط كل مشهد بمتصفح
// أُعلن بلا الباب
const Duration _browserCaptureCeiling = Duration(seconds: 30);
const Duration _browserRunWait = Duration(seconds: 90);

/// The one budget of every browser scene: above the whole wait of the largest
/// scene the lab has (two browser runs), the wire checks after them, and the
/// teardown. A run the browser itself bounded is never cut by the test before
/// its DOM arrives.
final Timeout _sceneBudget = Timeout(
  _browserRunWait * 2 + const Duration(seconds: 60),
);

/// Declares one browser scene: under the scene budget, skipped for the lab's
/// own reason or for the scene's [skip] when it names one.
void scene(String name, Future<void> Function() body, {String? skip}) =>
    test(name, body, skip: skip ?? _skipReason, timeout: _sceneBudget);

/// Drives the real browser headlessly over the lab page and returns the
/// dumped DOM: scripts run, virtual time advances the page's async work,
/// then the serialized DOM is printed to stdout. Every run prints one
/// `LAB-RUN:` line naming its evidence file and its wall time. When
/// BRIDGE_LAB_EVIDENCE_DIR is set, the full dump is also written there
/// verbatim (one file per call).
Future<String> _dumpDom(
  String url,
  String evidenceFile, {
  List<String> extraArgs = const [],
  bool virtualTime = true,
  int virtualTimeBudgetMs = 20000,
}) async {
  final userDataDir = await Directory.systemTemp.createTemp(
    'bridge-browser-lab-',
  );
  // زمن الجولة الحقيقي يُعلن لكل جولة: جولة بطيئة اكتملت علاماتها تمرّ،
  // وسطرها يبقى في السجل فيسمّي المشهد ومقداره — والمدة تُقرأ من
  // المخرج لا تُستنتج من سكون
  final stopwatch = Stopwatch()..start();
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
        // الوقت الافتراضي يُشغَّل للأموام التي تثبته شبكياً (fetch
        // يوقفه) — قناة الويب سوكيت لا توقفه فيسبق الساعةُ الحقيقيةُ
        // المرورَ فعلاً فيجري المشهدان على الزمن الحقيقي وسقف
        // الالتقاط الحقيقي يحرسها
        if (virtualTime) '--virtual-time-budget=$virtualTimeBudgetMs',
        '--timeout=${_browserCaptureCeiling.inMilliseconds}',
        url,
      ],
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    ).timeout(_browserRunWait);
    // ليست فشلاً: العلامات وحدها تحكم الجولة، وهذا السطر يسمّي مدتها
    // كي تُقرأ في سجل المشغّل حيث لا يُقرأ غيره
    print('LAB-RUN: $evidenceFile ${stopwatch.elapsed.inMilliseconds} ms');
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
  // أخطاء مستمع خادم الصفحة (لا أخطاء الطلبات): قطع النظير داخل مصافحة
  // TLS مع خادم الصفحة الآمن يبلغه المستمع الآمن خطأً في المقبس لا
  // استثناء مصافحة، وطبقة HTTP تمرر إلى تدفق الطلبات كل ما ليس استثناء
  // مصافحة — فلا يلتقطه إلا onError المستمع، وبلا معالج يصل منطقة
  // الاختبار خطأً غير معالج يسقط الشاهد. تسجيله هنا يمنع ذلك، ويسمح
  // للشاهد المسبق أدناه بقراءة ما وصل فعلاً لا الاكتفاء بالغياب
  final pageListenerErrors = <Object>[];
  Future<
    (HttpServer, LocalIntakeServer, LocalIntakeServer, int, int, int, String)
  >
  lab({
    bool tokenOnlyAdmitted = false,
    bool pairedAdmitted = false,
    List<Map<String, Object?>>? collectedReports,
    void Function()? onCommand,
  }) async {
    final token = generateBridgeToken();
    // الجسر المقبول يُبنى على أصل الصفحة قبل أن تُخدم الصفحة: المنفذ
    // المعمى في HTML يحتاج منافذ الجسور جاهزة أولاً. ووضع [pairedAdmitted]
    // يسلّح الشرط المشترك والاقتران معاً ويولّد رمز العرض — الشاهد
    // المتصفحي لدورة الاقتران كلها على الجسر الواحد
    final pageServer = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final (admitted, admittedPort) = await _startBridge(
      allowedOrigin: tokenOnlyAdmitted
          ? null
          : 'http://127.0.0.1:${pageServer.port}',
      token: token,
      paired: pairedAdmitted,
      onCommand: onCommand,
    );
    final (defaultBridge, defaultPort) = await _startBridge();
    final pairingOffer = pairedAdmitted
        ? admitted.protection.startPairing()
        : null;
    final html = _labPage(
      admittedBridgePort: admittedPort,
      defaultBridgePort: defaultPort,
      token: token,
      pairingCode: pairingOffer?.code,
    );
    // مجمّع التقارير: القناة التي يقرأها شاهد المحاكي (كروم Android لا
    // يفرغ DOM) — الصفحة في وضع ?report=1 تعيد علاماتها إلى هنا
    final reports = collectedReports ?? <Map<String, Object?>>[];
    pageServer.listen((request) async {
      if (request.uri.path == '/lab-report') {
        if (request.method == 'POST') {
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
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode(reports));
        await request.response.close();
        return;
      }
      if (request.uri.path == '/stream-body') {
        // صفحة محاولة الجسم المتدفق: باب مستقل كي لا تغيّر علامات صفحة
        // المختبر العامة ولا تحرّك شهودها
        request.response.headers.contentType = ContentType.html;
        request.response.write(
          _streamBodyPage(bridgePort: admittedPort, token: token),
        );
        await request.response.close();
        return;
      }
      if (request.uri.path != '/') {
        request.response.statusCode = HttpStatus.notFound;
        await request.response.close();
        return;
      }
      request.response.headers.contentType = ContentType.html;
      request.response.write(html);
      await request.response.close();
    }, onError: (Object error) => pageListenerErrors.add(error));
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

  scene('the token scenario runs on a token-only bridge: the token is the '
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
  });

  scene('an unpaired page is refused: the browser sees no verdict while the '
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
    // فيكون قناة استطلاع الحماية قد فُتحت. والسالب المشدد: أي سطر مقروء
    // بنمط الحالة الرقمية يفشل الجولة
    expect(
      dom,
      isNot(contains(RegExp('LAB-UNPAIRED:READ:[0-9]'))),
      reason:
          'a readable verdict line for the unpaired scenario is a recon '
          'channel the protection must never open',
    );
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
  });

  scene('the browser preflight round trip announces the token header and the '
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
  });

  scene('on this browser a page cannot stream a request body while an ordinary '
      'body crosses: both streaming calls are refused before the request '
      'leaves, and only the control command reaches the handler', () async {
    // صفحة على أصل صفحة المختبر ترسل أولاً جسماً عادياً (الشاهد الموجب:
    // يعبر ويقرأ 200) ثم تحاول fetch بجسم ReadableStream وduplex half على
    // الجسر المقبول مرتين — والجسر بعدّاد أوامر: عبورُ الجسم المتدفق
    // يظهر من الطرفين معاً، بحكم مقروء في الصفحة وبأمر يصل المعالج.
    // والحكم هنا سلوك متصفح المختبر نفسه لا قانون: متصفح آخر قد يرسل
    // كائن التدفق كسلسلة بطول ثابت بدل أن يرفض — فالشاهد يثبّت هذا
    // المتصفح، ويُعاد قياسه قبل أن يتغير متصفح المختبر
    var entered = 0;
    final (pageServer, admitted, _, pagePort, _, _, _) = await lab(
      onCommand: () => entered++,
    );
    addTearDown(pageServer.close);
    addTearDown(admitted.stop);
    final dom = _flat(
      await _dumpDom(
        'http://127.0.0.1:$pagePort/stream-body',
        'stream-body-dom.txt',
      ),
    );
    final verdicts = RegExp(
      r'^LAB-STREAMBODY-(PREFLIGHT|SIMPLE):.*$',
      multiLine: true,
    ).allMatches(dom).map((m) => m.group(0)!).toList()..sort();
    expect(verdicts, hasLength(2), reason: 'both attempts report a verdict');
    for (final verdict in verdicts) {
      expect(
        verdict,
        contains(':THREW:'),
        reason:
            'a streaming body must be refused by the browser before the '
            'request leaves - a readable status here means the body '
            'crossed: $verdict',
      );
    }
    expect(
      dom,
      isNot(
        contains(
          RegExp(r'^LAB-STREAMBODY-(PREFLIGHT|SIMPLE):READ:', multiLine: true),
        ),
      ),
      reason: 'no streaming attempt may read a status from the bridge',
    );
    // والشاهد الموجب في الصفحة نفسها: الجسم العادي بالترويسات نفسها
    // يعبر ويقرأ 200 — فالرفضان قرار المتصفح لا جسر لا يصل
    expect(
      dom,
      contains('LAB-STREAMBODY-CONTROL:READ:200:ok\n'),
      reason:
          'the control must cross on this browser - without it the two '
          'refusals would prove nothing',
    );
    expect(
      entered,
      1,
      reason:
          'exactly the control command reached the handler on the wire - '
          'no streaming body did',
    );
  });

  scene(
    'a page Chrome maps to public cannot reach the loopback bridge '
    'without the Local Network Access permission',
    () async {
      // سيناريو Local Network Access بالزوج الحاسم على الصفحة نفسها:
      // بعلم محاكاة الفضاء (--ip-address-space-overrides — مصدره المؤرخ
      // قضية Playwright رقم 37861 (سياق كروم 141/142) التي توثق العلم
      // لمحاكاة LNA، وسياسات المؤسسة للفئة منذ كروم 146؛ دليل كروم الرسمي
      // لمصادر LNA لا يذكر العلم) تُعامل صفحة المختبر كصفحة من الإنترنت،
      // وإرسالها إلى جسر loopback يحتاج إذن local-network-access
      // الذي لا يمنحه headless فيحجب المتصفح الإرسال كلياً. وبلا العلم
      // تعبر الصفحة نفسها على الجسر نفسه — فالفرق الوحيد بين الجولتين
      // هو فحص LNA لا الجسر. وتحت الإصدار 146 يتخطى الشاهد الصادق حتى
      // يُثبت تشغيله دونه — اسم العلم موجود في ثنائيي محركي 134 و145،
      // فالحدُّ حدُّ إثباتٍ لا حدُّ وجود
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
    skip: _browserMajor == null || _browserMajor! < 146
        ? 'the Local Network Access scenario is not run below browser '
              'version 146 until a run below it is proven: no usable '
              'browser, or one below the proven floor'
        : null,
  );

  scene(
    'the paired page pairs with the displayed code, signs its command, '
    'and reads the reply; the replay and the proofless page are refused',
    () async {
      // شاهد الاقتران على سطح المكتب: الصفحة المقترنة كاملة الدورة على
      // متصفح حقيقي — الاقتران بالرمز المعروض، ثم التوقيع بـWebCrypto
      // (HMAC-SHA-256 فوق الcanonical بنص التصميم)، ثم الأمر الموقَّع 200،
      // ثم إعادة التوقيع نفسه 403 pair_signature_replay، ثم الصفحة بلا
      // إثبات 403 token_required مقروءة — والسلك من طرف الاختبار يثبت
      // الطلب المحلي المكتوب يدوياً بالأصل المدرج وبلا إثبات يُرفض
      final (pageServer, admitted, _, pagePort, admittedPort, _, token) =
          await lab(pairedAdmitted: true);
      addTearDown(pageServer.close);
      addTearDown(admitted.stop);
      final dom = _flat(
        await _dumpDom('http://127.0.0.1:$pagePort/', 'j3-paired-dom.txt'),
      );
      expect(
        dom,
        contains('LAB-PAIRED:200:true\n'),
        reason:
            'the paired page pairs with the displayed code, signs with '
            'WebCrypto, and reads its command reply - the whole pairing '
            'story in a real browser',
      );
      expect(
        dom,
        contains('LAB-PAIRED-REPLAY:403:pair_signature_replay\n'),
        reason: 'the same signature never proves twice, read by the browser',
      );
      expect(
        dom,
        contains('LAB-STRICT-BARE:403:token_required\n'),
        reason:
            'the same page without its proof reads the honest strict '
            'refusal and retries from it',
      );
      // السلك من طرف الاختبار: برنامج محلي مكتوب يدوياً بالأصل المدرج
      // وبلا توكن — الرفض الصادق نفسه لا القبول
      final (forgedStatus, forgedBody, forgedHeaders) = await _send(
        admittedPort,
        origin: 'http://127.0.0.1:$pagePort',
      );
      expect(forgedStatus, 403);
      expect(forgedBody, contains('"error":"token_required"'));
      expect(
        forgedHeaders['access-control-allow-origin'],
        'http://127.0.0.1:$pagePort',
        reason: 'the qualified origin reads its refusal to retry with a proof',
      );
      // والتوكن المشترك لا يعالج الصفحة المقترنة هنا: الشاهد يقف على
      // أن الإثبات هو باب الصفحة لا التوكن الخام
      final (sharedStatus, sharedBody, _) = await _send(
        admittedPort,
        origin: 'http://127.0.0.1:$pagePort',
        headers: {'X-Bridge-Token': token},
      );
      expect(sharedStatus, 200, reason: 'the shared token stays a valid proof');
      expect(sharedBody, contains('"ok":true'));
    },
  );

  scene(
    'the paired page reports its verdicts through the collector: the '
    'channel the emulator witness reads, proven on a desktop browser',
    () async {
      // قناة شاهد المحاكي مثبتة هنا حصرا: كروم Android لا يفرغ DOM فيقرأ
      // الشاهدُ علاماتِ الصفحة من مجمّع المختبر (?report=1) — وهذا الشاهد
      // يثبت القناة نفسها على متصفح سطح مكتب قبل أن يسلكها المحاكي
      final collected = <Map<String, Object?>>[];
      final (pageServer, admitted, _, pagePort, _, _, _) = await lab(
        pairedAdmitted: true,
        collectedReports: collected,
      );
      addTearDown(pageServer.close);
      addTearDown(admitted.stop);
      await _dumpDom(
        'http://127.0.0.1:$pagePort/?report=1',
        'j3-paired-report-dom.txt',
      );
      // انتظار قصير لا يستبدل الاكتمال: التقرير قد يتأخر عن التقاط DOM
      for (var i = 0; i < 20 && collected.isEmpty; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      expect(collected, hasLength(1), reason: 'the page reported exactly once');
      final marks = (collected.single['marks'] as List).cast<String>();
      expect(
        marks,
        contains('LAB-PAIRED:200:true'),
        reason: 'the collector received the whole paired story, not a DOM',
      );
      // علامة LAB-REPORTED ذاتها لا تحتويها النسخة المرسلة بالتصميم: هي
      // تُكتب بعد بناء جسم التقرير — حضورها في الـDOM لا في المجمع
      expect(marks, contains('LAB-PAIRED-REPLAY:403:pair_signature_replay'));
      expect(marks, contains('LAB-STRICT-BARE:403:token_required'));
    },
  );

  // صفحة قناة المضيف: الرد المتدفق ثم الويب سوكيت — سيناريوهان
  // مواطنان دائمان على متصفح حقيقي، على جسر مخصص لهما (الخيارات
  // المسلحة تغيّر قائمة الترويسات المسموحة فلا تُسلّح على جسر
  // سيناريوهات المواطنين الأقدم التي تقرأ قائمتها حرفاً)
  String channelPageOf({required int bridgePort, required String token}) =>
      '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>localhost_bridge channel lab</title></head>
<body>
<pre id="lab-results"></pre>
<script>
'use strict';
const BRIDGE = 'http://127.0.0.1:$bridgePort';
const TOKEN = '$token';
const results = document.getElementById('lab-results');
const marks = [];
function mark(line) { marks.push(line); results.textContent += line + '\\n'; }

// الرد المتدفق من متصفح حقيقي: fetch وقراءة الجسم المتدفق بإطاراته
// بترتيب وصولها — ثلاثة تقدمات ثم النتيجة
async function streamScenario() {
  try {
    const res = await fetch(BRIDGE, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bridge-Stream': 'events',
        'X-Correlation-Id': 'lab-stream-1',
      },
      body: '["BROWSER-STREAM"]',
    });
    mark('LAB-STREAM-CTYPE:' + res.headers.get('content-type'));
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let text = '';
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      text += dec.decode(chunk.value, {stream: true});
    }
    const frames = text.trim().split('\\n\\n').map(function (b) {
      let ev = '', data = '';
      b.split('\\n').forEach(function (line) {
        if (line.startsWith('event: ')) ev = line.slice(7);
        if (line.startsWith('data: ')) data = line.slice(6);
      });
      return ev + '|' + data;
    });
    frames.forEach(function (f, i) { mark('LAB-STREAM-FRAME:' + i + ':' + f); });
    mark('LAB-STREAM-ORDER:' + frames.map(function (f) { return f.split('|')[0]; }).join(','));
    // يفكّ مثبّت الزمن الافتراضي بعد علامات المشهد كلها
    await fetch('/stream-done').catch(function () {});
  } catch (browserError) {
    mark('LAB-STREAM:THREW');
    await fetch('/stream-done').catch(function () {});
  }
}

// قناة الويب سوكيت من متصفح حقيقي: المصافحة عبر بوابات الأصل ثم
// قراءة إغلاق القناة الصادق — إطار الرفض الحرفي مع سبب الإغلاق.
// اتجاه الخادم إلى الصفحة هو ما يقيسه هذا المشهد؛ واتجاه الصفحة إلى
// الخادم (الاعتماد ثم الأمر وردّه) يقيسه طرف الاختبار المباشر في
// الشاهد نفسه كي لا يتراهن المشهد على توقيت إرسال المتصفح تحت
// الزمن الافتراضي
function wsScenario() {
  return new Promise(function (resolve) {
    let settled = false;
    const finish = function (line) {
      if (settled) return;
      settled = true;
      mark(line);
      resolve(null);
    };
    const ws = new WebSocket('ws://127.0.0.1:$bridgePort/ws');
    ws.onopen = function () { mark('LAB-WS-OPEN'); };
    ws.onmessage = function (e) {
      mark('LAB-WS-FRAME:' + e.data);
    };
    ws.onerror = function () { finish('LAB-WS-ERROR'); };
    ws.onclose = function (e) {
      mark('LAB-WS-CLOSE:' + e.code + ':' + e.reason);
      finish('LAB-WS-DONE');
    };
    setTimeout(function () { finish('LAB-WS-TIMEOUT'); }, 6000);
  });
}

(async () => {
  mark('LAB-CHANNEL-PAGE:' + location.origin);
  // مثبّتا الزمن الافتراضي: الجلبان المعلقان يجمّدان ساعة كروم أثناء
  // عبور المشهدين الحقيقي (قراءة جسم التدفق وموعد إغلاق الاعتماد)
  // فتعبر الإطارات إلى الصفحة قبل التقاط الـDOM
  const waiter = fetch('/ws-wait').catch(function () {});
  const streamWaiter = fetch('/stream-wait').catch(function () {});
  await streamScenario();
  await wsScenario();
  await waiter;
  await streamWaiter;
  mark('LAB-CHANNEL-END');
})();
</script>
</body>
</html>
''';

  Future<(HttpServer, LocalIntakeServer, IntakeProtection, int, int, String)>
  channelLab({bool secure = false}) async {
    final token = generateBridgeToken();
    // خادم الصفحة: http عادي أو https بشهادة الاختبار الذاتية — والأصل
    // الكامل بمخططه هو ما يدخل قائمة الأصل المسموح فتُحكم المصافحة به
    final pageServer = secure
        ? await HttpServer.bindSecure(
            InternetAddress.loopbackIPv4,
            0,
            _labTlsContext(),
          )
        : await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final pageOrigin =
        '${secure ? 'https' : 'http'}://127.0.0.1:${pageServer.port}';
    final protection = IntakeProtection(telemetry: _RecordingTelemetry());
    protection.update(
      policy: OriginPolicy(allowed: [pageOrigin]),
      token: token,
    );
    final bridge = LocalIntakeServer(
      onCommand: (cmd) async {
        // المعالج يبلّغ تقدمه الثلاثي ثم نتيجته — الترتيب على السلك
        // هو الترتيب الذي تقرؤه الصفحة
        cmd.progress?.call({'step': 1});
        cmd.progress?.call({'step': 2});
        cmd.progress?.call({'step': 3});
        return const CommandOutcome(ok: true, data: {'echo': true});
      },
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _labCorrelationId,
      protection: protection,
      config: const BridgeConfig(
        allowStreamingReplies: true,
        wsPath: '/ws',
        idleTimeout: Duration(seconds: 2),
      ),
      // مهلة الاعتماد القصيرة: إطار الإغلاق يصبح متاحاً للصفحة داخل
      // عمرها الافتراضي القصير (وإلا فمهلة الحزمة الداخلية عشر ثوانٍ)
      wsAuthTimeout: const Duration(milliseconds: 1200),
    );
    final port = await bridge.start(preferredPort: 0);
    final html = channelPageOf(bridgePort: port, token: token);
    // مثبّتا مشهدي القناة: كل جلب يُحتفظ به حتى تعبر علامات مشهده
    // الحقيقية (أو مهلة حقيقية تحرره فالفشل صادق لا معلق)
    final streamDone = Completer<void>();
    pageServer.listen((request) async {
      if (request.uri.path == '/stream-wait') {
        try {
          await streamDone.future.timeout(const Duration(seconds: 20));
        } on TimeoutException {
          // لم تكتمل قراءة التدفق: حرر الجلب ليكمل كروم بالفشل الصادق
        }
        request.response.headers.contentType = ContentType.json;
        request.response.write('{"waited":true}');
        await request.response.close();
        return;
      }
      if (request.uri.path == '/stream-done') {
        if (!streamDone.isCompleted) streamDone.complete();
        request.response.headers.contentType = ContentType.json;
        request.response.write('{"done":true}');
        await request.response.close();
        return;
      }
      if (request.uri.path == '/ws-wait') {
        // يعيد الجلب بعد أن يكون إطار إغلاق الاعتماد قد عبر فعلاً
        // (مهلة الاعتماد ثانية ونصف والمكوث هنا فوقها) — الزمن
        // الافتراضي محتجز طوال المكوث فلا تُقطع الصفحة قبل علاماتها
        await Future<void>.delayed(const Duration(milliseconds: 2500));
        request.response.headers.contentType = ContentType.json;
        request.response.write('{"waited":true}');
        await request.response.close();
        return;
      }
      if (request.uri.path != '/') {
        request.response.statusCode = HttpStatus.notFound;
        await request.response.close();
        return;
      }
      request.response.headers.contentType = ContentType.html;
      request.response.write(html);
      await request.response.close();
    }, onError: (Object error) => pageListenerErrors.add(error));
    return (pageServer, bridge, protection, pageServer.port, port, token);
  }

  scene('the streaming reply runs in a real browser: three progress frames '
      'then the result frame, in the arrival order the page reads', () async {
    final (pageServer, bridge, protection, pagePort, _, _) = await channelLab();
    addTearDown(pageServer.close);
    addTearDown(bridge.stop);
    addTearDown(protection.dispose);
    final dom = _flat(
      await _dumpDom(
        'http://127.0.0.1:$pagePort/',
        'j14-stream-dom.txt',
        virtualTimeBudgetMs: 60000,
      ),
    );
    expect(
      dom,
      contains('LAB-STREAM-CTYPE:text/event-stream'),
      reason:
          'the opted-in command reads the streaming media type in a '
          'real browser',
    );
    expect(
      dom,
      contains('LAB-STREAM-ORDER:progress,progress,progress,result'),
      reason: 'three progress frames then the result, in order',
    );
    expect(
      dom,
      contains('LAB-STREAM-FRAME:0:progress|{"step":1}'),
      reason: 'the first progress frame crossed intact',
    );
    expect(
      dom,
      contains('"step":3'),
      reason: 'the third progress frame crossed intact',
    );
    expect(
      dom,
      contains('LAB-STREAM-FRAME:3:result|{"ok":true,"data":{"echo":true}}'),
      reason: 'the final frame carries the standing reply contract',
    );
    expect(
      dom,
      isNot(contains('LAB-STREAM:THREW\n')),
      reason:
          'the streaming fetch never threw (the newline anchors the '
          'verdict line, not the page source)',
    );
  });

  scene('ws://127.0.0.1 from a real page: the handshake upgrades through the '
      'origin gates, the first message authenticates, and the command reply '
      'crosses the channel', () async {
    final (pageServer, bridge, protection, pagePort, bridgePort, token) =
        await channelLab();
    addTearDown(pageServer.close);
    addTearDown(bridge.stop);
    addTearDown(protection.dispose);
    final dom = _flat(
      await _dumpDom(
        'http://127.0.0.1:$pagePort/',
        'j14-ws-dom.txt',
        virtualTimeBudgetMs: 60000,
      ),
    );
    expect(
      dom,
      contains('LAB-WS-OPEN\n'),
      reason:
          'the browser opened the loopback WebSocket from a real '
          'page over the origin-gated handshake',
    );
    // الصفحة تقرأ إطار الرفض الحرفي وسبب الإغلاق — اتجاه الخادم إلى
    // الصفحة كاملاً داخل متصفح فعلي
    expect(
      dom,
      contains('LAB-WS-FRAME:{"ok":false,"error":"ws_auth_timeout"'),
      reason:
          'the channel refusal frame crossed to the page and was '
          'read by its onmessage - the literal code rides the frame',
    );
    expect(
      dom,
      contains('LAB-WS-CLOSE:1008:ws_auth_timeout\n'),
      reason:
          'the close carries the policy code and the literal code '
          'as its reason',
    );
    expect(
      dom,
      contains('LAB-WS-DONE\n'),
      reason: 'the channel story completed inside the page',
    );
    expect(
      dom,
      isNot(contains('LAB-WS-ERROR\n')),
      reason:
          'the channel never errored (the newline anchors the '
          'verdict line, not the page source)',
    );
    expect(
      dom,
      isNot(contains('LAB-WS-TIMEOUT\n')),
      reason: 'the exchange crossed without exhausting the wait',
    );
    // والقصة الكاملة عكسياً من طرف الاختبار المباشر على الجسر نفسه:
    // الاعتماد بأول رسالة ثم الأمر وردّه — اتجاه الصفحة إلى الخادم
    // تحت الزمن الافتراضي متردداً على هذا المضيف فيملكه
    // العميل المباشر هنا بذات الشهادة
    final ws = await WebSocket.connect(
      'ws://127.0.0.1:$bridgePort/ws',
      headers: {'Origin': 'http://127.0.0.1:$pagePort'},
    ).timeout(const Duration(seconds: 5));
    final replies = <String>[];
    final replied = Completer<void>();
    late final StreamSubscription sub;
    sub = ws.listen(
      (m) {
        replies.add(m as String);
        if (!replied.isCompleted) replied.complete();
      },
      onDone: () {
        if (!replied.isCompleted) replied.complete();
      },
      onError: (Object _) {
        if (!replied.isCompleted) replied.complete();
      },
    );
    ws.add(jsonEncode({'token': token, 'correlationId': 'lab-ws-1'}));
    ws.add(jsonEncode(['BROWSER-WS']));
    await replied.future.timeout(const Duration(seconds: 5));
    unawaited(sub.cancel());
    expect(
      replies.single,
      contains('"ok":true'),
      reason:
          'the credential opened the channel and the command reply '
          'crossed it',
    );
    expect(replies.single, contains('"echo":true'));
    await ws.close();
    expect(token, hasLength(64));
  });

  scene(
    'ws://127.0.0.1 from an https page: without the Local Network Access '
    'permission the browser blocks the channel, and with the permission '
    'granted the handshake crosses the acceptance gates',
    () async {
      // قصة Local Network Access الحقيقية على قناة الويب سوكيت: صفحة https
      // يخدمها خادم الاختبار (شهادة الاختبار الذاتية أعلاه بعلم الأتمتة
      // الموثق في ترويسة الملف) تحاول ws://127.0.0.1 على جسر مسلح القناة.
      // بعلم محاكاة الفضاء نفسه الذي في سيناريو Local Network Access
      // أعلاه: بتعيين أصل الصفحة نقطةً عامة
      // (‎--ip-address-space-overrides=127.0.0.1:<منفذ الصفحة>=public)
      // يحتاج عبورها إلى القناة الحلقية إذن local-network-access الذي لا
      // يمنحه headless فيحجب المتصفح القناة كلياً قبل أي ترقية — والجسر
      // نفسه يبقى سليماً فيجيب الطرف المحلي المباشر، فيثبت الوجهان أن
      // الحاجز فحص LNA في المتصفح لا علة في الجسر. وبتعيين نقطة الجسر
      // نفسها عامة بالمفتاح ذاته (محاكاة الإذن الممنوح: الجلسة بلا واجهة
      // لا تمنح الإذن أصلاً والفحص هو ما يسقط عن العبور) تعبر المصافحة
      // بوابات القبول كاملة: الأصل المدرج https ثم الترقية ثم إطار الرفض
      // الحرفي وإغلاقه كما تقرؤه صفحة قناة http المواطنة. واتجاه الصفحة
      // إلى الخادم تحت الزمن الافتراضي متردداً على هذا المضيف فيملكه
      // العميل المباشر داخل الشاهد نفسه بذات النمط
      final (pageServer, bridge, protection, pagePort, bridgePort, token) =
          await channelLab(secure: true);
      addTearDown(pageServer.close);
      addTearDown(bridge.stop);
      addTearDown(protection.dispose);
      // القصة السلبية: الصفحة عامة والقناة الحلقية تحتاج الإذن — المتصفح
      // يحجب فلا فتحة قناة ولا إطار يعبر إلى الصفحة
      final blocked = _flat(
        await _dumpDom(
          'https://127.0.0.1:$pagePort/',
          'j14-lna-https-blocked-dom.txt',
          extraArgs: [
            '--ignore-certificate-errors',
            '--ip-address-space-overrides=127.0.0.1:$pagePort=public',
          ],
          virtualTimeBudgetMs: 60000,
        ),
      );
      expect(
        blocked,
        contains('LAB-CHANNEL-PAGE:https://127.0.0.1:$pagePort\n'),
        reason:
            'the page really served over https - the story is the https '
            'origin reaching the loopback channel',
      );
      expect(
        blocked,
        isNot(contains('LAB-WS-OPEN\n')),
        reason:
            'no upgrade crossed: the public-mapped page needs the '
            'local-network-access permission to open the loopback '
            'channel and headless grants none',
      );
      // الحكم السلبي القارئ: المتصفح نفسه أوقف القناة — الخطأ ثم الإغلاق
      // 1006 (رمز الاتصال الذي لم يُفتح أبداً) لا أي إطار من الجسر
      expect(
        blocked,
        contains('LAB-WS-ERROR\n'),
        reason:
            'the browser itself stopped the channel: the connection '
            'errored before any handshake crossed',
      );
      expect(
        blocked,
        contains('LAB-WS-CLOSE:1006:\n'),
        reason:
            'the close carries the never-opened code with an empty '
            'reason - the block happened inside the browser',
      );
      expect(
        blocked,
        isNot(contains('\nLAB-WS-FRAME:')),
        reason:
            'no channel frame reached the page while the send was blocked '
            '(the newline anchors the verdict line, not the page source)',
      );
      // الجسر نفسه سليم: الطرف المحلي المباشر يقرأ رده فيفسح الحكم أن
      // الحاجز فحص المتصفح لا علة في الجسر (نمط التحكم في سيناريو
      // Local Network Access أعلاه)
      final (status, body, _) = await _send(
        bridgePort,
        origin: 'https://127.0.0.1:$pagePort',
        headers: {'X-Bridge-Token': token},
      );
      expect(status, 200, reason: 'the bridge answers the local direct party');
      expect(body, contains('"ok":true'));
      // القصة الموجبة: الإذن مُحاكى بالمفتاح ذاته على نقطة الجسر — الفحص
      // لم يعُد ينطبق فتعبر المصافحة بوابات القبول (الأصل المدرج https ثم
      // الترقية) وتقرأ الصفحة إطار الرفض الحرفي وإغلاقه
      final crossed = _flat(
        await _dumpDom(
          'https://127.0.0.1:$pagePort/',
          'j14-lna-https-crossed-dom.txt',
          extraArgs: [
            '--ignore-certificate-errors',
            '--ip-address-space-overrides=127.0.0.1:$bridgePort=public',
          ],
          virtualTimeBudgetMs: 60000,
        ),
      );
      expect(
        crossed,
        contains('LAB-WS-OPEN\n'),
        reason:
            'the handshake crossed the origin gates from the https page '
            'to the loopback channel',
      );
      expect(
        crossed,
        contains('LAB-WS-FRAME:{"ok":false,"error":"ws_auth_timeout"'),
        reason:
            'the channel refusal frame crossed to the page and was read '
            'by its onmessage - the literal code rides the frame',
      );
      expect(
        crossed,
        contains('LAB-WS-CLOSE:1008:ws_auth_timeout\n'),
        reason:
            'the close carries the policy code and the literal code '
            'as its reason',
      );
      expect(crossed, contains('LAB-WS-DONE\n'));
      expect(
        crossed,
        isNot(contains('LAB-WS-ERROR\n')),
        reason: 'the crossing run never errored',
      );
      // والقصة الكاملة من الطرف المباشر على الجسر نفسه: الاعتماد بأول
      // رسالة ثم الأمر وردّه — كما في شاهد قناة http المواطن
      final ws = await WebSocket.connect(
        'ws://127.0.0.1:$bridgePort/ws',
        headers: {'Origin': 'https://127.0.0.1:$pagePort'},
      ).timeout(const Duration(seconds: 5));
      final replies = <String>[];
      final replied = Completer<void>();
      late final StreamSubscription sub;
      sub = ws.listen(
        (m) {
          replies.add(m as String);
          if (!replied.isCompleted) replied.complete();
        },
        onDone: () {
          if (!replied.isCompleted) replied.complete();
        },
        onError: (Object _) {
          if (!replied.isCompleted) replied.complete();
        },
      );
      ws.add(jsonEncode({'token': token, 'correlationId': 'lab-ws-lna-1'}));
      ws.add(jsonEncode(['BROWSER-WS-HTTPS']));
      await replied.future.timeout(const Duration(seconds: 5));
      unawaited(sub.cancel());
      expect(
        replies.single,
        contains('"ok":true'),
        reason:
            'the credential opened the channel and the command reply '
            'crossed it',
      );
      expect(replies.single, contains('"echo":true'));
      await ws.close();
    },
    skip: _browserMajor == null || _browserMajor! < 146
        ? 'the https Local Network Access story is not run below '
              'browser version 146 until a run below it is proven: no '
              'usable browser, or one below the proven floor'
        : null,
  );

  // مختبر Firefox على عميل WebDriver نفسه: المشاهد التي يجريها كروم
  // بـ--dump-dom تجري هنا على Firefox بلا واجهة عبر geckodriver،
  // والسجل المقروء هو سجل الصفحة نفسها (pre#lab-results) — لا dump-dom
  // في فايرفوكس. وما لا ينطبق على فايرفوكس يتخطى بسبب مسمّى: محاكاة
  // إذن الشبكة المحلية علم كرومي لا نظير له هنا.
  // باب المشهد الفايرفوكسي: التخطي الافتراضي سببه هو غياب الثنائي
  // الفايرفوكسي (سلوك الجهاز المحلي الصادق)، وصورة المهمة تحمل
  // المتصفحين فلا تخطي فيها
  void firefoxScene(
    String name,
    Future<void> Function() body, {
    String? skip,
  }) =>
      test(name, body, skip: skip ?? _firefoxSkipReason, timeout: _sceneBudget);

  // جولة WebDriver واحدة لكل مشهد فايرفوكس: geckodriver ثم جلسة بلا
  // واجهة، والنسخة تُطبع من قدرات الجلسة فيسمّي كل سطر تشغيل فايرفوكس
  // الذي جرى عليه
  Future<WebDriverClient> firefoxDriver() async {
    final client = await WebDriverClient.spawn(executable: _geckoDriverPath!);
    addTearDown(client.shutdown);
    final session = await client.newSession(<String, Object?>{
      'browserName': 'firefox',
      'moz:firefoxOptions': <String, Object?>{
        'args': <String>['-headless'],
      },
    });
    print(
      'LAB-FIREFOX-SESSION: ${session.browserName} '
      '${session.browserVersion}',
    );
    return client;
  }

  // جولة الصفحة الفايرفوكسية: تنقّل، وانتظار سجل الصفحة حتى علامته
  // المنتهية، ثم قراءته كامل الدليل — سجل المتصفح الوحد بين المشغّلين
  Future<String> driveLog(
    WebDriverClient client,
    String url,
    String evidenceFile, {
    required String untilContains,
  }) async {
    final stopwatch = Stopwatch()..start();
    await client.setTimeouts();
    await client.navigate(url);
    final log = await client.waitForElementText(
      '#lab-results',
      untilContains: untilContains,
    );
    print('LAB-RUN: $evidenceFile ${stopwatch.elapsed.inMilliseconds} ms');
    final dir = Platform.environment['BRIDGE_LAB_EVIDENCE_DIR'];
    if (dir != null && dir.trim().isNotEmpty) {
      Directory(dir).createSync(recursive: true);
      File('$dir/$evidenceFile').writeAsStringSync(log);
    }
    return log;
  }

  firefoxScene('on Firefox the token-only bridge keeps the token as the '
      'only wire door: the browser page cannot cross it (nothing is '
      'echoed)', () async {
    final (pageServer, admitted, _, pagePort, admittedPort, _, token) =
        await lab(tokenOnlyAdmitted: true);
    addTearDown(pageServer.close);
    addTearDown(admitted.stop);
    final client = await firefoxDriver();
    final log = _flat(
      await driveLog(
        client,
        'http://127.0.0.1:$pagePort/',
        'ff-token-only-log.txt',
        untilContains: 'LAB-UNPAIRED:',
      ),
    );
    expect(
      log,
      contains('LAB-TOKENED:THREW\n'),
      reason:
          'a token-only bridge echoes nothing, so the Firefox page blocks '
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
  });

  firefoxScene('on Firefox the unpaired page is refused: the browser sees '
      'no verdict while the wire carries the literal code', () async {
    final (pageServer, _, defaultBridge, pagePort, _, defaultPort, _) =
        await lab();
    addTearDown(pageServer.close);
    addTearDown(defaultBridge.stop);
    final client = await firefoxDriver();
    final log = _flat(
      await driveLog(
        client,
        'http://127.0.0.1:$pagePort/',
        'ff-unpaired-log.txt',
        untilContains: 'LAB-UNPAIRED:',
      ),
    );
    final unpairedLines = RegExp(
      '^LAB-UNPAIRED:.*\$',
      multiLine: true,
    ).allMatches(log).map((m) => m.group(0)!).toList();
    expect(
      unpairedLines,
      ['LAB-UNPAIRED:BLOCKED-NO-VERDICT'],
      reason:
          'the blocked verdict is the ONLY line carrying the prefix - a '
          'readable refusal for an unpaired origin would be a recon '
          'channel the protection must never open',
    );
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
  });

  firefoxScene('on Firefox the preflight round trip announces the token '
      'header and the echo carries the new name alone', () async {
    final (pageServer, admitted, _, pagePort, admittedPort, _, _) = await lab();
    addTearDown(pageServer.close);
    addTearDown(admitted.stop);
    final client = await firefoxDriver();
    final log = _flat(
      await driveLog(
        client,
        'http://127.0.0.1:$pagePort/',
        'ff-preflight-log.txt',
        untilContains: 'LAB-UNPAIRED:',
      ),
    );
    expect(
      log,
      contains('LAB-OPTIONS:204:cors\n'),
      reason: 'the preflight endpoint answers the page origin on Firefox',
    );
    expect(
      log,
      contains('LAB-NOPREFLIGHT:BLOCKED-BY-PREFLIGHT\n'),
      reason:
          'a header the bridge never allows is stopped by the '
          'browser itself - the preflight is really consulted',
    );
    expect(
      log,
      isNot(contains('LAB-NOPREFLIGHT:2')),
      reason: 'the not-allowed-header call never crossed',
    );
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
      reason: 'the allowed-header list carries the standing names alone',
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
  });

  firefoxScene('on Firefox the paired page pairs with the displayed code, '
      'signs its command, and reads the reply; the replay and the '
      'proofless page are refused', () async {
    final (pageServer, admitted, _, pagePort, admittedPort, _, token) =
        await lab(pairedAdmitted: true);
    addTearDown(pageServer.close);
    addTearDown(admitted.stop);
    final client = await firefoxDriver();
    final log = _flat(
      await driveLog(
        client,
        'http://127.0.0.1:$pagePort/',
        'ff-paired-log.txt',
        untilContains: 'LAB-STRICT-BARE:',
      ),
    );
    expect(
      log,
      contains('LAB-PAIRED:200:true\n'),
      reason:
          'the Firefox page pairs with the displayed code, signs with '
          'WebCrypto, and reads its command reply',
    );
    expect(
      log,
      contains('LAB-PAIRED-REPLAY:403:pair_signature_replay\n'),
      reason: 'the same signature never proves twice, read by the browser',
    );
    expect(
      log,
      contains('LAB-STRICT-BARE:403:token_required\n'),
      reason:
          'the same page without its proof reads the honest strict '
          'refusal and retries from it',
    );
    final (forgedStatus, forgedBody, forgedHeaders) = await _send(
      admittedPort,
      origin: 'http://127.0.0.1:$pagePort',
    );
    expect(forgedStatus, 403);
    expect(forgedBody, contains('"error":"token_required"'));
    expect(
      forgedHeaders['access-control-allow-origin'],
      'http://127.0.0.1:$pagePort',
      reason: 'the qualified origin reads its refusal to retry with a proof',
    );
    final (sharedStatus, sharedBody, _) = await _send(
      admittedPort,
      origin: 'http://127.0.0.1:$pagePort',
      headers: {'X-Bridge-Token': token},
    );
    expect(sharedStatus, 200, reason: 'the shared token stays a valid proof');
    expect(sharedBody, contains('"ok":true'));
  });

  firefoxScene('on Firefox the paired page reports its verdicts through '
      'the collector: the channel the emulator witness reads, on a '
      'second engine', () async {
    final collected = <Map<String, Object?>>[];
    final (pageServer, admitted, _, pagePort, _, _, _) = await lab(
      pairedAdmitted: true,
      collectedReports: collected,
    );
    addTearDown(pageServer.close);
    addTearDown(admitted.stop);
    final client = await firefoxDriver();
    await driveLog(
      client,
      'http://127.0.0.1:$pagePort/?report=1',
      'ff-paired-report-log.txt',
      untilContains: 'LAB-REPORTED',
    );
    for (var i = 0; i < 20 && collected.isEmpty; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(collected, hasLength(1), reason: 'the page reported exactly once');
    final marks = (collected.single['marks'] as List).cast<String>();
    expect(
      marks,
      contains('LAB-PAIRED:200:true'),
      reason: 'the collector received the whole paired story',
    );
    expect(marks, contains('LAB-PAIRED-REPLAY:403:pair_signature_replay'));
    expect(marks, contains('LAB-STRICT-BARE:403:token_required'));
  });

  firefoxScene('on Firefox the streaming reply runs: three progress frames '
      'then the result frame, in the arrival order the page reads', () async {
    final (pageServer, bridge, protection, pagePort, _, _) = await channelLab();
    addTearDown(pageServer.close);
    addTearDown(bridge.stop);
    addTearDown(protection.dispose);
    final client = await firefoxDriver();
    final log = _flat(
      await driveLog(
        client,
        'http://127.0.0.1:$pagePort/',
        'ff-stream-log.txt',
        untilContains: 'LAB-CHANNEL-END',
      ),
    );
    expect(
      log,
      contains('LAB-STREAM-CTYPE:text/event-stream'),
      reason: 'the opted-in command reads the streaming media type',
    );
    expect(
      log,
      contains('LAB-STREAM-ORDER:progress,progress,progress,result'),
      reason: 'three progress frames then the result, in order',
    );
    expect(
      log,
      contains('LAB-STREAM-FRAME:0:progress|{"step":1}'),
      reason: 'the first progress frame crossed intact',
    );
    expect(
      log,
      contains('LAB-STREAM-FRAME:3:result|{"ok":true,"data":{"echo":true}}'),
      reason: 'the final frame carries the standing reply contract',
    );
    expect(
      log,
      isNot(contains('LAB-STREAM:THREW\n')),
      reason:
          'the streaming fetch never threw (the newline anchors the '
          'verdict line, not the page source)',
    );
  }, skip: _firefoxSkipReason ?? _firefoxChannelSkip);

  firefoxScene('on Firefox ws://127.0.0.1 from a real page: the handshake '
      'upgrades through the origin gates and the channel refusal frame '
      'crosses with its policy close', () async {
    final (pageServer, bridge, protection, pagePort, _, _) = await channelLab();
    addTearDown(pageServer.close);
    addTearDown(bridge.stop);
    addTearDown(protection.dispose);
    final client = await firefoxDriver();
    final log = _flat(
      await driveLog(
        client,
        'http://127.0.0.1:$pagePort/',
        'ff-ws-log.txt',
        untilContains: 'LAB-CHANNEL-END',
      ),
    );
    expect(
      log,
      contains('LAB-WS-OPEN\n'),
      reason:
          'the Firefox page opened the loopback WebSocket over the '
          'origin-gated handshake',
    );
    expect(
      log,
      contains('LAB-WS-FRAME:{"ok":false,"error":"ws_auth_timeout"'),
      reason:
          'the channel refusal frame crossed to the page and was '
          'read by its onmessage - the literal code rides the frame',
    );
    expect(
      log,
      contains('LAB-WS-CLOSE:1008:ws_auth_timeout\n'),
      reason:
          'the close carries the policy code and the literal code '
          'as its reason',
    );
    expect(log, contains('LAB-WS-DONE\n'));
    expect(
      log,
      isNot(contains('LAB-WS-ERROR\n')),
      reason: 'the channel never errored',
    );
    expect(
      log,
      isNot(contains('LAB-WS-TIMEOUT\n')),
      reason: 'the exchange crossed without exhausting the wait',
    );
  }, skip: _firefoxSkipReason ?? _firefoxChannelSkip);

  firefoxScene(
    'on Firefox the page cannot stream a request body below the '
    'engine floor: observed and printed, the control crossing on the '
    'same browser',
    () async {
      // الملاحظة 4.5: الجسم المتدفق سلوك محرك لا قانون — كروم يرفضه على
      // HTTP/1.x (شاهد كروم أعلاه)، وفايرفوكس من 161 فأعلى هو المدى
      // الذي تُرى فيه محاولة الإرسال الفعلية. المشهد هنا مُشغِّل ومطبِع:
      // حكم كل محاولة يُطبع في السجل (FIREFOX-STREAMBODY) ليُقرأ من خرج
      // المهمة ويُكتب حيث يُوثَّق، والشاهد الموجب الوحيد المشروط هو
      // الشاهد الموجب (الجسم العادي يعبر) ودخول أمرٍ إلى المعالج
      var entered = 0;
      final (pageServer, admitted, _, pagePort, _, _, _) = await lab(
        onCommand: () => entered++,
      );
      addTearDown(pageServer.close);
      addTearDown(admitted.stop);
      final client = await firefoxDriver();
      final log = _flat(
        await driveLog(
          client,
          'http://127.0.0.1:$pagePort/stream-body',
          'ff-stream-body-log.txt',
          untilContains: 'LAB-STREAMBODY-SIMPLE:',
        ),
      );
      final verdicts = RegExp(
        r'^LAB-STREAMBODY-(PREFLIGHT|SIMPLE):.*$',
        multiLine: true,
      ).allMatches(log).map((m) => m.group(0)!).toList()..sort();
      expect(verdicts, hasLength(2), reason: 'both attempts report a verdict');
      for (final verdict in verdicts) {
        print('FIREFOX-STREAMBODY: $verdict');
      }
      print('FIREFOX-STREAMBODY-HANDLER-ENTRIES: $entered');
      expect(
        log,
        contains('LAB-STREAMBODY-CONTROL:READ:200:ok\n'),
        reason:
            'the control must cross on this browser - without it the two '
            'streaming verdicts would prove nothing',
      );
      expect(
        entered,
        greaterThanOrEqualTo(1),
        reason: 'the control command reached the handler on the wire',
      );
    },
    skip:
        _firefoxSkipReason ??
        ((_firefoxMajor ?? 0) >= 161
            ? null
            : 'the streamed request body scene runs on Firefox from engine '
                  'version 161 - below it the browser ships no streamed '
                  'request body at all, and the rows below stay for the '
                  'emulator runs'),
  );

  firefoxScene(
    'on Firefox a page Chrome maps to public cannot reach the loopback '
    'bridge without the Local Network Access permission',
    () async {
      fail('this scene never runs: it exists to carry its named skip');
    },
    skip:
        'the Local Network Access pair simulates the Chrome-only '
        'address-space override flag (--ip-address-space-overrides); '
        'Firefox carries no such flag, so the pair stays a Chrome scene '
        'here',
  );

  firefoxScene(
    'on Firefox ws://127.0.0.1 from an https page without the Local '
    'Network Access permission',
    () async {
      fail('this scene never runs: it exists to carry its named skip');
    },
    skip:
        'the https Local Network Access story is the same Chrome-only '
        'simulation - Firefox carries no equivalent flag, so it stays a '
        'Chrome scene here',
  );

  // قطع النظير داخل مصافحة TLS مع خادم الصفحة الآمن: المتصفح الهامشي
  // يُقتل بانتهاء التفريغ فتُغلق مقابسه وهي داخل المصافحة بإعادة
  // تعيين (كروم يفتح اتصالات استباقية مع الأصل نفسه). المستمع الآمن
  // يبلغ هذا القطع خطأً في المقبس لا استثناء مصافحة، وطبقة HTTP تمرر
  // إلى تدفق الطلبات كل ما ليس استثناء مصافحة — فبلا onError على
  // المستمع يصل منطقة الاختبار خطأً غير معالج يسقط الشاهد. القطع هنا
  // حتمي بالطريقة نفسها: عميل لا يقرأ رحلة الخادم أبداً، وإغلاق مقبس
  // فيه بيانات غير مقروءة يرسل إعادة تعيين لا FIN
  test(
    'a client that resets inside the TLS handshake with the lab page '
    'server never fails the lab',
    () async {
      final (pageServer, bridge, protection, pagePort, _, _) = await channelLab(
        secure: true,
      );
      addTearDown(pageServer.close);
      addTearDown(bridge.stop);
      addTearDown(protection.dispose);
      final hello = await captureClientHello();
      final seenBefore = pageListenerErrors.length;
      // مهل متزايدة: رحلة الخادم يجب أن تكون وصلت غير مقروءة قبل إغلاق
      // العميل وإلا كان الإغلاق FIN عادياً فلا إعادة تعيين تُرسل
      for (final waitMs in const [40, 80, 160, 320, 640, 1280]) {
        final s = await Socket.connect(InternetAddress.loopbackIPv4, pagePort);
        s.add(hello);
        await s.flush();
        await Future<void>.delayed(Duration(milliseconds: waitMs));
        s.destroy();
        for (var i = 0; i < 20; i++) {
          await Future<void>.delayed(const Duration(milliseconds: 50));
          if (pageListenerErrors.length > seenBefore) break;
        }
        if (pageListenerErrors.length > seenBefore) break;
      }
      final seen = pageListenerErrors.skip(seenBefore).toList();
      // ويندوز يبلغ القطع ذاته إنهاءً للمصافحة فتسقطه طبقة HTTP قبل أن
      // يراه المستمع — فالنصف الموجب على مشغلات POSIX وحدها، ونصف الغياب
      // (لا خطأ غير معالج يسقط الشاهد) نافذ على كل منصة
      if (!Platform.isWindows) {
        expect(
          seen,
          isNotEmpty,
          reason:
              'the cut really reached the page server: its listener saw '
              'the reset - a witness that only checks absence proves nothing',
        );
        expect(
          seen.every(
            (e) => e is SocketException && e.toString().contains('reset'),
          ),
          isTrue,
          reason: 'the listener errors are the peer resets, nothing else',
        );
      }
      // والخادم يخدم مصافحة كاملة بعد القطع
      final client = HttpClient()
        ..badCertificateCallback = (cert, host, port) => true;
      try {
        final res = await client
            .getUrl(Uri.parse('https://127.0.0.1:$pagePort/'))
            .then((r) => r.close())
            .timeout(const Duration(seconds: 5));
        expect(
          res.statusCode,
          200,
          reason: 'the page server still serves a full handshake',
        );
        await res.drain<void>();
      } finally {
        client.close(force: true);
      }
    },
    skip: LocalIntakeServer.wsTransportCeilingSupported
        ? null
        : 'the lab page server this cut rides is the channel lab, which '
              'needs Dart 3.13 to arm',
    timeout: const Timeout(Duration(seconds: 60)),
  );

  test('every browser scene runs under one budget, and the budget outlives the '
      'whole wait of each browser run', () {
    // الشاهد يقرأ مصدر هذا الملف بلا متصفح: علاقة السقوف بعضها ببعض
    // (سقف انتظار الجولة فوق سقف الالتقاط، والميزانية فوق انتظار
    // جولتي أكبر مشهد)، وأن المعين يسلّم السقفين ثابتين لا رقمين
    // مكتوبين، وأن الباب يسلّم الميزانية لكل مشهد، وأن كل جولة متصفح
    // في الملف داخل مشهد أُعلن بالباب — فأي مشهد جديد بلا الباب، أو
    // برقم مكتوب مكان الثابت، أو بثلاث جولات فوق الميزانية، يُسقط
    // الشاهد قبل أن يصل إلى مشغّل
    expect(_browserRunWait, greaterThan(_browserCaptureCeiling));
    expect(
      _sceneBudget.duration,
      greaterThanOrEqualTo(_browserRunWait * 2),
      reason:
          'the budget covers two whole browser runs, the most any '
          'scene waits for',
    );
    final source = File('test/browser_lab_test.dart').readAsLinesSync();
    final mainAt = source.indexWhere((line) => line == 'void main() {');
    expect(mainAt, greaterThan(0), reason: 'the lab entry point is found');
    final helpers = source.take(mainAt).join('\n');
    expect(
      helpers,
      contains("'--timeout=\${_browserCaptureCeiling.inMilliseconds}'"),
      reason: 'the browser is handed the capture ceiling constant itself',
    );
    expect(
      helpers,
      contains('.timeout(_browserRunWait)'),
      reason: 'the browser run is waited on with its own ceiling constant',
    );
    expect(
      helpers,
      matches(RegExp(r'timeout:\s*_sceneBudget\b')),
      reason: 'the scene door hands every scene the budget',
    );
    final opening = RegExp(r'^  (test|scene)\(');
    final runCall = RegExp(r'_dumpDom\(');
    final blocks = <List<String>>[];
    for (final line in source) {
      if (opening.hasMatch(line)) blocks.add(<String>[]);
      if (blocks.isNotEmpty) blocks.last.add(line);
    }
    var runsInScenes = 0;
    for (final block in blocks) {
      final runs = block.fold<int>(
        0,
        (count, line) => count + runCall.allMatches(line).length,
      );
      if (runs == 0) continue;
      runsInScenes += runs;
      final declaration = block.first.trim();
      final door = opening.firstMatch(block.first)!.group(1);
      expect(
        door,
        'scene',
        reason:
            'the declaration "$declaration" waits for $runs browser '
            'run(s): only the scene door budgets a browser scene - a '
            'plain test runs under the default 30 seconds, below what '
            'one browser run may legally take',
      );
      expect(
        runs,
        lessThanOrEqualTo(2),
        reason:
            'the declaration "$declaration" waits for $runs browser '
            'runs and the budget covers two: widen the budget first',
      );
    }
    final runsInFile = source.fold<int>(
      0,
      (count, line) => count + runCall.allMatches(line).length,
    );
    expect(
      runsInFile - runsInScenes,
      1,
      reason:
          'every browser run in this file sits inside a declaration '
          'opened at the scene door - the single run outside them is '
          'the helper declaration',
    );
  });
}
