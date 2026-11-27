// مختبر Safari الحقيقي: safaridriver يقود Safari الفعلي على macOS عبر
// بروتوكول W3C WebDriver، وعميل test/support/webdriver_client.dart هو
// الطرف الوحيد الذي يتكلم معه — بلا أي اعتمادية. الخادم dart:io وحده:
// خادم صفحة https بشهادة حلقة، وجسور LocalIntakeServer على نقل TLS
// (الأمر عبر HTTPS على الحلقة، وpreflight من أصل مدرج، والقناة wss)،
// ولكل مشهد مشهد ضابط يثبت أن الفحص يرى الرفض: توكن خاطئ أو أصل غير
// مدرج — فلا يُحسب المشهد أخضر لأن المتصفح لم يرسل شيئاً.
//
// الحدود الصادقة (تُطبع كأسباب تخطٍّ مسمّاة ولا تُخفى):
// - safaridriver macOS حصراً: على سواه يتخطى المختبر كله بسبب مسمّى.
// - الشهادة لا تولَّد هنا: ملفَّا PEM بمساري البيئة BRIDGE_SAFARI_TLS_CERT
//   وBRIDGE_SAFARI_TLS_KEY (SAN للـ127.0.0.1) — مهمة CI safari-lab تولّد
//   شهادة الاختبار داخلها وتوثقها في سلسلة مفاتيح مؤقتة تُحذف في نهايتها،
//   وصاحب الجهاز يمرر شهادته الموثقة في Keychain محلياً. بلا الشهادة
//   يتخطى المختبر بسبب مسمّى.
// - safaridriver يقود Safari بنافذة حقيقية (لا وضع بلا واجهة له)، وفتح
//   الأتمتة خطوة نظامية واحدة قبل التشغيل: sudo safaridriver --enable.
// - سجل المتصفح الذي يقرؤه الشاهد هو سجل الصفحة نفسها (pre#lab-results
//   الذي تكتب فيه علامات LAB-SAFARI-*) — المواصفة لا توحد نقطة سجل وحدة
//   تحكم، وسجل الصفحة هو الوحد بين safaridriver وgeckodriver.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

import 'support/webdriver_client.dart';

// مشغّل Safari: الاسم المعتاد على PATH، وتجاوز صريح بمسار البيئة
final String _safariDriverExecutable =
    Platform.environment['BRIDGE_SAFARI_DRIVER']?.trim().isNotEmpty == true
    ? Platform.environment['BRIDGE_SAFARI_DRIVER']!.trim()
    : 'safaridriver';

String? _envFile(String name) {
  final value = Platform.environment[name]?.trim();
  if (value == null || value.isEmpty) return null;
  return value;
}

// ملفا شهادة الاختبار الحلقية من البيئة حصراً — لا توليد ولا كتابة هنا
final String? _certPath = _envFile('BRIDGE_SAFARI_TLS_CERT');
final String? _keyPath = _envFile('BRIDGE_SAFARI_TLS_KEY');

// سبب التخطي الصادق على مستوى الملف، أو null فيعمل المختبر فعلاً
final String? _skipReason = () {
  if (!Platform.isMacOS) {
    return 'safaridriver is macOS-only - this host is '
        '${Platform.operatingSystem}; the safari lab runs in the CI '
        'safari-lab job on macos-latest';
  }
  if (_certPath == null || _keyPath == null) {
    return 'the safari lab needs a loopback TLS certificate: set '
        'BRIDGE_SAFARI_TLS_CERT and BRIDGE_SAFARI_TLS_KEY to a PEM pair '
        'whose SAN names 127.0.0.1 (the CI safari-lab job generates one '
        'into a temporary keychain; a local host passes its own '
        'Keychain-trusted pair) - nothing runs without it';
  }
  if (!File(_certPath!).existsSync() || !File(_keyPath!).existsSync()) {
    return 'the certificate file pair named by BRIDGE_SAFARI_TLS_CERT and '
        'BRIDGE_SAFARI_TLS_KEY does not exist on this host - the safari '
        'lab reads the certificate files, it never writes one';
  }
  return null;
}();

// سياق TLS من ملفَّي البيئة — يُبنى هنا فقط حين لا تخطٍّ
SecurityContext _tlsContext() => SecurityContext()
  ..useCertificateChain(_certPath!)
  ..usePrivateKey(_keyPath!);

// مشاهد القناة فوق سقف نقل القناة: على SDK لا يسلّح القناة بمهلة نقل
// لا مشهد قناة أصلاً (الرفض عند البناء)
final String? _channelSkipReason = LocalIntakeServer.wsTransportCeilingSupported
    ? null
    : 'the channel refuses to arm without a transport ceiling below '
          'Dart 3.13 - the channel scene rides the wss door';

// ميزانية المشهد الواحد: أول إقلاع لسفاري عبر safaridriver بطيء، ثم
// تنقل وقراءة سجل الصفحة — فوق ما يحتاجه أي مشهد من المشاهد
const Timeout _sceneBudget = Timeout(Duration(minutes: 4));

var _labIdSeq = 0;

/// The lab's correlation ids: short, distinct, honest to the wire contract
String _labCorrelationId() => 'safari-${_labIdSeq++}';

/// The lab fixture as one record: the https page server, the three TLS
/// bridges (admitted, stranger, channel) with their protections, the
/// ports, the page origin, and the shared token.
typedef _Lab = ({
  HttpServer page,
  LocalIntakeServer admitted,
  LocalIntakeServer stranger,
  LocalIntakeServer channel,
  IntakeProtection admittedProtection,
  IntakeProtection strangerProtection,
  IntakeProtection channelProtection,
  int pagePort,
  int admittedPort,
  int strangerPort,
  int channelPort,
  String pageOrigin,
  String token,
});

/// A completed wire exchange as the test reads it: status, body text, and
/// the response headers (names lowercased by HttpClient).
typedef _Exchange = (int status, String body, Map<String, String> headers);

/// Sends one request to an https loopback door with the lab certificate
/// accepted (the client-side counterpart of the keychain trust the page
/// already rides): the direct wire party of every scene.
Future<_Exchange> _send(
  int port, {
  String method = 'POST',
  String? origin,
  Map<String, String> headers = const {},
  String body = '["BROWSER-SAFARI"]',
}) async {
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) => true;
  try {
    // كل مرحلة من مراحل النداء السلكي محدودة ومسماة: فتح TLS ونهاية
    // الجسم كلاهما قد يعلقان على جسر حي فوق شهادة الاختبار — انقضاء
    // الحد يرمي الفشل المسمّى فلا انتظار بلا مهلة في مختبر سفاري
    const wireBound = Duration(seconds: 8);
    final request = await client
        .openUrl(method, Uri.parse('https://127.0.0.1:$port/'))
        .timeout(
          wireBound,
          onTimeout: () => throw WebDriverWaitTimeout(
            'lab wire call $method 127.0.0.1:$port (connect)',
            wireBound,
            'the bridge answers',
          ),
        );
    if (origin != null) request.headers.set('Origin', origin);
    headers.forEach(request.headers.set);
    if (method == 'POST') {
      request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      request.headers.set('Sec-Fetch-Mode', 'cors');
      request.headers.set('Sec-Fetch-Dest', 'empty');
      request.add(utf8.encode(body));
    }
    final response = await request.close().timeout(
      wireBound,
      onTimeout: () => throw WebDriverWaitTimeout(
        'lab wire call $method 127.0.0.1:$port (response)',
        wireBound,
        'the response headers arrive',
      ),
    );
    final text = await utf8.decoder
        .bind(response)
        .join()
        .timeout(
          wireBound,
          onTimeout: () => throw WebDriverWaitTimeout(
            'lab wire call $method 127.0.0.1:$port (body)',
            wireBound,
            'the response body ends',
          ),
        );
    final flat = <String, String>{};
    response.headers.forEach((name, values) {
      flat[name.toLowerCase()] = values.join(', ');
    });
    return (response.statusCode, text, flat);
  } finally {
    client.close(force: true);
  }
}

/// The main lab page: an https page on a real loopback origin (a different
/// origin than each bridge - the ports differ), so every call crosses real
/// CORS machinery over real TLS. Four verdicts: the tokened command, the
/// wrong-token control, the explicit preflight, and the stranger send the
/// browser must block.
String _labPage({
  required int admittedPort,
  required int strangerPort,
  required String token,
}) =>
    '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>localhost_bridge safari lab</title></head>
<body>
<pre id="lab-results"></pre>
<script>
'use strict';
const ADMITTED = 'https://127.0.0.1:$admittedPort';
const STRANGER = 'https://127.0.0.1:$strangerPort';
const TOKEN = '$token';
const results = document.getElementById('lab-results');
function mark(line) { results.textContent += line + '\\n'; }

async function postJson(bridge, extraHeaders) {
  const headers = Object.assign({'Content-Type': 'application/json'},
                                extraHeaders);
  return fetch(bridge, {method: 'POST', headers, body: '["BROWSER-SAFARI"]'});
}

(async () => {
  mark('LAB-SAFARI-PAGE-ORIGIN:' + location.origin);
  // الأمر عبر HTTPS على الحلقة: ترويسة التوكن تجبر preflight أولاً،
  // فالحكم المقروء هنا لا يُبلغ إلا إذا عبر الـpreflight فعلاً
  try {
    const res = await postJson(ADMITTED, {
      'X-Bridge-Token': TOKEN,
      'X-Correlation-Id': 'safari-lab-1',
    });
    const body = await res.json().catch(() => null);
    mark('LAB-SAFARI-TOKENED:' + res.status + ':' +
         (body && body.ok === true ? 'true' : 'false') + ':' +
         (body && body.error ? body.error : 'no-error'));
  } catch (browserError) {
    mark('LAB-SAFARI-TOKENED:THREW');
  }
  // الضابط: التوكن الخاطئ — الرفض الحرفي المقروء يثبت أن الفحص يرى
  // الرفض لا القبول وحده
  try {
    const res = await postJson(ADMITTED, {
      'X-Bridge-Token': 'wrong-token-value-wrong-token-value12',
      'X-Correlation-Id': 'safari-lab-2',
    });
    const body = await res.json().catch(() => null);
    mark('LAB-SAFARI-BADTOKEN:' + res.status + ':' +
         (body && body.error ? body.error : 'no-error'));
  } catch (browserError) {
    mark('LAB-SAFARI-BADTOKEN:THREW');
  }
  // الـpreflight الصريح على الباب المقبول
  try {
    const res = await fetch(ADMITTED, {method: 'OPTIONS', mode: 'cors'});
    mark('LAB-SAFARI-PREFLIGHT:' + res.status + ':' + res.type);
  } catch (browserError) {
    mark('LAB-SAFARI-PREFLIGHT:THREW');
  }
  // الضابط الثاني: أصل الجسر غير المدرج — لا صدى على السلك فيحجب
  // المتصفح الإرسال نفسه، ولا حكم يُقرأ
  try {
    const res = await postJson(STRANGER, {});
    mark('LAB-SAFARI-STRANGER:' + res.status);
  } catch (browserError) {
    mark('LAB-SAFARI-STRANGER:BLOCKED');
  }
  mark('LAB-SAFARI-DONE');
})();
</script>
</body>
</html>
''';

/// The channel lab page: a wss handshake from an https page, authenticated
/// by the first message - the good run carries the shared token and reads
/// its command reply; the bad run carries a wrong token and reads the
/// literal refusal frame before the policy close. `?ws=bad` picks the bad
/// credential, the default is the good one.
String _channelPage({required int channelPort, required String token}) =>
    '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>localhost_bridge safari channel lab</title></head>
<body>
<pre id="lab-results"></pre>
<script>
'use strict';
const BRIDGE = 'wss://127.0.0.1:$channelPort';
const GOOD_TOKEN = '$token';
const BAD_TOKEN = 'wrong-token-value-wrong-token-value12';
const WHICH = new URLSearchParams(location.search).get('ws') === 'bad'
              ? BAD_TOKEN : GOOD_TOKEN;
const results = document.getElementById('lab-results');
let done = false;
function mark(line) { results.textContent += line + '\\n'; }
function finish(line) {
  if (done) return;
  if (line) mark(line);
  done = true;
  mark('LAB-SAFARI-WS-DONE');
}
const ws = new WebSocket(BRIDGE + '/ws');
ws.onopen = function () {
  mark('LAB-SAFARI-WS-OPEN');
  ws.send(JSON.stringify({token: WHICH, correlationId: 'safari-ws-1'}));
  ws.send(JSON.stringify(['BROWSER-SAFARI']));
};
ws.onmessage = function (e) {
  mark('LAB-SAFARI-WS-FRAME:' + e.data);
  try {
    const f = JSON.parse(e.data);
    if (f.ok === true) {
      mark('LAB-SAFARI-WS-REPLY:ok');
      ws.close();
    } else if (f.ok === false) {
      mark('LAB-SAFARI-WS-REPLY:refused:' + f.error);
    }
  } catch (parseError) {}
};
ws.onerror = function () { finish('LAB-SAFARI-WS-ERROR'); };
ws.onclose = function (e) {
  mark('LAB-SAFARI-WS-CLOSE:' + e.code + ':' + e.reason);
  finish(null);
};
setTimeout(function () { finish('LAB-SAFARI-WS-TIMEOUT'); }, 8000);
</script>
</body>
</html>
''';

/// The lab fixture: the https page server plus three TLS bridges on the
/// one lab certificate - the admitted one (listed origin + token, the
/// strict pair), the stranger one (nothing listed: the honest no-echo
/// refuser), and the channel one (wss, same origin list and token). The
/// page listener's own socket errors land in a recorder: a peer cut
/// inside a TLS handshake reaches the secure listener as a socket error,
/// and an unhandled one would crash the test zone.
Future<_Lab> _safariLab() async {
  final ctx = _tlsContext();
  final token = generateBridgeToken();
  final pageListenerErrors = <Object>[];

  // خادم الصفحة أولاً: أصل الصفحة يدخل قائمة كل جسر مقبول بعده
  final pageServer = await HttpServer.bindSecure(
    InternetAddress.loopbackIPv4,
    0,
    ctx,
  );
  final pageOrigin = 'https://127.0.0.1:${pageServer.port}';

  // الجسر المقبول: الأصل المدرج والتوكن معاً (الاقتران الصارم بلا طبقة
  // اقتران) — المؤهل بلا إثبات صالح يقرأ رفضه الصادق المقروء
  final admittedProtection = IntakeProtection(
    telemetry: const SilentTelemetry(),
  );
  admittedProtection.update(
    policy: OriginPolicy(allowed: [pageOrigin], requireOriginWithToken: true),
    token: token,
  );
  final admitted = LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: _labCorrelationId,
    protection: admittedProtection,
    config: BridgeConfig(securityContext: ctx),
  );
  final admittedPort = await admitted.start(preferredPort: 0);

  // جسر الغريب: لا قائمة ولا توكن — كل أصل غير مدرج والرفض بلا صدى
  final strangerProtection = IntakeProtection(
    telemetry: const SilentTelemetry(),
  );
  strangerProtection.update(policy: const OriginPolicy());
  final stranger = LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: _labCorrelationId,
    protection: strangerProtection,
    config: BridgeConfig(securityContext: ctx),
  );
  final strangerPort = await stranger.start(preferredPort: 0);

  // جسر القناة: الأصل المدرج والتوكن، والاعتماد بأول رسالة على wss
  final channelProtection = IntakeProtection(
    telemetry: const SilentTelemetry(),
  );
  channelProtection.update(
    policy: OriginPolicy(allowed: [pageOrigin]),
    token: token,
  );
  final channel = LocalIntakeServer(
    onCommand: (cmd) async =>
        const CommandOutcome(ok: true, data: {'echo': true}),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: _labCorrelationId,
    protection: channelProtection,
    config: BridgeConfig(
      securityContext: ctx,
      wsPath: '/ws',
      idleTimeout: const Duration(seconds: 2),
    ),
    wsAuthTimeout: const Duration(milliseconds: 1200),
  );
  final channelPort = await channel.start(preferredPort: 0);

  final html = _labPage(
    admittedPort: admittedPort,
    strangerPort: strangerPort,
    token: token,
  );
  final channelHtml = _channelPage(channelPort: channelPort, token: token);
  pageServer.listen((request) async {
    if (request.uri.path == '/channel') {
      request.response.headers.contentType = ContentType.html;
      request.response.write(channelHtml);
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
  }, onError: pageListenerErrors.add);

  return (
    page: pageServer,
    admitted: admitted,
    stranger: stranger,
    channel: channel,
    admittedProtection: admittedProtection,
    strangerProtection: strangerProtection,
    channelProtection: channelProtection,
    pagePort: pageServer.port,
    admittedPort: admittedPort,
    strangerPort: strangerPort,
    channelPort: channelPort,
    pageOrigin: pageOrigin,
    token: token,
  );
}

/// Stops the fixture completely: the page server, every bridge, and every
/// protection's own timers.
Future<void> _stopLab(_Lab lab) async {
  await lab.page.close();
  await lab.admitted.stop();
  await lab.stranger.stop();
  await lab.channel.stop();
  lab.admittedProtection.dispose();
  lab.strangerProtection.dispose();
  lab.channelProtection.dispose();
}

void main() {
  // عربة صفحة واحدة لكل مشهد: جلسة سفاري جديدة، تنقّل، وانتظار سجل
  // الصفحة حتى علامته المنتهية — والمدة تُعلن لكل جولة بسطرها
  Future<String> drivePage(
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
    final dir = Platform.environment['BRIDGE_LAB_EVIDENCE_DIR']?.trim();
    if (dir != null && dir.isNotEmpty) {
      // الدليل يُبنى إن لم يوجد: مطلب الدليل لا يُسقط إثبات المتصفح
      Directory(dir).createSync(recursive: true);
      File('$dir/$evidenceFile').writeAsStringSync(log);
    }
    return log;
  }

  // جولة سائق واحدة لكل مشهد: عزل المشهد بعزل السائق وجلسته، والنسخة
  // تُطبع من قدرات الجلسة فيسمّي كل سطر تشغيلٍ سفاري الذي جرى عليه
  Future<WebDriverClient> safariDriver() async {
    final client = await WebDriverClient.spawn(
      executable: _safariDriverExecutable,
    );
    addTearDown(client.shutdown);
    final session = await client.newSession(<String, Object?>{
      'browserName': 'safari',
    });
    print(
      'LAB-SAFARI-SESSION: ${session.browserName} '
      '${session.browserVersion}',
    );
    return client;
  }

  void scene(String name, Future<void> Function() body, {String? skip}) =>
      test(name, body, skip: skip ?? _skipReason, timeout: _sceneBudget);

  scene('a tokened command crosses HTTPS on loopback: the page sends over '
      'https and reads its honest reply', () async {
    final lab = await _safariLab();
    addTearDown(() => _stopLab(lab));
    final client = await safariDriver();
    final log = await drivePage(
      client,
      'https://127.0.0.1:${lab.pagePort}/',
      'safari-https-command-log.txt',
      untilContains: 'LAB-SAFARI-DONE',
    );
    expect(
      log,
      contains('LAB-SAFARI-PAGE-ORIGIN:https://127.0.0.1:${lab.pagePort}\n'),
      reason: 'the page really served over https on the loopback origin',
    );
    expect(
      log,
      contains('LAB-SAFARI-TOKENED:200:true:no-error\n'),
      reason:
          'the page crossed the https bridge with its token and read the '
          'standing reply - a readable verdict here is only reachable if '
          'the preflight crossed first',
    );
    // السلك من طرف الاختبار على الباب نفسه: التوكن الصحيح هو الباب
    final (status, body, _) = await _send(
      lab.admittedPort,
      origin: lab.pageOrigin,
      headers: {'X-Bridge-Token': lab.token},
    );
    expect(status, 200, reason: 'the correct token crosses the strict pair');
    expect(body, contains('"ok":true'));
  });

  scene('the https command check sees the rejection: a wrong token reads '
      'the literal refusal', () async {
    // الضابط لمشهد الأمر: الصفحة نفسها بتوكن خاطئ تقرأ الرفض الحرفي
    // المقروء (المؤهل يقرأ رفضه كي يعيد بالإثبات) — فلو كان المشهد
    // الأخضر لأن المتصفح لم يرسل شيئاً لَما كان هذا السطر ممكناً
    final lab = await _safariLab();
    addTearDown(() => _stopLab(lab));
    final client = await safariDriver();
    final log = await drivePage(
      client,
      'https://127.0.0.1:${lab.pagePort}/',
      'safari-https-badtoken-log.txt',
      untilContains: 'LAB-SAFARI-DONE',
    );
    expect(
      log,
      contains('LAB-SAFARI-BADTOKEN:403:token_required\n'),
      reason:
          'the wrong token reads the literal strict refusal - the check '
          'really distinguishes rejection from acceptance',
    );
    // والسلك يحمل الرفض نفسه بلا توكن أصلاً، بصدى الأصل الذي يجعل
    // الرفض قارئاً في الصفحة
    final (status, body, headers) = await _send(
      lab.admittedPort,
      origin: lab.pageOrigin,
    );
    expect(status, 403, reason: 'without the token the strict pair refuses');
    expect(body, contains('"error":"token_required"'));
    expect(
      headers['access-control-allow-origin'],
      lab.pageOrigin,
      reason: 'the qualified origin reads its refusal to retry with a proof',
    );
  });

  scene('the preflight announces the listed origin: the echo names the '
      'allowed headers with the token header alone', () async {
    final lab = await _safariLab();
    addTearDown(() => _stopLab(lab));
    final client = await safariDriver();
    final log = await drivePage(
      client,
      'https://127.0.0.1:${lab.pagePort}/',
      'safari-preflight-log.txt',
      untilContains: 'LAB-SAFARI-DONE',
    );
    expect(
      log,
      contains('LAB-SAFARI-PREFLIGHT:204:cors\n'),
      reason: 'the preflight endpoint answers the listed https page origin',
    );
    // الـpreflight الحقيقي كما يرسله المتصفح، والصدى بايتاً بايتاً
    final (status, _, headers) = await _send(
      lab.admittedPort,
      method: 'OPTIONS',
      origin: lab.pageOrigin,
      headers: {
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type, x-bridge-token',
      },
    );
    expect(status, 204);
    expect(
      headers['access-control-allow-origin'],
      lab.pageOrigin,
      reason: 'the preflight echo names the listed https origin',
    );
    expect(
      headers['access-control-allow-headers'],
      'Content-Type, X-Bridge-Token, X-Correlation-Id',
      reason: 'the allowed-header list carries the standing names alone',
    );
    expect(
      headers['access-control-allow-headers']!,
      isNot(contains('X-Portal-Token')),
      reason: 'the retired header name never returns through the echo',
    );
  });

  scene('the preflight check sees the stranger origin: no echo on the '
      'wire, and the browser blocks the unlisted send', () async {
    // الضابط لمشهد الـpreflight: أصل غير مدرج — بلا صدى على السلك،
    // والمتصفح نفسه يوقف الإرسال فلا حكم يُقرأ؛ فلو مُرّر المشهد
    // الأخضر بلا فحص لَما كان الحجب ممكناً
    final lab = await _safariLab();
    addTearDown(() => _stopLab(lab));
    final client = await safariDriver();
    final log = await drivePage(
      client,
      'https://127.0.0.1:${lab.pagePort}/',
      'safari-stranger-log.txt',
      untilContains: 'LAB-SAFARI-DONE',
    );
    expect(
      log,
      contains('LAB-SAFARI-STRANGER:BLOCKED\n'),
      reason:
          'the browser itself stopped the send to the unlisted bridge - '
          'no readable verdict, the block is real',
    );
    // وعلى السلك: الـpreflight للأصل الغريب بلا صدى أصلاً، والطلب نفسه
    // يُرد برمز عدم الإدراج الحرفي بلا صدى
    final (preflightStatus, _, preflightHeaders) = await _send(
      lab.strangerPort,
      method: 'OPTIONS',
      origin: lab.pageOrigin,
      headers: {'Access-Control-Request-Method': 'POST'},
    );
    expect(preflightStatus, 204);
    expect(
      preflightHeaders['access-control-allow-origin'],
      isNull,
      reason: 'the stranger origin earns no preflight echo at all',
    );
    final (status, body, headers) = await _send(
      lab.strangerPort,
      origin: lab.pageOrigin,
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

  scene('the channel carries an authenticated command and its reply over '
      'the wss handshake from the https page', () async {
    final lab = await _safariLab();
    addTearDown(() => _stopLab(lab));
    final client = await safariDriver();
    final log = await drivePage(
      client,
      'https://127.0.0.1:${lab.pagePort}/channel',
      'safari-channel-good-log.txt',
      untilContains: 'LAB-SAFARI-WS-DONE',
    );
    expect(
      log,
      contains('LAB-SAFARI-WS-OPEN\n'),
      reason:
          'the https page opened the loopback wss channel over the '
          'origin-gated handshake',
    );
    expect(
      log,
      contains('LAB-SAFARI-WS-FRAME:{"ok":true'),
      reason: 'the command reply frame crossed the channel to the page',
    );
    expect(log, contains('"echo":true'));
    expect(
      log,
      contains('LAB-SAFARI-WS-REPLY:ok\n'),
      reason: 'the page read the standing reply and closed from its side',
    );
    expect(
      log,
      contains('LAB-SAFARI-WS-CLOSE:1000:'),
      reason: 'the close after the reply is the page-owned normal close',
    );
    expect(log, contains('LAB-SAFARI-WS-DONE\n'));
    expect(
      log,
      isNot(contains('LAB-SAFARI-WS-ERROR\n')),
      reason:
          'the good story never errored (the newline anchors the '
          'verdict line, not the page source)',
    );
    // والقصة الكاملة من الطرف المباشر على القناة نفسها: الاعتماد بأول
    // رسالة ثم الأمر وردّه — اتجاه الصفحة إلى الخادم بلا وسيط
    final ws = await WebSocket.connect(
      'wss://127.0.0.1:${lab.channelPort}/ws',
      headers: {'Origin': lab.pageOrigin},
      customClient: HttpClient()
        ..badCertificateCallback = (cert, host, port) => true,
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
    ws.add(jsonEncode({'token': lab.token, 'correlationId': 'safari-ws-2'}));
    ws.add(jsonEncode(['BROWSER-SAFARI-DIRECT']));
    await replied.future.timeout(const Duration(seconds: 5));
    unawaited(sub.cancel());
    expect(
      replies.single,
      contains('"ok":true'),
      reason: 'the credential opened the channel and the reply crossed it',
    );
    expect(replies.single, contains('"echo":true'));
    await ws.close();
  }, skip: _skipReason ?? _channelSkipReason);

  scene('the channel check sees the rejection: a wrong credential closes '
      'the channel with the literal code', () async {
    // الضابط لمشهد القناة: أول رسالة بتوكن خاطئ — إطار الرفض الحرفي
    // ثم الإغلاق برمز السياسة؛ فقناة تقبل كل اعتماد تجعل المشهد الخضر
    // السابق كاذباً، وهذا السطران ما يمنعها
    final lab = await _safariLab();
    addTearDown(() => _stopLab(lab));
    final client = await safariDriver();
    final log = await drivePage(
      client,
      'https://127.0.0.1:${lab.pagePort}/channel?ws=bad',
      'safari-channel-bad-log.txt',
      untilContains: 'LAB-SAFARI-WS-DONE',
    );
    expect(
      log,
      contains('LAB-SAFARI-WS-OPEN\n'),
      reason:
          'the handshake itself crossed the origin gates - the refusal '
          'is the credential step, not the origin step',
    );
    expect(
      log,
      contains('LAB-SAFARI-WS-FRAME:{"ok":false,"error":"token_required"'),
      reason:
          'the literal refusal frame crossed to the page and was '
          'read by its onmessage',
    );
    expect(
      log,
      contains('LAB-SAFARI-WS-CLOSE:1008:token_required\n'),
      reason:
          'the close carries the policy code and the literal code '
          'as its reason',
    );
    expect(log, contains('LAB-SAFARI-WS-DONE\n'));
    // والسلك من الطرف المباشر: الاعتماد الخاطئ يقرأ الإغلاق نفسه
    final ws = await WebSocket.connect(
      'wss://127.0.0.1:${lab.channelPort}/ws',
      headers: {'Origin': lab.pageOrigin},
      customClient: HttpClient()
        ..badCertificateCallback = (cert, host, port) => true,
    ).timeout(const Duration(seconds: 5));
    final closed = Completer<int?>();
    late final StreamSubscription sub;
    sub = ws.listen(
      (_) {},
      onDone: () {
        if (!closed.isCompleted) closed.complete(ws.closeCode);
      },
      onError: (Object _) {
        if (!closed.isCompleted) closed.complete(ws.closeCode);
      },
    );
    ws.add(
      jsonEncode({
        'token': 'wrong-token-value-wrong-token-value12',
        'correlationId': 'safari-ws-3',
      }),
    );
    final code = await closed.future.timeout(const Duration(seconds: 5));
    unawaited(sub.cancel());
    expect(
      code,
      1008,
      reason: 'the direct wrong credential closes with the policy code',
    );
    expect(
      ws.closeReason,
      'token_required',
      reason: 'the close reason names the literal rejection code',
    );
  }, skip: _skipReason ?? _channelSkipReason);
}
