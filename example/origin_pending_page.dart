// مثال كامل لآلة حالة origin_pending — سؤال الموافقة من طرف إلى طرف:
// الانتظار ⟵ إعادة محاولة واحدة محترمة لـ Retry-After ⟵ منحة أو رفض.
//
// ملاحظة عن العنونة: مسار الاكتشاف يسأل الأصول https الصالحة حصراً، فصفحة
// تُخدم محلياً على http لا تعبر السؤال أصلاً (الحالة تعرض ذلك بصدق).
// الصفحة المخدومة هنا هي نص الآلة الجاهز للنسخ إلى بوابتك https، والجولة
// السلكية عند الإقلاع تسير الآلة نفسها على السلك من أصلين https تجريبيين
// كي ترى المنحة والرفض حيّين في الطرفية.
//
// شغّله من جذر الحزمة: dart run example/origin_pending_page.dart
// أو بلا مستخدم: dart run example/origin_pending_page.dart --self-check
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

// الإنسان التجريبي: أصل البوابة التجريبي يُجاب بمنحة-لمرة على سؤاله
// الأول بعد مهلة قصيرة ويرفض كل سؤال بعدها، وكل أصل آخر يُرفض من أول
// سؤال. حتمي كي تعرض الجولة المسارين: منحة ثم رفض.
const _humanAnswerDelay = Duration(milliseconds: 1100);
// نافذة السؤال (askTimeout) بمقاس هذا الإنسان التجريبي: أوسع من مهلة
// إجابته بحاشية، وأضيق بكثير من الافتراضي الذي يليق مضيفاً حياً
const _humanAskWindow = Duration(seconds: 3);
final _answersPerOrigin = <String, int>{};

Future<OriginConsent> _simulateHuman(String origin) async {
  final nth = (_answersPerOrigin[origin] ?? 0) + 1;
  _answersPerOrigin[origin] = nth;
  await Future<void>.delayed(_humanAnswerDelay);
  if (origin != _grantedDemoOrigin) return OriginConsent.reject;
  return nth == 1 ? OriginConsent.allowOnce : OriginConsent.reject;
}

// أصلان تجريبيان مجردان للجولة السلكية: الأول يُمنح والثاني يُرفض.
const _grantedDemoOrigin = 'https://portal.example';
const _refusedDemoOrigin = 'https://stranger.example';

void _state(String state, String detail) {
  final at = DateTime.now().toIso8601String().substring(11, 23);
  stdout.writeln('[$at] $state — $detail');
}

// جولة واحدة من الآلة على السلك: ترسل من أصل متصفح تجريبي وتقرأ الحالة
// والرمز وRetry-After كما تقرأهما الصفحة، وتعيد المحاولة مرة واحدة بعد
// الانتظار المعلن بالضبط. تعيد ما سرت فيه الحالات وحكمها الأخير وثانية
// الانتظار المعلن على السلك — بلا مطبوعات فقط يقرأها المستخدم.
Future<(List<String> states, String verdict, int waitSeconds)> _runFlow(
  HttpClient client,
  int port,
  String origin,
  String correlationId,
) async {
  final states = <String>[];
  // الحالة تُطبع كما كانت وتُجمع معاً: الطرفية يقرأها الإنسان والقائمة
  // يقرأها الفحص الذاتي — رواية واحدة لا اثنتان
  void mark(String state, String detail) {
    states.add(state);
    _state(state, detail);
  }

  Future<HttpClientResponse> send() async {
    final request = await client.openUrl(
      'POST',
      Uri.parse('http://127.0.0.1:$port/'),
    );
    request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    request.headers.set('Origin', origin);
    request.headers.set('Sec-Fetch-Mode', 'cors');
    request.headers.set('Sec-Fetch-Dest', 'empty');
    request.headers.set('X-Correlation-Id', correlationId);
    request.add(utf8.encode('["DEMO-PENDING"]'));
    return request.close();
  }

  mark('SENDING', 'POST ["DEMO-PENDING"] from $origin');
  final HttpClientResponse first;
  try {
    first = await send().timeout(const Duration(seconds: 5));
  } on Exception {
    mark('NO-VERDICT', 'the sender never got an answer — treat as down');
    return (states, states.last, 0);
  }
  final firstBody = await utf8.decoder.bind(first).join();
  final firstJson = jsonDecode(firstBody) as Map<String, dynamic>;
  if (first.statusCode == 200) {
    mark('GRANTED', 'admitted outright — not the consent path');
    return (states, states.last, 0);
  }
  if (first.statusCode != 403 || firstJson['error'] != 'origin_pending') {
    mark('REFUSED', '${first.statusCode} ${firstJson['error']}');
    return (states, states.last, 0);
  }
  final waitSeconds =
      int.tryParse(first.headers.value('retry-after') ?? '') ?? 2;
  mark('PENDING', 'consent question open — Retry-After: $waitSeconds s');
  mark('WAITING', 'honoring Retry-After — no hammering');
  await Future<void>.delayed(Duration(seconds: waitSeconds));
  mark('RETRYING', 'one respectful retry, same X-Correlation-Id');
  final HttpClientResponse second;
  try {
    second = await send().timeout(const Duration(seconds: 5));
  } on Exception {
    mark('NO-VERDICT', 'the sender never got an answer — treat as down');
    return (states, states.last, waitSeconds);
  }
  final secondBody = await utf8.decoder.bind(second).join();
  final secondJson = jsonDecode(secondBody) as Map<String, dynamic>;
  if (second.statusCode == 200) {
    mark('GRANTED', 'the allowOnce answer let the retry cross');
  } else {
    mark('REFUSED', '${second.statusCode} ${secondJson['error']}');
  }
  return (states, states.last, waitSeconds);
}

/// The consent state-machine page. In production this lives on your https
/// portal (add `targetAddressSpace: 'loopback'` there, as the README's
/// page-side reference shows); opened locally over http it reports the
/// honest blocked state instead of pretending to work.
String _pendingPage(int bridgePort) =>
    '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>origin_pending state machine</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 46rem; }
  pre { background: #f4f5f7; padding: 1rem; min-height: 8rem; white-space: pre-wrap; }
  button { font-size: 1rem; padding: .5rem 1.25rem; }
  .note { color: #555; }
</style>
</head>
<body>
<h1>origin_pending state machine</h1>
<p class="note">Bridge: <code>http://127.0.0.1:$bridgePort</code>.
In production, serve this page from your <strong>https</strong> portal —
the discovery path asks valid https origins only, so a page opened over
plain http stays blocked here (that is the bridge's own hardening, not a
bug). The wire demo in the host terminal walks the same states for you.</p>
<button id="run">Run the consent flow</button>
<pre id="log"></pre>
<script>
const ENDPOINT = 'http://127.0.0.1:' + new URLSearchParams(location.search).get('bridge-port') + '/';
const log = document.getElementById('log');
function enter(state, detail) {
  log.textContent += '[' + new Date().toISOString().substring(11, 23) + '] '
    + state + (detail ? ' — ' + detail : '') + '\\n';
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// IDLE -> SENDING -> PENDING -> WAITING -> RETRYING -> GRANTED | REFUSED | NO-VERDICT
async function runFlow() {
  // One correlation id for the whole round: the retry carries the same
  // id the first send carried, so the host's ledger can settle the pair.
  const correlationId = 'page-' + Date.now().toString(36);
  enter('SENDING', 'POST ["DEMO-PENDING"]');
  let res;
  try {
    res = await fetch(ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Correlation-Id': correlationId,
      },
      body: '["DEMO-PENDING"]',
    });
  } catch (browserError) {
    enter('NO-VERDICT',
      'the browser never got an answer — this page origin cannot cross the '
      + 'discovery path (it needs https) or the bridge is down; never report '
      + 'a command verdict from here');
    return;
  }
  if (res.status === 200) {
    enter('GRANTED', 'admitted outright — not the consent path');
    return;
  }
  const body = await res.json().catch(() => ({}));
  if (res.status !== 403 || body.error !== 'origin_pending') {
    enter('REFUSED', res.status + ' ' + (body.error || 'unreadable'));
    return;
  }
  const waitSeconds = Number(res.headers.get('Retry-After')) || 2;
  enter('PENDING', 'consent question open — Retry-After: ' + waitSeconds + 's');
  enter('WAITING', 'honoring Retry-After — no hammering');
  await sleep(waitSeconds * 1000);
  enter('RETRYING', 'one respectful retry, same X-Correlation-Id');
  let res2;
  try {
    res2 = await fetch(ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Correlation-Id': correlationId,
      },
      body: '["DEMO-PENDING"]',
    });
  } catch (browserError) {
    enter('NO-VERDICT', 'the retry never got an answer — treat as down');
    return;
  }
  if (res2.status === 200) {
    enter('GRANTED', 'the allowOnce answer let the retry cross');
    return;
  }
  const body2 = await res2.json().catch(() => ({}));
  enter('REFUSED', res2.status + ' ' + (body2.error || 'unreadable'));
}

document.getElementById('run').addEventListener('click', runFlow);
enter('IDLE', 'press the button; the simulated host grants the demo portal '
  + 'origin once and refuses everything else');
</script>
</body>
</html>
''';

// الفحص الذاتي (--self-check): يعمل بلا مستخدم على منفذين مؤقتين، ويجري
// فحوصاً حقيقية من طرف عميل على السلك — الصفحة تُخدَم وتُقرأ بطلب GET
// فعلي، والجولتان تسيرانه من أصلين تجريبيين ويُقرأ حكمهما من الردود لا
// من داخل المعالج.
Future<bool> _runSelfCheck() async {
  var passed = 0;
  var failed = 0;
  void check(String name, bool ok, [String detail = '']) {
    if (ok) {
      passed++;
      stdout.writeln('PASS: $name');
    } else {
      failed++;
      stdout.writeln('FAIL: $name${detail.isEmpty ? '' : ' — $detail'}');
    }
  }

  final bridge = LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(36),
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(
        // نافذة السؤال بمقاس الإنسان التجريبي الذي يجيب بعد 1.1 ثانية:
        // الافتراضي 60 ثانية يليق مضيفاً حياً لا عملاً يجب أن يخرج،
        // ومؤقّت السؤال الحي حتى نفاذه يُبقي العملية بعد الفحص حتماً
        policy: OriginPolicy(
          onUnknownOrigin: _simulateHuman,
          askTimeout: _humanAskWindow,
        ),
      ),
  );
  final bridgePort = await bridge.start(preferredPort: 0);

  final page = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  page.listen((request) async {
    request.response.headers.contentType = ContentType.html;
    request.response.write(_pendingPage(bridgePort));
    await request.response.close();
  });

  final client = HttpClient();
  try {
    final pageRequest = await client.getUrl(
      Uri.parse('http://127.0.0.1:${page.port}/'),
    );
    final pageReply = await pageRequest.close().timeout(
      const Duration(seconds: 5),
    );
    final pageBody = await utf8.decoder.bind(pageReply).join();
    check(
      'the consent page serves over http with the state machine in it',
      pageReply.statusCode == 200 &&
          pageBody.contains('origin_pending state machine'),
      'GET answered ${pageReply.statusCode}',
    );

    final grant = await _runFlow(
      client,
      bridgePort,
      _grantedDemoOrigin,
      'self-check-grant-1',
    );
    check(
      'the granted origin walks the machine over the wire: pending, '
          'honoring Retry-After, one retry, granted',
      grant.$1.contains('PENDING') &&
          grant.$1.contains('WAITING') &&
          grant.$1.contains('RETRYING') &&
          grant.$2 == 'GRANTED',
      'walked ${grant.$1.join(' -> ')}',
    );
    check(
      'the consent question carried an honest Retry-After on the wire',
      grant.$3 >= 1,
      'Retry-After was ${grant.$3} s',
    );

    final refuse = await _runFlow(
      client,
      bridgePort,
      _refusedDemoOrigin,
      'self-check-refuse-1',
    );
    check(
      'the stranger origin is refused without any grant',
      refuse.$2 == 'REFUSED',
      'walked ${refuse.$1.join(' -> ')}',
    );
  } finally {
    client.close(force: true);
    await page.close(force: true);
    await bridge.stop();
  }

  stdout.writeln(
    failed == 0
        ? 'SELF-CHECK PASSED ($passed checks)'
        : 'SELF-CHECK FAILED ($failed of ${passed + failed} checks failed)',
  );
  return failed == 0;
}

Future<void> main(List<String> args) async {
  // وضع الفحص الذاتي: بلا مستخدم ولا منافذ ثابتة — سطر لكل فحص ورمز
  // خروج 0 عند نجاحها وغير صفر عند فشل أي منها
  if (args.contains('--self-check')) {
    exitCode = await _runSelfCheck() ? 0 : 1;
    return;
  }

  final bridge = LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(36),
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(
        // نافذة السؤال بمقاس الإنسان التجريبي الذي يجيب بعد 1.1 ثانية:
        // الافتراضي 60 ثانية يليق مضيفاً حياً لا عملاً يجب أن يخرج،
        // ومؤقّت السؤال الحي حتى نفاذه يُبقي العملية بعد الفحص حتماً
        policy: OriginPolicy(
          onUnknownOrigin: _simulateHuman,
          askTimeout: _humanAskWindow,
        ),
      ),
  );
  final bridgePort = await bridge.start(preferredPort: 9300);

  final page = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  page.listen((request) async {
    request.response.headers.contentType = ContentType.html;
    request.response.write(_pendingPage(bridgePort));
    await request.response.close();
  });

  stdout
    ..writeln(
      'origin_pending state machine — bridge on http://127.0.0.1:$bridgePort',
    )
    ..writeln()
    ..writeln('wire demo (the same machine the page runs, over the wire):');
  final client = HttpClient();
  await _runFlow(client, bridgePort, _grantedDemoOrigin, 'demo-grant-1');
  await _runFlow(client, bridgePort, _refusedDemoOrigin, 'demo-refuse-1');
  client.close(force: true);

  stdout
    ..writeln()
    ..writeln(
      'open http://localhost:${page.port}/?bridge-port=$bridgePort for the '
      'page — over plain http it reports the honest blocked state; copy its '
      'machine into your https portal for the live flow.',
    )
    ..writeln('Ctrl+C to stop.');

  await ProcessSignal.sigint.watch().first;
  await page.close(force: true);
  await bridge.stop();
  stdout.writeln('stopped; bye.');
}
