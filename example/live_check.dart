// One live check of the browser-to-bridge channel over a real wire: runs
// the bridge under test plus a local check page, then looks with the
// browser's own eye — no curl, no dev tools.
// Run from the package root: dart run example/live_check.dart
import 'dart:async';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

/// The page served to the browser - it exercises the real CORS machinery
/// (preflight, admitted reads, readable rejects) and renders a verdict.
String _checkPage(int bridgePort) => '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>localhost_bridge live check</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 46rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  td, th { border: 1px solid #ccc; padding: .5rem .75rem; text-align: left; }
  .pass { color: #0a7d24; font-weight: 600; }
  .fail { color: #b00020; font-weight: 600; }
  .note { color: #555; }
  #banner { margin-top: 1.5rem; padding: 1rem; font-size: 1.15rem; font-weight: 700; }
</style>
</head>
<body>
<h1>localhost_bridge live check</h1>
<p class="note">Page origin: <code id="origin"></code> &middot; bridge under test:
<code>http://127.0.0.1:$bridgePort</code></p>
<table id="rows"><tr><th>Check</th><th>Result</th></tr></table>
<div id="banner"></div>
<script>
const BRIDGE = 'http://127.0.0.1:$bridgePort';
const admitted = location.hostname === 'localhost';
document.getElementById('origin').textContent = location.origin;

async function post(body, extraHeaders) {
  const headers = Object.assign({'Content-Type': 'application/json'}, extraHeaders);
  const res = await fetch(BRIDGE, {method: 'POST', headers, body});
  return {res, json: await res.json()};
}

const checks = [
  ['admitted POST crosses and is readable',
    async () => {
      const {res, json} = await post('["LIVE-CHECK"]');
      return res.status === 200 && json.ok === true;
    }],
  ['X-Correlation-Id is echoed back to the page',
    async () => {
      const {res} = await post('["LIVE-CHECK"]', {'X-Correlation-Id': 'live-check-1'});
      return res.headers.get('X-Correlation-Id') === 'live-check-1';
    }],
  ['element cap reject is readable (413 payload_too_complex)',
    async () => {
      const big = '[' + new Array(20001).fill('{}').join(',') + ']';
      const {res, json} = await post(big);
      return res.status === 413 && json.error === 'payload_too_complex';
    }],
];

(async () => {
  const table = document.getElementById('rows');
  const detail = [];
  for (const [name, run] of checks) {
    const tr = document.createElement('tr');
    const tdName = document.createElement('td');
    const tdRes = document.createElement('td');
    tdName.textContent = name;
    let ok, note = '';
    try {
      ok = await run();
    } catch (e) {
      ok = false;
      note = ' (browser blocked the call: ' + e + ')';
    }
    tdRes.textContent = (ok ? 'PASS' : 'FAIL') + note;
    tdRes.className = ok ? 'pass' : 'fail';
    tr.append(tdName, tdRes);
    table.append(tr);
    detail.push([name, ok, note]);
  }
  const banner = document.getElementById('banner');
  const allPass = detail.every(([, ok]) => ok);
  const allBlocked = detail.every(([, ok, note]) => !ok && note !== '');
  if (admitted && allPass) {
    banner.textContent = 'ALL CHECKS PASSED - the bridge works from a real browser.';
    banner.style.background = '#e6f6e9';
  } else if (!admitted && allBlocked) {
    banner.textContent = 'BLOCKED BY THE BROWSER - exactly as designed for an unlisted origin.';
    banner.style.background = '#eef2f7';
  } else {
    banner.textContent = 'UNEXPECTED RESULT - see the failing rows above.';
    banner.style.background = '#fdecea';
  }
})();
</script>
</body>
</html>
''';

Future<void> main() async {
  final bridge = LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(16),
    protection: IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          allowed: ['localhost'],
          allowLocalHttp: true,
        ),
      ),
  );
  final bridgePort = await bridge.start(
    preferredPort: 9200,
    fallbacks: const [9202, 9204],
  );

  final page = await HttpServer.bind(InternetAddress.loopbackIPv4, 9201);
  final pagePort = page.port;
  page.listen((request) async {
    final html = _checkPage(bridgePort);
    request.response.headers.contentType = ContentType.html;
    request.response.write(html);
    await request.response.close();
  });

  stdout
    ..writeln('localhost_bridge live check - one command, a real browser, no dev tools.')
    ..writeln()
    ..writeln('  Bridge under test : http://127.0.0.1:$bridgePort')
    ..writeln('  Check page        : http://localhost:$pagePort')
    ..writeln()
    ..writeln('  Step 1  open http://localhost:$pagePort  -> expect: ALL CHECKS PASSED (green)')
    ..writeln('  Step 2  open http://127.0.0.1:$pagePort  -> expect: BLOCKED BY THE BROWSER')
    ..writeln()
    ..writeln('  Ctrl+C to stop.');

  await ProcessSignal.sigint.watch().first;
  await page.close();
  await bridge.stop();
  stdout.writeln('live check stopped; bye.');
}
