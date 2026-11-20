// شاهد المحاكي — ج3 الرابع على Android: يشغّل تركيب المختبر نفسه على
// المضيف (جسر صارم بالاقتران المسلح + صفحة المختبر + مجمّع التقارير)
// ويطبع أوامر adb reverse بالمنافذ الفعلية وعنوان الفتح، ثم ينتظر أعلام
// الصفحة الأربعة من المجمع ويحسم PASS/INCOMPLETE بخروج واضح.
//
// لماذا أداة مستقلة؟ منافذ المختبر ephemeral داخل الاختبار فلا تعرفها
// أوامر adb، وكروم Android لا يفرغ DOM (لا --dump-dom) فالصفحة تعيد
// علاماتها إلى المجمّع — والقناة نفسها مثبتة على متصفح سطح مكتب في
// اختبار المختبر (شاهد «قناة التقرير») قبل أن يسلكها المحاكي.
//
// الاستعمال حرفيا (من جذر الحزمة):
//   dart run tool/emulator_pairing_lab.dart
// يطبع ثلاثة أسطر تنفيذية؛ نفّذها على المضيف:
//   adb reverse tcp:<جسر> tcp:<جسر> && adb reverse tcp:<صفحة> tcp:<صفحة>
//   adb shell am start -a android.intent.action.VIEW -d "http://127.0.0.1:<صفحة>/?report=1"
// فتفتح الصفحة على كروم المحاكي وتقرأ الأداة الأعلام وتحسم.
//
// صفحة هذه الأداة مرآة مختصرة لكتلة الاقتران في صفحة المختبر
// (browser_lab_test.dart) بنفس الcanonical والتوقيع وبالمفتاح نفسه:
// بايتات التوكن الخام الاثنتان والثلاثون مفكوكة من الhex — والشاهد
// الحاكم يبقى اختبار المختبر؛ هذه الأداة قناة تشغيل على المحاكي حصرا.
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

String _page({required int bridgePort, required String code}) =>
    '''
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>localhost_bridge emulator pairing lab</title></head>
<body>
<pre id="lab-results"></pre>
<script>
'use strict';
const BRIDGE = 'http://127.0.0.1:$bridgePort';
const PAIRING_CODE = '$code';
const results = document.getElementById('lab-results');
const marks = [];
function mark(line) { marks.push(line); results.textContent += line + '\\n'; }

async function signProof(tokenHex, pairingId, method, path, cid) {
  const stamp = Date.now();
  const canonical = 'v1\\n' + pairingId + '\\n' + stamp + '\\n' +
                    method + '\\n' + path + '\\n' + cid;
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
  mark('EMU-PAGE-ORIGIN:' + location.origin);
  try {
    const pairRes = await fetch(BRIDGE + '/pair', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({pairingCode: PAIRING_CODE}),
    });
    const pairBody = await pairRes.json().catch(() => null);
    if (pairRes.status === 200 && pairBody && pairBody.token) {
      const proof = await signProof(
          pairBody.token, pairBody.pairingId, 'POST', '/', 'emu-paired-1');
      const signed = await fetch(BRIDGE, {
        method: 'POST',
        headers: {'Content-Type': 'application/json',
                  'X-Bridge-Pairing': proof,
                  'X-Correlation-Id': 'emu-paired-1'},
        body: '["EMULATOR-WITNESS"]',
      });
      const signedBody = await signed.json().catch(() => null);
      mark('EMU-PAIRED:' + signed.status + ':' +
           (signedBody && signedBody.ok === true ? 'true' : 'false'));
      const replay = await fetch(BRIDGE, {
        method: 'POST',
        headers: {'Content-Type': 'application/json',
                  'X-Bridge-Pairing': proof,
                  'X-Correlation-Id': 'emu-paired-1'},
        body: '["EMULATOR-WITNESS"]',
      });
      const replayBody = await replay.json().catch(() => null);
      mark('EMU-REPLAY:' + replay.status + ':' +
           (replayBody && replayBody.error ? replayBody.error : 'no-error'));
      const bare = await fetch(BRIDGE, {
        method: 'POST',
        headers: {'Content-Type': 'application/json',
                  'X-Correlation-Id': 'emu-bare-1'},
        body: '["EMULATOR-WITNESS"]',
      });
      const bareBody = await bare.json().catch(() => null);
      mark('EMU-BARE:' + bare.status + ':' +
           (bareBody && bareBody.error ? bareBody.error : 'no-error'));
    } else {
      mark('EMU-PAIRING:' + pairRes.status + ':' +
           (pairBody && pairBody.error ? pairBody.error : 'unreadable'));
    }
  } catch (browserError) {
    mark('EMU-THREW');
  }
  // العودة إلى المجمّع على أصل الصفحة نفسه — آخر نداء في الصفحة
  try {
    await fetch('/lab-report', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({marks: marks}),
    });
  } catch (e) {
    mark('EMU-REPORT:THREW');
  }
})();
</script>
</body>
</html>
''';

Future<void> main() async {
  final protection = IntakeProtection(telemetry: const SilentTelemetry());
  final pageServer = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final pageOrigin = 'http://127.0.0.1:${pageServer.port}';
  protection.update(
    policy: OriginPolicy(allowed: [pageOrigin], requireOriginWithToken: true),
    token: generateBridgeToken(),
  );
  protection.enablePairing();
  final bridge = LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        'emu-${DateTime.now().microsecondsSinceEpoch}',
    protection: protection,
  );
  final bridgePort = await bridge.start(preferredPort: 0);
  final offer = protection.startPairing();
  final html = _page(bridgePort: bridgePort, code: offer.code);

  final reports = <Map<String, Object?>>[];
  pageServer.listen((request) async {
    if (request.uri.path == '/lab-report') {
      if (request.method == 'POST') {
        final body = await utf8.decoder.bind(request).join();
        try {
          reports.add((jsonDecode(body) as Map).cast<String, Object?>());
        } on FormatException {
          reports.add(<String, Object?>{'marks': <Object?>[]});
        }
        for (final mark in (reports.last['marks'] as List? ?? const [])) {
          stdout.writeln('[EMULATOR-WITNESS] $mark');
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
    if (request.uri.path != '/') {
      request.response.statusCode = HttpStatus.notFound;
      await request.response.close();
      return;
    }
    request.response.headers.contentType = ContentType.html;
    request.response.write(html);
    await request.response.close();
  });

  stdout.writeln('EMULATOR-WITNESS: the lab is up - run these on the host:');
  stdout.writeln(
    '  adb reverse tcp:$bridgePort tcp:$bridgePort && '
    'adb reverse tcp:${pageServer.port} tcp:${pageServer.port}',
  );
  stdout.writeln(
    '  adb shell am start -a android.intent.action.VIEW '
    '-d "http://127.0.0.1:${pageServer.port}/?report=1"',
  );
  stdout.writeln('waiting for the page marks (Ctrl+C to abort)...');

  const wanted = <String>[
    'EMU-PAIRED:200:true',
    'EMU-REPLAY:403:pair_signature_replay',
    'EMU-BARE:403:token_required',
  ];
  final deadline = DateTime.now().add(const Duration(minutes: 3));
  var pass = false;
  while (DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 500));
    final seen = reports
        .expand((r) => (r['marks'] as List? ?? const []).cast<String>())
        .toList();
    pass = wanted.every(seen.contains);
    if (pass) break;
  }
  await bridge.stop();
  await pageServer.close(force: true);
  if (pass) {
    stdout.writeln(
      'EMULATOR-WITNESS: PASS - pair, signed command, replay '
      'refusal, and the bare strict refusal all read on the emulator '
      'browser',
    );
    exit(0);
  }
  stdout.writeln(
    'EMULATOR-WITNESS: INCOMPLETE - the marks did not arrive '
    'within three minutes; check the adb reverse commands above and '
    'the emulator Chrome version',
  );
  exit(1);
}
