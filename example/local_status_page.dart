// مثال صفحة الحالة المحلية — مضيف بلا واجهة (أداة سطر أو خدمة) يخدم
// صفحة من الذاكرة عبر BridgeConfig.localPages: مسار واحد يجيب GET
// بالمحتوى الحرفي بترويسات أمانه الصارمة، وأصل الجسر نفسه يقرأ صفحته
// مسارَ القبول الصريح. الصفحة تعرض عدّادات حية تقرأها من أمر STATUS
// يعيدها المعالج من server.counters — وبلا أي سر فيها: الصفحة المحلية
// يقرأها كل برنامج على الجهاز بGET عادي بلا ترويسات متصفح، فلا توكن
// ولا رمز اقتران ولا سر يُكتب فيها أبداً.
//
// شغّله من جذر الحزمة: dart run example/local_status_page.dart
// ثم افتح العنوان المطبوع (صفحة /status) واقرأ العدّادات حية.
// بلا مستخدم: dart run example/local_status_page.dart --self-check
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

// أوامر المثال المغلقة — ما سواه رفض قبل أي أثر.
const _acceptedCommands = {'STATUS'};
// سقف الانتظار على كل فحص — الفشل الصادق أسرع من التعليق.
const _replyBudget = Duration(seconds: 5);

/// The page served verbatim from the host's memory - counters table,
/// inline script only (the strict CSP allows nothing else), and a note
/// that no secret belongs here. It polls the STATUS command once a
/// second and renders what the handler returned.
String _statusPage() => '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>bridge status (local)</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 40rem; }
  table { border-collapse: collapse; width: 100%; }
  td, th { border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; }
  .note { color: #555; }
</style>
</head>
<body>
<h1>bridge status (local)</h1>
<p class="note">This page is served from the host's memory and read by
every program on this device - so it carries no secret, ever: no token,
no pairing code, only the counters below.</p>
<table id="counters"><tr><th>Counter</th><th>Value</th></tr></table>
<script>
async function refresh() {
  try {
    const res = await fetch('/', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: '["STATUS"]',
    });
    const reply = await res.json();
    const table = document.getElementById('counters');
    table.textContent = '';
    const row = (k, v) => {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td');
      const td2 = document.createElement('td');
      td1.textContent = k;
      td2.textContent = String(v);
      tr.append(td1, td2);
      table.append(tr);
    };
    for (const [k, v] of Object.entries(reply.data ?? {})) row(k, v);
    if (reply.ok !== true) row('reply', reply.error || 'unreadable');
  } catch (fetchError) {
    // الصفحة تعرض الحالة لا تحكم أمر: فشل الجلب حالة تُرى لا كارثة
  }
}
refresh();
setInterval(refresh, 1000);
</script>
</body>
</html>
''';

/// One round trip from a client's seat: real request in, status, body,
/// and reply headers out - the checks below read the wire, never the
/// handler.
Future<(int status, String body, HttpClientResponse reply)> _get(
  HttpClient client,
  int port,
  String path, {
  String? origin,
}) async {
  final request = await client.getUrl(Uri.parse('http://127.0.0.1:$port$path'));
  if (origin != null) request.headers.set('Origin', origin);
  final reply = await request.close().timeout(_replyBudget);
  final text = await utf8.decoder.bind(reply).join();
  return (reply.statusCode, text, reply);
}

/// One POST the way the served page sends it: the page's own origin,
/// a JSON body.
Future<(int status, String body, HttpClientResponse reply)> _postLikePage(
  HttpClient client,
  int port,
  String body,
) async {
  final request = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
  request.headers.set('Origin', 'http://127.0.0.1:$port');
  request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
  request.add(utf8.encode(body));
  final reply = await request.close().timeout(_replyBudget);
  final text = await utf8.decoder.bind(reply).join();
  return (reply.statusCode, text, reply);
}

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

  late final LocalIntakeServer server;
  // التوكن يُولَّد هنا ويبقى في يد المضيف حصراً — والفحص يثبت غيابه
  // من الصفحة المخدومة حرفياً
  final token = generateBridgeToken();
  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    // سياسة فارغة + توكن: حامل السر هو المرسل الوحيد خارج أصل الجسر
    // نفسه — والصفحة تعرض عدّادات لا أسرار
    ..update(token: token, policy: const OriginPolicy());
  server = LocalIntakeServer(
    onCommand: (cmd) async {
      for (final payload in cmd.payloads) {
        if (!_acceptedCommands.contains(payload.trim().toUpperCase())) {
          return const CommandOutcome(
            ok: false,
            errorCode: 'unknown_command',
            errorMessage: 'only STATUS is accepted in this demo',
          );
        }
      }
      final counters = server.counters;
      return CommandOutcome(
        ok: true,
        data: {
          'activeSeats': counters.activeSeats,
          'orphanHandlers': counters.orphanHandlers,
          'wsChannels': counters.wsChannels,
          'rejectionsByCode': counters.rejectionsByCode,
        },
      );
    },
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(36),
    handlerTimeout: _replyBudget,
    protection: protection,
    config: BridgeConfig(
      localPages: [BridgeLocalPage(path: '/status', content: _statusPage())],
    ),
  );
  final port = await server.start(preferredPort: 0);
  final client = HttpClient();
  try {
    final (pageStatus, pageBody, pageReply) = await _get(
      client,
      port,
      '/status',
    );
    check(
      'the registered page answers GET verbatim from memory with its '
          'declared type',
      pageStatus == 200 &&
          pageBody.contains('bridge status (local)') &&
          (pageReply.headers.contentType?.toString() ?? '').contains(
            'text/html',
          ),
      'answered $pageStatus',
    );
    check(
      'the page carries its security headers on the reply',
      pageReply.headers.value('x-frame-options') == 'DENY' &&
          pageReply.headers.value('referrer-policy') == 'no-referrer',
      'x-frame-options ${pageReply.headers.value('x-frame-options')}, '
          'referrer-policy ${pageReply.headers.value('referrer-policy')}',
    );
    check(
      'no secret in the page: the armed token string is absent from the '
          'served markup',
      !pageBody.contains(token),
      'served ${pageBody.length} bytes with no token occurrence',
    );

    // الأمر كما ترسله الصفحة من أصلها الصريح: العدّادات الحية تعود
    final (statusStatus, statusBody, _) = await _postLikePage(
      client,
      port,
      '["STATUS"]',
    );
    final statusJson = statusStatus == 200
        ? jsonDecode(statusBody) as Map<String, dynamic>
        : <String, dynamic>{};
    check(
      'a POST from the served page origin crosses on its explicit path '
          'and the live counters come back as reply data',
      statusStatus == 200 &&
          statusJson['ok'] == true &&
          statusJson['data'] is Map &&
          (statusJson['data'] as Map).containsKey('activeSeats'),
      'answered $statusStatus ${statusBody.trim()}',
    );

    // الصفحة ليست للقراءة العابرة للأصل: لا صدى CORS لأصل أجنبي
    final (_, foreignBody, foreignReply) = await _get(
      client,
      port,
      '/status',
      origin: 'http://127.0.0.1:1',
    );
    check(
      'a foreign origin gets the page bytes but no CORS echo, so no '
          'foreign page reads it cross-origin',
      foreignBody.isNotEmpty &&
          foreignReply.headers.value('access-control-allow-origin') == null,
      'answered with body ${foreignBody.length} bytes, ACAO '
          '${foreignReply.headers.value('access-control-allow-origin')}',
    );

    final (otherStatus, otherBody, _) = await _get(client, port, '/nonsense');
    check(
      'any other GET keeps its standing 405 method_not_allowed',
      otherStatus == 405 && otherBody.contains('method_not_allowed'),
      'answered $otherStatus ${otherBody.trim()}',
    );
  } finally {
    client.close(force: true);
    await server.stop();
  }

  stdout.writeln(
    failed == 0
        ? 'SELF-CHECK PASSED ($passed checks)'
        : 'SELF-CHECK FAILED ($failed of ${passed + failed} checks failed)',
  );
  return failed == 0;
}

Future<void> main(List<String> args) async {
  // وضع الفحص الذاتي: بلا مستخدم وعلى منفذ مؤقت — سطر لكل فحص ورمز
  // خروج 0 عند نجاحها وغير صفر عند فشل أي منها
  if (args.contains('--self-check')) {
    exitCode = await _runSelfCheck() ? 0 : 1;
    return;
  }

  late final LocalIntakeServer server;
  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(token: generateBridgeToken(), policy: const OriginPolicy());
  server = LocalIntakeServer(
    onCommand: (cmd) async {
      for (final payload in cmd.payloads) {
        if (!_acceptedCommands.contains(payload.trim().toUpperCase())) {
          return const CommandOutcome(
            ok: false,
            errorCode: 'unknown_command',
            errorMessage: 'only STATUS is accepted in this demo',
          );
        }
      }
      final counters = server.counters;
      return CommandOutcome(
        ok: true,
        data: {
          'activeSeats': counters.activeSeats,
          'orphanHandlers': counters.orphanHandlers,
          'wsChannels': counters.wsChannels,
          'rejectionsByCode': counters.rejectionsByCode,
        },
      );
    },
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(36),
    handlerTimeout: _replyBudget,
    protection: protection,
    config: BridgeConfig(
      localPages: [BridgeLocalPage(path: '/status', content: _statusPage())],
    ),
  );
  final port = await server.start(preferredPort: 9380);
  stdout
    ..writeln('local status page demo — listening on http://127.0.0.1:$port')
    ..writeln(
      'open http://127.0.0.1:$port/status — live counters, no secret in '
      'the page (a local page is readable by every program on the '
      'device)',
    )
    ..writeln('Ctrl+C to stop.');

  await ProcessSignal.sigint.watch().first;
  await server.stop();
  stdout.writeln('stopped; bye.');
}
