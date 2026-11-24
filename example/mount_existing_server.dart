// مثال التركيب على خادم قائم — مضيف لديه خادم dart:io يعمل أصلاً
// يريد الجسر على مسار واحد لا على منفذ ثانٍ: المضيف يحتفظ بخادمه
// وتوجيهه كله، وما يحوّله إلى handleHostRequest وحده يصل الجسر —
// بمحاكمة القائمة كاملة (الأصل والشكل وسلطة Host والمقاعد) وبأكواد
// السلك نفسها، وبما أن سلطات Host تُبنى من منفذ خادم المضيف نفسه
// (hostPort) فما يسمعه المضيف فعلاً هو ما يحكم.
//
// شغّله من جذر الحزمة: dart run example/mount_existing_server.dart
// ثم حوّل طلباتك إلى المسار المركب (الأصل المدرج هو من يعبر):
// curl -X POST -H "Origin: https://app.example" \
//   -H "Content-Type: application/json" \
//   -d '{"data":["HELLO"]}' http://127.0.0.1:$PORT/bridge
// بلا مستخدم: dart run example/mount_existing_server.dart --self-check
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

// أصل الصفحة التجريبي — قائمة مغلقة.
const _demoPageOrigin = 'https://app.example';
// أوامر المثال المغلقة — ما سواه رفض قبل أي أثر.
const _acceptedCommands = {'HELLO'};
// سقف الانتظار على كل فحص — الفشل الصادق أسرع من التعليق.
const _replyBudget = Duration(seconds: 5);

/// The mounted demo in one place: the host server keeps its routes,
/// the path it forwards is the only thing the bridge judges, and the
/// handler keeps a count so the checks below can tell "the bridge ran"
/// from "the host ran" — reading the wire alone cannot see that.
class _MountedDemo {
  _MountedDemo._(this.host, this.bridge);

  final HttpServer host;
  final LocalIntakeServer bridge;
  // عدّاد دخول المعالج: طلب لم يره الجسر لا يرفعه
  int handlerEntries = 0;

  static Future<_MountedDemo> mount({
    required IntakeProtection protection,
    required int preferredPort,
  }) async {
    late final _MountedDemo demo;
    final bridge = LocalIntakeServer(
      onCommand: (cmd) async {
        demo.handlerEntries++;
        for (final payload in cmd.payloads) {
          if (!_acceptedCommands.contains(payload.trim().toUpperCase())) {
            return const CommandOutcome(
              ok: false,
              errorCode: 'unknown_command',
              errorMessage: 'only HELLO is accepted in this demo',
            );
          }
        }
        return const CommandOutcome(ok: true);
      },
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () =>
          DateTime.now().microsecondsSinceEpoch.toRadixString(36),
      handlerTimeout: _replyBudget,
      protection: protection,
    );
    final host = await HttpServer.bind(
      InternetAddress.loopbackIPv4,
      preferredPort,
    );
    demo = _MountedDemo._(host, bridge);
    host.listen((request) async {
      if (request.uri.path == '/bridge') {
        // المسار المركب: الجسر يجيب بالحماية الكاملة، وكل رد يُكتب
        // ويُقطع على المقبس المنتزع كما في خادمه الخاص
        await bridge.handleHostRequest(request, hostPort: host.port);
      } else {
        // مسارات المضيف تجيب بنفسها — الجسر لا يراها
        request.response.headers.contentType = ContentType.text;
        request.response.write(
          'the host answers this path itself — the bridge never saw '
          'this request\n',
        );
        await request.response.close();
      }
    });
    return demo;
  }

  /// The bridge never started a listener in this example - and stop()
  /// settles whatever is still in flight on the mounted path before the
  /// host server closes.
  Future<void> close() async {
    await bridge.stop();
    await host.close(force: true);
  }
}

/// One round trip from a client's seat: real request in, status, body,
/// and reply headers out - the checks below read the wire, never the
/// handler.
Future<(int status, String body, HttpClientResponse reply)> _send(
  HttpClient client,
  int hostPort,
  String path, {
  String? body,
  String? origin,
}) async {
  final request = await client.openUrl(
    'POST',
    Uri.parse('http://127.0.0.1:$hostPort$path'),
  );
  if (origin != null) request.headers.set('Origin', origin);
  request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
  if (body != null) request.add(utf8.encode(body));
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

  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(policy: OriginPolicy(allowed: [_demoPageOrigin]));
  final demo = await _MountedDemo.mount(
    protection: protection,
    preferredPort: 0,
  );
  final client = HttpClient();
  try {
    final pageRequest = await client.getUrl(
      Uri.parse('http://127.0.0.1:${demo.host.port}/'),
    );
    final pageReply = await pageRequest.close().timeout(_replyBudget);
    final pageBody = await utf8.decoder.bind(pageReply).join();
    check(
      'the host route answers itself and the bridge never saw it',
      pageReply.statusCode == 200 &&
          pageBody.contains('the host answers this path itself') &&
          demo.handlerEntries == 0,
      'answered ${pageReply.statusCode}, handler entries '
          '${demo.handlerEntries}',
    );

    final (bridgedStatus, bridgedBody, _) = await _send(
      client,
      demo.host.port,
      '/bridge',
      body: '["HELLO"]',
      origin: _demoPageOrigin,
    );
    check(
      'the forwarded path crosses with the full standing protection',
      bridgedStatus == 200 &&
          bridgedBody.contains('"ok":true') &&
          demo.handlerEntries == 1,
      'answered $bridgedStatus ${bridgedBody.trim()}, handler entries '
          '${demo.handlerEntries}',
    );

    final (strangerStatus, strangerBody, strangerReply) = await _send(
      client,
      demo.host.port,
      '/bridge',
      body: '["HELLO"]',
      origin: 'https://stranger.example',
    );
    check(
      'an unlisted origin on the forwarded path reads the same refusal '
          'the private door gives, with no CORS echo',
      strangerStatus == 403 &&
          strangerBody.contains('origin_not_listed') &&
          strangerReply.headers.value('access-control-allow-origin') == null &&
          demo.handlerEntries == 1,
      'answered $strangerStatus ${strangerBody.trim()}',
    );

    final (hostPathStatus, hostPathBody, _) = await _send(
      client,
      demo.host.port,
      '/',
      body: '["HELLO"]',
      origin: _demoPageOrigin,
    );
    check(
      'a POST on a path the host keeps is judged by the host, not the '
          'bridge: the handler never hears it',
      hostPathStatus == 200 &&
          hostPathBody.contains('the host answers this path itself') &&
          demo.handlerEntries == 1,
      'answered $hostPathStatus, handler entries ${demo.handlerEntries}',
    );
  } finally {
    client.close(force: true);
    await demo.close();
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

  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(policy: OriginPolicy(allowed: [_demoPageOrigin]));
  final demo = await _MountedDemo.mount(
    protection: protection,
    preferredPort: 9370,
  );
  stdout
    ..writeln(
      'mounted bridge demo — host server on '
      'http://127.0.0.1:${demo.host.port}',
    )
    ..writeln('  POST /bridge  — forwarded to the bridge (full protection)')
    ..writeln('  everything else — the host answers it itself')
    ..writeln('the curl in the file header crosses the mounted door; bye.')
    ..writeln('Ctrl+C to stop.');

  await ProcessSignal.sigint.watch().first;
  await demo.close();
  stdout.writeln('stopped; bye.');
}
