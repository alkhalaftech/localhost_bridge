// مثال التوكن وحده — السر مولَّد مرة واحدة ويُمرَّر معاملاً في سطر
// الأوامر، لا مكتوباً في الشيفرة ولا في أي ملف: السياسة فارغة (مغلقة
// افتراضياً) والتوكن هو الباب الوحيد، فحامل السر هو المرسل الوحيد وكل
// صفحة مهما زوّرت أصلها لا تعبر.
//
// شغّله من جذر الحزمة (بدون معاملات يولّد توكناً ويطبعه مع سطر التشغيل
// الذي يمرره، ويستمع على منفذه):
//   dart run example/token_from_command_line.dart
// أو بتوكن وُلِّد مرة عندك ووُلِّد غيره بعد ذلك:
//   dart run example/token_from_command_line.dart --token <القيمة>
// بلا مستخدم: dart run example/token_from_command_line.dart --self-check
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

// أوامر المثال المغلقة — ما سواه رفض قبل أي أثر.
const _acceptedCommands = {'PING'};
// سقف الانتظار على كل فحص — الفشل الصادق أسرع من التعليق.
const _replyBudget = Duration(seconds: 5);
// ميزانية التخمين كما تقول وثيقة الحزمة: خمسة توكنات خاطئة لكل نافذة
// ثم الأخطاء التالية تُقفل — والرقم هنا للفحص الذاتي لا للسياسة.
const _guessBudget = 5;

/// One round trip from a local client's seat: real request in, status,
/// body, and reply headers out - the checks below read the wire, never
/// the handler.
Future<(int status, String body, HttpClientResponse reply)> _send(
  HttpClient client,
  int port, {
  String? body,
  Map<String, String> headers = const {},
}) async {
  final request = await client.openUrl(
    'POST',
    Uri.parse('http://127.0.0.1:$port/'),
  );
  request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
  headers.forEach(request.headers.set);
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

  // التوكن يُولَّد مرة واحدة هنا كما يولّده المستدعي في سطر الأوامر —
  // بيانات مجرّدة داخل المثال ولا قيمة مكتوبة في الشيفرة
  final token = generateBridgeToken();
  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(token: token, policy: const OriginPolicy());
  final bridge = LocalIntakeServer(
    onCommand: (cmd) async {
      for (final payload in cmd.payloads) {
        if (!_acceptedCommands.contains(payload.trim().toUpperCase())) {
          return const CommandOutcome(
            ok: false,
            errorCode: 'unknown_command',
            errorMessage: 'only PING is accepted in this demo',
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
  final port = await bridge.start(preferredPort: 0);
  final client = HttpClient();
  try {
    final (bareStatus, bareBody, _) = await _send(
      client,
      port,
      body: '["PING"]',
    );
    check(
      'without any token the closed policy refuses: origin_not_listed',
      bareStatus == 403 && bareBody.contains('origin_not_listed'),
      'answered $bareStatus ${bareBody.trim()}',
    );

    final (rightStatus, rightBody, _) = await _send(
      client,
      port,
      body: '["PING"]',
      headers: {'X-Bridge-Token': token},
    );
    check(
      'the token holder crosses with no Origin at all: the token is '
          'the only door',
      rightStatus == 200 && rightBody.contains('"ok":true'),
      'answered $rightStatus ${rightBody.trim()}',
    );

    // التخمين الخاطئ لا يتعلم عن نفسه شيئاً: رفض الأصل يجيب لا رمز التوكن
    for (var i = 1; i <= _guessBudget; i++) {
      final (wrongStatus, wrongBody, _) = await _send(
        client,
        port,
        body: '["PING"]',
        headers: {'X-Bridge-Token': 'wrong-token-$i'},
      );
      check(
        'wrong token #$i reads the origin rejection, never a token verdict',
        wrongStatus == 403 && wrongBody.contains('origin_not_listed'),
        'answered $wrongStatus ${wrongBody.trim()}',
      );
    }

    final (lockedStatus, lockedBody, lockedReply) = await _send(
      client,
      port,
      body: '["PING"]',
      headers: {'X-Bridge-Token': 'wrong-token-${_guessBudget + 1}'},
    );
    check(
      'past the guess budget further wrong tokens read token_locked '
          'with the honest Retry-After',
      lockedStatus == 429 &&
          lockedBody.contains('token_locked') &&
          lockedReply.headers.value('retry-after') != null,
      'answered $lockedStatus ${lockedBody.trim()}',
    );

    final (holderStatus, holderBody, _) = await _send(
      client,
      port,
      body: '["PING"]',
      headers: {'X-Bridge-Token': token},
    );
    check(
      'the correct token is accepted whatever the failure history: '
          'the budget never locks out the holder',
      holderStatus == 200 && holderBody.contains('"ok":true'),
      'answered $holderStatus ${holderBody.trim()}',
    );
  } finally {
    client.close(force: true);
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
  // وضع الفحص الذاتي: بلا مستخدم وعلى منفذ مؤقت — سطر لكل فحص ورمز
  // خروج 0 عند نجاحها وغير صفر عند فشل أي منها
  if (args.contains('--self-check')) {
    exitCode = await _runSelfCheck() ? 0 : 1;
    return;
  }

  // الوسيط الوحيد: --token <قيمة>. بلا معاملات يُولَّد توكناً ويُطبَع
  // مع سطر التشغيل الذي يمرره — وأي وسيط آخر رفض صاخب
  final String token;
  switch (args) {
    case []:
      token = generateBridgeToken();
    case ['--token', final value]:
      token = value;
    default:
      stderr.writeln(
        'usage: dart run example/token_from_command_line.dart '
        '[--token <the value generated once>] — any other argument is '
        'refused; the token lives on the command line, never in code',
      );
      exitCode = 64;
      return;
  }

  // أرضية التوكن قرار بناء لا تحذير: توكن قصير أو ضحي التركيب يرفض
  // الجسر رفضاً صاخباً قبل أن يسمع أي طلب — والرسالة تسمي الطول لا القيمة
  final IntakeProtection protection;
  try {
    protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(token: token, policy: const OriginPolicy());
  } on ArgumentError catch (buildRefusal) {
    stderr.writeln(
      'the bridge refuses this token at build time: '
      '${buildRefusal.message}',
    );
    exitCode = 65;
    return;
  }

  final server = LocalIntakeServer(
    onCommand: (cmd) async {
      for (final payload in cmd.payloads) {
        if (!_acceptedCommands.contains(payload.trim().toUpperCase())) {
          return const CommandOutcome(
            ok: false,
            errorCode: 'unknown_command',
            errorMessage: 'only PING is accepted in this demo',
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

  final port = await server.start(preferredPort: 9350);
  stdout
    ..writeln(
      'token-only demo — listening on http://127.0.0.1:$port '
      '(empty policy + token: the token holder is the only sender)',
    )
    ..writeln('token   : $token')
    ..writeln(
      'run me again with this token on the command line: '
      'dart run example/token_from_command_line.dart --token $token',
    )
    ..writeln('the curl that crosses:')
    ..writeln(
      '  curl -X POST -H "X-Bridge-Token: $token" '
      '-H "Content-Type: application/json" '
      '-d \'{"data":["PING"]}\' http://127.0.0.1:$port/',
    )
    ..writeln('Ctrl+C to stop.');

  await ProcessSignal.sigint.watch().first;
  await server.stop();
  stdout.writeln('stopped; bye.');
}
