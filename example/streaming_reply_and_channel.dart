// مثال القناتين من المضيف إلى الصفحة — الرد المتدفق والقناة:
// `X-Bridge-Stream: events` يجعل رد أمر واحد text/event-stream (كل نداء
// تقدم إطار progress وترتيبها ترتيب النداءات، والأخير result بعقد الرد
// القائم)، و`wsPath` يفتح قناة WebSocket تمر بالقبول نفسه ثم تأخذ
// اعتمادها من أول رسالة (توكن أو إثبات اقتران) داخل مهلة قصيرة.
//
// شغّله من جذر الحزمة: dart run example/streaming_reply_and_channel.dart
// بلا مستخدم: dart run example/streaming_reply_and_channel.dart --self-check
// على SDK لا يعرف معلمة سقف النقل (تحت 3.13) لا تُسلَّح القناة أصلاً:
// الفحص الذاتي يفحص الرد المتدفق ويعلن تخطي جزء القناة تخطياً صادقاً
// مسمّياً ويخرج 0 — وفوق 3.13 يفحص القناة كاملة.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

// أصل الصفحة التجريبي — قائمة مغلقة.
const _demoPageOrigin = 'https://jobs.example';
// أوامر المثال المغلقة — ما سواه رفض قبل أي أثر.
const _acceptedCommands = {'LONG-JOB', 'WS-JOB'};
// سقف الانتظار على كل فحص — الفشل الصادق أسرع من التعليق.
const _replyBudget = Duration(seconds: 5);
// مهلة الاعتماد القصيرة: اتصال بلا رسالة أولى لا يجلس في حوض القنوات
// طويلاً — والمهلة المكتوبة هنا هي ما يراه الفحص الذاتي على السلك.
const _shortAuthDeadline = Duration(seconds: 3);

/// One command progress report per call - the sink exists only when the
/// request opted into the streaming reply.
Future<CommandOutcome> _runJob(TrustedCommand cmd) async {
  for (final payload in cmd.payloads) {
    if (!_acceptedCommands.contains(payload.trim().toUpperCase())) {
      return const CommandOutcome(
        ok: false,
        errorCode: 'unknown_command',
        errorMessage: 'only LONG-JOB and WS-JOB are accepted in this demo',
      );
    }
  }
  if (cmd.payloads.any((p) => p.trim().toUpperCase() == 'LONG-JOB')) {
    for (var step = 1; step <= 3; step++) {
      cmd.progress?.call('step $step of 3');
      // فاصل صغير يفصل الإطارات على السلك كي يقرأها القارئ إطاراً إطاراً
      await Future<void>.delayed(const Duration(milliseconds: 120));
    }
  }
  return const CommandOutcome(ok: true);
}

/// The example's wiring: streaming on, the channel armed only where the
/// SDK knows the transport ceiling, the token kept by the caller (the
/// channel's first message carries it as the credential).
LocalIntakeServer buildBridge({
  required bool channelSupported,
  required String token,
}) {
  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(
      token: token,
      policy: const OriginPolicy(allowed: [_demoPageOrigin]),
    );
  return LocalIntakeServer(
    onCommand: _runJob,
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(36),
    handlerTimeout: _replyBudget,
    wsAuthTimeout: _shortAuthDeadline,
    protection: protection,
    config: BridgeConfig(
      allowStreamingReplies: true,
      // بلا سقف نقل لا قناة: الحارس يرفض التسليح على SDK أقدم من 3.13،
      // والمثال يتركها مطفأة بدل أن يعلّق
      wsPath: channelSupported ? '/ws' : null,
    ),
  );
}

/// One round trip from a client's seat: real request in, status, body,
/// and reply headers out - the checks below read the wire, never the
/// handler.
Future<(int status, String body, HttpClientResponse reply)> _post(
  HttpClient client,
  int port, {
  required String origin,
  String? body,
  Map<String, String> headers = const {},
}) async {
  final request = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
  request.headers.set('Origin', origin);
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

  final channelSupported = LocalIntakeServer.wsTransportCeilingSupported;
  // التوكن يُولَّد مرة هنا كما يولّده أي مضيف — بيانات مجرّدة داخل المثال
  final token = generateBridgeToken();
  final bridge = buildBridge(channelSupported: channelSupported, token: token);
  final port = await bridge.start(preferredPort: 0);
  final client = HttpClient();
  try {
    // الطلب المتدفق: جسم الرد يُقرأ إطاراً إطاراً كما تقرأه الصفحة
    final streamed = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    streamed.headers.set('Origin', _demoPageOrigin);
    streamed.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    streamed.headers.set('X-Bridge-Stream', 'events');
    streamed.add(utf8.encode('["LONG-JOB"]'));
    final streamReply = await streamed.close().timeout(_replyBudget);
    var progressFrames = 0;
    String? resultData;
    // القراءة كما تقرأها الصفحة: سطر event: يسمّي الإطار الحالي وسطر
    // data: الذي يليه هو حمولته — فلا يختلط إطار تقدم بإطار نتيجة
    var currentEvent = '';
    await for (final line
        in streamReply
            .transform(utf8.decoder)
            .transform(const LineSplitter())) {
      if (line.startsWith('event: ')) {
        currentEvent = line.substring(7);
      } else if (line.startsWith('data: ')) {
        if (currentEvent == 'progress') progressFrames++;
        if (currentEvent == 'result') resultData = line.substring(6);
      }
    }
    check(
      'the streamed reply is text/event-stream with progress frames '
          'then the final result frame',
      streamReply.statusCode == 200 &&
          (streamReply.headers.value('content-type') ?? '').contains(
            'text/event-stream',
          ) &&
          progressFrames >= 3 &&
          (resultData ?? '').contains('"ok":true'),
      'answered ${streamReply.statusCode} with $progressFrames progress '
          'frames, result ${(resultData ?? '<none>').trim()}',
    );

    final (plainStatus, plainBody, plainReply) = await _post(
      client,
      port,
      origin: _demoPageOrigin,
      body: '["LONG-JOB"]',
    );
    check(
      'a command without the stream header reads the standing JSON reply '
          'even while streaming is armed',
      plainStatus == 200 &&
          plainBody.contains('"ok":true') &&
          (plainReply.headers.value('content-type') ?? '').contains(
            'application/json',
          ),
      'answered $plainStatus ${plainBody.trim()}',
    );

    final (strangerStatus, strangerBody, _) = await _post(
      client,
      port,
      origin: 'https://stranger.example',
      body: '["LONG-JOB"]',
      headers: {'X-Bridge-Stream': 'events'},
    );
    check(
      'the stream does not bypass admission: an unlisted origin is '
          'refused origin_not_listed',
      strangerStatus == 403 && strangerBody.contains('origin_not_listed'),
      'answered $strangerStatus ${strangerBody.trim()}',
    );

    if (!channelSupported) {
      // التخطي الصادق المسمّى: SDK بلا معلمة سقف النقل لا يسلح قناة،
      // والفحص يعلن ذلك بدل أن يزعم فحصاً لم يقع
      stdout.writeln(
        'SKIP: the WebSocket channel needs dart:io 3.13+ (the upgrade '
        'carries the maxPayloadLength transport ceiling there); this SDK '
        'arms no channel, so the channel checks are skipped honestly',
      );
    } else {
      // القناة كاملة: اعتماد بالتوكن في أول رسالة ثم أمر وردّه إطاراً
      final ws = await WebSocket.connect(
        'ws://127.0.0.1:$port/ws',
        headers: {'Origin': _demoPageOrigin},
      ).timeout(_replyBudget);
      final replies = <String>[];
      final gotReply = Completer<void>();
      late final StreamSubscription<Object?> sub;
      sub = ws.listen(
        (frame) {
          replies.add(frame as String);
          if (!gotReply.isCompleted) gotReply.complete();
        },
        onDone: () {
          if (!gotReply.isCompleted) gotReply.complete();
        },
        onError: (Object _) {
          if (!gotReply.isCompleted) gotReply.complete();
        },
      );
      ws.add(jsonEncode({'token': token, 'correlationId': 'ws-check-1'}));
      ws.add('["WS-JOB"]');
      await gotReply.future.timeout(const Duration(seconds: 8));
      await sub.cancel();
      // إغلاق القناة من جهة العميل حسمًا: مصافحة الإغلاق تكتمل بالطرفين
      // فلا مقبس يتيم يُبقي الجولة حية بعد نجاح الفحص — ومصافحة معلقة
      // فشلٌ معلن لا صمت
      var closeHandshake = true;
      try {
        await ws.close().timeout(const Duration(seconds: 3));
      } on TimeoutException {
        closeHandshake = false;
      }
      check(
        'the channel takes its credential from the first message, '
            'answers commands as reply events, and closes by both hands',
        replies.isNotEmpty &&
            replies.first.contains('"ok":true') &&
            ws.closeCode == null &&
            closeHandshake,
        'replies ${replies.take(2).join(' | ').trim()} closeCode '
            '${ws.closeCode} handshake $closeHandshake',
      );

      // اتصال بلا اعتماد: مهلة الاعتماد القصيرة تقطعه برمزها المسجل —
      // والفين قبل المهلة زائد هامش هو من يحكم انتظار الفحص
      final silent = await WebSocket.connect(
        'ws://127.0.0.1:$port/ws',
        headers: {'Origin': _demoPageOrigin},
      ).timeout(_replyBudget);
      final closed = Completer<List<String>>();
      final silentFrames = <String>[];
      late final StreamSubscription<Object?> silentSub;
      silentSub = silent.listen(
        (frame) => silentFrames.add(frame as String),
        onDone: () {
          if (!closed.isCompleted) closed.complete(silentFrames);
        },
        onError: (Object _) {
          if (!closed.isCompleted) closed.complete(silentFrames);
        },
      );
      final framesAtClose = await closed.future.timeout(
        _shortAuthDeadline + const Duration(seconds: 5),
        onTimeout: () => <String>[],
      );
      await silentSub.cancel();
      // العميل يغلق جهته أيضاً: قناة أغلقها الخادم مع اشتراكٍ ملغى قد
      // تجلس مقبسُها على مؤقّت الخمول بدل أن يموت حتماً — والإغلاق
      // المعلق فشلٌ معلن في الفحص لا صمت
      var silentHandshake = true;
      try {
        await silent.close().timeout(const Duration(seconds: 3));
      } on TimeoutException {
        silentHandshake = false;
      }
      check(
        'a channel with no credential inside the short auth deadline is '
            'cut with ws_auth_timeout, and both hands complete the close',
        framesAtClose.isNotEmpty &&
            silent.closeCode != null &&
            framesAtClose.any((f) => f.contains('ws_auth_timeout')) &&
            silentHandshake,
        'closeCode ${silent.closeCode} frames '
            '${framesAtClose.take(2).join(' | ').trim()} handshake '
            '$silentHandshake',
      );
    }
  } finally {
    client.close(force: true);
    await bridge.stop();
  }

  stdout.writeln(
    failed == 0
        ? 'SELF-CHECK PASSED ($passed checks'
              '${channelSupported ? '' : ', channel skipped'})'
        : 'SELF-CHECK FAILED ($failed of ${passed + failed} checks failed)',
  );
  // حسم الفحص: الحكم طُبع ولا انتظار بعده — قناة قطعتها مهلة الاعتماد
  // تُبقي على هذه الـSDK مؤقّتات تفكيك حية بعد كل الهدم فتعيش العملية
  // دقيقة إضافية، ووضع الفحص لا مضيف حي فالخروج صريح بالحكم النهائي
  exit(failed == 0 ? 0 : 1);
}

Future<void> main(List<String> args) async {
  // وضع الفحص الذاتي: بلا مستخدم وعلى منفذ مؤقت — سطر لكل فحص ورمز
  // خروج 0 عند نجاحها وغير صفر عند فشل أي منها
  if (args.contains('--self-check')) {
    exitCode = await _runSelfCheck() ? 0 : 1;
    return;
  }

  final bridge = buildBridge(
    channelSupported: LocalIntakeServer.wsTransportCeilingSupported,
    token: generateBridgeToken(),
  );
  final port = await bridge.start(preferredPort: 9360);
  stdout
    ..writeln(
      'stream + channel demo — listening on http://127.0.0.1:$port '
      '(origin $_demoPageOrigin'
      '${LocalIntakeServer.wsTransportCeilingSupported ? ', channel /ws' : ', no channel on this SDK'})',
    )
    ..writeln('the streamed command (read the body frame by frame):')
    ..writeln(
      '  curl -N -X POST -H "Origin: $_demoPageOrigin" '
      '-H "Content-Type: application/json" '
      '-H "X-Bridge-Stream: events" '
      '-d \'{"data":["LONG-JOB"]}\' http://127.0.0.1:$port/',
    )
    ..writeln(
      'the channel (browser): new WebSocket("ws://127.0.0.1:$port/ws") '
      'then send {"token":"<the token>"} as the first message inside '
      'the ${_shortAuthDeadline.inSeconds}s auth deadline',
    )
    ..writeln('Ctrl+C to stop.');

  await ProcessSignal.sigint.watch().first;
  await bridge.stop();
  stdout.writeln('stopped; bye.');
}
