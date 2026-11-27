// شاهد عدم القطع على القناة المعتمدة: قناة ويب سوكيت معتمدة (الأصل
// مسموح والرمز في رسالة الاعتماد الأولى) تعيش أطول من مهلة اكتمال
// الترويسات بإطارات لا تحمل سطراً فارغاً - فمهلة الترويسات لا تمسّ
// القناة المعتمدة، وإطاراتها لا تُفحص طلبات. هذا هو الحارس ضد طفرة
// "تجاهل Upgrade" التي تفحص إطارات القناة كطلبات فتقطعها.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

const _listed = 'https://portal.example';
final _token = generateBridgeToken();

// المهلة أقصر من عمر الإطارات كله: كل إطار يصل داخل المهلة والقناة
// تعيش فوقها إطاراتٍ عدة
const _headerTimeout = Duration(milliseconds: 700);
const _frameGap = Duration(milliseconds: 150);
const _frameCount = 10;

Future<LocalIntakeServer> _start() async {
  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(
      policy: const OriginPolicy(allowed: [_listed]),
      token: _token,
    );
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () => 'channel-nocut',
    protection: protection,
    onCommand: (_) async => const CommandOutcome(ok: true),
    config: const BridgeConfig(
      wsPath: '/ws',
      headerTimeout: _headerTimeout,
      idleTimeout: Duration(seconds: 30),
    ),
  );
  await srv.start(preferredPort: 0);
  return srv;
}

void main() {
  // على SDK لا يعرف dart:io معلمة سقف النقل (تحت 3.13) لا تُسلَّح القناة
  // فترمي عند البناء — ولا قناة تعيش فوق مهلة الترويسات أصلاً. تخطٍّ
  // صادق مسمّى كما في شهود القناة القائمة، والشاهد الكامل فوق 3.13 أدناه
  if (!LocalIntakeServer.wsTransportCeilingSupported) {
    test('below Dart 3.13 the channel never arms, so nothing can outlive '
        'the header deadline on it - an honest skip here', () {
      expect(LocalIntakeServer.wsTransportCeilingSupported, isFalse);
    });
    return;
  }
  test('an approved channel outlives the header deadline on frames that '
      'carry no empty line, and still serves its commands', () async {
    final srv = await _start();
    addTearDown(srv.stop);
    // قناة معتمدة: الأصل المسموح والرمز في أول رسالة داخل مهلة الاعتماد
    final ws = await WebSocket.connect(
      'ws://127.0.0.1:${srv.port}/ws',
      headers: {'Origin': _listed},
    ).timeout(const Duration(seconds: 5));
    ws.add(jsonEncode({'token': _token, 'correlationId': 'ws-auth'}));
    final closed = Completer<void>();
    final replies = Completer<void>();
    var replyCount = 0;
    late final StreamSubscription<dynamic> sub;
    sub = ws.listen(
      (_) {
        replyCount++;
        if (!replies.isCompleted) replies.complete();
      },
      onDone: () {
        if (!closed.isCompleted) closed.complete();
      },
      onError: (Object _) {
        if (!closed.isCompleted) closed.complete();
      },
    );
    addTearDown(() {
      unawaited(sub.cancel());
      unawaited(
        ws
            .close(WebSocketStatus.goingAway, 'teardown')
            .catchError((Object _) {}),
      );
    });
    // الإطارات: نص JSON بلا CR ولا LF حرفاً - لا سطر فارغ يمر بإطارها،
    // وعمرها الكلي أضعاف مهلة الترويسات
    final clock = Stopwatch()..start();
    for (var i = 0; i < _frameCount; i++) {
      await Future<void>.delayed(_frameGap);
      ws.add(jsonEncode(['CHANNEL-FRAME-$i']));
    }
    expect(
      clock.elapsed,
      greaterThan(_headerTimeout * 2),
      reason:
          'the frames outlive the header deadline twice over '
          '(${_headerTimeout.inMilliseconds} ms) - each frame lands '
          'inside the deadline window and the channel still outlives it',
    );
    // القناة ما تزال حية بعد مهلتين: لا قطع على القناة المعتمدة
    var stillOpen = true;
    try {
      await closed.future
          .timeout(const Duration(milliseconds: 50))
          .then<void>((_) => stillOpen = false);
    } on TimeoutException {
      stillOpen = true;
    }
    expect(
      stillOpen,
      true,
      reason:
          'the approved channel is open past the header deadline '
          '(${_headerTimeout.inMilliseconds} ms) on empty-line-free '
          'frames - the deadline never touches an approved channel and '
          'its frames are never scanned as requests',
    );
    // والقناة تخدم أوامرها: إطار أمر يرد عليه
    ws.add(jsonEncode(['CHANNEL-CMD']));
    await replies.future.timeout(const Duration(seconds: 5));
    expect(
      replyCount,
      greaterThan(0),
      reason: 'the channel still carries its commands after the deadline',
    );
    unawaited(sub.cancel());
    unawaited(
      ws
          .close(WebSocketStatus.goingAway, 'witness done')
          .catchError((Object _) {}),
    );
  }, timeout: const Timeout(Duration(seconds: 45)));
}
