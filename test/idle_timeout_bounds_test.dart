// شاهد مهلة الخمول في مستمعات HTTP للحزمة: مؤقت dart:io دوري، دوره الأولى
// تعلّم الاتصال خاملاً والتالية تدمّره، وكل اتصال جديد يدخل مجموعة
// الخاملين فور قبوله — فالاتصال الذي لا يحمل طلباً يُغلق بين مهلة الخمول
// وضعفها، لا عند المهلة نفسها. الشاهد بالساعة الحقيقية لأن المؤقت حقيقي،
// وحداه مكتوبان: سماحية صغيرة لتبكير المؤقت تحت الحد الأدنى، وهامش
// لتأخره فوق الحد الأعلى.
import 'dart:async';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

const Duration _idle = Duration(seconds: 1);

// سماحية لتبكير المؤقت: لا يُقبل إغلاق قبل المهلة ناقص هذه السماحية
const Duration _earlyTolerance = Duration(milliseconds: 50);

// هامش تأخر المؤقت فوق ضعف المهلة (حمل المشغّل يؤخر المؤقتات ولا يبكرها)
const Duration _lateMargin = Duration(seconds: 2);

void main() {
  test('a connection that carries no request closes between one idle '
      'period and two', () async {
    final server = LocalIntakeServer(
      onCommand: (_) async => const CommandOutcome(ok: true),
      telemetry: const SilentTelemetry(),
      config: const BridgeConfig(idleTimeout: _idle),
    );
    await server.start(preferredPort: 0);
    addTearDown(server.stop);
    final clock = Stopwatch()..start();
    final socket = await Socket.connect(
      InternetAddress.loopbackIPv4,
      server.port,
    );
    final closed = Completer<Duration>();
    void noteClosed() {
      if (!closed.isCompleted) closed.complete(clock.elapsed);
    }

    socket.listen(
      (_) {},
      onDone: noteClosed,
      onError: (Object _) => noteClosed(),
    );
    // الحد الأدنى: الدورة الأولى تعلّم فقط، فلا إغلاق قبل مهلة الخمول
    await Future<void>.delayed(_idle - _earlyTolerance);
    expect(
      closed.isCompleted,
      isFalse,
      reason:
          'the first period of the idle timer only marks the connection - '
          'nothing closes it before one idle period '
          '(${(_idle - _earlyTolerance).inMilliseconds} ms checked)',
    );
    // الحد الأعلى: الدورة الثانية تدمّر، وذلك قبل ضعف المهلة زائد الهامش
    final after = await closed.future.timeout(_idle + _lateMargin);
    print(
      'IDLE-BOUNDS: closed after ${after.inMilliseconds} ms '
      '(idle period ${_idle.inMilliseconds} ms; bounds '
      '${(_idle - _earlyTolerance).inMilliseconds} ms to '
      '${(_idle * 2 + _lateMargin).inMilliseconds} ms)',
    );
    expect(
      after,
      lessThan(_idle * 2 + _lateMargin),
      reason:
          'the second period of the idle timer destroys the connection, so '
          'it closes before two idle periods plus the timer margin '
          '(${(_idle * 2 + _lateMargin).inMilliseconds} ms)',
    );
    socket.destroy();
  }, timeout: const Timeout(Duration(seconds: 30)));
}
