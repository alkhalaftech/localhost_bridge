// حصرية المنفذ أثناء استماع الجسر: الربط يجري على 127.0.0.1 وحده بلا علم
// مشاركة (HttpServer.bind الافتراضي shared:false — local_intake_server.dart
// مرجع الربط الواحد)، فمستمع ثانٍ على العنوان نفسه يفشل من isolate مستقل
// بعلم المشاركة وبدونه — SocketException هو IOException الوحيد المتوقع هنا
// لأن المقبس الأول حصري — ويصير العنوان حرّاً بعد stop وهذا هو بيت القصيد:
// الفشل بيد الجسر لا بيئة الجهاز. أما ::1 فعائلة عنوان مختلفة لا يتنازعها
// الربط الأحادي: ربطها على الرقم نفسه ينجح وهو أثر متبقٍ موثق لا علة —
// ويُتخطى الاختبار حيث لا حلقة راجعة IPv6 على الجهاز.
import 'dart:async';
import 'dart:io';
import 'dart:isolate';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

/// Binds 127.0.0.1:[port] from a fresh isolate and reports the outcome as a
/// plain string so the value crosses the isolate boundary unchanged: the
/// expected failure shape is an IOException/SocketException (address in
/// use), and the type name keeps the assertion readable on every platform.
/// ServerSocket.bind is the plain socket bind call - the same OS-level bind
/// the bridge itself runs.
Future<String> _secondListener(int port, {required bool shared}) =>
    Isolate.run(() async {
      try {
        final listener = await ServerSocket.bind(
          InternetAddress.loopbackIPv4,
          port,
          shared: shared,
        );
        await listener.close();
        return 'bound';
      } on Object catch (error) {
        return error.runtimeType.toString();
      }
    });

/// Whether this host has an IPv6 loopback at all - probed on an ephemeral
/// port so the skip decision is a fact about the machine, not about the
/// bridge.
Future<bool> _ipv6LoopbackAvailable() async {
  ServerSocket? probe;
  try {
    probe = await ServerSocket.bind(
      InternetAddress.loopbackIPv6,
      0,
      v6Only: true,
    );
    return true;
  } on SocketException {
    return false;
  } finally {
    await probe?.close();
  }
}

LocalIntakeServer _bridge() => LocalIntakeServer(
  onCommand: (_) async => const CommandOutcome(ok: true),
  telemetry: const SilentTelemetry(),
  correlationIdGenerator: () => 'port-excl',
  protection: IntakeProtection(telemetry: const SilentTelemetry())
    ..update(policy: OriginPolicy(allowed: ['https://a.example'])),
);

void main() {
  test(
    'a second listener on 127.0.0.1:P fails while the bridge listens - without the shared flag, from a second isolate - and the address frees after stop',
    () async {
      final server = _bridge();
      final port = await server.start(preferredPort: 0);
      addTearDown(server.stop);
      final attempt = await _secondListener(port, shared: false);
      expect(
        attempt,
        'SocketException',
        reason:
            'the second bind must fail with an IOException/SocketException '
            '(address in use) while the bridge holds the port - got "$attempt"',
      );
      expect(
        server.isListening,
        isTrue,
        reason: 'the failed bind leaves the bridge untouched',
      );
      expect(
        server.port,
        port,
        reason:
            'the bridge keeps its bound port through a foreign bind attempt',
      );
      await server.stop();
      final after = await _secondListener(port, shared: false);
      expect(
        after,
        'bound',
        reason:
            'the same bind succeeds once the bridge releases the port - '
            'the failure above is the bridge holding the address, not an '
            'environmental block on binding',
      );
    },
  );

  test(
    'a second listener on 127.0.0.1:P fails even when it asks for sharing (shared: true), from a second isolate',
    () async {
      final server = _bridge();
      final port = await server.start(preferredPort: 0);
      addTearDown(server.stop);
      final attempt = await _secondListener(port, shared: true);
      expect(
        attempt,
        'SocketException',
        reason:
            'sharing is a request to join a cooperative holder - the '
            'bridge bound exclusively, so a shared-flag bind still fails with '
            'an IOException/SocketException - got "$attempt"',
      );
      await server.stop();
      final after = await _secondListener(port, shared: true);
      expect(
        after,
        'bound',
        reason:
            'the shared-flag bind succeeds on the same number once the '
            'bridge releases it',
      );
    },
  );

  test(
    'binding [::1]:P while the bridge holds 127.0.0.1:P still succeeds - documents a leftover artifact: the bridge binds 127.0.0.1 alone, so the same port number stays free on the IPv6 loopback (skipped where no IPv6 loopback exists)',
    () async {
      if (!await _ipv6LoopbackAvailable()) {
        throw Skip('no IPv6 loopback on this host');
      }
      final server = _bridge();
      final port = await server.start(preferredPort: 0);
      addTearDown(server.stop);
      final v6 = await ServerSocket.bind(
        InternetAddress.loopbackIPv6,
        port,
        v6Only: true,
      );
      expect(
        v6.port,
        port,
        reason:
            'the IPv6 loopback binds the very number the bridge holds - '
            'a leftover artifact of the IPv4-only bind, not a defect: hosts '
            'relying on port exclusivity must know ::1 is not covered',
      );
      await v6.close();
      expect(
        server.isListening,
        isTrue,
        reason:
            'the IPv6 bind leaves the bridge untouched - the two sockets '
            'never contend',
      );
    },
  );
}
