// الإلغاء التعاوني الاختياري: إشارة يقرؤها المعالج إن شاء — تشعل عند
// احتراق الميزانية (لحظة الـ504) وعند دخول stop، والأمر المبني خارج
// الجسر يحمل الثابت الذي لا يُشعل أبداً. العناوين بالإنجليزية (حزمة
// منشورة) والتعليقات بالعربية (قاعدة البيت).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

class _Rec extends BridgeTelemetry {
  @override
  void info(
    String m, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  void warn(
    String m, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  void error(
    String m, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) => body();
}

var _idSeq = 0;
String _cid() => 'signal-${_idSeq++}';

IntakeProtection _allowlist() {
  final pr = IntakeProtection(telemetry: _Rec());
  pr.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
  return pr;
}

Future<(int, String)> _post(
  int port, {
  String origin = 'https://portal.example',
}) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', origin);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } on Object {
    return (-1, '');
  } finally {
    client.close(force: true);
  }
}

// معالج يستطلع الإشارة حتى تشعل — والمهلة الحقيقية الطويلة حارسُ
// «لم تُشعل أبداً» فقط (فيسقط الاختبار بمهلة القشرة لا بخروج المعالج
// صامتاً): على عدّاء بنواتين تحت طقم متوازٍ تُجوَّع العزلة ثوانيَ
// متواصلة، فمهلة قصيرة تنفد قبل وصول الإشارة فيُكمل المعالج دون أن
// يلمحها — سباق جوعٍ لا سباق عقد
Future<CommandOutcome> _pollUntilCancelled(
  TrustedCommand cmd,
  void Function(bool cancelled) onExit,
) async {
  final signal = cmd.cancellation;
  final deadline = DateTime.now().add(const Duration(seconds: 30));
  while (!signal.isCancelled && DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  onExit(signal.isCancelled);
  return const CommandOutcome(ok: true);
}

void main() {
  test(
    'the handler budget expiry cancels the signal the handler reads',
    timeout: const Timeout(Duration(seconds: 60)),
    () async {
      var observed = false;
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (cmd) =>
            _pollUntilCancelled(cmd, (cancelled) => observed = cancelled),
        protection: _allowlist(),
        handlerTimeout: const Duration(milliseconds: 200),
      );
      final port = await srv.start(preferredPort: 0);
      try {
        final (status, body) = await _post(port);
        expect(status, 504);
        expect(body, contains('handler_timeout'));
        // المعالج يعمل كيتيم بعد الرد؛ الشاهد أن الإشارة شُعلت لحظة
        // الـ504 فلمسه المعالج — الاقتراع حتى الرؤية (لا نوماً ثابتاً)
        // يصمد ضد تجويع العزلة على عدّاء بطيء تحت طقم متوازٍ
        var waited = 0;
        while (!observed && waited < 10000) {
          await Future<void>.delayed(const Duration(milliseconds: 10));
          waited += 10;
        }
        expect(
          observed,
          isTrue,
          reason:
              'the budget expiry fires the signal - a handler that reads '
              'it can abandon work the page will never see',
        );
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'stop() fires the signal of a live seat: the handler wraps up, the '
    'seat drains, and the stop reports fully drained',
    timeout: const Timeout(Duration(seconds: 60)),
    () async {
      var sawCancelled = false;
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (cmd) =>
            _pollUntilCancelled(cmd, (cancelled) => sawCancelled = cancelled),
        protection: _allowlist(),
        handlerTimeout: LocalIntakeServer.noHandlerTimeout,
      );
      final port = await srv.start(preferredPort: 0);
      final slow = _post(port);
      // ننتظر حتى يمسك المعالج مقعده فعلا (حتمي بالعدّاد لا بالساعة)
      while (srv.counters.activeSeats == 0) {
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
      expect(srv.counters.activeSeats, 1);
      final report = await srv.stop(timeout: const Duration(seconds: 2));
      final (status, _) = await slow;
      expect(status, 200, reason: 'the handler answered before the cut');
      expect(
        sawCancelled,
        isTrue,
        reason: 'stop() fires the cooperative signal for live handlers',
      );
      expect(
        report.fullyDrained,
        isTrue,
        reason:
            'the handler wrapped up on the signal, so the seat drained '
            'inside the stop deadline',
      );
    },
  );

  test('a command built outside the intake carries the never-cancelled '
      'signal', () {
    const cmd = TrustedCommand(
      source: 'unknown-origin',
      payloads: ['X'],
      headers: {},
      correlationId: 'c',
    );
    expect(
      cmd.cancellation.isCancelled,
      isFalse,
      reason:
          'the const default never cancels - the intake always passes '
          'its own live per-command signal',
    );
    // وإشعالها اليدوي لا يفعل شيئا: العقد الثابت لا يُلمس
    cmd.cancellation.cancel();
    expect(cmd.cancellation.isCancelled, isFalse);
  });
}
