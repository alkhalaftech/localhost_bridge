// عقد stop المحدود وتقاعد اليتامى: stop بمهلة تعود داخل مهلتها وتُبلغ
// بما بقي يعمل، وstop الهادئة تُبلغ بالفراغ الكامل، ويتامى الجيل
// السابق لا يحملهم الجيل الجديد بعد عودة stop ويبقون ظاهرين في العداد.
// العناوين بالإنجليزية (حزمة منشورة) والتعليقات بالعربية (قاعدة البيت).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

class _Rec extends BridgeTelemetry {
  final warns = <String>[];
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
  }) {
    warns.add(m);
  }

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
String _cid() => 'stop-${_idSeq++}';

IntakeProtection _allowlist() {
  final pr = IntakeProtection(telemetry: _Rec());
  pr.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
  return pr;
}

/// طلب حقيقي عبر HttpClient يعيد (الحالة، الجسم) — بنمط شاهد عقد المهلة.
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

void main() {
  test(
    'a never-completing handler: stop(timeout) returns inside the deadline '
    'with margin and reports one working handler',
    timeout: const Timeout(Duration(seconds: 30)),
    () async {
      // الشاهد الأول: المهلة 150ms أقصر من ميزانية اليتامى 400ms عمداً
      // — العودة داخل المهلة بهامش واسع لا عند الميزانية، والتقرير
      // يسمي اليتيم الواحد ما زال يعمل
      final never = Completer<CommandOutcome>();
      final rec = _Rec();
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _cid,
        onCommand: (_) => never.future,
        protection: _allowlist(),
        handlerTimeout: const Duration(milliseconds: 400),
      );
      final port = await srv.start(preferredPort: 0);
      try {
        final (status, body) = await _post(port);
        expect(status, 504);
        expect(body, contains('handler_timeout'));
        final sw = Stopwatch()..start();
        final report = await srv.stop(
          timeout: const Duration(milliseconds: 150),
        );
        expect(
          sw.elapsed,
          lessThan(const Duration(milliseconds: 3000)),
          reason:
              'stop returned inside its own deadline with a wide margin, '
              'not at the orphan budget (took ${sw.elapsedMilliseconds}ms)',
        );
        expect(
          report.orphanHandlersStillRunning,
          1,
          reason: 'the stop reports exactly one working handler',
        );
        expect(report.seatsStillActive, 0);
        expect(report.fullyDrained, isFalse);
        expect(report.stillRunning, 1);
        expect(
          rec.warns.any((w) => w.contains('orphan handler')),
          isTrue,
          reason: 'the remainder is announced, never silent',
        );
      } finally {
        if (!never.isCompleted) never.complete(const CommandOutcome(ok: true));
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'a fully drained stop reports zero working work',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: _allowlist(),
      );
      final port = await srv.start(preferredPort: 0);
      final (status, _) = await _post(port);
      expect(status, 200);
      final report = await srv.stop();
      expect(
        report.fullyDrained,
        isTrue,
        reason: 'a quiet stop drains everything and says so',
      );
      expect(report.stillRunning, 0);
    },
  );

  test(
    'sixteen never-completing handlers, then stop() then start(): the next '
    'command is served and the orphans stay visible in the counter',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // الشاهد الثاني: الستة عشر يتقاعدون عند عودة stop فلا يحملهم
      // الجيل الجديد — الأمر الأول بعد إعادة التشغيل يُخدم 200،
      // والعداد العام يبقيهم ظاهرين ما داموا يعملون
      final never = Completer<CommandOutcome>();
      var calls = 0;
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) {
          calls++;
          return calls <= 16
              ? never.future
              : Future<CommandOutcome>.value(const CommandOutcome(ok: true));
        },
        protection: _allowlist(),
        handlerTimeout: const Duration(milliseconds: 150),
        config: const BridgeConfig(maxConcurrentRequests: 16),
      );
      final port = await srv.start(preferredPort: 0);
      try {
        for (var i = 0; i < 16; i++) {
          final (status, body) = await _post(port);
          expect(
            status,
            504,
            reason: 'request ${i + 1} leaves a working orphan',
          );
          expect(body, contains('handler_timeout'));
        }
        // ظهور المتقاعدين في العداد العام يُحرَس في اختبار العدادات،
        // والتقرير هنا يسمي الستة عشر الذين تُركوا يعملون
        final stopReport = await srv.stop();
        expect(
          stopReport.orphanHandlersStillRunning,
          16,
          reason: 'the stop announces the sixteen it retired',
        );
        final p2 = await srv
            .start(preferredPort: 0)
            .timeout(const Duration(seconds: 5));
        final (nextStatus, nextBody) = await _post(p2);
        expect(
          nextStatus,
          200,
          reason:
              'retired orphans do not count against the new generation - '
              'the first command after the restart is served',
        );
        expect(nextBody, contains('"ok":true'));
      } finally {
        if (!never.isCompleted) never.complete(const CommandOutcome(ok: true));
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'a second stop over still-working retired orphans counts each one '
    'exactly once: the report, the counter, and the bell never ghost',
    timeout: const Timeout(Duration(seconds: 30)),
    () async {
      // دورة stop نفسها المصرَّحة بنص عقد stop («a call after it
      // returned takes its own bounded pass»): stop محدودة فوق يتيم
      // عامل ثم start ثم stop ثانية — المتقاعد سابقاً يُعد مرة واحدة،
      // وبعد استقراره الحقيقي يصفر العدّادان فلا شبح يحرق ميزانية
      // انتظار stop تالية
      final never = Completer<CommandOutcome>();
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) => never.future,
        protection: _allowlist(),
        handlerTimeout: const Duration(milliseconds: 150),
      );
      final port = await srv.start(preferredPort: 0);
      try {
        final (status, _) = await _post(port);
        expect(status, 504);
        final first = await srv.stop(timeout: const Duration(milliseconds: 50));
        expect(first.orphanHandlersStillRunning, 1);
        expect(srv.counters.retiredOrphanHandlers, 1);
        await srv.start(preferredPort: 0).timeout(const Duration(seconds: 5));
        // لا أمر على الجيل الجديد — اليتيم العامل هو وحده ما يُعدّ
        final second = await srv.stop(
          timeout: const Duration(milliseconds: 50),
        );
        expect(
          second.orphanHandlersStillRunning,
          1,
          reason:
              'the orphan retired by the first stop is counted once - a '
              'second stop over the same working ticket must not inflate '
              'the report',
        );
        expect(
          srv.counters.retiredOrphanHandlers,
          1,
          reason: 'the retired pool keeps exactly one still-working orphan',
        );
        // الاستقرار الحقيقي يصفر العدّادين — لا شبح باقٍ إلى الأبد
        if (!never.isCompleted) never.complete(const CommandOutcome(ok: true));
        var waited = 0;
        while (srv.counters.orphanHandlers > 0 && waited < 100) {
          waited++;
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }
        expect(
          srv.counters.orphanHandlers,
          0,
          reason: 'no working orphan remains after the real settlement',
        );
        expect(
          srv.counters.retiredOrphanHandlers,
          0,
          reason:
              'no ghost: the retired pool drains with the very settlement '
              'that ended the work',
        );
        // والجرس دق: stop تالية محدودة تعود بتقرير فراغ لا على أشباح
        final third = await srv.stop(timeout: const Duration(milliseconds: 50));
        expect(
          third.fullyDrained,
          isTrue,
          reason:
              'a later bounded stop reports a clean drain - the drain bell '
              'rang at the real settlement',
        );
        expect(third.orphanHandlersStillRunning, 0);
      } finally {
        if (!never.isCompleted) never.complete(const CommandOutcome(ok: true));
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );
}
