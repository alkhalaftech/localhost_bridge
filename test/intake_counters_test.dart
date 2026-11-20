// عدادات القراءة فقط: المقاعد المستعملة، واليتامى العاملون عبر
// الأجيال، والرفض حسب الرمز من مخرج الرد الواحد، وعددا الشكل
// البروتوكولي والاقتران — لقطة قراءة لا تُكتب. العناوين بالإنجليزية
// (حزمة منشورة) والتعليقات بالعربية (قاعدة البيت).
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
String _cid() => 'counters-${_idSeq++}';

IntakeProtection _allowlist() {
  final pr = IntakeProtection(telemetry: _Rec());
  pr.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
  return pr;
}

/// طلب حقيقي عبر HttpClient يعيد (الحالة، الجسم).
Future<(int, String)> _post(
  int port, {
  String origin = 'https://portal.example',
  String path = '/',
  String body = '["CMD"]',
}) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port$path'));
    req.headers.set('Origin', origin);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode(body));
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
    'rejection tallies count from the single reply exit: by code, the '
    'protocol-shape tally, and the pairing tally',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final pr = _allowlist();
      pr.enablePairing();
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: pr,
      );
      final port = await srv.start(preferredPort: 0);
      try {
        // رفض شكل بروتوكولي: أصل معتل — خارج عدّاد الحماية وسجلها
        final (bad, badBody) = await _post(port, origin: 'not-an-origin');
        expect(bad, 400);
        expect(badBody, contains('origin_malformed'));
        // رفض اقتران على مسار الاقتران المسلح: رمز مجهول
        final (pairStatus, pairBody) = await _post(
          port,
          path: '/pair',
          body: '{"pairingCode":"000000"}',
        );
        expect(pairStatus, 403);
        expect(pairBody, contains('pair_code_invalid'));
        // أمر ناجح: لا رفض ولا عدّ
        final (ok, _) = await _post(port);
        expect(ok, 200);

        final c = srv.counters;
        expect(c.rejectionsByCode['origin_malformed'], 1);
        expect(c.rejectionsByCode['pair_code_invalid'], 1);
        expect(
          c.protocolShapeRejections,
          1,
          reason: 'only the wire-shape gate lands in the shape tally',
        );
        expect(
          c.pairingRejections,
          1,
          reason: 'the pairing route refusal carries its own tally',
        );
        expect(
          c.rejectionsByCode.length,
          2,
          reason: 'the successful command is not a rejection',
        );
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'the seats counter tracks live work from zero to one back to zero',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final hold = Completer<void>();
      var observedInFlight = -1;
      // late: إغلاق المعالج يقرأ الخادم وقت الاستدعاء لا وقت الإسناد
      late final LocalIntakeServer srv;
      srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) async {
          // المعالج نفسه يقرأ عداد المقاعد وهو ممسك مقعده — القراءة
          // لحظية لا محسوبة بعد الحسم
          observedInFlight = srv.counters.activeSeats;
          await hold.future;
          return const CommandOutcome(ok: true);
        },
        protection: _allowlist(),
      );
      final port = await srv.start(preferredPort: 0);
      final flying = _post(port);
      while (srv.counters.activeSeats == 0) {
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
      expect(srv.counters.activeSeats, 1);
      hold.complete();
      final (status, _) = await flying;
      expect(status, 200);
      expect(observedInFlight, 1, reason: 'the handler saw its own seat');
      // تحرر المقعد بعد وصول الرد بلحظة — الإثبات بالعدّاد لا بالهامش
      var freed = 0;
      while (srv.counters.activeSeats > 0 && freed < 100) {
        freed++;
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
      expect(
        srv.counters.activeSeats,
        0,
        reason: 'the seat freed when the reply settled',
      );
      await srv.stop().timeout(const Duration(seconds: 5));
    },
  );

  test(
    'the retired orphans of a previous generation stay visible in the '
    'counter and never in the new generation budget',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // ستة عشر لا يكملون ثم stop ثم start: العداد يبقيهم ظاهرين (16)
      // والمتقاعدون حصتهم معلومة، والأمر التالي يُخدم
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
          final (status, _) = await _post(port);
          expect(status, 504);
        }
        expect(srv.counters.orphanHandlers, 16);
        expect(srv.counters.retiredOrphanHandlers, 0);
        await srv.stop().timeout(const Duration(seconds: 5));
        final p2 = await srv
            .start(preferredPort: 0)
            .timeout(const Duration(seconds: 5));
        final (status, body) = await _post(p2);
        expect(status, 200, reason: 'the new generation is not blocked');
        expect(body, contains('"ok":true'));
        expect(
          srv.counters.orphanHandlers,
          16,
          reason: 'still working, so still visible across the restart',
        );
        expect(
          srv.counters.retiredOrphanHandlers,
          16,
          reason: 'every one of them is a retired-generation orphan',
        );
      } finally {
        if (!never.isCompleted) never.complete(const CommandOutcome(ok: true));
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'the counters snapshot is read-only for the host',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: _allowlist(),
      );
      final port = await srv.start(preferredPort: 0);
      try {
        await _post(port);
        final c = srv.counters;
        expect(
          () => c.rejectionsByCode['x'] = 5,
          throwsUnsupportedError,
          reason: 'a snapshot is a reading, never a writable map',
        );
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );
}
