// كبح أسطر التحذير: أربعة مواضع تكتب سطراً لكل طلب تحت الضغط —
// الانشغال، وانشغال اليتامى، ومهلة المعالج، واحتراق المهلة الكلية —
// فينمو السجل بمعدل الرفض لا بمعدل الحادثة. كل موضع يكتب مرة في
// الثانية على الأكثر بالساعة المحقونة، والسطر التالي بعد النافذة
// يحمل عدد المكتوم كي يبقى حجم الفيضان مرئياً. السلك لا يتغير: كل
// طلب يظل يجيب رمزه (503 انشغال، 503 انشغال اليتامى، 504 مهلة
// المعالج، قطع المهلة الكلية) سواء حُذّر عنه أو كُتِم.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _counterId() => 'tw-${_idSeq++}';

/// Telemetry recorder - the warns list is what the host reads, so the
/// throttling is asserted on the seam itself.
class _Rec extends BridgeTelemetry {
  final warns = <String>[];

  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}

  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    warns.add(message);
  }

  @override
  void error(
    String message, {
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
  }) async => await body();
}

Future<Map<String, Object?>> _exchange(
  int port,
  String request, {
  Duration wait = const Duration(seconds: 20),
}) async {
  final socket = await Socket.connect('127.0.0.1', port);
  final buffer = BytesBuilder();
  final done = Completer<Map<String, Object?>>();
  late final StreamSubscription<List<int>> sub;
  void settle(List<int> raw) {
    final text = latin1.decode(raw, allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    final head = sep < 0 ? text : text.substring(0, sep);
    final body = sep < 0 ? '' : text.substring(sep + 4);
    final statusLine = head.isEmpty ? '' : head.split('\r\n').first;
    final headers = <String, String>{};
    for (final line in head.split('\r\n').skip(1)) {
      final i = line.indexOf(':');
      if (i > 0) {
        headers[line.substring(0, i).trim().toLowerCase()] = line
            .substring(i + 1)
            .trim();
      }
    }
    done.complete({
      'status': statusLine.isEmpty
          ? -1
          : (int.tryParse(statusLine.split(' ')[1]) ?? -1),
      'headers': headers,
      'body': body,
    });
  }

  sub = socket.listen(
    (chunk) {
      buffer.add(chunk);
      if (done.isCompleted) return;
      final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
      final sep = text.indexOf('\r\n\r\n');
      if (sep < 0) return;
      final head = text.substring(0, sep);
      final clMatch = RegExp(
        r'content-length:\s*(\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      final bodyLen = text.length - (sep + 4);
      final hasCl = clMatch != null && bodyLen >= int.parse(clMatch.group(1)!);
      if (hasCl || text.endsWith('0\r\n\r\n')) settle(buffer.toBytes());
    },
    onDone: () {
      if (!done.isCompleted) settle(buffer.toBytes());
    },
  );
  socket.write(request);
  final result = await done.future.timeout(
    wait,
    onTimeout: () => <String, Object?>{
      'status': -2,
      'headers': <String, String>{},
      'body': 'NO-RESPONSE',
    },
  );
  await sub.cancel();
  socket.destroy();
  return result;
}

/// Browser-like command POST against [path] with the two Sec-Fetch headers.
String _postTo(int port, String path) =>
    'POST $path HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n'
    'Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n'
    'Origin: https://portal.example\r\n'
    'Content-Type: application/json\r\n'
    'Content-Length: 17\r\n\r\n{"data":["PING"]}';

/// A recorder whose request measurement never settles: the measurement
/// seam itself is the pre-handler hang - no gate, no body read, and no
/// managed close was ever attempted, so the total-deadline cut lands on
/// the untouched response. The deadline must still warn (throttled) and
/// cut while a hung measurement future holds the request. (The
/// attack-shaped OPTIONS-with-declared-body hang cannot take the cut: a
/// pending managed close holds the response and HttpRequest exposes no
/// socket to destroy - its seat is still freed by the deadline's return,
/// and that connection residual stays documented, not asserted.)
class _HangMeasureRec extends _Rec {
  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) {
    if (label == 'intake.handleRequest') {
      return Completer<T>().future;
    }
    return super.measure(label, body, context: context);
  }
}

/// Fires [count] concurrent command POSTs in small overlapping batches,
/// each on its own connection (every reject path here cuts the
/// connection by design, so one socket per request is the honest
/// shape), and returns the HTTP status of every reply - (-1) when the
/// connection was cut without a reply. The injected clock stays frozen
/// across the whole burst, so all events land inside one clock second.
/// [chunk] keeps each wave below any seat gate the scenario must pass.
Future<List<int>> _burst(
  int port,
  String raw,
  int count, {
  int chunk = 100,
}) async {
  final statuses = <int>[];
  for (var i = 0; i < count; i += chunk) {
    final n = (count - i) < chunk ? (count - i) : chunk;
    final futures = List.generate(
      n,
      (_) => _exchange(port, raw, wait: const Duration(seconds: 20)),
    );
    final results = await Future.wait(futures);
    statuses.addAll(results.map((r) => r['status'] as int));
  }
  return statuses;
}

LocalIntakeServer _server(
  _Rec rec, {
  required int Function() nowMs,
  void Function()? onCommandCall,
  Future<CommandOutcome> Function()? handler,
  BridgeConfig config = const BridgeConfig(),
  Duration? requestTimeout,
  Duration? handlerTimeout,
}) {
  return LocalIntakeServer(
    nowMs: nowMs,
    telemetry: rec,
    correlationIdGenerator: _counterId,
    requestTimeout: requestTimeout,
    handlerTimeout: handlerTimeout,
    config: config,
    onCommand: (_) async {
      onCommandCall?.call();
      if (handler != null) return handler();
      return const CommandOutcome(ok: true);
    },
    protection: IntakeProtection(telemetry: rec)
      ..update(
        // حصة الفيض مرفوعة لكل أصل كي لا يرد الفيض 429 ويقطع الاتصال
        // قبل أن تبلغ أحداثه مواضع التحذير (الافتراضي 30/دقيقة)
        policy: const OriginPolicy(
          allowAllHardened: true,
          perOriginPerMinute: 100000,
        ),
      ),
  );
}

/// The seat-busy lines this wing asserts on - one filter per position.
List<String> _busyWarns(_Rec rec) => rec.warns
    .where(
      (w) => w.contains('intake busy:') && w.contains('concurrent requests'),
    )
    .toList();
List<String> _orphanBusyWarns(_Rec rec) => rec.warns
    .where(
      (w) =>
          w.contains('intake busy:') &&
          w.contains('orphan handler(s) still running'),
    )
    .toList();
List<String> _timeoutWarns(_Rec rec) =>
    rec.warns.where((w) => w.contains('intake handler timeout')).toList();
List<String> _deadlineWarns(_Rec rec) =>
    rec.warns.where((w) => w.contains('exceeded its total deadline')).toList();

void main() {
  test(
    'a thousand busy rejects within one injected second write exactly one warning line, and the next second writes a line carrying the muted count',
    timeout: const Timeout(Duration(seconds: 60)),
    () async {
      final rec = _Rec();
      var fakeNow = 0;
      var handlerCalls = 0;
      final hang = Completer<CommandOutcome>();
      final srv = _server(
        rec,
        nowMs: () => fakeNow,
        config: const BridgeConfig(maxConcurrentRequests: 1),
        onCommandCall: () => handlerCalls++,
        handler: () => hang.future,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      // الطلب الحاجز: يأخذ المقعد الوحيد ويعلق فيه — كل ما بعده يُرد
      // انشغالاً بلا أن يبلغ المعالج
      unawaited(_exchange(p, _postTo(p, '/')).then((_) {}, onError: (_) {}));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      final statuses = await _burst(p, _postTo(p, '/x'), 1000);
      expect(
        statuses,
        everyElement(503),
        reason:
            'the wire does not change: every flooded request is still '
            'answered 503 server_busy',
      );
      expect(
        handlerCalls,
        1,
        reason: 'the refused requests never reach the handler',
      );
      expect(
        _busyWarns(rec).length,
        1,
        reason:
            'the whole busy flood inside one clock second mutes into one line',
      );

      fakeNow = 1000;
      final more = await _burst(p, _postTo(p, '/x'), 1);
      expect(more.single, 503);
      final warns = _busyWarns(rec);
      expect(
        warns.length,
        2,
        reason: 'the next clock second admits exactly one more line',
      );
      expect(
        warns.last,
        contains('+999 more suppressed'),
        reason:
            'the follow-up line carries the muted count so the flood size '
            'stays visible',
      );

      // يحرر الحاجز مقعده قبل الفراغ كي يصرف stop بلا انتظار
      hang.complete(const CommandOutcome(ok: true));
      await Future<void>.delayed(const Duration(milliseconds: 50));
    },
  );

  test(
    'a thousand orphan-busy rejects within one injected second write exactly one warning line, and the next second writes a line carrying the muted count',
    timeout: const Timeout(Duration(seconds: 60)),
    () async {
      final rec = _Rec();
      var fakeNow = 0;
      var handlerCalls = 0;
      final srv = _server(
        rec,
        nowMs: () => fakeNow,
        config: const BridgeConfig(maxConcurrentRequests: 16),
        handlerTimeout: const Duration(milliseconds: 200),
        onCommandCall: () => handlerCalls++,
        handler: () => Completer<CommandOutcome>().future,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      // البذرة: ستة عشر معالجا لا يكملون — مهلة المعالج تحرر كل مقعد
      // برد 504 ويبقى الستة عشر يتيمة حية فتملأ ميزانية العمل الحي
      // حتى الحد. بقعة 10 تحت 16 كي يمر كل طلب بوابة المقاعد ويصيب
      // بوابة اليتامى هي (بوابة المقاعد تسبقها فالأكبر يُرد عندها)
      final seedStatuses = await _burst(p, _postTo(p, '/'), 16);
      expect(
        seedStatuses,
        everyElement(504),
        reason: 'the seed requests time out into orphans exactly as before',
      );
      expect(handlerCalls, 16);

      final statuses = await _burst(p, _postTo(p, '/x'), 1000, chunk: 10);
      expect(
        statuses,
        everyElement(503),
        reason:
            'the wire does not change: the seats-plus-orphans budget still '
            'refuses with 503 before invoking another handler',
      );
      expect(
        handlerCalls,
        16,
        reason:
            'the refused requests never reach the handler - only the '
            'sixteen seeds ever did',
      );
      expect(
        _orphanBusyWarns(rec).length,
        1,
        reason:
            'the whole orphan-busy flood inside one clock second mutes into '
            'one line',
      );

      fakeNow = 1000;
      final more = await _burst(p, _postTo(p, '/x'), 1, chunk: 10);
      expect(more.single, 503);
      final warns = _orphanBusyWarns(rec);
      expect(
        warns.length,
        2,
        reason: 'the next clock second admits exactly one more line',
      );
      expect(
        warns.last,
        contains('+999 more suppressed'),
        reason:
            'the follow-up line carries the muted count so the flood size '
            'stays visible',
      );
    },
  );

  test(
    'a thousand handler timeouts within one injected second write exactly one warning line, and the next second writes a line carrying the muted count',
    timeout: const Timeout(Duration(seconds: 60)),
    () async {
      final rec = _Rec();
      var fakeNow = 0;
      var handlerCalls = 0;
      final srv = _server(
        rec,
        nowMs: () => fakeNow,
        config: const BridgeConfig(maxConcurrentRequests: 2000),
        handlerTimeout: const Duration(milliseconds: 30),
        onCommandCall: () => handlerCalls++,
        handler: () async {
          await Future<void>.delayed(const Duration(milliseconds: 250));
          return const CommandOutcome(ok: true);
        },
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      final statuses = await _burst(p, _postTo(p, '/x'), 1000);
      expect(
        statuses,
        everyElement(504),
        reason:
            'the wire does not change: every slow handler still answers '
            '504 handler_timeout',
      );
      expect(
        handlerCalls,
        1000,
        reason: 'every request still reaches the handler',
      );
      expect(
        _timeoutWarns(rec).length,
        1,
        reason:
            'the whole timeout flood inside one clock second mutes into one line',
      );

      fakeNow = 1000;
      // يتيمُ الموجة الأولى يستقر (250ms) قبل موجة السطر الثاني كي يظل
      // الحدث الوحيد في نافذته هو مهلة المعالج الجديدة نفسها
      await Future<void>.delayed(const Duration(milliseconds: 250));
      final more = await _burst(p, _postTo(p, '/x'), 1);
      expect(more.single, 504);
      final warns = _timeoutWarns(rec);
      expect(
        warns.length,
        2,
        reason: 'the next clock second admits exactly one more line',
      );
      expect(
        warns.last,
        contains('+999 more suppressed'),
        reason:
            'the follow-up line carries the muted count so the flood size '
            'stays visible',
      );
    },
  );

  test(
    'a thousand total-deadline cuts within one injected second write exactly one warning line, and the next second writes a line carrying the muted count',
    timeout: const Timeout(Duration(seconds: 90)),
    () async {
      final rec = _HangMeasureRec();
      var fakeNow = 0;
      var handlerCalls = 0;
      final srv = _server(
        rec,
        nowMs: () => fakeNow,
        config: const BridgeConfig(maxConcurrentRequests: 2000),
        requestTimeout: const Duration(milliseconds: 400),
        onCommandCall: () => handlerCalls++,
        handler: () => Completer<CommandOutcome>().future,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      // التعليق قبل المعالج هو ما تبقى تحت المهلة الكلية: قياس القياس
      // نفسه لا يكتمل فيبقى الطلب بلا بوابات ولا قراءة جسم ولا close()
      // معلقة — فتهبط القطع الكلية على الاستجابة النقية قطعاً بلا رد،
      // وما قبل المعالج حصرا فلا طلب يبلغ معالجاً
      final statuses = await _burst(p, _postTo(p, '/x'), 1000);
      expect(
        statuses,
        everyElement(-1),
        reason:
            'the wire does not change: the total-deadline cut still answers '
            'nothing - the connection is destroyed without a reply',
      );
      expect(
        handlerCalls,
        0,
        reason:
            'the deadline guards the pre-handler phase alone - none of the '
            'cut requests ever reaches a handler',
      );
      expect(
        _deadlineWarns(rec).length,
        1,
        reason:
            'the whole deadline flood inside one clock second mutes into one line',
      );

      fakeNow = 1000;
      final more = await _burst(p, _postTo(p, '/x'), 1);
      expect(more.single, -1);
      final warns = _deadlineWarns(rec);
      expect(
        warns.length,
        2,
        reason: 'the next clock second admits exactly one more line',
      );
      expect(
        warns.last,
        contains('+999 more suppressed'),
        reason:
            'the follow-up line carries the muted count so the flood size '
            'stays visible',
      );
      // القطعة الثانية يَنُّها (مهلة 400ms + يَن القطع) قبل الفراغ كي
      // يصرف stop بلا مقاعد معلقة
      await Future<void>.delayed(const Duration(milliseconds: 700));
    },
  );
}
