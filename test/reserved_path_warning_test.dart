// المسارات غير "/": الوثائق تقول إنها محجوزة والخادم يمرر أي مسار إلى
// المعالج بلا فحص. السلوك على السلك لا يتغير: كل مسار يبقى يبلغ
// المعالج ويُخدم كما هو. الجديد مرصدٌ لا بوابة: كل POST على مسار
// آخر يكتب تحذيراً مكبوحاً — مرة في الثانية على الأكثر بالساعة
// المحقونة الحتمية، والسطر التالي بعد النافذة يحمل عدد المكتوم كي
// يبقى حجم الاستعمال مرئياً. OPTIONS يُجاب 204 قبل هذا الموضع وغير
// POST يُرد 405 قبله — فالتحذير لطلب الأمر الفعلي (POST) حصراً.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson;

var _idSeq = 0;
String _counterId() => 'rpw-${_idSeq++}';

/// Telemetry recorder - the warns list is what the host reads, so the
/// throttled warning is asserted on the seam itself.
class _PathRec extends BridgeTelemetry {
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
  Duration wait = const Duration(seconds: 10),
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

/// A thousand command POSTs pipelined over one keep-alive connection:
/// the socket is read while the writes queue, and the flood completes
/// when [count] status lines came back. Reading is not per-reply framing
/// but a status-line count - the warning throttle is what is asserted.
Future<void> _flood(int port, String raw, int count) async {
  final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
  final received = BytesBuilder();
  final allDone = Completer<void>();
  late final StreamSubscription<List<int>> sub;
  sub = socket.listen((chunk) {
    received.add(chunk);
    if (allDone.isCompleted) return;
    final text = latin1.decode(received.toBytes(), allowInvalid: true);
    if ('HTTP/1.1 200'.allMatches(text).length >= count) allDone.complete();
  });
  for (var i = 0; i < count; i++) {
    socket.write(raw);
  }
  await allDone.future.timeout(const Duration(seconds: 30));
  await sub.cancel();
  socket.destroy();
}

LocalIntakeServer _server(
  _PathRec rec, {
  required int Function() nowMs,
  void Function()? onCommandCall,
}) {
  return LocalIntakeServer(
    nowMs: nowMs,
    telemetry: rec,
    correlationIdGenerator: _counterId,
    onCommand: (_) async {
      onCommandCall?.call();
      return const CommandOutcome(ok: true);
    },
    protection: IntakeProtection(telemetry: rec)
      ..update(
        // حصة الفيض مرفوعة لكل أصل كي لا يرد فيض الألف طلب 429 ويقطع
        // الاتصال قبل أن يثبت الشاهد الكبح نفسه (الافتراضي 30/دقيقة)
        policy: const OriginPolicy(
          allowAllHardened: true,
          perOriginPerMinute: 100000,
        ),
      ),
  );
}

/// The path warning lines this wing asserts on - one filter in one place.
List<String> _pathWarns(_PathRec rec) =>
    rec.warns.where((w) => w.contains('non-root path')).toList();

void main() {
  test(
    'a POST on /x is still served 200 with the handler invoked - the wire behavior does not change',
    () async {
      final rec = _PathRec();
      var handlerCalls = 0;
      final srv = _server(
        rec,
        nowMs: () => 0,
        onCommandCall: () => handlerCalls++,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(p, _postTo(p, '/x'));
      expect(
        r['status'],
        200,
        reason:
            'every path still reaches the handler - nothing on the wire changes',
      );
      expect(handlerCalls, 1, reason: 'the command ran exactly as on "/"');
    },
  );

  test(
    'a thousand POSTs to /x within one injected second write exactly one warning line, and the next second writes a line carrying the muted count',
    () async {
      final rec = _PathRec();
      var handlerCalls = 0;
      var fakeNow = 0;
      final srv = _server(
        rec,
        nowMs: () => fakeNow,
        onCommandCall: () => handlerCalls++,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      await _flood(p, _postTo(p, '/x'), 1000);
      expect(handlerCalls, 1000, reason: 'every flooded request was served');
      expect(
        _pathWarns(rec),
        hasLength(1),
        reason: 'the whole flood inside one clock second mutes into one line',
      );
      expect(_pathWarns(rec).single, contains('"/x"'));

      fakeNow = 1000;
      final r = await _exchange(p, _postTo(p, '/x'));
      expect(r['status'], 200);
      final warns = _pathWarns(rec);
      expect(
        warns,
        hasLength(2),
        reason: 'the next clock second admits exactly one more line',
      );
      expect(
        warns.last,
        contains('+999 more suppressed'),
        reason:
            'the follow-up line carries the muted count so the flood size stays visible',
      );
    },
  );

  test('a POST on / writes no path warning at all', () async {
    final rec = _PathRec();
    final srv = _server(rec, nowMs: () => 0);
    final p = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final r = await _exchange(p, _postTo(p, '/'));
    expect(r['status'], 200);
    expect(rec.warns.where((w) => w.contains('non-root path')), isEmpty);
  });

  test(
    'an OPTIONS preflight on /x answers 204 and writes no path warning - only the command method warns',
    () async {
      final rec = _PathRec();
      final srv = _server(rec, nowMs: () => 0);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final preflight =
          'OPTIONS /x HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
          'Origin: https://portal.example\r\n'
          'Access-Control-Request-Method: POST\r\n'
          'Content-Length: 0\r\n\r\n';
      final r = await _exchange(p, preflight);
      expect(r['status'], 204, reason: 'the preflight answer does not move');
      expect(
        rec.warns.where((w) => w.contains('non-root path')),
        isEmpty,
        reason:
            'OPTIONS never reaches the handler and cannot carry a command, so it never warns',
      );
    },
  );

  test(
    'a non-POST method on /x answers 405 and writes no path warning',
    () async {
      final rec = _PathRec();
      final srv = _server(rec, nowMs: () => 0);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        'GET /x HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n\r\n',
      );
      expect(r['status'], 405);
      expect(bodyJson(r.cast<String, Object>())['error'], 'method_not_allowed');
      expect(
        rec.warns.where((w) => w.contains('non-root path')),
        isEmpty,
        reason:
            'the method gate answers before the path is ever a command carrier',
      );
    },
  );

  test('a bloated request path is capped inside the warning line', () async {
    final rec = _PathRec();
    final srv = _server(rec, nowMs: () => 0);
    final p = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final bloated = '/${'a' * 400}';
    final r = await _exchange(p, _postTo(p, bloated));
    expect(r['status'], 200, reason: 'the wire keeps serving the long path');
    final warns = _pathWarns(rec);
    expect(warns, hasLength(1));
    expect(
      warns.single,
      contains('"/${'a' * 127}"'),
      reason:
          'the warned form is capped so a bloated path cannot inflate the line',
    );
    expect(
      warns.single.contains(bloated),
      isFalse,
      reason: 'the raw 400-character path never lands in the log whole',
    );
  });
}
