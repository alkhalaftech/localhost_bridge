// عقد خطأ المحلل على الحافة: HttpException الذي يبلغ معالجة ناتج قراءة
// الجسم هو من طبقة محلل dart:io حول شكل الرسالة الواردة حصراً (تأطير
// chunked معتل كContent-Length مع Transfer-Encoding بجسم خام، أو سطر حجم
// غير سداسي، أو انقطاع وسط الجسم) — يُرد 400 bad_request ويُقطع الاتصال
// على المقبس الخام بنمط الرفض المبكر، فلا يبلغ شبكة الأمان فيصير 500
// internal وسجل انهيار على خطأ شكل من العميل. الخط المرسوم: رموزنا
// الخاصة (سقف الجسم والمهلة وUTF-8) معالجة فوقه، وكل خطأ آخر عند هذه
// النقطة يبقى للمسار 500 القائم — وانحلال المعالج الداخلي يبقى 500 كما هو.
// والحارسات: تأطير chunked سليم مع Content-Length كاذبة يُخدم كما هو
// (المحلل يتجاهل CL عند TE chunked)، وPOST العادي يُخدم كما هو.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson;

var _idSeq = 0;
String _counterId() => 'parser-${_idSeq++}';

const _goodBody = '{"data":["PING"]}';

/// Telemetry recorder - the error count is asserted so a parser-shaped
/// client error no longer lands in the crash-log seam the host reads.
class _ParseRec extends BridgeTelemetry {
  final errors = <String>[];
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
  }) {}

  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    errors.add(message);
  }

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) async {
    return await body();
  }
}

/// One raw-socket exchange with a single subscription: returns the parsed
/// reply (status, headers, body), and with [observeEof] keeps reading after
/// the reply until EOF arrives on the same socket - `eofMs` null means the
/// connection stayed open past the reply.
Future<Map<String, Object?>> _exchange(
  int port,
  String request, {
  Duration wait = const Duration(seconds: 10),
  bool observeEof = false,
}) async {
  final socket = await Socket.connect('127.0.0.1', port);
  final buffer = BytesBuilder();
  final sw = Stopwatch()..start();
  int? replyMs;
  int? eofMs;
  Map<String, Object?>? reply;
  final replyDone = Completer<void>();
  final eofDone = Completer<void>();
  late final StreamSubscription<List<int>> sub;
  void checkReply() {
    if (replyDone.isCompleted) return;
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
    if (hasCl || text.endsWith('0\r\n\r\n')) {
      replyMs = sw.elapsedMilliseconds;
      final text2 = latin1.decode(buffer.toBytes(), allowInvalid: true);
      final sep2 = text2.indexOf('\r\n\r\n');
      final head2 = text2.substring(0, sep2);
      final body2 = text2.substring(sep2 + 4);
      final statusLine = head2.split('\r\n').first;
      final headers = <String, String>{};
      for (final line in head2.split('\r\n').skip(1)) {
        final i = line.indexOf(':');
        if (i > 0) {
          headers[line.substring(0, i).trim().toLowerCase()] = line
              .substring(i + 1)
              .trim();
        }
      }
      reply = {
        'status': int.tryParse(statusLine.split(' ')[1]) ?? -1,
        'headers': headers,
        'body': body2,
        'replyMs': replyMs,
      };
      replyDone.complete();
    }
  }

  sub = socket.listen(
    (chunk) {
      buffer.add(chunk);
      checkReply();
    },
    onDone: () {
      if (!replyDone.isCompleted) {
        // الاتصال انتهى بلا رد كامل — ما وصل يُحلل كما هو (status -1 بلا
        // سطر حالة) كي يثبت الفارق عن رد كامل
        replyMs = sw.elapsedMilliseconds;
        final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
        final sep = text.indexOf('\r\n\r\n');
        final head = sep < 0 ? text : text.substring(0, sep);
        final statusLine = head.isEmpty ? '' : head.split('\r\n').first;
        reply = {
          'status': statusLine.isEmpty
              ? -1
              : (int.tryParse(statusLine.split(' ')[1]) ?? -1),
          'headers': <String, String>{},
          'body': sep < 0 ? '' : text.substring(sep + 4),
          'replyMs': replyMs,
        };
        replyDone.complete();
      }
      if (!eofDone.isCompleted) {
        eofMs = sw.elapsedMilliseconds;
        eofDone.complete();
      }
    },
    onError: (Object _) {
      if (!replyDone.isCompleted) replyDone.complete();
      if (!eofDone.isCompleted) {
        eofMs = -3;
        eofDone.complete();
      }
    },
  );
  socket.write(request);
  try {
    await replyDone.future.timeout(wait, onTimeout: () {});
    if (!replyDone.isCompleted) {
      reply = {
        'status': -2,
        'headers': <String, String>{},
        'body': 'NO-RESPONSE',
        'replyMs': -1,
      };
    } else if (observeEof) {
      await eofDone.future.timeout(
        const Duration(seconds: 6),
        onTimeout: () {},
      );
    }
  } finally {
    await sub.cancel();
    socket.destroy();
  }
  final result = <String, Object?>{...reply!};
  if (observeEof) result['eofMs'] = eofMs;
  return result;
}

String _clTeRequest(int port) =>
    // الترويستتان معاً وجسم خام بلا تأطير chunked: المحلل يتجاهل CL عند TE
    // chunked فيقرأ "PING" سطرَ حجمٍ فيرمي HttpException وسط الجسم
    'POST / HTTP/1.1\r\n'
    'Host: 127.0.0.1:$port\r\n'
    'Origin: https://attacker.example\r\n'
    'Content-Type: application/json\r\n'
    'Content-Length: 4\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    'PING';

String _plainRequest(int port) =>
    'POST / HTTP/1.1\r\n'
    'Host: 127.0.0.1:$port\r\n'
    'Origin: https://attacker.example\r\n'
    'Content-Type: application/json\r\n'
    'Content-Length: ${_goodBody.length}\r\n'
    '\r\n'
    '$_goodBody';

LocalIntakeServer _allowAllServer(
  _ParseRec rec, {
  void Function()? onCommandCall,
}) {
  final protection = IntakeProtection(telemetry: rec);
  // الغياب يمر كي يصل الطلب إلى قراءة الجسم — المخالفة الحاضرة تبقى
  // مرفوضة بعقد المسار المتصفحي القائم
  protection.update(
    policy: const OriginPolicy(
      allowAllHardened: true,
      requireFetchMetadata: false,
    ),
  );
  return LocalIntakeServer(
    telemetry: rec,
    correlationIdGenerator: _counterId,
    onCommand: (_) async {
      onCommandCall?.call();
      return const CommandOutcome(ok: true);
    },
    protection: protection,
  );
}

void main() {
  test(
    'a request carrying Content-Length together with Transfer-Encoding answers 400 bad_request with the handler, the security counter, and the crash log untouched',
    () async {
      final rec = _ParseRec();
      var handlerCalls = 0;
      final srv = _allowAllServer(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final before = srv.protection.rejectedCount;
      final r = await _exchange(p, _clTeRequest(p));
      expect(
        r['status'],
        400,
        reason:
            'a parser-shaped wire error is the client\'s shape, not an '
            'internal fault',
      );
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'bad_request',
        reason: 'the stable code names the refused condition',
      );
      expect(
        handlerCalls,
        0,
        reason: 'the unparseable request never reaches the handler',
      );
      expect(
        srv.protection.rejectedCount,
        before,
        reason: 'a wire-shape reject stays outside the security counter',
      );
      expect(
        rec.errors,
        isEmpty,
        reason: 'no crash-log entry for a client framing error',
      );
      expect(
        (r['headers'] as Map<String, String>)['x-correlation-id'],
        isNotNull,
        reason: 'every reply carries a correlation id',
      );
    },
  );

  test(
    'the connection is cut after the bad_request reply: Connection close and EOF on the same socket',
    () async {
      final rec = _ParseRec();
      final srv = _allowAllServer(rec);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(p, _clTeRequest(p), observeEof: true);
      expect(
        (r['headers'] as Map<String, String>)['connection'],
        'close',
        reason: 'the reply itself declares the cut',
      );
      expect(
        r['eofMs'],
        isA<int>(),
        reason:
            'EOF lands on the same socket after the reply - a rejected '
            'request never leaves a reusable connection',
      );
    },
  );

  test(
    'the next request on a fresh connection is served after a parser-error reject',
    () async {
      final rec = _ParseRec();
      var handlerCalls = 0;
      final srv = _allowAllServer(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final hostile = await _exchange(p, _clTeRequest(p));
      expect(hostile['status'], 400);
      final next = await _exchange(p, _plainRequest(p));
      expect(
        next['status'],
        200,
        reason: 'the cut reject leaves the intake serving normally',
      );
      expect(handlerCalls, 1);
    },
  );

  test(
    'an invalid chunk-size line mid-body is answered 400 bad_request the same way',
    () async {
      final rec = _ParseRec();
      var handlerCalls = 0;
      final srv = _allowAllServer(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        'POST / HTTP/1.1\r\n'
        'Host: 127.0.0.1:$p\r\n'
        'Origin: https://attacker.example\r\n'
        'Content-Type: application/json\r\n'
        'Transfer-Encoding: chunked\r\n'
        '\r\n'
        'ZZ\r\n4\r\nPING\r\n0\r\n\r\n',
      );
      expect(r['status'], 400);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'bad_request',
        reason:
            'every body-framing error from the parser takes the same '
            'edge reply',
      );
      expect(handlerCalls, 0);
      expect(rec.errors, isEmpty);
    },
  );

  test(
    'a well-framed chunked body with a lying Content-Length is still served',
    () async {
      final rec = _ParseRec();
      var handlerCalls = 0;
      final srv = _allowAllServer(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        'POST / HTTP/1.1\r\n'
        'Host: 127.0.0.1:$p\r\n'
        'Origin: https://attacker.example\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: 999999\r\n'
        'Transfer-Encoding: chunked\r\n'
        '\r\n'
        '4\r\nPING\r\n0\r\n\r\n',
      );
      expect(
        r['status'],
        200,
        reason:
            'the parser ignores Content-Length under chunked framing - '
            'legitimate chunked clients are unchanged',
      );
      expect(handlerCalls, 1);
    },
  );

  test('a plain Content-Length POST is still served', () async {
    final rec = _ParseRec();
    var handlerCalls = 0;
    final srv = _allowAllServer(rec, onCommandCall: () => handlerCalls++);
    final p = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final r = await _exchange(p, _plainRequest(p));
    expect(r['status'], 200, reason: 'the ordinary path is untouched');
    expect(handlerCalls, 1);
  });

  test(
    'a handler crash still answers 500 internal - the internal-error path is unchanged',
    () async {
      final rec = _ParseRec();
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (_) async => throw StateError('boom'),
        protection: IntakeProtection(telemetry: rec)
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
            ),
          ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(p, _plainRequest(p));
      expect(r['status'], 500);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'internal',
        reason: 'handler-internal faults keep the plain internal reply',
      );
    },
  );
}
