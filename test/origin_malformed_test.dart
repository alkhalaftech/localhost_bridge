// عقد شكل الأصل الصارم: المتصفح لا يرسل إلا scheme://host[:port] وما
// بعدها شرطات ختامية يحدثها التطبيع — وما سواه (معلومات مستخدم، مسار،
// استعلام، جزء، مسافات ومحارف تحكم) يُرد 400 origin_malformed بجوار
// origin_too_long وقبله أي خريطة أو سطر سجل أو نداء موافقة أو صدى CORS.
// والقيمة الحرفية null وغياب الترويسة بمعاملتهما اليوم خارج البوابة،
// والطول يحكم قبل الشكل (المعتل طولاً وشكلاً يُجاب origin_too_long).
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson;

var _idSeq = 0;
String _counterId() => 'shape-${_idSeq++}';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

/// Telemetry recorder - keeps the warns so the gate's no-log contract is
/// asserted on the seam the host actually reads.
class _ShapeRec extends BridgeTelemetry {
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
  }) async {
    return await body();
  }
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

/// A browser-like command POST: the two Sec-Fetch headers ride along so the
/// value reaches the discovery branch today - the shape gate must answer
/// ahead of all of it.
String _post(int port, String origin) =>
    'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n'
    'Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n'
    'Origin: $origin\r\n'
    'Content-Type: application/json\r\n'
    'Content-Length: 17\r\n\r\n{"data":["PING"]}';

LocalIntakeServer _server(
  _ShapeRec rec, {
  bool withDiscovery = true,
  bool allowAll = false,
  List<String> allowed = const ['https://a.example'],
  void Function()? onCommandCall,
  void Function(String origin)? onAsk,
}) {
  return LocalIntakeServer(
    telemetry: rec,
    correlationIdGenerator: _counterId,
    onCommand: (_) async {
      onCommandCall?.call();
      return const CommandOutcome(ok: true);
    },
    protection: IntakeProtection(telemetry: rec)
      ..update(
        policy: allowAll
            ? const OriginPolicy(allowAllHardened: true)
            : OriginPolicy(
                allowed: allowed,
                onUnknownOrigin: withDiscovery
                    ? (origin) async {
                        onAsk?.call(origin);
                        return OriginConsent.dismissed;
                      }
                    : null,
              ),
      ),
  );
}

void main() {
  test(
    'a userinfo origin answers 400 origin_malformed with the handler, the consent callback, the rejection counter, and its log untouched',
    () async {
      final rec = _ShapeRec();
      var handlerCalls = 0;
      var asked = 0;
      final srv = _server(
        rec,
        onCommandCall: () => handlerCalls++,
        onAsk: (_) => asked++,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final before = srv.protection.rejectedCount;
      final r = await _exchange(
        p,
        _post(p, 'https://portal.example@evil.example'),
      );
      expect(
        r['status'],
        400,
        reason: 'the shape gate answers before any policy decision',
      );
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_malformed',
        reason: 'the fixed code sits next to origin_too_long in the contract',
      );
      expect(
        handlerCalls,
        0,
        reason: 'the hostile value never reaches the handler',
      );
      expect(
        asked,
        0,
        reason: 'the hostile value never opens a consent question for the host',
      );
      expect(
        srv.protection.rejectedCount,
        before,
        reason: 'a protocol-shape reject stays outside the security counter',
      );
      expect(
        rec.warns.where((w) => w.contains('intake rejected')),
        isEmpty,
        reason: 'no rejection log line is written for the shape reject',
      );
      expect(
        (r['headers'] as Map<String, String>).containsKey(
          'access-control-allow-origin',
        ),
        isFalse,
        reason: 'no CORS decision runs for a value the browser cannot send',
      );
    },
  );

  test(
    'path, query, space, and control-character origins each answer 400 origin_malformed and no consent question fires',
    () async {
      final rec = _ShapeRec();
      var asked = 0;
      final srv = _server(rec, onAsk: (_) => asked++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final cases = <String, String>{
        'path': 'https://a.example/x',
        'query': 'https://a.example?x=1',
        'space': 'https://a.exa mple',
        // مدى المحارف المضبوطة الثلاثة بشهود دائمين: BEL في C0، وESC،
        // وDEL، ونموذج من C1 — كل المدرجات مرفوضة بالفحص قبل الشكل
        'control': 'https://a.example\u0007',
        'escape': 'https://a.example\u001b',
        'delete': 'https://a.example\u007f',
        'c1-range': 'https://a.example\u0085',
      };
      for (final entry in cases.entries) {
        final r = await _exchange(p, _post(p, entry.value));
        expect(r['status'], 400, reason: 'origin ${entry.key} is refused');
        expect(
          bodyJson(r.cast<String, Object>())['error'],
          'origin_malformed',
          reason: 'origin ${entry.key} carries the stable shape code',
        );
      }
      expect(
        asked,
        0,
        reason: 'no hostile shape ever becomes a consent question',
      );
    },
  );

  test('a trailing slash still matches the listed origin', () async {
    final rec = _ShapeRec();
    var handlerCalls = 0;
    final srv = _server(
      rec,
      withDiscovery: false,
      onCommandCall: () => handlerCalls++,
    );
    final p = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final r = await _exchange(p, _post(p, 'https://a.example/'));
    expect(r['status'], 200, reason: 'the trailing slash normalizes away');
    expect(handlerCalls, 1, reason: 'the listed origin is admitted');
  });

  test(
    'the consent callback receives the normalized origin: lowercase scheme and host, port kept',
    () async {
      final rec = _ShapeRec();
      final received = <String>[];
      final srv = _server(rec, onAsk: received.add);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(p, _post(p, 'HTTPS://A.Example:8443'));
      expect(
        r['status'],
        403,
        reason: 'a well-formed unknown origin still takes the discovery path',
      );
      expect(bodyJson(r.cast<String, Object>())['error'], 'origin_pending');
      expect(
        received,
        ['https://a.example:8443'],
        reason: 'the host window reads the canonical form, never the raw value',
      );
    },
  );

  test(
    'the length gate precedes the shape gate: an Origin both oversized and malformed answers origin_too_long',
    () async {
      final rec = _ShapeRec();
      var asked = 0;
      final srv = _server(rec, onAsk: (_) => asked++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      const head = 'https://padding.example/';
      final both = '$head${'a' * (1100 - head.length - 1)}x';
      final r = await _exchange(p, _post(p, both));
      expect(r['status'], 400);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_too_long',
        reason: 'the length is settled before the shape is read',
      );
      expect(asked, 0);
    },
  );

  test(
    'an Origin at exactly the cap length with a path answers origin_malformed - the shape gate, not the length gate',
    () async {
      final rec = _ShapeRec();
      final srv = _server(rec);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      const head = 'https://padding.example/';
      final atCap = '$head${'a' * (1024 - head.length - 1)}x';
      expect(atCap.length, 1024, reason: 'the specimen sits at the cap itself');
      final r = await _exchange(p, _post(p, atCap));
      expect(r['status'], 400);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_malformed',
        reason: 'the path inside the value is a shape fact, not a length one',
      );
    },
  );

  test(
    'the literal null Origin keeps its treatment and a missing Origin takes the ordinary path',
    () async {
      final rec = _ShapeRec();
      final srv = _server(rec, allowAll: true);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final literalNull = await _exchange(p, _post(p, 'null'));
      expect(literalNull['status'], 403);
      expect(
        bodyJson(literalNull.cast<String, Object>())['error'],
        'origin_blocked',
        reason: 'the wire literal null stays outside the shape gate',
      );
      final noHeader = _post(
        p,
        'https://a.example',
      ).replaceFirst('Origin: https://a.example\r\n', '');
      final missing = await _exchange(p, noHeader);
      expect(missing['status'], 403);
      expect(
        bodyJson(missing.cast<String, Object>())['error'],
        'origin_blocked',
        reason: 'an absent Origin is not a malformed one',
      );
    },
  );

  test(
    'a token request carrying a malformed Origin is refused by the shape gate alone',
    () async {
      final rec = _ShapeRec();
      var handlerCalls = 0;
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (_) async {
          handlerCalls++;
          return const CommandOutcome(ok: true);
        },
        protection: IntakeProtection(telemetry: rec)
          ..update(policy: const OriginPolicy(), token: _t64),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
        'Origin: https://portal.example@evil.example\r\n'
        'X-Bridge-Token: $_t64\r\n'
        'Content-Type: application/json\r\nContent-Length: 17\r\n'
        '\r\n{"data":["PING"]}',
      );
      expect(r['status'], 400);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_malformed',
        reason: 'a correct token does not rescue a hostile shape',
      );
      expect(
        handlerCalls,
        0,
        reason: 'the token layer sits behind the shape gate',
      );
    },
  );

  group('the accepted Origin shape (isWellFormedOrigin)', () {
    test('browser-shaped origins pass', () {
      for (final origin in const [
        'https://a.example',
        'HTTPS://A.Example:8443',
        'http://localhost:9100',
        'http://127.0.0.1:5173',
        'http://[::1]:9100',
        'https://[::1]',
        'https://a.example/',
        'https://a.example///',
        'https://a.example.',
        'https://deep.sub.example',
        'https://a.example:1',
      ]) {
        expect(
          IntakeProtection.isWellFormedOrigin(origin),
          isTrue,
          reason: 'origin "$origin" is a browser wire shape',
        );
      }
    });
    test('hand-crafted shapes fail', () {
      for (final origin in const [
        'portal.example',
        'null',
        '',
        'https://',
        'https://user@host',
        'https://portal.example@evil.example',
        'https://a.example/x',
        'https://a.example/x/',
        'https://a.example?x=1',
        'https://a.example#f',
        'https://a.exa mple',
        ' https://a.example',
        'https://a.example ',
        'https://a.example\u0007',
        'https://a.example\u001b',
        'https://a.example:',
        'https://a.example:8x',
        'https://a:b',
        'https://a.example/path?q=1#f',
        'https://[g:1]',
      ]) {
        expect(
          IntakeProtection.isWellFormedOrigin(origin),
          isFalse,
          reason: 'origin "$origin" is not scheme://host[:port]',
        );
      }
    });
  });
}
