// عقد سقف طول الأصل: الأصل الأطول من السقف الداخلي يُرد 400 origin_too_long
// قبل أن يراه أي كود آخر — لا خريطة ولا سطر سجل ولا نداء موافقة ولا معالج
// ولا سياق telemetry. والطول عند السقف تماماً يسلك المسار الاعتيادي كما كان.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson;

var _idSeq = 0;
String _counterId() => 'cap-${_idSeq++}';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

/// An Origin value of exactly [length] characters (a plausible https head,
/// padding, and one final non-slash character).
String _originOfLength(int length) {
  const head = 'https://padding.example/';
  final pad = length - head.length - 1;
  if (pad < 0) throw ArgumentError('length too small: $length');
  return '$head${'a' * pad}x';
}

/// Telemetry recorder - keeps the warns and the measure contexts so the
/// cap's no-leak contract is asserted on what the seams actually carried.
class _CapRec extends BridgeTelemetry {
  final warns = <String>[];
  final contexts = <Map<String, Object?>?>[];
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
    contexts.add(context);
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
      final chunkedEnd = text.endsWith('0\r\n\r\n');
      final hasCl = clMatch != null && bodyLen >= int.parse(clMatch.group(1)!);
      if (hasCl || chunkedEnd) settle(buffer.toBytes());
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

LocalIntakeServer _server(
  _CapRec rec, {
  bool withDiscovery = true,
  bool requireFetchMetadata = false,
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
        policy: OriginPolicy(
          allowed: ['https://portal.example'],
          requireFetchMetadata: requireFetchMetadata,
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
    'an Origin one char over the cap answers 400 origin_too_long with the handler and the consent callback never invoked',
    () async {
      final rec = _CapRec();
      var handlerCalls = 0;
      var asked = 0;
      final srv = _server(
        rec,
        onCommandCall: () => handlerCalls++,
        onAsk: (_) => asked++,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final over = _originOfLength(1025);
      final r = await _exchange(
        p,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
        'Origin: $over\r\n'
        'Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
      );
      expect(
        r['status'],
        400,
        reason: 'the length gate rejects before anything',
      );
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_too_long',
        reason: 'the fixed code sits next to duplicate_header in the contract',
      );
      expect(
        handlerCalls,
        0,
        reason: 'the oversized value never reaches the handler',
      );
      expect(
        asked,
        0,
        reason:
            'the oversized value never opens a consent question for the host',
      );
    },
  );

  test(
    'no rejection line and no telemetry context carries an Origin longer than the cap',
    () async {
      final rec = _CapRec();
      final srv = _server(rec, withDiscovery: false);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final huge = _originOfLength(64 * 1024);
      final r = await _exchange(
        p,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
        'Origin: $huge\r\n'
        'Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
      );
      expect(r['status'], 400);
      expect(r['body'], contains('origin_too_long'));
      // بوابة الشكل تكتب سطر رفض صفراً — أي warn هنا يعني سطراً حمل
      // القيمة الخام خارج العقد، فيُحاكم بحد السجل الإنتاجي 200
      expect(
        rec.warns,
        isEmpty,
        reason:
            'a shape-gate reject writes no warning line at all - the '
            'gate rejects before any log line exists',
      );
      // أي سياق قياس يحمل أصلاً هنا يعني وصول القيمة الخام إلى القياس
      final carried = rec.contexts
          .map((c) => c?['origin'])
          .whereType<String>()
          .where((o) => o != 'unknown')
          .toList();
      expect(
        carried,
        isEmpty,
        reason:
            'no measure context carries the oversized origin - the '
            'gate rejects before the request measure runs',
      );
      for (final w in rec.warns) {
        final start = w.indexOf('origin=');
        if (start < 0) continue;
        final fieldStart = start + 'origin='.length;
        final close = w.indexOf(')', fieldStart);
        final field = close < 0
            ? w.substring(fieldStart)
            : w.substring(fieldStart, close);
        expect(
          field.length,
          lessThanOrEqualTo(200),
          reason: 'the log line stays under the production log cap (200)',
        );
      }
      for (final ctx in rec.contexts) {
        final origin = ctx?['origin'];
        if (origin is String && origin != 'unknown') {
          expect(
            origin.length,
            lessThanOrEqualTo(200),
            reason: 'the telemetry context stays under the log cap (200)',
          );
        }
      }
    },
  );

  test('an Origin at exactly the cap length takes the ordinary path', () async {
    final rec = _CapRec();
    var handlerCalls = 0;
    final srv = _server(
      rec,
      withDiscovery: false,
      onCommandCall: () => handlerCalls++,
    );
    final p = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // عند السقف تماماً وبشرطات ختامية: التطبيع يسري كالعادة فيقفز
    // الأصل إلى المدخل المدرج فيُخدم — السقف لا يمس الطول المسموح
    const listed = 'https://portal.example';
    final atCap = '$listed${'/' * (1024 - listed.length)}';
    const body = '{"data":["PING"]}';
    final admitted = await _exchange(
      p,
      'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
      'Origin: $atCap\r\n'
      'Content-Type: application/json\r\n'
      'Content-Length: ${utf8.encode(body).length}\r\n\r\n$body',
    );
    expect(admitted['status'], 200);
    expect(handlerCalls, 1);
    // وعند السقف بأصل سليم الشكل غير مدرج: الرفض الاعتيادي برمزه
    // الاعتيادي لا رمز الطول — العينة سليمة الشكل (لا مسار) لأن بوابة
    // الشكل تسبق السياسة، وأصلٌ بمسارٍ عن السقف يُجاب origin_malformed
    // في جناحه الخاص
    final unlisted = 'https://${'a' * (1024 - 'https://'.length)}';
    final rejected = await _exchange(
      p,
      'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
      'Origin: $unlisted\r\n'
      'Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
    );
    expect(rejected['status'], 403);
    expect(
      bodyJson(rejected.cast<String, Object>())['error'],
      'origin_not_listed',
    );
  });

  test(
    'the length gate precedes the single-header gate: a duplicated oversized Origin answers origin_too_long, not duplicate_header',
    () async {
      final rec = _CapRec();
      final srv = _server(rec);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final over = _originOfLength(1025);
      final r = await _exchange(
        p,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
        'Origin: $over\r\n'
        'Origin: $over\r\n'
        'Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
      );
      expect(r['status'], 400);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_too_long',
        reason:
            'the length is settled before the gate reads any header twice - '
            'no CORS decision runs for an oversized value',
      );
    },
  );

  test(
    'a token request carrying an oversized Origin is refused by the length gate alone',
    () async {
      final rec = _CapRec();
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
      final over = _originOfLength(1025);
      final r = await _exchange(
        p,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
        'Origin: $over\r\n'
        'X-Bridge-Token: $_t64\r\n'
        'Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
      );
      expect(r['status'], 400);
      expect(r['body'], contains('origin_too_long'));
      expect(
        handlerCalls,
        0,
        reason: 'the token layer does not rescue an oversized Origin',
      );
    },
  );
}
