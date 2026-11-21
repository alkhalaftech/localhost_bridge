// كل قيمة أصل تصل إلى telemetry تمر بالتعقيم نفسه الذي يمر به سجل
// الرفض: محارف التحكم تُحذف والقيمة تُقص إلى 200 محرفاً. سياق القياس
// كان يحمل القيمة الخام؛ والأصل بمحرف تحكم لا يبلغ القياس أصلاً لأن
// بوابة الشكل تردّه 400 origin_malformed قبل أي قياس أو خريطة أو سجل.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson;

var _idSeq = 0;
String _counterId() => 'otx-${_idSeq++}';

/// Telemetry recorder - captures the measurement contexts so the seam the
/// host reads is asserted on directly: the context map is what carries the
/// Origin value out of the package.
class _OriginRec extends BridgeTelemetry {
  final measureEvents = <({String label, Map<String, Object?>? context})>[];
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
    measureEvents.add((label: label, context: context));
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

/// A browser-like command POST with the two Sec-Fetch headers.
String _post(int port, String origin) =>
    'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n'
    'Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n'
    'Origin: $origin\r\n'
    'Content-Type: application/json\r\n'
    'Content-Length: 17\r\n\r\n{"data":["PING"]}';

LocalIntakeServer _server(_OriginRec rec, {void Function()? onCommandCall}) {
  return LocalIntakeServer(
    telemetry: rec,
    correlationIdGenerator: _counterId,
    onCommand: (_) async {
      onCommandCall?.call();
      return const CommandOutcome(ok: true);
    },
    protection: IntakeProtection(telemetry: rec)
      ..update(policy: const OriginPolicy(allowAllHardened: true)),
  );
}

/// The one request measurement captured for this recorder - a test helper
/// keeping the label filter in one place.
Map<String, Object?>? _handleRequestContext(_OriginRec rec) {
  final event = rec.measureEvents
      .where((e) => e.label == 'intake.handleRequest')
      .toList();
  if (event.isEmpty) return null;
  return event.single.context;
}

void main() {
  test(
    'a long well-formed Origin reaches the measurement context truncated to exactly 200 characters',
    () async {
      final rec = _OriginRec();
      var handlerCalls = 0;
      final srv = _server(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final origin = 'https://${'a' * 1016}';
      expect(origin.length, 1024, reason: 'the specimen sits at the cap');
      final r = await _exchange(p, _post(p, origin));
      expect(
        r['status'],
        200,
        reason: 'a well-formed origin under the length cap is served',
      );
      expect(handlerCalls, 1);
      final context = _handleRequestContext(rec);
      expect(context, isNotNull, reason: 'the measurement context is captured');
      final loggedOrigin = context!['origin'] as String;
      expect(
        loggedOrigin.length,
        200,
        reason:
            'the telemetry context carries the capped form, never the raw '
            'value the sender chose',
      );
      expect(loggedOrigin, 'https://${'a' * 192}');
    },
  );

  test(
    'an Origin carrying BEL and ESC control characters is refused 400 origin_malformed before any measurement context captures it',
    () async {
      final rec = _OriginRec();
      var handlerCalls = 0;
      final srv = _server(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final hostile = 'https://portal.example\u0007\u001b';
      final r = await _exchange(p, _post(p, hostile));
      expect(r['status'], 400, reason: 'the shape gate answers first');
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_malformed',
        reason: 'the fixed code stays next to origin_too_long',
      );
      expect(
        handlerCalls,
        0,
        reason: 'the hostile value never reaches the handler',
      );
      final hostileEvents = rec.measureEvents
          .where(
            (e) =>
                (e.context?['origin'] as String?)?.contains('\u0007') == true ||
                (e.context?['origin'] as String?)?.contains('\u001b') == true,
          )
          .toList();
      expect(
        hostileEvents,
        isEmpty,
        reason: 'no measurement context ever carries the raw hostile value',
      );
      expect(
        rec.measureEvents.where((e) => e.label == 'intake.handleRequest'),
        isEmpty,
        reason: 'the shape refusal lands before measurement is even entered',
      );
    },
  );

  test(
    'a missing Origin still lands in the measurement context as unknown - on the hardened refusal path itself',
    () async {
      final rec = _OriginRec();
      var handlerCalls = 0;
      final srv = _server(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final noHeader = _post(
        p,
        'https://a.example',
      ).replaceFirst('Origin: https://a.example\r\n', '');
      final r = await _exchange(p, noHeader);
      expect(
        r['status'],
        403,
        reason: 'hardened allow-all keeps refusing a missing origin',
      );
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_blocked',
        reason: 'the standing refusal code for a missing origin',
      );
      expect(handlerCalls, 0);
      // القياس يغلف الرفض أيضاً فسياقه يُلتقط — والقيمة تبقى unknown
      final context = _handleRequestContext(rec);
      expect(context, isNotNull);
      expect(context!['origin'], 'unknown');
    },
  );

  test(
    'an ordinary short Origin reaches the measurement context exactly as sent',
    () async {
      final rec = _OriginRec();
      var handlerCalls = 0;
      final srv = _server(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(p, _post(p, 'https://portal.example'));
      expect(r['status'], 200);
      expect(handlerCalls, 1);
      final context = _handleRequestContext(rec);
      expect(
        context!['origin'],
        'https://portal.example',
        reason: 'sanitization is a cap and a strip, not a rewrite',
      );
    },
  );

  group('the Origin sanitizer (originForLog)', () {
    test('caps a 1,024-character value at exactly 200 characters', () {
      final result = IntakeProtection.originForLog('a' * 1024);
      expect(result, isNotNull);
      expect(result!.length, 200, reason: 'the cap is 200 characters exactly');
    });
    test('keeps exactly 200 characters unchanged and truncates 201 to 200', () {
      expect(
        IntakeProtection.originForLog('b' * 200),
        'b' * 200,
        reason: 'a value at the boundary passes whole',
      );
      expect(
        IntakeProtection.originForLog('c' * 201),
        'c' * 200,
        reason: 'one character over the boundary is cut',
      );
    });
    test('strips control characters (BEL, ESC) before it truncates', () {
      expect(
        IntakeProtection.originForLog('https://a.example\u0007X\u001b'),
        'https://a.exampleX',
        reason: 'control characters cannot forge log or context lines',
      );
      // الترتيب: الحذف قبل القص — قصٌّ قبله كان يترك محارف تحكم داخل
      // النافذة الأولى ويخرج الحروف النظيفة خارجها
      final mixed = '${'a' * 150}\u0007${'\u001b' * 99}${'b' * 100}';
      expect(mixed.length, 350);
      expect(
        IntakeProtection.originForLog(mixed),
        '${'a' * 150}${'b' * 50}',
        reason: 'the clean 250 characters are what gets capped to 200',
      );
    });
    test('passes null through as null', () {
      expect(IntakeProtection.originForLog(null), isNull);
    });
  });
}
