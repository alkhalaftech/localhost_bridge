// عقد سقف ترويسة التوكن: القيمة الأطول من 1,024 بايتاً UTF-8 تُرد 400
// token_too_long قبل أي مقارنة أو نافذة إخفاق أو عدّاد رفض أو قرار
// سياسة — بنمط بوابتي الأصل قبلهما خارج العدّاد والسجل وبلا صدى CORS.
// الحد صارم وترتيب البوابات محسوم: 1,024 بايتاً بالضبط إخفاق عادي
// يصنع القفل، وبوابتا الأصل تحكمان على المعتل في الترويستين معاً،
// وبوابة شكل الترويسة تسبق بوابة الطريقة. وحشوة المقارنة: تمتد على
// السر المضبوط وحده فلا تنمو كلفة المقارنة بطول المرسل، وفرق الطول
// يُطوى في المُراكِم — شهود دلالة المقارنة بأطوال مولدة.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson;

var _idSeq = 0;
String _counterId() => 'toklen-${_idSeq++}';

const _goodBody = '{"data":["PING"]}';
const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';
final String _long1025 = 'x' * 1025;

/// Telemetry recorder - keeps the warns so the gate's no-log contract is
/// asserted on the seam the host actually reads.
class _TokRec extends BridgeTelemetry {
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

String _request(
  int port, {
  String method = 'POST',
  String? token,
  String? origin = 'https://attacker.example',
}) {
  final h = StringBuffer()
    ..write('$method / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n');
  if (origin != null) h.write('Origin: $origin\r\n');
  if (token != null) h.write('X-Portal-Token: $token\r\n');
  if (method == 'POST') {
    h.write('Content-Type: application/json\r\n');
    h.write('Content-Length: ${_goodBody.length}\r\n\r\n$_goodBody');
  } else {
    h.write('Content-Length: 0\r\n\r\n');
  }
  return h.toString();
}

LocalIntakeServer _tokenServer(
  _TokRec rec, {
  void Function()? onCommandCall,
  String? token = _t64,
}) {
  final protection = IntakeProtection(telemetry: rec);
  if (token != null) {
    protection.update(policy: const OriginPolicy(), token: token);
  } else {
    protection.update(policy: const OriginPolicy());
  }
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
    'a 1,025-byte token answers 400 token_too_long with the handler, the rejection counter, its log, and CORS untouched',
    () async {
      final rec = _TokRec();
      var handlerCalls = 0;
      final srv = _tokenServer(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final before = srv.protection.rejectedCount;
      final r = await _exchange(p, _request(p, token: _long1025));
      expect(
        r['status'],
        400,
        reason: 'the header length cap answers before any comparison',
      );
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'token_too_long',
        reason: 'the stable code names the refused condition',
      );
      expect(
        handlerCalls,
        0,
        reason: 'the bloated token never reaches the handler',
      );
      expect(
        srv.protection.rejectedCount,
        before,
        reason: 'a wire-shape reject stays outside the security counter',
      );
      expect(
        rec.warns.where((w) => w.contains('intake rejected')),
        isEmpty,
        reason: 'no rejection log line is written for the cap reject',
      );
      final headers = r['headers'] as Map<String, String>;
      expect(
        headers.containsKey('access-control-allow-origin'),
        isFalse,
        reason: 'no CORS decision runs for this reject',
      );
      expect(
        headers.containsKey('x-correlation-id'),
        isTrue,
        reason: 'the reject still carries a correlation id like every reply',
      );
    },
  );

  test(
    'five oversized tokens leave no miss window behind: the correct token right after them is served, not locked',
    () async {
      final rec = _TokRec();
      var handlerCalls = 0;
      final srv = _tokenServer(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final longStatuses = <int>[];
      for (var i = 0; i < 5; i++) {
        final r = await _exchange(p, _request(p, token: _long1025));
        longStatuses.add(r['status'] as int);
      }
      expect(
        longStatuses,
        everyElement(400),
        reason: 'each oversized token is refused by the cap, not compared',
      );
      final correct = await _exchange(p, _request(p, token: _t64));
      expect(
        correct['status'],
        200,
        reason:
            'no miss stamp was recorded, so the lockout never forms - '
            'a 429 here would mean the cap still counts as a miss',
      );
      expect(handlerCalls, 1, reason: 'the correct token is admitted');
    },
  );

  test(
    'the cap is strict: wrong tokens of exactly 1,024 bytes still count as misses and lock the window',
    () async {
      final rec = _TokRec();
      final srv = _tokenServer(rec);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final missStatuses = <int>[];
      for (var i = 0; i < 5; i++) {
        // 1,024 بايتاً بالضبط: آخر محرف يتغير بين المحاولات كي يختلف
        // التوكن فيبقى إخفاقاً حقيقياً في كل مرة
        final missToken = 'x' * 1023 + String.fromCharCode(0x61 + i);
        final r = await _exchange(
          p,
          _request(p, token: missToken, origin: 'https://boundary.example'),
        );
        expect(
          r['status'],
          403,
          reason:
              'a token at the cap itself is an ordinary miss, not a '
              'wire-shape reject',
        );
        expect(
          bodyJson(r.cast<String, Object>())['error'],
          'origin_not_listed',
          reason: 'the miss falls through to the origin policy as before',
        );
        missStatuses.add(r['status'] as int);
      }
      expect(missStatuses, everyElement(403));
      final locked = await _exchange(
        p,
        _request(p, token: _t64, origin: 'https://boundary.example'),
      );
      expect(
        locked['status'],
        429,
        reason:
            'five misses at exactly the cap formed the lockout - the '
            'gate guards only what is longer than the cap',
      );
      expect(bodyJson(locked.cast<String, Object>())['error'], 'token_locked');
    },
  );

  test(
    'the Origin gates settle first: an oversized token with a malformed Origin answers origin_malformed',
    () async {
      final rec = _TokRec();
      var handlerCalls = 0;
      final srv = _tokenServer(rec, onCommandCall: () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final before = srv.protection.rejectedCount;
      final r = await _exchange(
        p,
        _request(p, token: _long1025, origin: 'https://p.example@evil.example'),
      );
      expect(r['status'], 400);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'origin_malformed',
        reason:
            'the Origin shape gate owns the answer when both headers '
            'are hostile',
      );
      expect(handlerCalls, 0);
      expect(
        srv.protection.rejectedCount,
        before,
        reason: 'neither gate touches the security counter',
      );
    },
  );

  test(
    'the header-shape gate precedes the method gate: a GET with an oversized token answers token_too_long, not 405',
    () async {
      final rec = _TokRec();
      final srv = _tokenServer(rec);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        _request(p, method: 'GET', token: _long1025),
      );
      expect(r['status'], 400);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'token_too_long',
        reason:
            'the wire-shape gates answer before the method is judged, '
            'the same order the Origin gates keep',
      );
    },
  );

  test(
    'the token cap is a wire-shape gate: it fires with no token layer configured at all',
    () async {
      final rec = _TokRec();
      var handlerCalls = 0;
      final srv = _tokenServer(
        rec,
        token: null,
        onCommandCall: () => handlerCalls++,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(p, _request(p, token: _long1025));
      expect(r['status'], 400);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'token_too_long',
        reason:
            'a bloated header is refused work whether or not the '
            'token layer is on',
      );
      expect(handlerCalls, 0);
    },
  );

  test(
    'comparison semantics hold for generated lengths: correct passes, and wrong at the first byte, the last byte, past the secret, and below the secret all fail',
    () async {
      // أطوال مولدة فوق وحود الحشوة: السر تحت الحشوة وعندها وفوقها —
      // المقارنة تمتد على السر وحده والفرق في الطول يُطوى في المُراكِم
      final rec = _TokRec();
      for (final len in [32, 256, 300]) {
        final secret = List.generate(len, (i) => '${i % 10}').join();
        final p = IntakeProtection(telemetry: rec)
          ..update(policy: const OriginPolicy(), token: secret);
        expect(
          await p.check(origin: null, portalToken: secret),
          isNull,
          reason: 'the correct secret of $len bytes passes the comparison',
        );
        final wrongFirst =
            '${secret[0] == '9' ? '0' : '9'}${secret.substring(1)}';
        expect(
          await p.check(origin: null, portalToken: wrongFirst),
          isNotNull,
          reason: 'a difference at the first byte of $len bytes is caught',
        );
        final last = secret.substring(len - 1);
        final wrongLast =
            '${secret.substring(0, len - 1)}${last == 'z' ? 'y' : 'z'}';
        expect(
          await p.check(origin: null, portalToken: wrongLast),
          isNotNull,
          reason: 'a difference at the last byte of $len bytes is caught',
        );
        expect(
          await p.check(origin: null, portalToken: '$secret-tail'),
          isNotNull,
          reason:
              'a longer token with a correct prefix is caught by the '
              'length term and its extra bytes',
        );
        expect(
          await p.check(
            origin: null,
            portalToken: secret.substring(0, len - 1),
          ),
          isNotNull,
          reason:
              'a shorter token with a correct prefix is caught by the '
              'length term',
        );
        expect(
          await p.check(origin: null, portalToken: wrongLast),
          isNotNull,
          reason:
              'an equal-length token differing at the tail is compared '
              'in full',
        );
      }
      // سر متعدد البايتات: الحساب على بايتات UTF-8 لا المحارف
      final arabic = 'س' * 20; // 20 محرفاً × 2 بايت = 40 بايتاً
      final p = IntakeProtection(telemetry: rec)
        ..update(policy: const OriginPolicy(), token: arabic);
      expect(
        await p.check(origin: null, portalToken: arabic),
        isNull,
        reason: 'the multi-byte secret matches byte for byte',
      );
      expect(
        await p.check(origin: null, portalToken: '$arabicس'),
        isNotNull,
        reason: 'one more character than the multi-byte secret is caught',
      );
      // طول متطرف عبر المقارنة: البايتات فوق مدى الحلقة تسقط في
      // المُراكِم فلا مرور لطول متضخم مهما كان
      expect(
        await p.check(origin: null, portalToken: 'a' * (1 << 20)),
        isNotNull,
        reason: 'a megabyte token is refused by the comparison itself',
      );
    },
  );
}
