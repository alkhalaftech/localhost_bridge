// The WebSocket channel: a host-chosen path serves the upgrade handshake
// through the single admission step (the standing wire codes refuse it
// before the upgrade), the first message carries the credential (the
// token or a pairing signature) within the auth deadline, and every
// inbound message is a command passing the same payload checks. The
// channel holds one concurrency seat for its lifetime - the seat caps
// bound the live connections exactly like they bound the live commands.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:localhost_bridge/src/digest.dart' show hexEncode, hmacSha256;
import 'package:test/test.dart';

final _token = generateBridgeToken();
final _wrongToken = generateBridgeToken();

class TestBridge {
  late final LocalIntakeServer srv;
  late final IntakeProtection protection;
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand;
  BridgeConfig config = const BridgeConfig(
    wsPath: '/ws',
    idleTimeout: Duration(milliseconds: 400),
  );
  Duration? wsAuthTimeout = const Duration(milliseconds: 400);
}

Future<TestBridge> start({
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
  BridgeConfig? config,
  Duration? wsAuthTimeout = const Duration(milliseconds: 400),
  bool paired = false,
  List<String> allowed = const ['https://portal.example'],
}) async {
  final c = TestBridge();
  c.onCommand = onCommand;
  c.config =
      config ??
      BridgeConfig(
        wsPath: '/ws',
        idleTimeout: const Duration(milliseconds: 400),
      );
  c.wsAuthTimeout = wsAuthTimeout;
  c.protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(
      policy: OriginPolicy(allowed: allowed, requireOriginWithToken: paired),
      token: _token,
    );
  if (paired) c.protection.enablePairing();
  c.srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () => 'ws-1',
    protection: c.protection,
    onCommand: onCommand ?? (cmd) async => const CommandOutcome(ok: true),
    config: c.config,
    wsAuthTimeout: wsAuthTimeout,
  );
  await c.srv.start(preferredPort: 0);
  return c;
}

/// A connected, authenticated WebSocket: the token rides the first
/// message and the channel is open for commands.
Future<WebSocket> openChannel(
  int port, {
  String? origin = 'https://portal.example',
  String? token,
  String? path = '/ws',
  Map<String, String> extraHeaders = const {},
}) async {
  final ws = await WebSocket.connect(
    'ws://127.0.0.1:$port$path',
    headers: {'Origin': ?origin, ...extraHeaders},
  ).timeout(const Duration(seconds: 5));
  ws.add(jsonEncode({'token': token ?? _token, 'correlationId': 'ws-auth'}));
  return ws;
}

/// Collects the channel's messages until [count] arrive or the channel
/// closes; the reply list plus the close code travel back together.
Future<(List<String> replies, int? closeCode)> readUntil(
  WebSocket ws,
  int count, {
  Duration limit = const Duration(seconds: 5),
}) async {
  final replies = <String>[];
  final done = Completer<void>();
  late final StreamSubscription sub;
  sub = ws.listen(
    (m) {
      replies.add(m as String);
      if (replies.length >= count && !done.isCompleted) done.complete();
    },
    onDone: () {
      if (!done.isCompleted) done.complete();
    },
    onError: (Object _) {
      if (!done.isCompleted) done.complete();
    },
  );
  await done.future.timeout(limit);
  unawaited(sub.cancel());
  return (replies, ws.closeCode);
}

/// Collects everything the channel sends until it closes - the refusal
/// frame plus the close code ride the same close.
Future<(List<String> replies, int? closeCode)> awaitClosed(
  WebSocket ws, {
  Duration limit = const Duration(seconds: 5),
}) async {
  final replies = <String>[];
  final done = Completer<void>();
  late final StreamSubscription sub;
  sub = ws.listen(
    (m) => replies.add(m as String),
    onDone: () => done.complete(),
    onError: (Object _) => done.complete(),
  );
  await done.future.timeout(limit);
  unawaited(sub.cancel());
  return (replies, ws.closeCode);
}

/// A raw handshake that reads the HTTP reply the server writes BEFORE any
/// upgrade - the pre-upgrade refusals are plain HTTP answers.
Future<(int status, String body)> rawHandshake(
  int port, {
  String host = 'local',
  int? hostPort,
  String origin = 'https://portal.example',
  String path = '/ws',
}) async {
  final s = await Socket.connect('127.0.0.1', port);
  final head = StringBuffer()
    ..write('GET $path HTTP/1.1\r\n')
    ..write(
      'Host: ${host == 'local' ? '127.0.0.1:${hostPort ?? port}' : host}\r\n',
    )
    ..write('Upgrade: websocket\r\n')
    ..write('Connection: Upgrade\r\n')
    ..write('Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n')
    ..write('Sec-WebSocket-Version: 13\r\n');
  if (origin.isNotEmpty) head.write('Origin: $origin\r\n');
  head.write('Content-Length: 0\r\n\r\n');
  s.add(utf8.encode(head.toString()));
  final text = await utf8.decoder
      .bind(s)
      .join()
      .timeout(const Duration(seconds: 5));
  s.destroy();
  final statusMatch = RegExp(r'HTTP/1\.1 (\d{3})').firstMatch(text);
  return (statusMatch == null ? 0 : int.parse(statusMatch.group(1)!), text);
}

void main() {
  test('the handshake upgrades through the single admission, the first '
      'message carries the token, and the command message reads its '
      'reply event', () async {
    final c = await start(
      onCommand: (cmd) async =>
          const CommandOutcome(ok: true, data: {'echo': true}),
    );
    try {
      final ws = await openChannel(c.srv.port);
      ws.add(jsonEncode(['WS-CMD']));
      final (replies, closeCode) = await readUntil(ws, 1);
      expect(closeCode, isNull, reason: 'the channel stays open');
      expect(replies, hasLength(1));
      expect(replies.single, contains('"ok":true'));
      expect(replies.single, contains('"echo":true'));
      await ws.close();
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('with the option off the path reads the standing 405 like every '
      'non-POST path - the wire never upgrades', () async {
    final c = await start(config: const BridgeConfig(), wsAuthTimeout: null);
    try {
      final (status, body) = await rawHandshake(c.srv.port);
      expect(status, 405, reason: 'the disarmed wire has no channel');
      expect(body, contains('"method_not_allowed"'));
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('a handshake from an origin the policy refuses answers the wire '
      'code BEFORE the upgrade - no socket upgrades', () async {
    final c = await start();
    try {
      final (status, body) = await rawHandshake(
        c.srv.port,
        origin: 'https://stranger.example',
      );
      expect(status, 403);
      expect(body, contains('"origin_not_listed"'));
      expect(body, isNot(contains('101')));
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('a handshake with a non-local Host is refused by the host '
      'authority before the upgrade', () async {
    final c = await start();
    try {
      final (status, body) = await rawHandshake(
        c.srv.port,
        host: 'evil.example:1234',
      );
      expect(status, 403);
      expect(body, contains('"blocked_by_protection"'));
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('an admitted origin without a credential within the deadline is '
      'closed with ws_auth_timeout', () async {
    final c = await start(wsAuthTimeout: const Duration(milliseconds: 300));
    try {
      final ws = await WebSocket.connect(
        'ws://127.0.0.1:${c.srv.port}/ws',
        headers: {'Origin': 'https://portal.example'},
      ).timeout(const Duration(seconds: 5));
      final (replies, closeCode) = await awaitClosed(ws);
      expect(replies, hasLength(1));
      expect(replies.single, contains('"ws_auth_timeout"'));
      expect(closeCode, isNotNull, reason: 'the channel closed');
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('a malformed first message closes with ws_auth_invalid, and a '
      'wrong token closes with the admission refusal token_required', () async {
    final c = await start();
    try {
      // رسالة بلا حقل اعتماد
      final bad = await WebSocket.connect(
        'ws://127.0.0.1:${c.srv.port}/ws',
        headers: {'Origin': 'https://portal.example'},
      ).timeout(const Duration(seconds: 5));
      bad.add(jsonEncode({'hello': 1}));
      final (badReplies, badClose) = await awaitClosed(bad);
      expect(badReplies.single, contains('"ws_auth_invalid"'));
      expect(badClose, isNotNull);

      // توكن خاطئ: رفض خطوة القبول نفسها يصل برمزه الحقيقي
      final wrong = await WebSocket.connect(
        'ws://127.0.0.1:${c.srv.port}/ws',
        headers: {'Origin': 'https://portal.example'},
      ).timeout(const Duration(seconds: 5));
      wrong.add(jsonEncode({'token': _wrongToken}));
      final (wrongReplies, wrongClose) = await awaitClosed(wrong);
      expect(wrongReplies.single, contains('"token_required"'));
      expect(wrongClose, isNotNull);
      // طابع الإخفاق هبط فعلاً (تسوية الاعتماد نفسها عدّته)
      final misses = c.srv.protection.rejectedCount;
      expect(misses, greaterThanOrEqualTo(1));
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('a message over the internal channel cap closes with '
      'ws_message_too_large - the transformer refuses the declared '
      'length before the payload bytes', () async {
    final c = await start();
    try {
      final ws = await openChannel(c.srv.port);
      ws.add(jsonEncode(['x' * (300 * 1024)]));
      final (replies, closeCode) = await awaitClosed(ws);
      expect(replies, hasLength(1));
      expect(replies.single, contains('"ws_message_too_large"'));
      expect(closeCode, isNotNull);
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('silence past the idle timeout closes with ws_idle_timeout', () async {
    final c = await start();
    try {
      final ws = await openChannel(c.srv.port);
      final (replies, closeCode) = await awaitClosed(ws);
      expect(replies.single, contains('"ws_idle_timeout"'));
      expect(closeCode, isNotNull);
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('the channel holds a seat for its lifetime: an open connection '
      'occupies its origin share and the surplus HTTP command reads the '
      'seat-cap code', () async {
    var openBarrier = Completer<void>();
    final c = await start(
      config: BridgeConfig(
        wsPath: '/ws',
        maxSeatsPerOrigin: 1,
        idleTimeout: const Duration(seconds: 2),
      ),
      wsAuthTimeout: null,
      onCommand: (cmd) async {
        // أمر HTTP يعلق حتى نقرأ حكمه — القناة ممسكة الحصة الوحيدة
        await openBarrier.future;
        return const CommandOutcome(ok: true);
      },
    );
    try {
      final ws = await openChannel(c.srv.port);
      // القناة مفتوحة (لا رد اعتماد = باب مفتوح) وأمر HTTP من الأصل
      // نفسه فوق الحصة يرد برمز حصة الأصل لا بالانشغال العام
      final client = HttpClient();
      final req = await client.open('POST', '127.0.0.1', c.srv.port, '/');
      req.headers.set('Content-Type', 'application/json');
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set('Sec-Fetch-Mode', 'cors');
      req.headers.set('Sec-Fetch-Dest', 'empty');
      req.add(utf8.encode('["HTTP-CMD"]'));
      final res = await req.close().timeout(const Duration(seconds: 5));
      final body = await res.transform(utf8.decoder).join();
      client.close(force: true);
      expect(res.statusCode, 503);
      expect(body, contains('"origin_seat_limit"'));
      openBarrier.complete();
      await ws.close();
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('stop closes the live channel connections and reports a fully '
      'drained stop', () async {
    final c = await start();
    WebSocket? ws;
    try {
      ws = await openChannel(c.srv.port);
      final closed = awaitClosed(ws);
      final report = await c.srv.stop().timeout(const Duration(seconds: 5));
      expect(
        report.fullyDrained,
        isTrue,
        reason: 'the live channel held a seat and stop drained it',
      );
      // الاتصال قرأ الإغلاق من الطرف الآخر
      final (_, clientClose) = await closed;
      expect(clientClose, isNotNull);
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('the honest browser handshake shape (websocket/websocket over GET) '
      'passes the fetch-metadata gates, and a POST claiming websocket '
      'stays refused', () async {
    final pr = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          requireFetchMetadata: true,
        ),
        token: _token,
      );
    final srv = LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'ws-2',
      protection: pr,
      onCommand: (cmd) async => const CommandOutcome(ok: true),
      config: const BridgeConfig(wsPath: '/ws'),
    );
    await srv.start(preferredPort: 0);
    try {
      final ws = await WebSocket.connect(
        'ws://127.0.0.1:${srv.port}/ws',
        headers: {
          'Origin': 'https://portal.example',
          'Sec-Fetch-Mode': 'websocket',
          'Sec-Fetch-Dest': 'websocket',
        },
      ).timeout(const Duration(seconds: 5));
      ws.add(jsonEncode({'token': _token}));
      await Future<void>.delayed(const Duration(milliseconds: 300));
      expect(ws.readyState, WebSocket.open);
      await ws.close();
      // وPOST يدّعي websocket على مسار الأوامر: رفض نموذج الإرسال
      final client = HttpClient();
      final req = await client.open('POST', '127.0.0.1', srv.port, '/');
      req.headers.set('Content-Type', 'application/json');
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set('Sec-Fetch-Mode', 'websocket');
      req.headers.set('Sec-Fetch-Dest', 'websocket');
      req.add(utf8.encode('["X"]'));
      final res = await req.close().timeout(const Duration(seconds: 5));
      final body = await res.transform(utf8.decoder).join();
      client.close(force: true);
      expect(res.statusCode, 403);
      expect(body, contains('"cross_site_blocked"'));
    } finally {
      pr.dispose();
      await srv.stop();
    }
  });

  test('the pairing signature authenticates the channel, and the same '
      'signature never proves twice', () async {
    final c = await start(paired: true);
    try {
      final offer = c.protection.startPairing();
      final outcome = c.protection.pair(
        origin: 'https://portal.example',
        code: offer.code,
      );
      expect(outcome.token, isNotNull);
      final pairingId = outcome.pairingId!;
      final stamp = DateTime.now().millisecondsSinceEpoch;
      String sign(String method, String cid) {
        final canonical = 'v1\n$pairingId\n$stamp\n$method\n/ws\n$cid';
        final key = List<int>.generate(
          32,
          (i) =>
              int.parse(outcome.token!.substring(i * 2, i * 2 + 2), radix: 16),
        );
        return '$pairingId.$stamp.${hexEncode(hmacSha256(key, utf8.encode(canonical)))}';
      }

      final ws = await WebSocket.connect(
        'ws://127.0.0.1:${c.srv.port}/ws',
        headers: {'Origin': 'https://portal.example'},
      ).timeout(const Duration(seconds: 5));
      ws.add(
        jsonEncode({
          'pairing': sign('WS', 'ws-pair-1'),
          'correlationId': 'ws-pair-1',
        }),
      );
      // باب مفتوح: لا رد اعتماد ولا إغلاق — أمرٌ يجيب
      ws.add(jsonEncode(['PAIRED-CMD']));
      final (replies, _) = await readUntil(ws, 1);
      expect(replies.single, contains('"ok":true'));
      await ws.close();

      // التوقيع نفسه لا يثبت مرتين: رمز الإعادة الحقيقي يصل
      final ws2 = await WebSocket.connect(
        'ws://127.0.0.1:${c.srv.port}/ws',
        headers: {'Origin': 'https://portal.example'},
      ).timeout(const Duration(seconds: 5));
      ws2.add(jsonEncode({'pairing': sign('WS', 'ws-pair-1')}));
      final (replies2, close2) = await awaitClosed(ws2);
      expect(replies2.single, contains('"pair_signature_replay"'));
      expect(close2, isNotNull);
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('inbound messages pass the same payload checks: a binary frame, a '
      'broken body as raw command text, an over-complex message, and the '
      'reply data cap all read their standing codes', () async {
    final c = await start(
      onCommand: (cmd) async {
        expect(
          cmd.payloads,
          ['not json at all'],
          reason:
              'the broken body '
              'falls through as raw command text like the HTTP contract',
        );
        return CommandOutcome(ok: true, data: 'd' * (70 * 1024));
      },
    );
    try {
      final ws = await openChannel(c.srv.port);
      // إطار ثنائي: رفض المحتوى والقناة باقية
      ws.add([1, 2, 3]);
      // جسم مكسور: مسار النص الخام نفسه
      ws.add('not json at all');
      final (replies, _) = await readUntil(ws, 2);
      expect(replies[0], contains('"non_json_body"'));
      // الرد يحمل عقد الرد: البيانات فوق سقفها برمزها المسجل
      expect(replies[1], contains('"reply_data_too_large"'));
      await ws.close();
      final counters = c.srv.counters;
      expect(counters.rejectionsByCode['non_json_body'], 1);
      expect(counters.rejectionsByCode['reply_data_too_large'], 1);
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('a JSON message over the element cap refuses payload_too_complex '
      'and an empty payload refuses empty_payload - the connection stays '
      'open for the next message', () async {
    var commands = 0;
    final c = await start(
      onCommand: (cmd) async {
        commands++;
        return const CommandOutcome(ok: true);
      },
    );
    try {
      final ws = await openChannel(c.srv.port);
      final deep = '[' * 40 + ']' * 40; // أعمق من السقف الافتراضي 32
      ws.add(deep);
      ws.add(jsonEncode('')); // نص فارغ يفك إلى قائمة فارغة
      ws.add(jsonEncode(['OK-CMD']));
      final (replies, closeCode) = await readUntil(ws, 3);
      expect(closeCode, isNull, reason: 'the channel never closed');
      expect(replies, hasLength(3));
      expect(replies[0], contains('"payload_too_complex"'));
      expect(replies[1], contains('"empty_payload"'));
      // القناة باقية: أمر سليم بعدها يجيب
      expect(replies[2], contains('"ok":true'));
      expect(commands, 1, reason: 'only the good message reached the handler');
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('the wsPath is validated at construction: empty, non-path, and the '
      'pairing-route collision all throw', () async {
    final pr = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(policy: const OriginPolicy());
    LocalIntakeServer build(String? path) => LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'v',
      protection: pr,
      onCommand: (cmd) async => const CommandOutcome(ok: true),
      config: BridgeConfig(wsPath: path),
    );
    expect(() => build(''), throwsArgumentError);
    expect(() => build('ws'), throwsArgumentError);
    expect(() => build('/pair'), throwsArgumentError);
    // والصالح يبقى صالحاً
    final ok = build('/ws');
    await ok.start(preferredPort: 0);
    await ok.stop();
    pr.dispose();
  });

  test('commands over the channel count at the single rejection tally '
      'with their codes', () async {
    final c = await start();
    try {
      final ws = await openChannel(c.srv.port);
      ws.add(jsonEncode('')); // empty_payload
      final (replies, _) = await readUntil(ws, 1);
      expect(replies.single, contains('"empty_payload"'));
      await ws.close();
      expect(c.srv.counters.rejectionsByCode['empty_payload'], 1);
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });
}
