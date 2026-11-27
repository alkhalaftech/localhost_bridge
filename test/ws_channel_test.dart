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
import 'dart:typed_data';

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

/// A real HTTP POST command that returns (status, body) - the wire
/// observable the seat and share assertions read. A network failure is
/// recorded as (-1, '') instead of thrown, so the verdict speaks in
/// statuses.
Future<(int, String)> postBody(int port, {required String origin}) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', origin);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["HTTP-CMD"]'));
    final res = await req.close().timeout(const Duration(seconds: 5));
    final body = await res.transform(utf8.decoder).join();
    return (res.statusCode, body);
  } on Object {
    return (-1, '');
  } finally {
    client.close(force: true);
  }
}

/// A bounded wait for a counter condition - the verdict never leans on
/// a bare sleep wall.
Future<bool> waitFor(
  bool Function() check, {
  Duration limit = const Duration(seconds: 2),
}) async {
  final sw = Stopwatch()..start();
  while (!check() && sw.elapsed < limit) {
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  return check();
}

/// A raw handshake that reads the HTTP reply the server writes BEFORE any
/// upgrade - the pre-upgrade refusals are plain HTTP answers.
Future<(int status, String body)> rawHandshake(
  int port, {
  String host = 'local',
  int? hostPort,
  String origin = 'https://portal.example',
  String path = '/ws',
  Map<String, String> extra = const {},
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
  extra.forEach((name, value) => head.write('$name: $value\r\n'));
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
  // على SDK لا يعرف dart:io معلمة سقف النقل (تحت 3.13) لا تُسلَّح القناة
  // أصلاً: رفضٌ عند البناء هو العقد كله هنا، وبقية المشاهد تحتاج القناة
  // نفسها فلا وجود لها على هذا الـSDK — والشاهد الكاملة فوق 3.13 أدناه
  if (!LocalIntakeServer.wsTransportCeilingSupported) {
    test('below Dart 3.13 arming the channel throws at construction - '
        'the channel never runs without its transport ceiling', () {
      // التسليح يرمي ArgumentErrors واضحاً: الرسالة تسمّي الحد المفقود
      // والنسخة المطلوبة، والبناء بلا wsPath يبقى سالماً
      try {
        LocalIntakeServer(
          onCommand: (_) async => const CommandOutcome(ok: true),
          telemetry: const SilentTelemetry(),
          config: const BridgeConfig(wsPath: '/ws'),
        );
        fail('arming the channel must throw below Dart 3.13');
      } on ArgumentError catch (e) {
        expect(e.message, contains('3.13'));
        expect(e.message, contains('maxPayloadLength'));
        expect(e.name, 'config.wsPath');
      }
      // والقناة مطفأةً يبني الخادم كما هو: فشل البناء للقناة حصراً
      final srv = LocalIntakeServer(
        onCommand: (_) async => const CommandOutcome(ok: true),
        telemetry: const SilentTelemetry(),
      );
      expect(srv.config.wsPath, isNull);
    });
    return;
  }
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
      'ws_message_too_large - the refusal frame carries the literal '
      'code at delivery', () async {
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

  test('a frame over the transport ceiling is a protocol-level kill '
      'with no counted frame - the counted refusal lives at the '
      'delivery cap under it', () async {
    // فوق سقف النقل (2MiB) لا سقف التسليم (256KiB): محول dart:io
    // نفسه يرفض الطول المعلن ويغلق النقل بخطأ بروتوكول (1002) قبل
    // أي بايت حمولة وقبل أي إطار إفصاح — فالذاكرة محروسة والقناة
    // ميتة، والرفض المعدود المقروء (الإطار الحرفي + العدّ الواحد)
    // يعيش عند سقف التسليم تحته. والقناة لا تُسلَّح أصلاً حيث لا
    // تعرف dart:io معلمة السقف (تحت 3.13) فلا فرعَ بلا سقف نقل
    final c = await start();
    try {
      final ws = await openChannel(c.srv.port);
      ws.add('x' * (3 * 1024 * 1024));
      final (replies, closeCode) = await awaitClosed(ws);
      // قراءة رمز الإغلاق نفسها سباقُ معالجةِ إطار الإغلاق تحت الحمل:
      // النقل يقتل ب1002 لكن العميل قد يقرأ 1006 (إغلاق شاذ) قبل أن
      // يبلغه الإطار — فالحكم على القتل بمآلاته (لا إطار إفصاح ولا
      // عدّ) والرمز المرصود أحد الأمرين الصادقين
      expect(closeCode, anyOf(1002, 1006));
      expect(
        replies.where((r) => r.contains('ws_message_too_large')),
        isEmpty,
        reason:
            'the transport kills the connection itself - no '
            'disclosure frame rides a dead transport',
      );
      expect(
        c.srv.counters.rejectionsByCode['ws_message_too_large'],
        isNull,
        reason:
            'the delivery cap under the ceiling owns the counted, '
            'readable refusal',
      );
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

  test('credential acceptance with the seats full closes the channel with '
      'the standing server_busy code inside the rejection frame', () async {
    final c = await start(
      config: BridgeConfig(
        wsPath: '/ws',
        maxConcurrentRequests: 1,
        maxSeatsPerOrigin: 1,
        idleTimeout: const Duration(seconds: 2),
      ),
      wsAuthTimeout: const Duration(seconds: 5),
    );
    try {
      // القناة الأولى تعتمد وتمسك المقعد الوحيد للميزانية الضيقة —
      // والأخذ يُنتظر بالعداد كي لا يتسابق اعتماد القناتين
      final holder = await openChannel(c.srv.port);
      expect(
        await waitFor(() => c.srv.counters.activeSeats == 1),
        isTrue,
        reason: 'the authenticated holder holds the only seat',
      );
      // الثانية تعبر الترقية من الحوض قبل الاعتماد (لا مقعد قبل الاعتماد)
      // ثم يُغلق اعتمادها بالإطار السلكي القائم لرمز الانشغال
      final second = await WebSocket.connect(
        'ws://127.0.0.1:${c.srv.port}/ws',
        headers: {'Origin': 'https://portal.example'},
      ).timeout(const Duration(seconds: 5));
      second.add(jsonEncode({'token': _token, 'correlationId': 'ws-full'}));
      final (replies, closeCode) = await awaitClosed(second);
      expect(
        replies.single,
        contains('"server_busy"'),
        reason:
            'no seat is available at credential acceptance - the channel '
            'closes with the standing wire code in the rejection frame',
      );
      expect(closeCode, isNotNull, reason: 'the channel closed');
      await holder.close();
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('credential acceptance with the origin share full closes the '
      'channel with the standing origin_seat_limit code while the server '
      'still has room', () async {
    final c = await start(
      config: BridgeConfig(
        wsPath: '/ws',
        maxConcurrentRequests: 8,
        maxSeatsPerOrigin: 1,
        idleTimeout: const Duration(seconds: 2),
      ),
      wsAuthTimeout: const Duration(seconds: 5),
    );
    try {
      // الحاملة تمسك الحصة الوحيدة للأصل والمقاعد العامة ما زالت واسعة
      final holder = await openChannel(c.srv.port);
      expect(
        await waitFor(() => c.srv.counters.activeSeats == 1),
        isTrue,
        reason: 'the authenticated holder holds the origin share',
      );
      final second = await WebSocket.connect(
        'ws://127.0.0.1:${c.srv.port}/ws',
        headers: {'Origin': 'https://portal.example'},
      ).timeout(const Duration(seconds: 5));
      second.add(jsonEncode({'token': _token, 'correlationId': 'ws-share'}));
      final (replies, closeCode) = await awaitClosed(second);
      expect(
        replies.single,
        contains('"origin_seat_limit"'),
        reason:
            'the origin share is full at credential acceptance - the '
            'channel closes with the share code while the server still '
            'has room',
      );
      expect(closeCode, isNotNull, reason: 'the channel closed');
      await holder.close();
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('the channel takes its seat and its origin share at credential '
      'acceptance: an open unauthenticated channel holds none, and both '
      'free when the channel dies', () async {
    final c = await start(
      config: BridgeConfig(
        wsPath: '/ws',
        maxSeatsPerOrigin: 1,
        idleTimeout: const Duration(seconds: 2),
      ),
      wsAuthTimeout: const Duration(seconds: 5),
      allowed: const ['https://portal.example', 'https://other.example'],
    );
    try {
      final ws = await WebSocket.connect(
        'ws://127.0.0.1:${c.srv.port}/ws',
        headers: {'Origin': 'https://portal.example'},
      ).timeout(const Duration(seconds: 5));
      // القناة مفتوحة بلا اعتماد: لا مقعد ولا حصة — العداد صفر والأصل
      // نفسه يُخدم
      expect(
        c.srv.counters.activeSeats,
        0,
        reason: 'an open channel before its credential holds no seat at all',
      );
      final (beforeStatus, beforeBody) = await postBody(
        c.srv.port,
        origin: 'https://portal.example',
      );
      expect(
        beforeStatus,
        200,
        reason:
            'the unauthenticated channel never holds the origin share - '
            'the same origin is served beside it',
      );
      expect(beforeBody, contains('"ok":true'));
      // الاعتماد: المقعد وحصة الأصل تؤخذان في اللحظة نفسها
      ws.add(jsonEncode({'token': _token, 'correlationId': 'ws-seat'}));
      final taken = await waitFor(() => c.srv.counters.activeSeats == 1);
      expect(
        taken,
        isTrue,
        reason: 'credential acceptance takes exactly one seat',
      );
      // الحصة الآن ممتلئة: أمر من الأصل نفسه فوق الحصة يرد برمزها،
      // والأصل الآخر يُخدم
      final (heldStatus, heldBody) = await postBody(
        c.srv.port,
        origin: 'https://portal.example',
      );
      expect(heldStatus, 503);
      expect(heldBody, contains('"origin_seat_limit"'));
      final (otherStatus, _) = await postBody(
        c.srv.port,
        origin: 'https://other.example',
      );
      expect(otherStatus, 200, reason: 'another origin keeps its share');
      // موت القناة يحرر المقعد والحصة معا
      await ws.close();
      final freed = await waitFor(() => c.srv.counters.activeSeats == 0);
      expect(freed, isTrue, reason: 'the seat frees when the channel dies');
      final (afterStatus, afterBody) = await postBody(
        c.srv.port,
        origin: 'https://portal.example',
      );
      expect(
        afterStatus,
        200,
        reason: 'the origin share is released with the seat',
      );
      expect(afterBody, contains('"ok":true'));
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

  // ترويسات مصافحة كما يرسلها متصفح حقيقي ثانٍ، ملتقطة خاماً: Mode
  // بقيمة websocket وDest بقيمة empty — المصافحة من الوجهات التي لا
  // قيمة خاصة بها، فالمتصفح يضع empty لا websocket. المصافحة بهذا
  // الشكل باب متصفحي صادق كشكل websocket/websocket، وعلى مساري السياسة
  // معاً: الافتراضي (مطابقة الترويسات الحاضرة) والمتطلِّب للترويسات
  test('a handshake carrying the headers a second real browser sends '
      '(mode websocket, dest empty, over GET) passes the fetch-metadata '
      'gates on both policy shapes', () async {
    for (final requireFetchMetadata in [false, true]) {
      final pr = IntakeProtection(telemetry: const SilentTelemetry())
        ..update(
          policy: OriginPolicy(
            allowed: ['https://portal.example'],
            requireFetchMetadata: requireFetchMetadata,
          ),
          token: _token,
        );
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: () => 'ws-shape',
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
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'websocket',
            'Sec-Fetch-Site': 'same-site',
          },
        ).timeout(const Duration(seconds: 5));
        ws.add(jsonEncode({'token': _token}));
        await Future<void>.delayed(const Duration(milliseconds: 300));
        expect(
          ws.readyState,
          WebSocket.open,
          reason:
              'requireFetchMetadata=$requireFetchMetadata: the empty-dest '
              'handshake is admitted like the websocket-dest one',
        );
        await ws.close();
      } finally {
        pr.dispose();
        await srv.stop();
      }
    }
  });

  // والمعفى لا يتسع لغير الشكلين: Mode websocket مع أي Dest آخر رفضٌ
  // كما اليوم قبل الترقية، والادعاء على POST رفضٌ ولو كان Dest فارغاً
  test('mode websocket with a dest other than websocket or empty is '
      'refused before the upgrade, and a POST claiming the handshake '
      'shape stays refused', () async {
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
      correlationIdGenerator: () => 'ws-shape-pin',
      protection: pr,
      onCommand: (cmd) async => const CommandOutcome(ok: true),
      config: const BridgeConfig(wsPath: '/ws'),
    );
    await srv.start(preferredPort: 0);
    try {
      for (final dest in ['document', 'iframe', 'script']) {
        final (status, body) = await rawHandshake(
          srv.port,
          extra: {'Sec-Fetch-Mode': 'websocket', 'Sec-Fetch-Dest': dest},
        );
        expect(
          status,
          403,
          reason: 'mode websocket with dest $dest is no browser handshake',
        );
        expect(body, contains('"cross_site_blocked"'));
      }
      final client = HttpClient();
      final req = await client.open('POST', '127.0.0.1', srv.port, '/');
      req.headers.set('Content-Type', 'application/json');
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set('Sec-Fetch-Mode', 'websocket');
      req.headers.set('Sec-Fetch-Dest', 'empty');
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

  test('stop(timeout) keeps its deadline when a live channel never '
      'answers the close frame', () async {
    final c = await start(
      config: BridgeConfig(
        wsPath: '/ws',
        idleTimeout: const Duration(minutes: 10),
      ),
      wsAuthTimeout: null,
    );
    try {
      // نظير ميت بمقبس خام: مصافحة الترقية تجيب ثم الصمت أبدياً — لا
      // اعتماد ولا قراءة ولا جواب ولا إغلاق، والاتصال يبقى مفتوحاً في
      // مجموعة القنوات الحية فإطار الإغلاق يجد لا مجيباً أبداً
      final dead = await Socket.connect('127.0.0.1', c.srv.port);
      addTearDown(dead.destroy);
      final key = base64Encode(List<int>.filled(16, 0xab));
      dead.add(
        utf8.encode(
          'GET /ws HTTP/1.1\r\n'
          'Host: 127.0.0.1:${c.srv.port}\r\n'
          'Upgrade: websocket\r\n'
          'Connection: Upgrade\r\n'
          'Sec-WebSocket-Key: $key\r\n'
          'Sec-WebSocket-Version: 13\r\n'
          'Origin: https://portal.example\r\n'
          '\r\n',
        ),
      );
      final upgraded = Completer<void>();
      final firstBytes = BytesBuilder();
      late final StreamSubscription<List<int>> sub;
      sub = dead.listen(
        (chunk) {
          firstBytes.add(chunk);
          if (!upgraded.isCompleted &&
              utf8.decode(firstBytes.toBytes()).contains('\r\n\r\n')) {
            upgraded.complete();
            // توقّف القراءة هنا: لا إطار يُقرأ ولا يُجاب بعدها أبداً
            sub.pause();
          }
        },
        onError: (Object _) {
          if (!upgraded.isCompleted) upgraded.completeError('socket error');
        },
        onDone: () {
          if (!upgraded.isCompleted) upgraded.completeError('socket closed');
        },
      );
      await upgraded.future.timeout(const Duration(seconds: 5));
      expect(
        utf8.decode(firstBytes.toBytes()),
        contains('101'),
        reason: 'the upgrade completes - the channel is live and silent',
      );
      final watch = Stopwatch()..start();
      await c.srv
          .stop(timeout: const Duration(milliseconds: 900))
          .timeout(const Duration(seconds: 8));
      final elapsedMs = watch.elapsedMilliseconds;
      expect(
        elapsedMs,
        lessThan(3000),
        reason:
            'stop honors its deadline - a channel holding the close '
            'frame hostage cannot stretch the stop past it',
      );
      expect(c.srv.isListening, isFalse);
    } finally {
      c.protection.dispose();
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

  test(
    'the unsupported-shape refusal on the channel counts exactly once',
    () async {
      final c = await start();
      try {
        final ws = await openChannel(c.srv.port);
        ws.add(jsonEncode({'nope': 'x'}));
        final (replies, _) = await readUntil(ws, 1);
        expect(replies.single, contains('"unsupported_payload_shape"'));
        await ws.close();
        expect(
          c.srv.counters.rejectionsByCode['unsupported_payload_shape'],
          1,
          reason:
              'one refusal reads one increment - the reply writer is '
              'the only counter',
        );
      } finally {
        c.protection.dispose();
        await c.srv.stop();
      }
    },
  );

  test('the strict-item refusal on the channel counts exactly once', () async {
    final c = await start(
      config: BridgeConfig(
        wsPath: '/ws',
        idleTimeout: const Duration(milliseconds: 400),
        strictPayloadItems: true,
      ),
    );
    try {
      final ws = await openChannel(c.srv.port);
      ws.add(jsonEncode([42]));
      final (replies, _) = await readUntil(ws, 1);
      expect(replies.single, contains('"invalid_payload_item"'));
      await ws.close();
      expect(
        c.srv.counters.rejectionsByCode['invalid_payload_item'],
        1,
        reason:
            'one refusal reads one increment - the reply writer is '
            'the only counter',
      );
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('the json-only refusal on the channel counts exactly once', () async {
    final c = await start(
      config: BridgeConfig(
        wsPath: '/ws',
        idleTimeout: const Duration(milliseconds: 400),
        requireJsonBodies: true,
      ),
    );
    try {
      final ws = await openChannel(c.srv.port);
      ws.add('PRINT LABEL'); // نص خام: وضع JSON فقط هو الحكم
      final (replies, _) = await readUntil(ws, 1);
      expect(replies.single, contains('"non_json_body"'));
      await ws.close();
      expect(
        c.srv.counters.rejectionsByCode['non_json_body'],
        1,
        reason:
            'one refusal reads one increment - the reply writer is '
            'the only counter',
      );
    } finally {
      c.protection.dispose();
      await c.srv.stop();
    }
  });

  test('the busy refusal on the channel counts exactly once', () async {
    final release = Completer<void>();
    final c = await start(
      config: BridgeConfig(
        wsPath: '/ws',
        idleTimeout: const Duration(milliseconds: 400),
        handlerTimeout: const Duration(milliseconds: 150),
        maxConcurrentRequests: 1,
      ),
      onCommand: (cmd) async {
        await release.future; // المعالج الأول معلق فيصير يتيماً بعد مهلته
        return const CommandOutcome(ok: true);
      },
    );
    try {
      final ws = await openChannel(c.srv.port);
      // مشترك واحد يجمع الإطارين — القناة دفق اشتراكٍ وحيد
      final first = Completer<String>();
      final second = Completer<String>();
      late final StreamSubscription<Object?> sub;
      sub = ws.listen((m) {
        if (!first.isCompleted) {
          first.complete(m as String);
        } else if (!second.isCompleted) {
          second.complete(m as String);
        }
      });
      ws.add(jsonEncode(['FIRST']));
      expect(await first.future, contains('"handler_timeout"'));
      // اليتيم حي الآن: مقعد القناة + اليتيم فوق سقف المقعد الواحد
      ws.add(jsonEncode(['SECOND']));
      expect(await second.future, contains('"server_busy"'));
      expect(
        c.srv.counters.rejectionsByCode['server_busy'],
        1,
        reason:
            'one refusal reads one increment - the reply writer is '
            'the only counter',
      );
      // وإفصاح المعالج المعلق في finally وحده — إتمامُ مزدوج يرمي
      await sub.cancel();
      await ws.close();
    } finally {
      release.complete();
      c.protection.dispose();
      await c.srv.stop();
    }
  });
}
