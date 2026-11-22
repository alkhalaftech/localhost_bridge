// عقد التركيب على خادم dart:io قائم: طقم السلك كله يمر عبر التركيب كما
// يمر على خادم الجسر الخاص (مقارنة زوجية باب-باب)، والطرف غير loopback
// يُرفض 403، ومسار المضيف الآخر لا يمسه الجسر — الحماية واحدة لا نسخة
// ثانية، والصيغة المطبوعة ::ffff:127.0.0.1 لمضيف ثنائي الطبقة تعبَر
// لأنها loopback حقيقي بعد الفك.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

const _timeout = Duration(milliseconds: 700);
const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

class _Rec extends BridgeTelemetry {
  final warns = <String>[];
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
  }) {
    warns.add(m);
  }

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
  }) async => await body();
}

var _idSeq = 0;
String _counterId() => 'mnt-${_idSeq++}';

/// خادم الجسر القياسي بالشكل نفسه الذي يقوده طقم السلك — كل بند لاحق
/// يقارن بابه الخاص ببابه المركب من المصنع نفسه.
LocalIntakeServer _make({
  required _Rec rec,
  required IntakeProtection pr,
  int delayMs = 0,
  List<int>? commandsSink,
  BridgeConfig config = const BridgeConfig(maxSeatsPerOrigin: 16),
  Duration? handlerTimeout,
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
}) => LocalIntakeServer(
  telemetry: rec,
  correlationIdGenerator: _counterId,
  onCommand: (cmd) async {
    commandsSink?.add(1);
    if (onCommand != null) return onCommand(cmd);
    if (delayMs > 0) {
      await Future<void>.delayed(Duration(milliseconds: delayMs));
    }
    return const CommandOutcome(ok: true);
  },
  protection: pr,
  config: config,
  requestTimeout: _timeout,
  handlerTimeout: handlerTimeout,
);

/// باب المضيف: خادم dart:io عادي يوزّع طلباته — مسار التطبيق يبقى للمضيف
/// حصرا (الشاهد الثالث) وكل ما سوى جسرَ يُمرَّر للتركيب.
Future<(HttpServer, int)> _hostDoor(
  LocalIntakeServer bridge, {
  Future<void> Function(HttpRequest request)? app,
  InternetAddress? bindAddress,
}) async {
  final server = await HttpServer.bind(
    bindAddress ?? InternetAddress.loopbackIPv4,
    0,
  );
  server.listen((request) async {
    final route = app;
    if (route != null && request.uri.path == '/app') {
      await route(request);
      return;
    }
    await bridge.handleHostRequest(request, hostPort: server.port);
  });
  return (server, server.port);
}

/// فك الإطار المجزأ للرد المُدار: البابان يكتبان التأطير نفسه فالمقارنة
/// الزوجية صادقة قبل الفك وبعده، والقراءة المطلقة للأجسام تحتاج الجسم
/// الخالص
String _dechunk(String body) {
  final out = StringBuffer();
  var i = 0;
  while (i < body.length) {
    final lineEnd = body.indexOf('\r\n', i);
    if (lineEnd < 0) break;
    final size = int.tryParse(body.substring(i, lineEnd), radix: 16);
    if (size == null || size == 0) break;
    final start = lineEnd + 2;
    if (start + size > body.length) break;
    out.write(body.substring(start, start + size));
    i = start + size + 2;
  }
  return out.toString();
}

/// يقرأ رداً كاملاً من مقبس خام — لا يفترض نصاً صالحاً في أي طرف.
Future<Map<String, Object?>> _exchange(
  String address,
  int port,
  String request, {
  Duration wait = const Duration(seconds: 5),
}) async {
  final socket = await Socket.connect(address, port);
  final buffer = BytesBuilder();
  final done = Completer<Map<String, Object?>>();
  late StreamSubscription sub;
  void settle() {
    final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    final head = sep < 0 ? text : text.substring(0, sep);
    final bodyRaw = sep < 0 ? '' : text.substring(sep + 4);
    final headers = <String, String>{};
    for (final line in head.split('\r\n').skip(1)) {
      final i = line.indexOf(':');
      if (i > 0) {
        headers[line.substring(0, i).trim().toLowerCase()] = line
            .substring(i + 1)
            .trim();
      }
    }
    final body = headers['transfer-encoding']?.toLowerCase() == 'chunked'
        ? _dechunk(bodyRaw)
        : bodyRaw;
    final statusLine = head.isEmpty ? '' : head.split('\r\n').first;
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
      if (hasCl || chunkedEnd) settle();
    },
    onDone: () {
      if (!done.isCompleted) settle();
    },
  );
  socket.add(utf8.encode(request));
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

String _post(
  String host,
  String body, {
  String? origin,
  String? token,
  String? contentType = 'application/json',
  String path = '/',
  Map<String, String> extra = const {},
}) {
  final h = StringBuffer()
    ..writeln('POST $path HTTP/1.1')
    ..writeln('Host: $host');
  if (contentType != null) {
    h.writeln('Content-Type: $contentType');
  }
  h.writeln('Content-Length: ${utf8.encode(body).length}');
  if (origin != null) h.writeln('Origin: $origin');
  if (token != null) h.writeln('X-Bridge-Token: $token');
  extra.forEach((name, value) {
    h.writeln('$name: $value');
  });
  h.write('\r\n');
  return h.toString() + body;
}

IntakeProtection _protection(String mode, _Rec rec) {
  final pr = IntakeProtection(telemetry: rec);
  switch (mode) {
    case 'allowAll':
      pr.update(
        policy: const OriginPolicy(
          allowAllHardened: true,
          requireFetchMetadata: false,
          perOriginPerMinute: 1000,
        ),
      );
    case 'allowlist':
      pr.update(
        policy: const OriginPolicy(allowed: ['https://portal.example']),
      );
    case 'token':
      pr.update(policy: const OriginPolicy(), token: _t64);
  }
  return pr;
}

IntakeProtection _allowAll(_Rec rec) {
  final pr = IntakeProtection(telemetry: rec);
  pr.update(
    policy: const OriginPolicy(
      allowAllHardened: true,
      requireFetchMetadata: false,
      perOriginPerMinute: 1000,
    ),
  );
  return pr;
}

const _compareHeaders = <String>[
  'access-control-allow-origin',
  'access-control-allow-headers',
  'access-control-allow-methods',
  'access-control-max-age',
  'vary',
  'retry-after',
  'content-type',
];

void _expectSameWire(
  Map<String, Object?> private,
  Map<String, Object?> mounted,
  String caseName,
) {
  expect(
    mounted['status'],
    private['status'],
    reason:
        '[$caseName] the mounted door must answer the status the '
        'private door answers',
  );
  expect(
    mounted['body'],
    private['body'],
    reason:
        '[$caseName] the mounted door must answer the body the '
        'private door answers',
  );
  final ha = private['headers'] as Map<String, String>;
  final hb = mounted['headers'] as Map<String, String>;
  for (final name in _compareHeaders) {
    expect(
      hb[name],
      ha[name],
      reason: '[$caseName] header "$name" must match the private door',
    );
  }
}

Future<String?> _firstNonLoopbackIPv4() async {
  final list = await NetworkInterface.list(
    type: InternetAddressType.IPv4,
    includeLoopback: false,
  );
  for (final i in list) {
    for (final a in i.addresses) {
      if (!a.isLoopback) return a.address;
    }
  }
  return null;
}

void main() {
  final doors = <HttpServer>[];

  Future<HttpServer> openDoor(
    LocalIntakeServer bridge, {
    Future<void> Function(HttpRequest request)? app,
    InternetAddress? bindAddress,
  }) async {
    final (server, _) = await _hostDoor(
      bridge,
      app: app,
      bindAddress: bindAddress,
    );
    doors.add(server);
    return server;
  }

  tearDown(() async {
    for (final door in doors) {
      await door.close(force: true);
    }
    doors.clear();
  });

  test('the whole wire corpus passes through the mount with the same '
      'status, body, and echo headers the private server answers', () async {
    final small = jsonEncode({
      'data': ['SIZE 3', 'CLS', 'TEXT 10,10,3,1,1,1,hello', 'PRINT 1,1'],
    });
    final over = 'x' * (1024 * 1024 + 1);
    const wrapper = 13;
    final at = '{"data":["${'x' * (1024 * 1024 - wrapper)}"]}';
    final malformedOrigin = 'https://portal.example/path';
    final longOrigin = 'https://${'a' * 600}.example';

    for (final mode in ['allowAll', 'allowlist', 'token']) {
      final recA = _Rec();
      final recB = _Rec();
      final private = _make(rec: recA, pr: _protection(mode, recA));
      final mounted = _make(rec: recB, pr: _protection(mode, recB));
      await private.start(preferredPort: 0);
      final door = await openDoor(mounted);
      final pa = private.port;
      final pb = door.port;

      Future<void> cap(
        String name,
        String requestForPrivate,
        String requestForMounted,
      ) async {
        final a = await _exchange('127.0.0.1', pa, requestForPrivate);
        final b = await _exchange('127.0.0.1', pb, requestForMounted);
        _expectSameWire(a, b, '[$mode] $name');
        expect(b['status'], isNot(-2), reason: '[$mode] $name must answer');
      }

      await cap(
        '01_valid_small',
        _post(
          '127.0.0.1:$pa',
          small,
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          '127.0.0.1:$pb',
          small,
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '02_get_method',
        'GET / HTTP/1.1\r\nHost: 127.0.0.1:$pa\r\n\r\n',
        'GET / HTTP/1.1\r\nHost: 127.0.0.1:$pb\r\n\r\n',
      );
      await cap(
        '03_options',
        'OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$pa\r\n'
            'Origin: https://portal.example\r\n'
            'Access-Control-Request-Method: POST\r\n\r\n',
        'OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$pb\r\n'
            'Origin: https://portal.example\r\n'
            'Access-Control-Request-Method: POST\r\n\r\n',
      );
      await cap(
        '04_over_limit',
        _post(
          '127.0.0.1:$pa',
          over,
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          '127.0.0.1:$pb',
          over,
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '05_at_limit',
        _post(
          '127.0.0.1:$pa',
          at,
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          '127.0.0.1:$pb',
          at,
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '06_silence_timeout',
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$pa\r\nContent-Length: 500\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n',
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$pb\r\nContent-Length: 500\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n',
      );
      await cap(
        '08_origin_rejected',
        _post('127.0.0.1:$pa', small, origin: 'https://evil.com', token: _t64),
        _post('127.0.0.1:$pb', small, origin: 'https://evil.com', token: _t64),
      );
      await cap(
        '09_token_wrong',
        _post(
          '127.0.0.1:$pa',
          small,
          origin: 'https://portal.example',
          token: 'WRONG',
        ),
        _post(
          '127.0.0.1:$pb',
          small,
          origin: 'https://portal.example',
          token: 'WRONG',
        ),
      );
      await cap(
        '10_token_correct_no_origin',
        _post('127.0.0.1:$pa', small, token: _t64),
        _post('127.0.0.1:$pb', small, token: _t64),
      );
      await cap(
        '12_host_evil',
        _post('evil.com', small, origin: 'https://portal.example', token: _t64),
        _post('evil.com', small, origin: 'https://portal.example', token: _t64),
      );
      await cap(
        '13_absolute_form',
        'POST http://evil.com/ HTTP/1.1\r\nHost: 127.0.0.1:$pa\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n'
            '$small',
        'POST http://evil.com/ HTTP/1.1\r\nHost: 127.0.0.1:$pb\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n'
            '$small',
      );
      await cap(
        '14_duplicate_host',
        'POST / HTTP/1.1\r\nHost: first.com\r\nHost: 127.0.0.1:$pa\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n'
            '$small',
        'POST / HTTP/1.1\r\nHost: first.com\r\nHost: 127.0.0.1:$pb\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n'
            'Origin: https://portal.example\r\nX-Bridge-Token: $_t64\r\n\r\n'
            '$small',
      );
      await cap(
        '15_duplicate_origin_header',
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$pa\r\n'
            'Origin: https://portal.example\r\n'
            'Origin: https://portal.example\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n\r\n$small',
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$pb\r\n'
            'Origin: https://portal.example\r\n'
            'Origin: https://portal.example\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: ${utf8.encode(small).length}\r\n\r\n$small',
      );
      await cap(
        '16_origin_malformed',
        _post('127.0.0.1:$pa', small, origin: malformedOrigin, token: _t64),
        _post('127.0.0.1:$pb', small, origin: malformedOrigin, token: _t64),
      );
      await cap(
        '17_origin_too_long',
        _post('127.0.0.1:$pa', small, origin: longOrigin, token: _t64),
        _post('127.0.0.1:$pb', small, origin: longOrigin, token: _t64),
      );
      await cap(
        '18_token_too_long',
        _post(
          '127.0.0.1:$pa',
          small,
          origin: 'https://portal.example',
          token: 'x' * 1100,
        ),
        _post(
          '127.0.0.1:$pb',
          small,
          origin: 'https://portal.example',
          token: 'x' * 1100,
        ),
      );
      await cap(
        '19_legacy_token_header_alone',
        _post(
          '127.0.0.1:$pa',
          small,
          origin: 'https://portal.example',
          extra: {'X-Portal-Token': _t64},
        ),
        _post(
          '127.0.0.1:$pb',
          small,
          origin: 'https://portal.example',
          extra: {'X-Portal-Token': _t64},
        ),
      );
      await cap(
        '20_empty_payload',
        _post(
          '127.0.0.1:$pa',
          '{}',
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          '127.0.0.1:$pb',
          '{}',
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '21_invalid_json',
        _post(
          '127.0.0.1:$pa',
          'not json at all',
          origin: 'https://portal.example',
          token: _t64,
        ),
        _post(
          '127.0.0.1:$pb',
          'not json at all',
          origin: 'https://portal.example',
          token: _t64,
        ),
      );
      await cap(
        '22_unsupported_media_type',
        _post(
          '127.0.0.1:$pa',
          small,
          origin: 'https://portal.example',
          token: _t64,
          contentType: 'text/plain',
        ),
        _post(
          '127.0.0.1:$pb',
          small,
          origin: 'https://portal.example',
          token: _t64,
          contentType: 'text/plain',
        ),
      );
      await cap(
        '23_head_reply',
        'HEAD / HTTP/1.1\r\nHost: 127.0.0.1:$pa\r\n\r\n',
        'HEAD / HTTP/1.1\r\nHost: 127.0.0.1:$pb\r\n\r\n',
      );
      await cap(
        '24_non_root_path_still_reaches_the_handler',
        _post(
          '127.0.0.1:$pa',
          small,
          origin: 'https://portal.example',
          token: _t64,
          path: '/sub/x',
        ),
        _post(
          '127.0.0.1:$pb',
          small,
          origin: 'https://portal.example',
          token: _t64,
          path: '/sub/x',
        ),
      );

      // مسمار الخضرة على الباب المركب: الحالة السليمة تعبر فيه
      final ok = await _exchange(
        '127.0.0.1',
        pb,
        _post(
          '127.0.0.1:$pb',
          small,
          origin: 'https://portal.example',
          token: _t64,
          extra: const {'X-Correlation-Id': 'mnt-echo-witness'},
        ),
      );
      expect(ok['status'], 200, reason: '[$mode] the healthy one crosses');
      final okBody = jsonDecode(ok['body'] as String) as Map<String, Object?>;
      expect(okBody['ok'], true);
      // صدى معرف الارتباط: القيمة المرسلة تعود حرفياً على البابين
      final okA = await _exchange(
        '127.0.0.1',
        pa,
        _post(
          '127.0.0.1:$pa',
          small,
          origin: 'https://portal.example',
          token: _t64,
          extra: const {'X-Correlation-Id': 'mnt-echo-witness'},
        ),
      );
      expect(
        (ok['headers'] as Map)['x-correlation-id'],
        'mnt-echo-witness',
        reason: '[$mode] the mounted door echoes the correlation id',
      );
      expect(
        (okA['headers'] as Map)['x-correlation-id'],
        'mnt-echo-witness',
        reason: '[$mode] the private door echoes the same correlation id',
      );

      // مقارنة أسطر المرصد: البابان يقولان الشيء نفسه (نمط مسار غير الجذر)
      final warnA = recA.warns.where((w) => w.contains('non-root path'));
      final warnB = recB.warns.where((w) => w.contains('non-root path'));
      expect(
        warnB.length,
        warnA.length,
        reason: '[$mode] the same observer lines land on both doors',
      );

      await private.stop();
      await mounted.stop();
    }
  });

  test('the reply-data cap, the handler budget, the seat cap, and the '
      'origin share answer identically through the mount', () async {
    final small = jsonEncode({
      'data': ['PRINT 1'],
    });

    Future<void> pair(
      String name, {
      int delayMs = 0,
      BridgeConfig config = const BridgeConfig(maxSeatsPerOrigin: 16),
      IntakeProtection Function(_Rec)? protection,
      Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
      Duration? handlerTimeout,
      required Future<void> Function(int privatePort, int mountPort) run,
    }) async {
      final recA = _Rec();
      final recB = _Rec();
      final private = _make(
        rec: recA,
        pr: protection?.call(recA) ?? _protection('token', recA),
        delayMs: delayMs,
        config: config,
        onCommand: onCommand,
        handlerTimeout: handlerTimeout,
      );
      final mounted = _make(
        rec: recB,
        pr: protection?.call(recB) ?? _protection('token', recB),
        delayMs: delayMs,
        config: config,
        onCommand: onCommand,
        handlerTimeout: handlerTimeout,
      );
      await private.start(preferredPort: 0);
      final door = await openDoor(mounted);
      await run(private.port, door.port);
      await private.stop();
      await mounted.stop();
    }

    // سقف بيانات الرد: النجاح فوق 64KiB يرد 413 reply_data_too_large
    await pair(
      'reply_data_too_large',
      onCommand: (cmd) async =>
          CommandOutcome(ok: true, data: {'blob': 'y' * (64 * 1024 + 1)}),
      run: (pa, pb) async {
        String req(int port) => _post(
          '127.0.0.1:$port',
          small,
          origin: 'https://portal.example',
          token: _t64,
        );
        final a = await _exchange('127.0.0.1', pa, req(pa));
        final b = await _exchange('127.0.0.1', pb, req(pb));
        expect(a['status'], 413);
        _expectSameWire(a, b, 'reply_data_too_large');
      },
    );

    // ميزانية المعالج: تجاوزها يرد 504 handler_timeout ويترك اليتيم مكتوماً
    await pair(
      'handler_timeout',
      delayMs: 400,
      handlerTimeout: const Duration(milliseconds: 100),
      run: (pa, pb) async {
        String req(int port) => _post(
          '127.0.0.1:$port',
          small,
          origin: 'https://portal.example',
          token: _t64,
        );
        final a = await _exchange('127.0.0.1', pa, req(pa));
        final b = await _exchange('127.0.0.1', pb, req(pb));
        expect(a['status'], 504);
        _expectSameWire(a, b, 'handler_timeout');
      },
    );

    // سقف المقاعد العام: مقعد واحد بمعالج بطيء فالثاني 503 server_busy
    await pair(
      'server_busy',
      delayMs: 250,
      config: const BridgeConfig(maxConcurrentRequests: 1),
      run: (pa, pb) async {
        Future<List<int>> both(int port) async {
          final req = _post(
            '127.0.0.1:$port',
            small,
            origin: 'https://portal.example',
            token: _t64,
          );
          final rs = await Future.wait([
            _exchange('127.0.0.1', port, req),
            _exchange('127.0.0.1', port, req),
          ]);
          return rs.map((r) => r['status'] as int).toList()..sort();
        }

        final a = await both(pa);
        final b = await both(pb);
        expect(a, [200, 503]);
        expect(b, a, reason: 'the mounted door answers the same pair');
      },
    );

    // حصة الأصل: مقعد واحد لكل أصل فالثاني من الأصل نفسه 503 origin_seat_limit
    await pair(
      'origin_seat_limit',
      delayMs: 250,
      config: const BridgeConfig(
        maxConcurrentRequests: 4,
        maxSeatsPerOrigin: 1,
      ),
      run: (pa, pb) async {
        Future<List<int>> both(int port) async {
          final req = _post(
            '127.0.0.1:$port',
            small,
            origin: 'https://portal.example',
            token: _t64,
          );
          final rs = await Future.wait([
            _exchange('127.0.0.1', port, req),
            _exchange('127.0.0.1', port, req),
          ]);
          return rs.map((r) => r['status'] as int).toList()..sort();
        }

        final a = await both(pa);
        final b = await both(pb);
        expect(a, [200, 503]);
        expect(b, a, reason: 'the mounted door answers the same pair');
      },
    );

    // حصة المدرج مع صدى Retry-After الصادق: الثالثة فوق الحصة 429
    await pair(
      'origin_rate_limited_retry_after',
      protection: (rec) {
        final pr = IntakeProtection(telemetry: rec);
        pr.update(
          policy: const OriginPolicy(
            allowAllHardened: true,
            requireFetchMetadata: false,
            perOriginPerMinute: 2,
          ),
        );
        return pr;
      },
      run: (pa, pb) async {
        Future<List<Map<String, Object?>>> three(int port) async {
          final req = _post(
            '127.0.0.1:$port',
            small,
            origin: 'https://portal.example',
          );
          final rs = <Map<String, Object?>>[];
          for (var i = 0; i < 3; i++) {
            rs.add(await _exchange('127.0.0.1', port, req));
          }
          return rs;
        }

        final a = await three(pa);
        final b = await three(pb);
        for (var i = 0; i < 3; i++) {
          _expectSameWire(a[i], b[i], 'rate_limit[$i]');
        }
        expect(a[2]['status'], 429, reason: 'the third over the share is 429');
        final hb = b[2]['headers'] as Map<String, String>;
        expect(
          hb['retry-after'],
          isNotNull,
          reason: 'the honest wait rides the mounted door too',
        );
      },
    );
  });

  test(
    'a request from a non-loopback address is refused with 403 '
    'blocked_by_protection while the same request from loopback passes',
    () async {
      final rec = _Rec();
      final mounted = _make(rec: rec, pr: _allowAll(rec));
      final door = await openDoor(
        mounted,
        bindAddress: InternetAddress.anyIPv4,
      );
      final pb = door.port;
      final body = jsonEncode({
        'data': ['PRINT 1'],
      });

      // الضابط: النداء المحلي نفسه يعبر
      final ok = await _exchange(
        '127.0.0.1',
        pb,
        _post('localhost:$pb', body, origin: 'https://portal.example'),
      );
      expect(ok['status'], 200, reason: 'the loopback caller crosses');

      final ext = await _firstNonLoopbackIPv4();
      if (ext == null) {
        markTestSkipped(
          'no non-loopback interface on this host - the external-peer '
          'fact cannot be measured here',
        );
        return;
      }
      final refused = await _exchange(
        ext,
        pb,
        _post('localhost:$pb', body, origin: 'https://portal.example'),
      );
      expect(refused['status'], 403, reason: 'a non-loopback peer is refused');
      final refusedBody =
          jsonDecode(refused['body'] as String) as Map<String, Object?>;
      expect(refusedBody['ok'], false);
      expect(
        refusedBody['error'],
        'blocked_by_protection',
        reason: 'the standing 403 code carries the refusal - no new code',
      );
      expect(
        refusedBody['message'],
        contains('loopback'),
        reason: 'the message names the loopback fact, not the Host fact',
      );
    },
  );

  test('from a non-loopback peer the peer guard answers 403 '
      'blocked_by_protection ahead of every header gate and writes no '
      'metric line', () async {
    // الحارس البعيد أول بوابة: كل فحص ترويسة لاحق له سطر قياس أو عدّ
    // أو قراءة قيمة يتحكم فيها الطرف — فلا يبلغه شيء قبل حكم الطرف.
    // البوابات الخمس (أصل طويل، أصل معتل، توكن طويل، رمز اقتران طويل،
    // ترويسة مكررة) والترويسة المتقاعدة كلها تُجاب 403 الرمز القائم،
    // ولا سطر قياس واحد يكتب عنها — إنكار صامت مقصود: الطرف البعيد لا
    // يكتب في سجل الجسر ولا يصرف ميزانية الكبح.
    final rec = _Rec();
    final pr = _allowAll(rec)..enablePairing();
    final mounted = _make(rec: rec, pr: pr);
    final door = await openDoor(mounted, bindAddress: InternetAddress.anyIPv4);
    final pb = door.port;
    final body = jsonEncode({
      'data': ['PRINT 1'],
    });

    final ext = await _firstNonLoopbackIPv4();
    if (ext == null) {
      markTestSkipped(
        'no non-loopback interface on this host - the external-peer '
        'fact cannot be measured here',
      );
      return;
    }
    // أسطر الإعداد (تسليح السياسة والاقتران) تُستبعد: الشاهد يقيس ما
    // يكتبه الطلب نفسه لا ما كتبه الإعداد قبله
    final setupLines = rec.warns.length;

    Future<void> expectPeer403(String request, String label) async {
      final r = await _exchange(ext, pb, request);
      expect(
        r['status'],
        403,
        reason: '[$label] the peer fact is judged before any gate',
      );
      final jb = jsonDecode(r['body'] as String) as Map<String, Object?>;
      expect(
        jb['error'],
        'blocked_by_protection',
        reason: '[$label] the standing code carries the refusal',
      );
      expect(
        rec.warns.length,
        setupLines,
        reason: '[$label] no metric line is written for a remote party',
      );
    }

    // أصل فوق سقف الطول
    await expectPeer403(
      _post('localhost:$pb', body, origin: 'https://${'a' * 1100}.example'),
      'long origin',
    );
    // أصل معتل الشكل
    await expectPeer403(
      _post('localhost:$pb', body, origin: 'https://portal.example/../evil'),
      'malformed origin',
    );
    // توكن فوق سقف البايتات
    await expectPeer403(
      _post('localhost:$pb', body, token: 'a' * 1100),
      'long token',
    );
    // توقيع اقتران فوق سقفه والاقتران مسلح
    await expectPeer403(
      _post('localhost:$pb', body, extra: {'X-Bridge-Pairing': 'a' * 1100}),
      'long pairing proof',
    );
    // ترويسة مكررة — بناء خام بقيمتين
    final dup = StringBuffer()
      ..writeln('POST / HTTP/1.1')
      ..writeln('Host: localhost:$pb')
      ..writeln('Content-Type: application/json')
      ..writeln('Origin: https://portal.example')
      ..writeln('X-Correlation-Id: mnt-dup-1')
      ..writeln('X-Correlation-Id: mnt-dup-2')
      ..writeln('Content-Length: ${utf8.encode(body).length}')
      ..write('\r\n');
    await expectPeer403(dup.toString() + body, 'duplicate header');
    // الترويسة المتقاعدة: لا تبلغ قيمتها شيئا ولا يكتب تحذيرها
    await expectPeer403(
      _post(
        'localhost:$pb',
        body,
        origin: 'https://portal.example',
        token: _t64,
        extra: {'X-Portal-Token': _t64},
      ),
      'legacy token header',
    );
    expect(
      rec.warns.length,
      setupLines,
      reason:
          'the whole remote sweep wrote no metric line - the '
          'protection log stays for local callers',
    );
  });

  test('a dual-stack host bind delivers the loopback caller as the '
      'IPv4-mapped ::ffff:127.0.0.1 and it crosses', () async {
    final rec = _Rec();
    final mounted = _make(rec: rec, pr: _allowAll(rec));
    final door = await openDoor(mounted, bindAddress: InternetAddress.anyIPv6);
    final pb = door.port;
    final body = jsonEncode({
      'data': ['PRINT 1'],
    });
    // النداء عبر 127.0.0.1 إلى خادم ثنائي الطبقة يصل بطرف ::ffff:127.0.0.1 —
    // هو loopback حقيقي بعد فك الصيغة فيعبر
    final ok = await _exchange(
      '127.0.0.1',
      pb,
      _post('localhost:$pb', body, origin: 'https://portal.example'),
    );
    expect(
      ok['status'],
      200,
      reason: 'the mapped v4 loopback is loopback after the unwrap',
    );
  });

  test(
    'another path of the host server is never touched by the bridge',
    () async {
      final rec = _Rec();
      final commands = <int>[];
      final mounted = _make(
        rec: rec,
        pr: _allowAll(rec),
        commandsSink: commands,
      );
      var appHits = 0;
      final door = await openDoor(
        mounted,
        app: (request) async {
          appHits++;
          request.response.headers.set('Content-Type', 'application/json');
          request.response.statusCode = 200;
          request.response.write('{"app":true}');
          await request.response.close();
        },
      );
      final pb = door.port;

      // مسار التطبيق: المضيف يجيب بنفسه والجسر لا يراه
      final warnsBeforeApp = rec.warns.length;
      final app = await _exchange(
        '127.0.0.1',
        pb,
        'POST /app HTTP/1.1\r\nHost: 127.0.0.1:$pb\r\nContent-Length: 0\r\n\r\n',
      );
      expect(app['status'], 200);
      expect(
        app['body'],
        contains('{"app":true}'),
        reason:
            'the app answer is the host app body (chunked framing is '
            'the host server own)',
      );
      expect(appHits, 1, reason: 'the host app answered its own path');
      expect(
        commands,
        isEmpty,
        reason: 'the bridge never executed anything for the app path',
      );
      expect(mounted.counters.activeSeats, 0);
      expect(
        rec.warns.length,
        warnsBeforeApp,
        reason: 'no bridge observer line fired for the app path',
      );

      // ومسار الجسر يجيب من الجسر نفسه
      final bridge = await _exchange(
        '127.0.0.1',
        pb,
        _post(
          '127.0.0.1:$pb',
          jsonEncode({
            'data': ['PRINT 1'],
          }),
          origin: 'https://portal.example',
          path: '/bridge',
        ),
      );
      expect(bridge['status'], 200);
      final bridgeBody =
          jsonDecode(bridge['body'] as String) as Map<String, Object?>;
      expect(bridgeBody['ok'], true);
      expect(
        commands,
        hasLength(1),
        reason: 'the bridge executed the bridged command',
      );
      await mounted.stop();
    },
  );

  test('the streaming reply rides the mount with the same frame sequence '
      'as the private server', () async {
    IntakeProtection listed(_Rec rec) {
      final pr = IntakeProtection(telemetry: rec);
      pr.update(
        policy: const OriginPolicy(allowed: ['https://portal.example']),
      );
      return pr;
    }

    LocalIntakeServer streaming(_Rec rec) => LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: _counterId,
      onCommand: (cmd) async {
        cmd.progress?.call(const {'step': 1});
        cmd.progress?.call(const {'step': 2});
        return const CommandOutcome(ok: true, data: {'echo': true});
      },
      protection: listed(rec),
      config: const BridgeConfig(
        maxSeatsPerOrigin: 16,
        allowStreamingReplies: true,
      ),
      requestTimeout: const Duration(seconds: 5),
    );

    final private = streaming(_Rec());
    final mounted = streaming(_Rec());
    await private.start(preferredPort: 0);
    final door = await openDoor(mounted);

    Future<List<String>> frames(int port) async {
      final body = jsonEncode({
        'data': ['PRINT 1'],
      });
      final req = _post(
        '127.0.0.1:$port',
        body,
        origin: 'https://portal.example',
        extra: {'X-Bridge-Stream': 'events'},
      );
      final socket = await Socket.connect('127.0.0.1', port);
      final buffer = BytesBuilder();
      final done = Completer<List<String>>();
      late StreamSubscription sub;
      sub = socket.listen(
        (chunk) {
          buffer.add(chunk);
        },
        onDone: () {
          final text = utf8.decode(buffer.toBytes(), allowMalformed: true);
          final sep = text.indexOf('\r\n\r\n');
          final payload = sep < 0 ? '' : text.substring(sep + 4);
          done.complete(
            payload
                .split('\n')
                .map((l) => l.trim())
                .where((l) => l.startsWith('event: ') || l.startsWith('data: '))
                .toList(),
          );
        },
      );
      socket.add(utf8.encode(req));
      final result = await done.future.timeout(const Duration(seconds: 5));
      await sub.cancel();
      socket.destroy();
      return result;
    }

    final a = await frames(private.port);
    final b = await frames(door.port);
    expect(
      b,
      a,
      reason:
          'the mounted door streams the exact frame sequence the '
          'private door streams',
    );
    expect(a.where((f) => f.startsWith('event: progress')), hasLength(2));
    expect(a.last, contains('"ok":true'));
    await private.stop();
    await mounted.stop();
  });

  test('the WebSocket channel rides the mount: the unauthenticated '
      'handshake closes with ws_auth_timeout and the authenticated story '
      'runs the command', () async {
    const wsToken =
        'b3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c9';
    // على SDK لا تعرف dart:io معلمة سقف النقل لا تُسلَّح القناة أصلاً
    // (الرفض عند البناء) فلا قصة قناة على التركيب هنا
    if (!LocalIntakeServer.wsTransportCeilingSupported) {
      markTestSkipped(
        'the channel refuses to arm without a transport ceiling on this '
        'SDK - no channel story on the mount here',
      );
      return;
    }
    LocalIntakeServer channel(_Rec rec) => LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: _counterId,
      onCommand: (cmd) async =>
          const CommandOutcome(ok: true, data: {'echo': true}),
      protection: IntakeProtection(telemetry: rec)
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          token: wsToken,
        ),
      config: const BridgeConfig(wsPath: '/ws'),
      requestTimeout: _timeout,
      wsAuthTimeout: const Duration(milliseconds: 400),
    );

    final private = channel(_Rec());
    final mounted = channel(_Rec());
    await private.start(preferredPort: 0);
    final door = await openDoor(mounted);

    // القصة السلبية على البابين: مصافحة بأصل مؤهل وبلا اعتماد تُغلق برمز القناة
    Future<(int?, String?)> negative(int port) async {
      final ws = await WebSocket.connect(
        'ws://127.0.0.1:$port/ws',
        headers: const {'Origin': 'https://portal.example'},
      );
      final closed = Completer<void>();
      ws.listen(
        (_) {},
        onDone: closed.complete,
        onError: (Object _) => closed.complete(),
      );
      await closed.future.timeout(
        const Duration(milliseconds: 1500),
        onTimeout: () {},
      );
      final code = ws.closeCode;
      final reason = ws.closeReason;
      try {
        await ws.close();
      } on Object {
        // القناة ماتت بالفعل
      }
      return (code, reason);
    }

    final a = await negative(private.port);
    final b = await negative(door.port);
    expect(a.$1, isNotNull, reason: 'the private channel closes');
    expect(
      b,
      a,
      reason:
          'the mounted channel closes with the same code '
          'and reason as the private one',
    );
    expect(b.$2, 'ws_auth_timeout');

    // القصة الكاملة على الباب المركب: اعتماد أول رسالة ثم أمر فرد
    final ws = await WebSocket.connect(
      'ws://127.0.0.1:${door.port}/ws',
      headers: const {'Origin': 'https://portal.example'},
    );
    ws.add(jsonEncode({'token': wsToken, 'correlationId': 'ws-auth'}));
    final replies = <String>[];
    final gotReply = Completer<void>();
    ws.listen((frame) {
      replies.add(frame as String);
      if (!gotReply.isCompleted) gotReply.complete();
    }, onError: (Object _) {});
    ws.add(jsonEncode(['PRINT 1']));
    await gotReply.future.timeout(const Duration(seconds: 5));
    expect(replies.single, contains('"ok":true'));
    expect(replies.single, contains('"echo":true'));
    await ws.close();
    await private.stop();
    await mounted.stop();
  });
}
