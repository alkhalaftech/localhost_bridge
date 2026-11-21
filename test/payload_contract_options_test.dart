// The payload-contract options: every one ships off, and each carries a
// pair of witnesses - off keeps today's wire letter-for-letter, on
// produces the opt-in refusal or delivery. The four new refusal codes
// ride the single rejection registry like every other code, and the
// binary ceiling is an internal named constant, deliberately not an
// option. Titles in English (published package); comments explain the
// code to the developer reading it.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show Uint8List;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _counterId() => 'opt-${_idSeq++}';

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

LocalIntakeServer _server({
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
  BridgeConfig config = const BridgeConfig(),
}) {
  // أصل مدرج بلا حصة معدل: القائمة المؤهلة تقرأ الرسائل التفصيلية
  // (نص المضيف) والحصة صفر خيار صريح موثق يبقيها بلا معدل
  return LocalIntakeServer(
    telemetry: _Rec(),
    correlationIdGenerator: _counterId,
    onCommand: onCommand ?? (cmd) async => const CommandOutcome(ok: true),
    protection: IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          listedPerOriginPerMinute: 0,
        ),
      ),
    config: config,
  );
}

Future<({int status, String body, HttpClientResponse response})> _post(
  LocalIntakeServer srv, {
  Object body = '["CMD"]',
  String contentType = 'application/json',
  String origin = 'https://portal.example',
  Map<String, String> headers = const {},
}) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(
      Uri.parse('http://127.0.0.1:${srv.port}/'),
    );
    req.headers.set('Origin', origin);
    req.headers.set('Content-Type', contentType);
    headers.forEach(req.headers.set);
    if (body is String) {
      req.add(utf8.encode(body));
    } else if (body is List<int>) {
      req.add(body);
    } else {
      throw ArgumentError('body must be a String or List<int>');
    }
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (status: res.statusCode, body: text, response: res);
  } finally {
    client.close(force: true);
  }
}

Future<HttpClientResponse> _preflight(
  LocalIntakeServer srv, {
  String origin = 'https://portal.example',
}) async {
  final client = HttpClient();
  try {
    final req = await client.openUrl(
      'OPTIONS',
      Uri.parse('http://127.0.0.1:${srv.port}/'),
    );
    req.headers.set('Origin', origin);
    req.headers.set('Access-Control-Request-Method', 'POST');
    final res = await req.close();
    await res.drain<void>();
    return res;
  } finally {
    client.close(force: true);
  }
}

void main() {
  late LocalIntakeServer server;

  tearDown(() async => server.stop());

  // ── خيار العناصر الصارمة ────────────────────────────────────────────

  test('strict items off: non-string and empty list elements drop as '
      'today and the strings reach the handler', () async {
    server = _server(
      onCommand: (cmd) async {
        return CommandOutcome(ok: true, data: cmd.payloads);
      },
    );
    await server.start(preferredPort: 0);
    final res = await _post(server, body: '["A", "", 42, "B"]');
    expect(res.status, 200, reason: 'the default wire drops silently');
    expect(res.body, contains('"ok":true'));
    expect(
      res.body,
      contains('["A","B"]'),
      reason: 'non-text and empty elements dropped, strings delivered',
    );
  });

  test('strict items on: a non-text or empty element refuses 400 '
      'invalid_payload_item and nothing reaches the handler', () async {
    final seen = <List<String>>[];
    server = _server(
      config: const BridgeConfig(strictPayloadItems: true),
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final mixed = await _post(server, body: '["A", "", 42, "B"]');
    expect(mixed.status, 400, reason: 'an empty element is a strict refusal');
    expect(mixed.body, contains('"error":"invalid_payload_item"'));
    final nonText = await _post(server, body: '["A", 42]');
    expect(
      nonText.status,
      400,
      reason: 'a non-text element is a strict refusal',
    );
    expect(nonText.body, contains('"error":"invalid_payload_item"'));
    final wrapped = await _post(server, body: '{"data":["A", null]}');
    expect(
      wrapped.status,
      400,
      reason: 'the strict rule covers wrapper lists too',
    );
    expect(wrapped.body, contains('"error":"invalid_payload_item"'));
    expect(seen, isEmpty, reason: 'nothing reaches the handler');
  });

  test('strict items on: clean lists still unwrap and serve', () async {
    final seen = <List<String>>[];
    server = _server(
      config: const BridgeConfig(strictPayloadItems: true),
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final res = await _post(server, body: '["A","B"]');
    expect(res.status, 200, reason: 'a clean list is not a strict refusal');
    expect(seen.single, ['A', 'B']);
  });

  // ── خيار فحص الشكل للأجسام الحاوية ──────────────────────────────────

  test('shape check off: an unterminated container falls through as raw '
      'text exactly as today', () async {
    final seen = <List<String>>[];
    server = _server(
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final res = await _post(server, body: '["CMD"');
    expect(res.status, 200, reason: 'the default wire keeps the raw fallback');
    expect(seen.single.single, '["CMD"', reason: 'the raw text is the command');
  });

  test('shape check on: an unterminated container refuses 400 '
      'malformed_json_shape before any decode', () async {
    final seen = <List<String>>[];
    server = _server(
      config: const BridgeConfig(requireValidJsonShape: true),
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final cut = await _post(server, body: '["CMD"');
    expect(
      cut.status,
      400,
      reason: 'an opener without its closer is a refusal',
    );
    expect(cut.body, contains('"error":"malformed_json_shape"'));
    final cutObject = await _post(server, body: '{"data":');
    expect(cutObject.status, 400);
    expect(cutObject.body, contains('"error":"malformed_json_shape"'));
    expect(seen, isEmpty, reason: 'the broken body never reaches the handler');
  });

  test('shape check on: complete containers and quote-leading raw text '
      'stay outside the gate', () async {
    final seen = <List<String>>[];
    server = _server(
      config: const BridgeConfig(requireValidJsonShape: true),
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final complete = await _post(server, body: '{"data":["A"]}');
    expect(complete.status, 200, reason: 'a complete container is served');
    // المجال حاويات حصرا: نص خام يبدأ باقتباس ليس جسم JSON متعاهداً
    // فيبقى على مساره الخام كما كان
    final quoteLead = await _post(
      server,
      body: '"never closed',
      contentType: 'text/plain',
    );
    expect(
      quoteLead.status,
      200,
      reason: 'the gate scans container-shaped bodies only',
    );
    expect(seen.map((p) => p.single), ['A', '"never closed']);
  });

  // ── خيار invalid_json لنوع application/json ─────────────────────────

  test('invalid_json off: a broken application/json body falls through '
      'as raw text exactly as today', () async {
    final seen = <List<String>>[];
    server = _server(
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final res = await _post(server, body: '{"data":');
    expect(res.status, 200, reason: 'the default wire keeps the raw fallback');
    expect(seen.single.single, '{"data":');
  });

  test('invalid_json on: a broken application/json body answers 400 '
      'invalid_json', () async {
    final seen = <List<String>>[];
    server = _server(
      config: const BridgeConfig(rejectInvalidJson: true),
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final res = await _post(server, body: '{"data":');
    expect(res.status, 400);
    expect(res.body, contains('"error":"invalid_json"'));
    expect(seen, isEmpty, reason: 'a declared-JSON broken body never runs');
  });

  test('invalid_json on: the refusal is scoped to the declared '
      'application/json type - other types keep the raw path', () async {
    final seen = <List<String>>[];
    server = _server(
      config: const BridgeConfig(rejectInvalidJson: true),
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final plain = await _post(
      server,
      body: '{"data":',
      contentType: 'text/plain',
    );
    expect(
      plain.status,
      200,
      reason: 'a textual gateway never declared JSON, so the raw path holds',
    );
    expect(seen.single.single, '{"data":');
  });

  // ── وضع JSON فقط ────────────────────────────────────────────────────

  test('json-only off: a raw device-language command is served as raw '
      'text exactly as today', () async {
    // The device-command-language sample: two EPL2 lines in their
    // documented factory-manual forms - Eltron Programmer's Manual
    // Rev. D (980352-001): the X frame `X x,y,thickness,x_end,y_end`
    // with the manual's own example X50,200,5,400,20 (p. 3-120), and
    // the LO line `LO x,y,h_length,v_length` with the manual's example
    // LO200,50,20,400 (p. 3-69).
    const deviceJob = 'X50,200,5,400,20\r\nLO200,50,20,400';
    final seen = <List<String>>[];
    server = _server(
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final res = await _post(server, body: deviceJob, contentType: 'text/plain');
    expect(res.status, 200, reason: 'textual gateways keep working by default');
    expect(seen.single.single, deviceJob);
  });

  test('json-only on: raw text refuses 400 non_json_body while a JSON '
      'string body still serves', () async {
    // لغة أوامر الجهاز نفسها بصيغة الدليل المصنعي الموثق (X ص 3-120
    // وLO ص 3-69 من دليل Eltron Rev. D 980352-001) — هي النص الخام
    // الذي يرفضه الوضع
    const deviceJob = 'X50,200,5,400,20\r\nLO200,50,20,400';
    final seen = <List<String>>[];
    server = _server(
      config: const BridgeConfig(requireJsonBodies: true),
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final raw = await _post(server, body: deviceJob, contentType: 'text/plain');
    expect(raw.status, 400, reason: 'raw text is the refusal of this mode');
    expect(raw.body, contains('"error":"non_json_body"'));
    final jsonString = await _post(
      server,
      body: '"SIZE 4mm"',
      contentType: 'application/json',
    );
    expect(
      jsonString.status,
      200,
      reason: 'a quoted JSON string is still JSON - decoded and delivered',
    );
    expect(seen.single.single, 'SIZE 4mm');
  });

  test('json-only on: scalar JSON bodies refuse too, and with '
      'invalid_json on as well a declared broken body reads invalid_json '
      '(the specific code wins)', () async {
    final seen = <List<String>>[];
    server = _server(
      config: const BridgeConfig(
        requireJsonBodies: true,
        rejectInvalidJson: true,
      ),
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final scalar = await _post(server, body: '42');
    expect(
      scalar.status,
      400,
      reason:
          'a JSON number arrives as raw command text today - the mode '
          'refuses that path whole',
    );
    expect(scalar.body, contains('"error":"non_json_body"'));
    final broken = await _post(server, body: '{"data":');
    expect(
      broken.body,
      contains('"error":"invalid_json"'),
      reason: 'the declared-type code takes precedence for application/json',
    );
    expect(seen, isEmpty);
  });

  // ── خيار رفض المعالج ────────────────────────────────────────────────

  test('handler refusal off: ok:false with a refusal status still answers '
      '500 - the default stays', () async {
    server = _server(
      onCommand: (cmd) async => const CommandOutcome(
        ok: false,
        errorCode: 'printer_unavailable',
        errorMessage: 'no printer answered',
        refusalStatus: 409,
      ),
    );
    await server.start(preferredPort: 0);
    final res = await _post(server);
    expect(res.status, 500, reason: 'without the option the outcome is 500');
    expect(res.body, contains('"error":"printer_unavailable"'));
    expect(
      res.body,
      contains('no printer answered'),
      reason: 'a listed origin reads the host text',
    );
  });

  test('handler refusal on: the marked status rides the wire with the '
      'code', () async {
    server = _server(
      config: const BridgeConfig(acceptHandlerRefusal: true),
      onCommand: (cmd) async => const CommandOutcome(
        ok: false,
        errorCode: 'printer_unavailable',
        refusalStatus: 409,
      ),
    );
    await server.start(preferredPort: 0);
    final res = await _post(server);
    expect(res.status, 409, reason: 'the handler marks the refusal 4xx');
    expect(res.body, contains('"error":"printer_unavailable"'));
  });

  test('handler refusal on: a null or out-of-range marker keeps the 500 '
      'default', () async {
    server = _server(
      config: const BridgeConfig(acceptHandlerRefusal: true),
      onCommand: (cmd) async =>
          const CommandOutcome(ok: false, errorCode: 'x', refusalStatus: 600),
    );
    await server.start(preferredPort: 0);
    final overRange = await _post(server);
    expect(
      overRange.status,
      500,
      reason: 'only 400..499 is a client-refusal status',
    );
    expect(overRange.body, contains('"error":"x"'));
    server.stop();
    final noMarker = _server(
      config: const BridgeConfig(acceptHandlerRefusal: true),
      onCommand: (cmd) async => const CommandOutcome(ok: false, errorCode: 'x'),
    );
    server = noMarker;
    await noMarker.start(preferredPort: 0);
    final plain = await _post(noMarker);
    expect(plain.status, 500, reason: 'no marker, no refusal - 500 as always');
    expect(plain.body, contains('"error":"x"'));
  });

  // ── خيار حد رسالة الخطأ ─────────────────────────────────────────────

  test(
    'message cap off: a listed origin reads the whole host message',
    () async {
      final long = 'x' * 3000;
      server = _server(
        onCommand: (cmd) async =>
            CommandOutcome(ok: false, errorCode: 'e', errorMessage: long),
      );
      await server.start(preferredPort: 0);
      final res = await _post(server);
      expect(res.status, 500);
      expect(
        res.body.contains(long),
        isTrue,
        reason: 'without the cap the message travels whole',
      );
    },
  );

  test('message cap on: the host message truncates to exactly the cap '
      'characters and short messages stay untouched', () async {
    final long = 'y' * 3000;
    server = _server(
      config: const BridgeConfig(maxErrorMessageLength: 64),
      onCommand: (cmd) async =>
          CommandOutcome(ok: false, errorCode: 'e', errorMessage: long),
    );
    await server.start(preferredPort: 0);
    final res = await _post(server);
    expect(res.status, 500);
    expect(res.body.contains('y' * 64), isTrue);
    expect(
      res.body.contains('y' * 65),
      isFalse,
      reason: 'the reply never carries more error text than the cap',
    );
    server.stop();
    final short = _server(
      config: const BridgeConfig(maxErrorMessageLength: 64),
      onCommand: (cmd) async => const CommandOutcome(
        ok: false,
        errorCode: 'e',
        errorMessage: 'short sentence',
      ),
    );
    server = short;
    await short.start(preferredPort: 0);
    final small = await _post(short);
    expect(
      small.body.contains('short sentence'),
      isTrue,
      reason: 'a message under the cap is delivered verbatim',
    );
  });

  test('message cap counts UTF-8 bytes, not characters: a multi-byte '
      'message over the byte cap truncates even when its character count '
      'fits, cut at a whole-character boundary', () async {
    // عشرة محارف عربية = عشرة محارف (كانت تعبر كاملة تحت سقف 12 محرفاً)
    // لكنها عشرون بايتاً على السلك — السقف البايتي يقطعها إلى ستة محارف
    // (اثنا عشر بايتاً بالضبط) لا إلى سابعٍ فوق حده
    final arabic = 'ا' * 10;
    expect(utf8.encode(arabic).length, 20);
    server = _server(
      config: const BridgeConfig(maxErrorMessageLength: 12),
      onCommand: (cmd) async =>
          CommandOutcome(ok: false, errorCode: 'e', errorMessage: arabic),
    );
    await server.start(preferredPort: 0);
    final res = await _post(server);
    expect(res.status, 500);
    expect(
      res.body.contains('ا' * 6),
      isTrue,
      reason: 'twelve bytes of Arabic are exactly six characters',
    );
    expect(
      res.body.contains('ا' * 7),
      isFalse,
      reason: 'the reply never carries a seventh character past the byte '
          'cap - the cap is byte-wise',
    );
    server.stop();
    // القص عند حدّ محرفٍ كامل: ثلاثة محارف عربية (ستة بايتات) ثم رمزَان
    // من أربعة بايتات لكلٍّ — سقف 9 بايتات يُسقط الرمز الثاني كله ولا
    // يسافر نصفُه قط، والرد يبقى UTF-8 صالحاً بقراءته نفسها
    final emojis = 'ااا🖥🖥';
    expect(utf8.encode(emojis).length, 14);
    final bounded = _server(
      config: const BridgeConfig(maxErrorMessageLength: 9),
      onCommand: (cmd) async =>
          CommandOutcome(ok: false, errorCode: 'e', errorMessage: emojis),
    );
    server = bounded;
    await bounded.start(preferredPort: 0);
    final cut = await _post(bounded);
    expect(
      cut.body.contains('"message":"ااا"'),
      isTrue,
      reason: 'the cut lands exactly at the second emoji - neither emoji '
          'is split, the whole character is dropped instead',
    );
    server.stop();
    // والقصيرة تعبر بمحارفها كلها ما دامت بايتاتها تحت السقف
    final shortServer = _server(
      config: const BridgeConfig(maxErrorMessageLength: 12),
      onCommand: (cmd) async => const CommandOutcome(
        ok: false,
        errorCode: 'e',
        errorMessage: 'أهلاً',
      ),
    );
    server = shortServer;
    await shortServer.start(preferredPort: 0);
    final small = await _post(shortServer);
    expect(
      small.body.contains('أهلاً'),
      isTrue,
      reason: 'ten bytes of a five-character message sit under the cap - '
          'delivered verbatim',
    );
    server.stop();
    // والسالب يبقى خطأ بناء لا خياراً صامتاً
    expect(
      () => _server(config: const BridgeConfig(maxErrorMessageLength: -1)),
      throwsArgumentError,
      reason: 'a negative cap is a configuration mistake - the standing '
          'construction-time refusal unchanged',
    );
  });

  // ── خيار الجسم الثنائي ──────────────────────────────────────────────

  test('binary off: application/octet-stream refuses 415 and the '
      'preflight never offers X-Command', () async {
    final seen = <List<String>>[];
    final binaries = <Uint8List?>[];
    server = _server(
      onCommand: (cmd) async {
        seen.add(cmd.payloads);
        binaries.add(cmd.binaryPayload);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    final res = await _post(
      server,
      body: <int>[0xFF, 0x00, 0xFE, 0x01],
      contentType: 'application/octet-stream',
    );
    expect(res.status, 415, reason: 'the default wire refuses the binary type');
    expect(res.body, contains('"error":"unsupported_media_type"'));
    final pre = await _preflight(server);
    final offered = pre.headers.value('Access-Control-Allow-Headers') ?? '';
    expect(
      offered.contains('X-Command'),
      isFalse,
      reason: 'the disarmed allow-header list is letter-identical',
    );
    expect(seen, isEmpty);
    expect(binaries.whereType<Uint8List>(), isEmpty);
  });

  test('binary on: octet-stream bytes reach the handler exactly, payloads '
      'stay empty, and X-Command rides the command headers and the '
      'preflight list', () async {
    final seen = <TrustedCommand>[];
    server = _server(
      config: const BridgeConfig(acceptBinaryBodies: true),
      onCommand: (cmd) async {
        seen.add(cmd);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    // بايتات غير UTF-8 عمدا: الجسم الثنائي لا يمر بفك نص إطلاقاً
    final bytes = <int>[0xFF, 0x00, 0xFE, 0x01, 0x50, 0x4B];
    final res = await _post(
      server,
      body: bytes,
      contentType: 'application/octet-stream',
      headers: {'X-Command': 'print-label'},
    );
    expect(res.status, 200, reason: 'the armed wire admits the binary type');
    final cmd = seen.single;
    expect(
      cmd.binaryPayload,
      isNotNull,
      reason: 'the handler receives the bytes',
    );
    expect(cmd.binaryPayload, Uint8List.fromList(bytes));
    expect(
      cmd.payloads,
      isEmpty,
      reason: 'a binary body is never JSON-parsed - payloads stay empty',
    );
    expect(
      cmd.headers['x-command'],
      'print-label',
      reason: 'the command name rides the X-Command header',
    );
    final pre = await _preflight(server);
    final offered = pre.headers.value('Access-Control-Allow-Headers') ?? '';
    expect(
      offered.contains('X-Command'),
      isTrue,
      reason: 'the armed list announces X-Command so the browser may send it',
    );
  });

  test('binary on: an unnamed binary body refuses 400 command_required - '
      'the empty body included and a blank name alike', () async {
    final seen = <TrustedCommand>[];
    server = _server(
      config: const BridgeConfig(acceptBinaryBodies: true),
      onCommand: (cmd) async {
        seen.add(cmd);
        return const CommandOutcome(ok: true);
      },
    );
    await server.start(preferredPort: 0);
    // جسم غير فارغ بلا اسم: بايتات لا أحد يعرف لأي أمر أُرسلت فلا تُسلَّم
    final unnamed = await _post(
      server,
      body: <int>[0xFF, 0x00, 0xFE, 0x01],
      contentType: 'application/octet-stream',
    );
    expect(
      unnamed.status,
      400,
      reason: 'an unnamed binary body is a wire-shape refusal',
    );
    expect(unnamed.body, contains('"error":"command_required"'));
    // الجسم الفارغ بلا اسم يحمل القرار نفسه: قاعدة واحدة بلا استثناء
    // حجم — النص الخام الفارغ أخوته الحزمة تردّه empty_payload، فالثنائي
    // الفارغ بلا اسم يسلك قرارَ «لا أمر يُسلَّم» ذاته
    final empty = await _post(
      server,
      body: <int>[],
      contentType: 'application/octet-stream',
    );
    expect(
      empty.status,
      400,
      reason:
          'an empty binary body names no command either - one rule, no '
          'size carve-out',
    );
    expect(empty.body, contains('"error":"command_required"'));
    // الاسم الأعمى (فراغات حصراً) لا يسمي: قرارُه قرارُ الغياب
    final blank = await _post(
      server,
      body: <int>[0x50, 0x4B],
      contentType: 'application/octet-stream',
      headers: {'X-Command': '   '},
    );
    expect(blank.status, 400, reason: 'a blank name names nothing');
    expect(blank.body, contains('"error":"command_required"'));
    expect(seen, isEmpty, reason: 'no unnamed body reaches the handler');
  });

  test('binary on: a body over the internal ceiling refuses 413 '
      'payload_too_large naming the binary cap, while JSON still serves '
      'and exotic types still refuse 415', () async {
    server = _server(config: const BridgeConfig(acceptBinaryBodies: true));
    await server.start(preferredPort: 0);
    final overCeiling = Uint8List(64 * 1024 * 4 + 1); // 256 KiB + 1
    final res = await _post(
      server,
      body: overCeiling,
      contentType: 'application/octet-stream',
    );
    expect(res.status, 413, reason: 'the internal ceiling is a hard one');
    expect(res.body, contains('"error":"payload_too_large"'));
    expect(
      res.body.contains('256 KiB'),
      isTrue,
      reason: 'the binary ceiling is named on the wire, not the byte cap',
    );
    final json = await _post(server);
    expect(json.status, 200, reason: 'the JSON path is untouched');
    final exotic = await _post(
      server,
      body: '<a/>',
      contentType: 'application/xml',
    );
    expect(
      exotic.status,
      415,
      reason: 'only octet-stream joins the admitted types',
    );
  });
}
