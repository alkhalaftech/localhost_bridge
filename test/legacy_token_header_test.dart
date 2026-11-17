// شاهد الاسم القديم في الترويسة: ترويسة X-Portal-Token لا تُقبل قبولاً
// — الطلب الذي يحملها وحدها يُعامل كطلب بلا توكن، ويكتب الجسر سطر
// تحذير مكبوحاً واحداً في النافذة يسمّي الاسم الجديد X-Bridge-Token
// فيعرف المطور سبب الرفض. وpreflight يعلن الاسم الجديد وحده، وسقف
// طول التوكن والترويسة المكررة يعملان على الاسم الجديد، ولا ذكر
// للاسم القديم باقي في lib عقد بوابات CI. الساعة المحقونة تحكم
// نافذة كبح التحذير فلا نوم ولا اعتماد على زمن الحائط.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart';

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

var _seq = 0;
String _cid() => 'lh-${_seq++}';

/// Unified raw-socket client: returns status, headers, and body.
Future<Map<String, Object>> _talk(
  int port,
  String raw, {
  Duration wait = const Duration(seconds: 8),
}) async {
  final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
  unawaited(socket.done.catchError((Object _) {}));
  final done = Completer<Map<String, Object>>();
  final chunks = <int>[];
  late final StreamSubscription sub;
  sub = socket.listen(
    (d) {
      chunks.addAll(d);
      final text = latin1.decode(chunks, allowInvalid: true);
      final sep = text.indexOf('\r\n\r\n');
      if (done.isCompleted || sep < 0) return;
      final head = text.substring(0, sep);
      final cl = RegExp(
        'content-length:\\s*(\\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      final need = cl == null ? 0 : int.parse(cl.group(1)!);
      final bodyText = text.substring(sep + 4);
      final hasCl = cl != null && bodyText.length >= need;
      if (hasCl || bodyText.endsWith('0\r\n\r\n')) {
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
          'status': int.parse(head.split(' ')[1]),
          'headers': headers,
          'body': bodyText,
        });
      }
    },
    onDone: () {
      if (!done.isCompleted) done.completeError('قطع قبل الرد');
    },
  );
  socket.write(raw);
  final r = await done.future.timeout(wait);
  await sub.cancel();
  socket.destroy();
  return r;
}

String _post(
  int port,
  String? origin, {
  String? bridgeToken,
  String? legacyToken,
  String body = '{"data":["x"]}',
}) {
  final h = StringBuffer()
    ..write('POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n');
  if (origin != null) h.write('Origin: $origin\r\n');
  if (bridgeToken != null) h.write('X-Bridge-Token: $bridgeToken\r\n');
  if (legacyToken != null) h.write('X-Portal-Token: $legacyToken\r\n');
  h.write('Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n');
  h.write('Content-Type: application/json\r\n');
  h.write('Content-Length: ${utf8.encode(body).length}\r\n\r\n');
  return '$h$body';
}

void main() {
  late _Rec rec;
  final clockMs = <int>[0];

  LocalIntakeServer make() {
    final pr = IntakeProtection(telemetry: rec)..update(token: _t64);
    return LocalIntakeServer(
      nowMs: () => clockMs.first,
      telemetry: rec,
      correlationIdGenerator: _cid,
      onCommand: (_) async => const CommandOutcome(ok: true),
      protection: pr,
    );
  }

  setUp(() {
    rec = _Rec();
    clockMs[0] = 0;
  });

  test('the legacy X-Portal-Token header is never a token: the request is '
      'tokenless and one muted warning names X-Bridge-Token', () async {
    final srv = make();
    final p = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // القيمة الصحيحة نفسها فوق الاسم القديم: لا قبول — الطلب بلا توكن
    // فيُجاب برفض السياسة المغلقة لا بالعبور
    final legacy = await _talk(
      p,
      _post(p, 'https://k.example', legacyToken: _t64),
    );
    expect(legacy['status'], 403);
    expect(bodyText(legacy), contains('origin_not_listed'));
    // سطر التحذير: واحد في النافذة ويحمّل الاسم الجديد الذي يفهم منه
    // المطور سبب الرفض
    final legacyWarns = rec.warns
        .where((w) => w.contains('X-Portal-Token'))
        .toList();
    expect(legacyWarns, hasLength(1));
    expect(legacyWarns.single, contains('X-Bridge-Token'));
    // فيض الاسم القديم داخل النافذة نفسها لا يكتب سطراً ثانياً
    for (var i = 0; i < 20; i++) {
      await _talk(p, _post(p, 'https://k.example', legacyToken: _t64));
    }
    expect(
      rec.warns.where((w) => w.contains('X-Portal-Token')),
      hasLength(1),
      reason: 'the warning is muted for the rest of the window',
    );
    // والسطر التالي بعد النافذة يحمل عدد المكتوم
    clockMs[0] += 1001;
    await _talk(p, _post(p, 'https://k.example', legacyToken: _t64));
    final after = rec.warns.where((w) => w.contains('X-Portal-Token'));
    expect(after, hasLength(2));
    expect(after.last, contains('+20 more suppressed'));
  });

  test(
    'the preflight announces X-Bridge-Token and never the legacy name',
    () async {
      final srv = make();
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final pre = await _talk(
        p,
        'OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
        'Origin: https://k.example\r\n'
        'Access-Control-Request-Method: POST\r\n'
        'Access-Control-Request-Headers: content-type, x-portal-token\r\n'
        'Content-Length: 0\r\n\r\n',
      );
      expect(pre['status'], 204);
      final h = pre['headers'] as Map<String, String>;
      expect(
        h['access-control-allow-headers'],
        'Content-Type, X-Bridge-Token, X-Correlation-Id',
        reason: 'the allowed-header list carries the new name alone',
      );
      expect(
        h['access-control-allow-headers'],
        isNot(contains('X-Portal-Token')),
      );
    },
  );

  test('token_too_long answers on the new header name', () async {
    final srv = make();
    final p = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final over = await _talk(
      p,
      _post(p, 'https://k.example', bridgeToken: 'x' * 1025),
    );
    expect(over['status'], 400);
    expect(bodyText(over), contains('token_too_long'));
    expect(bodyText(over), contains('X-Bridge-Token'));
    // والاسم القديم فوق السقف لا يمر ببوابة التوكن أصلاً: هو ليس توكناً
    final legacyOver = await _talk(
      p,
      _post(p, 'https://k.example', legacyToken: 'x' * 1025),
    );
    expect(legacyOver['status'], isNot(400));
    expect(bodyText(legacyOver), isNot(contains('token_too_long')));
  });

  test('a duplicated X-Bridge-Token answers duplicate_header', () async {
    final srv = make();
    final p = await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final raw =
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
        'Origin: https://k.example\r\n'
        'X-Bridge-Token: $_t64\r\nX-Bridge-Token: $_t64\r\n'
        'Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: ${utf8.encode('{"data":["x"]}').length}\r\n\r\n'
        '{"data":["x"]}';
    final dup = await _talk(p, raw);
    expect(dup['status'], 400);
    expect(bodyText(dup), contains('duplicate_header'));
    expect(bodyText(dup), contains('x-bridge-token'));
  });

  test('no legacy intake name survives in lib outside its rejection site', () {
    // عقد بوابات CI محلياً: المولّد والرمز القديمان صفرٌ في lib إطلاقاً،
    // واسم الترويسة القديم لا يظهر إلا في موضع رفضه الموثق الوحيد (كشف
    // الاسم المتقاعد وتحذيره في الخادم) — أي ظهور ثالث أو في ملف آخر
    // يعني عودة الاسم القديم واجهةً فيفشل الباب
    final generatorHits = <String>[];
    final legacyByFile = <String, int>{};
    const retiredHeader = 'X-Portal-Token';
    final pattern = RegExp('generatePortalToken|unknown-portal');
    for (final e in Directory('lib').listSync(recursive: true)) {
      if (e is! File || !e.path.endsWith('.dart')) continue;
      final lines = e.readAsLinesSync();
      for (var i = 0; i < lines.length; i++) {
        if (pattern.hasMatch(lines[i])) {
          generatorHits.add('${e.path}:${i + 1}');
        }
        if (lines[i].contains(retiredHeader)) {
          legacyByFile.update(e.path, (n) => n + 1, ifAbsent: () => 1);
        }
      }
    }
    expect(
      generatorHits,
      isEmpty,
      reason:
          'generatePortalToken and unknown-portal must stay removed: '
          '$generatorHits',
    );
    expect(
      legacyByFile.keys,
      [
        'lib${Platform.pathSeparator}src${Platform.pathSeparator}'
            'local_intake_server.dart',
      ],
      reason:
          'the retired header name may appear only in the server file '
          'that rejects it: $legacyByFile',
    );
    expect(
      legacyByFile.values.single,
      2,
      reason:
          'exactly the detection read and the warning text may carry '
          'the retired name — a third mention means it came back as an '
          'accepted interface',
    );
  });
}
