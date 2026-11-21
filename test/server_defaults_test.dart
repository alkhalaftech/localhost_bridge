// شواهد الافتراضيات الجديدة: خادم بُني بلا telemetry ولا مولّد معرّفات
// يُبنى ويبدأ ويخدم أمراً حقيقياً على السلك، ومعرّف الارتباط الداخلي يولد
// لكل طلب معرّفاً غير فارغ فريداً وتُكرَّم معرّفات الوارد حرفاً، ورفض
// السلك القائم على الشكل نفسه، والطباعة الافتراضية (PrintTelemetry)
// بديلة صامتة السلوك لا تلمس عقد الرد.
// عناوين إنجليزية (حزمة منشورة)؛ السلك عبر خادم حقيقي كامل.
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

Future<(int, String, Map<String, String>)> _post(
  int port, {
  String? token,
  String? correlationId,
}) async {
  final client = HttpClient();
  try {
    final req = await client.post('127.0.0.1', port, '/');
    if (token != null) req.headers.set('X-Bridge-Token', token);
    if (correlationId != null) {
      req.headers.set('X-Correlation-Id', correlationId);
    }
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close().timeout(const Duration(seconds: 8));
    final text = await res.transform(utf8.decoder).join();
    final flat = <String, String>{};
    res.headers.forEach((name, values) {
      flat[name.toLowerCase()] = values.join(', ');
    });
    return (res.statusCode, text, flat);
  } finally {
    client.close(force: true);
  }
}

void main() {
  test('a server built with no telemetry and no id generator starts and serves '
      'a real command', () async {
    // لا telemetry ولا correlationIdGenerator: الاثنان على افتراضيهما
    // الجديدين — البناء نفسه إثبات أن المضيف لا يلزمه تمرير شيء
    final server = LocalIntakeServer(
      onCommand: (cmd) async =>
          CommandOutcome(ok: true, data: [cmd.correlationId]),
      protection: IntakeProtection()..update(token: _t64),
    );
    final port = await server.start(preferredPort: 0);
    try {
      final (status, body, _) = await _post(port, token: _t64);
      expect(status, 200);
      // عقد الرد كما هو حرفاً: ok مع data، والمعرّف الداخلي غير فارغ
      expect(body, contains('"ok":true'));
      final decoded = jsonDecode(body) as Map<String, dynamic>;
      final data = decoded['data'] as List<dynamic>;
      expect(data, hasLength(1));
      expect((data.single as String).isNotEmpty, isTrue);
    } finally {
      await server.stop();
    }
  });

  test('the internal id generator yields a fresh unique id per request and '
      'the incoming id is honored verbatim', () async {
    final seen = <String>{};
    final server = LocalIntakeServer(
      onCommand: (cmd) async =>
          CommandOutcome(ok: true, data: [cmd.correlationId]),
      protection: IntakeProtection()..update(token: _t64),
    );
    final port = await server.start(preferredPort: 0);
    try {
      for (var i = 0; i < 3; i++) {
        final (status, body, _) = await _post(port, token: _t64);
        expect(status, 200);
        final decoded = jsonDecode(body) as Map<String, dynamic>;
        final id = (decoded['data'] as List<dynamic>).single as String;
        expect(id.isEmpty, isFalse);
        seen.add(id);
      }
      // ثلاثة طلبات بلا معرّف وارد = ثلاثة معرّفات فريدة من المولّد
      expect(seen, hasLength(3));
      // المعرّف الوارد يُكرم حرفاً ولا يمر من المولّد
      final (cidStatus, cidBody, _) = await _post(
        port,
        token: _t64,
        correlationId: 'caller-id-42',
      );
      expect(cidStatus, 200);
      final cidDecoded = jsonDecode(cidBody) as Map<String, dynamic>;
      expect((cidDecoded['data'] as List<dynamic>).single, 'caller-id-42');
    } finally {
      await server.stop();
    }
  });

  test('the default-built server keeps the standing refusal wire letter '
      'identical', () async {
    final server = LocalIntakeServer(
      onCommand: (cmd) async => const CommandOutcome(ok: true),
      protection: IntakeProtection()..update(token: _t64),
    );
    final port = await server.start(preferredPort: 0);
    try {
      // حامل توكن خاطئ على أرض مغلقة يُرد برمز الأصل على شكله القائم
      final (status, body, headers) = await _post(port, token: 'WRONG-');
      expect(status, 403);
      expect(body, contains('"ok":false'));
      expect(body, contains('"error":"origin_not_listed"'));
      expect(headers['content-type'], contains('application/json'));
    } finally {
      await server.stop();
    }
  });

  test('the printing default carries the same interface and never drops the '
      'measured value', () async {
    // الطباعة الافتراضية هي تطبيع SilentTelemetry: نفس الواجهة، والقياس
    // يعيد قيمة الجسد كما هي — السلوك بلا أي تغيير، والكتابة الفعلية
    // على stdout/stderr يشهدها الأمر التجريبي الحي (demo_command_test)
    const t = PrintTelemetry();
    final measured = await t.measure<int>('label', () async => 7);
    expect(measured, 7);
    // const constructor: مشاركة النسخة const ممكنة كالصامتة
    expect(identical(t, const PrintTelemetry()), isTrue);
  });
}
