// The local pages: the host passes pages from memory (path, content,
// content type) and the bridge serves them over GET on those paths only,
// behind the standing host-authority gate, carrying the page's security
// headers. The page's own origin - the bridge's bound loopback origin -
// crosses the admission on its own explicit path, never through the
// allow-all path, while any other loopback origin stays refused exactly
// like before. The option is off by default: the disarmed wire is letter
// identical (every GET still answers 405).
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

/// The strict CSP the bridge serves every page with - pinned verbatim so a
/// loosening edit fails the witness instead of sliding through.
const _pageCsp =
    "default-src 'none'; script-src 'unsafe-inline'; style-src "
    "'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action "
    "'none'; frame-ancestors 'none'";

class Rig {
  late final LocalIntakeServer srv;
  late final IntakeProtection protection;
  final commands = <TrustedCommand>[];
}

Future<Rig> rig({
  BridgeConfig? config,
  OriginPolicy policy = const OriginPolicy(),
  String? token,
  void Function(IntakeProtection protection)? armProtection,
}) async {
  final r = Rig();
  r.protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(policy: policy, token: token);
  armProtection?.call(r.protection);
  r.srv = LocalIntakeServer(
    onCommand: (cmd) async {
      r.commands.add(cmd);
      return const CommandOutcome(ok: true);
    },
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () => 'lp-1',
    protection: r.protection,
    config: config ?? const BridgeConfig(),
  );
  await r.srv.start(preferredPort: 0);
  return r;
}

/// A GET request read to the end - status line facts plus the body text.
Future<(HttpClientResponse, String)> get(
  int port,
  String path, {
  String? host,
  String? origin,
  String method = 'GET',
}) async {
  final client = HttpClient();
  final req = await client.openUrl(
    method,
    Uri.parse('http://127.0.0.1:$port$path'),
  );
  if (host != null) req.headers.set(HttpHeaders.hostHeader, host);
  if (origin != null) req.headers.set('Origin', origin);
  final resp = await req.close().timeout(const Duration(seconds: 8));
  final body = await resp.transform(utf8.decoder).join();
  client.close(force: true);
  return (resp, body);
}

// نص التوثيق بعد طيّ كل الفراغات إلى مسافة واحدة: الحكم على النص لا على
// إخراج السطر
String _flattened(String path) =>
    File(path).readAsStringSync().replaceAll(RegExp(r'\s+'), ' ');

/// A POST command the way the served page sends it: fetch-shaped headers
/// (Sec-Fetch cors/empty) with a JSON body on the command root.
Future<(int status, Map<String, Object?> json, Map<String, String> headers)>
postCommand(
  int port, {
  required String origin,
  String path = '/',
  String body = '["PING"]',
}) async {
  final client = HttpClient();
  final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port$path'));
  req.headers.set('Origin', origin);
  req.headers.set('Sec-Fetch-Mode', 'cors');
  req.headers.set('Sec-Fetch-Dest', 'empty');
  req.headers.contentType = ContentType.json;
  req.write(body);
  final resp = await req.close().timeout(const Duration(seconds: 8));
  final text = await resp.transform(utf8.decoder).join();
  final headers = <String, String>{};
  resp.headers.forEach(
    (name, values) => headers[name.toLowerCase()] = values.first,
  );
  client.close(force: true);
  return (resp.statusCode, jsonDecode(text) as Map<String, Object?>, headers);
}

void main() {
  // ── الشاهد الأول: الصفحة تُخدم بترويساتها، وGET لمسار آخر يُرد 405 ──
  test('the registered page answers GET with its content, its declared '
      'type, and the page security headers', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [
          BridgeLocalPage(
            path: '/ui',
            content: '<html><body>PAIR:123456</body></html>',
          ),
        ],
      ),
    );
    addTearDown(r.srv.stop);
    final (resp, body) = await get(r.srv.port, '/ui');
    expect(resp.statusCode, 200);
    // المحتوى حرفاً من الذاكرة لا من أي مكان آخر
    expect(body, '<html><body>PAIR:123456</body></html>');
    // النوع المعلن كما مرّره المضيف
    expect(resp.headers.contentType?.toString(), 'text/html; charset=utf-8');
    // ترويسات الأمن الثلاث على الصفحة بالقيم الحرفية
    expect(resp.headers.value('content-security-policy'), _pageCsp);
    expect(resp.headers.value('x-frame-options'), 'DENY');
    expect(resp.headers.value('referrer-policy'), 'no-referrer');
    expect(resp.headers.value('x-content-type-options'), 'nosniff');
    // والصفحة ليست قابلة للقراءة العابرة للأصل: لا صدى CORS عليها
    expect(resp.headers.value('access-control-allow-origin'), isNull);
  });

  test('GET on any other path answers 405 method_not_allowed while the '
      'pages option is armed', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    final (resp, body) = await get(r.srv.port, '/other');
    expect(resp.statusCode, 405);
    expect(body, contains('"error":"method_not_allowed"'));
    // والجذر يبقى 405 كيما هو: المسارات المسجلة وحدها تجيب الصفحة
    final (rootResp, rootBody) = await get(r.srv.port, '/');
    expect(rootResp.statusCode, 405);
    expect(rootBody, contains('"error":"method_not_allowed"'));
  });

  test('the disarmed wire is letter identical: GET on a would-be page '
      'path answers 405 while the option is off', () async {
    final r = await rig();
    addTearDown(r.srv.stop);
    final (resp, body) = await get(r.srv.port, '/ui');
    expect(resp.statusCode, 405);
    expect(body, contains('"error":"method_not_allowed"'));
    // ولا ترويسات الصفحة على رد 405: CSP وno-referrer مني وحدي فتغيب،
    // وx-frame-options افتراضي dart:io القائم (SAMEORIGIN) لا DENY
    expect(resp.headers.value('content-security-policy'), isNull);
    expect(resp.headers.value('x-frame-options'), isNot('DENY'));
    expect(resp.headers.value('referrer-policy'), isNull);
  });

  test('the page reply is written on the detached socket: explicit '
      'content length, no chunked framing, connection close', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [
          BridgeLocalPage(path: '/ui', content: '<html>fine</html>'),
        ],
      ),
    );
    addTearDown(r.srv.stop);
    final socket = await Socket.connect('127.0.0.1', r.srv.port);
    addTearDown(socket.destroy);
    final buffer = BytesBuilder();
    final closed = Completer<void>();
    late final StreamSubscription<List<int>> sub;
    sub = socket.listen(
      (data) => buffer.add(data),
      onDone: () {
        if (!closed.isCompleted) closed.complete();
      },
      onError: (Object _) {
        if (!closed.isCompleted) closed.complete();
      },
    );
    socket.write('GET /ui HTTP/1.1\r\nHost: 127.0.0.1:${r.srv.port}\r\n\r\n');
    await socket.flush();
    await closed.future.timeout(const Duration(seconds: 8));
    await sub.cancel();
    final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
    expect(text.split('\r\n').first, contains(' 200 '));
    // تأطيرية الطول الفعلي لا الترقية — رد المقبس المنتزع بنمط بقية
    // الردود المبكرة
    expect(text, contains('content-length: 17'));
    expect(text.toLowerCase(), isNot(contains('transfer-encoding')));
    expect(text, contains('connection: close'));
    final headEnd = text.indexOf('\r\n\r\n');
    expect(text.substring(headEnd + 4), '<html>fine</html>');
  });

  test('HEAD on a registered page path stays 405 - the pages answer GET '
      'alone', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    final (resp, _) = await get(r.srv.port, '/ui', method: 'HEAD');
    expect(resp.statusCode, 405);
  });

  test('the page GET is not an admission decision: a foreign Origin on '
      'it still serves (navigation semantics) and settles nothing', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    final (resp, body) = await get(
      r.srv.port,
      '/ui',
      origin: 'https://unlisted.example',
    );
    expect(resp.statusCode, 200);
    expect(body, '<html></html>');
    // لا قرار قبول يسوّى ولا أمر ينفذ: المشاهدة قراءة حرة
    expect(r.commands, isEmpty);
    expect(r.protection.rejectedCount, 0);
  });

  // ── الشاهد الثاني: طلب الصفحة إلى الجسر بمسار القبول الجديد، وغيره يُرفض ──
  test('a POST from the bridge\'s own served origin crosses the admission '
      'on the bridgeOrigin path', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    final port = r.srv.port;
    final (status, json, _) = await postCommand(
      port,
      origin: 'http://127.0.0.1:$port',
    );
    expect(status, 200);
    expect(json['ok'], true);
    // الأمر وصل المعالج بمسار القبول الجديد المسجل على أصل الجسر نفسه
    expect(r.commands, hasLength(1));
    expect(
      r.commands.single.admission.acceptedPath,
      IntakeAdmissionPath.bridgeOrigin,
    );
    // الأصل من ترويسة متصفح فدرجته ترويسة - السجل لا الرد يحملها
    expect(
      r.commands.single.admission.originTrust,
      OriginTrustLevel.browserHeader,
    );
  });

  test('a POST from another loopback origin (a different port) is refused '
      'exactly as before', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    final port = r.srv.port;
    final (status, json, headers) = await postCommand(
      port,
      origin: 'http://127.0.0.1:${port + 1}',
    );
    expect(status, 403);
    expect(json['error'], 'origin_not_listed');
    expect(r.commands, isEmpty);
    // ولا الصفحة المزورة على منفذ آخر ترى ACAO على رفضها
    expect(headers['access-control-allow-origin'], isNull);
  });

  test(
    'the localhost spelling of the served origin crosses the same way '
    '- the served set is both loopback spellings of the bound port',
    () async {
      final r = await rig(
        config: const BridgeConfig(
          localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
        ),
      );
      addTearDown(r.srv.stop);
      final (status, _, _) = await postCommand(
        r.srv.port,
        origin: 'http://localhost:${r.srv.port}',
      );
      expect(status, 200);
      expect(
        r.commands.single.admission.acceptedPath,
        IntakeAdmissionPath.bridgeOrigin,
      );
    },
  );

  test('the allow-all path never admits the page\'s origin: under '
      'allowAllHardened the served origin crosses on bridgeOrigin while '
      'another loopback origin rides allowAll', () async {
    final r = await rig(
      policy: const OriginPolicy(allowAllHardened: true, allowLocalHttp: true),
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    final port = r.srv.port;
    // أصل الجسر نفسه: بابه الصريح لا وضع الكل
    final (pageStatus, _, _) = await postCommand(
      port,
      origin: 'http://127.0.0.1:$port',
    );
    expect(pageStatus, 200);
    expect(
      r.commands.first.admission.acceptedPath,
      IntakeAdmissionPath.bridgeOrigin,
    );
    // وأصل loopback آخر: وضع الكل يعمل لغيره كما كان
    final (otherStatus, _, _) = await postCommand(
      port,
      origin: 'http://localhost:${port + 1}',
    );
    expect(otherStatus, 200);
    expect(
      r.commands.last.admission.acceptedPath,
      IntakeAdmissionPath.allowAll,
    );
  });

  test('the served origin\'s preflight is answered - the page can read '
      'the reply of its own fetch', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    final (resp, _) = await get(
      r.srv.port,
      '/',
      method: 'OPTIONS',
      origin: 'http://127.0.0.1:${r.srv.port}',
    );
    expect(resp.statusCode, 204);
    expect(
      resp.headers.value('access-control-allow-origin'),
      'http://127.0.0.1:${r.srv.port}',
    );
  });

  test('the served origin rides the listed quota: over it the honest 429 '
      'with Retry-After lands like any listed origin', () async {
    final r = await rig(
      policy: const OriginPolicy(listedPerOriginPerMinute: 2),
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    final origin = 'http://127.0.0.1:${r.srv.port}';
    final (first, _, _) = await postCommand(r.srv.port, origin: origin);
    final (second, _, _) = await postCommand(r.srv.port, origin: origin);
    expect(first, 200);
    expect(second, 200);
    final (third, json, headers) = await postCommand(
      r.srv.port,
      origin: origin,
    );
    expect(third, 429);
    expect(json['error'], 'origin_rate_limited');
    expect(headers['retry-after'], isNotNull);
  });

  test('the served origin is a real qualification: under '
      'requireOriginWithToken the page without a token reads the standing '
      'token_required, and with the pairing proof it pairs', () async {
    final r = await rig(
      policy: const OriginPolicy(requireOriginWithToken: true),
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
      armProtection: (p) => p.enablePairing(),
    );
    addTearDown(r.srv.stop);
    final origin = 'http://127.0.0.1:${r.srv.port}';
    final (bare, bareJson, _) = await postCommand(r.srv.port, origin: origin);
    expect(bare, 403);
    expect(bareJson['error'], 'token_required');
    // وتأهيل الاقتران نفسه: أصل الجسر المُخدم يؤهل للباب كالمدرج
    final offer = r.protection.startPairing();
    final client = HttpClient();
    final req = await client.postUrl(
      Uri.parse('http://127.0.0.1:${r.srv.port}/pair'),
    );
    req.headers.set('Origin', origin);
    req.headers.contentType = ContentType.json;
    req.write(jsonEncode({'pairingCode': offer.code}));
    final resp = await req.close().timeout(const Duration(seconds: 8));
    final text = await resp.transform(utf8.decoder).join();
    client.close(force: true);
    expect(resp.statusCode, 200);
    expect((jsonDecode(text) as Map<String, Object?>)['ok'], true);
  });

  // ── الشاهد الثالث: Host غير محلي على GET الصفحة يُرفض ──
  test('a non-local Host on a page GET is refused by the standing '
      'authority gate', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [
          BridgeLocalPage(path: '/ui', content: '<html>secret</html>'),
        ],
      ),
    );
    addTearDown(r.srv.stop);
    final (resp, body) = await get(r.srv.port, '/ui', host: 'evil.example');
    expect(resp.statusCode, 403);
    expect(body, contains('"error":"blocked_by_protection"'));
    // والمحتوى لم يُخدم ولا أمر وصل
    expect(body, isNot(contains('secret')));
    expect(r.commands, isEmpty);
  });

  // ── حدود التركيب: الصفحات على مستمع الجسر نفسه حصراً ──
  test('the pages answer on the bridge\'s own listener only: a forwarded '
      'GET on a mounted door answers 405 like any non-POST', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    addTearDown(r.srv.stop);
    // خادم مضيف حقيقي يمرر طلباته إلى باب التركيب
    final host = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final forwarded = StreamIterator<HttpRequest>(host);
    unawaited(
      host.forEach((request) async {
        await r.srv.handleHostRequest(request, hostPort: host.port);
      }),
    );
    addTearDown(host.close);
    final client = HttpClient();
    final req = await client.getUrl(
      Uri.parse('http://127.0.0.1:${host.port}/ui'),
    );
    final resp = await req.close().timeout(const Duration(seconds: 8));
    final body = await resp.transform(utf8.decoder).join();
    client.close(force: true);
    await forwarded.cancel();
    expect(resp.statusCode, 405);
    expect(body, contains('"error":"method_not_allowed"'));
    expect(r.commands, isEmpty);
  });

  test('a served page survives a restart on a new port: the served '
      'origins re-arm at bind', () async {
    final r = await rig(
      config: const BridgeConfig(
        localPages: [BridgeLocalPage(path: '/ui', content: '<html></html>')],
      ),
    );
    await r.srv.stop();
    final firstPort = r.srv.port;
    await r.srv.start(preferredPort: 0);
    addTearDown(r.srv.stop);
    final secondPort = r.srv.port;
    // المنفذ الجديد قد يساوي القديم بالصدفة - الفرعان صادقان على أي حال
    final (status, _, _) = await postCommand(
      secondPort,
      origin: 'http://127.0.0.1:$secondPort',
    );
    expect(status, 200);
    expect(
      r.commands.single.admission.acceptedPath,
      IntakeAdmissionPath.bridgeOrigin,
    );
    // وأصل الربط الأول لم يبق مؤهلاً بعد إحلال المجموعة
    if (secondPort != firstPort) {
      final (staleStatus, staleJson, _) = await postCommand(
        secondPort,
        origin: 'http://127.0.0.1:$firstPort',
      );
      expect(staleStatus, 403);
      expect(staleJson['error'], 'origin_not_listed');
    }
  });

  // ── أخطاء الإعداد صاخبة عند البناء لا رفض صامتة على السلك ──
  test(
    'page configuration mistakes throw ArgumentError at construction',
    () async {
      void expectThrows(BridgeConfig config) {
        expect(
          () => LocalIntakeServer(
            onCommand: (_) async => const CommandOutcome(ok: true),
            telemetry: const SilentTelemetry(),
            correlationIdGenerator: () => 'lp-1',
            config: config,
          ),
          throwsArgumentError,
        );
      }

      // القائمة الفارغة ليست وضع إيقاف - الإيقاف null حصراً
      expectThrows(const BridgeConfig(localPages: []));
      // المسار يجب أن يبدأ بشرطة مائلة
      expectThrows(
        const BridgeConfig(
          localPages: [BridgeLocalPage(path: 'ui', content: 'x')],
        ),
      );
      // مسار الاقتران محجوز
      expectThrows(
        const BridgeConfig(
          localPages: [BridgeLocalPage(path: '/pair', content: 'x')],
        ),
      );
      // مسار مكرر يبني طاولة غامضة
      expectThrows(
        const BridgeConfig(
          localPages: [
            BridgeLocalPage(path: '/ui', content: 'x'),
            BridgeLocalPage(path: '/ui', content: 'y'),
          ],
        ),
      );
      // نوع محتوى فارغ
      expectThrows(
        const BridgeConfig(
          localPages: [
            BridgeLocalPage(path: '/ui', content: 'x', contentType: ' '),
          ],
        ),
      );
      // وتصادم مسار قناة الويب سوكيت مع صفحة يُرفض كذلك
      expectThrows(
        const BridgeConfig(
          wsPath: '/ws',
          localPages: [BridgeLocalPage(path: '/ws', content: 'x')],
        ),
      );
    },
  );

  test('a plain non-browser GET with no Origin reads the page - the page '
      'is readable by every program on the device, so no secret belongs '
      'in it', () async {
    // الشاهد المفصّل لحقيقة القراءة: عميل غير متصفح (HttpClient لا يرسل
    // Origin ولا Sec-Fetch ولا ترويسة متصفح واحدة) يقرأ الصفحة بGET خالص
    // — فالصفحة سطح عرض مقروء لكل برنامج على الجهاز، ولهذا لا توضع فيها
    // رمز اقتران ولا توكن ولا أي سر: رمز الاقتران يُعرض بقناة المضيف
    // نفسها (شاشته أو طرفيته) حيث يراه الإنسان وحده
    final r = await rig(
      config: const BridgeConfig(
        localPages: [
          BridgeLocalPage(
            path: '/status',
            content:
                '<html><body><pre id="out">printer idle</pre></body></html>',
          ),
        ],
      ),
    );
    addTearDown(r.srv.stop);
    final (resp, body) = await get(r.srv.port, '/status');
    expect(resp.statusCode, 200, reason: 'the headerless GET crosses');
    expect(body, contains('printer idle'));
    expect(resp.headers.value('access-control-allow-origin'), isNull);
  });

  test('the docs state the page is device-readable and the local-page '
      'example carries no secret', () {
    // شاهد التوثيق: جملة السلامة بنسختي README وبSECURITY.md، ومثال
    // الصفحة في النسختين بلا رمز اقتران ولا أي رقم سري — أي تراجع في
    // النص أو عودة الرمز إلى المثال تسقط هذا الشاهد
    final readme = _flattened('README.md');
    final readmeAr = _flattened('README.ar.md');
    final security = _flattened('SECURITY.md');

    const statementEn =
        'no pairing code, no token, and no secret belong in a local page';
    expect(readme, contains(statementEn));
    expect(security, contains(statementEn));
    expect(readmeAr, contains('لا يوضع فيها رمز اقتران ولا توكن ولا أي سر'));

    for (final entry in <(String, String, String, String)>[
      (
        'README.md',
        '## The local pages (an optional page from memory)',
        '## The listeners, the lifecycle, and the health page',
        readme,
      ),
      (
        'README.ar.md',
        '## الصفحات المحلية (صفحة اختيارية من الذاكرة)',
        '## المستمعات ودورة الحياة وصفحة الصحة',
        readmeAr,
      ),
    ]) {
      final (name, start, end, doc) = entry;
      final i = doc.indexOf(start);
      expect(i, greaterThanOrEqualTo(0), reason: '$name names the section');
      final j = doc.indexOf(end, i + start.length);
      expect(j, greaterThan(i), reason: '$name closes the section');
      final section = doc.substring(i, j);
      expect(
        section,
        isNot(contains('Pairing code')),
        reason: '$name local-page example carries no pairing code',
      );
      expect(
        section,
        isNot(contains('رمز الاقتران:')),
        reason: '$name local-page example carries no pairing code',
      );
      expect(
        RegExp(r'\b\d{6}\b').hasMatch(section),
        isFalse,
        reason: '$name local-page example carries no secret-looking code',
      );
    }

    // امتداد التوثيق إلى واجهة lib: dartdoc الصنف نفسه لا يناقض إصلاح
    // الصفحة الخالية من الأسرار — سطح العرض الذي يصفه نص الواجهة هو
    // نص README وSECURITY ذاتهما، فلا يذكر رمز الاقتران سطحاً يُعرض
    final bridgeConfigSource = File(
      'lib/src/bridge_config.dart',
    ).readAsStringSync().replaceAll(RegExp(r'^\s*///\s?', multiLine: true), '');
    final pageDocStart = bridgeConfigSource.indexOf('One in-memory page');
    expect(
      pageDocStart,
      greaterThanOrEqualTo(0),
      reason: 'the BridgeLocalPage dartdoc names its contract',
    );
    final pageDocEnd = bridgeConfigSource.indexOf('class BridgeLocalPage');
    expect(pageDocEnd, greaterThan(pageDocStart));
    final pageDoc = bridgeConfigSource
        .substring(pageDocStart, pageDocEnd)
        .replaceAll(RegExp(r'\s+'), ' ');
    expect(
      pageDoc,
      isNot(contains('display surface: a pairing code')),
      reason:
          'the BridgeLocalPage interface doc never names a pairing '
          'code as the display surface',
    );
    expect(
      pageDoc,
      contains('no pairing code, no token, and no secret belong in it'),
      reason:
          'the BridgeLocalPage interface doc carries the same '
          'secret-free rule as the README and SECURITY.md',
    );
  });
}
