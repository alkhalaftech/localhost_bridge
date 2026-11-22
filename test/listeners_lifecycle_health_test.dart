// The listeners, the lifecycle, and the health page: the optional ::1
// listener widens the host authorities in the same start, the optional
// unix-socket listener serves local CLI clients behind owner-only file
// permissions, pause/resume rebind the remembered port (or refuse it with
// the named bind failure when another process took it), instance info
// carries the actual port, a stable instance id, and the protocol version,
// and the armed /health page passes the standing gate and answers the
// accepted origin alone with no version and no details. Every option is
// off by default: the disarmed wire is letter identical to previous
// releases (a GET /health still reads 405, the authority set keeps exactly
// the IPv4 loopback forms).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:localhost_bridge/src/intake_invariants.dart'
    show computeAuthorities;
import 'package:test/test.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

class Rig {
  late final LocalIntakeServer srv;
  late final IntakeProtection protection;
  final commands = <TrustedCommand>[];
}

Future<Rig> rig({
  BridgeConfig? config,
  OriginPolicy policy = const OriginPolicy(),
  String? token = _t64,
}) async {
  final r = Rig();
  r.protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(policy: policy, token: token);
  r.srv = LocalIntakeServer(
    onCommand: (cmd) async {
      r.commands.add(cmd);
      return const CommandOutcome(ok: true);
    },
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () => 'j18-1',
    protection: r.protection,
    config: config ?? const BridgeConfig(),
  );
  await r.srv.start(preferredPort: 0);
  return r;
}

/// A token-riding POST command the way a local CLI sends it: the shared
/// token, no Origin, no fetch metadata - the standing token path.
Future<(int status, Map<String, Object?> json, Map<String, String> headers)>
postCommand(
  String host,
  int port, {
  required String token,
  String path = '/',
}) async {
  final client = HttpClient();
  final req = await client.postUrl(Uri.parse('http://$host:$port$path'));
  if (token.isNotEmpty) req.headers.set('X-Bridge-Token', token);
  req.headers.contentType = ContentType.json;
  req.write('["PING"]');
  final resp = await req.close().timeout(const Duration(seconds: 10));
  final text = await resp.transform(utf8.decoder).join();
  final headers = <String, String>{};
  resp.headers.forEach(
    (name, values) => headers[name.toLowerCase()] = values.first,
  );
  client.close(force: true);
  return (resp.statusCode, jsonDecode(text) as Map<String, Object?>, headers);
}

/// A GET request read to the end, with a host/origin override so the
/// authority gate and the origin gate are exercised independently of the
/// dial address.
Future<(HttpClientResponse, String)> get(
  String host,
  int port,
  String path, {
  String? hostHeader,
  String? origin,
  String? token,
}) async {
  final client = HttpClient();
  final req = await client.openUrl('GET', Uri.parse('http://$host:$port$path'));
  if (hostHeader != null) req.headers.set(HttpHeaders.hostHeader, hostHeader);
  if (origin != null) req.headers.set('Origin', origin);
  if (origin != null) {
    req.headers.set('Sec-Fetch-Mode', 'cors');
    req.headers.set('Sec-Fetch-Dest', 'empty');
  }
  if (token != null) req.headers.set('X-Bridge-Token', token);
  final resp = await req.close().timeout(const Duration(seconds: 10));
  final body = await resp.transform(utf8.decoder).join();
  client.close(force: true);
  return (resp, body);
}

/// Decodes a chunked body the way any raw HTTP client must - the managed
/// close frames its reply as chunks (the same bytes a raw TCP client
/// reads; HttpClient decodes them transparently there).
String _decodeChunked(String body) {
  final out = StringBuffer();
  var i = 0;
  while (i < body.length) {
    final lineEnd = body.indexOf('\r\n', i);
    if (lineEnd < 0) break;
    final size = int.parse(body.substring(i, lineEnd), radix: 16);
    if (size == 0) break;
    out.write(body.substring(lineEnd + 2, lineEnd + 2 + size));
    i = lineEnd + 2 + size + 2;
  }
  return out.toString();
}

/// One raw HTTP POST over a connected unix socket - the CLI client shape:
/// the socket path is the transport fact, the request line is plain HTTP.
Future<(int status, Map<String, Object?> json)> unixCommand(
  String socketPath, {
  required String token,
}) async {
  final socket = await Socket.connect(
    InternetAddress(socketPath, type: InternetAddressType.unix),
    0,
  );
  final head =
      'POST / HTTP/1.1\r\n'
      'Host: localhost\r\n'
      'X-Bridge-Token: $token\r\n'
      'Content-Type: application/json\r\n'
      'Content-Length: 8\r\n'
      'Connection: close\r\n\r\n["PING"]';
  socket.add(utf8.encode(head));
  await socket.flush();
  final reply = await utf8.decoder
      .bind(socket)
      .join()
      .timeout(const Duration(seconds: 10));
  socket.destroy();
  final headerBlock = reply.indexOf('\r\n\r\n');
  final statusLine = reply.split('\r\n').first;
  final status = int.parse(statusLine.split(' ')[1]);
  final headers = reply.substring(0, headerBlock).toLowerCase();
  final rawBody = reply.substring(headerBlock + 4);
  final body = headers.contains('transfer-encoding: chunked')
      ? _decodeChunked(rawBody)
      : rawBody;
  final json = jsonDecode(body) as Map<String, Object?>;
  return (status, json);
}

bool get _isPosix => Platform.isLinux || Platform.isMacOS;

/// A unique socket path inside a fresh temp directory; the caller owns the
/// cleanup through the returned directory. The path is a file inside the
/// directory - the socket path is never the directory itself.
Future<(String, Directory)> _unixPaths() async {
  final dir = await Directory.systemTemp.createTemp('lb-j18-sock-');
  // عقد النشر الحقيقي: المجلد الحامل للمقبس للمالك وحده — والخدمة ترفض
  // غير ذلك صاخباً باسم المجلد (شاهد المجلد المتساهل أدناه)، فالخدمة
  // هنا تهيئ مجلدها بالعقد نفسه. المجلد المؤقت قد يولد 0755 لا 0700
  // باختلاف المنصة فيجب التضييق الصريح
  await Process.run('/bin/chmod', <String>['700', dir.path]);
  return ('${dir.path}/bridge.sock', dir);
}

void main() {
  // ── شاهد الـ::1: المستمع الاختياري يخدم ويعيد الربط، والسلطات تتوسع ──
  test('the optional ::1 listener serves commands and rebinds with the '
      'IPv4 listener on a fresh start', () async {
    final r = await rig(config: const BridgeConfig(listenIPv6Loopback: true));
    addTearDown(r.srv.stop);
    final port = r.srv.port;
    final (status4, json4, _) = await postCommand(
      '127.0.0.1',
      port,
      token: _t64,
    );
    expect(status4, 200, reason: 'the standing IPv4 listener keeps its course');
    expect(json4['ok'], isTrue);
    final (status6, json6, _) = await postCommand('[::1]', port, token: _t64);
    expect(status6, 200, reason: 'the armed ::1 listener serves the same wire');
    expect(json6['ok'], isTrue);
    // إعادة الربط: stop ثم start من جديد يخدم العنوين معا
    await r.srv.stop();
    expect(r.srv.isListening, isFalse);
    final rebound = await r.srv.start(preferredPort: port);
    expect(rebound, port);
    final (status4b, _, _) = await postCommand('127.0.0.1', port, token: _t64);
    expect(status4b, 200, reason: 'the IPv4 address rebinds');
    final (status6b, _, _) = await postCommand('[::1]', port, token: _t64);
    expect(status6b, 200, reason: 'the ::1 address rebinds');
  });

  test('arming the ::1 listener widens the Host authorities in the same '
      'start - [::1]:port is an authority only then', () async {
    final r = await rig(config: const BridgeConfig(listenIPv6Loopback: true));
    addTearDown(r.srv.stop);
    final port = r.srv.port;
    final (status, _, _) = await postCommand('127.0.0.1', port, token: _t64);
    expect(status, 200);
    // Host بصيغة الـIPv6 يمرّ وهو مسلح: الطلب يعبر بوابة السلطة ويصل
    // بوابة الطريقة (405 كأي GET) — أما غير المحلي فيُرد 403 قبلهما
    final (v6hostResp, _) = await get(
      '127.0.0.1',
      port,
      '/',
      hostHeader: '[::1]:$port',
    );
    expect(
      v6hostResp.statusCode,
      405,
      reason:
          'the armed ::1 listener adds its Host forms to the same '
          'authority set - the request crosses the authority gate and '
          'reads the standing method gate, not the 403 refusal',
    );
    await r.srv.stop();
    // مطفأً المجموعة تبقى حرفا كما هي: Host بذاته يُرد 403
    final off = await rig();
    addTearDown(off.srv.stop);
    final (refusedResp, refusedBody) = await get(
      '127.0.0.1',
      off.srv.port,
      '/',
      hostHeader: '[::1]:${off.srv.port}',
    );
    expect(refusedResp.statusCode, 403);
    expect(refusedBody, contains('"error":"blocked_by_protection"'));
  });

  test('computeAuthorities keeps the IPv4 forms and adds the ::1 forms '
      'exactly when asked', () {
    final off = computeAuthorities(9200, const []);
    expect(off.contains('[::1]:9200'), isFalse);
    expect(off.contains('::1'), isFalse);
    expect(off.length, 4);
    final on = computeAuthorities(9200, const [], ipv6Loopback: true);
    expect(on.contains('[::1]:9200'), isTrue);
    expect(on.contains('::1'), isTrue);
    expect(on.contains('127.0.0.1:9200'), isTrue);
    expect(on.contains('localhost:9200'), isTrue);
    expect(on.contains('127.0.0.1'), isTrue);
    expect(on.contains('localhost'), isTrue);
    expect(on.length, 6);
  });

  // ── شاهد الـUnix socket: الطلب يُخدم والملف بصلاحيات المالك وحده ──
  test('the optional unix-socket listener serves a local CLI client and '
      'the socket file carries owner-only permissions', () async {
    if (!_isPosix) {
      return; // unix sockets are a Linux/macOS fact; the live witness runs there
    }
    final (sockPath, dir) = await _unixPaths();
    addTearDown(() async {
      try {
        await dir.delete(recursive: true);
      } on Object {
        // cleanup best-effort: the socket file is the package's job
      }
    });
    final r = await rig(
      policy: const OriginPolicy(requireFetchMetadata: false),
      config: BridgeConfig(unixSocketPath: sockPath),
    );
    addTearDown(r.srv.stop);
    final (status, json) = await unixCommand(sockPath, token: _t64);
    expect(status, 200, reason: 'the unix listener serves the standing wire');
    expect(json['ok'], isTrue);
    // صلاحيات الملف: مقبس مجال يونكس بصلاحيات المالك وحده
    final stat = File(sockPath).statSync();
    expect(stat.type, FileSystemEntityType.unixDomainSock);
    // ‏0x3F = بتات المجموعة والآخرون في صيغة posix الصلاحية
    expect(
      stat.mode & 0x3F,
      0,
      reason:
          'group and other carry no permission bits - the file '
          'permission is the boundary',
    );
    // إعادة الربط على المسار نفسه بعد stop (الملف رُفع عند الإيقاف)
    await r.srv.stop();
    final gone = File(sockPath).statSync().type;
    expect(
      gone,
      FileSystemEntityType.notFound,
      reason: 'the socket file the package created is removed at stop',
    );
    final rebound = await r.srv.start(preferredPort: 0);
    expect(rebound, greaterThan(0));
    final (status2, json2) = await unixCommand(sockPath, token: _t64);
    expect(status2, 200);
    expect(json2['ok'], isTrue);
  });

  test('an occupied unix-socket path refuses the whole start and leaves '
      'nothing bound', () async {
    if (!_isPosix) {
      return; // unix sockets are a Linux/macOS fact; the live witness runs there
    }
    final (sockPath, dir) = await _unixPaths();
    addTearDown(() async {
      try {
        await dir.delete(recursive: true);
      } on Object {
        // cleanup best-effort: the occupied file is the test's fixture
      }
    });
    // ملف عادي يحتل المسار: الربط يفشل والبدء كله يفشل صاخباً
    File(sockPath).writeAsStringSync('occupied');
    final r = Rig();
    r.protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(token: _t64);
    r.srv = LocalIntakeServer(
      onCommand: (_) async => const CommandOutcome(ok: true),
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'j18-2',
      protection: r.protection,
      config: BridgeConfig(unixSocketPath: sockPath),
    );
    await expectLater(
      r.srv.start(preferredPort: 0),
      throwsA(isA<IntakeBindException>()),
    );
    expect(
      r.srv.isListening,
      isFalse,
      reason:
          'a failed start leaves no '
          'half-bound listener - the IPv4 side closed with the unix failure',
    );
    expect(r.srv.port, 0);
  });

  test('a permissive parent directory fails the start closed naming the '
      'folder, and the tightened directory serves', () async {
    if (!_isPosix) {
      return; // unix sockets are a Linux/macOS fact; the live witness runs there
    }
    final (sockPath, dir) = await _unixPaths();
    addTearDown(() async {
      try {
        await dir.delete(recursive: true);
      } on Object {
        // cleanup best-effort
      }
    });
    // المجلد متساهل (للمجموعة والآخرين ركن): البدء كله يفشل فشلاً
    // مغلقاً والرسالة تسمي المجلد نفسه — لا مقبس يولد أصلاً في مكان
    // يعبره غير المالك، فنافذة الولادة قبل تضييق الملف سدّت
    await Process.run('/bin/chmod', <String>['755', dir.path]);
    expect(dir.statSync().mode & 0x3F, isNot(0));
    final refused = Rig();
    refused.protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(token: _t64);
    refused.srv = LocalIntakeServer(
      onCommand: (_) async => const CommandOutcome(ok: true),
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'fr4-permissive',
      protection: refused.protection,
      config: BridgeConfig(unixSocketPath: sockPath),
    );
    await expectLater(
      refused.srv.start(preferredPort: 0),
      throwsA(
        isA<IntakeBindException>().having(
          (e) => e.message,
          'message',
          contains(dir.path),
        ),
      ),
    );
    expect(
      refused.srv.isListening,
      isFalse,
      reason: 'the permissive parent closes the whole start',
    );
    expect(
      File(sockPath).statSync().type,
      FileSystemEntityType.notFound,
      reason: 'the refusal precedes the bind - no socket file exists',
    );

    // المجلد نفسه مضيَّقاً إلى المالك وحده: البدء يعمل ويخدم
    await Process.run('/bin/chmod', <String>['700', dir.path]);
    final serving = Rig();
    serving.protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(token: _t64);
    serving.srv = LocalIntakeServer(
      onCommand: (_) async => const CommandOutcome(ok: true),
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'fr4-tightened',
      protection: serving.protection,
      config: BridgeConfig(unixSocketPath: sockPath),
    );
    addTearDown(serving.srv.stop);
    final port = await serving.srv.start(preferredPort: 0);
    expect(port, greaterThan(0), reason: 'the owner-only parent serves');
    final (status, json) = await unixCommand(sockPath, token: _t64);
    expect(status, 200, reason: 'the tightened path serves the standing wire');
    expect(json['ok'], isTrue);
  });

  test('a missing /bin/chmod fails the start closed and the failure '
      'message names /bin/chmod', () async {
    if (!_isPosix) {
      return; // unix sockets are a Linux/macOS fact; the live witness runs there
    }
    // شاهد الأداة الغائبة: حين يتعذر تنفيذ /bin/chmod يفشل البدء كله
    // فشلاً مغلقاً والرسالة تسمّي الأداة نفسها كي يعرف المضيف الدواء —
    // لا مقبس بلا حاجز يخدم. البيئة التي يثبت فيها الشاهد هي التي قنّعت
    // الأداة فوق مسارها الثابت؛ وحيث تعمل الأداة لا سبيل لإفشال الحارس
    // فيُقال الصمت بصدق لا توهم إثباتاً
    final probeDir = await Directory.systemTemp.createTemp('lb-chmod-probe-');
    addTearDown(() async {
      try {
        await probeDir.delete(recursive: true);
      } on Object {
        // cleanup best-effort
      }
    });
    final probeFile = File('${probeDir.path}/probe');
    probeFile.writeAsStringSync('x');
    var chmodWorks = false;
    try {
      final probe = await Process.run('/bin/chmod', <String>[
        '600',
        probeFile.path,
      ]);
      chmodWorks = probe.exitCode == 0;
    } on Object {
      chmodWorks = false;
    }
    if (chmodWorks) {
      markTestSkipped(
        '/bin/chmod works here - the missing-tool refusal is proven only '
        'where the tool is masked above its fixed path',
      );
      return;
    }
    // تمهيد المقبس في مجلد ضيق سلفاً: الفحص الأب يقرأ الصلاحيات لا هوية
    // المالك، ومجلد المنزل في هذه البيئة ولد owner-only فيعبر الحاجز
    // الأول ويبلغ الحاجز الثاني حيث الأداة الغائبة هي الحكم
    Directory? parent;
    final homePath = Platform.environment['HOME'];
    if (homePath != null) {
      try {
        final home = Directory(homePath);
        final stat = home.statSync();
        if (stat.type == FileSystemEntityType.directory &&
            (stat.mode & 0x3F) == 0) {
          parent = home;
        }
      } on Object {
        parent = null;
      }
    }
    if (parent == null) {
      markTestSkipped(
        'no owner-only directory to stage the socket in - the '
        'missing-tool refusal cannot be staged here',
      );
      return;
    }
    final sockPath =
        '${parent.path}/lb-chmod-missing-${DateTime.now().microsecondsSinceEpoch}.sock';
    addTearDown(() async {
      try {
        await File(sockPath).delete();
      } on Object {
        // cleanup best-effort
      }
    });
    final srv = LocalIntakeServer(
      onCommand: (_) async => const CommandOutcome(ok: true),
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'chmod-missing',
      protection: IntakeProtection(telemetry: const SilentTelemetry())
        ..update(token: _t64),
      config: BridgeConfig(unixSocketPath: sockPath),
    );
    await expectLater(
      srv.start(preferredPort: 0),
      throwsA(
        isA<IntakeBindException>().having(
          (e) => e.message,
          'message',
          contains('/bin/chmod'),
        ),
      ),
    );
    expect(
      srv.isListening,
      isFalse,
      reason: 'the unguardable socket never serves',
    );
  });

  // ── شاهد pause/resume: المنفذ نفسه ومعرّف المثيل نفسه، أو رمز واضح ──
  test('resume rebinds the remembered port with the same instance id and '
      'serves again', () async {
    final r = await rig();
    addTearDown(r.srv.stop);
    final port = r.srv.port;
    final idBefore = r.srv.instanceId;
    final infoBefore = r.srv.instanceInfo;
    expect(infoBefore.port, port);
    expect(infoBefore.instanceId, idBefore);
    await r.srv.pause();
    expect(r.srv.isListening, isFalse);
    expect(r.srv.port, 0, reason: 'no bound port while paused');
    final resumedPort = await r.srv.resume();
    expect(
      resumedPort,
      port,
      reason:
          'resume rebinds the remembered port, '
          'never a fallback',
    );
    expect(
      r.srv.instanceId,
      idBefore,
      reason:
          'the instance id is the pinning identity - stable across '
          'pause/resume',
    );
    final (status, json, _) = await postCommand('127.0.0.1', port, token: _t64);
    expect(status, 200);
    expect(json['ok'], isTrue);
    expect(r.srv.instanceInfo.port, port);
  });

  test('resume with the port taken refuses with the named bind failure and '
      'keeps the pause state so the host can retry', () async {
    final r = await rig();
    addTearDown(r.srv.stop);
    final port = r.srv.port;
    final idBefore = r.srv.instanceId;
    await r.srv.pause();
    // منفذ مأخوذ: مقبس غريب يحتله قبل الاستئناف
    final occupier = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      port,
    );
    addTearDown(occupier.close);
    await expectLater(
      r.srv.resume(),
      throwsA(
        isA<IntakeBindException>().having(
          (e) => e.message,
          'message',
          allOf(contains('resume'), contains('$port'), contains('taken')),
        ),
      ),
      reason:
          'the refusal names the fact - the remembered port is held by '
          'another listener',
    );
    expect(r.srv.isListening, isFalse);
    expect(r.srv.instanceId, idBefore);
    // حالة الإيقاف باقية: تحرر الحاجز ثم الاستئناف ينجح على المنفذ نفسه
    await occupier.close();
    final resumed = await r.srv.resume();
    expect(resumed, port);
  });

  test('pause and resume refuse their impossible states loudly', () async {
    final r = await rig();
    addTearDown(r.srv.stop);
    // استئناف بلا إيقاف
    await expectLater(r.srv.resume(), throwsA(isA<StateError>()));
    // معلقاً مرتين
    await r.srv.pause();
    await expectLater(r.srv.pause(), throwsA(isA<StateError>()));
    await r.srv.resume();
    // إيقاف خادم غير مستمع (لم يبدأ أصلاً)
    final fresh = Rig();
    fresh.protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(token: _t64);
    fresh.srv = LocalIntakeServer(
      onCommand: (_) async => const CommandOutcome(ok: true),
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'j18-3',
      protection: fresh.protection,
    );
    await expectLater(fresh.srv.pause(), throwsA(isA<StateError>()));
    // معلقاً ثم start جديد: البدء ينسى المنفذ المحفوظ ويكون جيلاً جديداً
    await r.srv.pause();
    final newPort = await r.srv.start(preferredPort: 0);
    addTearDown(r.srv.stop);
    expect(newPort, greaterThan(0));
    await expectLater(
      r.srv.resume(),
      throwsA(isA<StateError>()),
      reason: 'start supersedes the pause - the remembered port is forgotten',
    );
  });

  test('instanceInfo carries the actual port, a stable random id, and the '
      'protocol version', () async {
    final a = await rig();
    addTearDown(a.srv.stop);
    final b = await rig();
    addTearDown(b.srv.stop);
    expect(a.srv.instanceId, hasLength(32));
    expect(
      RegExp(r'^[0-9a-f]{32}$').hasMatch(a.srv.instanceId),
      isTrue,
      reason: 'the pinning id is 128 bits of secure random, hex',
    );
    expect(
      a.srv.instanceId,
      isNot(b.srv.instanceId),
      reason: 'two instances are two identities',
    );
    expect(a.srv.instanceInfo.port, a.srv.port);
    expect(
      a.srv.instanceInfo.protocolVersion,
      BridgeInstanceInfo.bridgeProtocolVersion,
    );
    expect(BridgeInstanceInfo.bridgeProtocolVersion, isNotEmpty);
    await a.srv.pause();
    expect(
      () => a.srv.instanceInfo,
      throwsA(isA<StateError>()),
      reason: 'the actual port exists only while a listener is bound',
    );
    // ومعرّف المثيل يبقى مقروءاً وهو معلق - التثبيت لا ينتظر الاستئناف
    expect(a.srv.instanceId, hasLength(32));
  });

  // ── شاهد /health: البوابة نفسها، والأصل المقبول وحده، بلا رقم إصدار ──
  test('the armed health page answers the accepted origin with exactly '
      'ok - no version, no details', () async {
    final r = await rig(
      policy: const OriginPolicy(allowed: ['https://portal.example']),
      token: null,
      config: const BridgeConfig(healthPath: '/health'),
    );
    addTearDown(r.srv.stop);
    final (resp, body) = await get(
      '127.0.0.1',
      r.srv.port,
      '/health',
      origin: 'https://portal.example',
    );
    expect(resp.statusCode, 200);
    expect(
      body,
      '{"ok":true}',
      reason: 'the whole body - no version number, no counters, no details',
    );
    final headers = <String, String>{};
    resp.headers.forEach(
      (name, values) => headers[name.toLowerCase()] = values.first,
    );
    expect(
      headers['access-control-allow-origin'],
      'https://portal.example',
      reason: 'the accepted origin reads its answer',
    );
    // ومعرف الارتباط يخيطها ككل رد
    expect(headers['x-correlation-id'], isNotEmpty);
  });

  test('the health page from a non-accepted origin reads a refusal with no '
      'CORS echo - the browser never sees it', () async {
    final r = await rig(
      policy: const OriginPolicy(allowed: ['https://portal.example']),
      token: null,
      config: const BridgeConfig(healthPath: '/health'),
    );
    addTearDown(r.srv.stop);
    final (resp, body) = await get(
      '127.0.0.1',
      r.srv.port,
      '/health',
      origin: 'https://evil.example',
    );
    expect(resp.statusCode, 403);
    expect(body, contains('origin_not_listed'));
    final headerNames = <String>[];
    resp.headers.forEach((name, _) => headerNames.add(name.toLowerCase()));
    expect(
      headerNames.contains('access-control-allow-origin'),
      isFalse,
      reason:
          'no echo for the rejected - the browser hides the whole '
          'answer, so probing /health reveals nothing',
    );
    expect(body.contains('0.2.0'), isFalse);
  });

  test('the health page sits behind the standing gates: disarmed stays 405, '
      'a foreign Host stays 403, a mounted door stays 405', () async {
    // مطفأة: GET /health يبقى 405 حرفاً كما كان
    final off = await rig(token: null);
    addTearDown(off.srv.stop);
    final (offResp, offBody) = await get(
      '127.0.0.1',
      off.srv.port,
      '/health',
      origin: 'https://portal.example',
    );
    expect(offResp.statusCode, 405);
    expect(offBody, contains('method_not_allowed'));
    // مسلحة وHost غير محلي: بوابة السلطة فوق الصفحة
    final r = await rig(
      policy: const OriginPolicy(allowed: ['https://portal.example']),
      token: null,
      config: const BridgeConfig(healthPath: '/health'),
    );
    addTearDown(r.srv.stop);
    final (hostResp, hostBody) = await get(
      '127.0.0.1',
      r.srv.port,
      '/health',
      hostHeader: 'evil.example',
      origin: 'https://portal.example',
    );
    expect(hostResp.statusCode, 403);
    expect(hostBody, contains('blocked_by_protection'));
    // باب المضيف المركب: الصفحة تجيب على مستمع الجسر نفسه حصراً
    final host = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(host.close);
    late final StreamSubscription<HttpRequest> forwarded;
    forwarded = host.listen((request) {
      unawaited(
        r.srv
            .handleHostRequest(request, hostPort: host.port)
            .catchError((Object _, StackTrace _) {}),
      );
    });
    addTearDown(forwarded.cancel);
    final client = HttpClient();
    final req = await client.getUrl(
      Uri.parse('http://127.0.0.1:${host.port}/health'),
    );
    req.headers.set('Origin', 'https://portal.example');
    req.headers.set('Sec-Fetch-Mode', 'cors');
    req.headers.set('Sec-Fetch-Dest', 'empty');
    final resp = await req.close().timeout(const Duration(seconds: 10));
    final body = await resp.transform(utf8.decoder).join();
    client.close(force: true);
    await forwarded.cancel();
    expect(
      resp.statusCode,
      405,
      reason:
          'the health page answers on the bridge listener only - a '
          'mounted door keeps the standing 405 like any GET',
    );
    expect(body, contains('method_not_allowed'));
    expect(r.commands, isEmpty);
  });

  test(
    'a bad healthPath is a construction error, not a mystery on the wire',
    () {
      void expectBad(
        String? healthPath, {
        String? wsPath,
        List<BridgeLocalPage>? pages,
      }) {
        expect(
          () => LocalIntakeServer(
            onCommand: (_) async => const CommandOutcome(ok: true),
            telemetry: const SilentTelemetry(),
            correlationIdGenerator: () => 'j18-4',
            config: BridgeConfig(
              healthPath: healthPath,
              wsPath: wsPath,
              localPages: pages,
            ),
          ),
          throwsArgumentError,
        );
      }

      expectBad('');
      expectBad('health');
      expectBad('/');
      expectBad('/pair');
      expectBad('/ws', wsPath: '/ws');
      expectBad(
        '/ui',
        pages: [const BridgeLocalPage(path: '/ui', content: 'x')],
      );
      // والمسار الصالح يبني بلا صوت
      LocalIntakeServer(
        onCommand: (_) async => const CommandOutcome(ok: true),
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: () => 'j18-5',
        config: const BridgeConfig(healthPath: '/health'),
      ).config;
    },
  );

  test('a unix socket path is a Linux/macOS option - Windows refuses it at '
      'construction', () {
    if (!Platform.isWindows) {
      return; // the refusal is the Windows fact; the witness runs there
    }
    expect(
      () => LocalIntakeServer(
        onCommand: (_) async => const CommandOutcome(ok: true),
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: () => 'j18-6',
        config: const BridgeConfig(unixSocketPath: '/tmp/bridge.sock'),
      ),
      throwsArgumentError,
    );
    // والمسار الفارغ رفض إعداد في كل المنصات
    expect(
      () => LocalIntakeServer(
        onCommand: (_) async => const CommandOutcome(ok: true),
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: () => 'j18-7',
        config: const BridgeConfig(unixSocketPath: ''),
      ),
      throwsArgumentError,
    );
  });
}
