// شواهد مهلة اكتمال الترويسات في مسار القبول: العميل الذي ينقّط رأسه أو
// يرسله بالتقطيع يُقطع عند الحدّ قطعاً هادئاً على المقبس (بلا بايت ولا رد
// ولا رمز جديد)، على كل مستمع (العادي و::1 والآمن ومقبس يونكس). الحكم
// بمسبار العميل وحده بمقابس تحمل tcpNoDelay (لا Nagle يحتجب البايتات)،
// على مرحلتين: وصول نهاية الدفق داخل الحد المكتوب، ثم صمتُ البايتات
// قبله. والشاهد الرابع لا يقطع: طلب سليم بطيء معقول ترويساته تصل داخل
// الحد يُخدم كاملاً، والشاهد الثالث حارس عقد الخمول: اتصال مُبقى خامل
// بعد رد مكتمل يبقى مفتوحاً بعد مهلة الترويسات نفسها ويُغلق بحدَّي مهلة
// الخمول القائمة لا بقطعها. الشاهد الثالث والرابع حارسا ما كان قائماً
// فلا يحتملان الأحمر ببنية أطوار: الأولان يثبتان القطع الجديد.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/tls_cert.dart';

const _listed = 'https://portal.example';

// المهلة المحقونة للمشاهد: أقصر من هوامش الشهود كلها، والفعّالة هي
// أصغرها ومهلة الطلب (ثلاثين ثانية) = المهلة نفسها
const Duration _headerTimeout = Duration(milliseconds: 700);

// الحد النافذ كما يعلنه الخادم نفسه: القيمة المضبوطة عند البناء لا رقم
// مكتوب في الشاهد
Duration _bound(LocalIntakeServer srv) => srv.effectiveHeaderTimeout;

// مهلة الخمول المحقونة لشاهد عقد الخمول، وحدا شاهد الخمول القائم نفسه:
// سماحية تبكير المؤقت، وهامش تأخره فوق ضعف المهلة
const Duration _idle = Duration(seconds: 3);
const Duration _earlyTolerance = Duration(milliseconds: 50);
const Duration _lateMargin = Duration(seconds: 2);

// هامش وصول القطع بعد الحد (حمل المشغّل يؤخر المؤقت ولا يبكره)
const Duration _cutMargin = Duration(seconds: 2);

var _idSeq = 0;
String _cid() => 'header-deadline-${_idSeq++}';

class _Scene {
  const _Scene(this.name, {this.tls = false, this.v6 = false});
  final String name;
  final bool tls;
  final bool v6;
}

/// A unique socket path inside a fresh owner-only temp directory; the
/// caller owns the cleanup through the returned directory.
Future<(String, Directory)> _unixPaths() async {
  final dir = await Directory.systemTemp.createTemp('lb-h2-sock-');
  await Process.run('/bin/chmod', <String>['700', dir.path]);
  return ('${dir.path}/bridge.sock', dir);
}

BridgeConfig _config(_Scene scene, {Duration? idleTimeout}) => BridgeConfig(
  securityContext: scene.tls ? tlsContext() : null,
  listenIPv6Loopback: scene.v6,
  headerTimeout: _headerTimeout,
  idleTimeout: idleTimeout ?? const Duration(seconds: 60),
);

Future<LocalIntakeServer> _start(BridgeConfig config) async {
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: _cid,
    onCommand: (_) async => const CommandOutcome(ok: true),
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(policy: const OriginPolicy(allowed: [_listed])),
    config: config,
  );
  await srv.start(preferredPort: 0);
  return srv;
}

/// One connected raw client probe: it sends exactly the bytes it is given
/// (tcpNoDelay carries each write to the wire at once), collects the reply
/// bytes, and records the peer's close whenever it lands.
class _Link {
  _Link(this.socket) {
    unawaited(
      socket.done.catchError((Object _) {
        if (!_closed.isCompleted) _closed.complete();
      }),
    );
    socket.listen(
      (chunk) {
        _received += chunk.length;
        _buffer.add(chunk);
        _checkReply();
      },
      onDone: () {
        if (!_closed.isCompleted) _closed.complete();
      },
      onError: (Object _) {
        if (!_closed.isCompleted) _closed.complete();
      },
    );
  }

  final Socket socket;
  final _buffer = BytesBuilder(copy: true);
  final _answered = Completer<void>();
  final _closed = Completer<void>();
  int _received = 0;

  int get receivedBytes => _received;

  Future<void> get answeredFuture => _answered.future;

  static Future<_Link> connect(Socket socket, {required String host}) async {
    final set = socket.setOption(SocketOption.tcpNoDelay, true);
    if (!set) {
      throw StateError('the witness client could not disable Nagle');
    }
    return _Link(socket).._pendingHost = host;
  }

  String? _pendingHost;

  /// Sends one complete POST whose declared body may carry its first bytes.
  void sendPost({required int contentLength, List<int> firstBytes = const []}) {
    send([
      ...utf8.encode(
        'POST / HTTP/1.1\r\n'
        'Host: $_pendingHost\r\n'
        'Origin: $_listed\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: $contentLength\r\n'
        '\r\n',
      ),
      ...firstBytes,
    ]);
  }

  /// Sends raw bytes - the stalling header of a next request.
  void send(List<int> bytes) {
    try {
      socket.add(bytes);
    } on SocketException {
      // قطعه الخادم قبل هذه الكتابة: الإغلاق هو الحكم
    }
  }

  String get text => latin1.decode(_buffer.toBytes(), allowInvalid: true);

  String get statusLine => text.split('\r\n').first;

  void _checkReply() {
    if (_answered.isCompleted) return;
    final text = this.text;
    final sep = text.indexOf('\r\n\r\n');
    if (sep < 0) return;
    final m = RegExp(
      r'Content-Length:\s*(\d+)',
      caseSensitive: false,
    ).firstMatch(text.substring(0, sep));
    if (m == null) {
      if (text.endsWith('0\r\n\r\n')) _answered.complete();
      return;
    }
    if (text.length - (sep + 4) >= int.parse(m.group(1)!)) {
      _answered.complete();
    }
  }

  /// True when the server end of the stream arrived - end of stream or an
  /// error on it - within [bound]; false while it stays open.
  Future<bool> eofWithin(Duration bound) async {
    _checkReply();
    try {
      await _closed.future.timeout(bound);
      return true;
    } on TimeoutException {
      return false;
    }
  }

  void destroy() => socket.destroy();
}

/// A raw client that sends its header in paced writes - the slow but
/// legitimate sender whose headers arrive inside the deadline.
class _SlowClient {
  _SlowClient(this.socket) {
    socket.listen(
      (chunk) {
        _received += chunk.length;
        _buffer.add(chunk);
        _checkReply();
      },
      onDone: () {
        if (!_closed.isCompleted) _closed.complete();
      },
      onError: (Object _) {
        if (!_closed.isCompleted) _closed.complete();
      },
    );
  }

  final Socket socket;
  final _buffer = BytesBuilder(copy: true);
  final _answered = Completer<void>();
  final _closed = Completer<void>();
  int _received = 0;

  Future<void> get answeredFuture => _answered.future;
  Future<void> get closedFuture => _closed.future;
  int get receivedBytes => _received;

  void write(String piece) {
    try {
      socket.add(utf8.encode(piece));
    } on SocketException {
      // قطعه الخادم قبل هذه الكتابة
    }
  }

  String get text => latin1.decode(_buffer.toBytes(), allowInvalid: true);

  void _checkReply() {
    if (_answered.isCompleted) return;
    final text = this.text;
    final sep = text.indexOf('\r\n\r\n');
    if (sep < 0) return;
    final m = RegExp(
      r'Content-Length:\s*(\d+)',
      caseSensitive: false,
    ).firstMatch(text.substring(0, sep));
    if (m == null) {
      if (text.endsWith('0\r\n\r\n')) _answered.complete();
      return;
    }
    if (text.length - (sep + 4) >= int.parse(m.group(1)!)) {
      _answered.complete();
    }
  }

  void destroy() => socket.destroy();
}

/// One witness run: [clientSocket] builds a connected probe socket on the
/// listener under witness, and [host] is the authority header its listener
/// accepts.
typedef _WitnessBody =
    Future<void> Function({
      required LocalIntakeServer srv,
      required String host,
      required Future<Socket> Function() clientSocket,
    });

// الشاهد 1: رأس منقّط يُقطع في الحد قطعاً هادئاً.
Future<void> _witnessIncompleteHeaderCut({
  required LocalIntakeServer srv,
  required String host,
  required Future<Socket> Function() clientSocket,
}) async {
  final bound = _bound(srv);
  final link = await _Link.connect(await clientSocket(), host: host);
  addTearDown(link.destroy);
  link.send(
    utf8.encode(
      'GET / HTTP/1.1\r\n'
      'Host: $host\r\n'
      'X-Bridge-Trail',
    ),
  );
  final cut = await link.eofWithin(bound + _cutMargin);
  expect(
    cut,
    true,
    reason:
        'a client that stalls inside its request header is cut at the '
        'header deadline (${bound.inMilliseconds} ms + '
        '${_cutMargin.inMilliseconds} ms margin), not left to the idle '
        'timer',
  );
  expect(
    link.receivedBytes,
    0,
    reason:
        'the cut is quiet: no reply bytes, no wire code, and no standing '
        'rejection shape changes',
  );
}

// الشاهد 2: الحالة نفسها بعد طلب مكتمل على اتصال مُبقى - المهلة تبدأ
// عند أول بايت من الطلب التالي لا عند انتهاء الرد السابق.
Future<void> _witnessKeptAliveStallCut({
  required LocalIntakeServer srv,
  required String host,
  required Future<Socket> Function() clientSocket,
}) async {
  final bound = _bound(srv);
  final link = await _Link.connect(await clientSocket(), host: host);
  addTearDown(link.destroy);
  link.sendPost(contentLength: 15, firstBytes: utf8.encode('["BROWSER-LAB"]'));
  await link.answeredFuture.timeout(const Duration(seconds: 10));
  expect(link.statusLine, contains(' 200 '));
  final receivedBefore = link.receivedBytes;
  link.send(
    utf8.encode(
      'POST / HTTP/1.1\r\n'
      'Host: $host\r\n'
      'Origin: $_listed\r\n'
      'X-Bridge-Trail',
    ),
  );
  final cut = await link.eofWithin(bound + _cutMargin);
  expect(
    cut,
    true,
    reason:
        'the header deadline on a kept-alive connection starts at the '
        'first byte of the next request (${bound.inMilliseconds} ms + '
        '${_cutMargin.inMilliseconds} ms margin), so the stalled header is '
        'cut, not held to the idle timer',
  );
  expect(
    link.receivedBytes,
    receivedBefore,
    reason:
        'the cut is quiet: nothing new is written to the wire for the '
        'stalled request',
  );
}

// الشاهد 4: طلب سليم بطيء معقول ترويساته تصل داخل الحد يُخدم كاملاً -
// الحارس الذي يمنع القطع من التهام البطء الشرعي.
Future<void> _witnessSlowLegitServed({
  required LocalIntakeServer srv,
  required String host,
  required Future<Socket> Function() clientSocket,
}) async {
  final bound = _bound(srv);
  final client = _SlowClient(await clientSocket());
  addTearDown(client.destroy);
  client.write('POST / HTTP/1.1\r\n');
  await Future<void>.delayed(const Duration(milliseconds: 150));
  client.write('Host: $host\r\n');
  client.write('Origin: $_listed\r\n');
  await Future<void>.delayed(const Duration(milliseconds: 150));
  client.write('Content-Type: application/json\r\n');
  client.write('Content-Length: 15\r\n');
  client.write('\r\n');
  client.write('["BROWSER-LAB"]');
  await client.answeredFuture.timeout(const Duration(seconds: 10));
  final closed = await client.closedFuture
      .timeout(bound + _cutMargin)
      .then<bool>((_) => true)
      .catchError((Object _) => false);
  expect(
    closed,
    false,
    reason:
        'a legitimate sender whose headers arrive inside the deadline '
        '(${bound.inMilliseconds} ms) is never cut',
  );
  expect(client.receivedBytes, greaterThan(0));
  expect(client.text, contains(' 200 '));
  expect(client.text, contains('"ok":true'));
}

// الشاهد 3: الخامل المُبقى يبقى مفتوحاً بعد مهلة الترويسات ويُغلق تحت
// مهلة الخمول بحدَّي شاهد الخمول القائم. الخادم هنا يحمل مهلة الخمول
// المحقونة التي تشتق منها الحدود.
Future<void> _witnessIdleKeptAlive({
  required LocalIntakeServer srv,
  required String host,
  required Future<Socket> Function() clientSocket,
}) async {
  final bound = _bound(srv);
  final link = await _Link.connect(await clientSocket(), host: host);
  addTearDown(link.destroy);
  link.sendPost(contentLength: 15, firstBytes: utf8.encode('["BROWSER-LAB"]'));
  await link.answeredFuture.timeout(const Duration(seconds: 10));
  expect(link.statusLine, contains(' 200 '));
  final clock = Stopwatch()..start();
  // البقاء فوق مهلة الترويسات: الخامل المُبقى لا ساعة عليه
  final probe =
      bound + const Duration(milliseconds: 300) <
          _idle - const Duration(milliseconds: 300)
      ? bound + const Duration(milliseconds: 300)
      : _idle - const Duration(milliseconds: 300);
  if (clock.elapsed < probe) {
    expect(
      await link.eofWithin(probe - clock.elapsed),
      false,
      reason:
          'an idle kept-alive connection outlives the header deadline '
          '(${bound.inMilliseconds} ms) - the deadline never starts at the '
          'end of the previous reply',
    );
  }
  // الحد الأدنى لمهلة الخمول: الدورة الأولى تعلّم فقط
  final toLower = _idle - _earlyTolerance - clock.elapsed;
  if (toLower > Duration.zero) {
    expect(
      await link.eofWithin(toLower),
      false,
      reason:
          'the idle timer never closes before one idle period minus its '
          'tolerance (${(_idle - _earlyTolerance).inMilliseconds} ms)',
    );
  }
  // الحد الأعلى: الدورة الثانية تدمّر
  final upper = _idle * 2 + _lateMargin - clock.elapsed;
  expect(
    await link.eofWithin(upper > Duration.zero ? upper : Duration.zero),
    true,
    reason:
        'the idle connection closes under the idle timer before two '
        'periods plus the margin '
        '${(_idle * 2 + _lateMargin).inMilliseconds} ms - the standing '
        'idle contract carries it, not the header deadline',
  );
}

Future<void> _runSceneWitness(
  _WitnessBody witness, {
  required _Scene scene,
  required LocalIntakeServer srv,
}) async {
  final host = scene.v6 ? '[::1]:${srv.port}' : '127.0.0.1:${srv.port}';
  await witness(
    srv: srv,
    host: host,
    clientSocket: () async {
      if (scene.tls) {
        return SecureSocket.connect(
          '127.0.0.1',
          srv.port,
          onBadCertificate: (_) => true,
        );
      }
      return Socket.connect(
        scene.v6 ? InternetAddress.loopbackIPv6 : InternetAddress.loopbackIPv4,
        srv.port,
      );
    },
  );
}

Future<void> _runUnixWitness(
  _WitnessBody witness, {
  required LocalIntakeServer srv,
  required String sockPath,
}) async {
  await witness(
    srv: srv,
    host: 'localhost',
    clientSocket: () => Socket.connect(
      InternetAddress(sockPath, type: InternetAddressType.unix),
      0,
    ),
  );
}

void main() {
  final scenes = <_Scene>[
    const _Scene('plain'),
    const _Scene('::1 loopback', v6: true),
    const _Scene('TLS', tls: true),
  ];

  for (final scene in scenes) {
    group('${scene.name} listener', () {
      test('an incomplete request header is cut at the header deadline and '
          'the cut is quiet', () async {
        final srv = await _start(_config(scene));
        addTearDown(srv.stop);
        await _runSceneWitness(
          _witnessIncompleteHeaderCut,
          scene: scene,
          srv: srv,
        );
      }, timeout: const Timeout(Duration(seconds: 45)));

      test('after a completed request a kept-alive connection stalling its '
          'next header is cut from the first byte of that request', () async {
        final srv = await _start(_config(scene));
        addTearDown(srv.stop);
        await _runSceneWitness(
          _witnessKeptAliveStallCut,
          scene: scene,
          srv: srv,
        );
      }, timeout: const Timeout(Duration(seconds: 45)));

      test('a slow but legitimate request whose headers arrive inside the '
          'deadline is served whole', () async {
        final srv = await _start(_config(scene));
        addTearDown(srv.stop);
        await _runSceneWitness(_witnessSlowLegitServed, scene: scene, srv: srv);
      }, timeout: const Timeout(Duration(seconds: 45)));

      test('an idle kept-alive connection outlives the header deadline and '
          'closes between one idle period and two', () async {
        final srv = await _start(_config(scene, idleTimeout: _idle));
        addTearDown(srv.stop);
        await _runSceneWitness(_witnessIdleKeptAlive, scene: scene, srv: srv);
      }, timeout: const Timeout(Duration(seconds: 45)));
    });
  }

  group(
    'unix domain socket listener',
    () {
      // تخطٍ صادق مسمّى على نمط تخطي القناة: مقابس مجال يونكس ليست جزءاً
      // من dart:io على Windows - الشاهد الحي يجري على لينكس وماك حصراً
      test('an incomplete request header is cut at the header deadline and '
          'the cut is quiet', () async {
        final (sockPath, dir) = await _unixPaths();
        addTearDown(() async {
          try {
            await dir.delete(recursive: true);
          } on Object {
            // cleanup best-effort: the socket file is the package's job
          }
        });
        final srv = await _start(
          BridgeConfig(unixSocketPath: sockPath, headerTimeout: _headerTimeout),
        );
        addTearDown(srv.stop);
        await _runUnixWitness(
          _witnessIncompleteHeaderCut,
          srv: srv,
          sockPath: sockPath,
        );
      }, timeout: const Timeout(Duration(seconds: 45)));

      test('after a completed request a kept-alive connection stalling its '
          'next header is cut from the first byte of that request', () async {
        final (sockPath, dir) = await _unixPaths();
        addTearDown(() async {
          try {
            await dir.delete(recursive: true);
          } on Object {
            // cleanup best-effort: the socket file is the package's job
          }
        });
        final srv = await _start(
          BridgeConfig(unixSocketPath: sockPath, headerTimeout: _headerTimeout),
        );
        addTearDown(srv.stop);
        await _runUnixWitness(
          _witnessKeptAliveStallCut,
          srv: srv,
          sockPath: sockPath,
        );
      }, timeout: const Timeout(Duration(seconds: 45)));

      test('a slow but legitimate request whose headers arrive inside the '
          'deadline is served whole', () async {
        final (sockPath, dir) = await _unixPaths();
        addTearDown(() async {
          try {
            await dir.delete(recursive: true);
          } on Object {
            // cleanup best-effort: the socket file is the package's job
          }
        });
        final srv = await _start(
          BridgeConfig(unixSocketPath: sockPath, headerTimeout: _headerTimeout),
        );
        addTearDown(srv.stop);
        await _runUnixWitness(
          _witnessSlowLegitServed,
          srv: srv,
          sockPath: sockPath,
        );
      }, timeout: const Timeout(Duration(seconds: 45)));

      test('an idle kept-alive connection outlives the header deadline and '
          'closes between one idle period and two', () async {
        final (sockPath, dir) = await _unixPaths();
        addTearDown(() async {
          try {
            await dir.delete(recursive: true);
          } on Object {
            // cleanup best-effort: the socket file is the package's job
          }
        });
        final srv = await _start(
          BridgeConfig(
            unixSocketPath: sockPath,
            headerTimeout: _headerTimeout,
            idleTimeout: _idle,
          ),
        );
        addTearDown(srv.stop);
        await _runUnixWitness(
          _witnessIdleKeptAlive,
          srv: srv,
          sockPath: sockPath,
        );
      }, timeout: const Timeout(Duration(seconds: 45)));
    },
    skip: Platform.isWindows
        ? 'unix domain sockets are not part of dart:io on Windows - the '
              'live witness runs on Linux/macOS'
        : false,
  );

  group('headerTimeout value rule', () {
    // قاعدة القيمة كقاعدة حدّ الجسم حرفاً: القيمة الصريحة وحدها تُفحص -
    // موجبة ولا تزيد على مهلة الطلب - والفحص عند بناء الخادم حيث بقية
    // الفحوص لا كمفاجأة على السلك
    test('an explicit headerTimeout over the request timeout throws at '
        'construction', () {
      expect(
        () => LocalIntakeServer(
          telemetry: const SilentTelemetry(),
          onCommand: (_) async => const CommandOutcome(ok: true),
          config: const BridgeConfig(
            headerTimeout: Duration(seconds: 11),
            requestTimeout: Duration(seconds: 10),
          ),
        ),
        throwsArgumentError,
      );
    });

    test('a non-positive explicit headerTimeout throws at construction', () {
      expect(
        () => LocalIntakeServer(
          telemetry: const SilentTelemetry(),
          onCommand: (_) async => const CommandOutcome(ok: true),
          config: const BridgeConfig(headerTimeout: Duration.zero),
        ),
        throwsArgumentError,
      );
      expect(
        () => LocalIntakeServer(
          telemetry: const SilentTelemetry(),
          onCommand: (_) async => const CommandOutcome(ok: true),
          config: const BridgeConfig(headerTimeout: Duration(seconds: -1)),
        ),
        throwsArgumentError,
      );
    });

    test('unset selects the shorter of ten seconds and the request timeout, '
        'the explicit value announces itself, and equal still builds', () {
      final defaultServer = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        onCommand: (_) async => const CommandOutcome(ok: true),
      );
      expect(defaultServer.effectiveHeaderTimeout, const Duration(seconds: 10));
      final lowered = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        onCommand: (_) async => const CommandOutcome(ok: true),
        config: const BridgeConfig(requestTimeout: Duration(seconds: 4)),
      );
      expect(lowered.effectiveHeaderTimeout, const Duration(seconds: 4));
      final explicit = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        onCommand: (_) async => const CommandOutcome(ok: true),
        config: const BridgeConfig(headerTimeout: Duration(seconds: 7)),
      );
      expect(explicit.effectiveHeaderTimeout, const Duration(seconds: 7));
      final equal = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        onCommand: (_) async => const CommandOutcome(ok: true),
        config: const BridgeConfig(
          headerTimeout: Duration(seconds: 10),
          requestTimeout: Duration(seconds: 10),
        ),
      );
      expect(equal.effectiveHeaderTimeout, const Duration(seconds: 10));
    });
  });
}
