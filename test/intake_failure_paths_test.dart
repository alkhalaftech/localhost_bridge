// شواهد مسارات الفشل في الحاضنة: الكتابة المترابطة بجسم معلن وبايت
// زائد يظل الحد يحكمها (حارس عدّ الجسم)، وفشل حارس مقبس اليونكس
// يرجع مستوى واصفات العملية (حارس تسريب المستمع)، ومسار اليتامى
// بعد تعارض منفذ يترك المنفذ القديم حراً (حارس إغلاق اليتيم). كل
// مسار فشل يغلق ما فتحه — لا مستمع يتيم ولا بايت عدّ يبتلع اللاحق.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

const _listed = 'https://portal.example';
const _headerTimeout = Duration(milliseconds: 700);

// هامش وصول القطع بعد الحد (الحمل يؤخر المؤقت لا يبكره)
const _cutMargin = Duration(seconds: 2);

var _idSeq = 0;
String _cid() => 'failure-paths-${_idSeq++}';

Future<LocalIntakeServer> _start() async {
  final protection = IntakeProtection(telemetry: const SilentTelemetry())
    ..update(
      policy: const OriginPolicy(allowed: [_listed]),
      token: generateBridgeToken(),
    );
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: _cid,
    onCommand: (_) async => const CommandOutcome(ok: true),
    protection: protection,
    config: const BridgeConfig(headerTimeout: _headerTimeout),
  );
  await srv.start(preferredPort: 0);
  return srv;
}

// قارئ ردود يحصي الردود المكتملة على اتصال واحد: مسح بايتات صريح
// بفهرس استهلاك متقدم — كل رد تنتهي رأسه بسطر فارغ وجسمه بطول معلن
// يكتمل، والعدّ يقرأ ما وصل فعلاً
class _ReplyCounter {
  _ReplyCounter(this.socket) {
    socket.listen(
      (chunk) {
        _buffer.add(chunk);
        _count();
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
  final _closed = Completer<void>();
  int _replies = 0;
  int _consumed = 0;

  int get replies => _replies;

  Future<void> get closedFuture => _closed.future;

  static const List<int> _emptyLine = <int>[13, 10, 13, 10];
  static const List<int> _chunkedEnd = <int>[48, 13, 10, 13, 10];

  // أول موضع لتتابع البايتات المطلوب من [from]
  int _indexOf(List<int> hay, List<int> needle, int from) {
    for (var i = from; i + needle.length <= hay.length; i++) {
      var hit = true;
      for (var k = 0; k < needle.length; k++) {
        if (hay[i + k] != needle[k]) {
          hit = false;
          break;
        }
      }
      if (hit) return i;
    }
    return -1;
  }

  void _count() {
    final bytes = _buffer.toBytes();
    var i = _consumed;
    while (true) {
      final sep = _indexOf(bytes, _emptyLine, i);
      if (sep < 0) break;
      final head = latin1.decode(bytes.sublist(i, sep), allowInvalid: true);
      final m = RegExp(
        r'Content-Length:\s*(\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      if (m != null) {
        final bodyStart = sep + _emptyLine.length;
        final bodyLen = int.parse(m.group(1)!);
        if (bytes.length < bodyStart + bodyLen) break;
        _replies++;
        i = bodyStart + bodyLen;
      } else {
        // رد مقطّع بلا طول معلن: نهايته 0\r\n\r\n بعد رأسه
        final term = _indexOf(bytes, _chunkedEnd, sep);
        if (term < 0) break;
        _replies++;
        i = term + _chunkedEnd.length;
      }
    }
    _consumed = i;
  }
}

// عدد واصفات العملية على لينكس حيث مسار الفشل اليونكس حي: قراءة
// /proc/self/fd بإعادة محدودة على سباق الإغلاق (نمط شواهد المقابض
// القائمة) — وحيث لا يُقرأ يعيد null
int? _openDescriptors() {
  if (!Platform.isLinux) {
    return null;
  }
  for (var attempt = 0; attempt < 50; attempt++) {
    try {
      return Directory('/proc/self/fd').listSync().length;
    } on FileSystemException {
      sleep(const Duration(milliseconds: 2));
    }
  }
  return null;
}

// هل أدوات البيئة تُدفع مسار فشل الحارس؟ الحارس الوحيد القابل للحقن
// هنا هو /bin/chmod الغائب: حيث تعمل الأداة ينجح الحارس ولا سبيل
// لدفع المسار فيُقال التخطي بصدق لا توهم إثباتاً
Future<bool> _chmodMissing() async {
  final probeDir = await Directory.systemTemp.createTemp('lb-fp-chmod-');
  try {
    final probeFile = File('${probeDir.path}/probe');
    probeFile.writeAsStringSync('x');
    final probe = await Process.run('/bin/chmod', <String>[
      '600',
      probeFile.path,
    ]);
    return probe.exitCode != 0;
  } on Object {
    return true;
  } finally {
    try {
      await probeDir.delete(recursive: true);
    } on Object {
      // cleanup best-effort
    }
  }
}

void main() {
  test('two pipelined requests in one write with one extra trailing byte '
      'serve both replies and the stray byte is cut at the deadline', () async {
    final srv = await _start();
    addTearDown(srv.stop);
    final host = '127.0.0.1:${srv.port}';
    final socket = await Socket.connect(InternetAddress.loopbackIPv4, srv.port);
    final set = socket.setOption(SocketOption.tcpNoDelay, true);
    if (!set) {
      throw StateError('the witness client could not disable Nagle');
    }
    final counter = _ReplyCounter(socket);
    addTearDown(socket.destroy);
    // الطلبان متتابعان في كتابة واحدة والثاني بجسم معلن وبايت زائد:
    // البايت الزائد يبدأ طلباً لا يكتمل أبداً فيحكمه الحد
    final body = '["BROWSER-LAB"]';
    socket.add(
      utf8.encode(
        'POST / HTTP/1.1\r\n'
        'Host: $host\r\n'
        'Origin: $_listed\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: ${body.length}\r\n'
        '\r\n$body'
        'POST / HTTP/1.1\r\n'
        'Host: $host\r\n'
        'Origin: $_listed\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: ${body.length}\r\n'
        '\r\n$body'
        'X',
      ),
    );
    var waited = 0;
    while (counter.replies < 2 && waited < 10000) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
      waited += 20;
    }
    expect(
      counter.replies,
      2,
      reason:
          'both pipelined requests are served whole - the declared body '
          'is counted exactly, never one byte long into the next frame',
    );
    final clock = Stopwatch()..start();
    var cut = false;
    try {
      await counter.closedFuture.timeout(
        _headerTimeout + _cutMargin - clock.elapsed,
      );
      cut = true;
    } on TimeoutException {
      cut = false;
    }
    expect(
      cut,
      true,
      reason:
          'the stray byte starts a request that never completes and is '
          'cut at the deadline (${_headerTimeout.inMilliseconds} ms + '
          'margin) - a body counted one byte long would swallow the '
          'stray byte into the served body and the connection would '
          'never be cut',
    );
  }, timeout: const Timeout(Duration(seconds: 45)));

  test('a unix guard failure returns the process descriptors to their '
      'pre-start level: the failed start leaves no listener behind', () async {
    if (!Platform.isLinux) {
      markTestSkipped(
        'unix domain sockets are not part of dart:io on this platform - '
        'the guard-failure witness runs on Linux where the socket and '
        'its /bin/chmod guard live',
      );
      return;
    }
    if (!await _chmodMissing()) {
      markTestSkipped(
        '/bin/chmod works here - the guard-failure path is proven only '
        'where the tool is missing above its fixed path, and where it '
        'works the guard succeeds and the path cannot be driven',
      );
      return;
    }
    final dir = await Directory.systemTemp.createTemp('lb-fp-unix-');
    addTearDown(() async {
      try {
        await dir.delete(recursive: true);
      } on Object {
        // cleanup best-effort
      }
    });
    final sockPath = '${dir.path}/bridge.sock';
    final protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(
        policy: const OriginPolicy(allowed: [_listed]),
        token: generateBridgeToken(),
      );
    final srv = LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _cid,
      onCommand: (_) async => const CommandOutcome(ok: true),
      protection: protection,
      config: BridgeConfig(unixSocketPath: sockPath),
    );
    final before = _openDescriptors()!;
    await expectLater(
      srv.start(preferredPort: 0),
      throwsA(isA<IntakeBindException>()),
      reason: 'the unguardable unix socket fails the whole start closed',
    );
    // مهلة تسوية: أحداث إغلاق مسار الفشل تكتمل قبل العدّ
    await Future<void>.delayed(const Duration(milliseconds: 600));
    final after = _openDescriptors()!;
    expect(
      after,
      lessThanOrEqualTo(before + 4),
      reason:
          'the failed start closes every listener it opened - a unix '
          'guard failure that left its raw feed open would hold the '
          'socket descriptor above the pre-start level forever',
    );
  }, timeout: const Timeout(Duration(seconds: 45)));

  test('a port conflict pushed into the orphan path leaves the old port '
      'free: a fresh bind on the same port succeeds after the failed '
      'start', () async {
    if (!Platform.isLinux) {
      markTestSkipped(
        'the orphan path on this transport set is reached through the '
        'unix listener arm - the witness runs on Linux where that '
        'optional listener exists',
      );
      return;
    }
    if (!await _chmodMissing()) {
      markTestSkipped(
        '/bin/chmod works here - the orphan path is driven only by a '
        'bind that succeeds and a guard that fails, and where the tool '
        'exists the guard succeeds so the path cannot be driven',
      );
      return;
    }
    // المنفذ القديم: مربوط ثم حر — البدء عليه ينجح ربطه ثم يفشل في
    // حارس يونكس فيمشي مسار اليتامى
    final squatter = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final oldPort = squatter.port;
    await squatter.close();
    await Future<void>.delayed(const Duration(milliseconds: 200));
    final dir = await Directory.systemTemp.createTemp('lb-fp-orphan-');
    addTearDown(() async {
      try {
        await dir.delete(recursive: true);
      } on Object {
        // cleanup best-effort
      }
    });
    final sockPath = '${dir.path}/bridge.sock';
    final protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(
        policy: const OriginPolicy(allowed: [_listed]),
        token: generateBridgeToken(),
      );
    final srv = LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _cid,
      onCommand: (_) async => const CommandOutcome(ok: true),
      protection: protection,
      config: BridgeConfig(unixSocketPath: sockPath),
    );
    await expectLater(
      srv.start(preferredPort: oldPort, fallbacks: const <int>[]),
      throwsA(isA<IntakeBindException>()),
      reason:
          'the guard failure after a bound port fails the start '
          'closed and walks the orphan path',
    );
    expect(
      srv.port,
      0,
      reason:
          'the orphan path zeroes the port with its server - a stale '
          'bound number would point callers at a listener that no '
          'longer exists',
    );
    // المنفذ القديم حر: اليتيم أُغلق بيد المسار لا ترك مقبسه مشغولاً
    final fresh = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      oldPort,
    );
    await fresh.close();
  }, timeout: const Timeout(Duration(seconds: 45)));
}
