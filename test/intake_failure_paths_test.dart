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
      'pre-start level across thirty failed starts: the failed start '
      'leaves no listener behind', () async {
    if (!Platform.isLinux) {
      markTestSkipped(
        'unix domain sockets are not part of dart:io on Windows - the '
        'guard-failure witness runs on Linux, where the failure is '
        'driven by planting a regular file over the born socket path so '
        'the guard reads a non-socket and walks its failure branch - no '
        'tool masking needed',
      );
      return;
    }
    // حقن فشل الحارس بلا مس الأداة: مقبس اليونكس يولد ملفاً عند مساره
    // لحظة ربطه — المرقاب يلمح الولادة ويزرع مكانه ملفاً عادياً فيقرأ
    // الحارس نمطاً غير مقبس فيرجع false ويمشي مسار الفشل حتماً. والحالة
    // الفائتة الوحيدة (حسم الحارس قبل الزرع) تجعل البدء ينجح فيفشل
    // الشاهد صاخباً لا يمرّ صامتاً
    Future<bool> plantRegularFileOverSocket(String path, Duration limit) async {
      final sw = Stopwatch()..start();
      while (sw.elapsed < limit) {
        if (File(path).existsSync()) {
          try {
            File(path).deleteSync();
          } on Object {
            // سباق وصيل: من زرع قبلي فزرعه هو الأصل
          }
          File(path).writeAsStringSync('not a socket');
          return true;
        }
        await Future<void>.delayed(const Duration(milliseconds: 1));
      }
      return false;
    }

    final dir = await Directory.systemTemp.createTemp('lb-fp-unix-');
    addTearDown(() async {
      try {
        await dir.delete(recursive: true);
      } on Object {
        // cleanup best-effort
      }
    });
    final protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(
        policy: const OriginPolicy(allowed: [_listed]),
        token: generateBridgeToken(),
      );
    final before = _openDescriptors()!;
    // ثلاثون بدءاً فاشلاً: كل فشل نظيف يغلق ما فتحه (نمو صفر)، وفشل
    // يترك تلقمته مفتوحة يسرب واصفاً واحداً لكل محاولة فيبلغ الثلاثين
    for (var attempt = 0; attempt < 30; attempt++) {
      final sockPath = '${dir.path}/bridge-$attempt.sock';
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: protection,
        config: BridgeConfig(unixSocketPath: sockPath),
      );
      final planted = plantRegularFileOverSocket(
        sockPath,
        const Duration(seconds: 5),
      );
      await expectLater(
        srv.start(preferredPort: 0),
        throwsA(isA<IntakeBindException>()),
        reason:
            'attempt $attempt: the guard reads the planted regular '
            'file over the born socket, fails closed, and the whole '
            'start throws',
      );
      final wasPlanted = await planted;
      expect(
        wasPlanted,
        isTrue,
        reason:
            'attempt $attempt: the socket was born and the plant '
            'landed inside the guard window - a start that succeeded '
            'here means the plant lost its race and the witness must '
            'fail loudly, never pass silently',
      );
      // الملف المزروع عادي والحزمة ترفع مقبس اليونكس حصراً فلا تمسه —
      // نظافته شأن الشاهد
      try {
        File(sockPath).deleteSync();
      } on Object {
        // cleanup best-effort
      }
    }
    final after = _openDescriptors()!;
    expect(
      after - before,
      lessThanOrEqualTo(4),
      reason:
          'thirty clean guard failures close every listener they opened '
          '- growth stays near zero; a guard failure that left its raw '
          'feed open would leak one descriptor per attempt and blow '
          'past this bound thirty times over',
    );
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('a port conflict pushed into the orphan path leaves the old port '
      'free: a fresh bind on the same port succeeds after the failed '
      'start', () async {
    if (!Platform.isLinux) {
      markTestSkipped(
        'unix domain sockets are not part of dart:io on Windows - the '
        'orphan-path witness runs on Linux, where the path is driven '
        'deterministically by a stale regular file left on the unix '
        'socket path: the ipv4 port binds, the unix bind throws, and '
        'the orphan cleanup closes what it opened - no tool masking '
        'needed',
      );
      return;
    }
    // المنفذ القديم: مربوط ثم حر — البدء عليه ينجح ربطه ثم يفشل ربط
    // اليونكس على الملف الساكن المزروع فيمسك مسار اليتامى حتماً بلا
    // سباق ولا تمويه أداة
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
    File(sockPath).writeAsStringSync('stale file');
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
          'the unix bind over the stale file throws after the ipv4 '
          'port bound - the generation fails closed and walks the '
          'orphan path',
    );
    expect(
      srv.port,
      0,
      reason:
          'the orphan path zeroes the port with its server - a stale '
          'bound number would point callers at a listener that no '
          'longer exists',
    );
    // المنفذ القديم حر: اليتيم أغلق بيد المسار لا ترك مقبسه مشغولاً
    final fresh = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      oldPort,
    );
    await fresh.close();
    // الملف الساكن عادي والحزمة ترفع مقبس اليونكس حصراً فلا تمسه —
    // نظافته شأن الشاهد (تهدم مع مجلده في addTearDown)
  }, timeout: const Timeout(Duration(seconds: 45)));
}
