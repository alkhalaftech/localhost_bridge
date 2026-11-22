// حدّ مصافحة TLS على باب الجسر الآمن: التلقيمة تلف المستمع الخام وتغذي
// HttpServer.listenOn بعد بوابة أول سجل — أول بايت غير بدء مصافحة يُقطع
// فوراً بلا أي بايت من الخادم، والسجل المعلن فوق السقف يُقطع فوراً،
// والصامت وقاطر السجل البطيء يُقطعان عند المهلة والقطع يبلغ السلك
// (التدمير يصل السلك قبل تسليح المحرك حصراً)، والسقف يمنع المقبس الجديد
// قبل التسليح، وstop يحصد ما قبل التسليح فوراً ويعلن العالق بعد التسليح
// سطراً واحداً. المسبار الحاكم في كلها من العميل نفسه: خطأ سريع = ميت
// على السلك، صمت = حي، نجاح TLS = حي ويجيب.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/tls_cert.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

/// مرصد تحذيرات الخادم: أسطر الإيقاف المعلنة هي موضوع الشاهد
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
String _cid() => 'tlslimit-${_idSeq++}';

LocalIntakeServer _make({
  required _Rec? rec,
  IntakeProtection? pr,
  BridgeConfig config = const BridgeConfig(),
}) {
  final telemetry = rec ?? const SilentTelemetry();
  return LocalIntakeServer(
    telemetry: telemetry,
    correlationIdGenerator: _cid,
    onCommand: (_) async => const CommandOutcome(ok: true),
    protection:
        pr ??
        (IntakeProtection(telemetry: telemetry)..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          token: _t64,
        )),
    config: config,
  );
}

/// طلب POST حقيقي على الباب الآمن بمصافحة كاملة: الحالة والجسم
Future<(int, String)> _tlsPost(int port) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 5)
    ..badCertificateCallback = (cert, host, port) => true;
  try {
    final req = await client.postUrl(Uri.parse('https://127.0.0.1:$port/'));
    req.headers.set('Origin', 'https://portal.example');
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.headers.set('X-Bridge-Token', _t64);
    req.add(utf8.encode('{"data":["PRINT 1"]}'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } on Object {
    return (-1, '');
  } finally {
    client.close(force: true);
  }
}

/// قارئ اتصال TLS قائم واحد (keep-alive): اشتراك واحد على المقبس طوال
/// الحياة — مقبس dart:io جدولٌ واحدي الاشتراك فلا استماع ثانٍ —
/// وكل طلب ينتظر رده على الطابور نفسه، بتمام الطول المعلن أو تمام
/// المجزأ (transfer-encoding: chunked بلا طول معلن فـ0\r\n\r\n إتمامه)
class _LiveDoor {
  _LiveDoor(this.socket) {
    socket.listen(
      (chunk) {
        _buffer.add(chunk);
        _drain();
      },
      onDone: () => _fail(),
      onError: (Object _) => _fail(),
    );
  }

  final SecureSocket socket;
  final BytesBuilder _buffer = BytesBuilder();
  final List<Completer<int>> _pending = <Completer<int>>[];

  Future<int> send(String request) {
    final done = Completer<int>();
    _pending.add(done);
    socket.add(utf8.encode(request));
    return done.future.timeout(const Duration(seconds: 5));
  }

  void _drain() {
    final text = latin1.decode(_buffer.toBytes(), allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    if (sep < 0) return;
    final head = text.substring(0, sep);
    final cl = RegExp(
      r'content-length:\s*(\d+)',
      caseSensitive: false,
    ).firstMatch(head);
    final bodyLen = text.length - (sep + 4);
    final chunkedEnd = text.endsWith('0\r\n\r\n');
    final hasCl = cl != null && bodyLen >= int.parse(cl.group(1)!);
    if (!hasCl && !chunkedEnd) return;
    final status = int.tryParse(head.split('\r\n').first.split(' ')[1]) ?? -1;
    _buffer.clear();
    final done = _pending.isEmpty ? null : _pending.removeAt(0);
    if (done != null && !done.isCompleted) done.complete(status);
  }

  void _fail() {
    for (final done in _pending) {
      if (!done.isCompleted) done.complete(-1);
    }
    _pending.clear();
  }
}

String _post(String host, String body) =>
    'POST / HTTP/1.1\r\n'
    'Host: $host\r\n'
    'Content-Type: application/json\r\n'
    'Content-Length: ${utf8.encode(body).length}\r\n'
    'Origin: https://portal.example\r\n'
    'X-Bridge-Token: $_t64\r\n'
    '\r\n$body';

void main() {
  test('a silent TLS client is cut on the wire when the first-record '
      'timeout expires: the client-side probe dies fast', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        tlsFirstRecordTimeout: const Duration(seconds: 1),
        securityContext: tlsContext(),
      ),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // فتح TCP صامت كامل: لا بايت واحد يُرسل
    final client = await Socket.connect(InternetAddress.loopbackIPv4, srv.port);
    unawaited(client.done.catchError((Object _) {}));
    // المهلة ثانية واحدة + هامش
    await Future<void>.delayed(const Duration(milliseconds: 1400));
    final probe = await wireProbe(client);
    client.destroy();
    expect(
      probe,
      startsWith('DEAD'),
      reason:
          'the first-record timeout cut reaches the wire while the TLS '
          'engine never armed - the probe fails fast, it never hangs',
    );
  });

  test('a ClientHello dripped slower than the first-record timeout is cut '
      'before arming: the probe dies', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        tlsFirstRecordTimeout: const Duration(seconds: 1),
        securityContext: tlsContext(),
      ),
    );
    // رأس سجل صالح من ClientHello حقيقي ثم تقطير بايت كل 150ms —
    // الاكتمال يحتاج أضعاف المهلة فالقطع يقع عند المهلة قبل التسليح
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final client = await Socket.connect(InternetAddress.loopbackIPv4, srv.port);
    unawaited(client.done.catchError((Object _) {}));
    client.add(hello.sublist(0, 5));
    await client.flush();
    final drip = Timer.periodic(const Duration(milliseconds: 150), (t) {
      final i = 5 + t.tick;
      if (i < hello.length) {
        client.add(<int>[hello[i]]);
      }
    });
    // القطع يُرصد من عدّ القطع ثم يتوقف التقطير لحظته: كتابات العميل
    // بعد القطع تبقى في طابور إرساله غير مُسلَّمة فتعمي مسبار
    // SecureSocket.secure على العميل نفسه — القطع نفسه واصلٌ للسلك
    // في الحالتين وسطر الإغلاق يبلغ القارئ
    final cutSw = Stopwatch()..start();
    while (srv.counters.tlsSocketsCut == 0 &&
        cutSw.elapsed.inMilliseconds < 2500) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
    drip.cancel();
    expect(
      srv.counters.tlsSocketsCut,
      1,
      reason: 'the drip was cut exactly once at the first-record deadline',
    );
    expect(
      srv.counters.tlsHandshakesInFlight,
      0,
      reason: 'the cut socket left the in-flight count at once',
    );
    final probe = await wireProbe(client);
    client.destroy();
    expect(
      probe,
      startsWith('DEAD'),
      reason:
          'the slow drip never completes the first record inside the '
          'timeout - the cut lands before arming and reaches the wire',
    );
  });

  test('a plain HTTP first byte on the TLS port is destroyed at once: the '
      'close reaches the client within half the timeout and with no server '
      'bytes', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final client = await Socket.connect(InternetAddress.loopbackIPv4, srv.port);
    final got = <List<int>>[];
    final closed = Completer<void>();
    late final StreamSubscription<List<int>> sub;
    sub = client.listen(
      got.add,
      onDone: () {
        if (!closed.isCompleted) closed.complete();
      },
      onError: (Object _) {
        if (!closed.isCompleted) closed.complete();
      },
    );
    final sw = Stopwatch()..start();
    client.add(utf8.encode('GET / HTTP/1.1\r\n\r\n'));
    await client.flush();
    // المهلة الافتراضية خمس ثوانٍ: الإغلاق يجب أن يصل قبل نصفها
    await closed.future.timeout(const Duration(seconds: 4));
    sw.stop();
    unawaited(sub.cancel());
    client.destroy();
    expect(
      sw.elapsed,
      lessThan(const Duration(milliseconds: 2500)),
      reason:
          'the non-handshake first byte is destroyed immediately - the '
          'close reaches the client inside half the first-record timeout',
    );
    // مهلة تسوية: أي بايتات متأخرة من الخادم لو كانت قادمة لوصلت الآن
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(
      got,
      isEmpty,
      reason:
          'the immediate cut sends nothing - no TLS alert and no HTTP '
          'bytes ever leave the server toward the plain client',
    );
  });

  test('a first record declaring a length over the cap is destroyed at '
      'once: the probe dies fast', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final client = await Socket.connect(InternetAddress.loopbackIPv4, srv.port);
    unawaited(client.done.catchError((Object _) {}));
    // رأس سجل يعلن 16641 بايتاً: بايت فوق السقف المسموح
    final over = <int>[0x16, 0x03, 0x01, 0x41, 0x01];
    client.add(over);
    await client.flush();
    await Future<void>.delayed(const Duration(milliseconds: 400));
    final probe = await wireProbe(client);
    client.destroy();
    expect(
      probe,
      startsWith('DEAD'),
      reason:
          'a declared record length over the cap is destroyed at once - '
          'the socket is never armed and never answers',
    );
  });

  test('tlsFirstRecordTimeout bounds are enforced at construction: below '
      'one second and above sixty seconds throw ArgumentError, the bounds '
      'themselves construct', () {
    BridgeConfig build(Duration d) => BridgeConfig(tlsFirstRecordTimeout: d);
    expect(
      () => LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        config: build(const Duration(milliseconds: 999)),
      ),
      throwsArgumentError,
      reason: 'below the one-second floor the option throws at construction',
    );
    expect(
      () => LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        config: build(const Duration(seconds: 61)),
      ),
      throwsArgumentError,
      reason:
          'above the sixty-second ceiling the option throws at construction',
    );
    // حدّا النطاق نفسهما يمران بلا رمي
    expect(
      () => LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        config: build(const Duration(seconds: 1)),
      ),
      returnsNormally,
      reason: 'the floor value itself constructs',
    );
    expect(
      () => LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        config: build(const Duration(seconds: 60)),
      ),
      returnsNormally,
      reason: 'the ceiling value itself constructs',
    );
  });

  test('above the maxOpenConnections cap the new socket is cut before '
      'arming: refused while the cap holds, served once a closing stuck '
      'handshake frees a seat', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        maxOpenConnections: 2,
        tlsFirstRecordTimeout: const Duration(seconds: 1),
        securityContext: tlsContext(),
      ),
    );
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // مقعدان مسلّحان عالقان: مصافحة تعبر التسليح ثم يصمت العميل للأبد
    final stuck1 = await replayClientHello(hello, srv.port);
    final stuck2 = await replayClientHello(hello, srv.port);
    await Future<void>.delayed(const Duration(milliseconds: 600));
    // الثالث فوق السقف: يُقطع قبل التسليح فيموت على السلك
    final refused = await Socket.connect(
      InternetAddress.loopbackIPv4,
      srv.port,
    );
    unawaited(refused.done.catchError((Object _) {}));
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final probe = await wireProbe(refused);
    refused.destroy();
    expect(
      probe,
      startsWith('DEAD'),
      reason:
          'the new socket over the cap is destroyed before arming - the '
          'destruction is the one that reaches the wire',
    );
    // إغلاق أحد العالقين: المصافحة الفاشلة تنقص العدّ فيتحرر مقعد
    stuck1.destroy();
    var served = false;
    final sw = Stopwatch()..start();
    while (sw.elapsed < const Duration(seconds: 8)) {
      final (status, body) = await _tlsPost(srv.port);
      if (status == 200) {
        expect(body, contains('"ok":true'));
        served = true;
        break;
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    stuck2.destroy();
    expect(
      served,
      true,
      reason:
          'a freed seat admits the next sender - the cap is a gate, not '
          'a wall',
    );
  });

  test('the internal 64-handshake cap holds with the option off: the '
      'sixty-fifth socket is cut before arming and a seat freed by a '
      'closing client is re-served', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        // maxOpenConnections مطفأ: السقف الداخلي هو الحاكم
        tlsFirstRecordTimeout: const Duration(seconds: 1),
        securityContext: tlsContext(),
      ),
    );
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final stuck = <Socket>[];
    for (var i = 0; i < 64; i++) {
      stuck.add(await replayClientHello(hello, srv.port));
    }
    await Future<void>.delayed(const Duration(milliseconds: 1500));
    final refused = await Socket.connect(
      InternetAddress.loopbackIPv4,
      srv.port,
    );
    unawaited(refused.done.catchError((Object _) {}));
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final probe = await wireProbe(refused);
    refused.destroy();
    expect(
      probe,
      startsWith('DEAD'),
      reason:
          'with the option off the internal 64 cap still cuts the new '
          'socket before arming - a stuck armed handshake can never be '
          'freed by the server so it deserves the tighter ceiling',
    );
    stuck.first.destroy();
    var served = false;
    final sw = Stopwatch()..start();
    while (sw.elapsed < const Duration(seconds: 8)) {
      final (status, body) = await _tlsPost(srv.port);
      if (status == 200) {
        expect(body, contains('"ok":true'));
        served = true;
        break;
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    for (final s in stuck.skip(1)) {
      s.destroy();
    }
    expect(
      served,
      true,
      reason:
          'closing one stuck client frees a seat - the next sender is served',
    );
  });

  test('stop reaps the pre-arming sockets at once and announces the stuck '
      'past-arming count in exactly one line with the exact count', () async {
    final rec = _Rec();
    final srv = _make(
      rec: rec,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    // صامتان قبل التسليح وعالقان بعد التسليح
    final silent1 = await Socket.connect(
      InternetAddress.loopbackIPv4,
      srv.port,
    );
    final silent2 = await Socket.connect(
      InternetAddress.loopbackIPv4,
      srv.port,
    );
    unawaited(silent1.done.catchError((Object _) {}));
    unawaited(silent2.done.catchError((Object _) {}));
    final stuck1 = await replayClientHello(hello, srv.port);
    final stuck2 = await replayClientHello(hello, srv.port);
    await Future<void>.delayed(const Duration(milliseconds: 600));
    await srv.stop().timeout(const Duration(seconds: 5));
    // ما قبل التسليح ميت على السلك فور عودة stop
    final probe1 = await wireProbe(silent1);
    final probe2 = await wireProbe(silent2);
    silent1.destroy();
    silent2.destroy();
    stuck1.destroy();
    stuck2.destroy();
    expect(
      probe1,
      startsWith('DEAD'),
      reason:
          'stop harvests the pre-arming sockets at once - the destroy '
          'reaches the wire',
    );
    expect(
      probe2,
      startsWith('DEAD'),
      reason: 'every pre-arming socket is harvested, not only the first',
    );
    // سطر واحد بالضبط يعلن العالق بعد التسليح بعدد صحيح مطابق
    final stuckLines = rec.warns
        .where((w) => w.contains('TLS handshake'))
        .toList();
    expect(
      stuckLines,
      hasLength(1),
      reason:
          'exactly one line announces the stuck past-arming count - no '
          'per-socket spam and no silence',
    );
    expect(
      stuckLines.single,
      contains('2'),
      reason: 'the announced count matches the two armed-stuck handshakes',
    );
  });

  test('a stop with nothing stuck past arming writes no stuck '
      'announcement line', () async {
    final rec = _Rec();
    final srv = _make(
      rec: rec,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    await srv.start(preferredPort: 0);
    final (status, _) = await _tlsPost(srv.port);
    expect(status, 200, reason: 'the healthy door serves before the check');
    await srv.stop().timeout(const Duration(seconds: 5));
    expect(
      rec.warns.where((w) => w.contains('TLS handshake')),
      isEmpty,
      reason:
          'the stuck line is written only when the count is above zero - '
          'a clean stop stays quiet',
    );
  });

  test('no double counting: a delivered socket leaves the feed count while '
      'it rides the open-connection count, a failed handshake decrements, '
      'and the count returns to zero after every scene', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        maxOpenConnections: 1,
        securityContext: tlsContext(),
      ),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // (أ) مقبس أكمل مصافحته وخدم طلبين على اتصال واحد: خارج عدّ التلقيمة
    // وداخل عدّ الاتصالات المفتوحة — السقف واحد فلو عدّه الاثنان معاً
    // لرد الطلب الثاني 503
    final live = _LiveDoor(
      await SecureSocket.connect(
        '127.0.0.1',
        srv.port,
        onBadCertificate: (cert) => true,
      ),
    );
    final first = await live.send(
      _post('127.0.0.1:${srv.port}', '{"data":["PRINT 1"]}'),
    );
    final second = await live.send(
      _post('127.0.0.1:${srv.port}', '{"data":["PRINT 1"]}'),
    );
    expect(
      first,
      200,
      reason: 'the first request on the delivered socket is served',
    );
    expect(
      second,
      200,
      reason:
          'the second request on the same delivered connection is served '
          'under a cap of one - the feed stopped counting the socket the '
          'moment it was delivered, so the two counting systems sum to '
          'one, never two',
    );
    expect(
      srv.counters.tlsHandshakesInFlight,
      0,
      reason: 'a delivered socket is out of the feed count at once',
    );
    live.socket.destroy();
    // (ب) المصافحة الفاشلة تنقص العدّ: عالق بعد التسليح ثم مات العميل
    final hello = await captureClientHello();
    final stuck = await replayClientHello(hello, srv.port);
    await Future<void>.delayed(const Duration(milliseconds: 600));
    expect(
      srv.counters.tlsHandshakesInFlight,
      1,
      reason: 'the armed-stuck handshake counts while its outcome is open',
    );
    stuck.destroy();
    var drained = false;
    final sw = Stopwatch()..start();
    while (sw.elapsed < const Duration(seconds: 5)) {
      if (srv.counters.tlsHandshakesInFlight == 0) {
        drained = true;
        break;
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(
      drained,
      true,
      reason:
          'the failed handshake decrements the count - the seat it held '
          'is freed for the next sender',
    );
    final (status, _) = await _tlsPost(srv.port);
    expect(
      status,
      200,
      reason: 'the freed seat serves the next real sender over a cap of one',
    );
    // (ج) العدّ يعود إلى صفر بعد كل مشهد
    expect(
      srv.counters.tlsHandshakesInFlight,
      0,
      reason: 'the count is zero after every scene ends',
    );
  });

  test('the cumulative cut counter counts the wire cuts exactly: one '
      'plain-HTTP first byte is one cut, a served handshake is none', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        maxOpenConnections: 4,
        securityContext: tlsContext(),
      ),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    expect(
      srv.counters.tlsSocketsCut,
      0,
      reason: 'a fresh server has cut nothing',
    );
    final bad = await Socket.connect(InternetAddress.loopbackIPv4, srv.port);
    unawaited(bad.done.catchError((Object _) {}));
    bad.add(utf8.encode('GET / HTTP/1.1\r\n\r\n'));
    await bad.flush();
    await Future<void>.delayed(const Duration(milliseconds: 400));
    bad.destroy();
    expect(
      srv.counters.tlsSocketsCut,
      1,
      reason: 'the non-handshake first byte is exactly one cumulative cut',
    );
    expect(
      srv.counters.tlsHandshakesInFlight,
      0,
      reason: 'the cut socket is out of the in-flight count at once',
    );
    final (status, _) = await _tlsPost(srv.port);
    expect(status, 200, reason: 'the door keeps serving after the cut');
    expect(
      srv.counters.tlsHandshakesDelivered,
      1,
      reason: 'the served handshake is delivered exactly once',
    );
    expect(
      srv.counters.tlsSocketsCut,
      1,
      reason: 'a served handshake is not a cut - the counters stay distinct',
    );
  });

  test('a socket its peer abandons before arming is destroyed at once: '
      'process handles do not grow with abandon cycles', () async {
    if (Platform.isMacOS) {
      markTestSkipped(
        'no /proc and no PowerShell on macOS - the abandonment handle '
        'count is read from CI there',
      );
      return;
    }
    final srv = _make(
      rec: null,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final before = _openHandles();
    // دورات انصراف النظير قبل التسليح: نصفها صامت كامل ونصفها بايتان
    // من رأس السجل ثم انصراف — كلاهما مسار الانصراف ذاته
    for (var i = 0; i < 300; i++) {
      final s = await Socket.connect(InternetAddress.loopbackIPv4, srv.port);
      if (i.isEven) {
        s.add(<int>[0x16, 0x03, 0x01]);
        await s.flush();
      }
      s.destroy();
    }
    // مهلة تسوية: أحداث إغلاق المقابس المهدومة تكتمل
    await Future<void>.delayed(const Duration(milliseconds: 600));
    expect(
      srv.counters.tlsHandshakesInFlight,
      0,
      reason: 'the abandoned sockets are out of every count at once',
    );
    final after = _openHandles();
    expect(
      after - before,
      lessThan(100),
      reason:
          'every abandoned pre-arming socket is destroyed at the moment of '
          'abandonment - a cycle that leaks its handle would add hundreds '
          'of handles over three hundred cycles, and a hostile client '
          'looping connects and closes from outside would exhaust the '
          'file descriptors of the bridge process',
    );
  });
}

/// عدد مقابض/واصفات العملية الحالية: /proc/self/fd على لينكس،
/// HandleCount عبر PowerShell على ويندوز — وماك بلا واحدة من الاثنتين
/// فيتخطى شاهد الانصراف هناك صادقاً مسمّياً ويُقرأ من CI
int _openHandles() {
  if (Platform.isLinux) {
    return Directory('/proc/self/fd').listSync().length;
  }
  final result = Process.runSync('powershell', <String>[
    '-NoProfile',
    '-Command',
    '(Get-Process -Id $pid).HandleCount',
  ]);
  return int.parse(result.stdout.toString().trim());
}
