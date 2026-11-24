// حدّ مصافحة TLS على باب الجسر الآمن: التلقيمة تقبل خاماً وتغذي
// HttpServer.listenOn بعد بوابة أول سجل — أول بايت غير بدء مصافحة يُقتل
// فوراً بلا أي بايت من الخادم، والسجل المعلن فوق السقف يُقتل فوراً،
// والساعة الكاملة للمصافحة (من القبول إلى التسليم) تقتل الصامت وقاطر
// السجل البطيء والعالق بعد التسليح معاً عند المهلة — والمرجع الخام باقٍ
// في يد التلقيمة حتى التسليم فالقتل يبلغ السلك في كل حالاته، والسقف
// يمنع المقبس الجديد قبل التسليح، وstop يحصد ما قبل التسليح والمسلَّح
// معاً. المسبار الحاكم في كلها من العميل نفسه: خطأ سريع = ميت على
// السلك، صمت = حي، نجاح TLS = حي ويجيب — وعلى المسلَّح حصراً الإنصات
// السلبي هو القياس الصادق (المسبار المرسل يستفزّ المحرك فيغلق بروتوكول-
// خطأ فيقرأ ميتاً والمقبس حيّ).
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/tls_cert.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

// مرصد تحذيرات الخادم: أسطر الإيقاف المعلنة هي موضوع الشاهد
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

// طلب POST حقيقي على الباب الآمن بمصافحة كاملة: الحالة والجسم
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

// قارئ اتصال TLS قائم واحد (keep-alive): اشتراك واحد على المقبس طوال
// الحياة — مقبس dart:io جدولٌ واحدي الاشتراك فلا استماع ثانٍ —
// وكل طلب ينتظر رده على الطابور نفسه، بتمام الطول المعلن أو تمام
// المجزأ (transfer-encoding: chunked بلا طول معلن فـ0\r\n\r\n إتمامه)
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
  test('a silent TLS client is cut on the wire when the handshake '
      'deadline expires: the client-side probe dies fast', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        tlsHandshakeTimeout: const Duration(seconds: 1),
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
          'the handshake deadline cut reaches the wire while the TLS '
          'engine never armed - the probe fails fast, it never hangs',
    );
  });

  test('a ClientHello dripped slower than the handshake deadline is cut '
      'before arming: the probe dies', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        tlsHandshakeTimeout: const Duration(seconds: 1),
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
    // رأس السجل الخماسي دفعة واحدة، ثم البايت الأول بعده يُرسل صراحةً
    // الآن (الفهرس 5) — توقيته مسمّى بهذا النداء لا بنداء موقّت متعاقب
    client.add(hello.sublist(0, 5));
    await client.flush();
    client.add(<int>[hello[5]]);
    await client.flush();
    final drip = Timer.periodic(const Duration(milliseconds: 150), (t) {
      // أول نداء للموقّت يحمل tick == 1 فيكمل التقطير من الفهرس 6
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
      reason: 'the drip was cut exactly once at the handshake deadline',
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
          'close reaches the client inside half the handshake deadline',
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

  test('tlsHandshakeTimeout bounds are enforced at construction: below '
      'one second and above sixty seconds throw ArgumentError, the bounds '
      'themselves construct', () {
    BridgeConfig build(Duration d) => BridgeConfig(tlsHandshakeTimeout: d);
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
    final rec = _Rec();
    final srv = _make(
      rec: rec,
      config: BridgeConfig(
        maxOpenConnections: 2,
        tlsHandshakeTimeout: const Duration(seconds: 1),
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
    // سطر الخيار يسمّي ما يقيسه: اتصالات مفتوحة (مسلَّمة وجارية معاً)
    // لا مصافحات جارية — فالمسلَّم ليس مصافحة جارية أبداً
    final capLines = rec.warns
        .where((w) => w.contains('intake TLS accept limit'))
        .toList();
    expect(
      capLines,
      hasLength(1),
      reason: 'exactly one throttled line for the option-path accept cut',
    );
    expect(
      capLines.single,
      contains('open connections'),
      reason:
          'the option-path count is open connections - delivered and '
          'in-flight summed - and is never mislabeled as handshakes in '
          'flight',
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
        // maxOpenConnections مطفأ: السقف الداخلي هو الحاكم — والملء
        // بالمهلة الافتراضية: الساعة الكاملة تقتل المسلَّح أيضاً فالملء
        // كله يبقى داخل نافذتها
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

  test('stop reaps the pre-arming and the armed sockets on the wire at '
      'once: every held client reads dead once stop returns', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    // صامتان قبل التسليح وعالقان بعد التسليح: الحصاد يشمل الطرفين
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
    // مسبار الإغلاق السلبي على العالقين المسلَّحين: يُلحق مبكراً ولا
    // يرسل بايتاً — المسبار الاستفزازي يستفزّ محرك TLS فيقرأ ميتاً
    // والمقبس حيّ، فالإنصات لوصول إغلاق النظير هو القياس الصادق هنا
    final close1 = watchPeerClose(stuck1);
    final close2 = watchPeerClose(stuck2);
    await Future<void>.delayed(const Duration(milliseconds: 600));
    await srv.stop().timeout(const Duration(seconds: 5));
    // كل المقبول ميت على السلك فور عودة stop: ما قبل التسليح والمسلَّح
    // معاً — المقبض الخام باقٍ في اليد بعد التسليح فالحصاد يبلغه
    final probe1 = await wireProbe(silent1);
    final probe2 = await wireProbe(silent2);
    final sawClose1 = await close1.future.timeout(
      const Duration(milliseconds: 2000),
      onTimeout: () => false,
    );
    final sawClose2 = await close2.future.timeout(
      const Duration(milliseconds: 2000),
      onTimeout: () => false,
    );
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
    expect(
      sawClose1,
      true,
      reason:
          'stop reaps the armed sockets on the wire too - the raw handle '
          'is still held after arming, so the harvest reaches the peer '
          'and its connection closes',
    );
    expect(
      sawClose2,
      true,
      reason: 'every armed socket is reaped, not only the first',
    );
  });

  test('a silent armed client is cut on the wire at the handshake '
      'deadline: the client-side probe dies fast', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        tlsHandshakeTimeout: const Duration(seconds: 1),
        securityContext: tlsContext(),
      ),
    );
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // سجل أول كامل ثم صمت للأبد: الساعة الكاملة للمصافحة تسري على
    // المسلَّح أيضاً فيُقطع على السلك عند المهلة لا يُترك حيّاً —
    // والقياس بالمسبار السلبي: وصول إغلاق النظير هو الميت على السلك
    final stuck = await replayClientHello(hello, srv.port);
    unawaited(stuck.done.catchError((Object _) {}));
    final close = watchPeerClose(stuck);
    await Future<void>.delayed(const Duration(milliseconds: 2200));
    final sawClose = await close.future.timeout(
      const Duration(milliseconds: 500),
      onTimeout: () => false,
    );
    stuck.destroy();
    expect(
      sawClose,
      true,
      reason:
          'the whole-handshake deadline keeps running past arming - the '
          'armed silent client is cut on the wire at the deadline, so '
          'its connection closes instead of hanging open',
    );
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('the feed count returns to zero after stop reaps the armed '
      'sockets: the armed harvest counts its cuts', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    // عالقان مسلَّحان ما يزالان موصولين: العدّ ينزل صفراً لحظة عودة
    // stop بالحصاد لا بمسح أعمى — وكل مقبس محصود قطعةٌ معدودة
    final stuck1 = await replayClientHello(hello, srv.port);
    final stuck2 = await replayClientHello(hello, srv.port);
    await Future<void>.delayed(const Duration(milliseconds: 600));
    final cutBefore = srv.counters.tlsSocketsCut;
    await srv.stop().timeout(const Duration(seconds: 5));
    expect(
      srv.counters.tlsHandshakesInFlight,
      0,
      reason:
          'the count returns to zero at the stop return - the arming set '
          'is drained by the harvest',
    );
    expect(
      srv.counters.tlsSocketsCut - cutBefore,
      2,
      reason:
          'the armed harvest is a counted cut per reaped socket - the '
          'count returns to zero because the sockets were cut on the '
          'wire, never by a silent clear',
    );
    stuck1.destroy();
    stuck2.destroy();
  });

  test('cycling stop and start three times with the internal cap filled '
      'by two armed-stuck clients keeps process handles at their '
      'pre-flood level and reads every old armed client dead', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(
        // مهلة السقف الكاملة: القاتل الوحيد في هذا الشاهد هو stop —
        // ساعة المصافحة لا تُسبقه إلى العالقين المسلَّحين
        tlsHandshakeTimeout: const Duration(seconds: 60),
        securityContext: tlsContext(),
      ),
    );
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final before = _openHandles();
    if (before == null) {
      // في CI لا يتخطى الشاهد: كل منصة تُجري عليها الاختبارات يجب أن تُقرأ
      // عدّتها، والفشل المسمّى أصدق من نجاحٍ بلا قياس
      if (Platform.environment['CI'] == 'true') {
        expect(
          before,
          isNotNull,
          reason:
              'CI must read a process handle or descriptor count on every '
              'platform it runs - a skip here would make the green job prove '
              'nothing',
        );
      }
      markTestSkipped(
        'this platform exposes no process handle or descriptor count this '
        'witness can read locally - outside CI the witness skips honestly; '
        'under CI it fails instead of skipping',
      );
      return;
    }
    // ثلاث دورات: كل دورة تملأ السقف الداخلي بعالقين مسلَّحين و62 صامتة
    // (64 مصافحة جارية) ثم stop يحصد الكل ثم start جيل جديد — المقابض
    // المفتوحة تعود لمستواها قبل الطوفان ولا يتجاوز مجموعها السقف أبداً
    for (var cycle = 1; cycle <= 3; cycle++) {
      final armedA = await replayClientHello(hello, srv.port);
      final armedB = await replayClientHello(hello, srv.port);
      final silents = <Socket>[];
      for (var i = 0; i < 62; i++) {
        silents.add(
          await Socket.connect(InternetAddress.loopbackIPv4, srv.port),
        );
      }
      unawaited(armedA.done.catchError((Object _) {}));
      unawaited(armedB.done.catchError((Object _) {}));
      // المسبار السلبي على العالقين المسلَّحين: وصول إغلاق النظير بعد
      // stop هو الميت على السلك — بلا استفزازٍ يغلق المحرك وحده
      final closeA = watchPeerClose(armedA);
      final closeB = watchPeerClose(armedB);
      var waitedMs = 0;
      while (srv.counters.tlsHandshakesInFlight < 64 && waitedMs < 3000) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
        waitedMs += 20;
      }
      expect(
        srv.counters.tlsHandshakesInFlight,
        lessThanOrEqualTo(64),
        reason:
            'cycle $cycle: the in-flight count never passes the internal '
            'ceiling - the open handles stay bounded by the cap',
      );
      await srv.stop().timeout(const Duration(seconds: 10));
      final sawCloseA = await closeA.future.timeout(
        const Duration(milliseconds: 2000),
        onTimeout: () => false,
      );
      final sawCloseB = await closeB.future.timeout(
        const Duration(milliseconds: 2000),
        onTimeout: () => false,
      );
      armedA.destroy();
      armedB.destroy();
      for (final s in silents) {
        s.destroy();
      }
      expect(
        sawCloseA,
        true,
        reason:
            'cycle $cycle: the armed client reaped by stop reads its '
            'connection closed on the wire - no stuck socket outlives '
            'the stop',
      );
      expect(
        sawCloseB,
        true,
        reason:
            'cycle $cycle: every armed socket is reaped, not only the first',
      );
      expect(
        _openHandles()!,
        lessThanOrEqualTo(before + 64),
        reason:
            'cycle $cycle: the process handle count returns to its '
            'pre-flood level - a stop that left its sockets stuck would '
            'grow the handles by the whole cap every cycle',
      );
      await srv.start(preferredPort: 0);
    }
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('the pre-arming harvest at stop counts its cuts: two silent '
      'sockets raise tlsSocketsCut by exactly two across stop', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    await srv.start(preferredPort: 0);
    // صامتان قبل التسليح حصراً: لا قطع قبل الإيقاف فالفرق يبدأ من صفر
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
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final cutBefore = srv.counters.tlsSocketsCut;
    expect(
      cutBefore,
      0,
      reason:
          'the two silent sockets only hold pre-arming slots - no cut is '
          'counted before stop',
    );
    await srv.stop().timeout(const Duration(seconds: 5));
    silent1.destroy();
    silent2.destroy();
    expect(
      srv.counters.tlsSocketsCut - cutBefore,
      2,
      reason:
          'the pre-arming harvest at stop is a cut per harvested socket - '
          'the counter names what stop cut on the wire, and two silent '
          'sockets are exactly two',
    );
  });

  test('the option cap counts delivered connections too: with the cap of '
      'two held by two served keep-alive connections, a third TLS '
      'connection is cut on the wire with the named accept line', () async {
    final rec = _Rec();
    final srv = _make(
      rec: rec,
      config: BridgeConfig(
        maxOpenConnections: 2,
        securityContext: tlsContext(),
      ),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // اتصالان مكتمل المصافحة يخدمان طلباً حقيقياً ويبقيان حيَّين على
    // keep-alive: عدّ الاتصالات المفتوحة يمتلئ بالمسلَّم لا بالجاري
    final liveA = _LiveDoor(
      await SecureSocket.connect(
        '127.0.0.1',
        srv.port,
        onBadCertificate: (cert) => true,
      ),
    );
    final liveB = _LiveDoor(
      await SecureSocket.connect(
        '127.0.0.1',
        srv.port,
        onBadCertificate: (cert) => true,
      ),
    );
    final statusA = await liveA.send(
      _post('127.0.0.1:${srv.port}', '{"data":["PRINT 1"]}'),
    );
    final statusB = await liveB.send(
      _post('127.0.0.1:${srv.port}', '{"data":["PRINT 1"]}'),
    );
    expect(
      statusA,
      200,
      reason: 'the first served connection holds its delivered slot',
    );
    expect(
      statusB,
      200,
      reason: 'the second served connection holds its delivered slot',
    );
    expect(
      srv.counters.tlsHandshakesDelivered,
      2,
      reason:
          'two completed handshakes were delivered - the cap is full of '
          'delivered connections, not in-flight handshakes',
    );
    // الثالث فوق السقف: يُقطع قبل التسليح فيموت على السلك بالسطر المسمّى
    final refused = await Socket.connect(
      InternetAddress.loopbackIPv4,
      srv.port,
    );
    unawaited(refused.done.catchError((Object _) {}));
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final probe = await wireProbe(refused);
    refused.destroy();
    liveA.socket.destroy();
    liveB.socket.destroy();
    expect(
      probe,
      startsWith('DEAD'),
      reason:
          'the option cap counts delivered connections as well - a third '
          'TLS connection over the cap of two delivered ones is cut '
          'before arming and the cut reaches the wire',
    );
    expect(
      rec.warns.where((w) => w.contains('intake TLS accept limit')),
      hasLength(1),
      reason: 'exactly one throttled line for the delivered-count accept cut',
    );
    expect(
      rec.warns.singleWhere((w) => w.contains('intake TLS accept limit')),
      contains('intake TLS accept limit: 3 open connections over the cap of 2'),
      reason:
          'the line names the exact count: three open connections over '
          'the cap of two',
    );
  });

  test('the internal ceiling line names its own count: handshakes in '
      'flight', () async {
    final rec = _Rec();
    final srv = _make(
      rec: rec,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    final hello = await captureClientHello();
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    // الملء كامل 64 صامتة ثم الخامس والستون فوق السقف الداخلي
    final stuck = <Socket>[];
    for (var i = 0; i < 64; i++) {
      stuck.add(await replayClientHello(hello, srv.port));
    }
    var waitedMs = 0;
    while (srv.counters.tlsHandshakesInFlight < 64 && waitedMs < 3000) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
      waitedMs += 20;
    }
    final refused = await Socket.connect(
      InternetAddress.loopbackIPv4,
      srv.port,
    );
    unawaited(refused.done.catchError((Object _) {}));
    await Future<void>.delayed(const Duration(milliseconds: 300));
    for (final s in stuck) {
      s.destroy();
    }
    refused.destroy();
    final lines = rec.warns
        .where((w) => w.contains('intake TLS handshake limit'))
        .toList();
    expect(
      lines,
      hasLength(1),
      reason: 'exactly one throttled line for the internal ceiling cut',
    );
    expect(
      lines.single,
      contains('handshakes in flight'),
      reason:
          'the internal ceiling counts in-flight handshakes only and its '
          'line names that count - it is never mislabeled as open '
          'connections',
    );
  });

  test(
    'after stop begins no new handshake is accepted or armed: a fresh '
    'silent ClientHello client gets no server bytes while a request '
    'still holds its seat, and no TLS handshake warning is written',
    () async {
      final rec = _Rec();
      final entered = Completer<void>();
      final gate = Completer<void>();
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _cid,
        onCommand: (_) async {
          if (!entered.isCompleted) entered.complete();
          await gate.future;
          return const CommandOutcome(ok: true);
        },
        protection: IntakeProtection(telemetry: rec)
          ..update(
            policy: const OriginPolicy(allowed: ['https://portal.example']),
            token: _t64,
          ),
        config: BridgeConfig(securityContext: tlsContext()),
      );
      final hello = await captureClientHello();
      final port = await srv.start(preferredPort: 0);
      // طلب حي داخل المعالج يقف عند البوابة فيمتلك فراغ المقاعد
      unawaited(_tlsPost(port));
      await entered.future.timeout(const Duration(seconds: 5));
      // الالتقاط بعد دخول المعالج: مصافحة الطلب الحي نفسها سُلِّمت قبله
      final deliveredBefore = srv.counters.tlsHandshakesDelivered;
      // بداية stop بلا انتظار حسمه: التلقيمتان تُغلقان قبل فراغ المقاعد
      final stopping = srv.stop();
      await Future<void>.delayed(const Duration(milliseconds: 500));
      // عميل جديد بعد ClientHello حقيقي: لا بايت من الخادم داخل النافذة —
      // رفض الاتصال نفسه أو الصمت كلاهما «لا بايت» على كل منصة
      var serverBytes = -1;
      try {
        final fresh = await Socket.connect(
          InternetAddress.loopbackIPv4,
          port,
        ).timeout(const Duration(seconds: 2));
        var got = 0;
        late final StreamSubscription<List<int>> sub;
        sub = fresh.listen((chunk) => got += chunk.length);
        fresh.add(hello);
        await fresh.flush();
        await Future<void>.delayed(const Duration(milliseconds: 1200));
        unawaited(sub.cancel());
        fresh.destroy();
        serverBytes = got;
      } on Object {
        serverBytes = 0;
      }
      gate.complete();
      await stopping.timeout(const Duration(seconds: 15));
      expect(
        serverBytes,
        0,
        reason:
            'once stop has begun the feeds are closed before the seats '
            'drain - no new handshake is accepted or armed, so no server '
            'byte reaches a fresh ClientHello client on any platform',
      );
      expect(
        srv.counters.tlsHandshakesDelivered,
        deliveredBefore,
        reason: 'no new handshake completes and is delivered after stop began',
      );
      expect(
        rec.warns.where((w) => w.contains('TLS handshake')),
        isEmpty,
        reason:
            'the fresh client was never armed and the stop writes no TLS '
            'handshake warning on any path - the harvest is silent, the '
            'counters carry it',
      );
    },
  );

  test('a clean stop writes no TLS handshake warning line', () async {
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
          'the stop harvest needs no warning line on any path - the '
          'reap is complete and the counters carry what it cut',
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

  test('the internal ceiling caps in-flight handshakes only: sixty-four '
      'delivered keep-alive connections with the option off never refuse '
      'the next sender', () async {
    // maxOpenConnections مطفأ والسقف الداخلي للمصافحات الجارية حصراً:
    // اتصال مكتمل المصافحة أُسلِّم إلى HttpServer فليس مصافحة جارية —
    // عدّه في عدّ الاتصالات حيث يحدّه خيار المضيف وحده
    final srv = _make(
      rec: null,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final live = <SecureSocket>[];
    for (var i = 0; i < 64; i++) {
      live.add(
        await SecureSocket.connect(
          '127.0.0.1',
          srv.port,
          onBadCertificate: (cert) => true,
        ),
      );
    }
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(
      srv.counters.tlsHandshakesDelivered,
      64,
      reason: 'sixty-four completed handshakes were delivered to the intake',
    );
    expect(
      srv.counters.tlsHandshakesInFlight,
      0,
      reason: 'a delivered socket is out of the in-flight count at once',
    );
    final (status, body) = await _tlsPost(srv.port);
    expect(
      status,
      200,
      reason:
          'the internal ceiling never counts a delivered connection as an '
          'in-flight handshake - with the option off the sixty-fifth '
          'sender is served, not refused at the door',
    );
    expect(body, contains('"ok":true'));
    for (final s in live) {
      s.destroy();
    }
  });

  test('a socket its peer abandons before arming is destroyed at once: '
      'process handles do not grow with abandon cycles', () async {
    final srv = _make(
      rec: null,
      config: BridgeConfig(securityContext: tlsContext()),
    );
    await srv.start(preferredPort: 0);
    addTearDown(srv.stop);
    final before = _openHandles();
    if (before == null) {
      // في CI لا يتخطى الشاهد: كل منصة تُجري عليها الاختبارات يجب أن تُقرأ
      // عدّتها، والفشل المسمّى أصدق من نجاحٍ بلا قياس
      if (Platform.environment['CI'] == 'true') {
        expect(
          before,
          isNotNull,
          reason:
              'CI must read a process handle or descriptor count on every '
              'platform it runs - a skip here would make the green job prove '
              'nothing',
        );
      }
      markTestSkipped(
        'this platform exposes no process handle or descriptor count this '
        'witness can read locally - outside CI the witness skips honestly; '
        'under CI it fails instead of skipping',
      );
      return;
    }
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
    final after = _openHandles()!;
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

// مسبار الإغلاق السلبي على مقبس عميل: يُلحق مبكراً ولا يرسل بايتاً —
// يعدّ وصول إغلاق النظير (EOF أو خطأ) متى ما وقع. المسبار الذي يرسل
// ClientHello يستفزّ محرك TLS المسلَّح فيغلق بروتوكول-خطأ فيقرأ ميتاً
// والمقبس حيّ — فالإنصات الصامت هو القياس الصادق على المسلَّح
Completer<bool> watchPeerClose(Socket client) {
  final closed = Completer<bool>();
  client.listen(
    (_) {},
    onDone: () {
      if (!closed.isCompleted) closed.complete(true);
    },
    onError: (Object _) {
      if (!closed.isCompleted) closed.complete(true);
    },
    cancelOnError: true,
  );
  return closed;
}

// عدد مقابض/واصفات العملية الحالية حيثما يمكن قراءته محلياً لعملية
// الاختبار نفسها: /proc/self/fd على لينكس، و/dev/fd على ماك واصفاً
// واصفاً، وHandleCount عبر PowerShell على ويندوز — وحيث لا يُقرأ أي منها
// يعيد null: خارج CI يتخطى الشاهد صادقاً مسمّياً، وفي CI يفشل بدل التخطي
int? _openHandles() {
  if (Platform.isLinux) {
    // على لينكس إدراج /proc/self/fd يصنّف كل مدخل بفحصه، والواصف الذي
    // يُغلق بين قراءة المدخل وفحصه يُسقط الإدراج كله بخطأ واصف غائب —
    // ومقابس المشهد نفسه تُقتل في أثناء العدّ (حصاد stop ومهله المصافحة)
    // فالسباق حقيقي لا نظري. تُعاد القراءة مرات محدودة بفاصل قصير
    // يوقف مؤقتات المشهد لحظة القراءة التالية، وإن تعذر العدّ كله عاد
    // null كإخوته: خارج CI تخطٍّ صادق، وفي CI فشل مسمّى
    for (var attempt = 0; attempt < 50; attempt++) {
      try {
        return Directory('/proc/self/fd').listSync().length;
      } on FileSystemException {
        sleep(const Duration(milliseconds: 2));
      }
    }
    return null;
  }
  if (Platform.isMacOS) {
    // على ماك إدراج /dev/fd يعمل stat لكل مدخل، والواصف الذي يُغلق بين
    // الإدراج وفحصه يُسقط الإدراج كله بخطأ واصف سيئ — فكل واصف يُسأل
    // وحده: المفتوح يجيب فحصه والمغلق يرمي فيُلتقط، ولا يرمي شيء منهما
    // إلى الشاهد. وإن تعذر العدّ كله عاد null فيُتخطى الشاهد بأمانة
    try {
      var open = 0;
      for (var fd = 0; fd < 4096; fd++) {
        try {
          File('/dev/fd/$fd').statSync();
          open++;
        } on FileSystemException {
          // واصف غير مفتوح الآن
        }
      }
      return open;
    } on Object {
      return null;
    }
  }
  if (!Platform.isWindows) {
    return null;
  }
  final result = Process.runSync('powershell', <String>[
    '-NoProfile',
    '-Command',
    '(Get-Process -Id $pid).HandleCount',
  ]);
  return int.parse(result.stdout.toString().trim());
}
