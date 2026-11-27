// حدّ طور الجسم: الجسم الذي لا يكتمل يُقطع في حدّ قصير من بدء قراءته لا عند
// مهلة الطلب الكلية، فيتحرر مقعده والرد بالرمز القائم request_timeout (408).
// الحدّ الفعلي قيمة BridgeConfig.bodyTimeout الصريحة، وبلا قيمة الأصغر من
// عشر ثوانٍ ومهلة الطلب — فمن خفّض مهلة طلبه تحت العشر بلا أن يمسّ الخيار
// يُبنى كما كان ويتبعه الحدّ. والقيمة الصريحة وحدها تُفحص: موجبة ولا تزيد
// على مهلة الطلب.
// المواعيد على لونين: حقيقية بالساعة حيث يُختبر المؤقت نفسه (التنقيط كل
// أربع ثوانٍ على الافتراضي، والتنقيط على قيمة صريحة)، ومحقونة بالساعة حيث
// يكفي فحص الموعد عند وصول البيانات (الافتراضي بعشر ثوانٍ واتباع مهلة
// الطلب). والصالح لا يُقطع: جسم بأكبر حجم مقبول بتقطيع عادي يُخدم 200.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

/// Injectable monotonic clock: a single cell the server reads through
/// `nowMs`, so a test advances the body deadline at once.
final _clockMs = <int>[0];

var _idSeq = 0;
String _cid() => 'body-limit-${_idSeq++}';

/// Commands that reached the handler in the current test.
var _entered = 0;

Future<LocalIntakeServer> _start({
  Duration? requestTimeout,
  BridgeConfig config = const BridgeConfig(),
  bool injectClock = false,
}) async {
  final srv = LocalIntakeServer(
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: _cid,
    nowMs: injectClock ? () => _clockMs[0] : null,
    onCommand: (cmd) async {
      _entered++;
      return const CommandOutcome(ok: true);
    },
    requestTimeout: requestTimeout,
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(policy: const OriginPolicy(allowed: ['https://portal.example'])),
    config: config,
  );
  await srv.start(preferredPort: 0);
  return srv;
}

/// A raw POST that declares its body length and may carry its first bytes.
/// The reply is collected until its declared body is complete or the server
/// closes - a body refusal closes the connection by its own contract.
class _Link {
  _Link(this.socket) {
    socket.listen(
      (chunk) {
        _buffer.add(chunk);
        _check();
      },
      onDone: _finish,
      onError: (Object _) => _finish(),
    );
  }

  final Socket socket;
  final _buffer = BytesBuilder(copy: true);
  final _reply = Completer<String>();

  static Future<_Link> open(
    int port, {
    required int contentLength,
    List<int> firstBytes = const [],
  }) async {
    final s = await Socket.connect(InternetAddress.loopbackIPv4, port);
    unawaited(s.done.catchError((Object _) {}));
    s.add(
      utf8.encode(
        'POST / HTTP/1.1\r\n'
        'Host: 127.0.0.1:$port\r\n'
        'Origin: https://portal.example\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: $contentLength\r\n'
        '\r\n',
      ),
    );
    if (firstBytes.isNotEmpty) {
      s.add(firstBytes);
    }
    await s.flush();
    return _Link(s);
  }

  bool get answered => _reply.isCompleted;

  void send(List<int> bytes) {
    try {
      socket.add(bytes);
      socket.flush().catchError((Object _) {});
    } on Object {
      // already refused and closed - the reply is the verdict
    }
  }

  void _check() {
    if (_reply.isCompleted) return;
    final text = latin1.decode(_buffer.toBytes(), allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    if (sep < 0) return;
    final m = RegExp(
      r'Content-Length:\s*(\d+)',
      caseSensitive: false,
    ).firstMatch(text.substring(0, sep));
    if (m == null) {
      if (text.endsWith('0\r\n\r\n')) _reply.complete(text);
      return;
    }
    if (text.length - (sep + 4) >= int.parse(m.group(1)!)) {
      _reply.complete(text);
    }
  }

  void _finish() {
    if (!_reply.isCompleted) {
      _reply.complete(latin1.decode(_buffer.toBytes(), allowInvalid: true));
    }
  }

  Future<String> get reply => _reply.future;

  void destroy() => socket.destroy();
}

String _bodyOf(String reply) {
  final sep = reply.indexOf('\r\n\r\n');
  return sep < 0 ? '' : reply.substring(sep + 4);
}

/// True once the server holds [count] seats, polled briefly.
Future<bool> _seatsRead(LocalIntakeServer srv, int count) async {
  final sw = Stopwatch()..start();
  while (sw.elapsed < const Duration(seconds: 5)) {
    if (srv.counters.activeSeats == count) return true;
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  return false;
}

void _expectBodyRefused(String reply) {
  expect(reply.split('\r\n').first, contains(' 408 '));
  expect(
    _bodyOf(reply),
    contains('"error":"request_timeout"'),
    reason: 'the standing code sits in the body the page reads',
  );
}

void main() {
  setUp(() {
    _clockMs[0] = 0;
    _entered = 0;
  });

  test('a body that drips one byte every four seconds is cut at the default '
      'body limit: 408 request_timeout, the handler never entered, the seat '
      'freed', () async {
    // بالساعة الحقيقية وبلا ساعة محقونة: المؤقت نفسه هو المختبر —
    // والجسم خمسة بايتات `["A"]` تصل واحداً كل أربع ثوانٍ
    final srv = await _start();
    final link = await _Link.open(
      srv.port,
      contentLength: 5,
      firstBytes: '['.codeUnits,
    );
    addTearDown(link.destroy);
    addTearDown(srv.stop);
    final sw = Stopwatch()..start();
    for (var i = 1; i < 5 && !link.answered; i++) {
      // البايت التالي في موعده (أربع ثوانٍ بين بايت وآخر)، والرد يُرى
      // خلال مئة ملي ثانية من وصوله فلا ينتظر الشاهد الموعد التالي
      final due = Duration(seconds: 4 * i);
      while (!link.answered && sw.elapsed < due) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      if (link.answered) break;
      link.send('["A"]'.codeUnits.sublist(i, i + 1));
    }
    final reply = await link.reply.timeout(
      const Duration(seconds: 24),
      onTimeout: () => '',
    );
    sw.stop();
    expect(reply, isNotEmpty, reason: 'the server must answer');
    _expectBodyRefused(reply);
    expect(
      sw.elapsed,
      greaterThanOrEqualTo(const Duration(seconds: 9)),
      reason: 'the limit is not shorter than ten seconds',
    );
    expect(
      _entered,
      0,
      reason: 'a body cut at its limit never reaches the handler',
    );
    expect(
      await _seatsRead(srv, 0),
      true,
      reason: 'the refused body frees its seat',
    );
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('with the default limits a chunk arriving past ten seconds is refused '
      'request_timeout although the request timeout is thirty', () async {
    // الساعة المحقونة تقدَّم فوق العشر ثوانٍ بعد أخذ المقعد: فحص الموعد
    // عند وصول البايت التالي يحسم بلا انتظار حقيقي — وبمهلة الطلب
    // القديمة كان الجسم ليكتمل ويُخدم
    final srv = await _start(injectClock: true);
    final link = await _Link.open(
      srv.port,
      contentLength: 5,
      firstBytes: '['.codeUnits,
    );
    addTearDown(link.destroy);
    addTearDown(srv.stop);
    expect(
      await _seatsRead(srv, 1),
      true,
      reason: 'the dripping request holds its seat - its body read began',
    );
    await Future<void>.delayed(const Duration(milliseconds: 200));
    _clockMs[0] += 10 * 1000 + 500;
    link.send('"A"]'.codeUnits);
    final reply = await link.reply.timeout(
      const Duration(seconds: 10),
      onTimeout: () => '',
    );
    _expectBodyRefused(reply);
    expect(_entered, 0);
  });

  test(
    'a body of the full byte cap sent in ordinary chunks is served',
    () async {
      // جسم بأكبر حجم مقبول حرفاً — الأمر نفسه يملأ الباقي — بتقطيع 16KiB
      // كل خمس ملي ثانية: لا قطع كاذباً للمرسل الصالح البطيء المعتاد
      const cap = 1024 * 1024;
      const wrapper = '{"data":[""]}'.length;
      final body = utf8.encode('{"data":["${'x' * (cap - wrapper)}"]}');
      expect(body.length, cap);
      final srv = await _start();
      addTearDown(srv.stop);
      final client = HttpClient();
      addTearDown(() => client.close(force: true));
      final req = await client.postUrl(
        Uri.parse('http://127.0.0.1:${srv.port}/'),
      );
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      const chunk = 16 * 1024;
      final sw = Stopwatch()..start();
      for (var off = 0; off < cap; off += chunk) {
        final end = off + chunk < cap ? off + chunk : cap;
        req.add(body.sublist(off, end));
        await req.flush();
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
      final res = await req.close().timeout(const Duration(seconds: 30));
      final text = await res.transform(utf8.decoder).join();
      sw.stop();
      expect(res.statusCode, 200);
      expect(text, contains('"ok":true'));
      expect(_entered, 1);
      // الهامش المقيس يُكتب سطراً يُقرأ من مشغّل CI كما تُقرأ مدد المختبر
      print(
        'BODY-LIMIT: a full-cap body in 16 KiB chunks every 5 ms was served '
        'in ${sw.elapsedMilliseconds} ms (limit 10000 ms)',
      );
    },
    timeout: const Timeout(Duration(seconds: 60)),
  );

  test('a host that lowered requestTimeout under ten seconds without the '
      'option keeps its build, and the body limit follows it down', () async {
    // قبل الحدّ مقبول وبعده مرفوض: الحدّ هنا خمس ثوانٍ لا العشر
    final srv = await _start(
      injectClock: true,
      requestTimeout: const Duration(seconds: 5),
    );
    addTearDown(srv.stop);
    expect(
      srv.effectiveBodyTimeout,
      const Duration(seconds: 5),
      reason:
          'no explicit option: the limit is the request timeout '
          'itself once that is under ten seconds',
    );
    final early = await _Link.open(
      srv.port,
      contentLength: 5,
      firstBytes: '['.codeUnits,
    );
    addTearDown(early.destroy);
    expect(await _seatsRead(srv, 1), true);
    await Future<void>.delayed(const Duration(milliseconds: 200));
    _clockMs[0] += 4 * 1000 + 900;
    early.send('"A"]'.codeUnits);
    final okReply = await early.reply.timeout(
      const Duration(seconds: 10),
      onTimeout: () => '',
    );
    expect(
      okReply.split('\r\n').first,
      contains(' 200 '),
      reason: 'a body completed inside the limit is served',
    );
    expect(_entered, 1);
    expect(
      await _seatsRead(srv, 0),
      true,
      reason: 'the served request freed its seat before the next one',
    );
    final late = await _Link.open(
      srv.port,
      contentLength: 5,
      firstBytes: '['.codeUnits,
    );
    addTearDown(late.destroy);
    expect(await _seatsRead(srv, 1), true);
    await Future<void>.delayed(const Duration(milliseconds: 200));
    _clockMs[0] += 5 * 1000 + 100;
    late.send('"A"]'.codeUnits);
    final lateReply = await late.reply.timeout(
      const Duration(seconds: 10),
      onTimeout: () => '',
    );
    _expectBodyRefused(lateReply);
    expect(_entered, 1, reason: 'the refused body never reached the handler');
  });

  test('an explicit bodyTimeout cuts a dripping body at that limit and frees '
      'the seat', () async {
    // بالساعة الحقيقية: مهلة الطلب ثلاثون ثانية والحدّ الصريح ثلاث —
    // والتنقيط كل ثانية لا يترك مهلة الصمت تحسم، فالمؤقت المطلق وحده
    // هو الذي يقطع
    final srv = await _start(
      config: const BridgeConfig(
        requestTimeout: Duration(seconds: 30),
        bodyTimeout: Duration(seconds: 3),
      ),
    );
    addTearDown(srv.stop);
    expect(srv.effectiveBodyTimeout, const Duration(seconds: 3));
    final link = await _Link.open(
      srv.port,
      contentLength: 5,
      firstBytes: '['.codeUnits,
    );
    addTearDown(link.destroy);
    final sw = Stopwatch()..start();
    for (var i = 1; i < 6 && !link.answered; i++) {
      await Future<void>.delayed(const Duration(seconds: 1));
      if (link.answered) break;
      link.send('["A"]'.codeUnits.sublist(i, i + 1));
    }
    final reply = await link.reply.timeout(
      const Duration(seconds: 24),
      onTimeout: () => '',
    );
    sw.stop();
    expect(reply, isNotEmpty, reason: 'the server must answer');
    _expectBodyRefused(reply);
    expect(
      sw.elapsed,
      greaterThanOrEqualTo(const Duration(milliseconds: 2900)),
      reason: 'the limit is the explicit three seconds, not shorter',
    );
    expect(_entered, 0);
    expect(
      await _seatsRead(srv, 0),
      true,
      reason: 'the refused body frees its seat',
    );
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('an explicit bodyTimeout must be positive and no longer than the '
      'request timeout; equal and shorter both build', () {
    LocalIntakeServer build({
      Duration? requestTimeout,
      BridgeConfig config = const BridgeConfig(),
    }) => LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _cid,
      onCommand: (cmd) async => const CommandOutcome(ok: true),
      requestTimeout: requestTimeout,
      config: config,
    );
    final named = throwsA(
      isA<ArgumentError>().having((e) => e.name, 'name', 'config.bodyTimeout'),
    );
    expect(
      () =>
          build(config: const BridgeConfig(bodyTimeout: Duration(seconds: 31))),
      named,
      reason: 'longer than the thirty-second request timeout',
    );
    expect(
      () => build(config: const BridgeConfig(bodyTimeout: Duration.zero)),
      named,
      reason: 'zero is not a deadline',
    );
    expect(
      () =>
          build(config: const BridgeConfig(bodyTimeout: Duration(seconds: -1))),
      named,
    );
    expect(
      () => build(
        config: const BridgeConfig(
          requestTimeout: Duration(seconds: 10),
          bodyTimeout: Duration(seconds: 11),
        ),
      ),
      named,
      reason: 'the package-level request timeout counts too',
    );
    expect(
      () => build(
        requestTimeout: const Duration(seconds: 10),
        config: const BridgeConfig(bodyTimeout: Duration(seconds: 11)),
      ),
      named,
      reason: 'the constructor-level request timeout counts too',
    );
    // ويُبنى بما يساوي مهلة الطلب أو يقصر عنها، وبالقيم القصيرة
    expect(
      build(
        config: const BridgeConfig(bodyTimeout: Duration(seconds: 30)),
      ).effectiveBodyTimeout,
      const Duration(seconds: 30),
    );
    expect(
      build(
        config: const BridgeConfig(bodyTimeout: Duration(seconds: 2)),
      ).effectiveBodyTimeout,
      const Duration(seconds: 2),
    );
    expect(
      build(
        config: const BridgeConfig(
          requestTimeout: Duration(seconds: 60),
          bodyTimeout: Duration(seconds: 45),
        ),
      ).effectiveBodyTimeout,
      const Duration(seconds: 45),
      reason: 'a raised request timeout lets the body limit rise with it',
    );
    expect(
      build(
        config: const BridgeConfig(requestTimeout: Duration(seconds: 60)),
      ).effectiveBodyTimeout,
      const Duration(seconds: 10),
      reason: 'a raised request timeout does not raise the default',
    );
  });
}
