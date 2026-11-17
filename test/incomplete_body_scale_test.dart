// شاهدا المقياس لشكل الجسم المعلن الناقص نفسه الذي يحرسه
// incomplete_body_cut_test — الحكم في الاثنين بعدد المقابس الميتة حصراً،
// لا بأي قياس ذاكرة إطلاقاً:
// 1) 1200 مقبس يعلن Content-Length: 100 ويرسل بايتاً واحداً موزعة على
//    مسارات القطع السبعة قبل المقعد بتوزيع موثق (172/172/172/172
//    للأبواب الشكلية، 170 للمهيّأ OPTIONS، و171 لكل من Host و503
//    الانقطاع الفوري) — وبعد نافذة التفريغ وهامشها كل مقبس منها ميت
//    (1200/1200).
// 2) stop فوق 50 مقبساً معلقاً من النوع نفسه يعود داخل ثانيتين (حد
//    2000ms) ولا يبقى مقبس حي بعده (50/50).
// المواعيد حتمية عبر الساعة المحقونة (نمط incomplete_body_cut_test):
// كل موجة تفتح ثم تنتظر ردود أبوابها ثم تُقدَّم الساعة فوق نافذة
// التفريغ فينبض المرسل الصامت بايتاً فيحسم فحص الموعد عند أول وصول
// بيانات بدل انتظار مؤقته الحقيقي. حجم الموجة 50 يبقي المقابس
// المفتوحة المتزامنة عند ~140 واصفاً فلا تقترب من سقف واصفات مشغلي
// CI، والعدد الكلي يبقى 1200 كاملاً والحكم النهائي عليه.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

class _Rec extends BridgeTelemetry {
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
  }) {}
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

/// Injectable monotonic clock: a single cell the server reads through
/// `nowMs`, so a test advances every deadline at once.
final _clockMs = <int>[0];

var _idSeq = 0;
String _cid() => 'scale-${_idSeq++}';

Future<LocalIntakeServer> _startServer({
  required IntakeProtection protection,
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
  Duration? requestTimeout = const Duration(milliseconds: 400),
}) async {
  final srv = LocalIntakeServer(
    telemetry: _Rec(),
    correlationIdGenerator: _cid,
    nowMs: () => _clockMs[0],
    onCommand: onCommand ?? (cmd) async => const CommandOutcome(ok: true),
    protection: protection,
    requestTimeout: requestTimeout,
  );
  await srv.start(preferredPort: 0);
  return srv;
}

IntakeProtection _allowlist() {
  final pr = IntakeProtection(telemetry: _Rec());
  pr.update(policy: OriginPolicy(allowed: const ['https://portal.example']));
  return pr;
}

/// The documented distribution of the 1200 sockets over the seven
/// pre-seat cut paths: 172 per shape gate, 170 preflights, and 171 per
/// immediate-cut path - the blocks run in this exact order with the
/// busy block last, after its sixteen seat holders are seated.
const _distribution = <String, int>{
  'origin_too_long': 172,
  'origin_malformed': 172,
  'token_too_long': 172,
  'duplicate_header': 172,
  'options_preflight': 170,
  'blocked_by_protection': 171,
  'server_busy': 171,
};

const _waveSize = 50;

/// A raw socket that declares `Content-Length: 100` and sends a single
/// body byte, then goes silent. A Dart socket is a single-subscription
/// stream, so one listener feeds both the reply watcher and the dead
/// watcher.
class _Link {
  _Link(this.socket) {
    socket.listen(
      (c) {
        _buffer.add(c);
        _check();
      },
      onDone: () {
        if (!_dead.isCompleted) _dead.complete();
      },
      onError: (Object _) {
        if (!_dead.isCompleted) _dead.complete();
      },
    );
  }

  final Socket socket;
  final _buffer = BytesBuilder(copy: true);
  final _answered = Completer<void>();
  final _dead = Completer<void>();

  static Future<_Link> open(int port, String head) async {
    final s = await Socket.connect('127.0.0.1', port);
    s.add(utf8.encode('$head\r\nA'));
    await s.flush();
    return _Link(s);
  }

  void _check() {
    final text = latin1.decode(_buffer.toBytes(), allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    if (sep < 0) return;
    final head = text.substring(0, sep);
    final rest = text.substring(sep + 4);
    final m = RegExp(
      r'Content-Length:\s*(\d+)',
      caseSensitive: false,
    ).firstMatch(head);
    final cl = m == null ? 0 : int.parse(m.group(1)!);
    if (rest.length >= cl && !_answered.isCompleted) {
      _answered.complete();
    }
  }

  /// Completes once the gate answered on the wire - the sync point that
  /// proves the detached drain window is armed before the clock moves.
  Future<void> get answered => _answered.future;

  /// True when the server side cut the socket (EOF or an error) within
  /// the bound; false means it was still alive.
  Future<bool> waitDead({Duration limit = const Duration(seconds: 5)}) async {
    try {
      await _dead.future.timeout(limit);
      return true;
    } on TimeoutException {
      return false;
    }
  }

  /// One silent-sender nudge byte: with the clock already advanced past
  /// the drain window, the deadline check fires at once.
  Future<void> nudge() async {
    try {
      socket.add(utf8.encode('B'));
      await socket.flush();
    } on Object {
      // already dead - fine
    }
  }

  void destroy() => socket.destroy();
}

String _postHead(
  int port, {
  String? host,
  String? origin,
  String? token,
  String? correlationId,
  String method = 'POST',
}) {
  final b = StringBuffer()
    ..write('$method / HTTP/1.1\r\n')
    ..write('Host: ${host ?? '127.0.0.1:$port'}\r\n');
  if (origin != null) b.write('Origin: $origin\r\n');
  if (token != null) b.write('X-Bridge-Token: $token\r\n');
  if (correlationId != null) {
    b.write('X-Correlation-Id: $correlationId\r\n');
  }
  b
    ..write('Content-Type: application/json\r\n')
    ..write('Content-Length: 100\r\n')
    ..write('\r\n');
  return b.toString();
}

/// A complete legitimate POST through HttpClient - the seat holder for
/// the busy block.
Future<(int, String)> _post(int port, {String? origin}) async {
  final client = HttpClient();
  try {
    final req = await client.open('POST', '127.0.0.1', port, '/');
    if (origin != null) req.headers.set('Origin', origin);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } finally {
    client.close(force: true);
  }
}

/// Opens [count] incomplete-body sockets on [headFor] in waves of
/// [_waveSize]: per wave - connect, wait until every gate answered
/// (the drain window is armed), advance the injected clock past the
/// window plus margin, nudge each silent sender once, and require the
/// whole wave dead. Sockets are destroyed as each wave ends so the
/// concurrent descriptor peak stays at one wave, while the grand total
/// keeps the full count and the final verdict lands on it.
Future<int> _runBlock({
  required int port,
  required int count,
  required String Function(int) headFor,
  required List<_Link> sink,
}) async {
  var opened = 0;
  for (var offset = 0; offset < count; offset += _waveSize) {
    final n = count - offset < _waveSize ? count - offset : _waveSize;
    final wave = <_Link>[];
    await Future.wait([
      for (var i = 0; i < n; i++)
        () async {
          final l = await _Link.open(port, headFor(port));
          wave.add(l);
          sink.add(l);
        }(),
    ]);
    await Future.wait([
      for (final l in wave)
        l.answered.timeout(
          const Duration(seconds: 5),
          onTimeout: () =>
              fail('a gate socket never answered within five seconds'),
        ),
    ]);
    // نافذة التفريغ وهامشها عبر الساعة المحقونة ثم نبضة واحدة لكل مقبس
    _clockMs[0] += 10 * 60 * 1000;
    for (final l in wave) {
      await l.nudge();
    }
    final verdicts = await Future.wait([
      for (final l in wave) l.waitDead(limit: const Duration(seconds: 5)),
    ]);
    expect(
      verdicts.where((d) => d).length,
      wave.length,
      reason:
          'every socket of the wave must be cut after the drain window '
          'and its margin - the dead-socket count is the verdict',
    );
    for (final l in wave) {
      l.destroy();
    }
    opened += wave.length;
  }
  return opened;
}

void main() {
  setUp(() {
    // a fresh clock cell per test so no test inherits another's advance
    _clockMs[0] = 0;
  });

  test('1200 incomplete declared bodies across the seven pre-seat cut '
      'paths all die after the drain window', () async {
    final allLinks = <_Link>[];
    final holders = <Future<(int, String)>>[];
    final entered = <Completer<void>>[];
    final releases = <Completer<CommandOutcome>>[];
    final srv = await _startServer(
      protection: _allowlist(),
      onCommand: (cmd) {
        entered.add(Completer<void>()..complete());
        final release = Completer<CommandOutcome>();
        releases.add(release);
        return release.future;
      },
    );
    try {
      var total = 0;
      total += await _runBlock(
        port: srv.port,
        count: _distribution['origin_too_long']!,
        headFor: (p) => _postHead(p, origin: 'https://${'x' * 1100}'),
        sink: allLinks,
      );
      total += await _runBlock(
        port: srv.port,
        count: _distribution['origin_malformed']!,
        headFor: (p) => _postHead(p, origin: 'https://portal.example:8443:9'),
        sink: allLinks,
      );
      total += await _runBlock(
        port: srv.port,
        count: _distribution['token_too_long']!,
        headFor: (p) =>
            _postHead(p, origin: 'https://portal.example', token: 't' * 1100),
        sink: allLinks,
      );
      total += await _runBlock(
        port: srv.port,
        count: _distribution['duplicate_header']!,
        headFor: (p) =>
            _postHead(p, correlationId: 'dup-a\r\nX-Correlation-Id: dup-b'),
        sink: allLinks,
      );
      total += await _runBlock(
        port: srv.port,
        count: _distribution['options_preflight']!,
        headFor: (p) =>
            _postHead(p, method: 'OPTIONS', origin: 'https://portal.example'),
        sink: allLinks,
      );
      total += await _runBlock(
        port: srv.port,
        count: _distribution['blocked_by_protection']!,
        headFor: (p) => _postHead(
          p,
          host: 'evil.example:$p',
          origin: 'https://portal.example',
        ),
        sink: allLinks,
      );
      // the busy block last: fill all sixteen seats with handlers that
      // entered but never finish, then every incomplete body lands on
      // the busy gate
      for (var i = 0; i < 16; i++) {
        holders.add(_post(srv.port, origin: 'https://portal.example'));
      }
      final sw = Stopwatch()..start();
      while (entered.length < 16 && sw.elapsed < const Duration(seconds: 5)) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
      expect(
        entered.length,
        16,
        reason: 'all sixteen handlers must be seated before the busy block',
      );
      total += await _runBlock(
        port: srv.port,
        count: _distribution['server_busy']!,
        headFor: (p) => _postHead(p, origin: 'https://portal.example'),
        sink: allLinks,
      );
      expect(
        total,
        1200,
        reason:
            'the full count is 1200 - every one of the seven paths '
            'contributes its documented share and no socket is lowered '
            'or skipped',
      );
    } finally {
      for (final r in releases) {
        if (!r.isCompleted) r.complete(const CommandOutcome(ok: true));
      }
      for (final f in holders) {
        await f.timeout(const Duration(seconds: 5), onTimeout: () => (0, ''));
      }
      for (final l in allLinks) {
        l.destroy();
      }
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 120)));

  test('stop over 50 stuck incomplete declared bodies returns inside two '
      'seconds and every hanger is dead after it', () async {
    // the default request timeout (30s) puts the detached drain window
    // at its 2s patience cap, so the hangers are held by the drain and
    // cannot be cut early while stop is measured
    final srv = await _startServer(
      protection: _allowlist(),
      requestTimeout: null,
    );
    final hangers = <_Link>[];
    try {
      for (var i = 0; i < 50; i++) {
        hangers.add(
          await _Link.open(
            srv.port,
            _postHead(srv.port, origin: 'https://${'x' * 1100}'),
          ),
        );
      }
      await Future.wait([
        for (final l in hangers)
          l.answered.timeout(
            const Duration(seconds: 5),
            onTimeout: () =>
                fail('a hanger socket never answered within five seconds'),
          ),
      ]);
      expect(
        _clockMs[0],
        0,
        reason:
            'the drain window must not have elapsed yet - the fifty '
            'sockets are stuck when stop() is called',
      );
      final sw = Stopwatch()..start();
      await srv.stop().timeout(
        const Duration(seconds: 5),
        onTimeout: () => fail('stop() hung past five seconds'),
      );
      sw.stop();
      expect(
        sw.elapsedMilliseconds,
        lessThan(2000),
        reason:
            'stop must return inside the 2000ms budget - not five '
            'seconds',
      );
      // the drain window elapses through the injected clock plus one
      // nudge per hanger - then no live socket may remain
      _clockMs[0] += 10 * 60 * 1000;
      for (final l in hangers) {
        await l.nudge();
      }
      var dead = 0;
      for (final l in hangers) {
        if (await l.waitDead(limit: const Duration(seconds: 2))) dead++;
      }
      expect(
        dead,
        50,
        reason: 'no live socket may survive stop - 50/50 must be dead',
      );
    } finally {
      for (final l in hangers) {
        l.destroy();
      }
      // a failure before the measured stop still leaves no server behind
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 60)));
}
