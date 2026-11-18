// The single rejection-code registry, walked end to end: every registered
// code is produced on the live wire, the literal code rides the reply body
// with the registered status, and the registered close flavor is what
// actually happens - the documented immediate cut for the two documented
// paths, the bounded drain for every other unread body, a dead connection
// for every read body. A code the server produces but the registry lacks
// cannot reach the wire at all (the resolver throws), and a registered code
// no scenario walks fails the coverage verdict. The README wire table is
// matched against the same registry line for line. Titles in English
// (published package); deadlines are deterministic through the injected
// clock in the incomplete-body patterns.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

/// Injectable monotonic clock: a single cell the server reads through
/// `nowMs`, so the drain windows fire at once when the test advances it.
final _clockMs = <int>[0];

var _idSeq = 0;
String _cid() => 'reg-${_idSeq++}';

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

/// A raw-socket client: opens with the given head plus a first byte (the
/// incomplete-declared-body shape) or a full body, reads the reply once its
/// declared length arrived, and watches for the server-side cut.
class _Link {
  _Link(this.socket) {
    socket.listen(
      (c) {
        _buffer.add(c);
        _check();
      },
      onDone: () {
        // بعض الأجوبة تصل مع الإغلاق لا قبله (الـ408 فوق جسم موقوف) —
        // الاكتمال عند النهاية يقرأ ما وصل حرفاً كما وصل
        _check();
        if (!_dead.isCompleted) _dead.complete();
      },
      onError: (Object _) {
        _check();
        if (!_dead.isCompleted) _dead.complete();
      },
    );
  }

  final Socket socket;
  final _buffer = BytesBuilder(copy: true);
  final _reply = Completer<({String head, String body})>();
  final _dead = Completer<void>();

  static Future<_Link> openRaw(int port, String head, List<int> first) async {
    final s = await Socket.connect('127.0.0.1', port);
    s.add(utf8.encode(head));
    s.add(first);
    await s.flush();
    return _Link(s);
  }

  /// The incomplete declared body: `Content-Length: 100` promised, one byte
  /// sent, then silence.
  static Future<_Link> open(int port, String head) =>
      openRaw(port, head, utf8.encode('\r\nA'));

  /// A complete request: the whole body travels with the head.
  static Future<_Link> openFull(int port, String head, List<int> body) =>
      openRaw(port, head, body);

  void _check() {
    final text = latin1.decode(_buffer.toBytes(), allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    if (sep < 0 || _reply.isCompleted) return;
    final head = text.substring(0, sep);
    final rest = text.substring(sep + 4);
    final m = RegExp(
      r'Content-Length:\s*(\d+)',
      caseSensitive: false,
    ).firstMatch(head);
    if (m != null) {
      final cl = int.parse(m.group(1)!);
      if (rest.length >= cl) {
        _reply.complete((head: head, body: rest.substring(0, cl)));
      }
      return;
    }
    // الرد المُدار قد يصل مؤطَّراً chunked بلا Content-Length — يكتمل
    // القراء عند المقطع الختامي الصفري، أو عند نهاية الاتصال
    if (rest.endsWith('0\r\n\r\n')) {
      _reply.complete((head: head, body: rest));
    }
  }

  Future<({String head, String body})> readReply({
    Duration limit = const Duration(seconds: 3),
  }) async {
    try {
      return await _reply.future.timeout(limit);
    } on TimeoutException {
      return (head: '', body: '');
    }
  }

  Future<bool> waitDead({Duration limit = const Duration(seconds: 3)}) async {
    try {
      await _dead.future.timeout(limit);
      return true;
    } on TimeoutException {
      return false;
    }
  }

  /// Advances the injected clock past every window, then nudges the silent
  /// sender with one byte so the drain deadline check fires at once.
  Future<void> expireAndNudge() async {
    _clockMs[0] += 10 * 60 * 1000;
    try {
      socket.add(utf8.encode('B'));
      await socket.flush();
    } on Object {
      // already dead - fine
    }
  }

  void destroy() => socket.destroy();
}

String _head(
  int port, {
  String method = 'POST',
  String? host,
  String? origin,
  String? token,
  String? cid,
  String? contentType = 'application/json',
  int cl = 100,
  String? extraHeaders,
}) {
  final b = StringBuffer()
    ..write('$method / HTTP/1.1\r\n')
    ..write('Host: ${host ?? '127.0.0.1:$port'}\r\n');
  if (origin != null) b.write('Origin: $origin\r\n');
  if (token != null) b.write('X-Bridge-Token: $token\r\n');
  if (cid != null) b.write('X-Correlation-Id: $cid\r\n');
  if (contentType != null) b.write('Content-Type: $contentType\r\n');
  if (extraHeaders != null) b.write(extraHeaders);
  b
    ..write('Content-Length: $cl\r\n')
    ..write('\r\n');
  return b.toString();
}

String _statusOf(String head) => head.isEmpty ? '' : head.split('\r\n').first;

/// A complete small POST through HttpClient - the pre-step requests
/// (quota fill, token misses, the consent question) and the busy holders.
Future<(int, String)> _post(int port, {String? origin, String? token}) async {
  final client = HttpClient();
  try {
    final req = await client.open('POST', '127.0.0.1', port, '/');
    if (origin != null) req.headers.set('Origin', origin);
    if (token != null) req.headers.set('X-Bridge-Token', token);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } finally {
    client.close(force: true);
  }
}

class _Walk {
  _Walk(this.srv, this.link, this.release, {required this.preBody});

  final LocalIntakeServer srv;
  final _Link link;

  /// Frees what the scenario held (busy seat holders, a hanging handler)
  /// before the stop, so the teardown never hangs on purpose-held seats.
  final Future<void> Function() release;
  final bool preBody;
}

typedef _Scenario = ({String code, bool preBody, Future<_Walk> Function() run});

LocalIntakeServer _server({
  IntakeProtection? pr,
  Duration? requestTimeout = const Duration(milliseconds: 400),
  Duration? handlerTimeout,
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
  BridgeConfig config = const BridgeConfig(),
}) {
  final srv = LocalIntakeServer(
    telemetry: _Rec(),
    correlationIdGenerator: _cid,
    nowMs: () => _clockMs[0],
    onCommand: onCommand ?? (cmd) async => const CommandOutcome(ok: true),
    protection:
        pr ?? (IntakeProtection()..update(policy: const OriginPolicy())),
    handlerTimeout: handlerTimeout,
    config: config,
    requestTimeout: requestTimeout,
  );
  return srv;
}

Future<LocalIntakeServer> _listen(LocalIntakeServer srv) async {
  await srv.start(preferredPort: 0);
  return srv;
}

IntakeProtection _allowlist({int listedQuota = 0}) =>
    IntakeProtection()..update(
      policy: OriginPolicy(
        allowed: ['https://portal.example'],
        listedPerOriginPerMinute: listedQuota,
      ),
    );

IntakeProtection _closed() =>
    IntakeProtection()..update(policy: const OriginPolicy());

IntakeProtection _allowAll() => IntakeProtection()
  ..update(
    policy: const OriginPolicy(
      allowAllHardened: true,
      requireFetchMetadata: false,
    ),
  );

IntakeProtection _discovery(Future<OriginConsent> Function(String) cb) =>
    IntakeProtection()..update(
      policy: OriginPolicy(requireFetchMetadata: false, onUnknownOrigin: cb),
    );

List<_Scenario> _scenarios() {
  final cases = <({String code, bool preBody, Future<_Walk> Function() run})>[];

  // 400 - wire shapes over an incomplete declared body
  cases.add((
    code: 'origin_too_long',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://${'x' * 1100}'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'origin_malformed',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://portal.example:8443:9'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'token_too_long',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://portal.example', token: 't' * 1100),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'duplicate_header',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(
          srv.port,
          origin: 'https://portal.example',
          cid: 'dup-a\r\nX-Correlation-Id: dup-b',
        ),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'bad_request',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      // المحلل يقرأ الجسم تأطير chunked فيرمي على سطر الحجم 'PING'
      final link = await _Link.openRaw(
        srv.port,
        _head(
          srv.port,
          origin: 'https://portal.example',
          cl: 4,
          extraHeaders: 'Transfer-Encoding: chunked\r\n',
        ),
        utf8.encode('PING'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'method_not_allowed',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, method: 'GET', contentType: null),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));

  // 403 - policy and authority denials, all pre-read
  cases.add((
    code: 'origin_not_listed',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _closed()));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://attacker.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'origin_blocked',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowAll()));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'http://attacker.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'cross_site_blocked',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(
          srv.port,
          origin: 'https://portal.example',
          extraHeaders: 'Sec-Fetch-Mode: navigate\r\n',
        ),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'origin_unknown',
    preBody: true,
    run: () async {
      final srv = await _listen(
        _server(pr: _discovery((o) async => OriginConsent.dismissed)),
      );
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'http://attacker.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'origin_declined',
    preBody: true,
    run: () async {
      final srv = await _listen(
        _server(pr: _discovery((o) async => OriginConsent.reject)),
      );
      // السؤال الأول يفتح ويُجاب بالرفض، والثاني يقرأ الرفض المحفوظ
      final first = await _Link.openFull(
        srv.port,
        _head(srv.port, origin: 'https://new.example', cl: 9),
        utf8.encode('["CMD"]\r\n'),
      );
      await first.readReply();
      first.destroy();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://new.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'origin_pending',
    preBody: true,
    run: () async {
      final srv = await _listen(
        _server(pr: _discovery((o) => Completer<OriginConsent>().future)),
      );
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://fresh.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'blocked_by_protection',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(
          srv.port,
          host: 'evil.example:${srv.port}',
          origin: 'https://portal.example',
        ),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'token_required',
    preBody: true,
    run: () async {
      // الشرط المشترك: الأصل المؤهل بلا توكن يُرد بالرمز الجديد فوق
      // جسم غير مقروء، والقائمة مفعلة بخيار ج3
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(
            allowed: ['https://portal.example'],
            requireOriginWithToken: true,
          ),
          token: _t64,
        );
      final srv = await _listen(_server(pr: pr));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://portal.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));

  // 429 - budgets over an unread body
  cases.add((
    code: 'origin_rate_limited',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist(listedQuota: 1)));
      final (st, _) = await _post(srv.port, origin: 'https://portal.example');
      assert(st == 200);
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://portal.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'token_locked',
    preBody: true,
    run: () async {
      final pr = _closed()..update(token: _t64);
      final srv = await _listen(_server(pr: pr));
      // خمس إخفاقات كاملة تملى نافذة القفل للأصل نفسه
      for (var i = 0; i < 5; i++) {
        await _post(
          srv.port,
          origin: 'https://guess.example',
          token: 'WRONG$i',
        );
      }
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://guess.example', token: 'WRONG6'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));

  // 503 - disposal and the documented immediate-cut busy gate
  cases.add((
    code: 'protection_disposed',
    preBody: true,
    run: () async {
      final pr = _allowlist();
      final srv = await _listen(_server(pr: pr));
      pr.dispose();
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://portal.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));
  cases.add((
    code: 'server_busy',
    preBody: true,
    run: () async {
      final entered = <Completer<void>>[];
      final releases = <Completer<CommandOutcome>>[];
      final srv = await _listen(
        _server(
          pr: _allowlist(),
          onCommand: (cmd) {
            entered.add(Completer<void>()..complete());
            final release = Completer<CommandOutcome>();
            releases.add(release);
            return release.future;
          },
        ),
      );
      // ستة عشر مقعداً ممسوكة بمعالجات لا تكمل، والسابع عشر بجسم ناقص
      final holders = <Future<(int, String)>>[];
      for (var i = 0; i < 16; i++) {
        holders.add(_post(srv.port, origin: 'https://portal.example'));
      }
      final sw = Stopwatch()..start();
      while (entered.length < 16 && sw.elapsed < const Duration(seconds: 5)) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://portal.example'),
      );
      return _Walk(srv, link, () async {
        for (final r in releases) {
          if (!r.isCompleted) r.complete(const CommandOutcome(ok: true));
        }
        for (final f in holders) {
          await f.timeout(const Duration(seconds: 5), onTimeout: () => (0, ''));
        }
      }, preBody: true);
    },
  ));

  // 413 - the declared-length gate is pre-read
  cases.add((
    code: 'payload_too_large',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://portal.example', cl: 1024 * 1024 + 1),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));

  // 415 - post-admission, still pre-read
  cases.add((
    code: 'unsupported_media_type',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(
          srv.port,
          origin: 'https://portal.example',
          contentType: 'application/xml',
        ),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));

  // 408 - the read deadline over a stalled declared body (managed close
  // over the paused read, reply delivered first)
  cases.add((
    code: 'request_timeout',
    preBody: true,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.open(
        srv.port,
        _head(srv.port, origin: 'https://portal.example'),
      );
      return _Walk(srv, link, () async {}, preBody: true);
    },
  ));

  // Read-body rejections: full bodies, dead connections after the reply
  cases.add((
    code: 'invalid_utf8',
    preBody: false,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.openRaw(
        srv.port,
        _head(srv.port, origin: 'https://portal.example', cl: 3),
        [0xFF, 0xFE, 0x61],
      );
      return _Walk(srv, link, () async {}, preBody: false);
    },
  ));
  cases.add((
    code: 'payload_too_complex',
    preBody: false,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.openFull(
        srv.port,
        _head(srv.port, origin: 'https://portal.example', cl: 66),
        utf8.encode('${'[' * 33}${']' * 33}'),
      );
      return _Walk(srv, link, () async {}, preBody: false);
    },
  ));
  cases.add((
    code: 'unsupported_payload_shape',
    preBody: false,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.openFull(
        srv.port,
        _head(srv.port, origin: 'https://portal.example', cl: 15),
        utf8.encode('{"unknown":"x"}'),
      );
      return _Walk(srv, link, () async {}, preBody: false);
    },
  ));
  cases.add((
    code: 'empty_payload',
    preBody: false,
    run: () async {
      final srv = await _listen(_server(pr: _allowlist()));
      final link = await _Link.openFull(
        srv.port,
        _head(srv.port, origin: 'https://portal.example', cl: 2),
        utf8.encode('[]'),
      );
      return _Walk(srv, link, () async {}, preBody: false);
    },
  ));
  cases.add((
    code: 'handler_timeout',
    preBody: false,
    run: () async {
      final hang = Completer<CommandOutcome>();
      final srv = await _listen(
        _server(
          pr: _allowlist(),
          handlerTimeout: const Duration(milliseconds: 150),
          onCommand: (cmd) => hang.future,
        ),
      );
      final link = await _Link.openFull(
        srv.port,
        _head(srv.port, origin: 'https://portal.example', cl: 9),
        utf8.encode('["CMD"]\r\n'),
      );
      return _Walk(srv, link, () async {
        // اليتيم يُحل قبل التفكيك فيفرغ بلا انتظار
        if (!hang.isCompleted) hang.complete(const CommandOutcome(ok: true));
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }, preBody: false);
    },
  ));

  return cases;
}

void main() {
  setUp(() {
    // ساعة نظيفة لكل شاهد
    _clockMs[0] = 0;
  });

  test('walks the whole rejection registry on the live wire: registered '
      'status, the literal code in the body, and the registered close '
      'flavor', () async {
    final pending = Map<String, IntakeRejectSpec>.of(intakeRejectionRegistry);
    expect(
      pending,
      isNotEmpty,
      reason: 'the registry is the walk subject - empty is a structural loss',
    );
    final scenarios = _scenarios();
    for (final c in scenarios) {
      final spec = pending.remove(c.code);
      expect(
        spec,
        isNotNull,
        reason: '[${c.code}] every walked code sits in the registry',
      );
      final w = await c.run();
      try {
        final reply = await w.link.readReply();
        expect(
          _statusOf(reply.head),
          contains(' ${spec!.status} '),
          reason: '[${c.code}] the registered status is the wire status',
        );
        expect(
          reply.body,
          contains('"${c.code}"'),
          reason: '[${c.code}] the literal code rides the reply body',
        );
        if (spec.immediateCut) {
          expect(
            await w.link.waitDead(limit: const Duration(seconds: 1)),
            isTrue,
            reason:
                '[${c.code}] the documented immediate cut: no drain window '
                'is spent',
          );
        } else if (w.preBody) {
          await w.link.expireAndNudge();
          expect(
            await w.link.waitDead(limit: const Duration(seconds: 3)),
            isTrue,
            reason:
                '[${c.code}] the bounded drain ends the connection after '
                'the window',
          );
        } else {
          expect(
            await w.link.waitDead(limit: const Duration(seconds: 3)),
            isTrue,
            reason:
                '[${c.code}] a read-body rejection never leaves a live '
                'connection',
          );
        }
      } finally {
        await w.release();
        w.srv.protection.dispose();
        await w.srv.stop().timeout(const Duration(seconds: 5));
      }
    }
    expect(
      pending,
      isEmpty,
      reason:
          'every registered code was walked - a registry row with no wire '
          'scenario is a dead row, and a server code with no row fails the '
          'resolver before it ever reaches this walk',
    );
  }, timeout: const Timeout(Duration(seconds: 120)));

  test('stop over fifty stuck incomplete-body sockets returns inside two '
      'seconds and every hanger is dead after the window', () async {
    final srv = _server(pr: _allowlist(), requestTimeout: null);
    await srv.start(preferredPort: 0);
    final hangers = <_Link>[];
    try {
      for (var i = 0; i < 50; i++) {
        hangers.add(
          await _Link.open(
            srv.port,
            _head(srv.port, origin: 'https://${'x' * 1100}'),
          ),
        );
      }
      for (final h in hangers) {
        await h.readReply(limit: const Duration(seconds: 5));
      }
      // النافذة لم تمض بعد: الخمسون عالقون حين يُستدعى stop
      expect(_clockMs[0], 0);
      final sw = Stopwatch()..start();
      try {
        await srv.stop().timeout(
          const Duration(seconds: 5),
          onTimeout: () => fail('stop() hung past five seconds'),
        );
      } on TimeoutException {
        fail('stop() hung past five seconds');
      }
      sw.stop();
      expect(
        sw.elapsedMilliseconds,
        lessThan(2000),
        reason: 'stop owns no drain window - the hangers hold no seat',
      );
      _clockMs[0] += 10 * 60 * 1000;
      for (final h in hangers) {
        await h.expireAndNudge();
      }
      var dead = 0;
      for (final h in hangers) {
        if (await h.waitDead(limit: const Duration(seconds: 2))) dead++;
      }
      expect(
        dead,
        50,
        reason: 'no live socket may survive stop - 50/50 must be dead',
      );
    } finally {
      for (final h in hangers) {
        h.destroy();
      }
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 60)));

  test(
    'the README wire table matches the rejection registry line for line',
    () {
      final readme = File('README.md').readAsStringSync();
      // قسم عقد السلك حصراً — لا غيره من الجداول
      const startMark = '## Wire contract';
      const endMark = '## Page-side reference';
      final start = readme.indexOf(startMark);
      final end = readme.indexOf(endMark);
      expect(start, greaterThan(0), reason: 'the wire contract section exists');
      expect(end, greaterThan(start), reason: 'the section is delimited');
      final section = readme.substring(start, end);
      final row = RegExp(r'^\|\s*(\d{3})\s*\|\s*([^|]+)\|', multiLine: true);
      final wire = <String, int>{};
      for (final m in row.allMatches(section)) {
        final status = int.parse(m.group(1)!);
        for (final c in RegExp(r'`([a-z_0-9]+)`').allMatches(m.group(2)!)) {
          final code = c.group(1)!;
          final existing = wire[code];
          if (existing != null) {
            expect(
              existing,
              status,
              reason: '$code is documented with one status only',
            );
          }
          wire[code] = status;
        }
      }
      // كل رمز في السجل موثق في جدول السلك بحالته المسجلة نفسها
      intakeRejectionRegistry.forEach((code, spec) {
        expect(
          wire[code],
          spec.status,
          reason:
              '$code must sit in the README wire table with exactly its '
              'registry status',
        );
      });
      // وكل رمز موثق إما رفض مسجل أو من عائلة نتائج المعالج الموثقة
      // (500 internal وcommand_failed الاحتياطي ورموز المضيف غير المسماة)
      const outcomeFamily = {'internal', 'command_failed'};
      wire.forEach((code, status) {
        if (intakeRejectionRegistry.containsKey(code)) return;
        expect(
          outcomeFamily.contains(code),
          isTrue,
          reason:
              '$code appears in the README wire table but sits in no registry '
              '- register it, or name it in the documented outcome family',
        );
      });
    },
  );
}
