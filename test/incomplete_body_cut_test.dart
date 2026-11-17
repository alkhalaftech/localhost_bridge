// Witness of the seven pre-seat cut paths over an incomplete declared body:
// each path answers on the wire and cuts the connection - no reply hangs
// forever and no socket survives the reply. Titles in English (published
// package); the deadlines are deterministic through the injected clock, the
// reply reader is bounded by a short timeout so a hang fails the test fast,
// and every socket is destroyed in teardown.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

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

/// Injectable monotonic clock: a single cell the server reads through
/// `nowMs`, so a test advances every deadline at once.
final _clockMs = <int>[0];

var _idSeq = 0;
String _cid() => 'cut7-${_idSeq++}';

Future<LocalIntakeServer> _startServer({
  required IntakeProtection protection,
  Future<CommandOutcome> Function(TrustedCommand cmd)? onCommand,
  Duration requestTimeout = const Duration(milliseconds: 400),
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

/// A raw POST (or OPTIONS) socket that declares `Content-Length: 100` and
/// sends a single body byte, then goes silent - the incomplete-declared-body
/// shape every witness here answers. A Dart socket is a single-subscription
/// stream, so one listener feeds both the reply reader and the dead watcher.
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
  final _reply = Completer<({String head, String body})>();
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
    if (rest.length >= cl && !_reply.isCompleted) {
      _reply.complete((head: head, body: rest.substring(0, cl)));
    }
  }

  /// The reply once the head plus its declared Content-Length body arrived,
  /// or an empty head when the bound tripped first (the red shape: no reply).
  Future<({String head, String body})> readReply({
    Duration limit = const Duration(seconds: 3),
  }) async {
    try {
      return await _reply.future.timeout(limit);
    } on TimeoutException {
      return (head: '', body: '');
    }
  }

  /// True when the server side cut the socket (EOF or an error) within the
  /// bound; false means it was still alive.
  Future<bool> waitDead({Duration limit = const Duration(seconds: 3)}) async {
    try {
      await _dead.future.timeout(limit);
      return true;
    } on TimeoutException {
      return false;
    }
  }

  /// Advances the injected clock past every window and nudges the silent
  /// sender with one byte, so the bounded drain fires its deadline check at
  /// once instead of waiting its real window.
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

/// A complete legitimate POST through HttpClient - the control request that
/// must keep being served while liar sockets exist.
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

String _statusOf(String head) => head.isEmpty ? '' : head.split('\r\n').first;

void main() {
  setUp(() {
    // a fresh clock cell per test so no test inherits another's advance
    _clockMs[0] = 0;
  });

  test('an origin_too_long reject answers over an incomplete declared body '
      'and cuts the connection', () async {
    final srv = await _startServer(protection: _allowlist());
    _Link? liar;
    try {
      liar = await _Link.open(
        srv.port,
        _postHead(srv.port, origin: 'https://${'x' * 1100}'),
      );
      final reply = await liar.readReply();
      expect(
        _statusOf(reply.head),
        contains(' 400 '),
        reason:
            'the shape gate must answer even though the body never completes',
      );
      expect(reply.body, contains('origin_too_long'));
      expect(
        await liar.waitDead(),
        isTrue,
        reason: 'the connection must cut after the reply',
      );
    } finally {
      liar?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('an origin_malformed reject answers over an incomplete declared body '
      'and cuts the connection', () async {
    final srv = await _startServer(protection: _allowlist());
    _Link? liar;
    try {
      liar = await _Link.open(
        srv.port,
        _postHead(srv.port, origin: 'https://portal.example:8443:9'),
      );
      final reply = await liar.readReply();
      expect(_statusOf(reply.head), contains(' 400 '));
      expect(reply.body, contains('origin_malformed'));
      expect(await liar.waitDead(), isTrue);
    } finally {
      liar?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('a token_too_long reject answers over an incomplete declared body '
      'and cuts the connection', () async {
    final srv = await _startServer(protection: _allowlist());
    _Link? liar;
    try {
      liar = await _Link.open(
        srv.port,
        _postHead(
          srv.port,
          origin: 'https://portal.example',
          token: 't' * 1100,
        ),
      );
      final reply = await liar.readReply();
      expect(_statusOf(reply.head), contains(' 400 '));
      expect(reply.body, contains('token_too_long'));
      expect(await liar.waitDead(), isTrue);
    } finally {
      liar?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('a duplicate_header reject answers over an incomplete declared body '
      'and cuts the connection', () async {
    final srv = await _startServer(protection: _allowlist());
    _Link? liar;
    try {
      liar = await _Link.open(
        srv.port,
        _postHead(srv.port, correlationId: 'dup-a\r\nX-Correlation-Id: dup-b'),
      );
      final reply = await liar.readReply();
      expect(_statusOf(reply.head), contains(' 400 '));
      expect(reply.body, contains('duplicate_header'));
      expect(await liar.waitDead(), isTrue);
    } finally {
      liar?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('a Host-authority reject (blocked_by_protection) answers over an '
      'incomplete declared body and cuts the connection', () async {
    final srv = await _startServer(protection: _allowlist());
    _Link? liar;
    try {
      liar = await _Link.open(
        srv.port,
        _postHead(
          srv.port,
          host: 'evil.example:${srv.port}',
          origin: 'https://portal.example',
        ),
      );
      final reply = await liar.readReply();
      expect(_statusOf(reply.head), contains(' 403 '));
      expect(
        reply.body,
        contains('"blocked_by_protection"'),
        reason:
            'the stable code sits in the reply body - the only marker '
            'that separates a DNS-rebinding attempt from an unlisted origin',
      );
      expect(await liar.waitDead(), isTrue);
    } finally {
      liar?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('the busy 503 answers over an incomplete declared body and cuts the '
      'connection', () async {
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
    _Link? liar;
    final holders = <Future<(int, String)>>[];
    try {
      // fill all sixteen seats with handlers that entered but never finish
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
        reason:
            'all sixteen handlers must be seated before the busy '
            'witness fires',
      );
      // the seventeenth request with an incomplete declared body lands on
      // the busy gate
      liar = await _Link.open(
        srv.port,
        _postHead(srv.port, origin: 'https://portal.example'),
      );
      final reply = await liar.readReply();
      expect(_statusOf(reply.head), contains(' 503 '));
      expect(reply.body, contains('server_busy'));
      expect(await liar.waitDead(), isTrue);
    } finally {
      for (final r in releases) {
        if (!r.isCompleted) r.complete(const CommandOutcome(ok: true));
      }
      for (final f in holders) {
        await f.timeout(const Duration(seconds: 5), onTimeout: () => (0, ''));
      }
      liar?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('the OPTIONS preflight answers 204 over an incomplete declared body '
      'and cuts the connection', () async {
    final srv = await _startServer(protection: _allowlist());
    _Link? liar;
    try {
      liar = await _Link.open(
        srv.port,
        _postHead(
          srv.port,
          method: 'OPTIONS',
          origin: 'https://portal.example',
        ),
      );
      final reply = await liar.readReply();
      expect(
        _statusOf(reply.head),
        contains(' 204 '),
        reason:
            'the preflight must answer even though its body never completes',
      );
      expect(
        reply.head.toLowerCase(),
        contains('access-control-allow-origin'),
        reason: 'a listed origin preflight keeps its CORS echo',
      );
      expect(reply.body, isEmpty, reason: '204 carries no body');
      expect(
        await liar.waitDead(),
        isTrue,
        reason: 'the preflight connection must cut after the reply',
      );
    } finally {
      liar?.destroy();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('sixteen incomplete-body liars across the shape gates cannot starve '
      'the next legitimate request', () async {
    final srv = await _startServer(protection: _allowlist());
    final liars = <_Link>[];
    try {
      for (final head in [
        _postHead(srv.port, origin: 'https://${'x' * 1100}'),
        _postHead(srv.port, origin: 'https://portal.example:8443:9'),
        _postHead(
          srv.port,
          origin: 'https://portal.example',
          token: 't' * 1100,
        ),
        _postHead(srv.port, correlationId: 'dup-a\r\nX-Correlation-Id: dup-b'),
      ]) {
        for (var i = 0; i < 4; i++) {
          liars.add(await _Link.open(srv.port, head));
        }
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
      final sw = Stopwatch()..start();
      final (status, body) = await _post(
        srv.port,
        origin: 'https://portal.example',
      );
      sw.stop();
      expect(status, 200, reason: 'the legitimate request must be served');
      expect(
        sw.elapsed,
        lessThan(const Duration(seconds: 1)),
        reason: 'the legitimate request must be served within a second',
      );
      expect(body, contains('"ok":true'));
      for (final l in liars) {
        await l.expireAndNudge();
      }
      var dead = 0;
      for (final l in liars) {
        if (await l.waitDead()) dead++;
      }
      expect(
        dead,
        liars.length,
        reason: 'every liar connection must be cut by the server',
      );
    } finally {
      for (final l in liars) {
        l.destroy();
      }
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 30)));
}
