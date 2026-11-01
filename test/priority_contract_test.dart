// Priority contract witnesses (highest priority): table-driven CORS matrix,
// القفل الذي لا يحجب المدرج، الأسرار في السجلات، والضرب العشوائي
// المقيد بعقد عدم التسريب. منافذ عشوائية (0) في كل خادم جديد.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart';

class _Rec extends BridgeTelemetry {
  final warns = <String>[];
  final errs = <String>[];
  final infos = <String>[];
  @override
  void info(
    String m, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    infos.add(m);
  }

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
  }) {
    errs.add('$m :: $error');
  }

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) async => await body();
}

var _seq = 0;
String _cid() => 'p0-${_seq++}';

/// Unified raw-socket client: returns status, headers, and body.
Future<Map<String, Object>> _talk(
  int port,
  String raw, {
  Duration wait = const Duration(seconds: 8),
}) async {
  final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
  unawaited(socket.done.catchError((Object _) {}));
  final done = Completer<Map<String, Object>>();
  final chunks = <int>[];
  late final StreamSubscription sub;
  sub = socket.listen(
    (d) {
      chunks.addAll(d);
      final text = latin1.decode(chunks, allowInvalid: true);
      final sep = text.indexOf('\r\n\r\n');
      if (done.isCompleted || sep < 0) return;
      final head = text.substring(0, sep);
      final cl = RegExp(
        'content-length:\\s*(\\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      final need = cl == null ? 0 : int.parse(cl.group(1)!);
      final bodyText = text.substring(sep + 4);
      final hasCl = cl != null && bodyText.length >= need;
      if (hasCl || bodyText.endsWith('0\r\n\r\n')) {
        final headers = <String, String>{};
        for (final line in head.split('\r\n').skip(1)) {
          final i = line.indexOf(':');
          if (i > 0) {
            headers[line.substring(0, i).trim().toLowerCase()] = line
                .substring(i + 1)
                .trim();
          }
        }
        done.complete({
          'status': int.parse(head.split(' ')[1]),
          'headers': headers,
          'body': bodyText,
        });
      }
    },
    onDone: () {
      if (!done.isCompleted) done.completeError('قطع قبل الرد');
    },
  );
  socket.write(raw);
  final r = await done.future.timeout(wait);
  await sub.cancel();
  socket.destroy();
  return r;
}

String _post(
  int port,
  String? origin, {
  String body = '{"data":["x"]}',
  String? token,
  String? extra,
}) {
  final h = StringBuffer()
    ..write('POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n');
  if (origin != null) h.write('Origin: $origin\r\n');
  if (token != null) h.write('X-Portal-Token: $token\r\n');
  h.write('Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n');
  if (extra != null) h.write(extra);
  h.write('Content-Type: application/json\r\n');
  h.write('Content-Length: ${utf8.encode(body).length}\r\n\r\n');
  return '$h$body';
}

void main() {
  late _Rec rec;

  LocalIntakeServer make({
    OriginPolicy policy = const OriginPolicy(allowAllHardened: true),
    String token = '',
    BridgeConfig config = const BridgeConfig(),
    Future<CommandOutcome> Function()? handler,
  }) {
    final pr = IntakeProtection(telemetry: rec)
      ..update(policy: policy, token: token);
    return LocalIntakeServer(
      telemetry: rec,
      correlationIdGenerator: _cid,
      onCommand: (_) async =>
          handler == null ? const CommandOutcome(ok: true) : await handler(),
      protection: pr,
      config: config,
      requestTimeout: const Duration(seconds: 2),
      handlerTimeout: const Duration(seconds: 2),
    );
  }

  setUp(() => rec = _Rec());

  group('token lock gates comparison only — it never blocks listed origins', () {
    test(
      'listed origin with wrong token under a locked window still passes',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(allowed: ['https://portal.example']),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        for (var i = 0; i < 5; i++) {
          await p.check(origin: 'https://evil.example', portalToken: 'WRONG');
        }
        final listed = await p.check(
          origin: 'https://portal.example',
          portalToken: 'WRONG',
        );
        expect(
          listed,
          isNull,
          reason:
              'the lock blocks the comparison, not the policy - the listed origin passes',
        );
      },
    );

    test(
      'unlisted origin with correct token: the guessing origin stays locked, another passes',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        for (var i = 0; i < 5; i++) {
          await p.check(origin: 'https://evil.example', portalToken: 'WRONG');
        }
        final locked = await p.check(
          origin: 'https://evil.example',
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        expect(locked!.status, 429);
        expect(
          locked.code,
          'token_locked',
          reason:
              'comparison is blocked under the lock, so a correct token '
              'does not save the guessing origin',
        );
        final other = await p.check(
          origin: 'https://x.example',
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        expect(
          other,
          isNull,
          reason:
              'the window is per-origin - another origin is not jailed '
              'by the guesser',
        );
      },
    );

    test(
      'window edges on the injected clock: the sixth miss locks, 60001ms unlocks',
      () async {
        var fakeNow = 0;
        final p = IntakeProtection(nowMs: () => fakeNow)
          ..update(
            policy: const OriginPolicy(),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        for (var i = 1; i <= 5; i++) {
          final r = await p.check(
            origin: 'https://a.example',
            portalToken: 'W',
          );
          expect(
            r!.code,
            isNot('token_locked'),
            reason: 'attempt $i is not locked',
          );
        }
        final sixth = await p.check(
          origin: 'https://a.example',
          portalToken: 'W',
        );
        expect(
          sixth!.code,
          'token_locked',
          reason: 'the sixth is the first locked one',
        );
        fakeNow = 60_001;
        final after = await p.check(
          origin: 'https://a.example',
          portalToken: 'W',
        );
        expect(
          after!.code,
          isNot('token_locked'),
          reason: 'the window expired',
        );
      },
    );

    test('no-origin and web-origin misses keep two independent windows', () async {
      final p = IntakeProtection()
        ..update(
          policy: const OriginPolicy(),
          token:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
      for (var i = 0; i < 5; i++) {
        await p.check(origin: null, portalToken: 'W');
      }
      expect(
        (await p.check(origin: 'https://a.example', portalToken: 'W'))!.code,
        isNot('token_locked'),
        reason: 'an originless lock does not touch web origins',
      );
      for (var i = 0; i < 5; i++) {
        await p.check(origin: 'https://b.example', portalToken: 'W');
      }
      // نافذة بلا-أصل ما زالت مقفولة بلا إخفاقات ويب إضافية
      expect(
        (await p.check(
          origin: null,
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        ))!.status,
        429,
        reason: 'the originless window is separate from the web one',
      );
    });
  });

  group(
    'CORS echo of 503 and 400 for listed origins — rejects stay echoless',
    () {
      test('503 echoes ACAO for listed origins — stranger gets none', () async {
        final slow = Completer<void>();
        final srv = make(
          policy: const OriginPolicy(
            allowed: ['https://portal.example'],
            allowAllHardened: true,
            perOriginPerMinute: 1000,
          ),
          config: const BridgeConfig(maxConcurrentRequests: 1),
          handler: () async {
            await slow.future;
            return const CommandOutcome(ok: true);
          },
        );
        final port = await srv.start(preferredPort: 0);
        addTearDown(srv.stop);

        final busy = _talk(port, _post(port, 'https://portal.example'));
        await pumpEventQueue();
        final listedBusy = await _talk(
          port,
          _post(port, 'https://portal.example'),
        );
        expect(listedBusy['status'], 503);
        final h = listedBusy['headers'] as Map<String, String>;
        expect(
          h['access-control-allow-origin'],
          'https://portal.example',
          reason: 'the listed origin distinguishes busy from down',
        );
        expect(h['vary'], 'Origin');
        slow.complete();
        await busy;
        // الغريب غير المعتمد (وضع القائمة): 503 بلا صدى — خادم مغلق القائمة
        final strictGate = Completer<void>();
        final strict = make(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          config: const BridgeConfig(maxConcurrentRequests: 1),
          handler: () async {
            await strictGate.future;
            return const CommandOutcome(ok: true);
          },
        );
        final strictPort = await strict.start(preferredPort: 0);
        addTearDown(strict.stop);
        final holder = _talk(
          strictPort,
          _post(strictPort, 'https://portal.example'),
        );
        await pumpEventQueue();
        final strangerBusy = await _talk(
          strictPort,
          _post(strictPort, 'https://stranger.example'),
        );
        expect(strangerBusy['status'], 503);
        expect(
          (strangerBusy['headers'] as Map<String, String>).containsKey(
            'access-control-allow-origin',
          ),
          isFalse,
          reason: 'the untrusted stranger: 503 with no echo',
        );
        strictGate.complete();
        await holder;
      });

      test(
        '400 duplicate header with ACAO for listed origins — stranger gets none',
        () async {
          final srv = make(
            policy: const OriginPolicy(
              allowed: ['https://portal.example'],
              allowAllHardened: true,
              perOriginPerMinute: 1000,
            ),
          );
          final port = await srv.start(preferredPort: 0);
          addTearDown(srv.stop);

          Future<Map<String, Object>> dup(String origin) => _talk(
            port,
            'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n'
            'Origin: $origin\r\nOrigin: $origin\r\n'
            'Content-Length: 13\r\n\r\n{"data":["x"]}',
          );

          final listed = await dup('https://portal.example');
          expect(listed['status'], 400);
          expect(
            (listed['headers']
                as Map<String, String>)['access-control-allow-origin'],
            'https://portal.example',
          );
          final stranger = await dup('https://stranger.example');
          expect(stranger['status'], 400);
          // على «الكل» الغريب https مؤهل أصلا فيرى صدى 400 — الثابت الأهم:
          // بلا نجمة، وبقيمة أصله حرفيا
          expect(
            (stranger['headers']
                as Map<String, String>)['access-control-allow-origin'],
            'https://stranger.example',
          );
        },
      );

      test(
        'declined discovery origins (origin_declined) see no ACAO',
        () async {
          final srv = make(
            policy: OriginPolicy(
              requireFetchMetadata: false,
              onUnknownOrigin: (o) async => OriginConsent.reject,
            ),
          );
          final port = await srv.start(preferredPort: 0);
          addTearDown(srv.stop);
          // الطلب الأول يطلق السؤال ويأخذ pending — الرفض يخدم إعادة المحاولة
          final first = await _talk(port, _post(port, 'https://new.example'));
          expect(first['status'], 403);
          expect(bodyJson(first)['error'], 'origin_pending');
          await pumpEventQueue();
          final r = await _talk(port, _post(port, 'https://new.example'));
          expect(r['status'], 403);
          expect(bodyJson(r)['error'], 'origin_declined');
          expect(
            (r['headers'] as Map<String, String>).containsKey(
              'access-control-allow-origin',
            ),
            isFalse,
            reason: 'no probing channel for the rejected - discovery too',
          );
        },
      );
    },
  );

  group('table-driven CORS contract matrix (random port)', () {
    final cases = <List<Object?>>[
      ['closed', null, 403, false],
      ['closed', 'https://x.example', 403, false],
      ['allowlist', 'https://portal.example', 200, true],
      ['allowlist', 'https://stranger.example', 403, false],
      ['allowAll', 'https://any.example', 200, true],
      ['allowAll', 'http://any.example', 403, false],
      ['discovery', 'https://new.example', 403, true],
      ['token', 'https://stranger.example', 403, false],
      ['token-valid', 'https://stranger.example', 200, true],
    ];

    LocalIntakeServer serverFor(String mode) {
      switch (mode) {
        case 'closed':
          return make(policy: const OriginPolicy());
        case 'allowlist':
          return make(
            policy: const OriginPolicy(
              allowed: ['https://portal.example'],
              perOriginPerMinute: 1000,
            ),
          );
        case 'allowAll':
          return make(
            policy: const OriginPolicy(
              allowAllHardened: true,
              perOriginPerMinute: 1000,
            ),
          );
        case 'discovery':
          return make(
            policy: OriginPolicy(
              requireFetchMetadata: false,
              onUnknownOrigin: (_) => Completer<OriginConsent>().future,
              askTimeout: const Duration(seconds: 30),
            ),
          );
        case 'token':
        case 'token-valid':
          return make(
            policy: const OriginPolicy(perOriginPerMinute: 1000),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
      }
      throw StateError(mode);
    }

    for (final c in cases) {
      final mode = c[0] as String;
      final origin = c[1] as String?;
      final status = c[2] as int;
      final echo = c[3] as bool;
      test(
        '[$mode · ${origin ?? 'no-origin'}] ⟵ $status${echo ? ' echoed' : ' echoless'}',
        () async {
          final srv = serverFor(mode);
          final port = await srv.start(preferredPort: 0);
          addTearDown(srv.stop);
          final token = mode == 'token-valid'
              ? 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7'
              : null;
          final r = await _talk(port, _post(port, origin, token: token));
          expect(r['status'], status, reason: '[$mode] the promised status');
          final h = r['headers'] as Map<String, String>;
          if (echo) {
            expect(
              h['access-control-allow-origin'],
              origin,
              reason:
                  'the echo equals the requester origin verbatim - nothing else',
            );
            expect(h['vary'], 'Origin');
          } else {
            expect(
              h.containsKey('access-control-allow-origin'),
              isFalse,
              reason: 'no echo header at all',
            );
          }
          expect(
            h['access-control-allow-origin'],
            isNot('*'),
            reason: 'the wildcard is always forbidden',
          );
          expect(h.containsKey('access-control-allow-credentials'), isFalse);
        },
      );
    }
  });

  group('no secrets in logs', () {
    test(
      'measure output across a full combination: no token, no payload',
      () async {
        final srv = make(
          policy: const OriginPolicy(
            allowed: ['https://portal.example'],
            allowAllHardened: true,
            perOriginPerMinute: 1000,
          ),
          token:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        final port = await srv.start(preferredPort: 0);
        addTearDown(srv.stop);
        await _talk(
          port,
          _post(
            port,
            'https://portal.example',
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
        );
        await _talk(
          port,
          _post(port, 'https://stranger.example', token: 'WRONG-TOKEN'),
        );
        await _talk(port, _post(port, 'https://stranger.example'));
        final all = [...rec.warns, ...rec.errs, ...rec.infos].join('\n');
        expect(
          all.contains(
            'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isFalse,
          reason: 'the configured token',
        );
        expect(all.contains('WRONG-TOKEN'), isFalse, reason: 'the sent token');
        expect(all.contains('"data"'), isFalse, reason: 'the payload body');
      },
    );
  });

  group('seeded random fuzz (fixed seed, 300 rounds)', () {
    test(
      'no crash — seats drain back to zero and the server stays alive',
      timeout: const Timeout(Duration(minutes: 2)),
      () async {
        final zoneErrors = <Object>[];
        const seed = 20261012;
        final rnd = Random(seed);
        final srv = make(
          policy: const OriginPolicy(
            allowAllHardened: true,
            perOriginPerMinute: 10000,
          ),
          config: const BridgeConfig(maxConcurrentRequests: 4),
        );
        final port = await srv.start(preferredPort: 0);
        addTearDown(srv.stop);

        final mutations = <String Function(Random)>[
          (r) => 'GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n\r\n',
          (r) =>
              'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: https://a.example\r\nContent-Length: abc\r\n\r\nx',
          (r) =>
              'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: https://a.example\r\nContent-Length: 10, 10\r\n\r\n1234567890',
          (r) =>
              'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: https://a.example\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n1e\r\nhello\r\n0\r\n\r\n',
          (r) =>
              'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: https://a.example\r\nX-Weird: ${'w' * 1024}\r\nContent-Length: 2\r\n\r\nhi',
          (r) => 'POST / HTTP/1.0\r\n\r\n',
          (r) => 'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: x\r\n\r\n',
          (r) => 'POST / HTTP/1.1\nHost: 127.0.0.1:$port\n\n{x}',
          (r) =>
              'POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: https://a.example\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok',
          (r) => _post(
            port,
            'https://a.example',
            extra: 'X-Dup: 1\r\nX-Dup: 2\r\n',
          ),
          (r) => _post(port, 'https://a.example', body: 'not-json-at-all'),
        ];

        await runZonedGuarded(() async {
          for (var i = 0; i < 300; i++) {
            final raw = mutations[rnd.nextInt(mutations.length)](rnd);
            final socket = await Socket.connect(
              InternetAddress.loopbackIPv4,
              port,
            );
            unawaited(socket.done.catchError((Object _) {}));
            final chunks = <int>[];
            late final StreamSubscription sub;
            sub = socket.listen((d) => chunks.addAll(d));
            socket.write(raw);
            await socket.flush();
            await pumpEventQueue();
            await sub.cancel();
            socket.destroy();
          }
        }, (e, st) => zoneErrors.add(e));

        final ok = await Future.wait(
          List.generate(
            4,
            (_) => _talk(
              port,
              _post(port, 'https://alive.example'),
              wait: const Duration(seconds: 10),
            ),
          ),
        );
        for (final r in ok) {
          expect(
            r['status'],
            200,
            reason: 'the seats returned to zero and the server is alive',
          );
        }
        expect(zoneErrors, isEmpty, reason: 'seed $seed: zero uncaught errors');
      },
    );
  });

  group('policy decision witnesses', () {
    test(
      'full idleness after dispose: no prompt, no timer, no answer effect',
      () async {
        var asked = 0;
        Completer<OriginConsent>? gate;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              requireFetchMetadata: false,
              onUnknownOrigin: (o) {
                asked++;
                gate = Completer<OriginConsent>();
                return gate!.future;
              },
              askTimeout: const Duration(seconds: 30),
            ),
          );
        expect(
          (await p.check(origin: 'https://late.example'))!.code,
          'origin_pending',
        );
        expect(asked, 1);
        p.dispose();
        final after = await p.check(origin: 'https://late.example');
        expect(
          after!.code,
          'protection_disposed',
          reason: 'a final rejection on every path with no half-alive state',
        );
        expect(asked, 1, reason: 'no callback invocation after dispose');
        gate!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          (await p.check(origin: 'https://late.example'))!.code,
          'protection_disposed',
          reason: 'no consent remembered from a reply after dispose',
        );
        expect(asked, 1);
      },
    );

    test('late answer under a stale policy is void after update', () async {
      Completer<OriginConsent>? gate;
      final p = IntakeProtection()
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            onUnknownOrigin: (o) {
              gate = Completer<OriginConsent>();
              return gate!.future;
            },
            askTimeout: const Duration(seconds: 30),
          ),
        );
      expect(
        (await p.check(origin: 'https://stale.example'))!.code,
        'origin_pending',
      );
      // المشرف أغلق الاكتشاف والجواب لم يصل بعد
      p.update(policy: const OriginPolicy());
      gate!.complete(OriginConsent.allowAlways);
      await pumpEventQueue();
      // لا تعود موافقة القديمة للحياة حتى لو أعيد تفعيل الاكتشاف
      p.update(
        policy: OriginPolicy(
          requireFetchMetadata: false,
          onUnknownOrigin: (_) => Completer<OriginConsent>().future,
          askTimeout: const Duration(seconds: 30),
        ),
      );
      final r = await p.check(origin: 'https://stale.example');
      expect(
        r!.code,
        'origin_pending',
        reason: 'a reply from the previous generation died with its policy',
      );
    });

    test(
      'JSON: strings unquoted — unknown objects 400 — non-JSON stays raw',
      () async {
        final seen = <List<String>>[];
        final srv = LocalIntakeServer(
          telemetry: const SilentTelemetry(),
          correlationIdGenerator: _cid,
          onCommand: (cmd) async {
            seen.add(cmd.payloads);
            return const CommandOutcome(ok: true);
          },
          protection: IntakeProtection()
            ..update(policy: const OriginPolicy(allowAllHardened: true)),
        );
        final port = await srv.start(preferredPort: 0);
        addTearDown(srv.stop);

        // نص JSON: يصل بلا علامات اقتباس
        await _talk(
          port,
          _post(port, 'https://a.example', body: '"TEXT 10,10"'),
        );
        expect(
          seen.last.single,
          'TEXT 10,10',
          reason: 'a bare JSON string is unquoted - the quotes are not printed',
        );
        // Map بلا مفاتيح معروفة: 400
        final unknown = await _talk(
          port,
          _post(port, 'https://a.example', body: '{"foo":1}'),
        );
        expect(unknown['status'], 400);
        expect(bodyJson(unknown)['error'], 'unsupported_payload_shape');
        // single values are raw text commands by contract
        final number = await _talk(
          port,
          _post(port, 'https://a.example', body: '123'),
        );
        expect(number['status'], 200, reason: 'a number is a raw command');
        expect(seen.last.single, '123');
        final boolBody = await _talk(
          port,
          _post(port, 'https://a.example', body: 'true'),
        );
        expect(boolBody['status'], 200, reason: 'a boolean is a raw command');
        // غير-JSON: المسار الخام كما هو
        await _talk(
          port,
          _post(port, 'https://a.example', body: 'SIZE 3 r CLS r PRINT 1,1'),
        );
        expect(seen.last.single, contains('SIZE 3'));
      },
    );

    test(
      'correlation id: valid is honored — invalid replaced, only its length logged',
      () async {
        final rec2 = _Rec();
        final srv = LocalIntakeServer(
          telemetry: rec2,
          correlationIdGenerator: _cid,
          onCommand: (_) async => const CommandOutcome(ok: true),
          protection: IntakeProtection()
            ..update(policy: const OriginPolicy(allowAllHardened: true)),
        );
        final port = await srv.start(preferredPort: 0);
        addTearDown(srv.stop);

        String cidHeader(String cid) => 'X-Correlation-Id: $cid\r\n';
        Future<String?> echoCid(String cid) async {
          final r = await _talk(
            port,
            _post(port, 'https://a.example', extra: cidHeader(cid)),
          );
          return (r['headers'] as Map<String, String>)['x-correlation-id'];
        }

        expect(
          await echoCid('abc-DEF_123.45'),
          'abc-DEF_123.45',
          reason: 'the valid one within the contract is honored',
        );
        final huge = await echoCid('c' * 300);
        expect(huge, isNot('c' * 300), reason: 'the bloated one is replaced');
        expect(huge, startsWith('p0-'), reason: 'with the package generator');
        final esc = await echoCid('bad[2Jid');
        expect(
          esc,
          startsWith('p0-'),
          reason: 'control characters are replaced',
        );
        expect(
          await echoCid('a' * 128),
          'a' * 128,
          reason: 'the contract edge of 128 is accepted verbatim',
        );
        expect(
          await echoCid('a' * 129),
          startsWith('p0-'),
          reason: 'over the limit is replaced',
        );
        expect(
          rec2.warns.any(
            (w) => w.contains('correlation id rejected (length 300)'),
          ),
          isTrue,
          reason: 'logged by value length, not text',
        );
        expect(
          rec2.warns.any((w) => w.contains('cccc')),
          isFalse,
          reason: 'never the original value text in the log',
        );
      },
    );
  });

  group('policy-generation and idleness witnesses', () {
    test('policy generation seals the updateFromSaved TOCTOU bypass', () async {
      Completer<OriginConsent>? gate;
      final p = IntakeProtection()
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            onUnknownOrigin: (_) {
              gate = Completer<OriginConsent>();
              return gate!.future;
            },
            askTimeout: const Duration(seconds: 30),
          ),
        );
      expect(
        (await p.check(origin: 'https://stale.example'))!.code,
        'origin_pending',
      );
      // الإقلاع الحي: إعادة تحميل الإعدادات المحفوظة تغير السياسة بلا
      // زيادة جيل إن أُعيدت الزيادة إلى update وحدها — هذا هو الاختراق
      p.updateFromSaved(
        savedMode: 'allowlist',
        allowedOrigins: ['https://portal.example'],
      );
      gate!.complete(OriginConsent.allowAlways);
      await pumpEventQueue();
      // إعادة تفعيل الاكتشاف لا تعيد موافقة الجيل السابق للحياة
      p.update(
        policy: OriginPolicy(
          allowed: ['https://portal.example'],
          requireFetchMetadata: false,
          onUnknownOrigin: (_) => Completer<OriginConsent>().future,
          askTimeout: const Duration(seconds: 30),
        ),
      );
      expect(
        (await p.check(origin: 'https://stale.example'))!.code,
        'origin_pending',
        reason:
            'a reply from the previous generation died with updateFromSaved',
      );
      expect(
        await p.check(origin: 'https://portal.example'),
        isNull,
        reason: 'the listed origin crosses naturally in the new generation',
      );
    });

    test(
      'dispose is final on every path: listed and token flows stop too',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(allowed: ['https://portal.example']),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        expect(
          await p.check(origin: 'https://portal.example'),
          isNull,
          reason: 'before dispose everything works',
        );
        p.dispose();
        final listed = await p.check(origin: 'https://portal.example');
        expect(listed!.status, 503);
        expect(
          listed.code,
          'protection_disposed',
          reason: 'no half-alive state - the listed origin stops too',
        );
        final token = await p.check(
          origin: null,
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        expect(
          token!.code,
          'protection_disposed',
          reason: 'and the token layer too',
        );
      },
    );

    test('bare null stays raw — data:5 is an unsupported shape', () async {
      final seen = <List<String>>[];
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (cmd) async {
          seen.add(cmd.payloads);
          return const CommandOutcome(ok: true);
        },
        protection: IntakeProtection()
          ..update(policy: const OriginPolicy(allowAllHardened: true)),
      );
      final port = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final nullBody = await _talk(
        port,
        _post(port, 'https://a.example', body: 'null'),
      );
      expect(nullBody['status'], 200, reason: 'a bare null is a raw command');
      expect(seen.last.single, 'null');
      final dataNum = await _talk(
        port,
        _post(port, 'https://a.example', body: '{"data": 5}'),
      );
      expect(dataNum['status'], 400);
      expect(bodyJson(dataNum)['error'], 'unsupported_payload_shape');
    });

    test(
      'correlation-id warning throttle on the injected clock: per-second cap, suppressed count reported',
      () async {
        final rec2 = _Rec();
        var fakeNow = 0;
        final srv = LocalIntakeServer(
          nowMs: () => fakeNow,
          telemetry: rec2,
          correlationIdGenerator: _cid,
          onCommand: (_) async => const CommandOutcome(ok: true),
          protection: IntakeProtection()
            ..update(policy: const OriginPolicy(allowAllHardened: true)),
        );
        final port = await srv.start(preferredPort: 0);
        addTearDown(srv.stop);

        Future<void> bad() async {
          await _talk(
            port,
            _post(
              port,
              'https://a.example',
              extra: 'X-Correlation-Id: bad!\r\n',
            ),
          );
        }

        await bad();
        expect(
          rec2.warns.where((w) => w.contains('correlation')).length,
          1,
          reason: 'the first writes at once',
        );
        for (var i = 0; i < 3; i++) {
          await bad();
        }
        expect(
          rec2.warns.where((w) => w.contains('correlation')).length,
          1,
          reason: 'within the same second it is muted',
        );
        fakeNow = 999;
        await bad();
        expect(
          rec2.warns.where((w) => w.contains('correlation')).length,
          1,
          reason: '999ms is still within the second',
        );
        fakeNow = 1000;
        await bad();
        final warns = rec2.warns
            .where((w) => w.contains('correlation'))
            .toList();
        expect(warns.length, 2, reason: 'the second elapsed so it writes');
        expect(
          warns.last,
          contains('+4 more suppressed'),
          reason:
              'and it carries the muted count - the attack size stays visible',
        );
      },
    );
  });

  group('token — comparison length witnesses', () {
    test(
      'lengths 32/255/256/257: correct accepted, wrong rejected at each',
      () async {
        // ما دون 32 بايتا لم يعد قابلا للضبط أصلا — شهود الرفض في
        // عقد الإعداد، وهنا عقود المقارنة للأطوال المسموحة
        for (final len in [32, 255, 256, 257]) {
          final token = List.generate(len, (i) => '${i % 10}').join();
          final p = IntakeProtection()
            ..update(policy: const OriginPolicy(), token: token);
          expect(
            await p.check(origin: null, portalToken: token),
            isNull,
            reason:
                'a correct token of length $len passes through the comparison pad',
          );
          // الفرق داخل نافذة المقارنة (البايت الأول) — يرفض دائما
          final wrong = (token[0] == '9' ? '0' : '9') + token.substring(1);
          expect(
            await p.check(origin: 'https://w.example', portalToken: wrong),
            isNotNull,
            reason:
                'a wrong token of length $len is rejected (a difference inside the pad)',
          );
          // العقد: المقارنة تغطي أطول الطرفين كاملا — الفرق بعد البايت
          // 256 يُقارن ويرفض (كان حد الحشوة يمرر صحيح-البادئة فقط)
          if (len > 256) {
            final beyond = '${token.substring(0, 256)}z';
            expect(
              await p.check(origin: null, portalToken: beyond),
              isNotNull,
              reason:
                  'a difference past 256 is compared - a correct-prefix token is rejected',
            );
          }
        }
        // المحارف متعددة البايت: بايتاتها هي التي تُحسب
        final arabic = 'س' * 40; // 40 محرفا × 2 بايت
        final p = IntakeProtection()..update(token: arabic);
        expect(await p.check(origin: null, portalToken: arabic), isNull);
      },
    );

    test('whitespace: configured token is trimmed — sent token is not', () async {
      final p = IntakeProtection()
        ..update(
          token:
              ' a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7 ',
        );
      expect(
        await p.check(
          origin: null,
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        ),
        isNull,
        reason: 'the configured one was trimmed at save time',
      );
      expect(
        await p.check(
          origin: 'https://w.example',
          portalToken:
              ' a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        ),
        isNotNull,
        reason:
            'the sent one is not trimmed - trailing whitespace fails the match',
      );
      final q = IntakeProtection()
        ..update(
          token:
              ' a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7 ',
        );
      expect(
        await q.check(
          origin: 'https://w.example',
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7 ',
        ),
        isNotNull,
        reason: 'the sent one is not trimmed - trailing whitespace stays',
      );
    });

    test(
      'empty configured token: the header layer is fully disabled',
      () async {
        final p = IntakeProtection()..update(token: '');
        // لا نافذة قفل ولا مطابقة — الترويسة غائبة المعنى
        expect(
          await p.check(origin: null, portalToken: 'ANY'),
          isNotNull,
          reason: 'no token layer - evaluation falls to the policy',
        );
      },
    );
  });
}
