// عقد السلك (§5.5): الأسلاف عبر الخادم كاملاً لا دوال مفردة —
// replays corpus cases against the package and writes the output for differential comparison التفاضلية
// (المخرج: tools/bridge-differential/out/new-<date>.json — بنية corpus نفسها).
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson;

// output goes to the system temp dir (differential tooling was removed).
final _outPath = '${Directory.systemTemp.path}/bridge-wire-new.json';
const _timeout = Duration(milliseconds: 700);
const _pMain = 31991, _pSlow = 31992;

/// A realistic configured token: 32 random bytes hex-encoded - the floor
/// update() enforces and the shape generatePortalToken() produces.
const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

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
String _counterId() => 'corp-${_idSeq++}';

Future<Map<String, Object?>> _exchange(
  int port,
  String request, {
  Duration wait = const Duration(seconds: 4),
}) async {
  final socket = await Socket.connect('127.0.0.1', port);
  final buffer = BytesBuilder();
  final done = Completer<Map<String, Object?>>();
  late StreamSubscription sub;
  void settle(String text) {
    final head = text.contains('\r\n\r\n')
        ? text.split('\r\n\r\n').first
        : text;
    final body = text.contains('\r\n\r\n')
        ? text.split('\r\n\r\n').skip(1).join('\r\n\r\n')
        : '';
    final statusLine = head.isEmpty ? '' : head.split('\r\n').first;
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
      'status': statusLine.isEmpty
          ? -1
          : (int.tryParse(statusLine.split(' ')[1]) ?? -1),
      'headers': headers,
      'body': body,
    });
  }

  sub = utf8.decoder
      .bind(socket)
      .listen(
        (chunk) {
          buffer.add(utf8.encode(chunk));
          final text = utf8.decode(buffer.toBytes(), allowMalformed: true);
          if (done.isCompleted) return;
          final sep = text.indexOf('\r\n\r\n');
          if (sep < 0) return;
          final head = text.substring(0, sep);
          final clMatch = RegExp(
            r'content-length:\s*(\d+)',
            caseSensitive: false,
          ).firstMatch(head);
          final bodyLen = text.length - (sep + 4);
          final chunkedEnd = text.endsWith('0\r\n\r\n');
          final hasCl =
              clMatch != null && bodyLen >= int.parse(clMatch.group(1)!);
          if (hasCl || chunkedEnd) settle(text);
        },
        onDone: () {
          if (!done.isCompleted) {
            settle(utf8.decode(buffer.toBytes(), allowMalformed: true));
          }
        },
      );
  socket.write(request);
  final result = await done.future.timeout(
    wait,
    onTimeout: () => <String, Object?>{
      'status': -2,
      'headers': <String, String>{},
      'body': 'NO-RESPONSE',
    },
  );
  await sub.cancel();
  socket.destroy();
  return result;
}

void main() {
  LocalIntakeServer? srv, slow;
  late _Rec rec;
  final dump = <String, dynamic>{};

  /// The three scenarios after the merge: hardened allow-all - the list - the token.
  IntakeProtection makeProtection(String mode, {bool trackRejections = true}) {
    final pr = IntakeProtection(telemetry: trackRejections ? rec : null);
    switch (mode) {
      case 'allowAll':
        pr.update(
          policy: const OriginPolicy(
            allowAllHardened: true,
            requireFetchMetadata: false,
            perOriginPerMinute: 1000,
          ),
        );
      case 'allowlist':
        pr.update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
        );
      case 'token':
        pr.update(
          policy: const OriginPolicy(),
          token:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
    }
    return pr;
  }

  LocalIntakeServer make({
    int delayMs = 0,
    required IntakeProtection pr,
    BridgeConfig config = const BridgeConfig(),
  }) => LocalIntakeServer(
    telemetry: rec,
    correlationIdGenerator: _counterId,
    onCommand: (cmd) async {
      if (delayMs > 0) {
        // تأخير محاكاة خادم: المعالج البطيء صناعة هذا الشاهد نفسه —
        // استبداله بمضخة الأحداث يفرغ الشاهد من معناه لا يسرعه
        await Future<void>.delayed(Duration(milliseconds: delayMs));
      }
      return const CommandOutcome(ok: true);
    },
    protection: pr,
    config: config,
    requestTimeout: _timeout,
  );

  setUp(() {
    rec = _Rec();
  });
  tearDown(() async {
    await srv?.stop();
    await slow?.stop();
    srv = null;
    slow = null;
  });

  test(
    'replays 14 corpus cases over the wire across 3 protection modes and writes the comparison output',
    timeout: const Timeout(Duration(minutes: 4)),
    () async {
      String post(
        String host,
        String body, {
        String? origin,
        String? token,
        String path = '/',
      }) {
        final h = StringBuffer()
          ..writeln('POST $path HTTP/1.1')
          ..writeln('Host: $host')
          ..writeln('Content-Type: application/json')
          ..writeln('Content-Length: ${utf8.encode(body).length}');
        if (origin != null) h.writeln('Origin: $origin');
        if (token != null) h.writeln('X-Portal-Token: $token');
        h.write('\r\n');
        return h.toString() + body;
      }

      final small = jsonEncode({
        'data': ['SIZE 3', 'CLS', 'TEXT 10,10,3,1,1,1,hello', 'PRINT 1,1'],
      });
      final over = 'x' * (1024 * 1024 + 1);
      const wrapper = 13;
      final at = '{"data":["${'x' * (1024 * 1024 - wrapper)}"]}';

      for (final mode in ['allowAll', 'allowlist', 'token']) {
        final m = mode;
        final pr = makeProtection(mode);
        srv = make(pr: pr);
        await srv!.start(
          preferredPort: _pMain,
          fallbacks: const [31997, 31998],
        );
        final p = srv!.port;

        Future<void> cap(String name, String request, String describe) async {
          final r = await _exchange(p, request);
          dump.putIfAbsent(name, () => <String, Object?>{'case': name});
          final modes =
              (dump[name]!['modes'] as Map<String, Object?>?) ??
              <String, Object?>{};
          modes[m] = {
            'request': describe,
            'response': {
              'status': r['status'],
              'headers': r['headers'],
              'body': r['body'],
            },
          };
          dump[name]!['modes'] = modes;
        }

        await cap(
          '01_valid_small',
          post(
            '127.0.0.1:$p',
            small,
            origin: 'https://portal.example',
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          'POST صالح',
        );
        await cap(
          '02_get_method',
          'GET / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n\r\n',
          'GET',
        );
        await cap(
          '03_options',
          'OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\nOrigin: https://portal.example\r\nAccess-Control-Request-Method: POST\r\n\r\n',
          'preflight',
        );
        await cap(
          '04_over_limit',
          post(
            '127.0.0.1:$p',
            over,
            origin: 'https://portal.example',
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          '1MB+1',
        );
        await cap(
          '05_at_limit',
          post(
            '127.0.0.1:$p',
            at,
            origin: 'https://portal.example',
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          '1MB بالضبط',
        );
        await cap(
          '06_silence_timeout',
          'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\nContent-Length: 500\r\nOrigin: https://portal.example\r\nX-Portal-Token: a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7\r\n\r\n',
          'جسم واعد لا يصل',
        );
        await cap(
          '08_origin_rejected',
          post(
            '127.0.0.1:$p',
            small,
            origin: 'https://evil.com',
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          'Origin خارج القائمة',
        );
        await cap(
          '09_token_wrong',
          post(
            '127.0.0.1:$p',
            small,
            origin: 'https://portal.example',
            token: 'WRONG',
          ),
          'توكن خاطئ',
        );
        await cap(
          '10_token_correct_no_origin',
          post(
            '127.0.0.1:$p',
            small,
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          'توكن صحيح بلا Origin',
        );
        await cap(
          '11_host_with_port',
          post(
            '127.0.0.1:$p',
            small,
            origin: 'https://portal.example',
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          'Host بمنفذ',
        );
        await cap(
          '12_host_evil',
          post(
            'evil.com',
            small,
            origin: 'https://portal.example',
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          'rebinding',
        );

        await cap(
          '13_absolute_form',
          'POST http://evil.com/ HTTP/1.1\r\nHost: 127.0.0.1:$p\r\nContent-Type: application/json\r\nContent-Length: ${utf8.encode(small).length}\r\nOrigin: https://portal.example\r\nX-Portal-Token: a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7\r\n\r\n$small',
          'absolute-form',
        );
        await cap(
          '14_duplicate_host',
          post(
            'first.com',
            small,
            origin: 'https://portal.example',
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          'POST بترويسة Host مكررة (الأولى first.com والأخيرة محلية) — الحزمة تضيف التكرار أدناه',
        );
        // أدرج الترويسة المكررة حرفياً كالمُصيّر: أعِد الحالة بنفس الطلب ثنائي Host
        {
          final body = small;
          final req =
              'POST / HTTP/1.1\r\nHost: first.com\r\nHost: 127.0.0.1:$p\r\n'
              'Content-Type: application/json\r\nContent-Length: ${utf8.encode(body).length}\r\n'
              'Origin: https://portal.example\r\nX-Portal-Token: a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7\r\n\r\n$body';
          final r = await _exchange(p, req);
          dump['14_duplicate_host']!['modes']![m] = {
            'request':
                'POST بترويسة Host مكررة (الأولى first.com والأخيرة محلية)',
            'response': {
              'status': r['status'],
              'headers': r['headers'],
              'body': r['body'],
            },
          };
        }

        // 7 التزامن على الخادم البطيء
        slow = make(delayMs: 250, pr: makeProtection(mode));
        await slow!.start(preferredPort: _pSlow, fallbacks: const [31998]);
        final results = await Future.wait(
          List.generate(17, (i) async {
            final body = jsonEncode({
              'data': ['PRINT $i'],
            });
            return _exchange(
              slow!.port,
              post(
                '127.0.0.1:${slow!.port}',
                body,
                origin: 'https://portal.example',
                token:
                    'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
              ),
              wait: const Duration(seconds: 5),
            );
          }),
        );
        final statuses = results.map((r) => r['status']).toList()..sort();
        dump.putIfAbsent(
          '07_concurrency_17',
          () => <String, Object?>{'case': 'concurrency_17'},
        );
        final modes7 =
            (dump['07_concurrency_17']!['modes'] as Map<String, Object?>?) ??
            <String, Object?>{};
        modes7[m] = {
          'request': '17 POST صالحة مقبضة معاً على خادم بتأخير 250ms',
          'response': {
            'counts': {
              for (final v in statuses.toSet())
                '$v': statuses.where((r) => r == v).length,
            },
            'sorted_statuses': statuses,
          },
        };
        dump['07_concurrency_17']!['modes'] = modes7;

        // شواهد §5.5 لهذا النمط
        expect(
          dump['01_valid_small']!['modes']![m]!['response']['status'],
          200,
          reason: '[$m] the healthy one passes',
        );
        expect(
          dump['04_over_limit']!['modes']![m]!['response']['status'],
          413,
          reason: '[$m] over-limit: 413',
        );
        expect(
          dump['05_at_limit']!['modes']![m]!['response']['status'],
          200,
          reason: '[$m] at-limit-exact: 200 (strictly greater)',
        );
        expect(
          dump['06_silence_timeout']!['modes']![m]!['response']['status'],
          408,
          reason: '[$m] silence: 408 with injected timeout',
        );
        expect(
          dump['12_host_evil']!['modes']![m]!['response']['status'],
          403,
          reason: '[$m] rebinding rejected in all modes ',
        );
        expect(
          dump['13_absolute_form']!['modes']![m]!['response']['status'],
          403,
          reason: '[$m] absolute-form is rejected',
        );
        expect(
          dump['11_host_with_port']!['modes']![m]!['response']['status'],
          200,
          reason:
              '[$m] a Host with a port is accepted (authorities come from the bound port)',
        );
        final counts =
            (dump['07_concurrency_17']!['modes']![m]!['response']
                    as Map)['counts']
                as Map<String, dynamic>;
        expect(counts['200'], 16, reason: '[$m] seat cap: 16 accepted');
        expect(counts['503'], 1, reason: '[$m] and the seventeenth gets 503');

        // حرّر المنفذين قبل النمط التالي (ويندوز يمنع إعادة الربط والمقبض حي)
        await srv!.stop();
        srv = null;
        await slow!.stop();
        slow = null;
        if (mode == 'allowAll') {
          expect(
            dump['03_options']!['modes']![m]!['response']['status'],
            204,
            reason: 'preflight: 204',
          );
          expect(
            dump['02_get_method']!['modes']![m]!['response']['status'],
            405,
          );
          final h =
              dump['03_options']!['modes']![m]!['response']['headers']
                  as Map<String, String>;
          // صدى أصل الطالب مع Vary — لا «*»
          expect(h['access-control-allow-origin'], 'https://portal.example');
          expect(h['vary'], 'Origin');
          expect(h['access-control-max-age'], '600');
          expect(h['access-control-allow-methods'], 'POST, OPTIONS');
          expect(
            h['access-control-allow-headers'],
            'Content-Type, X-Portal-Token, X-Correlation-Id',
          );
          expect(
            dump['14_duplicate_host']!['modes']![m]!['response']['status'],
            200,
            reason:
                'Dart folds to the last value, which is local, so it is accepted',
          );
          // «الكل» المحصَّن يقبل أي https (المدرج افتراضيا بالمعنى الجديد)
          expect(
            dump['08_origin_rejected']!['modes']![m]!['response']['status'],
            200,
            reason: 'any https crosses the allow-all path after its hardening',
          );
        }
        if (mode == 'allowlist') {
          expect(
            dump['08_origin_rejected']!['modes']![m]!['response']['status'],
            403,
            reason: 'forged origin rejected',
          );
        }
        if (mode == 'token') {
          expect(
            dump['09_token_wrong']!['modes']![m]!['response']['status'],
            403,
            reason: 'a wrong token falls to the closed policy',
          );
          expect(
            dump['10_token_correct_no_origin']!['modes']![m]!['response']['status'],
            200,
          );
        }
      }

      final outFile = File(_outPath);
      outFile.createSync(recursive: true);
      outFile.writeAsStringSync(
        const JsonEncoder.withIndent('  ').convert(dump),
      );
    },
  );

  test(
    'a real nested 1MB body over the live wire leaves the server alive',
    timeout: const Timeout(Duration(minutes: 2)),
    () async {
      // جسم متداخل حقيقياً: N فتحاً ثم N إغلاقاً = 2N بايتاً بالضبط.
      const n = 1024 * 1024 ~/ 2;
      final nested = '[' * n + ']' * n;
      expect(nested.length, 1024 * 1024, reason: 'a body of exactly 1MB');
      final pr = makeProtection('allowAll');
      srv = make(pr: pr);
      await srv!.start(preferredPort: 31996, fallbacks: const [31997]);

      final sw = Stopwatch()..start();
      final r = await _exchange(
        srv!.port,
        'POST / HTTP/1.1\r\n'
        'Host: 127.0.0.1:${srv!.port}\r\n'
        'Origin: https://agent.test\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: ${nested.length}\r\n'
        '\r\n'
        '$nested',
        wait: const Duration(seconds: 30),
      );
      sw.stop();
      // سجل النتيجة الحرفية أياً كانت — هذا شاهد قياس لا مطابقة توقّع
      final bodyStr = r['body'] as String;
      // ignore: avoid_print
      print(
        'DEPTH-WIRE status=${r['status']} '
        'elapsedMs=${sw.elapsedMilliseconds} '
        'body=${bodyStr.length > 120 ? bodyStr.substring(0, 120) : bodyStr}',
      );
      // العقد الحي: الخادم لا يموت — طلب تالٍ سليم يجاوب
      final followUp = jsonEncode({
        'data': ['ALIVE'],
      });
      final ok = await _exchange(
        srv!.port,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:${srv!.port}\r\n'
        'Origin: https://agent.test\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: ${followUp.length}\r\n\r\n'
        '$followUp',
      );
      expect(
        ok['status'],
        200,
        reason: 'the server is alive after the nested body',
      );
      // والنتيجة المسجلة نفسها تُطبع للسجل — القبول هنا على البقاء والأثر المقيس
      expect(
        r['status'],
        isNot(-2),
        reason: 'a reply arrived (no socket silence)',
      );
    },
  );

  test('rejection is not silent: origin denial is counted and logged', () async {
    final pr = makeProtection('allowAll');
    srv = make(pr: pr);
    await srv!.start(preferredPort: _pMain, fallbacks: const [31997]);
    final before = pr.rejectedCount;
    final r = await _exchange(
      srv!.port,
      'POST / HTTP/1.1\r\nHost: evil.com\r\nContent-Length: 2\r\n\r\n{}',
    );
    expect(r['status'], 403);
    expect(
      pr.rejectedCount,
      before + 1,
      reason: 'the rejection went through the same counter path',
    );
    expect(
      rec.warns.any((w) => w.contains('Request Host is not allowed')),
      isTrue,
      reason:
          'and the security log too - surfacing it to the user is up to the host',
    );
  });

  test('both 413 responses name the 1MB limit, never 0MB', () async {
    // افتراضي: «1MB» حرفياً — وكلا موقعي الرفض يشترك في _mbLabel
    final pr = makeProtection('allowAll');
    srv = make(pr: pr);
    await srv!.start(preferredPort: _pMain, fallbacks: const [31997]);
    final over = await _exchange(
      srv!.port,
      'POST / HTTP/1.1\r\n'
              'Host: 127.0.0.1:${srv!.port}\r\n'
              'Origin: https://agent.test\r\n'
              'Content-Type: application/json\r\n'
              'Content-Length: ${1024 * 1024 + 1}\r\n'
              '\r\n'
              'x' *
          (1024 * 1024 + 1),
    );
    expect(over['status'], 413);
    expect(
      over['body'],
      contains('Request body exceeds the allowed limit (1MB)'),
      reason: 'the early gate (Content-Length)',
    );
    // الحد غير القابل للتقسيم يسقط إلى البايتات — لا 0MB
    final odd = make(
      pr: makeProtection('allowAll'),
      config: const BridgeConfig(maxBodyBytes: 900 * 1024),
    );
    await odd.start(preferredPort: 31995, fallbacks: const [31997]);
    addTearDown(odd.stop);
    final overOdd = await _exchange(
      odd.port,
      'POST / HTTP/1.1\r\n'
              'Host: 127.0.0.1:${odd.port}\r\n'
              'Origin: https://agent.test\r\n'
              'Content-Type: application/json\r\n'
              'Content-Length: ${1024 * 1024 + 1}\r\n'
              '\r\n'
              'x' *
          (1024 * 1024 + 1),
    );
    expect(overOdd['status'], 413);
    expect(
      overOdd['body'],
      contains('(921600B)'),
      reason: 'a cap under a megabyte is shown in bytes, never 0MB',
    );
  });

  test(
    'compressed payloads pass through untouched (host owns decompression)',
    () async {
      final seen = <List<String>>[];
      srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (cmd) async {
          seen.add(cmd.payloads);
          return const CommandOutcome(ok: true);
        },
        protection: makeProtection('allowAll'),
        requestTimeout: _timeout,
      );
      await srv!.start(preferredPort: _pMain, fallbacks: const [31997]);
      final bomb = 'H4sIAAA${'A' * 200000}=';
      final r = await _exchange(
        srv!.port,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:${srv!.port}\r\n'
        'Origin: https://agent.test\r\n'
        'Content-Type: application/json\r\nContent-Length: ${utf8.encode(bomb).length}\r\n\r\n$bomb',
      );
      expect(r['status'], 200);
      expect(
        seen.single.single,
        bomb,
        reason:
            'the host received the same bytes - the package does not decompress',
      );
    },
  );

  test(
    'Retry-After says the real lockout window, not a generic constant',
    () async {
      final pr = IntakeProtection(telemetry: rec)
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          token: _t64,
        );
      srv = make(pr: pr);
      await srv!.start(preferredPort: 31993, fallbacks: const [31996]);
      String raw() =>
          'POST / HTTP/1.1\r\n'
          'Host: 127.0.0.1:${srv!.port}\r\n'
          'Origin: https://stranger.example\r\n'
          'Content-Type: application/json\r\nContent-Length: 2\r\n'
          'X-Portal-Token: miss-value\r\n\r\n{}';
      // خمس إخفاقات من أصل غير مدرج تملأ نافذة قفل التوكن
      for (var i = 0; i < 5; i++) {
        final r = await _exchange(srv!.port, raw());
        expect(
          r['status'],
          403,
          reason: 'before the lock the miss shows as an origin reject',
        );
      }
      final locked = await _exchange(srv!.port, raw());
      expect(locked['status'], 429);
      final headers = (locked['headers'] as Map).cast<String, String>();
      final secs = int.parse(headers['retry-after'] ?? '0');
      expect(
        secs,
        greaterThanOrEqualTo(55),
        reason: 'the lockout window is 60s - the header must say its remainder',
      );
    },
  );

  test(
    'question-budget Retry-After tells the honest multi-minute wait',
    () async {
      final pr = IntakeProtection(telemetry: rec)
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            onUnknownOrigin: (origin) async => OriginConsent.dismissed,
          ),
        );
      srv = make(pr: pr);
      await srv!.start(preferredPort: 31994, fallbacks: const [31995]);
      Future<Map<String, Object?>> fire(String origin) => _exchange(
        srv!.port,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:${srv!.port}\r\n'
        'Origin: $origin\r\n'
        'Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
      );
      // عشرة أسئلة جديدة تملأ ميزانية العشر دقائق
      for (var i = 0; i < 10; i++) {
        final r = await fire('https://o$i.example');
        expect(bodyJson(r.cast<String, Object>())['error'], 'origin_pending');
      }
      final budget = await fire('https://budget.example');
      final headers = (budget['headers'] as Map).cast<String, String>();
      final secs = int.parse(headers['retry-after'] ?? '0');
      expect(
        secs,
        greaterThan(60),
        reason: 'the budget window is 10 minutes - a 2s header would be a lie',
      );
    },
  );

  test(
    'hidden-form content types are refused while the textual gateway passes',
    () async {
      srv = make(pr: makeProtection('allowlist'));
      await srv!.start(preferredPort: 31989, fallbacks: const [31988]);
      Future<Map<String, Object?>> post(String ct, String body) => _exchange(
        srv!.port,
        'POST / HTTP/1.1\r\nHost: 127.0.0.1:${srv!.port}\r\n'
        'Origin: https://portal.example\r\n'
        '${ct.isEmpty ? '' : 'Content-Type: $ct\r\n'}'
        'Content-Length: ${utf8.encode(body).length}\r\n\r\n$body',
      );
      final form = await post('application/x-www-form-urlencoded', 'a=b');
      expect(form['status'], 415);
      expect(
        bodyJson(form.cast<String, Object>())['error'],
        'unsupported_media_type',
      );
      final multipart = await post('multipart/form-data; boundary=x', 'x');
      expect(multipart['status'], 415);
      final textual = await post('text/plain;charset=UTF-8', 'PRINT 1,1\n');
      expect(
        textual['status'],
        200,
        reason: 'the production gateway is textual - it must keep passing',
      );
      final json = await post('application/json', '["PRINT 1,1"]');
      expect(json['status'], 200);
      final absent = await post('', 'PRINT 1,1\n');
      expect(absent['status'], 200);
    },
  );
}
