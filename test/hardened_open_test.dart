// شهود «الكل» المحصَّن الثمانية
// وشاهد استقرار الذاكرة : كلها عبر مقبس خام ضد الخادم الحي.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _counterId() => 'hard-${_idSeq++}';

/// Theil-Sen estimator: the median of all pairwise slopes. The witness
/// reads the RSS of the whole test process, and other files' isolates
/// allocate and free concurrently, so any two raw points can jump tens of
/// MB on a burst with no leak at all. A median needs a majority of the
/// samples to bend before it moves, which is why the leak guard is a
/// robust slope over many samples instead of deltas between three of
/// them.
double _theilSenSlope(List<int> ys, List<double> xs) {
  final slopes = <double>[];
  for (var i = 0; i < ys.length; i++) {
    for (var j = i + 1; j < ys.length; j++) {
      slopes.add((ys[j] - ys[i]) / (xs[j] - xs[i]));
    }
  }
  slopes.sort();
  final mid = slopes.length ~/ 2;
  return slopes.length.isOdd
      ? slopes[mid]
      : (slopes[mid - 1] + slopes[mid]) / 2;
}

class _Rec extends BridgeTelemetry {
  final warns = <String>[];
  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    warns.add(message);
  }

  @override
  void error(
    String message, {
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

void main() {
  late _Rec rec;

  LocalIntakeServer makeServer({
    OriginPolicy policy = const OriginPolicy(allowAllHardened: true),
    Future<CommandOutcome> Function()? handler,
  }) => LocalIntakeServer(
    telemetry: rec,
    correlationIdGenerator: _counterId,
    onCommand: (_) async =>
        handler == null ? const CommandOutcome(ok: true) : await handler(),
    protection: IntakeProtection(telemetry: rec)..update(policy: policy),
  );

  setUp(() => rec = _Rec());

  /// Raw exchange returning status and body - understands CL and chunked encoding.
  Future<Map<String, Object>> send(
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
        // لا استقرار مبكرا: بلا CL ننتظر خاتمة الترميز المقطوع
        final hasCl = cl != null && bodyText.length >= need;
        if (hasCl || bodyText.endsWith('0\r\n\r\n')) {
          done.complete({
            'status': int.parse(head.split(' ')[1]),
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

  /// Raw exchange returning status, headers, and body together.
  Future<Map<String, Object>> rawWithHeaders(
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

  String post(
    int port, {
    String? origin,
    String? extra,
    String body = '{"data":["x"]}',
    String? fetchMode = 'cors',
    String? fetchDest = 'empty',
  }) {
    final h = StringBuffer()
      ..write('POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n');
    if (origin != null) h.write('Origin: $origin\r\n');
    if (fetchMode != null) h.write('Sec-Fetch-Mode: $fetchMode\r\n');
    if (fetchDest != null) h.write('Sec-Fetch-Dest: $fetchDest\r\n');
    if (extra != null) h.write(extra);
    h.write('Content-Type: application/json\r\n');
    h.write('Content-Length: ${utf8.encode(body).length}\r\n\r\n');
    return '$h$body';
  }

  test(
    'navigate and no-cors fetch modes rejected: 403 cross_site_blocked',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer();
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      final navigate = await send(
        p,
        post(
          p,
          origin: 'https://evil.example',
          fetchMode: 'navigate',
          fetchDest: 'document',
          body: 'x=1',
          extra: null,
        ),
      );
      expect(navigate['status'], 403);
      expect(navigate['body'], contains('cross_site_blocked'));

      final noCors = await send(
        p,
        post(
          p,
          origin: 'https://evil.example',
          fetchMode: 'no-cors',
          body: 'x=1',
        ),
      );
      expect(noCors['status'], 403);
      expect(noCors['body'], contains('cross_site_blocked'));
    },
  );

  test(
    'genuine cors fetch from https origin passes — 200',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer();
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await send(
        p,
        post(
          p,
          origin: 'https://portal.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
      );
      expect(
        r['status'],
        200,
        reason: 'a legitimate portal with fetch works as is',
      );
    },
  );

  test(
    'missing Sec-Fetch headers: rejected by default, pass with '
    'requireFetchMetadata off',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      // The default refuses headerless sends: a legacy browser or a hidden
      // form would otherwise fire silently through the hardened allow-all
      // path. The explicit off-switch is the only way a headerless client
      // crosses it.
      final srv = makeServer();
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final missing = await send(
        p,
        post(
          p,
          origin: 'https://any.example',
          fetchMode: null,
          fetchDest: null,
        ),
      );
      expect(missing['status'], 403);
      expect(missing['body'], contains('cross_site_blocked'));

      final off = makeServer(
        policy: const OriginPolicy(
          allowAllHardened: true,
          requireFetchMetadata: false,
        ),
      );
      final pOff = await off.start(preferredPort: 0);
      addTearDown(off.stop);
      final headerless = await send(
        pOff,
        post(
          pOff,
          origin: 'https://any.example',
          fetchMode: null,
          fetchDest: null,
        ),
      );
      expect(
        headerless['status'],
        200,
        reason: 'requireFetchMetadata: false admits headerless sends again',
      );
    },
  );

  test(
    'null, missing, and http origins all rejected — origin_blocked',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer();
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      for (final origin in ['null', null, 'http://x.example']) {
        final r = await send(p, post(p, origin: origin));
        expect(
          r['status'],
          403,
          reason: 'origin $origin is rejected on the allow-all path',
        );
        expect(r['body'], contains('origin_blocked'));
      }
    },
  );

  test(
    'per-origin quota exceeded: 429, another origin passes same moment',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer(
        policy: const OriginPolicy(
          allowAllHardened: true,
          perOriginPerMinute: 2,
        ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      expect(
        (await send(p, post(p, origin: 'https://a.example')))['status'],
        200,
      );
      expect(
        (await send(p, post(p, origin: 'https://a.example')))['status'],
        200,
      );
      final over = await send(p, post(p, origin: 'https://a.example'));
      expect(over['status'], 429);
      expect(over['body'], contains('origin_rate_limited'));
      expect(
        (await send(p, post(p, origin: 'https://b.example')))['status'],
        200,
        reason: 'the quota of one origin does not punish another',
      );
    },
  );

  test(
    'reportOnly: shape violations still 403 — only the quota is watched',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer(
        policy: const OriginPolicy(
          allowAllHardened: true,
          reportOnly: true,
          perOriginPerMinute: 1,
        ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      // شكل الطلب لا يعفى منه وضع المراقبة: نموذج مخفي (أصل A) وhttp
      // (أصل B) يرفضان دائما — لا fetch شرعيا يفشل هذه الفحوص قط
      expect(
        (await send(
          p,
          post(p, origin: 'https://a.example', fetchMode: 'navigate'),
        ))['status'],
        403,
      );
      expect(
        (await send(p, post(p, origin: 'http://b.example')))['status'],
        403,
      );
      // الحصة وحدها تُراقب: فوقها يمر 200 مع سطر كان-سيرفض
      expect(
        (await send(p, post(p, origin: 'https://c.example')))['status'],
        200,
      );
      expect(
        (await send(p, post(p, origin: 'https://c.example')))['status'],
        200,
        reason: 'over the quota still passes - watching does not reject',
      );
      expect(
        rec.warns.where((w) => w.contains('would reject')).length,
        greaterThanOrEqualTo(1),
        reason:
            'a line per would-have-been quota rejection - measurement-day data',
      );
    },
  );

  test(
    'host failure detail hidden from unapproved origin, shown to trusted one',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer(
        policy: const OriginPolicy(
          allowAllHardened: true,
          allowed: ['https://portal.example'],
          perOriginPerMinute: 1000,
        ),
        handler: () async =>
            const CommandOutcome(ok: false, errorMessage: 'SECRET-HOST-DETAIL'),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      final stranger = await send(
        p,
        post(p, origin: 'https://stranger.example'),
      );
      expect(stranger['status'], 500);
      expect(
        stranger['body'],
        contains('command_failed'),
        reason:
            'the package default code is domain-neutral - a host with '
            'an existing wire contract sets fallbackErrorCode',
      );
      expect(
        stranger['body'],
        isNot(contains('SECRET-HOST-DETAIL')),
        reason: 'host text is not exposed to the untrusted',
      );

      final trusted = await send(p, post(p, origin: 'https://portal.example'));
      expect(trusted['status'], 500);
      expect(
        trusted['body'],
        contains('SECRET-HOST-DETAIL'),
        reason: 'the listed origin is trusted - it sees the detail',
      );
    },
  );

  test(
    'four unknown-origin requests get origin_pending, hold no seats; listed served',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        config: const BridgeConfig(maxConcurrentRequests: 4),
        protection: IntakeProtection()
          ..update(
            policy: OriginPolicy(
              allowed: ['https://portal.example'],
              onUnknownOrigin: (_) => Completer<OriginConsent>().future,
              askTimeout: const Duration(seconds: 30),
            ),
          ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      // أربعة طلبات من أصل غريب: ترد فورا origin_pending بلا مقاعد محجوزة
      final evilResults = await Future.wait(
        List.generate(
          4,
          (_) async =>
              rawWithHeaders(p, post(p, origin: 'https://x.evil.example')),
        ),
      );
      for (final r in evilResults) {
        expect(r['status'], 403);
        expect(r['body'], contains('origin_pending'));
        expect(
          (r['headers'] as Map<String, String>).containsKey('retry-after'),
          isTrue,
          reason: 'the page retries after a moment',
        );
      }

      // المدرج في اللحظة نفسها: يعبر — المقاعد حرة
      final listed = await send(p, post(p, origin: 'https://portal.example'));
      expect(listed['status'], 200, reason: 'no awaiters holding seats');

      // pending يرى صداه وكشف Retry-After (الطالب أطلقه بنفسه فلا تسريب)
      final pendingEcho = await rawWithHeaders(
        p,
        post(p, origin: 'https://y.evil.example'),
      );
      expect(pendingEcho['status'], 403);
      final ph = pendingEcho['headers'] as Map<String, String>;
      expect(
        ph['access-control-allow-origin'],
        'https://y.evil.example',
        reason: 'the page must read pending and retry afterwards',
      );
      expect(
        ph['access-control-expose-headers'],
        contains('Retry-After'),
        reason: 'the browser does not expose it by default',
      );
      expect(ph['retry-after'], '2');
    },
  );

  test(
    '300 consecutive 413 rejections: RSS stays stable',
    timeout: const Timeout(Duration(minutes: 3)),
    () async {
      final srv = makeServer(
        policy: const OriginPolicy(
          allowAllHardened: true,
          perOriginPerMinute: 1000,
          requireFetchMetadata: false,
        ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      const mb = 1024 * 1024;
      // الجسم كاملا كحالة 04 المجربة: الإرسال الجزئي يخسر سباق RST أحيانا
      // (الخادم يغلق ببيانات غير مقروءة فيبتلع المتصفحُّ الرد) — هنا الشاهد
      // للذاكرة لا لموثوقية النقل، فنسلك المسار المستقر
      final headers =
          'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
          'Origin: https://agent.test\r\n'
          'Content-Type: application/json\r\n'
          'Content-Length: ${mb + 1}\r\n\r\n';
      final payload = 'x' * (mb + 1);
      final fullRequest = headers + payload;

      final sampleXs = <double>[];
      final sampleYs = <int>[];
      for (var i = 1; i <= 300; i++) {
        final socket = await Socket.connect(InternetAddress.loopbackIPv4, p);
        unawaited(socket.done.catchError((Object _) {}));
        final done = Completer<int>();
        final chunks = <int>[];
        late final StreamSubscription sub;
        sub = socket.listen((d) {
          chunks.addAll(d);
          final text = latin1.decode(chunks, allowInvalid: true);
          final sep = text.indexOf('\r\n\r\n');
          if (!done.isCompleted && sep >= 0) {
            done.complete(int.parse(text.substring(0, sep).split(' ')[1]));
          }
        });
        socket.write(fullRequest);
        final status = await done.future.timeout(const Duration(seconds: 10));
        await sub.cancel();
        socket.destroy();
        expect(status, 413);
        if (i % 20 == 0) {
          // مهلة قياس مقصودة: تهدئة تخصيصات الذاكرة قبل قراءة RSS —
          // جزء من بروتوكول الشاهد نفسه لا تسوية أحداث قابلة للضخ
          await Future<void>.delayed(const Duration(milliseconds: 200));
          sampleXs.add(i.toDouble());
          sampleYs.add(ProcessInfo.currentRss);
        }
      }
      final slopePerRejection = _theilSenSlope(sampleYs, sampleXs);
      // ignore: avoid_print
      print(
        'MEM-WITNESS samples=${sampleYs.length} '
        'first=${sampleYs.first} last=${sampleYs.last} '
        'slope=${slopePerRejection.toStringAsFixed(3)}B/rejection',
      );
      // سقف الميل: أي احتفاظ ثابت لكل رفض فوق ~0.15MiB يبني نمواً خطياً
      // يلتقطه الوسيط (تسربٌ يحتفظ بجسم الـ1MiB المرفوض لكل طلب يميل
      // نحو ~1MiB/رفض ≈ 300MB عبر الثلاثمئة)، بينما انفجارات العزل
      // الموازي تنزاحها أقل من أن تحرك وسيطَ الأزواج — وهي الضجيج الذي
      // أسقط دلتاي الثلاث نقاط سابقاً
      expect(
        slopePerRejection,
        lessThan(0.15 * mb),
        reason:
            'no persistent per-rejection growth: a leak retaining even a '
            'fraction of each refused 1MiB body would slope near '
            '1MiB/rejection, while the median pairwise slope ignores '
            'allocation bursts from test isolates running in parallel',
      );
    },
  );

  test(
    'no ACAO for unlisted origin; listed and allow-all echo theirs',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      // سياسة قائمة حصرا: الغريب مرفوض ولا يرى ACAO — والمدرج يرى صداه
      final srv = makeServer(
        policy: const OriginPolicy(
          allowed: ['https://portal.example'],
          perOriginPerMinute: 1000,
        ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      // غير مسموح بقائمة: 403 ولا ACAO أصلا — المتصفح يمنع القراءة
      final strangerPost = await rawWithHeaders(
        p,
        post(p, origin: 'https://stranger.example'),
      );
      expect(strangerPost['status'], 403);
      expect(
        (strangerPost['headers'] as Map<String, String>).containsKey(
          'access-control-allow-origin',
        ),
        isFalse,
        reason: 'no echo for the unlisted - the browser blocks reading',
      );

      // preflight من غير مسموح: 204 بلا ACAO
      final strangerOptions = await rawWithHeaders(
        p,
        'OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
        'Origin: https://stranger.example\r\n'
        'Access-Control-Request-Method: POST\r\n\r\n',
      );
      expect(strangerOptions['status'], 204);
      expect(
        (strangerOptions['headers'] as Map<String, String>).containsKey(
          'access-control-allow-origin',
        ),
        isFalse,
      );

      // المدرج: صدى أصله مع Vary
      final listedPost = await rawWithHeaders(
        p,
        post(p, origin: 'https://portal.example'),
      );
      final h = listedPost['headers'] as Map<String, String>;
      expect(h['access-control-allow-origin'], 'https://portal.example');
      expect(h['vary'], 'Origin');

      // ومسار «الكل»: الصالح https يُصدَّر (قادر على
      // الإرسال أصلا، والنص الحساس محجوب عنه بverboseErrorsFor)
      final all = makeServer(
        policy: const OriginPolicy(
          allowAllHardened: true,
          perOriginPerMinute: 1000,
        ),
      );
      final pAll = await all.start(preferredPort: 0);
      addTearDown(all.stop);
      final strangerOnAll = await rawWithHeaders(
        pAll,
        post(pAll, origin: 'https://stranger.example'),
      );
      expect(strangerOnAll['status'], 200);
      expect(
        (strangerOnAll['headers']
            as Map<String, String>)['access-control-allow-origin'],
        'https://stranger.example',
        reason:
            'the allow-all path echoes valid https - and the host message stays hidden from it',
      );
    },
  );

  test(
    'token-only host: a preflight from any origin carries no ACAO',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      // سياسة فارغة وتوكن مضبوط: التوكن هو المسار الوحيد، وصفحة المتصفح
      // لا تستطيع الوصول إليه — صدى الpreflight يتبع سياسة الأصول لا
      // التوكن، فلا ACAO لأي أصل مهما سأل بإرسال ترويسة التوكن
      const token =
          'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: IntakeProtection(telemetry: rec)
          ..update(policy: const OriginPolicy(), token: token),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      Future<Map<String, Object>> preflight(String origin, {String? ask}) =>
          rawWithHeaders(
            p,
            'OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
            'Origin: $origin\r\n'
            'Access-Control-Request-Method: POST\r\n'
            "${ask == null ? '' : 'Access-Control-Request-Headers: $ask\r\n'}"
            '\r\n',
          );
      for (final origin in const [
        'https://portal.example',
        'https://stranger.example',
        'http://127.0.0.1:5173',
      ]) {
        final r = await preflight(origin);
        expect(r['status'], 204);
        expect(
          (r['headers'] as Map<String, String>).containsKey(
            'access-control-allow-origin',
          ),
          isFalse,
          reason: 'an empty policy admits no origin - no ACAO for $origin',
        );
      }
      // وسؤال إرسال ترويسة التوكن نفسه يبقى بلا صدى: الإذن لا يأتي من
      // الpreflight مهما كان الأصل
      final tokenPreflight = await preflight(
        'https://portal.example',
        ask: 'Content-Type, X-Bridge-Token',
      );
      expect(tokenPreflight['status'], 204);
      expect(
        (tokenPreflight['headers'] as Map<String, String>).containsKey(
          'access-control-allow-origin',
        ),
        isFalse,
        reason:
            'the page cannot present the token through CORS either - '
            'the echo follows the origin policy, not the token',
      );
    },
  );

  test(
    'origin_rate_limited 429 echoes CORS: the page reads the code and '
    'Retry-After',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer(
        policy: const OriginPolicy(
          allowAllHardened: true,
          perOriginPerMinute: 1,
        ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      expect(
        (await send(p, post(p, origin: 'https://a.example')))['status'],
        200,
      );
      final limited = await rawWithHeaders(
        p,
        post(p, origin: 'https://a.example'),
      );
      expect(limited['status'], 429);
      expect(limited['body'], contains('origin_rate_limited'));
      final h = limited['headers'] as Map<String, String>;
      expect(
        h['access-control-allow-origin'],
        'https://a.example',
        reason:
            'without the echo the browser hides the code and the honest '
            'Retry-After from the retrying page',
      );
      expect(h['access-control-expose-headers'], contains('Retry-After'));
      expect(h.containsKey('retry-after'), isTrue);
    },
  );

  test(
    'token_locked 429 echoes CORS: the page reads the code and Retry-After',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      // Discovery policy + token: the unknown valid origin sits on the
      // consent path (origin_pending 403), so a guessing origin accumulates
      // misses until the per-origin lock answers 429 token_locked — and the
      // page must still be able to read the code and the honest wait.
      const token =
          'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: IntakeProtection(telemetry: rec)
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (_) => Completer<OriginConsent>().future,
              askTimeout: const Duration(seconds: 30),
            ),
            token: token,
          ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      for (var i = 0; i < 5; i++) {
        expect(
          (await send(
            p,
            post(
              p,
              origin: 'https://a.example',
              extra: 'X-Bridge-Token: wrong$i\r\n',
            ),
          ))['status'],
          403,
        );
      }
      final locked = await rawWithHeaders(
        p,
        post(
          p,
          origin: 'https://a.example',
          extra: 'X-Bridge-Token: wrong\r\n',
        ),
      );
      expect(locked['status'], 429);
      expect(locked['body'], contains('token_locked'));
      final h = locked['headers'] as Map<String, String>;
      expect(
        h['access-control-allow-origin'],
        'https://a.example',
        reason: 'the locked page must read the code and the honest wait',
      );
      expect(h['access-control-expose-headers'], contains('Retry-After'));
      expect(h.containsKey('retry-after'), isTrue);
    },
  );
}
