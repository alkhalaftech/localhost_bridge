// شهود «الكل» المحصَّن الثمانية
// وشاهد استقرار الذاكرة : كلها عبر مقبس خام ضد الخادم الحي.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _counterId() => 'hard-${_idSeq++}';

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
      final p = await srv.start(preferredPort: 31901, fallbacks: const [31881]);
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
      final p = await srv.start(preferredPort: 31902, fallbacks: const [31881]);
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
    'missing Sec-Fetch headers pass — non-browser or old browser',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer();
      final p = await srv.start(preferredPort: 31903, fallbacks: const [31881]);
      addTearDown(srv.stop);
      final r = await send(p, post(p, origin: 'https://any.example'));
      expect(r['status'], 200);
    },
  );

  test(
    'null, missing, and http origins all rejected — origin_blocked',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = makeServer();
      final p = await srv.start(preferredPort: 31904, fallbacks: const [31881]);
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
      final p = await srv.start(preferredPort: 31905, fallbacks: const [31881]);
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
      final p = await srv.start(preferredPort: 31906, fallbacks: const [31881]);
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
      final p = await srv.start(preferredPort: 31907, fallbacks: const [31881]);
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
      final p = await srv.start(preferredPort: 31912, fallbacks: const [31881]);
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
      final p = await srv.start(preferredPort: 31908, fallbacks: const [31881]);
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

      final samples = <int>[];
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
        if (i == 100 || i == 200 || i == 300) {
          // مهلة قياس مقصودة: تهدئة تخصيصات الذاكرة قبل قراءة RSS —
          // جزء من بروتوكول الشاهد نفسه لا تسوية أحداث قابلة للضخ
          await Future<void>.delayed(const Duration(milliseconds: 200));
          samples.add(ProcessInfo.currentRss);
        }
      }
      final d1 = samples[1] - samples[0];
      final d2 = samples[2] - samples[1];
      // ignore: avoid_print
      print(
        'MEM-WITNESS rss100=${samples[0]} rss200=${samples[1]} '
        'rss300=${samples[2]} delta1=$d1 delta2=$d2',
      );
      expect(
        samples[2] - samples[0],
        lessThan(30 * mb),
        reason:
            'no linear growth: three hundred rejections and total RSS under 30MB',
      );
      // الدلتا الأولى تثبت عند الصفر حين
      // يحرر GC الشطر الأول (كانت سالبة تفجر المقارنة كذبا) — ومعها سقف
      // مطلق للشطر الثاني: الاستقرار يقاس بالنمو لا بتحرر مبكر
      final d1Clamped = d1 < 0 ? 0 : d1;
      expect(
        d2,
        lessThan(d1Clamped + 8 * mb),
        reason:
            'the second half grows no more than the first - it settles, it does not leak',
      );
      expect(
        d2,
        lessThan(20 * mb),
        reason:
            'وسقف مطلق واسع لتذبذب GC مع ملفات موازية — الحارس الكلي 30MB فوقه',
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
      final p = await srv.start(preferredPort: 31909, fallbacks: const [31881]);
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
      final pAll = await all.start(
        preferredPort: 31910,
        fallbacks: const [31881],
      );
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
}
