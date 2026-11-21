// عقد المهلتين بعد تصحيحه: المهلة الكلية تحرس ما قبل المعالج وحرف
// الاستدعاء، ووقت المعالج عقد handlerTimeout وحده (null بلا مهلة
// إطلاقاً). العناوين بالإنجليزية (حزمة منشورة) والسلوك موصوف سلكياً
// بطلبات حقيقية ومهل قصيرة بمعاملات البناء — لا نوماً يبطئ الطقم.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

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

var _idSeq = 0;
String _cid() => 'budget-${_idSeq++}';

IntakeProtection _allowlist() {
  final pr = IntakeProtection();
  pr.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
  return pr;
}

LocalIntakeServer _server({
  required Future<CommandOutcome> Function(TrustedCommand cmd) onCommand,
  Duration requestTimeout = const Duration(milliseconds: 100),
  Duration? handlerTimeout,
  int maxConcurrentRequests = 16,
}) => LocalIntakeServer(
  telemetry: _Rec(),
  correlationIdGenerator: _cid,
  onCommand: onCommand,
  protection: _allowlist(),
  requestTimeout: requestTimeout,
  handlerTimeout: handlerTimeout,
  config: BridgeConfig(maxConcurrentRequests: maxConcurrentRequests),
);

/// طلب حقيقي عبر HttpClient يعيد (الحالة، الجسم) — وانقطاع الاتصال بلا
/// رد يُسجل (-1, '') بدل استثناء، كي يسمي الفشل الحكم لا العطل.
Future<(int, String)> _post(
  int port, {
  String origin = 'https://portal.example',
}) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', origin);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } on Object {
    return (-1, '');
  } finally {
    client.close(force: true);
  }
}

void main() {
  test(
    'a null handler budget lets a handler run past the request timeout and '
    'answer 200 - the total deadline never reaches the handler phase',
    timeout: const Timeout(Duration(seconds: 30)),
    () async {
      // ضعف المهلة مقصود نصاً: المعالج 800ms والمهلة الكلية 400ms —
      // على العقد المصحح يكمل المعالج ويُرد 200، وعلى الكود القديم
      // تحرق المهلة الكلية الاتصال عند 400ms فيُسجل -1 بلا رد (نقطة
      // القطع القديمة 400+250 اليَن تقع قبل اكتمال المعالج حتماً)
      var calls = 0;
      final srv = _server(
        requestTimeout: const Duration(milliseconds: 400),
        handlerTimeout: null,
        onCommand: (_) async {
          calls++;
          await Future<void>.delayed(const Duration(milliseconds: 800));
          return const CommandOutcome(ok: true);
        },
      );
      final port = await srv.start(preferredPort: 0);
      try {
        final (status, body) = await _post(port);
        expect(
          status,
          200,
          reason:
              'handlerTimeout: null means no handler deadline at all - the '
              'handler runs to completion and the reply is 200',
        );
        expect(body, contains('"ok":true'));
        expect(calls, 1, reason: 'the handler was invoked exactly once');
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'a handler budget longer than the request timeout answers 504 at its '
    'own deadline and counts the handler as an orphan',
    timeout: const Timeout(Duration(seconds: 30)),
    () async {
      // الميزانية 800ms أطول من المهلة الكلية 400ms عمداً: على العقد
      // المصحح يُرد 504 عند الميزانية نفسها ويُعدّ المعالج يتيماً
      // (الرفض التالي يصطدم بميزانية المقاعد+اليتامى فيرد 503)، وعلى
      // الكود القديم تحرق المهلة الكلية الاتصال عند 400ms (ونقطة القطع
      // 400+250 اليَن) قبل أن تلحق ميزانية المعالج أبداً فيُسجل -1
      // بلا رد ولا يتيم
      final never = Completer<CommandOutcome>();
      var calls = 0;
      final srv = _server(
        requestTimeout: const Duration(milliseconds: 400),
        handlerTimeout: const Duration(milliseconds: 800),
        maxConcurrentRequests: 1,
        onCommand: (_) {
          calls++;
          return never.future;
        },
      );
      final port = await srv.start(preferredPort: 0);
      final futures = <Future<(int, String)>>[];
      try {
        final (status, body) = await _post(port);
        expect(
          status,
          504,
          reason:
              'the handler budget is the only deadline over the handler - '
              'the 504 lands at the budget, not at the request timeout',
        );
        expect(body, contains('handler_timeout'));
        expect(calls, 1);

        // عدّاد اليتامى بالسلك: اليتيم حي فوق ميزانية المقعد الواحد،
        // فالتالي يُرد انشغال اليتامى قبل استدعاء معالج جديد
        futures.add(_post(port));
        final (busy, busyBody) = await futures.single;
        expect(
          busy,
          503,
          reason:
              'seats plus orphans are one live-work budget - the orphaned '
              'handler still counts against the next request',
        );
        expect(busyBody, contains('server_busy'));
        expect(
          calls,
          1,
          reason: 'the refused request never reaches the handler',
        );
      } finally {
        never.complete(const CommandOutcome(ok: true));
        for (final f in futures) {
          await f.catchError((Object _) => (-1, ''));
        }
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'sixteen handlers without a handler budget hold their seats past the '
    'request timeout - the seventeenth request is refused 503 server_busy',
    timeout: const Timeout(Duration(seconds: 30)),
    () async {
      // الانتظار بعد نقطة القطع القديمة عمداً (150ms مهلة + 250ms يَن
      // القطع): على العقد المصحح المعالجات الست عشرة تمسك مقاعدها
      // فيرد السابع عشر 503، وعلى الكود القديم تُقطع كلها عند المهلة
      // فيتحرر المقاعد ويرد السابع عشر 200 - وهذا هو انقلاب الشاهد
      final never = Completer<CommandOutcome>();
      var calls = 0;
      final srv = _server(
        requestTimeout: const Duration(milliseconds: 150),
        handlerTimeout: null,
        onCommand: (_) {
          calls++;
          return never.future;
        },
      );
      final port = await srv.start(preferredPort: 0);
      final futures = <Future<(int, String)>>[];
      try {
        for (var i = 0; i < 16; i++) {
          futures.add(_post(port));
        }
        // الانتظار حتى بلوغ المعالجات كلها (حتمي بالعدّاد لا بالساعة)
        final sw = Stopwatch()..start();
        while (calls < 16 && sw.elapsed < const Duration(seconds: 10)) {
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }
        expect(calls, 16, reason: 'all sixteen reached the handler');

        // تجاوز نقطة القطع القديمة (150 + 250 اليَن + هامش)
        await Future<void>.delayed(const Duration(milliseconds: 600));

        final (status, body) = await _post(port);
        expect(
          status,
          503,
          reason:
              'a handler with no budget holds its seat - sixteen stuck '
              'handlers exhaust the service and the next command is '
              'answered server_busy',
        );
        expect(body, contains('server_busy'));
        expect(calls, 16, reason: 'the seventeenth never reaches the handler');
      } finally {
        never.complete(const CommandOutcome(ok: true));
        for (final f in futures) {
          await f.catchError((Object _) => (-1, ''));
        }
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );
}
