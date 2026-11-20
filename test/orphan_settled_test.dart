// نداء onOrphanSettled: مرة واحدة لكل استقرار يتيم — حياً في جيله أو
// متقاعداً عند عودة stop — وأخطاؤه محتواة لا تكسر الفراغ ولا السلك.
// العناوين بالإنجليزية (حزمة منشورة) والتعليقات بالعربية (قاعدة البيت).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

class _Rec extends BridgeTelemetry {
  final errors = <String>[];
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
  }) {
    errors.add(m);
  }
  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) => body();
}

var _idSeq = 0;
String _cid() => 'settled-${_idSeq++}';

IntakeProtection _allowlist() {
  final pr = IntakeProtection(telemetry: _Rec());
  pr.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
  return pr;
}

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
    'onOrphanSettled fires once per settlement, for a retired orphan too',
    timeout: const Timeout(Duration(seconds: 30)),
    () async {
      var settled = 0;
      final release = Completer<void>();
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) async {
          await release.future;
          return const CommandOutcome(ok: true);
        },
        protection: _allowlist(),
        handlerTimeout: const Duration(milliseconds: 100),
        onOrphanSettled: () => settled++,
      );
      final port = await srv.start(preferredPort: 0);
      final (status, _) = await _post(port);
      expect(
        status,
        504,
        reason: 'the held handler is orphaned at the budget',
      );
      // يتيم حي فوق الميزانية؛ stop بمهلة قصيرة تعود ويُتقاعد اليتيم
      final report = await srv.stop(timeout: const Duration(milliseconds: 50));
      expect(report.orphanHandlersStillRunning, 1);
      expect(settled, 0, reason: 'nothing settled yet');
      release.complete();
      // الاستقرار المتأخر يُدق النداء مرة واحدة بعد التقاعد أيضاً
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(
        settled,
        1,
        reason: 'the retired orphan settlement still fires the callback',
      );
      expect(srv.counters.orphanHandlers, 0);
    },
  );

  test(
    'a throwing onOrphanSettled is contained: the settlement drains and '
    'the wire never sees it',
    timeout: const Timeout(Duration(seconds: 30)),
    () async {
      final rec = _Rec();
      final release = Completer<void>();
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: _cid,
        onCommand: (_) async {
          await release.future;
          return const CommandOutcome(ok: true);
        },
        protection: _allowlist(),
        handlerTimeout: const Duration(milliseconds: 100),
        // نداء يرمي دائما — الاحتواء هو الشاهد
        onOrphanSettled: () => throw StateError('host callback boom'),
      );
      final port = await srv.start(preferredPort: 0);
      final (status, _) = await _post(port);
      expect(status, 504);
      release.complete();
      await srv.stop().timeout(const Duration(seconds: 5));
      expect(
        rec.errors.any((e) => e.contains('onOrphanSettled callback threw')),
        isTrue,
        reason: 'the throw is said once in the telemetry, not swallowed',
      );
      expect(
        srv.counters.orphanHandlers,
        0,
        reason: 'the bookkeeping drained whatever the callback did',
      );
    },
  );
}
