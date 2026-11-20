// عقد ميزانية المعالج: الافتراض محدود من config، والثابت
// noHandlerTimeout يطلب «بلا مهلة» بدل null، والسالب يُرفض وقت البناء.
// العناوين بالإنجليزية (حزمة منشورة) والتعليقات بالعربية (قاعدة البيت).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

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
  }) => body();
}

var _idSeq = 0;
String _cid() => 'budget-${_idSeq++}';

IntakeProtection _allowlist() {
  final pr = IntakeProtection(telemetry: _Rec());
  pr.update(policy: const OriginPolicy(allowed: ['https://portal.example']));
  return pr;
}

/// طلب حقيقي عبر HttpClient يعيد (الحالة، الجسم) — بنمط شاهد عقد المهلة.
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
  test('the shipped default budget is 30 seconds', () {
    expect(
      const BridgeConfig().handlerTimeout,
      const Duration(seconds: 30),
      reason:
          'the default budget bounds a stuck handler at half a minute - '
          'the seat and the stop wait are never unbounded again',
    );
  });

  test(
    'a handler longer than the configured default budget answers 504 '
    'handler_timeout with no explicit handlerTimeout parameter',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      // المعامل null ⟵ ميزانية config الافتراضية (هنا 300ms للقياس):
      // المعالج الأطول منها يُرد 504 handler_timeout بلا معامل صريح
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) async {
          await Future<void>.delayed(const Duration(milliseconds: 900));
          return const CommandOutcome(ok: true);
        },
        protection: _allowlist(),
        config: const BridgeConfig(handlerTimeout: Duration(milliseconds: 300)),
      );
      final port = await srv.start(preferredPort: 0);
      try {
        final (status, body) = await _post(port);
        expect(status, 504, reason: 'the default budget frees the seat');
        expect(body, contains('handler_timeout'));
      } finally {
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'the noHandlerTimeout constant lets the same handler complete - '
    'the explicit way to ask for no deadline',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: _Rec(),
        correlationIdGenerator: _cid,
        onCommand: (_) async {
          await Future<void>.delayed(const Duration(milliseconds: 700));
          return const CommandOutcome(ok: true);
        },
        protection: _allowlist(),
        handlerTimeout: LocalIntakeServer.noHandlerTimeout,
      );
      final port = await srv.start(preferredPort: 0);
      try {
        final (status, body) = await _post(port);
        expect(
          status,
          200,
          reason:
              'the named constant carries the old null meaning: no '
              'handler deadline at all',
        );
        expect(body, contains('"ok":true'));
      } finally {
        await srv.stop().timeout(const Duration(seconds: 10));
      }
    },
  );

  test('a negative handler budget is refused at construction', () {
    expect(
      () => LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _cid,
        onCommand: (_) async => const CommandOutcome(ok: true),
        handlerTimeout: const Duration(milliseconds: -1),
      ),
      throwsArgumentError,
      reason:
          'a negative budget is a configuration mistake - it must surface '
          'loudly, while Duration.zero is the named no-deadline constant',
    );
  });
}
