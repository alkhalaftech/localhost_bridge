// شهادة seam القياس : الواجهة تحمل مستوى×تصنيف×خطأ/كومة
// وسياق — والمضيف يطوّعها. SilentTelemetry يمرر الجسم كما هو.
import 'dart:async';
import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

class _Recording extends BridgeTelemetry {
  final records = <String>[];
  final measures = <String>[];

  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    records.add('info/$category: $message ctx=$context');
  }

  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    records.add('warn/$category: $message');
  }

  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {
    records.add(
      'error/$category: $message err=$error stack=${stackTrace != null}',
    );
  }

  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) async {
    measures.add(label);
    return await body();
  }
}

void main() {
  test(
    'the seam carries level, category, error, stack, and context without loss',
    () async {
      final r = _Recording();
      r.info('i', category: BridgeCategory.security, context: {'k': 1});
      r.warn('w');
      try {
        throw StateError('boom');
      } catch (e, s) {
        r.error(
          'e',
          error: e,
          stackTrace: s,
          category: BridgeCategory.security,
        );
      }
      final v = await r.measure<int>('m', () async => 7, context: {'c': 2});
      expect(v, 7);
      expect(r.records[0], contains('info/BridgeCategory.security'));
      expect(r.records[0], contains('{k: 1}'));
      expect(r.records[2], contains('err=Bad state: boom'));
      expect(r.records[2], contains('stack=true'));
      expect(r.measures, ['m']);
    },
  );

  test('SilentTelemetry passes the body silently', () async {
    final out = await const SilentTelemetry().measure<String>(
      'm',
      () async => 'ok',
    );
    expect(out, 'ok');
  });
}
