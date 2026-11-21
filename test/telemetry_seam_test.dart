// شهادة seam القياس: أحداث الحزمة الحقيقية (الإقلاع، سطر الرفض الأمني،
// انهيار المعالج، حمل القياس) تمر بالواجهة إلى مرصد المضيف بلا فقد —
// المستوى والتصنيف والخطأ والكومة والسياق كما مرّتها الحزمة. والمستقبل
// الصامت يمتنع بلا أثر ويمرر الجسم كما هو.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

class _Recording extends BridgeTelemetry {
  final records = <String>[];
  final contexts = <Map<String, Object?>?>[];
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
    records.add('warn/$category: $message ctx=$context');
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
    contexts.add(context);
    return await body();
  }
}

void main() {
  test(
    'the seam carries level, category, error, stack, and context without loss',
    () async {
      final r = _Recording();
      // خادم مغلق: سطر الرفض الأمني عبر النداء الحقيقي — warn بتصنيف
      // الأمن يحمل رمز الرفض وحقل الأصل المعقم
      final closed = LocalIntakeServer(
        telemetry: r,
        correlationIdGenerator: () => 'seam-cid',
        onCommand: (cmd) async => const CommandOutcome(ok: true),
        protection: IntakeProtection(telemetry: r),
      );
      final closedPort = await closed.start(preferredPort: 0);
      addTearDown(closed.stop);
      final client = HttpClient();
      final req = await client.open('POST', '127.0.0.1', closedPort, '/');
      req.headers.set('Origin', 'https://stranger.example');
      req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      req.add(utf8.encode('["CMD"]'));
      final res = await req.close();
      expect(res.statusCode, 403);
      await res.transform(utf8.decoder).join();
      client.close(force: true);

      // (info) سطر الإقلاع عبر الربط الحقيقي — تصنيف الشبكة حاضر
      expect(
        r.measures,
        contains('intake.start'),
        reason: 'the start measure label travels the seam',
      );
      expect(
        r.records.any((x) => x.startsWith('info/BridgeCategory.network')),
        isTrue,
        reason: 'the listening line reaches the host seam as info',
      );
      // (warn) سطر الحماية: التصنيف أمن والرمز والحقل المعقم في السطر
      final warnLine = r.records.firstWhere(
        (x) => x.startsWith('warn/BridgeCategory.security'),
      );
      expect(
        warnLine,
        contains('origin_not_listed'),
        reason: 'the rejection reason code travels the warn line',
      );
      expect(
        warnLine,
        contains('origin=https://stranger.example'),
        reason: 'the origin rides the sanitized origin= field, not raw',
      );

      // (error + كومة + سياق) معالج يرمي على طلب مقبول: خطأ الحزمة
      // الحقيقي يمر error بتصنيف الشبكة مع الخطأ والكومة، وسياق قياس
      // الطلب يحمل معرف الارتباط والأصل كما مرّا
      final crashing = LocalIntakeServer(
        telemetry: r,
        correlationIdGenerator: () => 'seam-cid',
        onCommand: (cmd) async => throw StateError('boom'),
        protection: IntakeProtection(telemetry: r)
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
              perOriginPerMinute: 1000,
            ),
          ),
      );
      final crashPort = await crashing.start(preferredPort: 0);
      addTearDown(crashing.stop);
      // عميل ثانٍ: الأول أُغلق بعد رفض الأصل الغريب — إعادة استعماله
      // بعد الإغلاق ترمي Client is closed
      final client2 = HttpClient();
      final req2 = await client2.open('POST', '127.0.0.1', crashPort, '/');
      req2.headers.set('Origin', 'https://portal.example');
      req2.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
      req2.add(utf8.encode('["CMD"]'));
      final res2 = await req2.close();
      expect(res2.statusCode, 500);
      await res2.transform(utf8.decoder).join();
      client2.close(force: true);

      final errorLine = r.records.firstWhere((x) => x.startsWith('error/'));
      expect(
        errorLine,
        contains('error/BridgeCategory.network'),
        reason: 'the crash line reaches the seam as an error',
      );
      expect(
        errorLine,
        contains('err=Bad state: boom'),
        reason: 'the thrown error travels the seam',
      );
      expect(
        errorLine,
        contains('stack=true'),
        reason: 'the stack trace flag travels the seam',
      );
      expect(
        r.contexts.any(
          (c) =>
              c != null &&
              c['origin'] == 'https://portal.example' &&
              c['correlationId'] == 'seam-cid',
        ),
        isTrue,
        reason:
            'the request measure context carries the id and the origin '
            'as passed',
      );
    },
  );

  test(
    'SilentTelemetry swallows the reports and passes the body silently',
    () async {
      const t = SilentTelemetry();
      // الاستهلاك الثلاثي نداءات بلا أثر — الصمت عقد الواجهة ولا يرمي
      t.info('i');
      t.warn('w');
      t.error('e');
      final out = await t.measure<String>('m', () async => 'ok');
      expect(out, 'ok', reason: 'the measured body passes untouched');
    },
  );
}
