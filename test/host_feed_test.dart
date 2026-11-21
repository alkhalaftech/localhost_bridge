// شواهد القنوات التي يغذيها المضيف: الأمر الواصل من قناة غير HTTP يمرّ
// بالفحوص نفسها — الأصل غير المقبول يُرفض، والحمولة فوق الحد تُرفض،
// والحصة تُحسب — ودرجة ثقة الأصل تسكن سجل القبول لا أي رد سلكي.
// العناوين بالإنجليزية (حزمة منشورة) والتعليقات بالعربية (قاعدة البيت).
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
String _cid() => 'feed-${_idSeq++}';

LocalIntakeServer _server({
  OriginPolicy policy = const OriginPolicy(),
  String token = '',
  int maxBodyBytes = 1024 * 1024,
}) {
  final protection = IntakeProtection(telemetry: _Rec());
  if (token.isEmpty) {
    protection.update(policy: policy);
  } else {
    protection.update(policy: policy, token: token);
  }
  return LocalIntakeServer(
    onCommand: (command) async => const CommandOutcome(ok: true),
    telemetry: _Rec(),
    correlationIdGenerator: _cid,
    protection: protection,
    config: BridgeConfig(maxBodyBytes: maxBodyBytes),
  );
}

void main() {
  group('host feed - the same checks on a non-HTTP channel', () {
    test('a platform-verified origin outside the policy is rejected with the '
        'standing wire code', () async {
      final server = _server();
      final result = await server.acceptHostFeed(
        body: '["CMD"]',
        origin: 'https://stranger.example',
        originTrust: OriginTrustLevel.platformVerified,
        correlationId: 'feed-reject-1',
      );
      expect(result.accepted, isFalse);
      expect(result.command, isNull);
      final rejection = result.rejection!;
      expect(rejection.status, 403);
      expect(rejection.code, 'origin_not_listed');
      // الرفض محسوب في عدّاد الحماية وعدّاد الخادم معا — لا رفض صامت
      expect(server.protection.rejectedCount, 1);
      expect(server.counters.rejectionsByCode['origin_not_listed'], 1);
    });

    test(
      'a body over the standing limit is refused with payload_too_large',
      () async {
        final server = _server(
          policy: const OriginPolicy(allowed: ['https://lab.example']),
          maxBodyBytes: 64,
        );
        final result = await server.acceptHostFeed(
          body: '["${'x' * 200}"]',
          origin: 'https://lab.example',
          originTrust: OriginTrustLevel.platformVerified,
        );
        expect(result.accepted, isFalse);
        expect(result.rejection!.status, 413);
        expect(result.rejection!.code, 'payload_too_large');
      },
    );

    test(
      'the per-origin quota counts channel commands exactly like HTTP ones',
      () async {
        final server = _server(
          policy: const OriginPolicy(
            allowed: ['https://lab.example'],
            listedPerOriginPerMinute: 2,
          ),
        );
        final first = await server.acceptHostFeed(
          body: '["A"]',
          origin: 'https://lab.example',
          originTrust: OriginTrustLevel.platformVerified,
        );
        final second = await server.acceptHostFeed(
          body: '["B"]',
          origin: 'https://lab.example',
          originTrust: OriginTrustLevel.platformVerified,
        );
        final third = await server.acceptHostFeed(
          body: '["C"]',
          origin: 'https://lab.example',
          originTrust: OriginTrustLevel.platformVerified,
        );
        expect(first.accepted, isTrue);
        expect(second.accepted, isTrue);
        expect(third.accepted, isFalse);
        expect(third.rejection!.code, 'origin_rate_limited');
        expect(third.rejection!.status, 429);
        expect(server.counters.rejectionsByCode['origin_rate_limited'], 1);
      },
    );

    test('an originless native client crosses by its token alone', () async {
      final token = 'a1b2c3d4' * 8; // 64 بايت فوق أرضية العشوائية
      final server = _server(token: token);
      final result = await server.acceptHostFeed(
        body: '["PING"]',
        origin: null,
        originTrust: OriginTrustLevel.none,
        token: token,
      );
      expect(result.accepted, isTrue);
      expect(result.rejection, isNull);
      expect(result.command, isNotNull);
      expect(result.command!.admission.acceptedPath, IntakeAdmissionPath.token);
      expect(result.command!.source, 'unknown-origin');
      expect(result.command!.correlationId, isNotEmpty);
      expect(result.command!.payloads, ['PING']);
    });

    test('an origin with no declared trust grade is refused loudly, never '
        'treated as a browser header', () async {
      final server = _server(
        policy: const OriginPolicy(allowed: ['https://lab.example']),
      );
      // أصل بدرجة none تناقض: من لا يوثق بالأصل لا يمرره أصلا
      await expectLater(
        server.acceptHostFeed(
          body: '["CMD"]',
          origin: 'https://lab.example',
          originTrust: OriginTrustLevel.none,
        ),
        throwsArgumentError,
      );
      // والعكس: بلا أصل فلا درجة متصفح ولا درجة منصة
      await expectLater(
        server.acceptHostFeed(
          body: '["CMD"]',
          origin: null,
          originTrust: OriginTrustLevel.browserHeader,
        ),
        throwsArgumentError,
      );
      await expectLater(
        server.acceptHostFeed(
          body: '["CMD"]',
          origin: null,
          originTrust: OriginTrustLevel.platformVerified,
        ),
        throwsArgumentError,
      );
      // والتناقض لم يترك أثرا في العدادات
      expect(server.protection.rejectedCount, 0);
    });

    test('the trust grade lives in the admission record only', () async {
      final server = _server(
        policy: const OriginPolicy(allowed: ['https://lab.example']),
      );
      final accepted = await server.acceptHostFeed(
        body: '["CMD"]',
        origin: 'https://lab.example',
        originTrust: OriginTrustLevel.platformVerified,
        correlationId: 'feed-cid-1',
      );
      expect(accepted.command, isNotNull);
      expect(
        accepted.command!.admission.originTrust,
        OriginTrustLevel.platformVerified,
      );
      expect(
        accepted.command!.admission.normalizedOrigin,
        'https://lab.example',
      );
      expect(accepted.command!.correlationId, 'feed-cid-1');
      expect(accepted.command!.payloads, ['CMD']);
      // ولا الرفض يحمل الدرجة — سجل القبول هو موضعها حصرا
      final rejected = await server.acceptHostFeed(
        body: '["CMD"]',
        origin: 'https://other.example',
        originTrust: OriginTrustLevel.platformVerified,
      );
      expect(rejected.rejection, isNotNull);
      expect(
        rejected.admission!.originTrust,
        OriginTrustLevel.platformVerified,
      );
    });

    test('requireFetchMetadata exempts the platform-verified grade and stays '
        'closed for the header grade', () async {
      final server = _server(
        policy: const OriginPolicy(allowAllHardened: true),
      );
      // المنصة وثقت بالأصل وعلى القناة لا ترويسات Sec-Fetch أصلا —
      // الغياب باب صادق للدرجة الموثقة
      final verified = await server.acceptHostFeed(
        body: '["CMD"]',
        origin: 'https://app.example',
        originTrust: OriginTrustLevel.platformVerified,
      );
      expect(verified.accepted, isTrue);
      expect(
        verified.command!.admission.acceptedPath,
        IntakeAdmissionPath.allowAll,
      );
      // ومن يدّعي درجة الترويسة على قناة بلا ترويسات يظل مغلقا الباب
      final claimed = await server.acceptHostFeed(
        body: '["CMD"]',
        origin: 'https://app.example',
        originTrust: OriginTrustLevel.browserHeader,
      );
      expect(claimed.rejection!.code, 'cross_site_blocked');
    });

    test(
      'the wire shape gates answer the standing codes before admission',
      () async {
        final server = _server();
        final tooLong = await server.acceptHostFeed(
          body: '["CMD"]',
          origin: 'https://${'a' * 1100}.example',
          originTrust: OriginTrustLevel.platformVerified,
        );
        expect(tooLong.rejection!.status, 400);
        expect(tooLong.rejection!.code, 'origin_too_long');
        // رفض الشكل البروتوكولي قبولٌ للمقارنة: لا سجل قبول بني بعده
        expect(tooLong.admission, isNull);
        final malformed = await server.acceptHostFeed(
          body: '["CMD"]',
          origin: 'https://bad.example/path',
          originTrust: OriginTrustLevel.platformVerified,
        );
        expect(malformed.rejection!.code, 'origin_malformed');
        final bigToken = await server.acceptHostFeed(
          body: '["CMD"]',
          origin: null,
          originTrust: OriginTrustLevel.none,
          token: 't' * 1100,
        );
        expect(bigToken.rejection!.code, 'token_too_long');
        // والثلاثة في عدّاد الشكل البروتوكولي وحده
        expect(server.counters.protocolShapeRejections, 3);
      },
    );

    test('payload checks answer the standing codes on the feed', () async {
      // أصل مدرج كي تعبر بوابة القبول ويبلغ الأمر فحوص الحمولة —
      // بترتيب السلك نفسه: بوابة الأصل قبل قراءة الجسم
      final server = _server(
        policy: const OriginPolicy(allowed: ['https://lab.example']),
      );
      final empty = await server.acceptHostFeed(
        body: '[]',
        origin: 'https://lab.example',
        originTrust: OriginTrustLevel.platformVerified,
      );
      expect(empty.rejection!.code, 'empty_payload');
      final unsupported = await server.acceptHostFeed(
        body: '{"unknown": 1}',
        origin: 'https://lab.example',
        originTrust: OriginTrustLevel.platformVerified,
      );
      expect(unsupported.rejection!.code, 'unsupported_payload_shape');
    });
  });
}
