// Witnesses of the one admission step: every acceptance route confirms the
// recorded value (route, CORS echo, verbose errors), the state effects land
// on settle alone, and the token is compared at most once per request.
// Titles in English (published package); unit-level witnesses on
// IntakeProtection.admit plus one full-server comparison witness.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

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

Future<Map<String, Object?>> _post(
  int port, {
  String? origin,
  String? token,
}) async {
  final client = HttpClient();
  try {
    final req = await client.open('POST', '127.0.0.1', port, '/');
    if (origin != null) req.headers.set('Origin', origin);
    if (token != null) req.headers.set('X-Bridge-Token', token);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return {'status': res.statusCode, 'body': text};
  } finally {
    client.close(force: true);
  }
}

void main() {
  test(
    'the listed path records listed with the echo and the host text',
    () async {
      final rec = _Rec();
      final pr = IntakeProtection(telemetry: rec)
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
        );
      final a = await pr.admit(origin: 'https://portal.example', path: '/x');
      expect(a.rejection, isNull);
      expect(a.acceptedPath, IntakeAdmissionPath.listed);
      expect(a.echoesCors, isTrue);
      expect(a.verboseErrors, isTrue);
      // السجل يحمل حقائق الطلب كما وردت: الأصل وشكله القانوني والمسار
      expect(a.origin, 'https://portal.example');
      expect(a.normalizedOrigin, 'https://portal.example');
      expect(a.path, '/x');
    },
  );

  test(
    'the saved-consent path records savedConsent after allowAlways',
    () async {
      final rec = _Rec();
      final pr = IntakeProtection(telemetry: rec)
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            onUnknownOrigin: (origin) async => OriginConsent.allowAlways,
          ),
        );
      final first = await pr.admit(origin: 'https://new.example');
      expect(first.rejection?.code, 'origin_pending');
      expect(first.acceptedPath, isNull);
      first.settle();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      final second = await pr.admit(origin: 'https://new.example');
      expect(second.rejection, isNull);
      expect(second.acceptedPath, IntakeAdmissionPath.savedConsent);
      expect(second.echoesCors, isTrue);
      expect(second.verboseErrors, isTrue);
    },
  );

  test('the one-time grant records onceGrant and settle consumes it', () async {
    final pr = IntakeProtection()
      ..update(
        policy: OriginPolicy(
          requireFetchMetadata: false,
          onUnknownOrigin: (origin) async => OriginConsent.allowOnce,
        ),
      );
    final first = await pr.admit(origin: 'https://once.example');
    expect(first.rejection?.code, 'origin_pending');
    first.settle();
    await Future<void>.delayed(const Duration(milliseconds: 10));
    final second = await pr.admit(origin: 'https://once.example');
    expect(second.rejection, isNull);
    expect(second.acceptedPath, IntakeAdmissionPath.onceGrant);
    second.settle();
    // المنحة استُهلكت بالتسوية: الطلب التالي يسأل من جديد لا يمرر
    final third = await pr.admit(origin: 'https://once.example');
    expect(third.rejection?.code, 'origin_pending');
    expect(third.acceptedPath, isNull);
  });

  test(
    'the allow-all path records allowAll with the echo and no host text',
    () async {
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(
            allowAllHardened: true,
            requireFetchMetadata: false,
          ),
        );
      final a = await pr.admit(origin: 'https://any.example');
      expect(a.rejection, isNull);
      expect(a.acceptedPath, IntakeAdmissionPath.allowAll);
      expect(a.echoesCors, isTrue);
      expect(
        a.verboseErrors,
        isFalse,
        reason: 'the allow-all sender is untrusted - the code without the text',
      );
    },
  );

  test(
    'a correct token alone records token: no echo, full host text',
    () async {
      final pr = IntakeProtection()
        ..update(policy: const OriginPolicy(), token: _t64);
      final a = await pr.admit(
        origin: 'https://stranger.example',
        portalToken: _t64,
      );
      expect(a.rejection, isNull);
      expect(a.acceptedPath, IntakeAdmissionPath.token);
      expect(
        a.echoesCors,
        isFalse,
        reason: 'a stranger origin reads no ACAO - the token client needs none',
      );
      expect(a.verboseErrors, isTrue);
    },
  );

  test(
    'a correct token over a listed origin records originWithToken',
    () async {
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          token: _t64,
        );
      final a = await pr.admit(
        origin: 'https://portal.example',
        portalToken: _t64,
      );
      expect(a.rejection, isNull);
      expect(a.acceptedPath, IntakeAdmissionPath.originWithToken);
      expect(a.echoesCors, isTrue);
      expect(a.verboseErrors, isTrue);
    },
  );

  test(
    'the projection is pure: only settle fires the consent question',
    () async {
      var asks = 0;
      final pr = IntakeProtection()
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            onUnknownOrigin: (origin) async {
              asks++;
              return OriginConsent.dismissed;
            },
          ),
        );
      final a = await pr.admit(origin: 'https://fresh.example');
      expect(
        asks,
        0,
        reason: 'the projection asks nothing - a pure read leaves no question',
      );
      a.settle();
      expect(asks, 1, reason: 'settle lands the question exactly once');
      // وقراءة ثانية بلا تسوية لا تطلق شيئاً
      await pr.admit(origin: 'https://fresh.example');
      expect(asks, 1);
    },
  );

  test('the projection is pure: quota stamps land on settle alone', () async {
    final stamped = IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          allowAllHardened: true,
          requireFetchMetadata: false,
          perOriginPerMinute: 1,
        ),
      );
    final a1 = await stamped.admit(origin: 'https://q.example');
    expect(a1.rejection, isNull);
    a1.settle();
    // الطابع هبط: الثاني يُرد بالحصة من الإسقاط الخالص نفسه
    final a2 = await stamped.admit(origin: 'https://q.example');
    expect(a2.rejection?.code, 'origin_rate_limited');
    a2.settle();

    final pure = IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          allowAllHardened: true,
          requireFetchMetadata: false,
          perOriginPerMinute: 1,
        ),
      );
    for (var i = 0; i < 3; i++) {
      final a = await pure.admit(origin: 'https://q.example');
      expect(
        a.rejection,
        isNull,
        reason: 'without settle no stamp lands - every read sees a free quota',
      );
    }
  });

  test(
    'a rejection counts and logs on settle, never on the pure read',
    () async {
      final rec = _Rec();
      final pr = IntakeProtection(telemetry: rec)
        ..update(policy: const OriginPolicy());
      final before = pr.rejectedCount;
      final a = await pr.admit(origin: 'https://attacker.example');
      expect(pr.rejectedCount, before, reason: 'the pure read counts nothing');
      expect(rec.warns.where((w) => w.contains('intake rejected')), isEmpty);
      a.settle();
      expect(pr.rejectedCount, before + 1);
      expect(
        rec.warns.any(
          (w) =>
              w.contains('origin_not_listed') && w.contains('attacker.example'),
        ),
        isTrue,
        reason: 'the throttled security line carries the code and the origin',
      );
    },
  );

  test(
    'a token is compared at most once per request, never under the lock',
    () async {
      final rec = _Rec();
      final pr = IntakeProtection(telemetry: rec)
        ..update(policy: const OriginPolicy(), token: _t64);
      expect(pr.tokenComparisonCount, 0);
      // خمس إخفاقات: كل طلب يقارن مرة واحدة حصراً ويختم طابعاً واحداً
      for (var i = 0; i < 5; i++) {
        final a = await pr.admit(
          origin: 'https://guess.example',
          portalToken: 'WRONG$i',
        );
        a.settle();
        expect(pr.tokenComparisonCount, i + 1);
      }
      final locked = await pr.admit(
        origin: 'https://guess.example',
        portalToken: 'WRONG6',
      );
      expect(locked.rejection?.code, 'token_locked');
      expect(
        pr.tokenComparisonCount,
        5,
        reason:
            'the locked window forbids the comparison - the token is absent',
      );
      // والصحيح نفسه لا يقارن تحت القفل
      final correct = await pr.admit(
        origin: 'https://guess.example',
        portalToken: _t64,
      );
      expect(correct.rejection?.code, 'token_locked');
      expect(pr.tokenComparisonCount, 5);
      // بلا ترويسة توكن لا مقارنة إطلاقاً
      await pr.admit(origin: 'https://other.example');
      expect(pr.tokenComparisonCount, 5);
    },
  );

  test(
    'a full server request over the record compares the token once',
    () async {
      final rec = _Rec();
      final pr = IntakeProtection(telemetry: rec)
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          token: _t64,
        );
      final srv = LocalIntakeServer(
        telemetry: rec,
        correlationIdGenerator: () => 'adm-1',
        onCommand: (cmd) async => const CommandOutcome(ok: true),
        protection: pr,
      );
      final port = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final before = pr.tokenComparisonCount;
      final r = await _post(
        port,
        origin: 'https://portal.example',
        token: _t64,
      );
      expect(r['status'], 200);
      expect(
        pr.tokenComparisonCount,
        before + 1,
        reason:
            'one comparison for the whole request - the verbose decision reads '
            'the record instead of comparing again',
      );
    },
  );

  test('noteAuthorityReject routes the host-authority deny through the same '
      'counter and security line', () async {
    final rec = _Rec();
    final pr = IntakeProtection(telemetry: rec)
      ..update(policy: const OriginPolicy(allowed: ['https://portal.example']));
    final a = await pr.admit(origin: 'https://portal.example');
    final before = pr.rejectedCount;
    a.noteAuthorityReject(
      'Request Host is not allowed — this bridge accepts localhost only',
    );
    expect(pr.rejectedCount, before + 1);
    expect(
      rec.warns.any(
        (w) =>
            w.contains('Request Host is not allowed') &&
            w.contains('portal.example'),
      ),
      isTrue,
      reason: 'denial is never silent - the line carries the reason and origin',
    );
  });

  test(
    'a record settles once; the unrecorded placeholder refuses both calls',
    () async {
      final pr = IntakeProtection()
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
        );
      final a = await pr.admit(origin: 'https://portal.example');
      a.settle();
      expect(
        () => a.settle(),
        throwsStateError,
        reason: 'one settle per request',
      );
      expect(() => IntakeAdmission.unrecorded.settle(), throwsStateError);
      expect(
        () => IntakeAdmission.unrecorded.noteAuthorityReject('x'),
        throwsStateError,
      );
      // وقيمة TrustedCommand الافتراضية هي المثال نفسه
      const cmd = TrustedCommand(
        source: 'x',
        payloads: [],
        headers: {},
        correlationId: 'c',
      );
      expect(identical(cmd.admission, IntakeAdmission.unrecorded), isTrue);
    },
  );
}
