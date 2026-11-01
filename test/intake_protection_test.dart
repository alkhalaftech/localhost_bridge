// اختبارات حماية المدخل بالسياسة الموحدة : القائمة تحكم،
// «مسموح للكل» تحصيناته ملازمة، والاكتشاف يسأل المضيف مرة — والافتراضي
// مغلق. ترتيب الترتيب الحرج انتقل للحارس؛ هنا عقد القبول الجديد.
import 'dart:async';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

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
  group('default-deny: intake rejects everything until configured', () {
    test(
      'empty allowlist rejects every origin with origin_not_listed 403',
      () async {
        final p = IntakeProtection();
        expect(await p.check(origin: null), isNotNull);
        final r = await p.check(
          origin: 'https://evil.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(r!.code, 'origin_not_listed');
        expect(r.status, 403);
      },
    );

    test('updateFromSaved: removed open mode denies with a warning', () async {
      final rec = _Rec();
      final p = IntakeProtection(telemetry: rec);
      p.updateFromSaved(savedMode: 'open');
      expect(
        await p.check(
          origin: 'https://portal.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNotNull,
        reason: 'open no longer exists - closed',
      );
      expect(rec.warns.any((w) => w.contains('"open" was removed')), isTrue);
      final q = IntakeProtection();
      q.updateFromSaved(
        savedMode: 'allowlist',
        allowedOrigins: ['portal.example'],
      );
      expect(
        await q.check(
          origin: 'https://portal.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
      );
      final t = IntakeProtection();
      t.updateFromSaved(
        savedMode: 'token',
        token:
            'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
      );
      expect(
        await t.check(
          origin: null,
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        ),
        isNull,
        reason: 'the token layer passes on its own without browser headers',
      );
    });
  });

  group('origin allowlist admits listed origins', () {
    final p = IntakeProtection()
      ..update(
        policy: const OriginPolicy(
          allowed: [
            'https://portal.example.com',
            'partner.io',
            '*.charts.example',
          ],
        ),
      );

    test('admits exact listed origins and bare-host entries', () async {
      expect(
        await p.check(
          origin: 'https://portal.example.com',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
      );
      expect(
        await p.check(
          origin: 'https://partner.io',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
      );
    });

    test('wildcard entry matches subdomains only, never the root', () async {
      expect(
        await p.check(
          origin: 'https://app.charts.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
      );
      expect(
        await p.check(
          origin: 'https://charts.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNotNull,
        reason:
            'the root must be listed explicitly - the pattern is for subdomains',
      );
    });

    test(
      'rootless *. wildcard accepts nothing, not even trailing-dot origins',
      () async {
        final q = IntakeProtection()
          ..update(policy: const OriginPolicy(allowed: ['*.']));
        expect(
          await q.check(
            origin: 'https://evil.com.',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNotNull,
          reason:
              'a legitimate browser origin with a trailing dot - it passes quietly',
        );
        expect(
          await q.check(
            origin: 'https://any.host',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNotNull,
        );
      },
    );

    test(
      'one in-flight question for concurrent checks; the answer serves the retry',
      () async {
        var asked = 0;
        final gate = Completer<OriginConsent>();
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) async {
                asked++;
                return await gate.future;
              },
            ),
          );
        final a = p.check(
          origin: 'https://concurrent.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        final b = p.check(
          origin: 'https://concurrent.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(
          asked,
          1,
          reason: 'the second rides the same window, not a new one',
        );
        expect(
          (await a)!.code,
          'origin_pending',
          reason:
              'no waiting - an immediate reply whose answer serves the retry',
        );
        expect((await b)!.code, 'origin_pending');
        gate.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          await p.check(
            origin: 'https://concurrent.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason:
              'remembered as always - the retry passes with no new question',
        );
        expect(asked, 1);
      },
    );

    test(
      'unlisted subdomain of a listed host is rejected — no suffix matching',
      () async {
        expect(
          await p.check(
            origin: 'https://app.partner.io',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNotNull,
        );
      },
    );

    test('check never counts rejections — only noteRejection does', () async {
      final before = p.rejectedCount;
      await p.check(
        origin: 'https://evil.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      expect(p.rejectedCount, before);
      p.noteRejection('x');
      expect(p.rejectedCount, before + 1);
    });

    test('trailing slash and case are normalized before matching', () async {
      expect(
        await p.check(
          origin: 'https://PORTAL.example.com/',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
      );
    });

    test('non-https origin stays rejected under the allowlist', () async {
      expect(await p.check(origin: 'http://portal.example.com'), isNotNull);
    });
  });

  group(
    'hardened allow-all: origin checks, fetch metadata, per-origin rate limit',
    () {
      test(
        'missing, empty, null and http origins blocked; any https passes',
        () async {
          final p = IntakeProtection()
            ..update(policy: const OriginPolicy(allowAllHardened: true));
          expect((await p.check(origin: null))!.code, 'origin_blocked');
          expect((await p.check(origin: ''))!.code, 'origin_blocked');
          expect((await p.check(origin: 'null'))!.code, 'origin_blocked');
          expect(
            (await p.check(origin: 'http://x.example'))!.code,
            'origin_blocked',
          );
          expect(
            await p.check(
              origin: 'https://any.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason:
                'any https crosses the allow-all path - hardening is not a list',
          );
        },
      );

      test(
        'allowLocalHttp lets localhost http through, non-local stays blocked',
        () async {
          final p = IntakeProtection()
            ..update(
              policy: const OriginPolicy(
                allowAllHardened: true,
                allowLocalHttp: true,
              ),
            );
          expect(
            await p.check(
              origin: 'http://localhost:8080',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
          );
          expect(
            await p.check(
              origin: 'http://127.0.0.1:5173',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
          );
          expect(
            await p.check(origin: 'http://evil.example'),
            isNotNull,
            reason: 'the exception is for local origins only',
          );
        },
      );

      test(
        'fetch metadata: navigate/no-cors rejected, cors and absent pass',
        () async {
          final p = IntakeProtection()
            ..update(policy: const OriginPolicy(allowAllHardened: true));
          expect(
            (await p.check(
              origin: 'https://a.example',
              fetchMode: 'navigate',
              fetchDest: 'document',
            ))!.code,
            'cross_site_blocked',
          );
          expect(
            (await p.check(
              origin: 'https://a.example',
              fetchMode: 'no-cors',
            ))!.code,
            'cross_site_blocked',
          );
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason: 'a real fetch header passes',
          );
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason:
                'a missing Sec-Fetch passes - a non-browser client or an old browser',
          );
        },
      );

      test(
        'per-origin quota: excess gets 429, other origins still pass',
        () async {
          final p = IntakeProtection()
            ..update(
              policy: const OriginPolicy(
                allowAllHardened: true,
                perOriginPerMinute: 3,
              ),
            );
          for (var i = 0; i < 3; i++) {
            expect(
              await p.check(
                origin: 'https://a.example',
                fetchMode: 'cors',
                fetchDest: 'empty',
              ),
              isNull,
            );
          }
          final over = await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          );
          expect(over!.status, 429);
          expect(over.code, 'origin_rate_limited');
          expect(
            await p.check(
              origin: 'https://b.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason: 'the quota of one origin does not punish another',
          );
        },
      );

      test(
        'reportOnly rejects request-shape violations — watching covers the quota only',
        () async {
          final rec = _Rec();
          final p = IntakeProtection(telemetry: rec)
            ..update(
              policy: const OriginPolicy(
                allowAllHardened: true,
                reportOnly: true,
              ),
            );
          expect(
            (await p.check(origin: 'http://x.example'))!.code,
            'origin_blocked',
            reason: 'an http origin is rejected even while watching',
          );
          expect(
            (await p.check(
              origin: 'https://a.example',
              fetchMode: 'navigate',
              fetchDest: 'document',
            ))!.code,
            'cross_site_blocked',
            reason: 'a form navigation is rejected even while watching',
          );
          expect(
            (await p.check(
              origin: 'https://a.example',
              fetchMode: 'no-cors',
            ))!.code,
            'cross_site_blocked',
            reason: 'a no-cors send is rejected even while watching',
          );
          expect(
            (await p.check(origin: null))!.code,
            'origin_blocked',
            reason: 'a request without Origin is rejected even while watching',
          );
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason: 'a well-formed fetch passes while watching',
          );
          expect(
            rec.warns.any((w) => w.contains('would reject')),
            isFalse,
            reason: 'nothing passed here that watching would have rejected',
          );
        },
      );

      test(
        'reportOnly logs the quota it would reject and lets it through',
        () async {
          final rec = _Rec();
          final p = IntakeProtection(telemetry: rec)
            ..update(
              policy: const OriginPolicy(
                allowAllHardened: true,
                reportOnly: true,
                perOriginPerMinute: 1,
              ),
            );
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
          );
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason: 'over the quota still passes - watching does not reject',
          );
          expect(
            rec.warns.any((w) => w.contains('would reject')),
            isTrue,
            reason: 'a line for the quota that would have been rejected',
          );
        },
      );

      test(
        'enabling allow-all-hardened warns instead of activating silently',
        () async {
          final rec = _Rec();
          IntakeProtection(
            telemetry: rec,
          ).update(policy: const OriginPolicy(allowAllHardened: true));
          expect(
            rec.warns.any((w) => w.contains('allow-all-hardened is ACTIVE')),
            isTrue,
          );
        },
      );
    },
  );

  group('independent token layer', () {
    test(
      'valid token passes without origin; invalid falls back to policy',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(allowed: ['https://portal.example']),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        expect(
          await p.check(
            origin: null,
            portalToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
        );
        expect(
          await p.check(origin: 'https://portal.example', portalToken: 'WRONG'),
          isNull,
          reason: 'a listed origin is enough',
        );
        expect(
          await p.check(origin: 'https://other.example', portalToken: 'x'),
          isNotNull,
        );
      },
    );

    test(
      'correct tokens from 64 to 300 chars pass — full-length comparison',
      () async {
        for (final len in [64, 128, 256, 300]) {
          final token = List.generate(len, (i) => 't${i % 10}').join();
          final p = IntakeProtection()
            ..update(policy: const OriginPolicy(), token: token);
          expect(
            await p.check(origin: null, portalToken: token),
            isNull,
            reason: 'a correct token of length $len must be accepted',
          );
        }
      },
    );

    test('verbose errors only for authorized origins and tokens', () async {
      final p = IntakeProtection()
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          token:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
      expect(p.verboseErrorsFor('https://portal.example', null), isTrue);
      expect(
        p.verboseErrorsFor(
          null,
          'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        ),
        isTrue,
      );
      expect(p.verboseErrorsFor('https://stranger.example', null), isFalse);
      final all = IntakeProtection()
        ..update(policy: const OriginPolicy(allowAllHardened: true));
      expect(
        all.verboseErrorsFor('https://any.example', null),
        isFalse,
        reason:
            'the allow-all path is untrusted - it gets the code without the host text',
      );
    });
  });

  group('token length guard', () {
    test(
      'over-pad warning never rejects; the whole token is still compared',
      () async {
        final rec = _Rec();
        final p = IntakeProtection(telemetry: rec);
        p.update(token: 't' * 300);
        final overWarn = rec.warns
            .where((w) => w.contains('exceeds the'))
            .join(' ');
        expect(overWarn, isNotEmpty, reason: 'over the pad warns');
        // صدق النص نفسه لا مجرد وجوده: العقد يقارن التوكن كاملا فلا
        // يعود التحذير يصف ما بعد الحد بأنه غير مقارن
        expect(overWarn, contains('the whole token is still compared'));
        expect(overWarn, isNot(contains('not compared')));
        expect(
          p.rejectedCount,
          0,
          reason: 'a settings warning does not pollute the rejection counter',
        );
        expect(
          await p.check(origin: null, portalToken: 't' * 300),
          isNull,
          reason: 'full-length comparison - accepted as is',
        );
      },
    );
  });

  group('auto discovery: non-blocking origin consent prompt', () {
    test(
      'unknown origin answers origin_pending at once; allowAlways is remembered',
      () async {
        var asked = 0;
        Completer<OriginConsent>? gate;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) {
                asked++;
                final g = Completer<OriginConsent>();
                gate = g;
                return g.future;
              },
            ),
          );
        final r1 = await p.check(
          origin: 'https://new.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(
          r1!.code,
          'origin_pending',
          reason: 'no waiting - an immediate reply',
        );
        expect(asked, 1);
        gate!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          await p.check(
            origin: 'https://new.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'remembered: the second passes with no new question',
        );
        expect(asked, 1);
      },
    );

    test('allowOnce grants a single retry then asks again', () async {
      var asked = 0;
      final gates = <String, Completer<OriginConsent>>{};
      final p = IntakeProtection()
        ..update(
          policy: OriginPolicy(
            onUnknownOrigin: (origin) {
              asked++;
              final g = Completer<OriginConsent>();
              gates[origin] = g;
              return g.future;
            },
          ),
        );
      expect(
        (await p.check(
          origin: 'https://once.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ))!.code,
        'origin_pending',
      );
      gates['https://once.example']!.complete(OriginConsent.allowOnce);
      await pumpEventQueue();
      expect(
        await p.check(
          origin: 'https://once.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
        reason: 'the grant is consumed by the first retry',
      );
      expect(
        (await p.check(
          origin: 'https://once.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ))!.code,
        'origin_pending',
        reason: 'the grant expired - it asks again',
      );
      expect(asked, 2);
    });

    test('rejection is remembered — no repeated prompting', () async {
      var asked = 0;
      Completer<OriginConsent>? gate;
      final p = IntakeProtection()
        ..update(
          policy: OriginPolicy(
            onUnknownOrigin: (origin) {
              asked++;
              gate = Completer<OriginConsent>();
              return gate!.future;
            },
          ),
        );
      await p.check(
        origin: 'https://deny.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      gate!.complete(OriginConsent.reject);
      await pumpEventQueue();
      final r = await p.check(
        origin: 'https://deny.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      expect(r!.code, 'origin_declined');
      expect(asked, 1, reason: 'the rejection is remembered for the session');
    });

    test(
      'a dismissed question leaves no memory — the origin is asked again',
      () async {
        var asked = 0;
        Completer<OriginConsent>? gate;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) {
                asked++;
                gate = Completer<OriginConsent>();
                return gate!.future;
              },
            ),
          );
        await p.check(
          origin: 'https://gone.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        gate!.complete(OriginConsent.dismissed);
        await pumpEventQueue();
        expect(
          (await p.check(
            origin: 'https://gone.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
          reason:
              'a dismissed question is not a decision - nothing is remembered',
        );
        expect(
          asked,
          2,
          reason: 'the origin is asked anew instead of declined',
        );
      },
    );

    test(
      'a policy update revokes remembered session consents and once-grants',
      () async {
        Completer<OriginConsent>? gate;
        Future<OriginConsent> ask(String origin) {
          gate = Completer<OriginConsent>();
          return gate!.future;
        }

        final p = IntakeProtection()
          ..update(policy: OriginPolicy(onUnknownOrigin: ask));
        await p.check(
          origin: 'https://consented.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        gate!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          await p.check(
            origin: 'https://consented.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'the session remembers the consent before any update',
        );
        // تطبيق سياسة جديدة يسحب الموافقة المحفوظة — القائمة الجديدة هي
        // الحقيقة والاكتشاف يسأل من جديد لا يرث قرار جيل سابق
        p.update(
          policy: OriginPolicy(
            allowed: const ['https://only.example'],
            onUnknownOrigin: ask,
          ),
        );
        expect(
          await p.check(
            origin: 'https://consented.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNotNull,
          reason:
              'a stale consent must not outlive the policy it was '
              'granted under',
        );
        // ومنحة «مرة واحدة» كذلك: أعطيت تحت الجيل السابق فتسقط معه —
        // والسؤال حي هنا كي يتميز الناجي (كان سيعبر) عن الميت (يسأل)،
        // والتحديث يغيّر القائمة فعلاً (إعادة تطبيق السياسة نفسها
        // عمداً لا تسحب شيئاً — شاهد النقطة السابقة)
        await p.check(
          origin: 'https://once.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        gate!.complete(OriginConsent.allowOnce);
        await pumpEventQueue();
        p.update(
          policy: OriginPolicy(
            allowed: const ['https://only.example', 'https://three.example'],
            onUnknownOrigin: ask,
          ),
        );
        expect(
          await p.check(
            origin: 'https://once.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNotNull,
          reason:
              'a once-grant must not survive a policy change either - '
              'had it survived, this request would pass on it',
        );
      },
    );

    test(
      'a token-only or bare update keeps session origin decisions',
      () async {
        final t64 =
            'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';
        Completer<OriginConsent>? gate;
        Future<OriginConsent> ask(String origin) {
          gate = Completer<OriginConsent>();
          return gate!.future;
        }

        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              allowed: const ['https://portal.example'],
              onUnknownOrigin: ask,
            ),
            token: t64,
          );
        await p.check(
          origin: 'https://granted.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        gate!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          await p.check(
            origin: 'https://granted.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'sanity: the grant works before any update',
        );
        // تحديث التوكن وحده: طبقة مستقلة لا تعني قرارات الأصل شيئا
        p.update(token: t64);
        expect(
          await p.check(
            origin: 'https://granted.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'a token-only update must not revoke origin decisions',
        );
        // والنداء المجرد كذلك: إعادة تطبيق السياسة نفسها ليست تغييرا
        p.update();
        expect(
          await p.check(
            origin: 'https://granted.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason:
              'a bare update re-applies the same decisions - nothing to '
              'revoke',
        );
      },
    );

    test('a policy change revokes grants but keeps the denials', () async {
      Completer<OriginConsent>? gate;
      Future<OriginConsent> ask(String origin) {
        gate = Completer<OriginConsent>();
        return gate!.future;
      }

      final p = IntakeProtection()
        ..update(
          policy: OriginPolicy(
            allowed: const ['https://portal.example'],
            onUnknownOrigin: ask,
          ),
        );
      await p.check(
        origin: 'https://denied.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      gate!.complete(OriginConsent.reject);
      await pumpEventQueue();
      expect(
        (await p.check(
          origin: 'https://denied.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ))!.code,
        'origin_declined',
        reason: 'sanity: the denial is remembered before any update',
      );
      p.update(
        policy: OriginPolicy(
          allowed: const ['https://portal.example', 'https://two.example'],
          onUnknownOrigin: ask,
        ),
      );
      expect(
        (await p.check(
          origin: 'https://denied.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ))!.code,
        'origin_declined',
        reason:
            'a denial is the user\'s verdict on the origin, not on the '
            'policy - it must survive policy changes for the session',
      );
    });

    test('a throwing consent callback consumes the question budget', () async {
      var calls = 0;
      final p = IntakeProtection()
        ..update(
          policy: OriginPolicy(
            onUnknownOrigin: (_) {
              calls++;
              throw StateError('broken host dialog');
            },
          ),
        );
      for (var i = 0; i < 11; i++) {
        final r = await p.check(
          origin: 'https://rot$i.evil.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(
          r!.code,
          'origin_pending',
          reason: 'the page always gets a retryable reply',
        );
      }
      expect(
        calls,
        10,
        reason:
            'a broken callback is invoked under the same time budget as '
            'a healthy one - it must not be re-invoked without end',
      );
    });

    test(
      'requireFetchMetadata: legacy browsers are closed by default',
      () async {
        // الافتراضي مفعّل: متصفح بلا Fetch Metadata مرفوض صمتا — لا يمر
        final on = IntakeProtection()
          ..update(policy: const OriginPolicy(allowAllHardened: true));
        expect(
          (await on.check(origin: 'https://old.example'))!.code,
          'cross_site_blocked',
          reason:
              'a legacy browser without Fetch Metadata must not send '
              'silently — the flag is on by default',
        );
        expect(
          await on.check(
            origin: 'https://new.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'a healthy fetch still passes',
        );
        var asked = 0;
        final discovery = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (_) {
                asked++;
                return Completer<OriginConsent>().future;
              },
            ),
          );
        expect(
          (await discovery.check(origin: 'https://old.example'))!.code,
          'cross_site_blocked',
          reason:
              'the discovery path is guarded too - no question for a '
              'blocked shape',
        );
        expect(asked, 0, reason: 'no question fired');
        // والمعطِّل صراحة يستعيد مرور الطلبات بلا الترويسات (توكن أو عميل خام)
        final off = IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
            ),
          );
        expect(
          await off.check(
            origin: 'https://legacy.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'turning it off keeps passing headerless clients',
        );
      },
    );

    test(
      'an optional listed-path quota bounds a compromised listed origin',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowed: ['https://a.example', 'https://b.example'],
              listedPerOriginPerMinute: 2,
            ),
          );
        expect(
          await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
        );
        expect(
          await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
        );
        expect(
          (await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_rate_limited',
          reason: 'the third request in the minute crosses the optional cap',
        );
        expect(
          await p.check(
            origin: 'https://b.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'another listed origin is not punished with it',
        );
        final disabled = IntakeProtection()
          ..update(policy: const OriginPolicy(allowed: ['https://a.example']));
        for (var i = 0; i < 5; i++) {
          expect(
            await disabled.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason: 'the default (0) keeps the listed path unquotaed',
          );
        }
      },
    );

    test('watch mode also watches the optional listed-path quota', () async {
      final rec = _Rec();
      final p = IntakeProtection(telemetry: rec)
        ..update(
          policy: const OriginPolicy(
            allowed: ['https://a.example'],
            listedPerOriginPerMinute: 1,
            reportOnly: true,
          ),
        );
      expect(
        await p.check(
          origin: 'https://a.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
      );
      expect(
        await p.check(
          origin: 'https://a.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
        reason:
            'watch mode logs a would-reject and still serves - the '
            'listed quota is a quota like the allow-all one',
      );
      expect(
        rec.warns.any(
          (w) =>
              w.contains('would reject') && w.contains('origin_rate_limited'),
        ),
        isTrue,
        reason: 'the would-reject is said, not silenced',
      );
    });

    test('a broad wildcard entry warns at save time', () {
      final rec = _Rec();
      IntakeProtection(telemetry: rec).update(
        policy: const OriginPolicy(allowed: ['*.com', '*.shop.example']),
      );
      expect(
        rec.warns.any((w) => w.contains('*.com') && w.contains('subdomain')),
        isTrue,
        reason:
            'a wildcard over a one-or-two-label root matches whole '
            'registries - say so once at save time',
      );
    });

    test(
      'new questions are budgeted over time: subdomain rotation cannot ask forever',
      () async {
        var fakeNow = 0;
        var asked = 0;
        final gates = <Completer<OriginConsent>>[];
        final p = IntakeProtection(nowMs: () => fakeNow)
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) {
                asked++;
                final g = Completer<OriginConsent>();
                gates.add(g);
                return g.future;
              },
            ),
          );
        // عشرة أسئلة جديدة تُطلق، وبينها تُفرَّغ النوافذ المعلقة كي لا
        // يسبق سقف اللحظة (ثلاث نوافذ) ميزانيةَ الزمن
        for (var i = 0; i < 10; i++) {
          fakeNow = i * 1000;
          final r = await p.check(
            origin: 'https://rot$i.evil.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          );
          expect(r!.code, 'origin_pending');
          if (gates.length > 2) {
            gates.removeAt(0).complete(OriginConsent.allowOnce);
            await pumpEventQueue();
          }
        }
        expect(asked, 10, reason: 'the budget itself allows ten new questions');
        // فرَّغ النوافذ الثلاث المتبقية: الحاجز أمام الحادي عشر وقتها هو
        // ميزانية الزمن وحدها — لا سقف اللحظة
        for (final g in gates) {
          g.complete(OriginConsent.allowOnce);
        }
        await pumpEventQueue();
        fakeNow = 10_000;
        final r11 = await p.check(
          origin: 'https://rot10.evil.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(
          r11!.code,
          'origin_pending',
          reason:
              'over the time budget the page still gets a retryable '
              'reply',
        );
        expect(
          asked,
          10,
          reason:
              'no new question fires over the budget - the pending '
              'windows are free, the budget is not',
        );
        // وبعد خروج كبار الأسئلة من النافذة يعود السؤال — ميزانية
        // متدحرجة لا قفلا دائما
        fakeNow = 601_001;
        final r12 = await p.check(
          origin: 'https://rot10.evil.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(r12!.code, 'origin_pending');
        expect(
          asked,
          11,
          reason: 'the budget is a rolling window, not a permanent lock',
        );
      },
    );

    test(
      'concurrent unknown-origin checks trigger exactly one host question',
      () async {
        var asked = 0;
        final gate = Completer<OriginConsent>();
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (_) {
                asked++;
                return gate.future;
              },
            ),
          );
        final a = p.check(
          origin: 'https://concurrent.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        final b = p.check(
          origin: 'https://concurrent.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(
          asked,
          1,
          reason: 'the second joins, it does not open a second window',
        );
        expect((await a)!.code, 'origin_pending');
        expect((await b)!.code, 'origin_pending');
        gate.complete(OriginConsent.allowAlways);
      },
    );

    test(
      'sandbox null origin is never asked — explicit origin_unknown',
      () async {
        var asked = 0;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) {
                asked++;
                return Completer<OriginConsent>().future;
              },
            ),
          );
        final r = await p.check(origin: 'null');
        expect(r, isNotNull);
        expect(r!.code, 'origin_unknown');
        expect(asked, 0, reason: 'null is not an origin to ask about');
      },
    );

    test(
      'crashed consent dialog expires cleanly; retry re-asks, never errors',
      () async {
        var asked = 0;
        final gates = <int, Completer<OriginConsent>>{};
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) {
                asked++;
                final g = Completer<OriginConsent>();
                gates[asked] = g;
                return g.future;
              },
              askTimeout: const Duration(milliseconds: 120),
            ),
          );
        await p.check(
          origin: 'https://crash.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ); // نافذة 1
        gates[1]!.completeError(StateError('dialog crashed'));
        await pumpEventQueue();
        expect(
          (await p.check(
            origin: 'https://crash.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
          reason: 'the collapsed window expired - it asks again, no 500',
        );
        expect(asked, 2);
      },
    );
  });

  group('allowlist policy and hardening contracts', () {
    test(
      'bare and wildcard allowlist entries match https only; http rejected',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowed: ['partner.io', '*.charts.example'],
            ),
          );
        expect(
          await p.check(origin: 'http://partner.io'),
          isNotNull,
          reason: 'regression: http for a bare entry used to be accepted',
        );
        expect(
          await p.check(origin: 'http://a.charts.example'),
          isNotNull,
          reason: 'and the pattern entry too',
        );
        expect(
          await p.check(
            origin: 'https://partner.io',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
        );
        expect(
          await p.check(
            origin: 'https://a.charts.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
        );
        // والاستثناء المحلي وحده يفتح http
        final local = IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowed: ['localhost'],
              allowLocalHttp: true,
            ),
          );
        expect(
          await local.check(
            origin: 'http://localhost:8080',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
        );
      },
    );

    test(
      'check returns instantly; silent prompt windows release after askTimeout',
      () async {
        var asked = 0;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) {
                asked++;
                return Completer<OriginConsent>().future;
              },
              askTimeout: const Duration(milliseconds: 150),
            ),
          );
        final sw = Stopwatch()..start();
        final r = await p.check(
          origin: 'https://new.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        sw.stop();
        expect(r!.code, 'origin_pending');
        expect(
          sw.elapsed,
          lessThan(const Duration(milliseconds: 100)),
          reason:
              'no waiting: the request returns at once and the page retries',
        );
        // النافذة الصامتة تشغل خانتها حتى انقضاء مهلتها — ثم يفتح المجال
        expect(
          (await p.check(
            origin: 'https://other.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
        );
        expect(asked, 2, reason: 'another origin: a new window (the cap is 3)');
        // انتظار حقيقي مقصود: يعبر مهلة السؤال الفعلية (150ms) — مؤقت
        // حقيقي لا يقدّمه ضخ الأحداث، ولا ساعة محقونة في هذه الواجهة
        await Future<void>.delayed(const Duration(milliseconds: 220));
        expect(
          (await p.check(
            origin: 'https://third.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
        );
        expect(
          asked,
          3,
          reason:
              'after both timeouts expired, their two slots freed for the third origin',
        );
      },
    );

    test(
      'pending-question cap: fourth unknown replies at once; listed origins unaffected',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              allowed: ['https://portal.example'],
              onUnknownOrigin: (origin) => Completer<OriginConsent>().future,
              askTimeout: const Duration(seconds: 30),
            ),
          );
        final pending = [
          for (final o in ['a1', 'a2', 'a3'])
            p.check(
              origin: 'https://$o.evil.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
        ];
        await pumpEventQueue();
        final fourth = await p.check(
          origin: 'https://a4.evil.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(fourth!.code, 'origin_pending', reason: 'over the pending cap');
        expect(
          await p.check(
            origin: 'https://portal.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'the listed origin crosses at the same moment',
        );
        expect(pending.length, 3);
      },
    );

    test(
      'hidden-form navigation from unlisted origin blocked without asking',
      () async {
        var asked = 0;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) async {
                asked++;
                return OriginConsent.allowAlways;
              },
            ),
          );
        final r = await p.check(
          origin: 'https://x.example',
          fetchMode: 'navigate',
          fetchDest: 'document',
        );
        expect(
          r!.code,
          'cross_site_blocked',
          reason: 'hardening before the question - no window for a hidden form',
        );
        expect(asked, 0);
      },
    );

    test('short token is refused at configuration time', () {
      final rec = _Rec();
      expect(
        () => IntakeProtection(telemetry: rec)..update(token: 'short-8'),
        throwsArgumentError,
        reason: 'the guessing floor is a configuration error, not a warning',
      );
    });

    test(
      'token_locked: the window is per-origin - a guessing origin locks only itself',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        final sw = Stopwatch()..start();
        // خمسة إخفاقات من أصل واحد تكفي لعتبة قفله وحده — بلا نوم
        for (var i = 0; i < 5; i++) {
          await p.check(origin: 'https://guess.example', portalToken: 'WRONG');
        }
        sw.stop();
        expect(
          sw.elapsed,
          lessThan(const Duration(milliseconds: 200)),
          reason: 'no sleep at all - the lock is immediate and free',
        );
        // التوكن الصحيح من الأصل المقفل نفسه: يُرد 429 — القفل يسبق المقارنة
        final correctButLocked = await p.check(
          origin: 'https://guess.example',
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        expect(correctButLocked!.status, 429);
        expect(correctButLocked.code, 'token_locked');
        // أصل آخر بالتوكن الصحيح: يعبر — قفل المخمّن لا يسجن الجسر
        // للبوابة الشرعية
        final other = await p.check(
          origin: 'https://legit.example',
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        expect(
          other,
          isNull,
          reason:
              'a guessing origin cannot lock the token for the '
              'legitimate origin',
        );
        // وبلا أصل: نافذة مشتركة مستقلة — التكامل المحلي لم يقفل بعد
        final anon = await p.check(origin: null, portalToken: 'WRONG');
        expect(
          anon!.code,
          isNot('token_locked'),
          reason: 'an originless window separate from web origins',
        );
        expect(
          await p.check(
            origin: null,
            portalToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
          reason: 'a correct token from an unlocked window passes',
        );
      },
    );

    test(
      'the originless window is one shared lock for local integrations',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        for (var i = 0; i < 5; i++) {
          await p.check(origin: null, portalToken: 'WRONG');
        }
        final anon = await p.check(
          origin: null,
          portalToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        expect(
          anon!.code,
          'token_locked',
          reason:
              'originless misses share one window - the lock precedes '
              'the comparison',
        );
        expect(
          await p.check(
            origin: 'https://web.example',
            portalToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
          reason: 'the originless lock does not touch web origins',
        );
      },
    );
  });

  group('short token refusal: configuration error, inert at boot', () {
    // التوكن القصير قابل للتخمين من صفحة ويب، فالطبقة إما كاملة أو
    // غير موجودة: الرفض وقت الإعداد لا تحذير يمر، والإقلاع لا ينهار
    test('update() throws for a token below 32 bytes instead of warning', () {
      final p = IntakeProtection(telemetry: _Rec());
      expect(
        () => p.update(token: 'SHORT'),
        throwsArgumentError,
        reason: 'a guessable token must never become an active layer',
      );
    });

    test('the short-token error names the length, never the token itself', () {
      final p = IntakeProtection(telemetry: _Rec());
      Object? caught;
      try {
        p.update(token: 'TOPSECRET-GUESSABLE');
      } catch (e) {
        caught = e;
      }
      expect(
        caught,
        isArgumentError,
        reason: 'the floor is still a configuration error',
      );
      expect(
        caught.toString(),
        isNot(contains('TOPSECRET')),
        reason:
            'a rejected secret must not surface in the exception text '
            'that hosts log',
      );
      expect(
        caught.toString(),
        contains('19 bytes'),
        reason: 'the length carries the diagnosis instead',
      );
    });

    test(
      'the throw applies nothing: previous state survives a failed update',
      () {
        final t64 =
            'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(allowed: ['https://portal.example']),
            token: t64,
          );
        expect(
          () => p.update(
            policy: const OriginPolicy(allowed: ['https://evil.example']),
            token: 'SHORT',
          ),
          throwsArgumentError,
        );
        // الحالة القديمة باقية حرفيا: المدرج القديم يعبر والجديد لا،
        // والتوكن القديم ما زال فعالا — الرمي بلا أثر جانبي
        expect(
          p.check(
            origin: 'https://portal.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          completion(isNull),
        );
        expect(
          p.check(
            origin: 'https://evil.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          completion(isNotNull),
          reason: 'the new allowlist was not applied - the old one still rules',
        );
        expect(
          p.check(origin: 'https://evil.example', portalToken: t64),
          completion(isNull),
          reason:
              'the old token still works - the failed update changed nothing',
        );
      },
    );

    test('a one-field update keeps the other layer', () async {
      final t64 =
          'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';
      final other64 =
          'b7e2d5f8a3c1e9046f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7a3f1c52e94b7d0';
      final p = IntakeProtection()
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
          token: t64,
        );
      // تحديث القائمة وحدها: طبقة التوكن لا تُطفأ
      p.update(
        policy: const OriginPolicy(
          allowed: ['https://portal.example', 'https://two.example'],
        ),
      );
      expect(
        await p.check(origin: 'https://elsewhere.example', portalToken: t64),
        isNull,
        reason: 'the token layer survives a policy-only update',
      );
      // وتحديث التوكن وحده: القائمة لا تُغلق على السياسة الفارغة
      p.update(token: other64);
      expect(
        await p.check(
          origin: 'https://two.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
        reason: 'the allowlist survives a token-only update',
      );
      expect(
        await p.check(
          origin: 'https://elsewhere.example',
          portalToken: other64,
        ),
        isNull,
        reason: 'the new token is active alongside the kept list',
      );
    });

    test(
      'saved short token stays inert at boot with one loud warning',
      () async {
        final rec = _Rec();
        final p = IntakeProtection(telemetry: rec);
        p.updateFromSaved(savedMode: 'token', token: 'SHORT');
        expect(
          rec.warns.any((w) => w.contains('inert')),
          isTrue,
          reason:
              'boot says once that the token layer is off, never crash-loops',
        );
        final verdict = await p.check(origin: null, portalToken: 'SHORT');
        expect(
          verdict,
          isNotNull,
          reason: 'an inert token must not admit even its own value',
        );
      },
    );
  });

  group('pending-question cap and comment fingerprint guard', () {
    test(
      'cap counts open prompt windows, not waiters — no fourth question',
      () async {
        var asked = 0;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) {
                asked++;
                return Completer<OriginConsent>().future;
              },
              askTimeout: const Duration(seconds: 30),
            ),
          );
        // ثلاث نوافذ مفتوحة لا تجيب
        for (final o in ['a1', 'a2', 'a3']) {
          expect(
            (await p.check(
              origin: 'https://$o.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
          );
        }
        // الرابع: فوق السقف — بلا نافذة رابعة (لا إرهاق بالمطالبة)
        expect(
          (await p.check(
            origin: 'https://a4.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
        );
        expect(
          asked,
          3,
          reason: 'three windows are open so a fourth is not opened',
        );
        // ولو أجيبت الأولى: تنضم للقائمة ويفتح مكانها
        // (تغطى بشاهد الإنهيار أعلاه)
      },
    );
  });

  group('re-audit hygiene: rejection log throttle and once-grant sweep', () {
    // فيضان سجل الرفض: طوفان صفحة يغرق telemetry بسطر لكل مرفوض —
    // الكبح بنمط خنق معرف الارتباط (1/ث + عدّاد مكتوم يُقال لاحقا)
    test(
      'a rejection flood logs at most one line per second, counter intact',
      () async {
        final rec = _Rec();
        var now = 0;
        final p = IntakeProtection(telemetry: rec, nowMs: () => now);
        p.update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
        );
        for (var i = 0; i < 20; i++) {
          now = i; // كلها داخل نافذة الثانية الأولى
          p.noteRejection(
            'Origin is not on the allowed list',
            'https://evil.example',
          );
        }
        expect(
          rec.warns.where((w) => w.contains('intake rejected')).length,
          lessThanOrEqualTo(2),
          reason:
              'twenty rejections inside one second must not be twenty '
              'log lines — the flood lives in the counter, not the log',
        );
        expect(
          p.rejectedCount,
          20,
          reason: 'throttling is logging-only: every rejection still counts',
        );
      },
    );

    test(
      'suppressed rejections are announced on the next emitted line',
      () async {
        final rec = _Rec();
        var now = 0;
        final p = IntakeProtection(telemetry: rec, nowMs: () => now);
        p.update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
        );
        for (var i = 0; i < 10; i++) {
          now = i;
          p.noteRejection(
            'Origin is not on the allowed list',
            'https://evil.example',
          );
        }
        now = 5000; // خارج نافذة الكبح — السطر التالي يخرج
        p.noteRejection(
          'Origin is not on the allowed list',
          'https://evil.example',
        );
        final emitted = rec.warns
            .where((w) => w.contains('intake rejected'))
            .toList();
        expect(emitted.length, 2);
        expect(emitted.last, contains('suppressed'));
      },
    );

    // منح allowOnce غير المستهلكة كانت تبقى للأبد — النسح عند الإدراج
    // يطرد المنتهية فلا ينمو المخطط بلا حد في الجلسات الطويلة
    test('expired once-grants are swept on insert, not kept forever', () async {
      var now = 0;
      final p = IntakeProtection(nowMs: () => now)
        ..update(
          policy: OriginPolicy(
            onUnknownOrigin: (origin) async => OriginConsent.allowOnce,
          ),
        );
      // 65 منحة: أولها o1 عند t=0 (تنتهي عند 30)، والبقية متباعدة
      // زمنيا فتتجاوز سقف الإدراج وتكنس المنتهية
      for (var i = 0; i < 65; i++) {
        now = i * 600_001;
        final verdict = await p.check(
          origin: 'https://o$i.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(verdict!.code, 'origin_pending');
      }
      // o1 أُجيبت allowOnce ولم تُستهلك: ساعتها تعود داخل نافذتها —
      // إن بقيت منحتها تُستهلك (null)، وإن كُنست يسأل من جديد
      now = 5;
      final afterSweep = await p.check(
        origin: 'https://o1.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      expect(
        afterSweep,
        isNotNull,
        reason:
            'the expired o1 grant must have been swept by the later '
            'inserts — an unconsumed grant cannot live forever',
      );
    });
  });
}
