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
          bridgeToken:
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

      test('fetch metadata: navigate, no-cors, and absent headers rejected — '
          'cors alone passes', () async {
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
        // Absent Sec-Fetch headers are refused by default: a silent send
        // (legacy browser, hidden form) never crosses the hardened path.
        expect(
          (await p.check(origin: 'https://a.example'))!.code,
          'cross_site_blocked',
          reason: 'the default refuses headerless sends',
        );
        // The explicit off-switch is what admits headerless clients.
        final off = IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
            ),
          );
        expect(
          await off.check(origin: 'https://a.example'),
          isNull,
          reason: 'requireFetchMetadata: false admits headerless sends',
        );
      });

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
            bridgeToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
        );
        expect(
          await p.check(origin: 'https://portal.example', bridgeToken: 'WRONG'),
          isNull,
          reason: 'a listed origin is enough',
        );
        expect(
          await p.check(origin: 'https://other.example', bridgeToken: 'x'),
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
            await p.check(origin: null, bridgeToken: token),
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
        // 300 بايتاً فوق الحشوة بتنوّع يمر فحص التنوع — الشاهد هنا عن
        // الطول والتحذير لا عن التنوع
        final overPadToken = List.generate(
          300,
          (i) => '0123456789abcdef'[i % 16],
        ).join();
        p.update(token: overPadToken);
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
          await p.check(origin: null, bridgeToken: overPadToken),
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

    test(
      'a pending answer survives a token-only update under the same policy',
      () async {
        const t64 =
            'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';
        Completer<OriginConsent>? gate;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (origin) {
                gate = Completer<OriginConsent>();
                return gate!.future;
              },
              askTimeout: const Duration(seconds: 30),
            ),
          );
        expect(
          (await p.check(
            origin: 'https://pending.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
        );
        // تحديث التوكن وحده بالسياسة نفسها: قرارات الأصل لم تتغير فلا
        // جيل جديد — جواب السؤال المفتوح يبقى حياً ويُطبَّق
        p.update(token: t64);
        gate!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          await p.check(
            origin: 'https://pending.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason:
              'the token layer never changed origin decisions, so the '
              'open question answer must be saved',
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
        // and the explicit off-switch restores headerless passage — the
        // check sends no Sec-Fetch headers at all, which is the case the
        // switch exists for (a legacy browser or a raw non-browser client).
        final off = IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
            ),
          );
        expect(
          await off.check(origin: 'https://legacy.example'),
          isNull,
          reason: 'with the flag off a headerless client passes again',
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
        // ترتيب لا ساعة: مؤقت الشاهد يُسلَّح قبل النداء بمهلة السؤال
        // نفسها فيُجدول قبل مؤقت النافذة الداخلي بحكم الاشتغال لا
        // بهامش زمني — فإن عاد الرد قبل اشتغاله وثّق أن العودة سابقة
        // لمسار المؤقت كله؛ ولو انتظر check السؤال أو مهلته لعاد بعد
        // اشتغاله حصراً فيحمر الترتيب، ولو انتظر موافقة السؤال نفسها
        // لعاد الرد أبداً (البوابة لم تُحسم) فيحمر الاختبار بمهلته
        var probeFired = false;
        final probe = Timer(const Duration(milliseconds: 150), () {
          probeFired = true;
        });
        final r = await p.check(
          origin: 'https://new.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(r!.code, 'origin_pending');
        expect(
          probeFired,
          isFalse,
          reason:
              'the reply was recorded before the ask-deadline timer path '
              'fired - check hands the question to the page and returns at '
              'once; holding the call past the ask timeout would return '
              'only after this timer',
        );
        probe.cancel();
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
        // والثالث يسأل في الحال: الخانات الثلاث لم تمتلئ بعد (نافذتان)
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
          reason: 'the third unknown origin opens the last window',
        );
        // تحرر الخانة بإشارة من مسار المؤقت: الأصل الرابع لا يُسأل ما
        // دامت النوافذ الثلاث مفتوحة، ويُسأل فور انقضائها بمؤقتاتها -
        // نستطلع حتى تحدث الإشارة (سؤالٌ رابع) بلا أي هامش ساعة ثابت
        final waitFloor = DateTime.now().add(const Duration(seconds: 10));
        var fourthAsked = false;
        while (!fourthAsked) {
          if (DateTime.now().isAfter(waitFloor)) {
            fail('the askTimeout never released the occupied windows');
          }
          await Future<void>.delayed(const Duration(milliseconds: 50));
          final fourth = await p.check(
            origin: 'https://fourth.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          );
          expect(fourth!.code, 'origin_pending');
          fourthAsked = asked >= 4;
        }
        expect(
          asked,
          4,
          reason:
              'the fourth ask happens only after the three windows expired '
              'on their own askTimeout timers - the slot release is the '
              'timer-path signal, and a fourth window could not open while '
              'they held the cap',
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
      'the wrong-guess budget is per-origin - a guessing origin spends only its own',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        final sw = Stopwatch()..start();
        // خمسة إخفاقات من أصل واحد تكفي لميزانيته وحده — بلا نوم
        for (var i = 0; i < 5; i++) {
          await p.check(origin: 'https://guess.example', bridgeToken: 'WRONG');
        }
        sw.stop();
        expect(
          sw.elapsed,
          lessThan(const Duration(milliseconds: 200)),
          reason: 'no sleep at all - the budget is immediate and free',
        );
        // الخاطئ السادس فوق الميزانية: يُرد token_locked — الرمز باق
        // للتخمين الخاطئ لا للصحيح
        final sixthWrong = await p.check(
          origin: 'https://guess.example',
          bridgeToken: 'WRONG',
        );
        expect(sixthWrong!.status, 429);
        expect(sixthWrong.code, 'token_locked');
        // والتوكن الصحيح من الأصل المفيض نفسه: يُقارن ويُقبل — النافذة
        // إشارة لا رافض، وما فوق الميزانية رفضٌ للخاطئ لا للصحيح
        final correctAfterFlood = await p.check(
          origin: 'https://guess.example',
          bridgeToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        expect(
          correctAfterFlood,
          isNull,
          reason: 'the correct token is accepted whatever the failure history',
        );
        // أصل آخر بالتوكن الصحيح: يعبر — ميزانية المخمّن لا تسجن الجسر
        // للبوابة الشرعية
        final other = await p.check(
          origin: 'https://legit.example',
          bridgeToken:
              'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
        );
        expect(
          other,
          isNull,
          reason:
              'a guessing origin cannot spend the token budget for the '
              'legitimate origin',
        );
        // وبلا أصل: نافذة مشتركة مستقلة — التكامل المحلي لم ينفق بعد
        final anon = await p.check(origin: null, bridgeToken: 'WRONG');
        expect(
          anon!.code,
          isNot('token_locked'),
          reason: 'an originless window separate from web origins',
        );
        expect(
          await p.check(
            origin: null,
            bridgeToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
          reason: 'a correct token from an unspent window passes',
        );
      },
    );

    test(
      'the originless window is one shared budget for local integrations',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        for (var i = 0; i < 5; i++) {
          await p.check(origin: null, bridgeToken: 'WRONG');
        }
        // الخاطئ السادس فوق الميزانية المشتركة: يُرد — والصحيح بعده
        // يُقارن ويُقبَل أياً كان تاريخ الإخفاقات
        final wrongSixth = await p.check(origin: null, bridgeToken: 'WRONG');
        expect(
          wrongSixth!.code,
          'token_locked',
          reason:
              'originless misses share one budget - wrong guesses above it '
              'wait',
        );
        expect(
          await p.check(
            origin: null,
            bridgeToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
          reason: 'the shared window never refuses the correct token',
        );
        expect(
          await p.check(
            origin: 'https://web.example',
            bridgeToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
          reason: 'the originless budget does not touch web origins',
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
          p.check(origin: 'https://evil.example', bridgeToken: t64),
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
        await p.check(origin: 'https://elsewhere.example', bridgeToken: t64),
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
          bridgeToken: other64,
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
        final verdict = await p.check(origin: null, bridgeToken: 'SHORT');
        expect(
          verdict,
          isNotNull,
          reason: 'an inert token must not admit even its own value',
        );
      },
    );
  });

  group('policy numbers are validated at update time, never on the wire', () {
    test(
      'a corrupt quota or timeout throws and keeps the previous policy',
      () async {
        final p = IntakeProtection(telemetry: _Rec())
          ..update(
            policy: const OriginPolicy(
              allowed: ['https://portal.example'],
              perOriginPerMinute: 30,
              askTimeout: Duration(seconds: 60),
            ),
          );
        // A negative allow-all quota sits above every window length, so it
        // would answer 429 to every request; a zero ask timeout closes every
        // consent question before any answer can arrive. Both are
        // configuration mistakes that must surface at update() time.
        expect(
          () => p.update(policy: const OriginPolicy(perOriginPerMinute: -1)),
          throwsArgumentError,
        );
        expect(
          () => p.update(
            policy: const OriginPolicy(listedPerOriginPerMinute: -1),
          ),
          throwsArgumentError,
        );
        expect(
          () => p.update(policy: const OriginPolicy(askTimeout: Duration.zero)),
          throwsArgumentError,
        );
        // No half-apply: the previous policy rules exactly as it stood.
        expect(p.policy.perOriginPerMinute, 30);
        expect(p.policy.askTimeout, const Duration(seconds: 60));
        expect(p.policy.allowed, contains('https://portal.example'));
        expect(
          await p.check(
            origin: 'https://portal.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'the previous allowlist still decides after a failed update',
        );
        // And the zero listed quota stays legal: it means unquotaed.
        p.update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
        );
        expect(p.policy.listedPerOriginPerMinute, 0);
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

  group('rejection log throttle and once-grant sweep', () {
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

    test('logged Origin is stripped of control characters and capped', () {
      // The Origin header is attacker-controlled input: raw control
      // characters would forge extra log lines, and an unbounded value
      // would bloat every throttled line. The log sees a cleaned, capped
      // form; the counter and the decision still see the real value.
      final rec = _Rec();
      final p = IntakeProtection(telemetry: rec, nowMs: () => 0);
      final hostile = 'https://evil.example/\u0000\u001Fx${'a' * 500}';
      p.noteRejection('Origin is not on the allowed list', hostile);
      final line = rec.warns.single;
      final logged = line.substring(line.indexOf('origin=') + 'origin='.length);
      expect(logged, isNot(contains('\u0000')));
      expect(logged, isNot(contains('\u001F')));
      expect(line, isNot(contains(hostile)));
      expect(
        logged.length,
        lessThanOrEqualTo(200),
        reason: 'a long origin is capped, never dumped whole into the log',
      );
      expect(logged, startsWith('https://evil.example/x'));
    });

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

  group(
    'consent supersession: the latest question for an origin owns its answer',
    () {
      test(
        'a superseded window answer cannot override a newer decision',
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
          // السؤال أ يفتح وينتهي بلا جواب
          expect(
            (await p.check(
              origin: 'https://stale.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
          );
          await Future<void>.delayed(const Duration(milliseconds: 220));
          // السؤال ب للأصل نفسه يفتح ويُرفض
          expect(
            (await p.check(
              origin: 'https://stale.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
          );
          expect(asked, 2, reason: 'the expired window re-asks for the origin');
          gates[2]!.complete(OriginConsent.reject);
          await pumpEventQueue();
          expect(
            (await p.check(
              origin: 'https://stale.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_declined',
          );
          // جواب أ المتأخر بالسماح لا يطغى على قرار ب الأحدث
          gates[1]!.complete(OriginConsent.allowAlways);
          await pumpEventQueue();
          expect(
            (await p.check(
              origin: 'https://stale.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_declined',
            reason:
                'a superseded window answer never applies over the newer '
                'decision',
          );
        },
      );

      test(
        'a superseded allow cannot ride over a newer allowOnce grant',
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
          expect(
            (await p.check(
              origin: 'https://stalegrant.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
          );
          await Future<void>.delayed(const Duration(milliseconds: 220));
          expect(
            (await p.check(
              origin: 'https://stalegrant.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
          );
          gates[2]!.complete(OriginConsent.allowOnce);
          await pumpEventQueue();
          expect(
            await p.check(
              origin: 'https://stalegrant.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason: 'the newer once-grant serves the first retry',
          );
          // جواب أ المتأخر بالسماح الدائم لا يعود الأصل مقبولاً للأبد
          gates[1]!.complete(OriginConsent.allowAlways);
          await pumpEventQueue();
          expect(
            (await p.check(
              origin: 'https://stalegrant.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
            reason:
                'a stale allow must not admit the origin after the '
                'once-grant was consumed',
          );
          expect(asked, 3, reason: 'the origin is asked again, not admitted');
        },
      );

      test(
        'a stale answer cannot ride over a newer dismissed window',
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
          expect(
            (await p.check(
              origin: 'https://staledismiss.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
          );
          await Future<void>.delayed(const Duration(milliseconds: 220));
          expect(
            (await p.check(
              origin: 'https://staledismiss.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
          );
          // النافذة الأحدث أُغلقت بلا قرار — فجواب الأقدم بالرفض لا يُتذكر
          gates[2]!.complete(OriginConsent.dismissed);
          await pumpEventQueue();
          gates[1]!.complete(OriginConsent.reject);
          await pumpEventQueue();
          expect(
            (await p.check(
              origin: 'https://staledismiss.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
            reason: 'nothing is remembered from the superseded window',
          );
          expect(
            asked,
            3,
            reason:
                'dismissed leaves no memory and a stale reject must not '
                'create one',
          );
        },
      );

      test('a late answer with no newer question still applies', () async {
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
              askTimeout: const Duration(milliseconds: 120),
            ),
          );
        // نافذة تنتهي بلا جواب ثم يصل الجواب متأخراً بلا سؤال أحدث: هو
        // الكلمة الأخيرة للأصل فيطبق — سلوك مقصود لا يكسره ترقيم الأسئلة
        expect(
          (await p.check(
            origin: 'https://latelast.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
        );
        await Future<void>.delayed(const Duration(milliseconds: 220));
        gate!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          await p.check(
            origin: 'https://latelast.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'the late answer is the last word for the origin',
        );
        expect(asked, 1, reason: 'no newer question was opened for the origin');
      });

      test(
        'a late answer for an open question survives a thousand newer asks',
        () async {
          var fakeNow = 0;
          var asked = 0;
          final gates = <String, Completer<OriginConsent>>{};
          final p = IntakeProtection(nowMs: () => fakeNow)
            ..update(
              policy: OriginPolicy(
                onUnknownOrigin: (origin) {
                  asked++;
                  final g = Completer<OriginConsent>();
                  gates[origin] = g;
                  return g.future;
                },
                // أبعد من مدة الاختبار كله: النوافذ لا تنقضي بمؤقتها
                // الحي — فالسؤال المفتوح الوحيد يبقى مفتوحاً حتى جوابه
                askTimeout: const Duration(minutes: 10),
              ),
            );
          // مضخة سؤال-وجواب: بين كل عشرة أسئلة جديدة تُقدَّم الساعة
          // نافذةَ الميزانية (عشر دقائق) كي لا يسبق ميزانية الزمن
          // عدَّ الأسئلة — وسقف اللحظة (ثلاث نوافذ) لا يمس التصميم:
          // كل سؤال يُجاب فور إطلاقه فلا تتكدس النوافذ
          var sinceBudgetBump = 0;
          Future<void> askAndAnswer(String origin) async {
            if (sinceBudgetBump == 10) {
              fakeNow += 601_000;
              sinceBudgetBump = 0;
            }
            final r = await p.check(
              origin: origin,
              fetchMode: 'cors',
              fetchDest: 'empty',
            );
            expect(r!.code, 'origin_pending');
            sinceBudgetBump++;
            gates[origin]!.complete(OriginConsent.allowAlways);
            await pumpEventQueue();
          }

          // ألف أصل يُسأل ويُجاب: كل جواب يُطبق فيمحا رقمه فالخريطة
          // لا تنمو منهم (ترقيم الأصل يُمحى مع التطبيق)
          for (var i = 0; i < 1000; i++) {
            await askAndAnswer('https://answered$i.example');
          }
          // سؤال X يفتح ويبقى مفتوحاً: رقمه يبقى آخر رقم لأصله
          fakeNow += 601_000;
          const x = 'https://open.example';
          final rx = await p.check(
            origin: x,
            fetchMode: 'cors',
            fetchDest: 'empty',
          );
          expect(rx!.code, 'origin_pending');
          // ألف أصل آخر يُسأل ويُجاب — عقد السقف: الخريطة لا تتجاوز
          // سقف الموافقات ولا جوارٌ يُسقط خطأً بحجز السقف
          for (var i = 0; i < 1000; i++) {
            await askAndAnswer('https://later$i.example');
          }
          // جواب X المتأخر بلا سؤال أحدث لأصله هو الكلمة الأخيرة: يُطبق
          // ويُحفظ — طابورٌ جانبي يمحو رقم X الحي يجعله يسقط
          gates[x]!.complete(OriginConsent.allowAlways);
          await pumpEventQueue();
          expect(
            await p.check(origin: x, fetchMode: 'cors', fetchDest: 'empty'),
            isNull,
            reason:
                'the open question keeps its number across the newer asks '
                '- its late answer is still the last word and is remembered',
          );
          expect(
            await p.check(
              origin: 'https://later999.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason:
                'the newer asks keep their own answers - the cap '
                'bookkeeping drops no live answer of theirs',
          );
          expect(asked, 2001, reason: 'no origin was asked twice');
          p.dispose();
        },
      );

      test('a late answer for an open question survives a thousand abandoned '
          'windows', () async {
        var fakeNow = 0;
        var totalFires = 0;
        final asked = <String, int>{};
        final gates = <String, Completer<OriginConsent>>{};
        Future<OriginConsent> ask(String origin) {
          totalFires++;
          asked[origin] = (asked[origin] ?? 0) + 1;
          final g = Completer<OriginConsent>();
          gates[origin] = g;
          return g.future;
        }

        final p = IntakeProtection(nowMs: () => fakeNow)
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: ask,
              // أبعد من مدة الاختبار كله: نافذة X تبقى حية حتى جوابها
              askTimeout: const Duration(minutes: 10),
            ),
          );
        // سؤال X يُفتح أولاً ويبقى مفتوحاً: رقمه أول مفاتيح خريطة
        // الترقيم ونافذته حية — فرع الطرد عند السقف يجب أن يتجاوزه
        // شرط «ليس له سؤال حي» حصراً
        const x = 'https://open.example';
        expect(
          (await p.check(
            origin: x,
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
        );
        // قلب المهلة إلى قصيرة عبر تحديث سياسة لا يغيّر قرارات الأصل:
        // الجيل باقٍ فجواب X لا يقفل، والنوافذ الجديدة تنقضي بمؤقتها.
        // المؤقت حقيقي لا تقوده الساعة المحقونة — الانتظار الحي القصير
        // بعد كل سؤال هو ما يزيل النافذة من القائمة الحية ويترك رقمها
        // بلا سؤال حي
        p.update(
          policy: OriginPolicy(
            onUnknownOrigin: ask,
            askTimeout: const Duration(milliseconds: 1),
          ),
        );
        // مضخة الميزانية المعروفة: بين كل عشرة أسئلة تُقدَّم الساعة
        // نافذةَ الميزانية (عشر دقائق) كي لا يسبق ميزانية الزمن عدَّ
        // الأسئلة — والانتظار الحي يبقي النوافذ المعلقة تحت سقف اللحظة.
        // العدّ يبدأ من واحد: سؤال X نفسه استهلك خانة من ميزانية
        // العشرة فطابورها يبدأ بعنصر واحد
        var sinceBudgetBump = 1;
        Future<void> askAbandoned(String origin) async {
          if (sinceBudgetBump == 10) {
            fakeNow += 601_000;
            sinceBudgetBump = 0;
          }
          final fires = totalFires;
          final r = await p.check(
            origin: origin,
            fetchMode: 'cors',
            fetchDest: 'empty',
          );
          expect(r?.code, 'origin_pending');
          expect(
            totalFires,
            fires + 1,
            reason: 'every abandoned ask must fire its own question',
          );
          sinceBudgetBump++;
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }

        // ألف نافذة تُفتح وتنقضي مهلتها بلا جواب: خريطة الترقيم تمتلئ
        // بألف رقم لا سؤال حياً لها
        for (var i = 0; i < 1000; i++) {
          await askAbandoned('https://ghost$i.example');
        }
        // مضخة قبل ما بعدها: ميزانية الأسئلة لا تسدّ الفحوص التالية
        fakeNow += 601_000;
        // خمسون نافذة جديدة فوق السقف: كل إدراج يُشغّل فرع الطرد فيأكل
        // الأشباح من مقدمة الإدراج — ورقم X الحي لا يُلمَس
        for (var i = 0; i < 50; i++) {
          await askAbandoned('https://wave$i.example');
        }

        // جواب X المتأخر يُطبق: يُحفظ والأصل يُقبل بلا سؤال ثانٍ
        fakeNow += 601_000;
        gates[x]!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          await p.check(origin: x, fetchMode: 'cors', fetchDest: 'empty'),
          isNull,
          reason:
              'the live question kept its number across the abandoned '
              'windows - its late answer is remembered',
        );
        expect(asked[x], 1, reason: 'no second question for the origin');

        // جواب أقدم شبح طُرد رقمه لا يُطبق: الأصل يُسأل من جديد عند
        // طلبه التالي فعدّاد أسئلته يزيد
        gates['https://ghost0.example']!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          (await p.check(
            origin: 'https://ghost0.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ))!.code,
          'origin_pending',
          reason:
              'its number was evicted, so the late answer is not the '
              'last word - the origin is asked anew',
        );
        expect(
          asked['https://ghost0.example'],
          2,
          reason: 'the question counter increases for the evicted ghost',
        );

        // جواب شبح لم يُطرد (آخرها) يُطبق — فالطرد أصاب الأقدم بلا
        // سؤال حي حصراً
        gates['https://ghost999.example']!.complete(OriginConsent.allowAlways);
        await pumpEventQueue();
        expect(
          await p.check(
            origin: 'https://ghost999.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason:
              'its number was never evicted, so the late answer is the '
              'last word for the origin',
        );
        expect(asked['https://ghost999.example'], 1);
        // ألف شبح + خمسون + سؤال X + إعادة سؤال الشبح المطرود — لا
        // سؤال ثانٍ لأحد سواهم
        expect(totalFires, 1052);
        p.dispose();
      });
    },
  );

  group('quota window: a rejected request does not occupy the quota', () {
    test(
      'waiting exactly Retry-After after a rejection admits the retry',
      () async {
        var now = 0;
        final p = IntakeProtection(nowMs: () => now)
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              perOriginPerMinute: 3,
            ),
          );
        for (final at in [0, 15000, 30000]) {
          now = at;
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason: 'accepted at ${at}ms inside the quota',
          );
        }
        now = 31000;
        final over = await p.check(
          origin: 'https://a.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(over!.code, 'origin_rate_limited');
        expect(
          over.retryAfterMs,
          29500,
          reason: 'the honest remainder from the oldest admitted stamp',
        );
        now += over.retryAfterMs!;
        expect(
          await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason:
              'the rejected request left the window, so the announced '
              'wait actually lands',
        );
      },
    );

    test(
      '20000 rejected attempts leave the window at the quota length',
      () async {
        var now = 0;
        final p = IntakeProtection(nowMs: () => now)
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              perOriginPerMinute: 3,
            ),
          );
        for (var i = 0; i < 3; i++) {
          now = i * 15000;
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
          );
        }
        now = 31000;
        IntakeRejection? over;
        for (var i = 0; i < 20000; i++) {
          over = await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          );
          if (over == null || over.code != 'origin_rate_limited') {
            fail('flood attempt $i must be rejected, got ${over?.code}');
          }
        }
        // آخر رفض يعلن بقايا أقدم طابع مقبول (0) لا طوابع المرفوضات
        expect(over!.retryAfterMs, 29500);
        now += over.retryAfterMs!;
        expect(
          await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'the window held only the admitted requests all along',
        );
      },
    );

    test('the same rule holds for the listed-path quota', () async {
      var now = 0;
      final p = IntakeProtection(nowMs: () => now)
        ..update(
          policy: const OriginPolicy(
            allowed: ['https://a.example'],
            listedPerOriginPerMinute: 3,
          ),
        );
      for (final at in [0, 15000, 30000]) {
        now = at;
        expect(
          await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
        );
      }
      now = 31000;
      final over = await p.check(
        origin: 'https://a.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      expect(over!.code, 'origin_rate_limited');
      expect(over.retryAfterMs, 29500);
      now += over.retryAfterMs!;
      expect(
        await p.check(
          origin: 'https://a.example',
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
        reason: 'the listed path drops its rejections from the window too',
      );
    });

    test(
      'watch mode also drops the would-be-rejected stamp from the window',
      () async {
        final rec = _Rec();
        var now = 0;
        final p = IntakeProtection(telemetry: rec, nowMs: () => now)
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              reportOnly: true,
              perOriginPerMinute: 3,
            ),
          );
        for (final at in [0, 15000, 30000]) {
          now = at;
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
          );
        }
        expect(
          rec.warns.where((w) => w.contains('would reject')),
          isEmpty,
          reason: 'the admitted requests are inside the quota',
        );
        now = 31000;
        for (var i = 0; i < 20000; i++) {
          expect(
            await p.check(
              origin: 'https://a.example',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ),
            isNull,
            reason: 'watching serves every request',
          );
        }
        expect(
          rec.warns.where((w) => w.contains('would reject')).length,
          20000,
          reason: 'each flood attempt was measured, never silenced',
        );
        now = 60500; // مقادار Retry-After الصادق: أقدم طابع مقبول 0
        expect(
          await p.check(
            origin: 'https://a.example',
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
        );
        expect(
          rec.warns.where((w) => w.contains('would reject')).length,
          20000,
          reason:
              'the would-rejects left no stamp, so the honest wait lands '
              'with no new would-reject',
        );
      },
    );
  });

  group('rejection lines carry no raw origin', () {
    void expectSanitizedLine(String line, String hostile) {
      expect(
        line.contains(hostile),
        isFalse,
        reason: 'the raw origin never enters the line',
      );
      expect(
        line.contains('\u0000') || line.contains('\u001F'),
        isFalse,
        reason: 'no control character survives anywhere in the line',
      );
      // حقل الأصل نفسه: بين 'origin=' وقوس الإغلاق إن وُجد (سطور
      // المراقبة تحيطه بقوسين، وسطر noteRejection يليه اللاحقة مباشرة)
      final start = line.indexOf('origin=') + 'origin='.length;
      final close = line.indexOf(')', start);
      final logged = close == -1
          ? line.substring(start)
          : line.substring(start, close);
      expect(
        logged.length,
        lessThanOrEqualTo(200),
        reason: 'the origin field stays under its declared cap',
      );
    }

    test(
      'the origin_not_listed line through a real check carries no raw origin',
      () async {
        final rec = _Rec();
        final p = IntakeProtection(telemetry: rec, nowMs: () => 0);
        final hostile = 'https://evil.example/\u0000\u001F${'a' * 1000}';
        final r = await p.check(origin: hostile);
        expect(r!.code, 'origin_not_listed');
        // مسار الخادم الحقيقي: رسالة الرفض نفسها هي سبب السجل — أي قيمة
        // خام داخلها تنسخ إلى السطر كله
        p.noteRejection(r.message, hostile);
        expectSanitizedLine(rec.warns.single, hostile);
      },
    );

    test(
      'the listed-quota watch line passes through the origin sanitizer',
      () async {
        final rec = _Rec();
        final hostile = 'https://evil.example/\u0000\u001F${'a' * 1000}';
        final p = IntakeProtection(telemetry: rec, nowMs: () => 0)
          ..update(
            policy: OriginPolicy(
              allowed: [hostile],
              listedPerOriginPerMinute: 1,
              reportOnly: true,
            ),
          );
        expect(await p.check(origin: hostile), isNull);
        expect(
          await p.check(origin: hostile),
          isNull,
          reason: 'watching serves over the quota',
        );
        expectSanitizedLine(
          rec.warns.singleWhere((w) => w.contains('would reject')),
          hostile,
        );
      },
    );

    test(
      'the allow-all watch line passes through the origin sanitizer',
      () async {
        final rec = _Rec();
        final hostile = 'https://evil.example/\u0000\u001F${'a' * 1000}';
        final p = IntakeProtection(telemetry: rec, nowMs: () => 0)
          ..update(
            policy: OriginPolicy(
              allowAllHardened: true,
              reportOnly: true,
              perOriginPerMinute: 1,
            ),
          );
        expect(
          await p.check(origin: hostile, fetchMode: 'cors', fetchDest: 'empty'),
          isNull,
        );
        expect(
          await p.check(origin: hostile, fetchMode: 'cors', fetchDest: 'empty'),
          isNull,
        );
        expectSanitizedLine(
          rec.warns.singleWhere((w) => w.contains('would reject')),
          hostile,
        );
      },
    );
  });

  group('origin normalization output contract', () {
    test('trailing slashes are stripped and case is unified', () {
      expect(
        IntakeProtection.normalize('https://Portal.Example.COM///'),
        'https://portal.example.com',
      );
      expect(
        IntakeProtection.normalize('HTTPS://PORTAL.EXAMPLE.COM/'),
        'https://portal.example.com',
      );
      expect(
        IntakeProtection.normalize('https://portal.example.com/'),
        'https://portal.example.com',
      );
    });

    test('an origin with no trailing slash comes back unchanged', () {
      expect(
        IntakeProtection.normalize('https://portal.example.com'),
        'https://portal.example.com',
      );
      expect(
        IntakeProtection.normalize('https://portal.example.com/a/b'),
        'https://portal.example.com/a/b',
      );
    });

    test(
      'slashes inside the origin are kept; only the final run is removed',
      () {
        expect(
          IntakeProtection.normalize('https://portal.example.com/a/b//'),
          'https://portal.example.com/a/b',
        );
        // المدخل المبطن بشرطات لا تقع في الآخر يعود كما هو — الشكل الذي
        // كان يربّع زمن المسح عليه بلا أي تغيير في الناتج
        final padded = 'https://portal.example${'/' * 5000}x';
        expect(IntakeProtection.normalize(padded), padded);
      },
    );
  });

  group('token miss-window retention below the cap', () {
    test(
      'a thousand stale miss windows release their origins after the window; a fresh burst re-locks from zero',
      () async {
        var now = 0;
        final p = IntakeProtection(nowMs: () => now)
          ..update(
            policy: const OriginPolicy(),
            token:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          );
        // ألف أصل بإخفاق واحد لكل منها: الخريطة عند سقفها بالضبط —
        // الكنس الذي كان ينتظر ما فوق السقف يتركها مقيدة إلى الأبد
        for (var i = 0; i < 1000; i++) {
          final r = await p.check(
            origin: 'https://stale$i.example',
            bridgeToken: 'WRONG',
          );
          expect(r!.code, 'origin_not_listed');
        }
        // تقديم الساعة بعد النافذة ثم طلب واحد آخر — نبضة الكنس
        now += 61_000;
        expect(
          (await p.check(
            origin: 'https://fresh.example',
            bridgeToken: 'WRONG',
          ))!.code,
          'origin_not_listed',
        );
        // عقد الاحتفاظ بما يُرصد علنياً: لا شبح من النافذة المنقضية —
        // التوكن الصحيح يعبر، والانفجار الجديد ينفق الميزانية من الصفر
        // بانتظار صادق
        expect(
          await p.check(
            origin: 'https://stale0.example',
            bridgeToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
          reason: 'an expired window never haunts its origin',
        );
        for (var i = 0; i < 5; i++) {
          await p.check(origin: 'https://stale0.example', bridgeToken: 'WRONG');
        }
        // الخاطئ السادس فوق الميزانية المنفقة يُرد بانتظار يحسب
        // الإخفاقات الطازجة وحدها فالمعلن صادق — والصحيح بعده يُقبل
        final locked = await p.check(
          origin: 'https://stale0.example',
          bridgeToken: 'WRONG',
        );
        expect(locked!.code, 'token_locked');
        expect(
          locked.retryAfterMs,
          60_500,
          reason:
              'the re-lock counts only fresh misses - the expired window '
              'exerted no influence and the announced wait is honest',
        );
        expect(
          await p.check(
            origin: 'https://stale0.example',
            bridgeToken:
                'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7',
          ),
          isNull,
          reason: 'the correct token is accepted whatever the fresh misses',
        );
      },
    );
  });

  group('one token verdict per request: the verified token keeps its verdict', () {
    const t64 =
        'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

    test('a budget-spent window never refuses the correct token and never '
        'hides its host message', () async {
      final p = IntakeProtection()
        ..update(
          policy: const OriginPolicy(allowAllHardened: true),
          token: t64,
        );
      for (var i = 0; i < 5; i++) {
        await p.check(
          origin: 'https://guess.example',
          bridgeToken: 'WRONG',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
      }
      // خمسة إخفاقات انفقت ميزانية الأصل: الطلب الصحيح يُقارن ويُقبل —
      // والنص التفصيلي للمضيف يقرأ نتيجة المقارنة المسجلة نفسها فالمتحقق
      // منه يأخذ نصه مهما كان تاريخ الإخفاقات، والنافذة إشارة عن
      // التخمين الخاطئ لا رافض للتوكن الصحيح
      expect(
        await p.check(
          origin: 'https://guess.example',
          bridgeToken: t64,
          fetchMode: 'cors',
          fetchDest: 'empty',
        ),
        isNull,
        reason: 'the spent budget admits the verified token',
      );
      expect(
        p.verboseErrorsFor('https://guess.example', t64),
        isTrue,
        reason:
            'a verified token keeps the host text whatever the miss-window '
            'history - the verdict reads the recorded comparison',
      );
      // النافذة المشتركة للطلبات بلا Origin تحكم القرار نفسه: الصحيح
      // يُقبل ولا يُخفى نصه
      for (var i = 0; i < 5; i++) {
        await p.check(origin: null, bridgeToken: 'WRONG');
      }
      expect(
        await p.check(origin: null, bridgeToken: t64),
        isNull,
        reason: 'the shared originless window never refuses the correct token',
      );
      expect(
        p.verboseErrorsFor(null, t64),
        isTrue,
        reason: 'a verified token over the shared window keeps the text too',
      );
    });

    test(
      'with no misses the correct token from an unlisted origin keeps the message',
      () async {
        final p = IntakeProtection()
          ..update(
            policy: const OriginPolicy(allowAllHardened: true),
            token: t64,
          );
        expect(
          p.verboseErrorsFor('https://quiet.example', t64),
          isTrue,
          reason: 'no failure window exists - the correct token is trusted',
        );
        final listed = IntakeProtection()
          ..update(
            policy: const OriginPolicy(allowed: ['https://portal.example']),
            token: t64,
          );
        expect(
          listed.verboseErrorsFor('https://portal.example', null),
          isTrue,
          reason: 'a listed origin earns the message without any token',
        );
      },
    );

    test(
      'after the lock window expires on the injected clock the message returns',
      () async {
        var now = 0;
        final p = IntakeProtection(nowMs: () => now)
          ..update(
            policy: const OriginPolicy(allowAllHardened: true),
            token: t64,
          );
        for (var i = 0; i < 5; i++) {
          await p.check(
            origin: 'https://guess.example',
            bridgeToken: 'WRONG',
            fetchMode: 'cors',
            fetchDest: 'empty',
          );
        }
        now = 60_001;
        expect(
          await p.check(
            origin: 'https://guess.example',
            bridgeToken: t64,
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'the window expired - the lock no longer holds',
        );
        expect(
          p.verboseErrorsFor('https://guess.example', t64),
          isTrue,
          reason: 'an expired window never haunts the verbose decision',
        );
      },
    );

    test(
      'a spent budget is refused without opening a new consent question',
      () async {
        var asked = 0;
        final p = IntakeProtection()
          ..update(
            policy: OriginPolicy(
              onUnknownOrigin: (_) {
                asked++;
                return Future<OriginConsent>.value(OriginConsent.dismissed);
              },
            ),
            token: t64,
          );
        // خمسة إخفاقات من أصل جديد: كل واحد يفتح سؤالاً ويُجاب dismissed
        // فوراً فلا يبقى أثر للسؤال
        for (var i = 0; i < 5; i++) {
          expect(
            (await p.check(
              origin: 'https://fresh.example',
              bridgeToken: 'WRONG',
              fetchMode: 'cors',
              fetchDest: 'empty',
            ))!.code,
            'origin_pending',
          );
          await pumpEventQueue();
        }
        expect(asked, 5, reason: 'each in-budget miss fired its own question');
        // السادس الخاطئ فوق الميزانية: يُرد token_locked بلا سؤال سادس،
        // فطلب فوق الميزانية لا يفتح نوافذ موافقة جديدة مهما ما زالت
        // ميزانية الأسئلة تسمح — والصحيح فوق الميزانية نفسها يُقبل
        final sixth = await p.check(
          origin: 'https://fresh.example',
          bridgeToken: 'WRONG',
          fetchMode: 'cors',
          fetchDest: 'empty',
        );
        expect(sixth!.status, 429);
        expect(sixth.code, 'token_locked');
        expect(
          asked,
          5,
          reason:
              'a budget-spent request opens no consent question - the '
              'callback counter stays at five',
        );
        expect(
          await p.check(
            origin: 'https://fresh.example',
            bridgeToken: t64,
            fetchMode: 'cors',
            fetchDest: 'empty',
          ),
          isNull,
          reason: 'the correct token over the spent budget is accepted',
        );
      },
    );
  });
}
