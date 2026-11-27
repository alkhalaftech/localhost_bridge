// إشارة انتهاء سؤال الموافقة: المضيف يُبلَّغ مرة واحدة حين تُغلق النافذة
// — جواباً كان أو انهيار نداءه أو مهلتها — بلا مساس بتوقيع نداء السؤال
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
  group('the consent-question closed signal', () {
    test('an answered question signals its close exactly once, on the '
        'normalized origin', () async {
      final closed = <String>[];
      final gates = <String, Completer<OriginConsent>>{};
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            askTimeout: const Duration(minutes: 10),
            onUnknownOrigin: (origin) {
              final g = Completer<OriginConsent>();
              gates[origin] = g;
              return g.future;
            },
          ),
        )
        ..onQuestionClosed = closed.add;
      final a = await p.admit(origin: 'https://Q.example');
      expect(a.rejection?.code, 'origin_pending');
      a.settle();
      await pumpEventQueue();
      expect(closed, isEmpty, reason: 'an open window has not ended yet');
      gates['https://q.example']!.complete(OriginConsent.allowOnce);
      await pumpEventQueue();
      expect(
        closed,
        ['https://q.example'],
        reason:
            'the answer closes the window and the signal fires once on '
            'the same normalized origin the question was asked with',
      );
      // سؤال ثانٍ لأصل آخر: جوابه يرسل إشارته هو، والإشارتان بلا ازدواج
      final b = await p.admit(origin: 'https://other.example');
      expect(b.rejection?.code, 'origin_pending');
      b.settle();
      await pumpEventQueue();
      gates['https://other.example']!.complete(OriginConsent.dismissed);
      await pumpEventQueue();
      expect(closed, [
        'https://q.example',
        'https://other.example',
      ], reason: 'a dismissed question ended too - exactly one signal each');
      p.dispose();
    });

    test('a timeout-closed question signals once and its late answer adds '
        'no second signal', () async {
      final closed = <String>[];
      Completer<OriginConsent>? gate;
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            askTimeout: const Duration(milliseconds: 80),
            onUnknownOrigin: (origin) {
              gate = Completer<OriginConsent>();
              return gate!.future;
            },
          ),
        )
        ..onQuestionClosed = closed.add;
      final a = await p.admit(origin: 'https://slow.example');
      expect(a.rejection?.code, 'origin_pending');
      a.settle();
      await pumpEventQueue();
      // المهلة الحية تقود المؤقت الحقيقي لا الساعة المحقونة: انتظار يفوق
      // المهلة حتى تغلق النافذة بلا جواب
      await Future<void>.delayed(const Duration(milliseconds: 250));
      expect(closed, [
        'https://slow.example',
      ], reason: 'the ask timeout closes the window and the signal fires once');
      // الجواب المتأخر بعد الإغلاق: النافذة ليست حية فلا إشارة ثانية
      gate!.complete(OriginConsent.allowAlways);
      await pumpEventQueue();
      expect(closed, [
        'https://slow.example',
      ], reason: 'a late answer rides no live window - no second signal');
      p.dispose();
    });

    test('a thrown host future and a pure read each behave once', () async {
      final closed = <String>[];
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            askTimeout: const Duration(minutes: 10),
            onUnknownOrigin: (origin) =>
                Future<OriginConsent>.error(StateError('host dialog died')),
          ),
        )
        ..onQuestionClosed = closed.add;
      // نداء المضيف ينهار: النافذة تُغلق بإشارتها مرة واحدة
      final a = await p.admit(origin: 'https://dying.example');
      expect(a.rejection?.code, 'origin_pending');
      a.settle();
      await pumpEventQueue();
      expect(closed, [
        'https://dying.example',
      ], reason: 'a collapsed host future still ends the window - one signal');
      // القراءة الخالصة بلا تسوية لا تفتح سؤالاً فلا تُغلق شيئاً
      await p.admit(origin: 'https://never-settled.example');
      await pumpEventQueue();
      expect(closed.length, 1, reason: 'no settle, no question, no signal');
      p.dispose();
    });

    test('dispose closes the remaining windows silently', () async {
      final closed = <String>[];
      final p = IntakeProtection(nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            askTimeout: const Duration(minutes: 10),
            onUnknownOrigin: (origin) => Completer<OriginConsent>().future,
          ),
        )
        ..onQuestionClosed = closed.add;
      final a = await p.admit(origin: 'https://open-at-dispose.example');
      expect(a.rejection?.code, 'origin_pending');
      a.settle();
      await pumpEventQueue();
      p.dispose();
      await pumpEventQueue();
      expect(
        closed,
        isEmpty,
        reason:
            'the host tore the object down itself - no end-of-question '
            'signal rides dispose',
      );
    });

    test('a throwing closed-signal callback is contained and said', () async {
      final rec = _Rec();
      final gates = <String, Completer<OriginConsent>>{};
      final p = IntakeProtection(telemetry: rec, nowMs: () => 0)
        ..update(
          policy: OriginPolicy(
            requireFetchMetadata: false,
            askTimeout: const Duration(minutes: 10),
            onUnknownOrigin: (origin) {
              final g = Completer<OriginConsent>();
              gates[origin] = g;
              return g.future;
            },
          ),
        )
        ..onQuestionClosed = (origin) => throw StateError('UI gone');
      final a = await p.admit(origin: 'https://uigone.example');
      expect(a.rejection?.code, 'origin_pending');
      a.settle();
      await pumpEventQueue();
      // الجواب يُطبق رغم رمي الإشارة: الموافقة محفوظة والأصل يُقبل
      gates['https://uigone.example']!.complete(OriginConsent.allowAlways);
      await pumpEventQueue();
      final ok = await p.admit(origin: 'https://uigone.example');
      expect(
        ok.rejection,
        isNull,
        reason:
            'the throwing hook never breaks the answer path - the '
            'consent is remembered either way',
      );
      ok.settle();
      expect(rec.warns, isNotEmpty, reason: 'the contained throw is said');
      p.dispose();
    });
  });
}
