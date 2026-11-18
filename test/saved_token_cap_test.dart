// عقد التوكن المحفوظ فوق سقف الترويسة (أكبر من 1,024 بايت UTF-8): يُعامل
// كالقصير المحفوظ عينه — الطبقة تُقلع خاملة (فشل مغلق) بتحذير واحد عالٍ
// بصنف security يسمي الطول والسقف وgenerateBridgeToken للتدوير، ولا رمي
// في أي حال، وupdate() بعد الإقلاع هذا حي يطبق السياسة (لا فخ قفل).
import 'dart:convert';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

/// A deterministic 1,025-byte token over the header cap, with 32 distinct
/// ASCII characters so the diversity floor never explains the outcome.
String _overCapToken() {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz012345';
  return List.generate(1025, (i) => alphabet[i % alphabet.length]).join();
}

/// Telemetry recorder keeping each warn line with its category.
class _SavedCapRec extends BridgeTelemetry {
  final warns = <String>[];
  final categories = <BridgeCategory>[];

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
    categories.add(category);
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
  test(
    'the witness token is exactly 1,025 UTF-8 bytes and character-diverse',
    () {
      final token = _overCapToken();
      expect(
        utf8.encode(token).length,
        1025,
        reason: 'one byte past the 1,024-byte header cap, exactly',
      );
      expect(
        token.runes.toSet().length,
        greaterThanOrEqualTo(8),
        reason:
            'the diversity floor stays clear, so length alone decides '
            'the outcome',
      );
    },
  );

  test('a saved token over the header cap boots the token layer inert with '
      'exactly one loud security warning', () async {
    final token = _overCapToken();
    final rec = _SavedCapRec();
    final p = IntakeProtection(telemetry: rec);
    p.updateFromSaved(savedMode: 'token', token: token);
    expect(
      rec.warns,
      hasLength(1),
      reason:
          'one loud warning at boot - not silence, not a crash-loop '
          'flood',
    );
    expect(
      rec.categories,
      everyElement(BridgeCategory.security),
      reason: 'the saved-token defect is a security line',
    );
    expect(
      rec.warns.single,
      contains('1025'),
      reason: 'the warning names the saved length',
    );
    expect(
      rec.warns.single,
      contains('1024'),
      reason: 'the warning names the header cap the wire enforces',
    );
    expect(
      rec.warns.single,
      contains('generateBridgeToken'),
      reason: 'the warning names the rotation path',
    );
    // الخمول عين ملاحظة القصير المحفوظ: قيمة التوكن نفسها لا تُقبل —
    // الطبقة مطفأة فيقرر الافتراضي المغلق
    final verdict = await p.check(origin: null, bridgeToken: token);
    expect(
      verdict,
      isNotNull,
      reason:
          'the over-cap token must not sit configured active - the layer '
          'boots inert, so even its own value is not admitted',
    );
    expect(
      verdict!.code,
      'origin_not_listed',
      reason: 'inert means the closed default decides, not the token layer',
    );
  });

  test('after an over-cap saved boot, a policy-only update() applies without '
      'throwing', () async {
    final token = _overCapToken();
    final p = IntakeProtection(telemetry: _SavedCapRec());
    p.updateFromSaved(savedMode: 'token', token: token);
    expect(
      () => p.update(
        policy: const OriginPolicy(allowed: ['https://portal.example']),
      ),
      returnsNormally,
      reason:
          'the inert boot must not leave a state whose inherited token '
          'makes every later policy update throw',
    );
    expect(
      p.policy.allowed,
      contains('https://portal.example'),
      reason: 'the new policy is applied, not merely tolerated',
    );
    expect(
      await p.check(
        origin: 'https://portal.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      ),
      isNull,
      reason: 'the applied allowlist admits its origin on the wire',
    );
  });
}
