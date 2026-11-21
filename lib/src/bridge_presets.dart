// الإعدادات الجاهزة الأربعة — مصنع واحد لطبقة الحماية، وكل إعداد يعطي
// سياسته المطابقة حرفاً كما يوثق رأسه. الابناء تنتهي عند update() الواحد
// فتحقق التوكن ورسالة خطأه هما حرفاً تحقق الخادم نفسه، ولا إعداد يُضعف
// شيئاً: «مغلق» والقائمة بلا توكن، و«توكن فقط» يُبقي سياسة الأصول مغلقة
// كاملة (الباب الوحيد طبقة التوكن المستقلة)، و«جوال» يشتّرط الأصل
// والتوكن معاً (requireOriginWithToken) ويسلح الاقتران. لا إعداد هنا
// يفتح allow-all ولا يسلح الاكتشاف — لا شكلاً ولا قيمة افتراضية.

import 'bridge_telemetry.dart';
import 'intake_protection.dart';

/// The four ready-made protection presets - a host picks one instead of
/// assembling an [IntakeProtection] by hand. Every preset returns a fully
/// built protection whose [IntakeProtection.policy] matches its contract
/// exactly (each factory's doc names the literal shape), so the choice is
/// checkable, not folklore. None of them opens allow-all and none of them
/// arms discovery - the widest thing a preset can produce is the
/// host's own origin list.
///
/// - [closed]: every origin refuses; no token, no pairing. The intake
///   answers `403 origin_not_listed` on every browser page and every
///   token attempt (the token layer sits unconfigured, so it admits
///   nothing).
/// - [allowList]: the host's own origin list admits, exactly as
///   `OriginPolicy.allowed` matches (full origins pin scheme and port;
///   bare hosts and `*.domain` admit https on any port). No token, no
///   pairing.
/// - [tokenOnly]: the origin policy stays closed and the token is the
///   one door - a correct `X-Bridge-Token` crosses without browser
///   headers (local programs and agents); everything else reads
///   `403 origin_not_listed`, and a wrong token is answered with the
///   origin rejection alone, so a bad sender learns nothing about its
///   token.
/// - [mobile]: the host pairs its pages - [OriginPolicy.requireOriginWithToken]
///   closes the one-legged doors (a qualified origin without proof reads
///   `403 token_required`; the token alone never admits) and the pairing
///   layer is armed (`startPairing` / `POST /pair`, the origin-bound
///   signed proof), so a page qualifies by pairing instead of a raw
///   token. This is the preset a mobile host starts from: pair the
///   pages it serves, list any external origins beside them.
///
/// Token validation is the standing one: a token below the 32-byte floor,
/// over the header cap, or too low in character diversity throws
/// [ArgumentError] at build time - a preset never arms a token the wire
/// would refuse.
abstract final class BridgePresets {
  /// The closed preset - the literal closed shape. The policy is the
  /// default [OriginPolicy]: an empty `allowed` list, no allow-all, no
  /// discovery callback, the Fetch Metadata check on, the quotas at their
  /// defaults, and `requireOriginWithToken` off; pairing sits disarmed.
  /// Nothing admits; pass [telemetry] to hear the security log.
  static IntakeProtection closed({BridgeTelemetry? telemetry}) =>
      IntakeProtection(telemetry: telemetry)
        ..update(policy: const OriginPolicy());

  /// The allow-list preset - exactly [origins] admit, stored with the
  /// standing normalization (trimmed, lower-cased, trailing slashes
  /// stripped, blanks dropped) and matched like every listed entry. The
  /// policy carries no allow-all, no discovery, and
  /// `requireOriginWithToken` off; no token is configured and pairing
  /// sits disarmed.
  static IntakeProtection allowList({
    required List<String> origins,
    BridgeTelemetry? telemetry,
  }) =>
      IntakeProtection(telemetry: telemetry)
        ..update(policy: OriginPolicy(allowed: origins));

  /// The token-only preset - the origin policy stays the closed shape and
  /// [token] is the one door: a correct `X-Bridge-Token` admits a
  /// headerless client on its own; every origin path refuses. The policy
  /// is the default [OriginPolicy] with `requireOriginWithToken` off (the
  /// token crosses through its independent path, not through the
  /// combined requirement), and pairing sits disarmed.
  static IntakeProtection tokenOnly({
    required String token,
    BridgeTelemetry? telemetry,
  }) =>
      IntakeProtection(telemetry: telemetry)
        ..update(policy: const OriginPolicy(), token: token);

  /// The mobile preset - the paired host. The policy carries [origins]
  /// (empty by default: pages the bridge itself serves qualify on their
  /// own while the local-pages option is armed) with
  /// [OriginPolicy.requireOriginWithToken] on, and the pairing layer is
  /// armed with the host's callbacks - `startPairing` shows a one-time
  /// code, the page pairs at `POST /pair`, and the issued origin-bound
  /// token signs every request afterwards. The shared [token] is the
  /// bridge secret the proofs derive from and the direct path for
  /// clients that carry origin plus token together.
  static IntakeProtection mobile({
    required String token,
    List<String> origins = const [],
    BridgeTelemetry? telemetry,
    void Function(PairingInfo info)? onPaired,
    Future<void> Function(String origin, String token, int lifetimeMs)?
    onPairedSave,
    void Function(String origin)? onPairedRevoke,
    void Function(String origin, OriginConsent consent)? onConsentSave,
  }) {
    final protection = IntakeProtection(telemetry: telemetry)
      ..update(
        policy: OriginPolicy(allowed: origins, requireOriginWithToken: true),
        token: token,
      )
      ..enablePairing(
        onPaired: onPaired,
        onPairedSave: onPairedSave,
        onPairedRevoke: onPairedRevoke,
        onConsentSave: onConsentSave,
      );
    return protection;
  }
}
