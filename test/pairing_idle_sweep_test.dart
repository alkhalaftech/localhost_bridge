// الكنس الدوري القائم يخرج حالة الاقتران الميتة: الجلسات المنتهية
// والسجلات المقترنة المنتهية (ومنها فهرس المعرف) وذاكرة إعادة التوقيع —
// لا ينتظر الموتى إدراج الاقتران التالي ليموتوا. الأثر السلكي الوحيد
// الموثق: رمز جلسة كُنست بالخمول يجيب pair_code_invalid بدل
// pair_code_expired (كلاهما 403 والإرشاد واحد)، والسجلات وذاكرة
// الإعادة سلكها لا يتغير (فحص الانتهاء والطبع يسبق أثرهما). والحراسة
// العكسية هنا أيضاً: الكنس بالخمول لا يُخرج سجلاً حياً أبداً. العناوين
// بالإنجليزية (حزمة منشورة) والتعليقات بالعربية (قاعدة البيت).
import 'dart:convert';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:localhost_bridge/src/digest.dart' show hexEncode, hmacSha256;

const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

final _clockMs = <int>[1_000_000];

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
  }) => body();
}

/// حماية صارمة مقترنة بساعة محقونة — نمط شاهد التوقيع القائم حرفا
IntakeProtection _strictPaired() {
  final protection = IntakeProtection(telemetry: _Rec(), nowMs: () => _clockMs[0])
    ..update(
      policy: const OriginPolicy(
        allowed: ['https://portal.example'],
        requireOriginWithToken: true,
      ),
      token: _t64,
    )
    ..enablePairing();
  return protection;
}

/// توكن حشو مميز بالموقع — كل سجل حشو يحتاج توكناً مختلفاً كي لا يستبدل
/// أحدهم الآخر في الخريطة (مفتاحها digest التوكن)
String _fillerToken(int i) => _t64.replaceFirst(
  'a3f1',
  i.toRadixString(16).padLeft(4, '0'),
);

/// توقيع صفحة بنفس بناء شاهد التوقيع القائم — الطابع من ساعة الجدار
/// الحقيقية (نافذة الانحراف تُقاس عليها لا على الساعة المحقونة)
String _sign({required String token, required String pairingId}) {
  final stamp = DateTime.now().millisecondsSinceEpoch;
  final canonical = 'v1\n$pairingId\n$stamp\nPOST\n/\n';
  final keyBytes = [
    for (var i = 0; i + 1 < token.length; i += 2)
      int.parse(token.substring(i, i + 2), radix: 16),
  ];
  final signature = hexEncode(hmacSha256(keyBytes, utf8.encode(canonical)));
  return '$pairingId.$stamp.$signature';
}

void main() {
  setUp(() {
    _clockMs[0] = 1_000_000;
  });

  test(
    'an expired pairing session swept by idle traffic answers '
    'pair_code_invalid, and a session inside its life is untouched',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final pr = IntakeProtection(nowMs: () => _clockMs[0], telemetry: _Rec())
        ..update(
          // الوضع المحصن: حصة الأصل (30/دقيقة افتراضا) هي الفرع الذي
          // يقود كنس الخاملين على مرور الطلب
          policy: const OriginPolicy(allowAllHardened: true),
        )
        ..enablePairing();
      // المنتهية أولاً بعمر كامل، ثم الحية تولد بعد دقيقة فتعيش أبعد
      // من نقطة الكنس (لو ولدتا معاً في المللي-ثانية نفسها لموتا معاً)
      final expired = pr.startPairing();
      _clockMs[0] += 60_000;
      final live = pr.startPairing();
      _clockMs[0] += 61_000;
      // مسير الكنس: طلب متصفح واحد بأصل https مؤهل يمر ببوابة الحصة
      // فيقود كنس الخاملين مرة كل ثانية — هو الذي يجب أن يخرج الجلسة
      // الميتة (admit إسقاط خالص والتسوية هي التي تهبط بأثر نافذة
      // الحصة، والوضع المحصن يطلب ترويسات الـfetch ليقبل أصلاً)
      final drive = await pr.admit(
        origin: 'https://portal.example',
        fetchMode: 'cors',
        fetchDest: 'empty',
      );
      drive.settle();
      final dead = pr.pair(
        origin: 'https://portal.example',
        code: expired.code,
      );
      expect(
        dead.rejection?.code,
        'pair_code_invalid',
        reason:
            'the idle sweep removed the expired session - the code is an '
            'unknown one now, not a known-but-expired one',
      );
      final alive = pr.pair(
        origin: 'https://portal.example',
        code: live.code,
      );
      expect(
        alive.token,
        isNotNull,
        reason: 'the still-live session survives the idle sweep',
      );
    },
  );

  test(
    'expired paired records leave through the idle pass: the insert-time '
    'eviction never fires on a live record, and a live binding keeps '
    'verifying after the churn',
    timeout: const Timeout(Duration(seconds: 20)),
    () async {
      final pr = _strictPaired();
      // الربط الحي أولاً بعمر كامل (24 ساعة)
      final first = pr.pair(
        origin: 'https://portal.example',
        code: pr.startPairing().code,
      );
      final liveToken = first.token!;
      final liveId = first.pairingId!;
      // ثم 63 سجلاً حشواً بعمر ثانية واحدة يمتلئ معها البيت (السقف 64)
      for (var i = 0; i < 63; i++) {
        pr.restorePairedOrigin(
          origin: 'https://filler$i.example',
          token: _fillerToken(i),
          remainingMs: 1000,
        );
      }
      // الحشوان انتهى وهم جالسون في الخريطة (بلا أي إدراج اقتران بعدهم)
      _clockMs[0] += 2000;
      // مسير الكنس عبر نافذة إخفاق التوكن: توكن خاطئ متعمد على البوابة
      // الصارمة يفتح نافذة الإخفاق التي يقودها الكنس الدوري فيخرج
      // حالة الاقتران الميتة (والحكم token_required لا يهم الشاهد)
      final drive = await pr.admit(
        origin: 'https://portal.example',
        bridgeToken:
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      );
      drive.settle();
      // اقتران جديد بعد الكنس: بيته أُفرغ من الموتى فلا يُطرد الحي —
      // وكان الإدراج القديم يكنس المنتهية بنفسه، والحراسة الحقيقية أن
      // السجل الحي ما زال يوقّع بعد الدوران كله
      final second = pr.pair(
        origin: 'https://portal.example',
        code: pr.startPairing().code,
      );
      expect(second.token, isNotNull, reason: 'the house has room after the sweep');
      // توقيع جديد (طابع جديد فلا إعادة) يثبت أن سجل الحي خرج من الكنس
      // سليماً وقبوله بمسار الربط المقترن نفسه
      final a = await pr.admit(
        origin: 'https://portal.example',
        pairingProof: _sign(token: liveToken, pairingId: liveId),
      );
      a.settle();
      expect(
        a.acceptedPath,
        IntakeAdmissionPath.originWithPairedToken,
        reason:
            'the live binding still verifies after the idle sweeps and the '
            'churn - the sweep removed only the expired',
      );
    },
  );
}
