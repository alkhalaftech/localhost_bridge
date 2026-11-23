// مثال من مجال الدفع — بيانات تجريدية حصراً: مضيف يستقبل أوامر وصل دفع
// فوق طبقة التوكن (سياسة فارغة + توكن = حامل السر هو المرسل الوحيد)،
// ولا يُنفَّذ وصل إلا بمرجع تفويض صادراً من المضيف نفسه — وهذا المرجع
// هو محل «تأكيد الإنسان» في هذا المثال: يُطبع عند الإقلاع، ويُستهلك
// استعمالاً واحداً، وينقضي بعد خمس دقائق.
//
// الرد على السلك هو {"ok":true} أو رمز الخطأ حصراً — لا بيانات نتيجة،
// فكل ما يراه المرسل هو القرار لا الوصل نفسه.
//
// شغّله من جذر الحزمة: dart run example/payment_receipt.dart
// ثم أرسل (بالتوكن المطبوع عند الإقلاع والمرجع المطبوع معه):
// curl -X POST -H "X-Bridge-Token: $BRIDGE_TOKEN" \
//   -H "Content-Type: application/json" \
//   -d '{"data":["{\"action\":\"receipt\",\"ref\":\"<المرجع المطبوع>\",\"order\":\"DEMO-9\",\"totalMinor\":1250,\"currency\":\"EUR\"}"]}' \
//   http://127.0.0.1:$PORT/
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

// مواصفة الوصل بمفاتيح مغلقة: action/ref/order/totalMinor/currency.
const _receiptKeys = {'action', 'ref', 'order', 'totalMinor', 'currency'};
// العملات التجريدية المسموحة — قائمة مغلقة.
const _currencies = {'EUR', 'USD', 'SAR'};
// سقف المبلغ بالوحدات الصغرى — حد تجريدي داخلي باسم.
const _maxTotalMinor = 100000000;
// عمر مرجع التفويض — يجب أن يطابق دورة قرار الإنسان عندك لا أطول.
const _authorizeRefTtl = Duration(minutes: 5);
// سقف المراجع الحية — بعده يُرفض الإصدار fail-closed لا طرد حي.
const _maxLiveAuthorizeRefs = 64;

class _AuthorizeRef {
  _AuthorizeRef(this.expiresAt);
  final DateTime expiresAt;
}

// دفتر التفويض: مرجع واحد استعمال واحد، وامتلاكه لا يعني الشرعية بل
// مجرد المرور من بوابة القرار — كما TrustedCommand بالضبط.
final _liveRefs = <String, _AuthorizeRef>{};

String _issueRef() {
  final now = DateTime.now();
  _liveRefs.removeWhere((_, r) => now.isAfter(r.expiresAt));
  if (_liveRefs.length >= _maxLiveAuthorizeRefs) {
    throw StateError('authorize-ref ledger is full — refuse fail-closed');
  }
  final ref =
      'DEMO-A-${now.microsecondsSinceEpoch.toRadixString(36).toUpperCase()}';
  _liveRefs[ref] = _AuthorizeRef(now.add(_authorizeRefTtl));
  return ref;
}

// التحقق المجالي لأمر وصل واحد: مواصفة مغلقة، ومرجع حي يُستهلك مرة
// واحدة قبل أي أثر، ثم قيم مغلقة.
CommandOutcome _settleReceipt(String payload) {
  final Object? decoded;
  try {
    decoded = jsonDecode(payload);
  } on FormatException {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_receipt_spec',
      errorMessage: 'a receipt command must be one JSON object',
    );
  }
  if (decoded is! Map<String, dynamic>) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_receipt_spec',
      errorMessage: 'a receipt command must be one JSON object',
    );
  }
  final keys = decoded.keys.toSet();
  if (!keys.containsAll(_receiptKeys) ||
      keys.any((k) => !_receiptKeys.contains(k))) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_receipt_spec',
      errorMessage:
          'receipt spec keys are closed: action, ref, order, totalMinor, currency',
    );
  }
  if (decoded['action'] != 'receipt') {
    return const CommandOutcome(
      ok: false,
      errorCode: 'unknown_command',
      errorMessage: 'only the receipt action is accepted here',
    );
  }
  final ref = decoded['ref'];
  final entry = ref is String ? _liveRefs.remove(ref) : null;
  if (entry == null || DateTime.now().isAfter(entry.expiresAt)) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'unauthorized_ref',
      errorMessage: 'no live authorize ref — ask the host to issue one',
    );
  }
  final order = decoded['order'];
  if (order is! String || !order.startsWith('DEMO-') || order.length > 16) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_receipt_spec',
      errorMessage: 'order must be a demo id of at most 16 characters',
    );
  }
  final totalMinor = decoded['totalMinor'];
  if (totalMinor is! int || totalMinor < 1 || totalMinor > _maxTotalMinor) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_receipt_spec',
      errorMessage: 'totalMinor must be a positive integer within the cap',
    );
  }
  final currency = decoded['currency'];
  if (currency is! String || !_currencies.contains(currency)) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_receipt_spec',
      errorMessage: 'currency must be one of EUR, USD, SAR',
    );
  }
  stdout.writeln(
    'receipt settled (demo): order=$order totalMinor=$totalMinor '
    'currency=$currency ref=$ref',
  );
  return const CommandOutcome(ok: true);
}

Future<void> main() async {
  final token = generateBridgeToken();
  final server = LocalIntakeServer(
    onCommand: (cmd) async {
      for (final payload in cmd.payloads) {
        final outcome = _settleReceipt(payload);
        if (!outcome.ok) return outcome;
      }
      return const CommandOutcome(ok: true);
    },
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        DateTime.now().microsecondsSinceEpoch.toRadixString(36),
    handlerTimeout: const Duration(seconds: 5),
    protection: IntakeProtection(telemetry: const SilentTelemetry())
      ..update(
        token: token,
        // سياسة فارغة + توكن: حامل السر هو المرسل الوحيد — أي صفحة
        // مهما زوّرت أصلها لا تعبر (لا صدى فحص مسبق تحت الفارغة).
        policy: const OriginPolicy(),
      ),
  );

  final port = await server.start(preferredPort: 9320);
  final demoRef = _issueRef();
  stdout
    ..writeln(
      'payment receipt demo — listening on http://127.0.0.1:$port '
      '(empty policy + token: the token holder is the only sender)',
    )
    ..writeln('token   : $token')
    ..writeln(
      'authorize ref (single-use, expires in ${_authorizeRefTtl.inMinutes} min): $demoRef',
    )
    ..writeln(
      'a real host issues this ref from its own confirmation UI — the '
      'bridge never sees it',
    )
    ..writeln('the curl in the file header settles one demo receipt; bye.');

  await ProcessSignal.sigint.watch().first;
  await server.stop();
}
