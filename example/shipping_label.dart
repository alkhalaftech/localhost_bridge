// مثال من مجال الشحن — بيانات تجريدية حصراً: مضيف مستودع يستقبل أوامر
// إصدار ملصقات شحن من بوابة المتجر، وكل التحقق جهة المضيف (الجسر لا يفهم
// الحمولات). نمط التهيئة: أصل مدرج واحد + حصة لكل أصل، والأمر كائن JSON
// بمفاتيح مغلقة قبل أي تنفيذ.
//
// شغّله من جذر الحزمة: dart run example/shipping_label.dart
// ثم أرسل من أصل مدرج (الأمر JSON داخل مصفوفة الحمولات):
// curl -X POST -H "Origin: https://store.example" \
//   -H "Content-Type: application/json" \
//   -d '{"data":["{\"action\":\"label\",\"consignment\":\"DEMO-C-1\",\"lane\":\"A\",\"items\":3}"]}' \
//   http://127.0.0.1:$PORT/
//
// إصدار الملصق أمر بأثر (استهلاك شريط/تكلفة ناقل): المضيف الجاد يضعه
// خلف تأكيد بشري ودفتر عدم تكرار — انظر example/idempotent_handler.dart
// وقسم «Recommended setup for irreversible commands» في SECURITY.md.
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';

// مواصفة الملصق بمفاتيح مغلقة: كل مفتاح ناقص أو زائد رفض قبل التنفيذ —
// لا إضافة صامتة لمفتاح مجال جديد.
const _labelKeys = {'action', 'consignment', 'lane', 'items'};
// الممرات التجريدية المسموحة — قائمة مغلقة كأفعال الأوامر.
const _lanes = {'A', 'B', 'C'};
// سقف عناصر الشحنة الواحدة — حد تجريدي داخلي باسم.
const _maxItemsPerConsignment = 500;

// التحقق المجالي لأمر ملصق واحد: مواصفة مغلقة ثم قيم مغلقة، وكل رفض
// يحمل رمزاً ثابتاً يقرأه مطور البوابة.
CommandOutcome _createLabel(String payload) {
  final Object? decoded;
  try {
    decoded = jsonDecode(payload);
  } on FormatException {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_label_spec',
      errorMessage: 'a label command must be one JSON object',
    );
  }
  if (decoded is! Map<String, dynamic>) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_label_spec',
      errorMessage: 'a label command must be one JSON object',
    );
  }
  final keys = decoded.keys.toSet();
  if (!keys.containsAll(_labelKeys) ||
      keys.any((k) => !_labelKeys.contains(k))) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_label_spec',
      errorMessage:
          'label spec keys are closed: action, consignment, lane, items',
    );
  }
  if (decoded['action'] != 'label') {
    return const CommandOutcome(
      ok: false,
      errorCode: 'unknown_command',
      errorMessage: 'only the label action is accepted here',
    );
  }
  final consignment = decoded['consignment'];
  if (consignment is! String ||
      !consignment.startsWith('DEMO-C-') ||
      consignment.length > 24) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_label_spec',
      errorMessage: 'consignment must be a demo id of at most 24 characters',
    );
  }
  final lane = decoded['lane'];
  if (lane is! String || !_lanes.contains(lane)) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_label_spec',
      errorMessage: 'lane must be one of A, B, C',
    );
  }
  final items = decoded['items'];
  if (items is! int || items < 1 || items > _maxItemsPerConsignment) {
    return const CommandOutcome(
      ok: false,
      errorCode: 'bad_label_spec',
      errorMessage:
          'items must be an integer between 1 and $_maxItemsPerConsignment',
    );
  }
  stdout.writeln(
    'label created (demo): consignment=$consignment lane=$lane items=$items',
  );
  return const CommandOutcome(ok: true);
}

Future<void> main() async {
  final server = LocalIntakeServer(
    onCommand: (cmd) async {
      // الحمولات بيانات غير موثوقة حتى بعد قبول الأصل — كل عنصر يُحقق
      // قبل أي أثر، وأول رفض يوقف البقية.
      for (final payload in cmd.payloads) {
        final outcome = _createLabel(payload);
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
        policy: const OriginPolicy(
          // بوابة المتجر وحدها — قائمة مغلقة بحصة أصل، والبقية مرفوضة.
          allowed: ['https://store.example'],
          listedPerOriginPerMinute: 120,
        ),
      ),
  );

  final port = await server.start(preferredPort: 9310);
  stdout
    ..writeln(
      'shipping label demo — listening on http://127.0.0.1:$port '
      '(origin https://store.example, quota 120/min)',
    )
    ..writeln('the curl in the file header sends one demo label; bye.');

  await ProcessSignal.sigint.watch().first;
  await server.stop();
}
