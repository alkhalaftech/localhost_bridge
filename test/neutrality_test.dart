// شاهد الحياد وشهود وجه النشر فقط هنا — حارس بصمات العمليات انتقل
// إلى tools/protocol-hooks/package-fingerprints.mjs بجذر المستودع:
// مفرداتنا الداخلية لا تُشحن مع الحزمة (الوجه المنشور محايد).
// frozen-neutrality witness: strips printing/label terms in lib and
// matches the full set against the locked allowlist. Any addition or growth
// يفشل الاختبار ويُطلب تعليل موثق للإضافة.
import 'dart:io';

import 'package:test/test.dart';

/// The frozen allowlist - what the domain-term scan may still find in lib:
/// one TSPL note in a comment. The two wire identifiers that used to live
/// here (tscCode the portal key, print_failed a standing error code) moved
/// out with the neutral defaults: wrapper keys are config-driven and the
/// fallback code is command_failed, so lib carries no domain vocabulary.
/// `label` stays deliberately excluded: measure(label) is an API name, not
/// printing - the same false-positive family as fingerprint.
const _frozen = <String, Map<String, int>>{
  'lib/src/local_intake_server.dart': {'TSPL': 1},
};

void main() {
  test(
    'frozen neutrality: no printing/label terms in lib beyond the locked allowlist',
    () {
      final found = <String, Map<String, int>>{};
      final libDir = Directory('lib');
      for (final entity in libDir.listSync(recursive: true)) {
        if (entity is! File || !entity.path.endsWith('.dart')) continue;
        final rel = entity.path.replaceAll('\\', '/');
        final counts = <String, int>{};
        // شبكة دقيقة الرموز: print تستثني fingerprint وprint_failed
        // تلقائياً (حدّا الكلمة)، وعائلتا طباع/ملص تغطيان السطر الحامل
        // «يطبع ملصقاً» عبر ملصقاً — و«الطابع/يطبع '?'» تسجيليان لا يُعدّان.
        // zpl/tspl/escpos أوامر عتاد صريحة.
        // الرموز المصنّعة غير حساسة للحالة (TSPL الفعلية ب:420)؛
        // وlabel مستبعد عمداً: معامل measure(label) اسم API لا طباعة —
        // صنيفة fingerprint الكاذبة نفسها.
        final domainRe = RegExp(
          'طباع[ةى]|ملص[قكم]|\\bprint\\b|print_failed|tscCode|\\bzpl\\b|\\btspl\\b|\\bescpos\\b',
          caseSensitive: false,
        );
        for (final m in domainRe.allMatches(entity.readAsStringSync())) {
          final term = m.group(0)!;
          counts[term] = (counts[term] ?? 0) + 1;
        }
        if (counts.isNotEmpty) found[rel] = counts;
      }
      // اتحاد المفاتيح: ملف جديد يحمل مصطلحاً يفشل أيضاً
      final files = {...found.keys, ..._frozen.keys};
      for (final f in files) {
        expect(
          found[f] ?? const <String, int>{},
          equals(_frozen[f] ?? const <String, int>{}),
          reason:
              '$f — الحياد مجمّد عند المسموحات المقفلة؛ '
              'أي تغيير يُطلب له تعليل موثق',
        );
      }
    },
  );

  test('purity: zero Arabic inside string literals of lib', () {
    final litRe = RegExp("'[^']*'|\"[^\"]*\"");
    final arabic = RegExp('[\u0600-\u06FF]');
    final libDir = Directory('lib');
    for (final entity in libDir.listSync(recursive: true)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      // التعليقات حقها العربية — تنزع قبل فحص الحرفيات. حد نظري
      // النزع الخطي `//.*` يأكل ما بعد // داخل حرفية
      // (كhttp://) — اتجاهه السلبية الكاذبة فقط (يفلت لا يفتري)
      final noComments = entity
          .readAsStringSync()
          .replaceAll(RegExp('//.*'), '')
          .replaceAll(RegExp('/\\*[\\s\\S]*?\\*/'), '');
      for (final m in litRe.allMatches(noComments)) {
        expect(
          arabic.hasMatch(m.group(0)!),
          isFalse,
          reason:
              '${entity.path} يحمل عربية داخل حرفية نصية — '
              'الوجه المنشور إنجليزي محايد: ${m.group(0)}',
        );
      }
    }
  });

  test('purity: zero Arabic inside test and group titles', () {
    // عناوين الاختبارات والمجموعات تُنشر مع الحزمة وتعرض على pub.dev —
    // عقدها إنجليزي سلوكي، والعربية مكانها أسباب expect والتعليقات.
    // النمط يشمل الاقتباس المزدوج والسلاسل المتجاورة (القسم الثاني من
    // عنوان مقسوم) كي لا يهرب عنوان بإزاحة عربيته لمقطع لاحق
    final titleRe = RegExp(
      r"(?:test|group)\(\s*(?:'[^']*'|[\x22][^\x22]*[\x22])"
      r"(?:\s*(?:'[^']*'|[\x22][^\x22]*[\x22]))*",
      dotAll: true,
    );
    final arabic = RegExp('[\u0600-\u06FF]');
    final testDir3 = Directory('test');
    for (final entity in testDir3.listSync(recursive: true)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;
      for (final m in titleRe.allMatches(entity.readAsStringSync())) {
        expect(
          arabic.hasMatch(m.group(0)!),
          isFalse,
          reason:
              '${entity.path}: عنوان اختبار يحمل عربية — '
              'الوجه المنشور إنجليزي سلوكي: ${m.group(0)}',
        );
      }
    }
  });
}
