// شاهد الحياد وشهود وجه النشر فقط هنا: مفردات المجال الداخلية لا تُشحن
// مع الحزمة والوجه المنشور محايد — أي إضافة تفشل وتُطلب تعليل موثق.
// frozen-neutrality witness: the domain-term scan in lib matches the
// full set against the frozen allowlist - empty since lib went fully
// neutral - and the vocabulary witness bans the original product's
// wording outright.
import 'dart:io';

import 'package:test/test.dart';

/// The frozen allowlist - what the domain-term scan may still find in lib.
/// It is empty: lib carries no domain vocabulary at all. The identifiers
/// that used to live here (the portal wrapper key, the standing error
/// code) moved out with the neutral defaults: wrapper keys are
/// config-driven and the fallback code is command_failed. `label` stays
/// deliberately excluded from the pattern: measure(label) is an API name,
/// not printing - the same false-positive family as fingerprint.
///
/// The two hardware command names the scan below still names (zpl,
/// escpos) - and every other term this guard spells out in order to
/// forbid it - stay in this file on purpose: a guard cannot work without
/// naming its targets, and paraphrasing them away would only camouflage
/// the gate.
const _frozen = <String, Map<String, int>>{};

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
        // zpl/escpos اسما عتاد صريحان يبقيان مسميين عمداً: الحارس لا
        // يعمل دون أن يسمي ما يمنعه.
        // الرموز المصنّعة غير حساسة للحالة؛
        // وlabel مستبعد عمداً: معامل measure(label) اسم API لا طباعة —
        // صنيفة fingerprint الكاذبة نفسها.
        final domainRe = RegExp(
          'طباع[ةى]|ملص[قكم]|\\bprint\\b|print_failed|\\bzpl\\b|\\bescpos\\b',
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

  test(
    'product-vocabulary neutrality: no original-product wording anywhere in lib',
    () {
      // The published face describes a host logger, plain commands, and a
      // local Dart app. The original product's own vocabulary - its logger
      // type name, its "label commands" phrase, its printing wording -
      // never ships in lib, in comments included: the scan is whole-file,
      // so a comment cannot carry what the docs promise is absent.
      final vocabRe = RegExp(
        'AppLogger|label commands|printing',
        caseSensitive: false,
      );
      final found = <String, List<String>>{};
      final libDir = Directory('lib');
      for (final entity in libDir.listSync(recursive: true)) {
        if (entity is! File || !entity.path.endsWith('.dart')) continue;
        final rel = entity.path.replaceAll('\\', '/');
        final hits = vocabRe
            .allMatches(entity.readAsStringSync())
            .map((m) => m.group(0)!)
            .toList();
        if (hits.isNotEmpty) found[rel] = hits;
      }
      expect(
        found,
        isEmpty,
        reason:
            'lib carries original-product wording - the published face '
            'speaks of a host logger, commands, and a local Dart app',
      );
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
