// شاهد تطابق الدليلين قسماً قسماً: README.md وREADME.ar.md يجب أن
// يعرضا خمسة عشر قسماً من المستوى الثاني بالترتيب نفسه، وكل زوج
// قسمين متساوٍ في عدد كتل الشيفرة المسوّرة وعدد أسطر الجداول وعدد
// عناوين المستوى الثالث وعدد عناصر القوائم، وكل ما بين علامتَي
// backtick في ضلع يوجد حرفاً في الضلع الآخر إلا استثنائاً معللاً في
// القائمة أدناه. كتل الشيفرة المسوّرة تُستبعد من فحص الفواصل لأن
// ما فيها تعليقات ورموز لغات لا معرّفات عقد سلك. علامات الاتجاه
// الحرفية تُنزع قبل المقارنة، والمسافات المتتالية تنطبق إلى مسافة
// واحدة فلا يكسر لفُّ السطر تطابقَ معرّف.
import 'dart:io';

import 'package:test/test.dart';

/// The English/Arabic level-2 section title pairs, in the order both
/// guides must present them.
const List<(String, String)> sectionPairs = [
  ('Quick start', 'البدء السريع'),
  ('Ready-made presets', 'الإعدادات الجاهزة'),
  (
    'Security model — read before choosing a policy',
    'نموذج الأمن — اقرأه قبل اختيار السياسة',
  ),
  ('Origin policy reference', 'مرجع سياسة الأصول'),
  (
    'ArrivalGuard — an optional host-side tool',
    'ArrivalGuard — أداة اختيارية لدى المضيف',
  ),
  ('Wire contract (what your page sees)', 'عقد السلك (ما تراه صفحتك)'),
  (
    'The host-to-page channels (streaming replies and the WebSocket)',
    'قناتا المضيف إلى الصفحة (الرد المتدفق والويب سوكيت)',
  ),
  (
    'Mounting the bridge on an existing dart:io server',
    'تركيب الجسر على خادم dart:io قائم',
  ),
  (
    'The local pages (an optional page from memory)',
    'الصفحات المحلية (صفحة اختيارية من الذاكرة)',
  ),
  (
    'The listeners, the lifecycle, and the health page',
    'المستمعات ودورة الحياة وصفحة الصحة',
  ),
  ('Page-side reference (JavaScript)', 'مرجع جهة الصفحة (JavaScript)'),
  ('Browser support (reviewed 2026-11)', 'دعم المتصفحات (آخر فحص: 2026-11)'),
  ('Host platforms', 'منصات المضيف'),
  ('Limits (by design)', 'الحدود (بقرار تصميمي)'),
  ('Documentation', 'الوثائق'),
];

/// Inline-code spans allowed to sit on one side only, each justified.
/// Every other span's text must appear verbatim in the opposite side's
/// section.
const Map<String, String> allowedSpanAsymmetries = {
  // نثر إنجليزي ملفوف بعلامتين لا معرّفاً؛ اسم حقل السلك هو `error`
  // وهو المذكور في الضلع العربي من الجملة نفسها.
  'code':
      'English prose word wrapped in backticks in the intro bullet; the '
      'wire field itself is "error", which the Arabic side quotes',
  // من قائمة «ما تحصل عليه» في المقدمة العربية؛ موضع كل معرّف أدناه
  // مشترك بين الدليلين ويُفحص هناك في قسمه.
  'Sec-Fetch-Mode: cors':
      'from the Arabic intro what-you-get list; checked in the '
      'requireFetchMetadata row of the origin-policy reference on both '
      'sides',
  'Sec-Fetch-Dest: empty':
      'from the Arabic intro what-you-get list; checked in the '
      'requireFetchMetadata row of the origin-policy reference on both '
      'sides',
  'no-cors':
      'from the Arabic intro what-you-get list; checked in the '
      'security-model allow-all bullet on both sides',
  'perOriginPerMinute':
      'from the Arabic intro what-you-get list; checked in its '
      'origin-policy reference row on both sides',
  'listedPerOriginPerMinute':
      'from the Arabic intro what-you-get list; checked in its '
      'origin-policy reference row on both sides',
  'Vary: Origin':
      'from the Arabic intro what-you-get list; checked in the '
      'quick-start CORS echo sentence on both sides',
  'Retry-After':
      'from the Arabic intro what-you-get list; checked across the '
      'wire-contract section on both sides',
  'X-Correlation-Id':
      'from the Arabic intro what-you-get list; checked across the '
      'wire-contract section on both sides',
  'BridgeTelemetry':
      'from the Arabic intro what-you-get list; on the English side it '
      'lives inside the fenced Dart quick-start block, which this check '
      'excludes by design',
};

final RegExp _headingLine = RegExp(r'^## (.+)$');
final RegExp _bidiMarks = RegExp('[\u200e\u200f\u202a-\u202e\u2066-\u2069]');

/// Collapses bidi control marks and whitespace runs so line wrapping
/// never breaks an identifier comparison.
String _normalize(String text) =>
    text.replaceAll(_bidiMarks, '').replaceAll(RegExp(r'\s+'), ' ').trim();

final class _Guide {
  final String intro;
  final List<String> headings;
  final Map<String, String> bodies;

  const _Guide(this.intro, this.headings, this.bodies);

  String? bodyOf(String heading) => bodies[heading];
}

/// Splits a guide into its intro (before the first level-2 heading) and
/// one raw body per level-2 heading (up to the next one, or EOF).
_Guide _parseGuide(String path) {
  final lines = File(path).readAsLinesSync();
  final headingIndexes = <int>[];
  final headings = <String>[];
  for (var i = 0; i < lines.length; i++) {
    final match = _headingLine.firstMatch(lines[i]);
    if (match != null) {
      headingIndexes.add(i);
      headings.add(_normalize(match.group(1)!));
    }
  }
  final intro = _normalize(
    lines
        .take(headingIndexes.isEmpty ? lines.length : headingIndexes.first)
        .join('\n'),
  );
  final bodies = <String, String>{};
  for (var i = 0; i < headingIndexes.length; i++) {
    final start = headingIndexes[i] + 1;
    final end = i + 1 < headingIndexes.length
        ? headingIndexes[i + 1]
        : lines.length;
    bodies[headings[i]] = lines.sublist(start, end).join('\n');
  }
  return _Guide(intro, headings, bodies);
}

/// Removes fenced code blocks, keeping the surrounding prose only.
String _stripFenced(String raw) {
  final kept = <String>[];
  var insideFence = false;
  for (final line in raw.split('\n')) {
    if (line.trimLeft().startsWith('```')) {
      insideFence = !insideFence;
      continue;
    }
    if (!insideFence) kept.add(line);
  }
  return kept.join('\n');
}

int _fenceMarkerCount(String raw) =>
    raw.split('\n').where((line) => line.trimLeft().startsWith('```')).length;

int _countTableLines(String stripped) =>
    RegExp(r'^\|', multiLine: true).allMatches(stripped).length;

int _countLevel3Headings(String stripped) =>
    RegExp(r'^### ', multiLine: true).allMatches(stripped).length;

int _countListItems(String stripped) =>
    RegExp(r'^\s*- ', multiLine: true).allMatches(stripped).length;

Set<String> _inlineSpans(String stripped) => RegExp(
  '`([^`]+)`',
).allMatches(stripped).map((match) => _normalize(match.group(1)!)).toSet();

void main() {
  final english = _parseGuide('README.md');
  final arabic = _parseGuide('README.ar.md');

  test('both guides expose exactly the fifteen paired sections in order', () {
    expect(
      english.headings,
      sectionPairs.map((pair) => pair.$1).toList(),
      reason:
          'README.md level-2 headings must equal the English column of '
          'the pair table, same count, order and text',
    );
    expect(
      arabic.headings,
      sectionPairs.map((pair) => pair.$2).toList(),
      reason:
          'README.ar.md level-2 headings must equal the Arabic column of '
          'the pair table, same count, order and text',
    );
  });

  for (final pair in sectionPairs) {
    test('section pair "${pair.$1}" matches in shape and identifiers', () {
      final englishBody = english.bodyOf(pair.$1);
      final arabicBody = arabic.bodyOf(pair.$2);
      if (englishBody == null || arabicBody == null) {
        fail('the section is missing on one side: "${pair.$1}" / "${pair.$2}"');
      }

      expect(
        _fenceMarkerCount(englishBody) % 2,
        0,
        reason: 'unbalanced code fences in the English section',
      );
      expect(
        _fenceMarkerCount(arabicBody) % 2,
        0,
        reason: 'unbalanced code fences in the Arabic section',
      );
      expect(
        _fenceMarkerCount(englishBody),
        _fenceMarkerCount(arabicBody),
        reason: 'fenced code block count must match',
      );

      final englishStripped = _stripFenced(englishBody);
      final arabicStripped = _stripFenced(arabicBody);
      expect(
        _countTableLines(englishStripped),
        _countTableLines(arabicStripped),
        reason: 'table line count must match',
      );
      expect(
        _countLevel3Headings(englishStripped),
        _countLevel3Headings(arabicStripped),
        reason: 'level-3 heading count must match',
      );
      expect(
        _countListItems(englishStripped),
        _countListItems(arabicStripped),
        reason: 'list item count must match',
      );

      final englishSpans = _inlineSpans(englishStripped);
      final arabicSpans = _inlineSpans(arabicStripped);
      final englishText = _normalize(englishStripped);
      final arabicText = _normalize(arabicStripped);
      final allowed = allowedSpanAsymmetries.keys.toSet();
      final missingInArabic =
          englishSpans.where((span) => !arabicText.contains(span)).toSet()
            ..removeAll(allowed);
      expect(
        missingInArabic,
        isEmpty,
        reason:
            'every inline-code span of the English section must appear '
            'verbatim in its Arabic section (backticked identifiers, option '
            'names, headers and wire codes are never translated)',
      );
      final missingInEnglish =
          arabicSpans.where((span) => !englishText.contains(span)).toSet()
            ..removeAll(allowed);
      expect(
        missingInEnglish,
        isEmpty,
        reason:
            'every inline-code span of the Arabic section must appear '
            'verbatim in its English section, or sit on the justified '
            'exception list',
      );
    });
  }

  test('the file intros match in inline identifiers', () {
    final englishStripped = _stripFenced(english.intro);
    final arabicStripped = _stripFenced(arabic.intro);
    final englishSpans = _inlineSpans(englishStripped);
    final arabicSpans = _inlineSpans(arabicStripped);
    final englishText = _normalize(englishStripped);
    final arabicText = _normalize(arabicStripped);
    final allowed = allowedSpanAsymmetries.keys.toSet();
    final missingInArabic =
        englishSpans.where((span) => !arabicText.contains(span)).toSet()
          ..removeAll(allowed);
    expect(
      missingInArabic,
      isEmpty,
      reason:
          'every inline-code span of the English intro must appear '
          'verbatim in the Arabic intro',
    );
    final missingInEnglish =
        arabicSpans.where((span) => !englishText.contains(span)).toSet()
          ..removeAll(allowed);
    expect(
      missingInEnglish,
      isEmpty,
      reason:
          'every inline-code span of the Arabic intro must appear '
          'verbatim in the English intro, or sit on the justified '
          'exception list',
    );
  });
}
