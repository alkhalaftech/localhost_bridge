// شاهد التقابل بين CHANGELOG ودليل الانتقال: كل سطر كاسر في قسم 0.2.0
// له قسم واحد في MIGRATION-0.2.0.md بالعنوان نفسه وبالترتيب نفسه، وكل
// قسم في الدليل له سطر كاسر واحد — تقابل واحد لواحد لا يتحمل قسماً
// يتيمياً ولا سطراً بلا دليل. ويحرس الشاهد بنية القسم كذلك: أنواع
// CHANGELOG الأربعة حصراً (Behavior وAPI وSecurity وCompatibility) على
// كل مدخل من مستوى أول، والكاسر أولاً قبل سواها، ولا عنوان كاسر
// مكرراً. ونسخ مؤقتة معدلة من الملفين تجعل الشاهد أحمر بالاتجاهين:
// حذف قسم من الدليل يحمرّه، وسطر كاسر بلا قسم يحمرّه — المسارَان
// يُقرآن من متغيرَي البيئة BRIDGE_PARITY_CHANGELOG و
// BRIDGE_PARITY_MIGRATION عند ضبطهما (تمرين الأحمر حصراً)، ومن ملفات
// الشجرة عند تركهما، فلا يحمل الشاهد حالة في CI.
import 'dart:io';

import 'package:test/test.dart';

final String _changelogPath =
    Platform.environment['BRIDGE_PARITY_CHANGELOG'] ?? 'CHANGELOG.md';
final String _migrationPath =
    Platform.environment['BRIDGE_PARITY_MIGRATION'] ?? 'MIGRATION-0.2.0.md';

/// The four entry types the 0.2.0 section may use, breaking or not.
const List<String> _entryTypes = [
  'Behavior',
  'API',
  'Security',
  'Compatibility',
];

/// A top-level breaking bullet: `- **Breaking (Type): title** - ...`
/// The title may wrap across source lines, so the capture spans lines
/// lazily up to the closing `**`.
final RegExp _breakingEntry = RegExp(
  r'^- \*\*Breaking \((Behavior|API|Security|Compatibility)\): ([\s\S]+?)\*\*',
  multiLine: true,
);

/// A top-level non-breaking bullet opens with one of the four types.
final RegExp _typedEntry = RegExp(
  r'^- (Behavior|API|Security|Compatibility): ',
);

final RegExp _migrationHeading = RegExp(r'^## (.+)$', multiLine: true);

final RegExp _bidiMarks = RegExp('[\u200e\u200f\u202a-\u202e\u2066-\u2069]');

/// Collapses bidi marks, whitespace runs and letter case so a title
/// wrapped across CHANGELOG source lines still equals its one-line
/// migration heading.
String _normalize(String text) => text
    .replaceAll(_bidiMarks, '')
    .replaceAll(RegExp(r'\s+'), ' ')
    .trim()
    .toLowerCase();

/// The body of the `## 0.2.0` section, up to the next `## ` heading.
String _zeroSection(String changelog) {
  final lines = changelog.split('\n');
  final start = lines.indexOf('## 0.2.0');
  if (start < 0) {
    fail('no "## 0.2.0" section found in the changelog');
  }
  var end = lines.length;
  for (var i = start + 1; i < lines.length; i++) {
    if (lines[i].startsWith('## ')) {
      end = i;
      break;
    }
  }
  return lines.sublist(start + 1, end).join('\n');
}

/// The section's top-level entries, one block per bullet: each block
/// starts at a `- ` line and runs to the next one (indented
/// sub-bullets and wrapped lines stay inside their block).
List<String> _entryBlocks(String section) {
  final blocks = <String>[];
  final current = <String>[];
  for (final line in section.split('\n')) {
    if (line.startsWith('- ')) {
      if (current.isNotEmpty) blocks.add(current.join('\n'));
      current
        ..clear()
        ..add(line);
    } else if (current.isNotEmpty) {
      current.add(line);
    }
  }
  if (current.isNotEmpty) blocks.add(current.join('\n'));
  return blocks;
}

void main() {
  // نمط قارئ readme_parity_test.dart: readAsLinesSync يسقط نهايات
  // الأسطر أياً كانت (LF/CRLF/CR) — فقرص ويندوزي بإعداد autocrlf لا
  // يعلق \r على الأسطر ويكسر مطابقة العناوين الحرفية
  final changelog = File(_changelogPath).readAsLinesSync().join('\n');
  final migration = File(_migrationPath).readAsLinesSync().join('\n');
  final blocks = _entryBlocks(_zeroSection(changelog));
  final migrationTitles = _migrationHeading
      .allMatches(migration)
      .map((match) => _normalize(match.group(1)!))
      .toList();

  test('every 0.2.0 entry carries one of the four types', () {
    final untyped = <String>[];
    for (final block in blocks) {
      if (!_typedEntry.hasMatch(block) && !_breakingEntry.hasMatch(block)) {
        untyped.add(block.split('\n').first);
      }
    }
    expect(
      untyped,
      isEmpty,
      reason:
          'every top-level CHANGELOG 0.2.0 entry must carry Breaking(Type) '
          'or one of: ${_entryTypes.join(", ")} - untyped entries: '
          '${untyped.take(3).join(" | ")}',
    );
  });

  test('the breaking entries come before every other entry', () {
    final isBreaking = blocks.map(_breakingEntry.hasMatch).toList();
    var seenNonBreaking = false;
    final offenders = <int>[];
    for (var i = 0; i < isBreaking.length; i++) {
      if (isBreaking[i]) {
        if (seenNonBreaking) offenders.add(i);
      } else {
        seenNonBreaking = true;
      }
    }
    expect(
      offenders,
      isEmpty,
      reason:
          'the breaking entries must sit first in the 0.2.0 section - '
          'breaking entries found after a non-breaking one at entry '
          'indexes: $offenders',
    );
  });

  test('every breaking line pairs one migration section, one to one', () {
    final breakingTitles = <String>[];
    for (final block in blocks) {
      final match = _breakingEntry.firstMatch(block);
      if (match != null) breakingTitles.add(_normalize(match.group(2)!));
    }

    expect(
      breakingTitles,
      isNotEmpty,
      reason: '0.2.0 must carry its breaking entries',
    );
    expect(
      breakingTitles.toSet(),
      hasLength(breakingTitles.length),
      reason:
          'a duplicated breaking title would let one section answer two '
          'lines: ${breakingTitles.join(" | ")}',
    );

    expect(
      breakingTitles,
      migrationTitles,
      reason:
          'the breaking lines of CHANGELOG 0.2.0 and the "## " sections of '
          'MIGRATION-0.2.0.md must be the same titles in the same order - '
          'a deleted or added section on either side breaks the pairing '
          '(breaking: ${breakingTitles.join(" | ")}; sections: '
          '${migrationTitles.join(" | ")})',
    );
  });
}
