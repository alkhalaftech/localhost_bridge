// شاهد تشغيل الأمثلة: كل مثال يعمل بلا مستخدم عبر --self-check — منفذ
// مؤقت وفحوص حقيقية من طرف عميل على السلك — ويُشغَّل هنا كما يشغّله
// القارئ حرفاً (`dart run example/<الاسم> --self-check`)، فلا بديل
// سريع ولا تشغيل من داخل المعالج. النجاح: خروج 0 وسطر نجاح واحد في
// المخرجات؛ وأي فشل يُقرأ من سطر FAIL المطبوع لا من صمت. مهلة مكتوبة
// لكل عملية: مثال عالق يموت بقتل العملية ولا يعلّق البوابة.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

/// The wall clock each example self-check gets - a stuck example is
/// killed at the deadline and reported as the timeout it is.
const _selfCheckTimeout = Duration(seconds: 90);

/// The one success line every example prints after its last passing check.
const _successLine = 'SELF-CHECK PASSED';

/// The six runnable examples: five new ones and the consent page example
/// that grew its --self-check mode. Each runs exactly the command a
/// reader runs, from the package root.
const _examples = [
  'pairing_page.dart',
  'token_from_command_line.dart',
  'streaming_reply_and_channel.dart',
  'mount_existing_server.dart',
  'local_status_page.dart',
  'origin_pending_page.dart',
];

Future<(int exitCode, String output, bool timedOut)> _runSelfCheck(
  String example,
) async {
  final process = await Process.start(Platform.executable, [
    'run',
    'example/$example',
    '--self-check',
  ], workingDirectory: Directory.current.path);
  final stdoutText = process.stdout.transform(utf8.decoder).join();
  final stderrText = process.stderr.transform(utf8.decoder).join();
  var timedOut = false;
  final watchdog = Timer(_selfCheckTimeout, () {
    timedOut = true;
    // Kill الافتراضي وحده: يعمل على الأنظمة الثلاثة، وسقوط العملية
    // يُحسم بمستقبل exitCode لا بإشارة معينة
    process.kill();
  });
  final exitCode = await process.exitCode;
  watchdog.cancel();
  final output = await stdoutText;
  final err = await stderrText;
  return (exitCode, '$output$err', timedOut);
}

void main() {
  test('the package root is the working directory this witness runs from', () {
    expect(
      File('pubspec.yaml').existsSync(),
      isTrue,
      reason: 'the examples are run relative to the package root',
    );
  });

  for (final example in _examples) {
    test('example $example runs its --self-check to green within '
        '${_selfCheckTimeout.inSeconds}s', () async {
      // مهلة الاختبار أوسع من مهلة المراقبة: القتل بيد المهلة المكتوبة
      // هنا لا بمهلة عدّاء الاختبار الافتراضية
      final (exitCode, output, timedOut) = await _runSelfCheck(example);
      if (timedOut) {
        fail(
          'the self-check exceeded ${_selfCheckTimeout.inSeconds}s and was '
          'killed - an example that never finishes proves nothing',
        );
      }
      expect(
        exitCode,
        0,
        reason:
            'the self-check must exit 0 - its own output says what '
            'failed:\n$output',
      );
      expect(
        output,
        contains(_successLine),
        reason:
            'a green exit is accepted only with the success line in '
            'the printed output, never on the exit code alone',
      );
      expect(
        output,
        isNot(contains('FAIL:')),
        reason:
            'a failing check line in the output is a failure even '
            'beside a green exit',
      );
    }, timeout: const Timeout(Duration(minutes: 3)));
  }
}
