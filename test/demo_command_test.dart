// شواهد أمر التجربة في bin/: الوسيطات الوحيدة المقبولة --port وحدها،
// وكل خيار آخر — ومنه كل ما يفتح allow-all أو الاكتشاف — يُرفض رفضاً
// صاخباً وقت التشغيل، والعملية الحية تطبع توكنها (64 hex) ومنفذها
// وطريقة الإيقاف، وتخدم أمراً حقيقياً بالتوكن المطبوع نفسه، وتُرد
// بلا توكن برمز الأصل.
// عناوين إنجليزية (حزمة منشورة)؛ العملية الحية بمخرجها الحقيقي.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import '../bin/bridge_demo.dart' as demo;

/// The dart executable to spawn the demo with. Under `dart test` the
/// runner itself is the VM; under `flutter test` it is flutter_tester,
/// and the dart SDK sits beside it in the same cache (three levels up
/// from the engine artifact folder) - the probe climbs until it finds
/// dart-sdk/bin/dart(.exe), so both runners spawn the real CLI.
Future<String> _dartExecutable() async {
  final self = Platform.resolvedExecutable;
  final name = self.replaceAll('\\', '/').split('/').last.toLowerCase();
  if (name == 'dart.exe' || name == 'dart') return self;
  var probe = File(self).parent;
  for (var up = 0; up < 6; up++) {
    probe = probe.parent;
    final exe = File.fromUri(probe.uri.resolve('dart-sdk/bin/dart.exe'));
    if (exe.existsSync()) return exe.path;
    final vm = File.fromUri(probe.uri.resolve('dart-sdk/bin/dart'));
    if (vm.existsSync()) return vm.path;
  }
  throw StateError(
    'the dart executable was not found near the test runner ($self)',
  );
}

void main() {
  test('the demo accepts no option beyond --port — every allow-all or '
      'discovery opener is refused loudly', () {
    // الافتراضي: بلا وسيطات = منفذ تلقائي
    expect(demo.parseDemoPort(const []), isNull);
    expect(demo.parseDemoPort(const ['--port', '9100']), 9100);
    // كل ما يجاوز --port يُرفض صاخباً — خاصة ما يفتح الأبواب المرفوضة
    for (final flag in [
      '--allow-all',
      '--allowAll',
      '--discovery',
      '--open',
      '--allow',
      '--no-token',
      '--bogus',
      'extra',
    ]) {
      expect(
        () => demo.parseDemoPort([flag]),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            contains('token-only'),
          ),
        ),
        reason: '$flag must never be accepted by the demo',
      );
    }
    // قيمة المنفذ غير الرقمية خطأ إعداد أيضاً
    expect(() => demo.parseDemoPort(['--port', 'abc']), throwsA(anything));
  });

  test('the running demo prints its token, its port, and the stop method, and '
      'serves a real command with that token', () async {
    final process = await Process.start(await _dartExecutable(), [
      'bin/bridge_demo.dart',
    ], workingDirectory: Directory.current.path);
    final stdoutLines = <String>[];
    final portCompleter = Completer<(String, int)>();
    final stopLine = Completer<bool>();
    late final StreamSubscription<String> sub;
    final tokenPattern = RegExp(r'token:\s*([0-9a-f]{64})');
    final portPattern = RegExp(r'port:\s*(\d+)');
    String? tokenValue;
    int? portValue;
    sub = process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
          stdoutLines.add(line);
          final tm = tokenPattern.firstMatch(line);
          final pm = portPattern.firstMatch(line);
          if (tm != null) tokenValue = tm.group(1);
          if (pm != null) portValue = int.parse(pm.group(1)!);
          if (tokenValue != null && portValue != null) {
            if (!portCompleter.isCompleted) {
              portCompleter.complete((tokenValue!, portValue!));
            }
          }
          if (RegExp(r'stop:').hasMatch(line) && !stopLine.isCompleted) {
            stopLine.complete(true);
          }
        });
    var stderrText = '';
    process.stderr.transform(utf8.decoder).listen((s) => stderrText += s);
    try {
      final (token, port) = await portCompleter.future.timeout(
        const Duration(seconds: 90),
        onTimeout: () => throw StateError(
          'demo never printed its token and port; stdout was: '
          '${stdoutLines.join('\n')} stderr: $stderrText',
        ),
      );
      // طريقة الإيقاف مطبوعة في اللافتة
      expect(
        await stopLine.future.timeout(const Duration(seconds: 5)),
        isTrue,
        reason: 'the banner must print how to stop (stop: ...)',
      );
      // الطباعة الافتراضية للخادم حية على stdout: سطر الجسر بعلامة
      // [bridge] جاء من افتراض telemetry نفسه — الديمو لم يمرر واحداً
      // للخادم، فالسطر إثبات أن الافتراضي يكتب لا يكتم
      expect(
        stdoutLines.any((line) => line.startsWith('[bridge]')),
        isTrue,
        reason:
            'the default telemetry must write the bridge lines '
            '(the demo passes the server none)',
      );
      // الأمر الحقيقي بالتوكن المطبوع نفسه يُخدم على السلك الحي
      final client = HttpClient();
      try {
        final req = await client.post('127.0.0.1', port, '/');
        req.headers.set('X-Bridge-Token', token);
        req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
        req.add(utf8.encode('["ping"]'));
        final res = await req.close().timeout(const Duration(seconds: 8));
        final body = await res.transform(utf8.decoder).join();
        expect(res.statusCode, 200);
        expect(body, contains('"ok":true'));
        expect(jsonDecode(body)['data'], ['ping']);
        // بلا توكن: الرفض القائم لا باب مفتوح
        final bare = await client.post('127.0.0.1', port, '/');
        bare.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
        bare.add(utf8.encode('["ping"]'));
        final bareRes = await bare.close().timeout(const Duration(seconds: 8));
        final bareBody = await bareRes.transform(utf8.decoder).join();
        expect(bareRes.statusCode, 403);
        expect(bareBody, contains('"error":"origin_not_listed"'));
      } finally {
        client.close(force: true);
      }
    } finally {
      sub.cancel();
      process.kill();
      // انتظار الخروج بلا drain: مجرى stdout مستمعٌ أصلاً من الأعلى
      try {
        await process.exitCode.timeout(const Duration(seconds: 5));
      } on TimeoutException {
        // العملية عنيدة: الإنهاء القسري ثانية
        process.kill(ProcessSignal.sigkill);
      }
    }
  }, timeout: const Timeout(Duration(seconds: 120)));
}
