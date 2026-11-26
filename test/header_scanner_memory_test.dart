// شاهد حصة الذاكرة لكل اتصال عالق في مُفرِّص الترويسات: الاحتفاظ بسطر
// مرشّح (يبدأ بـ c) لا يكلف فوق الاحتفاظ بسطر غير مرشّح بالطول نفسه —
// التخزين الخاص بالشكل ممنوع: مئة اتصال معلّقة على سطر 16 كيلوبايت
// بلا LF، مرة ببداية مرشّحة ومرة ببداية غير مرشّحة، والنسبة بين نما
// الجولتين لا تزيد على 1.3.
//
// **طريقة القياس الثابتة (مكتوبة هنا لتكرارها لا لتغييرها):**
// - الخادم عملية مستقلة (`header_memory_child.dart`) تُقرأ RSS منها
//   من خارجها بنداء "rss" على مدخلاتها: ذاكرة العملاء وإطار الاختبار
//   لا تدخل في القراءة — هذا هو مقاس الحصة نفسه: عملية خادم مستقلة.
// - مهلة الترويسات ومهلة الطلب 30 ثانية: لا قطع خلال نافذة القياس
//   فلا مقبس يُدمَّر فيسرب حصته من المقارنة.
// - تدفئة أولى بعشرين وصلاً قصيراً وقطعاً قبل أي عدّ.
// - ثلاث جولات متناوبة لكل طرف بالإجراء نفسه: مئة اتصال تعالق داخل
//   سطر 16 كيلوبايت بدايته X (غير مرشّح) أو c (مرشّح)، مهلة تسوية
//   ثانيتين، وقراءة RSS قبل الجولة وبعدها والفرق هو نمو الجولة، ثم
//   تُغلق مقابس الجولة. التناوب يوازن انجراف الكومة بين الطرفين.
// - الحكم: نما (نمو جولات المرشّح) ÷ نما (نمو جولات غير المرشّح)
//   ≤ 1.3. **تباين أخذ RSS معلوم كسبب ضجيج هنا:** القراءة تحمل صفحات
//   الكومة المحررة غير المستعادة بين الجولات، فلذلك أُخذ الوسيط لا
//   القراءة الواحدة — وهو سبب مسمّى لا هامش موسَّع.
// - **حد الشاهد وما يحرسه حصراً:** الاحتفاظ بسطر مرشّح لا يكلف فوق
//   الاحتفاظ بسطر غير مرشّح بنفس الطول. أما خصلية العبء الكلي عبر
//   الأشجار (مفرِّس يخزّن كل سطر بايتاً بايتاً) فلا يقيسها هذا الشاهد
//   داخل شجرة واحدة إطلاقاً — وهي محكومة بأداة القياس التفاضلية
//   عبر-الأشجار خارج المستودع حيث قيس 3.6 أضعاف على المفرِّس القديم.
// - ويندوز مقبولة لشاهد الذاكرة هذا كما بقية المنصات (القراءة
//   `ProcessInfo.currentRss` في الطفلة)؛ حصة اختبار حارسة لا قياس
//   أداء زمني.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

const _listed = 'https://portal.example';
const _connections = 100;
const _lineTailBytes = 16383; // البداية + 16383 حرفاً = 16 كيلوبايت حصراً
const _settle = Duration(seconds: 2);
const _maxRatio = 1.3;
const _roundsPerSide = 3;

// قارئ أسطر من مخرجات الطفلة بلا طابور خارجي: كل نداء يُسلَّم أقدم
// سطر وصل ولم يُستهلك، وإلا انتظر الواصل
class _ChildLines {
  final StreamIterator<String> _it;
  final _waiters = <Completer<String>>[];
  final _buffered = <String>[];

  _ChildLines(Stream<String> lines) : _it = StreamIterator<String>(lines);

  Future<String> next() {
    if (_buffered.isNotEmpty) {
      return Future<String>.value(_buffered.removeAt(0));
    }
    final waiter = Completer<String>();
    _waiters.add(waiter);
    unawaited(_pump());
    return waiter.future;
  }

  Future<void> _pump() async {
    while (_waiters.isNotEmpty) {
      final has = await _it.moveNext();
      if (!has) {
        while (_waiters.isNotEmpty) {
          _waiters
              .removeAt(0)
              .completeError(
                StateError('the measurement child closed its output'),
              );
        }
        return;
      }
      _waiters.removeAt(0).complete(_it.current);
    }
  }
}

Future<Process> _spawnChild() {
  return Process.start(Platform.resolvedExecutable, [
    'test/support/header_memory_child.dart',
  ], workingDirectory: Directory.current.path);
}

Future<List<Socket>> _stallRound(int port, String tail) async {
  final host = '127.0.0.1:$port';
  final sockets = <Socket>[];
  for (var i = 0; i < _connections; i++) {
    final s = await Socket.connect(InternetAddress.loopbackIPv4, port);
    s.add(
      utf8.encode(
        'POST / HTTP/1.1\r\n'
        'Host: $host\r\n'
        'Origin: $_listed\r\n'
        '$tail',
      ),
    );
    sockets.add(s);
  }
  return sockets;
}

Future<void> _closeAll(List<Socket> sockets) async {
  for (final s in sockets) {
    s.destroy();
  }
  // مهلة تهدئة بعد الإغلاق: أحداث الهدم تكتمل قبل الجولة التالية
  await Future<void>.delayed(const Duration(milliseconds: 500));
}

int _median(List<int> values) {
  final sorted = values.toList()..sort();
  return sorted[sorted.length ~/ 2];
}

void main() {
  test(
    'holding a stalled 16 KiB candidate line costs at most '
    '$_maxRatio times holding a non-candidate line of the same length',
    () async {
      // ignore: avoid_print
      print('MEM-WITNESS platform=${Platform.version}');
      final child = await _spawnChild();
      addTearDown(() {
        child.stdin.writeln('quit');
        // الإنهاء صامت: مخرجات الطفلة لمجرى قارئ واحد فالاستماع ثانية
        // يرمي — والقتل بعد مهلة قصيرة يضمن نظافة العملية مهما تعطلت
        Future<void>.delayed(const Duration(seconds: 2)).then<void>((_) {
          child.kill();
        });
      });
      final lines = _ChildLines(
        child.stdout.transform(utf8.decoder).transform(const LineSplitter()),
      );
      final portLine = await lines.next().timeout(const Duration(seconds: 20));
      final port = int.parse(portLine.split(' ').last);
      Future<int> childRss() async {
        child.stdin.writeln('rss');
        final rssLine = await lines.next().timeout(const Duration(seconds: 10));
        return int.parse(rssLine.split(' ').last);
      }

      // التدفئة: عشرون وصلاً قصيراً وقطعاً تُشعل مسارات التخصيص
      final warm = await _stallRound(port, 'X-Pad:');
      await _closeAll(warm.sublist(0, 20));
      await Future<void>.delayed(const Duration(milliseconds: 500));

      // ثلاث جولات متناوبة لكل طرف بالإجراء نفسه: غير مرشّح ثم مرشّح
      final growths = <String, List<int>>{
        'nonCandidate': <int>[],
        'candidate': <int>[],
      };
      for (var round = 0; round < _roundsPerSide; round++) {
        for (final side in ['nonCandidate', 'candidate']) {
          final tail = side == 'nonCandidate'
              ? 'X${'x' * _lineTailBytes}'
              : 'c${'x' * _lineTailBytes}';
          final rssBefore = await childRss();
          final sockets = await _stallRound(port, tail);
          await Future<void>.delayed(_settle);
          final rssAfter = await childRss();
          growths[side]!.add(rssAfter - rssBefore);
          await _closeAll(sockets);
          // ignore: avoid_print
          print(
            'MEM-WITNESS round=${round + 1} side=$side '
            'growth=${rssAfter - rssBefore} bytes',
          );
        }
      }
      final medianNonCandidate = _median(growths['nonCandidate']!);
      final medianCandidate = _median(growths['candidate']!);
      // ignore: avoid_print
      print(
        'MEM-WITNESS medianNonCandidate=$medianNonCandidate '
        'medianCandidate=$medianCandidate bytes',
      );
      final ratio = medianCandidate / medianNonCandidate;
      // ignore: avoid_print
      print('MEM-WITNESS ratio=$ratio limit=$_maxRatio');
      expect(
        medianNonCandidate,
        greaterThan(0),
        reason:
            'the non-candidate rounds grew the child resident set '
            'measurably - a zero median means the rounds did not run',
      );
      expect(
        ratio,
        lessThanOrEqualTo(_maxRatio),
        reason:
            'shape-specific storage is forbidden: holding a stalled '
            '16 KiB candidate line costs at most $_maxRatio times '
            'holding a non-candidate line of the same length - the '
            'scanner never buffers one shape byte-by-byte while it '
            'spares the other '
            '(non-candidate $medianNonCandidate, candidate '
            '$medianCandidate)',
      );
    },
    timeout: const Timeout(Duration(seconds: 180)),
  );
}
