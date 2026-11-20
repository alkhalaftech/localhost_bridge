// سقف المقاعد لكل أصل: مرسل واحد لا يحتكر الخدمة كلها. الشاهد السلكي
// الحرفي: ستة عشر أمراً بطيئاً من أصل واحد لا تمنع الأصل الآخر من
// أول أمر له — والمرسل بلا Origin سقفه مثله، والـOPTIONS يُحسب في
// سقف أصل حامله. العناوين بالإنجليزية (حزمة منشورة) والسلوك سلكي
// حقيقي بمهلة انتظار قصيرة محدودة فلا يتعلق الطقم بحائط زمني.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _cid() => 'seat-${_idSeq++}';

IntakeProtection _allowlist() {
  final pr = IntakeProtection();
  pr.update(
    policy: const OriginPolicy(allowed: [
      'https://busy.example',
      'https://other.example',
    ]),
  );
  return pr;
}

LocalIntakeServer _server({
  required Future<CommandOutcome> Function(TrustedCommand cmd) onCommand,
  IntakeProtection? protection,
}) => LocalIntakeServer(
  telemetry: const SilentTelemetry(),
  correlationIdGenerator: _cid,
  onCommand: onCommand,
  protection: protection ?? _allowlist(),
  requestTimeout: const Duration(milliseconds: 150),
  handlerTimeout: LocalIntakeServer.noHandlerTimeout,
);

/// طلب POST حقيقي يعيد (الحالة، الجسم) — انقطاع الاتصال بلا رد يُسجل
/// (-1, '') بدل استثناء كي يتحدث الحكم بالأسماء لا بالأعطال.
Future<(int, String)> _post(
  int port, {
  String? origin = 'https://busy.example',
  String method = 'POST',
  String? token,
}) async {
  final client = HttpClient();
  try {
    final req = await client.openUrl(method, Uri.parse('http://127.0.0.1:$port/'));
    if (origin != null) req.headers.set('Origin', origin);
    if (token != null) req.headers.set('X-Bridge-Token', token);
    req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
    req.add(utf8.encode('["CMD"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  } on Object {
    return (-1, '');
  } finally {
    client.close(force: true);
  }
}

void main() {
  test(
    'sixteen slow commands from one origin cannot starve another origin: '
    'the fifth and later holds answer origin_seat_limit and the other '
    'origin is served',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // الشاهد الحرفي للبند: 16 أمراً بطيئاً من busy.example تحتكر
      // الخدمة على الكود قبل الإصلاح (كل مرسل آخر 503) — وبعد
      // الإصلاح يحمل busy.example أربعة مقاعد حصرا والبقية ترد
      // origin_seat_limit، فأول أمر لـother.example يُخدم 200
      final never = Completer<CommandOutcome>();
      var entered = 0;
      final srv = _server(
        onCommand: (cmd) {
          entered++;
          return cmd.source == 'https://busy.example'
              ? never.future
              : Future<CommandOutcome>.value(const CommandOutcome(ok: true));
        },
      );
      final port = await srv.start(preferredPort: 0);
      final holders = <Future<(int, String)>>[];
      try {
        for (var i = 0; i < 16; i++) {
          holders.add(_post(port));
        }
        // الاستقرار حتمي بالعدّاد: الأصل المحتكر إما يدخل معالجاته
        // الستة عشر (الكود قبل الإصلاح) أو يستقر عند أربعة (بعد
        // الإصلاح) — الانتظار موصول بسقف زمني قصير فلا يتعلق الحكم
        // بحائط
        final sw = Stopwatch()..start();
        while (entered < 16 && sw.elapsed < const Duration(seconds: 2)) {
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }

        // الأصل الآخر يُخدم — عين الشاهد
        final (otherStatus, otherBody) = await _post(
          port,
          origin: 'https://other.example',
        );
        expect(
          otherStatus,
          200,
          reason:
              'one monopolizing origin must not starve another - the '
              'per-origin seat cap leaves the other origin its share and '
              'its first command is served',
        );
        expect(otherBody, contains('"ok":true'));

        // أربعة مقاعد حصرا للمحتكر، والرفض الثالث عشر فما فوق بالرمز
        final replies = await Future.wait([
          for (final f in holders)
            f.timeout(
              const Duration(seconds: 3),
              onTimeout: () => (-1, ''),
            ),
        ]);
        final seatLimited = replies
            .where((r) => r.$1 == 503 && r.$2.contains('origin_seat_limit'))
            .length;
        expect(
          seatLimited,
          12,
          reason:
              'exactly the holders past the per-origin cap answer '
              'origin_seat_limit - the first four hold their seats',
        );
        expect(
          entered,
          5,
          reason:
              'only the four capped seats and the other origin command '
              'ever reach a handler',
        );
        expect(
          srv.counters.activeSeats,
          4,
          reason:
              'the monopolizer holds exactly its per-origin share - the '
              'rejected twelve never held a seat',
        );
      } finally {
        never.complete(const CommandOutcome(ok: true));
        for (final f in holders) {
          await f.catchError((Object _) => (-1, ''));
        }
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'the originless sender is capped the same way: the fifth held '
    'command answers origin_seat_limit while an origin of its own is '
    'served',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // سقف المرسل بلا Origin مثله: دلو واحد مشترك لمن لا يرسل أصلاً
      // — ودخوله على طبقة التوكن (allow-all يرفض بلا أصل دوماً)،
      // وأصلاً آخر له دلوه الخاص فيُخدم
      const token =
          'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';
      final never = Completer<CommandOutcome>();
      var entered = 0;
      final srv = _server(
        protection: IntakeProtection()..update(token: token),
        onCommand: (cmd) {
          entered++;
          return cmd.source == 'unknown-origin'
              ? never.future
              : Future<CommandOutcome>.value(const CommandOutcome(ok: true));
        },
      );
      final port = await srv.start(preferredPort: 0);
      final holders = <Future<(int, String)>>[];
      try {
        for (var i = 0; i < 4; i++) {
          holders.add(_post(port, origin: null, token: token));
        }
        final sw = Stopwatch()..start();
        while (entered < 4 && sw.elapsed < const Duration(seconds: 2)) {
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }
        expect(entered, 4, reason: 'the first four originless holds sit');

        final (fifthStatus, fifthBody) = await _post(
          port,
          origin: null,
          token: token,
        );
        expect(
          fifthStatus,
          503,
          reason:
              'requests without an Origin share one bucket with the same '
              'cap - the fifth held command is refused past it',
        );
        expect(fifthBody, contains('origin_seat_limit'));

        // دلو آخر: أصل مختلف يُخدم لا يخصم من دلو المرسل الأعمى
        final (otherStatus, otherBody) = await _post(
          port,
          origin: 'https://other.example',
          token: token,
        );
        expect(otherStatus, 200, reason: 'another sender keeps its share');
        expect(otherBody, contains('"ok":true'));
      } finally {
        never.complete(const CommandOutcome(ok: true));
        for (final f in holders) {
          await f.catchError((Object _) => (-1, ''));
        }
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );

  test(
    'OPTIONS counts into the origin seats: a saturated origin cannot '
    'even preflight, another origin preflights normally',
    timeout: const Timeout(Duration(seconds: 40)),
    () async {
      // الـpreflight يُحسب في سقف الأصل: أصل ممتلئ لا يفتح مقعداً
      // سادساً بمهيّأ، والأصل الآخر مهيّؤه يمر 204
      final never = Completer<CommandOutcome>();
      var entered = 0;
      final srv = _server(
        onCommand: (cmd) {
          entered++;
          return cmd.source == 'https://busy.example'
              ? never.future
              : Future<CommandOutcome>.value(const CommandOutcome(ok: true));
        },
      );
      final port = await srv.start(preferredPort: 0);
      final holders = <Future<(int, String)>>[];
      try {
        for (var i = 0; i < 4; i++) {
          holders.add(_post(port));
        }
        final sw = Stopwatch()..start();
        while (entered < 4 && sw.elapsed < const Duration(seconds: 2)) {
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }
        expect(entered, 4, reason: 'the four holds sit before the preflights');

        final (busyOptions, busyOptionsBody) = await _post(
          port,
          method: 'OPTIONS',
        );
        expect(
          busyOptions,
          503,
          reason:
              'OPTIONS counts into the origin seats - a saturated origin '
              'cannot open a fifth seat with a preflight',
        );
        expect(busyOptionsBody, contains('origin_seat_limit'));

        final (otherOptions, _) = await _post(
          port,
          origin: 'https://other.example',
          method: 'OPTIONS',
        );
        expect(
          otherOptions,
          204,
          reason: 'another origin preflights within its own empty bucket',
        );
      } finally {
        never.complete(const CommandOutcome(ok: true));
        for (final f in holders) {
          await f.catchError((Object _) => (-1, ''));
        }
        await srv.stop().timeout(const Duration(seconds: 5));
      }
    },
  );
}
