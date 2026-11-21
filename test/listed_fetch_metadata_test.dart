// عقد مسار القائمة مع Fetch Metadata: ترويستا الإرسال الحاضرتان بقيمة
// مخالفة (نموذج مخفي navigate أو no-cors أو Dest غير empty) تُرد 403
// cross_site_blocked ولا تبلغ المعالج — والغياب يبقى ممراً كما اليوم
// (العملاء غير المتصفحات المدرجة لا يرسلونهما)، وrequireFetchMetadata
// لا يتغير معناه (فحص القائمة على الحاضرة المخالفة وحدها).
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson;

var _idSeq = 0;
String _counterId() => 'fm-${_idSeq++}';

// جسم النموذج المخفي الحقيقي (enctype=text/plain يرسل name=value):
// الاسم والقيمة يولّدان JSON سليما يفكه الخادم — الصورة السلكية
// الكاملة للإرسال الصامت الذي يحجبه هذا العقد
const _formName = '{"data":["PING"],"x":"';
const _formValue = '"}';
final _formBody = '$_formName=$_formValue';

class _Rec extends BridgeTelemetry {
  @override
  void info(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  void warn(
    String message, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  Future<T> measure<T>(
    String label,
    Future<T> Function() body, {
    Map<String, Object?>? context,
  }) async => await body();
}

LocalIntakeServer _listedServer(
  _Rec rec,
  void Function() onCommandCall, {
  bool requireFetchMetadata = true,
}) => LocalIntakeServer(
  telemetry: rec,
  correlationIdGenerator: _counterId,
  onCommand: (_) async {
    onCommandCall();
    return const CommandOutcome(ok: true);
  },
  protection: IntakeProtection(telemetry: rec)
    ..update(
      policy: OriginPolicy(
        allowed: const ['https://a.example'],
        requireFetchMetadata: requireFetchMetadata,
      ),
    ),
);

Future<Map<String, Object?>> _exchange(
  int port,
  String request, {
  Duration wait = const Duration(seconds: 8),
}) async {
  final socket = await Socket.connect('127.0.0.1', port);
  final buffer = BytesBuilder();
  final done = Completer<Map<String, Object?>>();
  late final StreamSubscription<List<int>> sub;
  void settle(List<int> raw) {
    final text = latin1.decode(raw, allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    final head = sep < 0 ? text : text.substring(0, sep);
    final body = sep < 0 ? '' : text.substring(sep + 4);
    final statusLine = head.isEmpty ? '' : head.split('\r\n').first;
    final headers = <String, String>{};
    for (final line in head.split('\r\n').skip(1)) {
      final i = line.indexOf(':');
      if (i > 0) {
        headers[line.substring(0, i).trim().toLowerCase()] = line
            .substring(i + 1)
            .trim();
      }
    }
    done.complete({
      'status': statusLine.isEmpty
          ? -1
          : (int.tryParse(statusLine.split(' ')[1]) ?? -1),
      'headers': headers,
      'body': body,
    });
  }

  sub = socket.listen(
    (chunk) {
      buffer.add(chunk);
      if (done.isCompleted) return;
      final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
      final sep = text.indexOf('\r\n\r\n');
      if (sep < 0) return;
      final head = text.substring(0, sep);
      final clMatch = RegExp(
        r'content-length:\s*(\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      final bodyLen = text.length - (sep + 4);
      final hasCl = clMatch != null && bodyLen >= int.parse(clMatch.group(1)!);
      if (hasCl || text.endsWith('0\r\n\r\n')) settle(buffer.toBytes());
    },
    onDone: () {
      if (!done.isCompleted) settle(buffer.toBytes());
    },
  );
  socket.write(request);
  final result = await done.future.timeout(
    wait,
    onTimeout: () => <String, Object?>{
      'status': -2,
      'headers': <String, String>{},
      'body': 'NO-RESPONSE',
    },
  );
  await sub.cancel();
  socket.destroy();
  return result;
}

String _post(
  int port, {
  String origin = 'https://a.example',
  String? fetchMode,
  String? fetchDest,
  String contentType = 'application/json',
  String body = '{"data":["PING"]}',
}) {
  final h = StringBuffer()
    ..write('POST / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n');
  if (fetchMode != null) h.write('Sec-Fetch-Mode: $fetchMode\r\n');
  if (fetchDest != null) h.write('Sec-Fetch-Dest: $fetchDest\r\n');
  h.write('Origin: $origin\r\n');
  h.write('Content-Type: $contentType\r\n');
  h.write('Content-Length: ${utf8.encode(body).length}\r\n\r\n');
  return '$h$body';
}

void main() {
  test(
    'a navigate send from a listed origin answers 403 cross_site_blocked and never reaches the handler',
    () async {
      final rec = _Rec();
      var handlerCalls = 0;
      final srv = _listedServer(rec, () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        _post(p, fetchMode: 'navigate', fetchDest: 'document'),
      );
      expect(
        r['status'],
        403,
        reason: 'a form navigation is a cross-site send',
      );
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'cross_site_blocked',
        reason: 'the stable send-method code applies on the listed path too',
      );
      expect(handlerCalls, 0, reason: 'the hidden-form command never executes');
    },
  );

  test(
    'a no-cors send from a listed origin answers 403 cross_site_blocked',
    () async {
      final rec = _Rec();
      var handlerCalls = 0;
      final srv = _listedServer(rec, () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        _post(p, fetchMode: 'no-cors', fetchDest: 'empty'),
      );
      expect(r['status'], 403);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'cross_site_blocked',
        reason: 'no-cors is the beacon/send-only shape the browser cannot read',
      );
      expect(handlerCalls, 0);
    },
  );

  test(
    'a document fetch destination from a listed origin answers 403 cross_site_blocked even with mode cors',
    () async {
      final rec = _Rec();
      var handlerCalls = 0;
      final srv = _listedServer(rec, () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        _post(p, fetchMode: 'cors', fetchDest: 'document'),
      );
      expect(r['status'], 403);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'cross_site_blocked',
        reason: 'a document destination is a navigation, not a data fetch',
      );
      expect(handlerCalls, 0);
    },
  );

  test(
    'a real hidden-form send (text/plain wire shape) from a listed origin is blocked before the handler',
    () async {
      final rec = _Rec();
      var handlerCalls = 0;
      final srv = _listedServer(rec, () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      // enctype="text/plain" sends name=value: the crafted pair below is
      // valid JSON, and text/plain rides the allowed content types by
      // default - the send used to reach the handler in full.
      final r = await _exchange(
        p,
        _post(
          p,
          fetchMode: 'navigate',
          fetchDest: 'document',
          contentType: 'text/plain',
          body: _formBody,
        ),
      );
      expect(r['status'], 403);
      expect(
        bodyJson(r.cast<String, Object>())['error'],
        'cross_site_blocked',
        reason: 'the script-less form send is stopped at the policy layer',
      );
      expect(handlerCalls, 0, reason: 'the form body never drives a command');
    },
  );

  test(
    'cors with empty destination from a listed origin is served as before',
    () async {
      final rec = _Rec();
      var handlerCalls = 0;
      final srv = _listedServer(rec, () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(
        p,
        _post(p, fetchMode: 'cors', fetchDest: 'empty'),
      );
      expect(r['status'], 200, reason: 'a legitimate fetch keeps crossing');
      expect(handlerCalls, 1, reason: 'the listed command is executed');
    },
  );

  test(
    'absent Sec-Fetch headers from a listed origin are served as before',
    () async {
      final rec = _Rec();
      var handlerCalls = 0;
      final srv = _listedServer(rec, () => handlerCalls++);
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final r = await _exchange(p, _post(p));
      expect(
        r['status'],
        200,
        reason: 'headerless non-browser clients stay on the listed path',
      );
      expect(handlerCalls, 1);
    },
  );

  test(
    'with requireFetchMetadata off the listed path still blocks a wrong value and still serves absence',
    () async {
      final rec = _Rec();
      var handlerCalls = 0;
      final srv = _listedServer(
        rec,
        () => handlerCalls++,
        requireFetchMetadata: false,
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final wrong = await _exchange(
        p,
        _post(p, fetchMode: 'navigate', fetchDest: 'document'),
      );
      expect(
        wrong['status'],
        403,
        reason: 'the wrong-value check stands on its own, off-switch or not',
      );
      expect(
        bodyJson(wrong.cast<String, Object>())['error'],
        'cross_site_blocked',
      );
      final absent = await _exchange(p, _post(p));
      expect(
        absent['status'],
        200,
        reason: 'absence keeps its treatment: only the wrong value blocks',
      );
      expect(
        handlerCalls,
        1,
        reason: 'only the absent request reached the handler',
      );
    },
  );
}
