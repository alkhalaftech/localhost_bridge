// Witnesses of the reply-first 413 route: the counter-path rejection is
// handed back at the crossing moment, the reply is written and flushed on
// the detached socket before any drain byte, the unread remainder drains
// bounded in the background holding no concurrency seat, and the cut
// follows - no path cuts before the reply is on the wire. A sender that
// finishes within the bounds reads the reply as before; a sender that
// never stops reads it too (20 of 20 locally); and the seat is free the
// moment the reply is written, not after the drain ends.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

const _cap = 64 * 1024;
const _chunk = 16 * 1024;

LocalIntakeServer _server({int? capBytes, int maxConcurrentRequests = 100}) {
  final protection = IntakeProtection()
    ..update(policy: const OriginPolicy(allowAllHardened: true));
  return LocalIntakeServer(
    onCommand: (_) async => const CommandOutcome(ok: true),
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () => 'rf413',
    protection: protection,
    config: BridgeConfig(
      maxBodyBytes: capBytes ?? 1024 * 1024,
      maxConcurrentRequests: maxConcurrentRequests,
    ),
  );
}

String _head(int port, int promisedBytes) =>
    'POST / HTTP/1.1\r\n'
    'Host: 127.0.0.1:$port\r\n'
    'Origin: https://agent.test\r\n'
    'Content-Type: application/json\r\n'
    'Sec-Fetch-Mode: cors\r\n'
    'Sec-Fetch-Dest: empty\r\n'
    'Content-Length: $promisedBytes\r\n'
    '\r\n';

/// Opens the chunked never-stopping sender shape: two 512 KiB chunks
/// reach the cap exactly, then a one-byte trickle keeps the wire busy
/// forever - the sender shape the honest-exception bullet names. The
/// reply, where it is written, is read in parallel by the caller's
/// reader.
Future<void> _trickleFlood(Socket socket, int port) async {
  try {
    socket.write(
      'POST / HTTP/1.1\r\n'
      'Host: 127.0.0.1:$port\r\n'
      'Origin: https://agent.test\r\n'
      'Content-Type: application/json\r\n'
      'Sec-Fetch-Mode: cors\r\n'
      'Sec-Fetch-Dest: empty\r\n'
      'Transfer-Encoding: chunked\r\n\r\n',
    );
    await socket.flush();
    final half = 'y' * (1024 * 512);
    socket.write('80000\r\n$half\r\n');
    await socket.flush();
    socket.write('80000\r\n$half\r\n');
    await socket.flush();
    final sw = Stopwatch()..start();
    while (sw.elapsed < const Duration(seconds: 15)) {
      socket.write('1\r\nz\r\n');
      await socket.flush();
      // نبضة المنبع: بايت واحد كل بضع عشرات من المللي ثانية — المرسل
      // لا يتوقف أبداً ولا يكمل إرساله فيبقى مسار التفريغ حياً حتى
      // حدّه الزمني
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  } on SocketException {
    // الخادم قطع بعد حدود التفريغ — هذا ما ينتظر منه المرسل الذي لا
    // يتوقف
  } on Object {
    // الوضع مات مع المقبس — لا شيء يُضاف
  }
}

/// Reads the reply head from the wire and returns its status line - the
/// head terminator ends the read, so the body bytes are not required.
Future<String> _readStatusLine(Socket socket) async {
  final buffer = BytesBuilder();
  final completer = Completer<String>();
  late final StreamSubscription<List<int>> sub;
  sub = socket.listen(
    (data) {
      buffer.add(data);
      final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
      final headEnd = text.indexOf('\r\n\r\n');
      if (headEnd >= 0 && !completer.isCompleted) {
        completer.complete(text.substring(0, text.indexOf('\r\n')));
      }
    },
    onDone: () {
      if (!completer.isCompleted) {
        final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
        completer.complete(text.isEmpty ? '<empty>' : text.split('\r\n').first);
      }
    },
    onError: (Object e) {
      if (!completer.isCompleted) completer.complete('<error: $e>');
    },
  );
  final status = await completer.future.timeout(const Duration(seconds: 8));
  await sub.cancel();
  return status;
}

void main() {
  test(
    'a sender that finishes within the drain bounds reads the 413 reply',
    () async {
      // مرسل يُكمل إرساله ضمن الحدود: وعد 256KiB على سقف 64KiB، يرسل
      // الجموع ثم يقف — الرد يصله 413 بالرمز الثابت كما اليوم
      final srv = _server(capBytes: _cap);
      final port = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final socket = await Socket.connect('127.0.0.1', port);
      addTearDown(socket.destroy);
      final buffer = BytesBuilder();
      final gotReply = Completer<void>();
      late final StreamSubscription<List<int>> sub;
      sub = socket.listen(
        (data) {
          buffer.add(data);
          final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
          if (text.contains('payload_too_large') && !gotReply.isCompleted) {
            gotReply.complete();
          }
        },
        onDone: () {
          if (!gotReply.isCompleted) gotReply.complete();
        },
        onError: (Object _) {
          if (!gotReply.isCompleted) gotReply.complete();
        },
      );
      socket.write(_head(port, 256 * 1024));
      for (var sent = 0; sent < 256 * 1024; sent += _chunk) {
        socket.write('x' * _chunk);
      }
      await socket.flush();
      await gotReply.future.timeout(const Duration(seconds: 8));
      await sub.cancel();
      final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
      expect(text.split('\r\n').first, contains(' 413 '));
      expect(text, contains('payload_too_large'));
      expect(text, contains('Request body exceeds the allowed limit'));
    },
  );

  test(
    'a sender that never stops reads the 413 in flight - 20 of 20 locally',
    () async {
      // المرسل الذي لا يتوقف (ولا يكمل جسمه أبداً) كان يخسر الرد كلياً:
      // نافذة التفريغ تنقطع فيُهدم المقبس قبل كتابة الرد. على «الرد
      // أولاً» يُكتب الرد لحظة تجاوز السقف فيقرؤه القارئ الموازي في نفس
      // الرحلة — عشرون جولة محلية، والعداد داخل الشاهد يرفض أقل من
      // العشرين
      final srv = _server();
      final port = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      var delivered = 0;
      for (var round = 1; round <= 20; round++) {
        final socket = await Socket.connect('127.0.0.1', port);
        final reader = _readStatusLine(socket);
        unawaited(_trickleFlood(socket, port));
        final status = await reader;
        socket.destroy();
        expect(
          status,
          contains(' 413 '),
          reason: 'round $round: the reply must reach a parallel reader',
        );
        delivered++;
      }
      expect(delivered, 20, reason: 'the count is the proof - no fewer');
    },
  );

  test(
    'the seat frees when the 413 reply is written, not after the drain',
    () async {
      // مقعد واحد: مرسل لا يتوقف على الطلب الأول، والقارئ الموازي يقرأ
      // 413 — ثم يأتي طلب عادي فيحوز المقعد فوراً ويرد 200. لو بقي
      // المقعد مع التفريغ الخلفي لَرد 503 server_busy
      final srv = _server(maxConcurrentRequests: 1);
      final port = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final socket = await Socket.connect('127.0.0.1', port);
      final reader = _readStatusLine(socket);
      unawaited(_trickleFlood(socket, port));
      expect(await reader, contains(' 413 '));
      socket.destroy();
      // الرد وُلد والمقعد تحرر لحظته: الطلب التالي يُخدم لا يُرد انشغالاً
      final client = HttpClient();
      try {
        final req = await client.open('POST', '127.0.0.1', port, '/');
        req.headers.set('Origin', 'https://agent.test');
        req.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
        req.headers.set('Sec-Fetch-Mode', 'cors');
        req.headers.set('Sec-Fetch-Dest', 'empty');
        req.add(utf8.encode('["CMD"]'));
        final res = await req.close().timeout(const Duration(seconds: 8));
        final text = await utf8.decoder.bind(res).join();
        expect(
          res.statusCode,
          200,
          reason:
              'the seat is free the moment the reply is written - the '
              'background drain holds no seat (got ${res.statusCode}: $text)',
        );
      } finally {
        client.close(force: true);
      }
    },
  );
}
