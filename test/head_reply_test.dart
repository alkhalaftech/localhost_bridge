// Witness of the HEAD contract: a response to a HEAD request carries no
// body on the wire - the framing headers (with the would-be body length
// as metadata) ride alone, and the connection closes after the header
// section. The method gate is where every HEAD lands, so the raw-socket
// reply is the path under test.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

void main() {
  test(
    'a HEAD request is answered with headers only - no body bytes',
    () async {
      final protection = IntakeProtection()
        ..update(
          policy: const OriginPolicy(allowed: ['https://portal.example']),
        );
      final srv = LocalIntakeServer(
        onCommand: (_) async => const CommandOutcome(ok: true),
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: () => 'head-r',
        protection: protection,
      );
      final port = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);
      final socket = await Socket.connect('127.0.0.1', port);
      addTearDown(socket.destroy);
      final buffer = BytesBuilder();
      final closed = Completer<void>();
      late final StreamSubscription<List<int>> sub;
      sub = socket.listen(
        (data) => buffer.add(data),
        onDone: () {
          if (!closed.isCompleted) closed.complete();
        },
        onError: (Object _) {
          if (!closed.isCompleted) closed.complete();
        },
      );
      socket.write('HEAD / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n\r\n');
      await socket.flush();
      // الرد يحمل Connection: close فإغلاق جهة الكتابة من الخادم ينهي
      // القراءة — كل ما وصل هو الرأس وما بعده
      await closed.future.timeout(const Duration(seconds: 8));
      await sub.cancel();
      final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
      expect(text.split('\r\n').first, contains(' 405 '));
      final headEnd = text.indexOf('\r\n\r\n');
      expect(
        headEnd,
        isNonNegative,
        reason: 'a complete header section arrives',
      );
      final body = text.substring(headEnd + 4);
      expect(
        body,
        isEmpty,
        reason:
            'a HEAD response carries no content on the wire - the framing '
            'stays as metadata and the connection closes after the headers',
      );
      // والرمز الثابت للطريقة مخفي في الترويسات لا في جسم
      expect(text, isNot(contains('method_not_allowed')));
    },
  );
}
