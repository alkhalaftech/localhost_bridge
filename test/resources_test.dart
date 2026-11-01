// شهادة الموارد : القراءة بلا نسخ مزدوجة
// (copy:false) والرفض يحرر مخزنه في الحال (clear عند settle). القياس
// عبر RSS قبل/بعد 30 جسما بمقياس الميغابايت — والجسم الفائض يُرسل
// بترميز chunked عمدا كي يمر بعدّاد _readBody نفسه لا بوابة
// Content-Length المبكرة (أول تغطية سلكية لهذا المسار).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _counterId() => 'res-${_idSeq++}';

void main() {
  test(
    'body resources: 15 chunked rejections over the cap plus 15 accepts at the cap — RSS never escapes',
    timeout: const Timeout(Duration(minutes: 2)),
    () async {
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
              perOriginPerMinute: 1000,
            ),
          ),
      );
      final p = await srv.start(preferredPort: 31897, fallbacks: const [31881]);
      addTearDown(srv.stop);

      Future<int> exchange(String raw) async {
        final socket = await Socket.connect(InternetAddress.loopbackIPv4, p);
        unawaited(socket.done.catchError((Object _) {}));
        final done = Completer<int>();
        final chunks = <int>[];
        late final StreamSubscription sub;
        sub = socket.listen(
          (d) {
            chunks.addAll(d);
            final text = latin1.decode(chunks, allowInvalid: true);
            final sep = text.indexOf('\r\n\r\n');
            if (done.isCompleted || sep < 0) return;
            final head = text.substring(0, sep);
            final cl = RegExp(
              'content-length:\\s*(\\d+)',
              caseSensitive: false,
            ).firstMatch(head);
            final need = cl == null ? 0 : int.parse(cl.group(1)!);
            final bodyText = text.substring(sep + 4);
            if (bodyText.length >= need || bodyText.endsWith('0\r\n\r\n')) {
              done.complete(int.parse(head.split(' ')[1]));
            }
          },
          onDone: () {
            if (!done.isCompleted) done.completeError('قطع قبل الرد');
          },
          onError: (Object e) {
            if (!done.isCompleted) done.completeError('خطأ مقبس قبل الرد: $e');
          },
        );
        socket.write(raw);
        final status = await done.future.timeout(const Duration(seconds: 30));
        await sub.cancel();
        socket.destroy();
        return status;
      }

      const mb = 1024 * 1024;
      // فائض بترميز chunked: مجموع المقاطع بعد فك الترقيم > السقف
      String chunkedOver(int payloadLen) {
        final b = StringBuffer();
        var remaining = payloadLen;
        const chunk = 65536;
        while (remaining > 0) {
          final take = remaining > chunk ? chunk : remaining;
          b.write('${take.toRadixString(16)}\r\n');
          b.write('x' * take);
          b.write('\r\n');
          remaining -= take;
        }
        b.write('0\r\n\r\n');
        return 'POST / HTTP/1.1\r\nHost: 127.0.0.1:$p\r\n'
            'Origin: https://agent.test\r\n'
            'Content-Type: application/json\r\n'
            'Transfer-Encoding: chunked\r\n\r\n$b';
      }

      final over = chunkedOver(mb + 4096);
      final atBody = '{"data":["${'x' * (mb - 200)}"]}';
      expect(
        utf8.encode(atBody).length,
        lessThan(mb),
        reason: 'at the cap without the wrapper',
      );
      final atHeader =
          'POST / HTTP/1.1\r\n'
          'Host: 127.0.0.1:$p\r\n'
          'Origin: https://agent.test\r\n'
          'Content-Type: application/json\r\n'
          'Content-Length: ${utf8.encode(atBody).length}\r\n\r\n';
      final at = atHeader + atBody;

      // إحماء لكل مسار ثم القياس
      expect(
        await exchange(over),
        413,
        reason: 'the excess through the byte counter',
      );
      expect(await exchange(at), 200, reason: 'at the cap it passes');

      final before = ProcessInfo.currentRss;
      for (var i = 0; i < 15; i++) {
        expect(await exchange(over), 413);
        expect(await exchange(at), 200);
      }
      final after = ProcessInfo.currentRss;
      // ignore: avoid_print
      print(
        'RSS-WITNESS before=$before after=$after '
        'delta-KB=${(after - before) ~/ 1024}',
      );
      expect(
        after - before,
        lessThan(64 * mb),
        reason: 'no cumulative runaway with 30 megabyte-scale bodies',
      );
    },
  );

  test(
    'json amplification: 16 concurrent 1MiB bodies of empty objects stay under a declared ceiling',
    timeout: const Timeout(Duration(minutes: 2)),
    () async {
      // قياس موثق لا تخمين: جسم 1MiB من عناصر فارغة يتضخم لكائنات
      // مفكوكة قبل أن يراها المعالج — المقاعد ال16 كلها دفعة واحدة
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async => const CommandOutcome(ok: true),
        protection: IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
              perOriginPerMinute: 1000,
            ),
          ),
      );
      final p = await srv.start(preferredPort: 31899, fallbacks: const [31881]);
      addTearDown(srv.stop);

      // JSON صالح محشو أقصى عدد عناصر في ميغابايت حرفيا — القطع الأعمى
      // قد يفسر المصفوفة فيرمي المحلل مبكرا بلا تضخيم أصلا
      final parts = <String>['['];
      var budget = 1024 * 1024 - 2;
      while (budget >= 3) {
        final piece = budget > 3 ? '{},' : '{}';
        parts.add(piece);
        budget -= piece.length;
      }
      parts.add(']');
      final body = parts.join();
      final raw =
          'POST / HTTP/1.1\r\n'
          'Host: 127.0.0.1:$p\r\n'
          'Origin: https://amp.test\r\n'
          'Content-Type: application/json\r\n'
          'Content-Length: ${utf8.encode(body).length}\r\n'
          '\r\n'
          '$body';

      final before = ProcessInfo.currentRss;
      final sends = List.generate(16, (_) async {
        final s = await Socket.connect(InternetAddress.loopbackIPv4, p);
        unawaited(s.done.catchError((Object _) {}));
        s.write(raw);
        await s.flush();
        return s;
      });
      final socks = await Future.wait(sends);
      await pumpEventQueue();
      final peak = ProcessInfo.currentRss;
      for (final s in socks) {
        s.destroy();
      }
      final deltaMb = (peak - before) / (1024 * 1024);
      // ignore: avoid_print
      print('AMP-WITNESS rss-delta-MB=$deltaMb');
      // سقف معلن مسبقا: التضخم حقيقي لكنه محصور — تجاوزه يغير قرار
      // توثيق وضع «الكل» (راجع README: cap element counts)
      expect(
        deltaMb,
        lessThan(1024),
        reason: 'peak under the declared megabyte ceiling',
      );
    },
  );
}
