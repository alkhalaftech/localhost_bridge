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
      final p = await srv.start(preferredPort: 0);
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
      // قياس موثق لا تخمين: جسم 1MiB من عناصر فارغة يُعدّ عناصره قبل
      // الفك فيُرد 413 قبل أي معالج — والشاهد يقرأ الردود الستة عشر
      // كلها ويؤكد الرفض وصفر معالج، فحالةُ الذاكرة وحدها كانت تقبل
      // خادماً فكّ الأجسام فعلاً بلا أن يخفق شيء
      var handlerCalls = 0;
      final srv = LocalIntakeServer(
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: _counterId,
        onCommand: (_) async {
          handlerCalls++;
          return const CommandOutcome(ok: true);
        },
        protection: IntakeProtection()
          ..update(
            policy: const OriginPolicy(
              allowAllHardened: true,
              requireFetchMetadata: false,
              perOriginPerMinute: 1000,
            ),
          ),
      );
      final p = await srv.start(preferredPort: 0);
      addTearDown(srv.stop);

      /// يقرأ رداً كاملاً من مقبس جسم مُرسل — يفهم CL وخاتمة chunked
      Future<int> readStatus(Socket s) async {
        final done = Completer<int>();
        final chunks = <int>[];
        late final StreamSubscription sub;
        sub = s.listen(
          (d) {
            chunks.addAll(d);
            if (done.isCompleted) return;
            final text = latin1.decode(chunks, allowInvalid: true);
            final sep = text.indexOf('\r\n\r\n');
            if (sep < 0) return;
            final head = text.substring(0, sep);
            final cl = RegExp(
              'content-length:\\s*(\\d+)',
              caseSensitive: false,
            ).firstMatch(head);
            final bodyText = text.substring(sep + 4);
            final hasCl =
                cl != null && bodyText.length >= int.parse(cl.group(1)!);
            if (hasCl || bodyText.endsWith('0\r\n\r\n')) {
              done.complete(int.parse(head.split(' ')[1]));
            }
          },
          onDone: () {
            if (!done.isCompleted) done.completeError('انقطع قبل الرد');
          },
          onError: (Object e) {
            if (!done.isCompleted) done.completeError('خطأ مقبس: $e');
          },
        );
        final status = await done.future.timeout(const Duration(seconds: 30));
        await sub.cancel();
        return status;
      }

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
      // الردود الستة عشر كلها تُقرأ — لا مقبس يهدم قبل أن يحمل حكمه
      final statuses = await Future.wait([
        for (final s in socks) readStatus(s),
      ]);
      final peak = ProcessInfo.currentRss;
      for (final s in socks) {
        s.destroy();
      }
      final deltaMb = (peak - before) / (1024 * 1024);
      final rejected413 = statuses.where((st) => st == 413).length;
      // ignore: avoid_print
      print(
        'AMP-WITNESS rejected413=$rejected413/16 '
        'handler-calls=$handlerCalls rss-delta-MB=$deltaMb',
      );
      expect(
        rejected413,
        16,
        reason:
            'every 1MiB empty-object body is over the element cap and is '
            'refused 413 pre-decode - the witness reads all sixteen replies',
      );
      expect(
        handlerCalls,
        0,
        reason:
            'the element gate answers before any handler runs - a single '
            'decoded body would call the handler here',
      );
      // الحد مشتق مكتوب لا رقم معلق: سقف الجسم (1MiB) × عدد المقاعد
      // (16) = 16MiB أجساماً خاماً؛ النسختان لكل جسم (بايتات المقبس
      // وسلسلة العدّ) ومساحة العد ترفعان المشتق إلى 4×، وضجيج الجيران
      // الموازيين في نفس العملية ×2 — الحد المعلن 128MiB بهامش ×8
      const cfg = BridgeConfig();
      final ceilingMb =
          (cfg.maxBodyBytes * cfg.maxConcurrentRequests * 8) / (1024 * 1024);
      expect(
        deltaMb,
        lessThan(ceilingMb),
        reason:
            'peak under the derived ceiling (body cap × seats, ×8 written '
            'margin) - the old 1024MB bound accepted a decoded runaway',
      );
    },
  );
}
