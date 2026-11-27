// شاهد حتمي لحجز السطر المرشّح: ما يحجزه الفاحص المقطعي يُعدّ لا يُقاس.
// سطر يبدأ بـ c طوله 16 كيلوبايت بلا نهاية (لا LF) يُغذّى للفاحص عبر
// الباب العادي في الموضع الذي يصنعه الكود نفسه: تلقيمة القبول تغلّف كل
// مقبول والغلاف يبني الفاحص. يُغذّى السطر مرةً قطعةً واحدة ومرةً بايتاً
// بايتاً، والمطلوب في الحالتين أن تبقى السعة المحجوزة للمخزن عند سقفها
// 256 بايتاً أو أقل — وأيّ نمط وصولٍ للبايتات يحكمه المنطق نفسه فالسقف
// لا يعتمد على تجزيء الوصول. على نسخة بلا سقف يبلغ الحجز حجم السطر كله
// (16384) فيحمرّ الشاهد بالرقم نفسه.
import 'dart:async';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/src/header_watchdog_feed.dart'
    show HeaderDeadlineSocket, HeaderWatchdogFeed;

const int _lineBytes = 16384;
const int _capBytes = 256;
const Duration _deadline = Duration(seconds: 30);

Future<(HeaderWatchdogFeed, int)> _plainDoor() async {
  final door = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final feed = HeaderWatchdogFeed(door: door, deadline: _deadline);
  return (feed, door.port);
}

Future<void> _feedLine(Socket client, List<int> line, bool byteWise) async {
  if (!byteWise) {
    client.add(line);
    await client.flush();
    return;
  }
  for (final b in line) {
    client.add(<int>[b]);
  }
  await client.flush();
}

void main() {
  for (final byteWise in [false, true]) {
    final mode = byteWise ? 'byte by byte' : 'as a single chunk';
    test('a stalled 16 KiB candidate line fed $mode keeps the reserved '
        'buffer at or under the $_capBytes-byte cap', () async {
      final (feed, port) = await _plainDoor();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      unawaited(client.done.catchError((Object _) {}));
      final set = client.setOption(SocketOption.tcpNoDelay, true);
      expect(
        set,
        true,
        reason: 'the witness client must carry every write to the wire',
      );
      final delivered = Completer<Socket>();
      feed.listen(delivered.complete);
      // السطر: أول بايت c (بداية مرشّحة - أول حرف من الترويسات الثلاث
      // المتتبعة) والباقي x، بلا نهاية فلا يُفهم ولا يُسرَّح
      final line = List<int>.filled(_lineBytes, 0x78);
      line[0] = 0x63;
      await _feedLine(client, line, byteWise);
      // تسوية على الساعة: وصول المقطع ومعالجته داخل حدث المقبس الواحد
      // متزامنان، والانتظار يضمن أن آخر مقطع وصل حُسِب قبل القراءة
      await Future<void>.delayed(const Duration(milliseconds: 500));
      final wrapped = await delivered.future.timeout(
        const Duration(seconds: 5),
      );
      final reserved = (wrapped as HeaderDeadlineSocket).candidateReservedBytes;
      // ignore: avoid_print
      print(
        'CANDIDATE-RESERVE mode=$mode fed=$_lineBytes '
        'reserved=$reserved cap=$_capBytes',
      );
      expect(
        reserved,
        lessThanOrEqualTo(_capBytes),
        reason:
            'the scanner must never reserve more than the $_capBytes-byte '
            'cap for a candidate line, however the line arrives - on the '
            'uncapped code the reservation grows with the line to '
            '$_lineBytes bytes (measured: $reserved)',
      );
      client.destroy();
      await feed.close();
    }, timeout: const Timeout(Duration(seconds: 30)));
  }
}
