// شاهدَا عقد محوّل النقل الآمن الناقصين في جدول العقد:
// (1) addStream عبر المسار المسمّى: HttpServer مبنية على التلقيمة
//     تُسلّم مقابس المحوّل، ومسار الرد `HttpResponse.addStream`
//     ينادي `_HttpOutbound.addStream` الذي ينادي `_socket.addStream`
//     (http_impl.dart:3841-3842) — فعلى مقبس المحوّل المسلَّم يجري
//     المسار كله: جسم متدفق يقرأه العميل على TLS كاملاً بترتيبه.
// (2) setOption موجب مباشر: مسار القبول في dart:io يضع tcpNoDelay على
//     كل مقبس غير يونكس (http_impl.dart:3558-3562) — والشاهد يثبت أن
//     نداء المحوّل يبلغ الخام فعلاً: القيمة تُقرأ راجعة من الخام.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:localhost_bridge/src/tls_handshake_feed.dart';

import 'support/tls_cert.dart';

Future<TlsHandshakeFeed> _feed() async {
  final raw = await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  return TlsHandshakeFeed(
    raw: raw,
    context: tlsContext(),
    handshakeTimeout: const Duration(seconds: 5),
    openConnectionCap: 0,
    inFlightHandshakeCap: TlsHandshakeFeed.internalHandshakeCap,
    openConnectionTotal: () => 0,
    inFlightHandshakesTotal: () => 0,
    onCut: () {},
    onDelivered: () {},
    onOverHandshakeCap: (int _, int _) {},
    onOverConnectionCap: (int _, int _) {},
  );
}

void main() {
  test('a host route answering through HttpResponse.addStream streams its '
      'reply over the feed-delivered TLS socket', () async {
    final feed = await _feed();
    addTearDown(() async {
      await feed.close();
    });
    final server = HttpServer.listenOn(feed);
    addTearDown(() async {
      await server.close(force: true);
    });
    server.listen((request) async {
      // هذا هو المسار المسمّى: HttpResponse.addStream على ردّ مرسلته
      // HttpServer فوق مقبس المحوّل المسلَّم
      final chunks = Stream<List<int>>.fromIterable(<List<int>>[
        utf8.encode('streamed-'),
        utf8.encode('body-over-tls'),
      ]);
      request.response.persistentConnection = false;
      await request.response.addStream(chunks);
      await request.response.close();
    });
    final client = HttpClient()
      ..badCertificateCallback = (X509Certificate _, String _, int _) => true;
    addTearDown(() async {
      client.close(force: true);
    });
    final request = await client.getUrl(
      Uri.parse('https://127.0.0.1:${server.port}/'),
    );
    final response = await request.close();
    expect(response.statusCode, 200);
    final body = await utf8.decoder.bind(response).join();
    expect(
      body,
      'streamed-body-over-tls',
      reason:
          'HttpResponse.addStream reaches the adapter and every chunk '
          'crosses the delivered TLS socket in order',
    );
  });

  test('the adapter forwards setOption to its raw socket: tcpNoDelay reads '
      'back set', () async {
    final feed = await _feed();
    addTearDown(() async {
      await feed.close();
    });
    final delivered = Completer<Socket>();
    final sub = feed.listen((socket) {
      if (!delivered.isCompleted) delivered.complete(socket);
    });
    addTearDown(() async {
      await sub.cancel();
    });
    final client = await SecureSocket.connect(
      '127.0.0.1',
      feed.port,
      onBadCertificate: (_) => true,
    );
    addTearDown(client.destroy);
    final adapter = await delivered.future.timeout(
      const Duration(seconds: 5),
      onTimeout: () => fail('the feed never delivered the TLS socket'),
    );
    expect(
      adapter.setOption(SocketOption.tcpNoDelay, true),
      true,
      reason:
          'the accept path of dart:io calls setOption(tcpNoDelay, true) on '
          'every delivered socket (http_impl.dart:3558-3562) - the adapter '
          'must forward it, not name it unsupported',
    );
    // التمكين يُقرأ من الخام بترميز منصته، ولا رقم واحد عبر المنصات:
    // لينكس ويندوز يقرآن 1 وماك يقرأ 4 (مقيس على macos-latest في CI) —
    // فالحكم المشترك الصادق: الحالة بعد النداء ممكَّنة أي غير صفرية،
    // والويندوز يقرأ 1 افتراضياً قبل النداء فلا «تغيّر حالة» يُنتظر
    // منه هناك
    final after = adapter.getRawOption(RawSocketOption(6, 1, Uint8List(4)));
    expect(
      after[0],
      isNot(0),
      reason:
          'IPPROTO_TCP/TCP_NODELAY reads back enabled from the raw socket '
          'after the call - the forward reached the wire layer, it was not '
          'swallowed',
    );
    client.destroy();
  });
}
