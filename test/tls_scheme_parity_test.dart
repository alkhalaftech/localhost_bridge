// شاهد توازي المخطط على باب TLS: الحارس داخل المحوّل الآمن نفسه يعني أن
// كل مقبس مسلَّم يبقى SecureSocket حقيقياً - فالمخطط الذي يقرؤه
// HttpServer عبر `is SecureSocket` يظل https مع المهلة مسلَّحة كما بلا
// مهلة، بالبناء لا بالتجاوز. والشاهد يبني التلقيمة كما يبنيها الخادم
// (مستمع خام وتلقيمة ومهلة مصافحة) ويركّب HttpServer عليه بمعالج
// خارجي يقرأ المخطط والشهادة - وكلتا الحالتين تُدَّعى لا تُطبع.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/src/tls_handshake_feed.dart';
import 'package:test/test.dart';

import 'support/tls_cert.dart';

Future<String> _schemeThrough(Duration? headerTimeout) async {
  final raw = await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final feed = TlsHandshakeFeed(
    raw: raw,
    context: tlsContext(),
    handshakeTimeout: const Duration(seconds: 5),
    headerTimeout: headerTimeout,
    openConnectionCap: 0,
    inFlightHandshakeCap: TlsHandshakeFeed.internalHandshakeCap,
    openConnectionTotal: () => 0,
    inFlightHandshakesTotal: () => 0,
    onCut: () {},
    onDelivered: () {},
    onOverHandshakeCap: (_, _) {},
    onOverConnectionCap: (_, _) {},
  );
  final server = HttpServer.listenOn(feed);
  final seen = Completer<String>();
  server.listen((req) async {
    // قراءة الشكل كما يقرؤه HttpServer: المخطط من requestedUri
    // والشهادة من سطح SecureSocket - كلاهما يُطلب هنا فأي شكل مخفي
    // يظهر في القيمة لا في صمت
    var certificateReadable = true;
    try {
      req.certificate;
    } on Object {
      certificateReadable = false;
    }
    if (!seen.isCompleted) {
      seen.complete(
        'scheme=${req.requestedUri.scheme} '
        'certificateReadable=$certificateReadable',
      );
    }
    req.response.write('ok');
    await req.response.close();
  });
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) => true;
  try {
    final req = await client.getUrl(
      Uri.parse('https://127.0.0.1:${raw.port}/parity'),
    );
    final res = await req.close().timeout(const Duration(seconds: 5));
    final status = res.statusCode;
    await res.drain<void>();
    final seenValue = await seen.future.timeout(const Duration(seconds: 5));
    return '$seenValue status=$status';
  } finally {
    client.close(force: true);
    await server.close(force: true);
    await feed.close();
  }
}

void main() {
  test('a delivered TLS socket reads https with and without the header '
      'deadline armed', () async {
    final without = await _schemeThrough(null);
    final withDeadline = await _schemeThrough(const Duration(seconds: 10));
    expect(
      without,
      contains('scheme=https'),
      reason:
          'with no header deadline the delivered adapter is the only '
          'layer - HttpServer reads its SecureSocket shape and the '
          'request scheme is https',
    );
    expect(
      withDeadline,
      contains('scheme=https'),
      reason:
          'the header deadline lives inside the SecureSocket adapter '
          'itself, so the delivered socket keeps its SecureSocket shape '
          'and HttpServer still reads scheme=https - a wrapper hiding '
          'the shape would read http here',
    );
    expect(
      withDeadline,
      contains('certificateReadable=true'),
      reason: 'the SecureSocket surface stays readable under the deadline',
    );
    expect(
      withDeadline,
      contains('status=200'),
      reason: 'the deadline-armed door serves the request whole',
    );
  });

  test('the header deadline is armed on the TLS door: a stalled header on '
      'a delivered connection is still cut', () async {
    final raw = await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    const deadline = Duration(milliseconds: 700);
    final feed = TlsHandshakeFeed(
      raw: raw,
      context: tlsContext(),
      handshakeTimeout: const Duration(seconds: 5),
      headerTimeout: deadline,
      openConnectionCap: 0,
      inFlightHandshakeCap: TlsHandshakeFeed.internalHandshakeCap,
      openConnectionTotal: () => 0,
      inFlightHandshakesTotal: () => 0,
      onCut: () {},
      onDelivered: () {},
      onOverHandshakeCap: (_, _) {},
      onOverConnectionCap: (_, _) {},
    );
    final server = HttpServer.listenOn(feed);
    server.listen((req) async {
      req.response.write('ok');
      await req.response.close();
    });
    // اتصال مكتمل المصافحة يخدم طلباً ثم يعالق ترويسات الطلب التالي:
    // الساعة التي وُلدت مع المحوّل تقطع العالق في الحد قطعاً هادئاً
    final socket = await SecureSocket.connect(
      '127.0.0.1',
      raw.port,
      onBadCertificate: (cert) => true,
    );
    socket.add(
      utf8.encode(
        'POST / HTTP/1.1\r\n'
        'Host: 127.0.0.1:${raw.port}\r\n'
        'Content-Length: 15\r\n'
        '\r\n["BROWSER-LAB"]',
      ),
    );
    final served = Completer<void>();
    final closed = Completer<void>();
    late final StreamSubscription<List<int>> sub;
    sub = socket.listen(
      (chunk) {
        if (!served.isCompleted) served.complete();
      },
      onDone: () {
        if (!closed.isCompleted) closed.complete();
      },
      onError: (Object _) {
        if (!closed.isCompleted) closed.complete();
      },
    );
    await served.future.timeout(const Duration(seconds: 5));
    socket.add(utf8.encode('GET / HTTP/1.1\r\nHost: x\r\nX-Bridge-Trail'));
    var cut = false;
    try {
      await closed.future.timeout(deadline + const Duration(seconds: 2));
      cut = true;
    } on TimeoutException {
      cut = false;
    }
    unawaited(sub.cancel());
    socket.destroy();
    await server.close(force: true);
    await feed.close();
    expect(
      cut,
      true,
      reason:
          'the tracker armed inside the adapter cuts the stalled header '
          'at the deadline (${deadline.inMilliseconds} ms + margin) - '
          'the deadline arrived with the delivery, not before it',
    );
  });
}
