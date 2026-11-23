// شهادة النصاب الذاتي لمشهود TLS ومساعداته المشتركة: الشهادة ثابتان
// مضمنان يحميان لا شيء (حلقي 127.0.0.1 و::1 وlocalhost فقط، ولود محلياً
// مرة واحدة وقت كتابة الملف ليس وقت التشغيل) ويقبلها عميل TLS بعلم
// badCertificate حصراً. والمساعدات الثلاثة هي آلية الشهود على باب TLS:
// التقاط ClientHello حقيقي من عميل SecureSocket نحو مستمع TCP خام،
// وإعادة تشغيل تلك البايتات نحو باب آخر، ومسبار الحياة على السلك من
// العميل نفسه (خطأ سريع = ميت، صمت = حي، نجاح TLS = حي ويجيب).
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

const String certPem = '''
-----BEGIN CERTIFICATE-----
MIIB3zCCAYSgAwIBAgIUfCbVoVwn4WVVULR2IhRc6rxVOsQwCgYIKoZIzj0EAwIw
LTErMCkGA1UEAwwibG9jYWxob3N0X2JyaWRnZS10bHMtdHJhbnNwb3J0LWxhYjAe
Fw0yNjExMjEyMzA3MzhaFw0zNjExMjAyMzA3MzhaMC0xKzApBgNVBAMMImxvY2Fs
aG9zdF9icmlkZ2UtdGxzLXRyYW5zcG9ydC1sYWIwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATPQHygs36xdVlXESz2jhx5eyoi50uvnyN6J0xydgxOrxy1JT5BQLMW
qzPwCl/wMlLzbHNJYEeVpakUB7XNfMeho4GBMH8wHQYDVR0OBBYEFHgaXlPCQz8W
0dtH1Hhj+VIL0uKJMB8GA1UdIwQYMBaAFHgaXlPCQz8W0dtH1Hhj+VIL0uKJMA8G
A1UdEwEB/wQFMAMBAf8wLAYDVR0RBCUwI4cEfwAAAYcQAAAAAAAAAAAAAAAAAAAA
AYIJbG9jYWxob3N0MAoGCCqGSM49BAMCA0kAMEYCIQCJQY2T3zOP7pdUNCqK28T4
CI8Doo3bwh+wQC2R9CXL4gIhAPiTYGZSEZsj8ljXYaoxipEb3eJYP47KR/rsHCQY
GOUV
-----END CERTIFICATE-----''';

const String keyPem = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpVY43QY5bcNL7dFw
599lgDp5x38JRWoBJcXOzvkNalyhRANCAATPQHygs36xdVlXESz2jhx5eyoi50uv
nyN6J0xydgxOrxy1JT5BQLMWqzPwCl/wMlLzbHNJYEeVpakUB7XNfMeh
-----END PRIVATE KEY-----''';

// سياق TLS جاهز من الثابتين المضمّنين حصراً — بلا ملفات وبلا توليد:
// هذا عقد الخيار نفسه (المضيف يمرر سياقاً جاهزاً).
SecurityContext tlsContext() => SecurityContext()
  ..useCertificateChainBytes(utf8.encode(certPem))
  ..usePrivateKeyBytes(utf8.encode(keyPem));

// التقاط أول سجل TLS كامل من عميل حقيقي: مستمع TCP خام يقبل
// `SecureSocket.connect` من عميل، يقرأ الرأس الخماسي والحمولة المعلنة
// (ClientHello)، ثم يغلق — فترجع البايتات لمن يدوّرها على باب آخر.
// العميل نفسه تفشل مصافحته حتماً (الماسك لا يجيب) وهذا هو المقصود.
Future<List<int>> captureClientHello() async {
  final capture = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final done = Completer<List<int>>();
  capture.listen((sock) {
    final buffered = BytesBuilder();
    late final StreamSubscription<List<int>> sub;
    sub = sock.listen(
      (chunk) {
        buffered.add(chunk);
        final bytes = buffered.toBytes();
        if (bytes.length < 5) return;
        final declared = (bytes[3] << 8) | bytes[4];
        if (bytes.length < 5 + declared) return;
        if (!done.isCompleted) {
          done.complete(bytes.sublist(0, 5 + declared));
        }
        sub.cancel();
        sock.destroy();
      },
      onDone: () {
        if (!done.isCompleted) {
          done.completeError(
            StateError('the capture closed before a full first TLS record'),
          );
        }
      },
      onError: (Object _) {
        if (!done.isCompleted) {
          done.completeError(
            StateError(
              'the capture socket errored before a full first TLS record',
            ),
          );
        }
      },
    );
  });
  // عميل TLS حقيقي يرسل ClientHello نحو الماسك؛ فشل مصافحته لا يهم —
  // البايتات وصلت إلى الماسك وهي المطلوب
  unawaited(
    SecureSocket.connect(
      InternetAddress.loopbackIPv4,
      capture.port,
      timeout: const Duration(seconds: 3),
    ).then<void>((c) => c.destroy()).catchError((Object _) {}),
  );
  final hello = await done.future.timeout(const Duration(seconds: 5));
  await capture.close();
  return hello;
}

// إعادة تشغيل ClientHello الملتقط على باب خام: مقبس TCP يكتب السجل
// ويصمت — محرك الطرف الآخر يتسلم الرأس ويعلن مصافحة لن يكملها أحد.
Future<Socket> replayClientHello(List<int> hello, int port) async {
  final sock = await Socket.connect(InternetAddress.loopbackIPv4, port);
  sock.add(hello);
  await sock.flush();
  unawaited(sock.done.catchError((Object _) {}));
  return sock;
}

// مسبار الحياة على السلك من العميل نفسه: مصافحة TLS على المقبس الحي
// بمهلة قصيرة. خطأ سريع (HandshakeException/SocketException) = المقبس
// ميت وصل الإغلاق إلى السلك؛ صمت بالمهلة = حي لا أحد أجاب؛ نجاح TLS =
// حي بل يجيب. هذا المسبار هو القياس لا مخطط أطراف متعددة.
Future<String> wireProbe(Socket client) async {
  try {
    final sec = await SecureSocket.secure(
      client,
      host: 'localhost',
      onBadCertificate: (cert) => true,
    ).timeout(const Duration(seconds: 2));
    sec.destroy();
    return 'TLS-SUCCEEDED';
  } on TimeoutException {
    return 'TIMEOUT-SILENT';
  } on Object catch (e) {
    return 'DEAD (${e.runtimeType})';
  }
}
