// شواهد محوّل Native Messaging: الرسالة المؤطرة تُقبل عبر خطوة القبول
// نفسها بأصل الامتداد الموثق من المنصة، وإطارٌ يعلن طولاً فوق السقف
// يُرفض قبل قراءة بايت واحد من جسمه. العناوين بالإنجليزية والتعليقات
// بالعربية (قاعدة البيت).
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import '../tool/native_messaging_adapter.dart';

class _Rec extends BridgeTelemetry {
  @override
  void info(
    String m, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  void warn(
    String m, {
    BridgeCategory category = BridgeCategory.network,
    Map<String, Object?>? context,
  }) {}
  @override
  void error(
    String m, {
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
  }) => body();
}

var _idSeq = 0;

void main() {
  group('native messaging frames', () {
    test(
      'a frame is four little-endian length bytes followed by its payload',
      () {
        final payload = utf8.encode('{"body": "[\\"CMD\\"]"}');
        final frame = encodeNativeMessageFrame(payload);
        expect(frame.length, 4 + payload.length);
        final reader = NativeMessagingFrameReader(maxFrameBytes: 1024 * 1024);
        final events = reader.push(frame);
        expect(events, hasLength(1));
        final frameEvent = events.single;
        expect(frameEvent, isA<NativeMessageFrame>());
        expect((frameEvent as NativeMessageFrame).payload, payload);
      },
    );

    test('a frame split across pushes still reads whole', () {
      final payload = utf8.encode('{"body": "[\\"A\\", \\"B\\"]"}');
      final frame = encodeNativeMessageFrame(payload);
      final reader = NativeMessagingFrameReader(maxFrameBytes: 1024 * 1024);
      expect(reader.push(frame.sublist(0, 2)), isEmpty);
      expect(reader.push(frame.sublist(2, 5)), isEmpty);
      final events = reader.push(frame.sublist(5));
      expect(events, hasLength(1));
      expect((events.single as NativeMessageFrame).payload, payload);
    });

    test('a framed message feeds the same admission step with the extension '
        'origin', () async {
      // جسر صارم بالقائمة: أصل الامتداد مدرجا كاملاً بنمطه — المدخل
      // الكامل يطابق بالتساوي الحرفي قبل أي حكم مخطط
      const extensionOrigin = 'chrome-extension://labextensionidhere';
      final protection = IntakeProtection(telemetry: _Rec());
      protection.update(policy: const OriginPolicy(allowed: [extensionOrigin]));
      final server = LocalIntakeServer(
        onCommand: (command) async => const CommandOutcome(ok: true),
        telemetry: _Rec(),
        correlationIdGenerator: () => 'nm-${_idSeq++}',
        protection: protection,
      );
      final envelope = jsonEncode({
        'body': '["CMD"]',
        'correlationId': 'nm-frame-1',
      });
      final reader = NativeMessagingFrameReader(
        maxFrameBytes: server.config.maxBodyBytes,
      );
      final events = reader.push(
        encodeNativeMessageFrame(utf8.encode(envelope)),
      );
      final payload = utf8.decode(
        (events.single as NativeMessageFrame).payload,
      );
      final envelopeMap = jsonDecode(payload) as Map<String, Object?>;
      final result = await server.acceptHostFeed(
        body: envelopeMap['body']! as String,
        origin: extensionOrigin,
        originTrust: OriginTrustLevel.platformVerified,
        correlationId: envelopeMap['correlationId']! as String,
      );
      expect(result.accepted, isTrue);
      expect(result.command!.payloads, ['CMD']);
      expect(result.command!.correlationId, 'nm-frame-1');
      expect(
        result.command!.admission.acceptedPath,
        IntakeAdmissionPath.listed,
      );
      expect(
        result.command!.admission.originTrust,
        OriginTrustLevel.platformVerified,
      );
    });

    test('a frame declaring a length over the cap is refused before its '
        'payload is read', () {
      final reader = NativeMessagingFrameReader(maxFrameBytes: 64);
      // الترويسة وحدها: أربعة بايتات تعلن 65 — بايتا فوق سقف الـ64
      final header = Uint8List(4);
      ByteData.sublistView(header).setUint32(0, 65, Endian.little);
      final events = reader.push(header);
      expect(events, hasLength(1));
      final refusal = events.single;
      expect(refusal, isA<NativeFrameRefusal>());
      expect((refusal as NativeFrameRefusal).declaredBytes, 65);
      // الجسم المعلن راقد لا مقروء: البايتات المرسلة بعده لم تدخل
      // القراءة ولم تُستهلك
      expect(reader.parkedBytes, 0);
      final after = reader.push([1, 2, 3]);
      expect(after, isEmpty);
      expect(reader.refused, isTrue);
      expect(reader.parkedBytes, 3);
    });
  });
}
