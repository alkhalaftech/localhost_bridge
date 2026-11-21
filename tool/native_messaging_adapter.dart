// محوّل Native Messaging — جسر إطار المتصفحات إلى خطوة القبول نفسها:
// طول بأربعة بايتات (بالترتيب الأصلي — الأقل أولاً على كل المنصات
// التي تفتح المتصفحات مضيفاً أصلياً) ثم JSON على stdin، وعلى stdout
// الإطار نفسه بعقد الرد القائم. يغذي الخطوةَ أصلَ الامتداد من إعداده
// لا من داخل الرسالة: المتصفح هو من وثّق بالأصل حين سمح للامتداد
// بفتح المضيف بقائمة allowed_extensions في بيان المضيف، فالقيمة من
// الإعداد الموثق تمرّ بدرجة المنصة، وقيمةٌ من داخل الرسالة لا توثيق
// لها فلا تصل الأصل إطلاقاً.
//
// الاستعمال حرفياً (من جذر الحزمة):
//   dart run tool/native_messaging_adapter.dart --origin chrome-extension://<معرّف>
// وبتوكن مشترك إن سُلّح الجسر به:
//   dart run tool/native_messaging_adapter.dart --origin <الأصل> --token <التوكن>
//
// رسالةُ الامتداد غلافُ JSON كائنٌ فيه:
//   {"body": "<نص الأمر كما كان سيُرسل POST>", "token": "<اختياري>",
//    "correlationId": "<اختياري>"}
// والجواب إطارٌ بعقد الرد القائم: {"ok": true/false, ...} بحقوله
// المألوفة (error وmessage وdata) — والقبول هنا الفحوصُ كلها؛
// تنفيذ الأمر وما بعده شأنُ المضيف الذي يعدّل هذه الأداة.
//
// إطارٌ يعلن طولاً فوق سقف الجسم يُرفض قبل قراءة بايت واحد من جسمه:
// الجواب إطار رفض والحجم المعلن راقدٌ غير مقروء ثم تنتهي الأداة —
// تيار الإطار أصبح غير موثوق والقراءة بعده تصرفٌ على بيانات أعمى.
//
// أداةُ إثباتٍ بالواجهة القائمة حصراً: بلا اعتماديات غير dart:io
// وdart:convert والحزمة نفسها، ومضيفُ الإنتاج ينقل منها الثلاثة:
// قارئ الإطارات، وغلاف الرسالة، ونداء acceptHostFeed.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:localhost_bridge/localhost_bridge.dart';

/// One outcome of the frame reader: a complete message frame, or the
/// honest refusal of a declared length over the cap.
sealed class NativeFrameEvent {
  const NativeFrameEvent();
}

/// A complete frame - the payload bytes exactly as the sender framed them.
class NativeMessageFrame extends NativeFrameEvent {
  const NativeMessageFrame(this.payload);

  /// The framed bytes (the JSON message), read whole after the length
  /// header passed the cap.
  final Uint8List payload;
}

/// A refused frame: the four header bytes alone announced a length over
/// the cap, and not one payload byte was read - the declared body stays
/// parked in the reader, unconsumed, so the refusal is provable.
class NativeFrameRefusal extends NativeFrameEvent {
  const NativeFrameRefusal(this.declaredBytes);

  /// The length the header declared - over [NativeMessagingFrameReader.maxFrameBytes].
  final int declaredBytes;
}

/// The incremental Native Messaging frame reader: four native-order
/// (little-endian everywhere the browsers run hosts) length bytes, then
/// that many bytes of JSON. Push stdin chunks as they come; every push
/// returns the events it completed. A frame whose declared length
/// crosses [maxFrameBytes] is refused from the header alone - the body
/// bytes are never read, and the reader parks whatever arrives after the
/// refusal ([parkedBytes]) so the not-read property stays observable and
/// the caller can stop with the stream exactly as it stands.
class NativeMessagingFrameReader {
  NativeMessagingFrameReader({required this.maxFrameBytes})
    : _stash = Uint8List(0);

  /// The largest frame this reader will read - the same standing body
  /// limit the bridge enforces behind it, so an accepted frame is never
  /// a body the admission step would refuse for size alone.
  final int maxFrameBytes;

  Uint8List _stash;
  int _declared = -1;
  bool _refused = false;

  /// Whether a length refusal fired - the reader keeps refusing (and
  /// parking) from here on: the frame stream is not trustworthy.
  bool get refused => _refused;

  /// Bytes parked unread after a refusal - the declared body never
  /// entered a read. Zero while the reader is still healthy.
  int get parkedBytes => _refused ? _stash.length : 0;

  /// Absorbs one stdin chunk and returns every frame it completed (or
  /// the one refusal). Frames split across pushes read whole.
  List<NativeFrameEvent> push(List<int> bytes) {
    if (_refused) {
      // راقدٌ لا مقروء: بايتات ما بعد الرفض تتراكم ظاهرةً ولا بايت
      // منها يدخل قراءةً - دليل «الرفض قبل القراءة» باقٍ على الكائن
      final merged = Uint8List(_stash.length + bytes.length)
        ..setRange(0, _stash.length, _stash)
        ..setRange(_stash.length, _stash.length + bytes.length, bytes);
      _stash = merged;
      return const [];
    }
    _stash = _concat(_stash, bytes);
    final events = <NativeFrameEvent>[];
    while (true) {
      if (_declared < 0) {
        if (_stash.length < 4) break;
        final declared = ByteData.sublistView(
          _stash,
          0,
          4,
        ).getUint32(0, Endian.little);
        if (declared > maxFrameBytes) {
          // الحكم من الترويسة وحدها: الجسم المعلن لا يُقرأ منه بايت
          _refused = true;
          _stash = Uint8List.sublistView(_stash, 4);
          events.add(NativeFrameRefusal(declared));
          break;
        }
        _declared = declared;
        _stash = Uint8List.sublistView(_stash, 4);
        continue;
      }
      if (_stash.length < _declared) break;
      final payload = Uint8List.fromList(
        Uint8List.sublistView(_stash, 0, _declared),
      );
      _stash = Uint8List.sublistView(_stash, _declared);
      _declared = -1;
      events.add(NativeMessageFrame(payload));
    }
    return events;
  }

  static Uint8List _concat(Uint8List a, List<int> b) {
    final out = Uint8List(a.length + b.length)
      ..setRange(0, a.length, a)
      ..setRange(a.length, a.length + b.length, b);
    return out;
  }
}

/// Frames one payload for stdout: four little-endian length bytes, then
/// the payload bytes whole.
Uint8List encodeNativeMessageFrame(List<int> payload) {
  final frame = Uint8List(4 + payload.length);
  ByteData.sublistView(frame, 0, 4).setUint32(0, payload.length, Endian.little);
  frame.setRange(4, frame.length, payload);
  return frame;
}

/// The neutral reference handler: it proves acceptance by answering the
/// standing reply contract with the payload count - a host replaces it
/// with its real command work. The package ends at the trusted command.
Future<CommandOutcome> _echoHandler(TrustedCommand command) async =>
    CommandOutcome(ok: true, data: {'payloads': command.payloads.length});

Future<void> _writeFrame(Uint8List payload) async {
  stdout.add(encodeNativeMessageFrame(payload));
  await stdout.flush();
}

Future<void> _writeErrorFrame(String code, String message) => _writeFrame(
  Uint8List.fromList(
    utf8.encode(
      jsonEncode(<String, Object?>{
        'ok': false,
        'error': code,
        'message': message,
      }),
    ),
  ),
);

Future<void> main(List<String> args) async {
  // الأصل من الإعداد الموثق حصراً: قيمة داخل الرسالة لا توثيق لها فلا
  // تصل الأصل - المتصفح وثّق بالامتداد عند فتح المضيف، والإعداد هو
  // ما يحمل ذلك الأصل إلى خطوة القبول
  String? origin;
  String token = '';
  for (var i = 0; i < args.length; i++) {
    if (args[i] == '--origin' && i + 1 < args.length) {
      origin = args[++i];
    } else if (args[i] == '--token' && i + 1 < args.length) {
      token = args[++i];
    }
  }
  if (origin == null || origin.isEmpty) {
    stderr.writeln(
      'usage: dart run tool/native_messaging_adapter.dart --origin '
      '<extension-origin> [--token <shared-token>]',
    );
    exitCode = 64;
    return;
  }
  // جسر صارم بالقائمة: أصل الامتداد مدرجاً بنمطه الكامل، وبالتوكن
  // المشترك إن مرّ - ونداء القبول الواحد يبقي الفحوص واحدة
  final protection = IntakeProtection();
  protection.update(
    policy: OriginPolicy(allowed: [origin]),
    token: token.isEmpty ? null : token,
  );
  final server = LocalIntakeServer(
    onCommand: _echoHandler,
    telemetry: const SilentTelemetry(),
    correlationIdGenerator: () =>
        'nm-${DateTime.now().microsecondsSinceEpoch.toRadixString(36)}',
    protection: protection,
  );
  final reader = NativeMessagingFrameReader(
    maxFrameBytes: server.config.maxBodyBytes,
  );
  var dead = false;
  await for (final chunk in stdin) {
    for (final event in reader.push(chunk)) {
      if (event is NativeFrameRefusal) {
        // الرفض قبل القراءة حتماً: جوابٌ برمزه ثم نهاية - تيار
        // الإطارات بعد طولٍ كاذب ليس جسراً يُستمر عليه
        await _writeErrorFrame(
          'payload_too_large',
          'The frame declares ${event.declaredBytes} bytes - over the '
              '${reader.maxFrameBytes}-byte cap; the body was not read',
        );
        exitCode = 2;
        dead = true;
        break;
      }
      final frame = event as NativeMessageFrame;
      Object? envelope;
      try {
        envelope = jsonDecode(utf8.decode(frame.payload));
      } on FormatException {
        // فكٌّ بايتي أو JSON مكسور - الرمز واحد للحقيقة واحدة
        await _writeErrorFrame('invalid_json', 'The frame is not valid JSON');
        continue;
      }
      if (envelope is! Map<String, Object?>) {
        await _writeErrorFrame(
          'bad_request',
          'The message envelope must be a JSON object',
        );
        continue;
      }
      final body = envelope['body'];
      if (body is! String) {
        await _writeErrorFrame(
          'bad_request',
          'The message envelope must carry a string "body" field',
        );
        continue;
      }
      final messageToken = envelope['token'];
      if (messageToken != null && messageToken is! String) {
        await _writeErrorFrame(
          'bad_request',
          'The envelope "token" field must be a string',
        );
        continue;
      }
      final messageCid = envelope['correlationId'];
      if (messageCid != null && messageCid is! String) {
        await _writeErrorFrame(
          'bad_request',
          'The envelope "correlationId" field must be a string',
        );
        continue;
      }
      // خطوة القبول الواحدة بأصل الامتداد الموثق من الإعداد - لا
      // منطق حماية في هذه الأداة إطلاقاً
      final result = await server.acceptHostFeed(
        body: body,
        origin: origin,
        originTrust: OriginTrustLevel.platformVerified,
        token: messageToken as String?,
        correlationId: (messageCid as String?) ?? '',
      );
      final rejection = result.rejection;
      if (rejection != null) {
        await _writeErrorFrame(rejection.code, rejection.message);
        continue;
      }
      // القبول يسلّم الأمر الموثوق، والتنفيذ مرجعُ المضيف: المعالج
      // المحايد هنا إثباتُ العقد لا نموذجُ العمل
      final outcome = await _echoHandler(result.command!);
      await _writeFrame(
        Uint8List.fromList(
          utf8.encode(
            jsonEncode(<String, Object?>{
              'ok': outcome.ok,
              if (!outcome.ok) 'error': outcome.errorCode,
              if (!outcome.ok && outcome.errorMessage != null)
                'message': outcome.errorMessage,
              if (outcome.data != null) 'data': outcome.data,
            }),
          ),
        ),
      );
    }
    if (dead) break;
  }
}
