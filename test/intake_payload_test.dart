import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

var _idSeq = 0;
String _counterId() => 'corp-${_idSeq++}';

void main() {
  late LocalIntakeServer server;
  final received = <List<String>>[];

  setUp(() {
    received.clear();
    server = LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _counterId,
      onCommand: (cmd) async {
        received.add(cmd.payloads);
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
  });

  tearDown(() async => server.stop());

  test('listens on preferred port and answers CORS + payload', () async {
    final port = await server.start(preferredPort: 0);
    expect(port, greaterThan(0), reason: 'the assigned port of a port-0 bind');
    expect(server.isListening, isTrue);

    final client = HttpClient();
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', 'https://portal.example');
    req.headers.contentType = ContentType.json;
    req.write(jsonEncode(['H4sIAAAAAAAA/test=']));
    final resp = await req.close();
    final body = await resp.transform(utf8.decoder).join();

    expect(resp.statusCode, 200);
    expect(body, contains('"ok":true'));
    // صدى أصل الطالب — لا «*»
    expect(
      resp.headers.value('Access-Control-Allow-Origin'),
      'https://portal.example',
    );
    expect(received.single.single, 'H4sIAAAAAAAA/test=');
    client.close();
  });

  test('GET is rejected with clear error', () async {
    final port = await server.start(preferredPort: 0);
    final client = HttpClient();
    final req = await client.getUrl(Uri.parse('http://127.0.0.1:$port/'));
    final resp = await req.close();
    expect(resp.statusCode, 405);
    client.close();
  });

  test('falls back when preferred port is busy', () async {
    // المرشح المشغول يُولد من المنفذ 0 ويمسكه مستمع عادي — لا منفذ ثابت.
    // والمرشح الحر يُضم ثم يُحرَّر كي يكون رقمه معلوماً لا مخمَّناً.
    final busy = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(busy.close);
    final spareHolder = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    final spare = spareHolder.port;
    await spareHolder.close();
    final port = await server.start(
      preferredPort: busy.port,
      fallbacks: [spare],
    );
    expect(
      port,
      spare,
      reason: 'the busy candidate is skipped for the fallback',
    );
    expect(port, isNot(busy.port));
  });

  test('a body carrying more than one wrapper key is refused 400 '
      'unsupported_payload_shape and nothing reaches the handler', () async {
    final port = await server.start(preferredPort: 0);
    final client = HttpClient();
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', 'https://portal.example');
    req.headers.contentType = ContentType.json;
    // two wrapper keys present at once: an ambiguous envelope must not be
    // resolved silently by the key order - it is refused as a whole
    req.write('{"payload":["A"],"data":["B"]}');
    final resp = await req.close();
    final body = await resp.transform(utf8.decoder).join();
    expect(
      resp.statusCode,
      400,
      reason: 'an ambiguous multi-key envelope is refused, never guessed',
    );
    expect(body, contains('"error":"unsupported_payload_shape"'));
    expect(
      received,
      isEmpty,
      reason: 'nothing reaches the handler for an ambiguous envelope',
    );
    client.close();
  });

  test('a single wrapper key still unwraps - the ambiguous refusal does not '
      'touch the ordinary shapes', () async {
    final port = await server.start(preferredPort: 0);
    final client = HttpClient();
    for (final body in <String>[
      '{"data":["B"]}',
      '{"payload":["A"]}',
      '{"commands":["C"]}',
    ]) {
      final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
      req.headers.set('Origin', 'https://portal.example');
      req.headers.contentType = ContentType.json;
      req.write(body);
      final resp = await req.close();
      final text = await resp.transform(utf8.decoder).join();
      expect(resp.statusCode, 200, reason: 'single key $body stays served');
      expect(text, contains('"ok":true'));
    }
    expect(received.map((p) => p.single), [
      'B',
      'A',
      'C',
    ], reason: 'each single-key envelope delivers its own command');
    client.close();
  });
}
