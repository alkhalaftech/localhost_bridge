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
    final port = await server.start(preferredPort: 19991);
    expect(port, 19991);
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
    final port = await server.start(preferredPort: 19992);
    final client = HttpClient();
    final req = await client.getUrl(Uri.parse('http://127.0.0.1:$port/'));
    final resp = await req.close();
    expect(resp.statusCode, 405);
    client.close();
  });

  test('falls back when preferred port is busy', () async {
    final blocker = LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: _counterId,
      onCommand: (_) async => const CommandOutcome(ok: false),
    );
    await blocker.start(preferredPort: 19993);
    final port = await server.start(
      preferredPort: 19993,
      fallbacks: const [19994],
    );
    expect(port, 19994);
    await blocker.stop();
  });
}
