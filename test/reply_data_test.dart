// CommandOutcome.data - the reply-data channel back to the page under the
// internal size cap. The success reply carries the data field; over the
// cap the whole result is refused with the registered 413 code (counted
// at the single reply exit), a failed outcome carries the error contract
// and never data, and a null data keeps the wire byte-identical to the
// pre-0.2.0 reply. The exact cap value is pinned here by name of its
// effect: at-cap rides, one byte over refuses.
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

Future<Map<String, Object?>> _send(int port, String cid) async {
  final client = HttpClient();
  try {
    final req = await client.postUrl(Uri.parse('http://127.0.0.1:$port/'));
    req.headers.set('Origin', 'https://data.test');
    req.headers.set('X-Correlation-Id', cid);
    req.headers.contentType = ContentType.json;
    req.write('{"data":["PAY"]}');
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    return <String, Object?>{
      'status': res.statusCode,
      'body': body,
    };
  } finally {
    client.close(force: true);
  }
}

LocalIntakeServer _server(CommandOutcome outcome, List<String> runs) =>
    LocalIntakeServer(
      onCommand: (cmd) async {
        runs.add(cmd.correlationId);
        return outcome;
      },
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'gen-id',
      protection: IntakeProtection(telemetry: const SilentTelemetry())
        ..update(policy: const OriginPolicy(allowed: ['https://data.test'])),
    );

void main() {
  test('data under the cap rides the success reply as its data field', () async {
    final runs = <String>[];
    final server = _server(
      const CommandOutcome(ok: true, data: {
        'receipt': 'R-1',
        'copies': 2,
      }),
      runs,
    );
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    final r = await _send(port, 'd-1');
    expect(r['status'], 200);
    final decoded = jsonDecode(r['body'] as String) as Map<String, Object?>;
    expect(decoded['ok'], true);
    expect(
      decoded['data'],
      {'receipt': 'R-1', 'copies': 2},
      reason: 'the handler data reaches the page verbatim under the cap',
    );
    expect(runs, ['d-1']);
  });

  test('data over the internal cap refuses the whole result with 413 '
      'reply_data_too_large - the command ran once and is counted', () async {
    final runs = <String>[];
    final server = _server(
      CommandOutcome(ok: true, data: 'x' * 100_000),
      runs,
    );
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    final r = await _send(port, 'd-2');
    expect(r['status'], 413, reason: 'the registered status of the code');
    expect(r['body'], contains('reply_data_too_large'));
    expect(r['body'], isNot(contains('xxxxx')),
        reason: 'the over-cap payload itself never reaches the page');
    expect(runs, ['d-2'],
        reason: 'the command executed - the refusal is about the reply, '
            'not the work');
    final counters = server.counters;
    expect(counters.rejectionsByCode['reply_data_too_large'], 1,
        reason: 'the refusal is counted at the single reply exit');
  });

  test('the cap is exact: data of exactly the cap bytes rides, one byte '
      'over refuses', () async {
    // 65534 ASCII chars encode (with the two JSON quotes) to exactly
    // 65536 bytes - the internal cap itself; 65535 chars is one over.
    final runs = <String>[];
    final atCap = _server(
      CommandOutcome(ok: true, data: 'a' * 65_534),
      runs,
    );
    final portAt = await atCap.start(preferredPort: 0);
    addTearDown(atCap.stop);
    final okReply = await _send(portAt, 'd-3');
    expect(okReply['status'], 200, reason: 'at the cap is not over it');
    final decoded = jsonDecode(okReply['body'] as String) as Map<String, Object?>;
    expect(decoded['data'], 'a' * 65_534);

    final overCap = _server(
      CommandOutcome(ok: true, data: 'b' * 65_535),
      runs,
    );
    final portOver = await overCap.start(preferredPort: 0);
    addTearDown(overCap.stop);
    final refused = await _send(portOver, 'd-4');
    expect(refused['status'], 413);
    expect(refused['body'], contains('reply_data_too_large'));
  });

  test('data on a failed outcome is dropped - the error contract is the '
      'reply', () async {
    final runs = <String>[];
    final server = _server(
      const CommandOutcome(
        ok: false,
        errorCode: 'unknown_command',
        data: {'ignored': true},
      ),
      runs,
    );
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    final r = await _send(port, 'd-5');
    expect(r['status'], 500);
    final decoded = jsonDecode(r['body'] as String) as Map<String, Object?>;
    expect(decoded['error'], 'unknown_command');
    expect(
      decoded.containsKey('data'),
      isFalse,
      reason: 'a failed reply carries the error contract and never data',
    );
  });

  test('a null data keeps the reply byte-identical: {"ok":true}', () async {
    final runs = <String>[];
    final server = _server(const CommandOutcome(ok: true), runs);
    final port = await server.start(preferredPort: 0);
    addTearDown(server.stop);

    final r = await _send(port, 'd-6');
    expect(r['status'], 200);
    expect(
      r['body'],
      '{"ok":true}',
      reason: 'no data field is added when the outcome carries none - '
          'the default wire is unchanged for every existing host',
    );
  });
}
