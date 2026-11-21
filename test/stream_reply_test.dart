// The streaming reply channel: a command that opts in with the
// X-Bridge-Stream header reads text/event-stream on the wire - progress
// frames first, then the final result frame carrying the standing reply
// contract. The option is off by default: an unknown header keeps the
// ordinary JSON reply byte-identical, and only the armed config + the
// header pair turns a command into a stream.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:localhost_bridge/localhost_bridge.dart';
import 'package:test/test.dart';

/// The SSE frames of a streamed reply as (event, data) pairs, read in the
/// arrival order the page sees.
List<(String, String)> framesOf(String text) {
  final out = <(String, String)>[];
  for (final block in text.trim().split('\n\n')) {
    String? event;
    final data = <String>[];
    for (final line in block.split('\n')) {
      if (line.startsWith('event: ')) event = line.substring(7);
      if (line.startsWith('data: ')) data.add(line.substring(6));
    }
    if (event != null) out.add((event, data.join('\n')));
  }
  return out;
}

void main() {
  Future<(LocalIntakeServer, IntakeProtection)> server({
    required Future<CommandOutcome> Function(TrustedCommand cmd) onCommand,
    BridgeConfig config = const BridgeConfig(),
  }) async {
    final protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(policy: const OriginPolicy(allowed: ['https://portal.example']));
    final srv = LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'stream-1',
      protection: protection,
      onCommand: onCommand,
      config: config,
    );
    await srv.start(preferredPort: 0);
    return (srv, protection);
  }

  /// A full streaming POST: the option armed, the header set, the reply
  /// read to its end.
  Future<(String ctype, String text)> streamPost(int port) async {
    final client = HttpClient();
    final req = await client.open('POST', '127.0.0.1', port, '/');
    req.headers.set('Content-Type', 'application/json');
    req.headers.set('X-Bridge-Stream', 'events');
    req.headers.set('Origin', 'https://portal.example');
    req.headers.set('Sec-Fetch-Mode', 'cors');
    req.headers.set('Sec-Fetch-Dest', 'empty');
    req.add(utf8.encode('["LONG-JOB"]'));
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    final ctype = res.headers.value(HttpHeaders.contentTypeHeader) ?? '';
    client.close(force: true);
    return (ctype, text);
  }

  test('a POST opting in with X-Bridge-Stream reads a streaming reply: '
      'three progress frames then the result frame, in order', () async {
    final (srv, protection) = await server(
      config: const BridgeConfig(allowStreamingReplies: true),
      onCommand: (cmd) async {
        cmd.progress?.call({'step': 1});
        cmd.progress?.call({'step': 2});
        cmd.progress?.call({'step': 3});
        return const CommandOutcome(ok: true, data: {'done': true});
      },
    );
    try {
      final (ctype, text) = await streamPost(srv.port);
      expect(
        ctype,
        contains('text/event-stream'),
        reason: 'the opted-in command answers the streaming media type',
      );
      final frames = framesOf(text);
      expect(frames, hasLength(4), reason: 'three progress then the result');
      expect(frames[0].$1, 'progress');
      expect(frames[0].$2, contains('"step":1'));
      expect(frames[1].$1, 'progress');
      expect(frames[1].$2, contains('"step":2'));
      expect(frames[2].$1, 'progress');
      expect(frames[2].$2, contains('"step":3'));
      expect(frames[3].$1, 'result');
      final result = jsonDecode(frames[3].$2) as Map;
      expect(result['ok'], true);
      expect((result['data'] as Map)['done'], true);
    } finally {
      protection.dispose();
      await srv.stop();
    }
  });

  test('with the option off the streaming header is unknown and the reply '
      'stays the ordinary JSON one', () async {
    final (srv, protection) = await server(
      onCommand: (cmd) async {
        expect(
          cmd.progress,
          isNull,
          reason: 'no streaming channel was asked for - the sink is null',
        );
        return const CommandOutcome(ok: true, data: {'done': true});
      },
    );
    try {
      final client = HttpClient();
      final req = await client.open('POST', '127.0.0.1', srv.port, '/');
      req.headers.set('Content-Type', 'application/json');
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set('X-Bridge-Stream', 'events');
      req.add(utf8.encode('["X"]'));
      final res = await req.close();
      final ctype = res.headers.value(HttpHeaders.contentTypeHeader) ?? '';
      expect(
        ctype,
        contains('application/json'),
        reason: 'the disarmed wire never streams',
      );
      final body = await res.transform(utf8.decoder).join();
      expect(body, contains('"ok":true'));
      client.close(force: true);
    } finally {
      protection.dispose();
      await srv.stop();
    }
  });

  test('the allowed-header list offers the streaming name only while the '
      'option is on', () async {
    final (off, offProtection) = await server(
      onCommand: (cmd) async => const CommandOutcome(ok: true),
    );
    try {
      final client = HttpClient();
      final req = await client.open('OPTIONS', '127.0.0.1', off.port, '/');
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set('Access-Control-Request-Method', 'POST');
      final res = await req.close();
      final offered = res.headers.value('Access-Control-Allow-Headers') ?? '';
      expect(offered, isNot(contains('X-Bridge-Stream')));
      client.close(force: true);
    } finally {
      offProtection.dispose();
      await off.stop();
    }
    final (on, onProtection) = await server(
      config: const BridgeConfig(allowStreamingReplies: true),
      onCommand: (cmd) async => const CommandOutcome(ok: true),
    );
    try {
      final client = HttpClient();
      final req = await client.open('OPTIONS', '127.0.0.1', on.port, '/');
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set('Access-Control-Request-Method', 'POST');
      req.headers.set('Access-Control-Request-Headers', 'x-bridge-stream');
      final res = await req.close();
      final offered = res.headers.value('Access-Control-Allow-Headers') ?? '';
      expect(
        offered,
        contains('X-Bridge-Stream'),
        reason: 'the preflight must allow the streaming header while armed',
      );
      client.close(force: true);
    } finally {
      onProtection.dispose();
      await on.stop();
    }
  });

  test('a progress report over the internal event cap ends the stream with '
      'the registered refusal and fires the cancel signal', () async {
    final seenCancelled = <bool>[];
    final (srv, protection) = await server(
      config: const BridgeConfig(allowStreamingReplies: true),
      onCommand: (cmd) async {
        cmd.progress?.call('small');
        cmd.progress?.call('p' * (70 * 1024));
        // The refusal ended the channel - the sink is inert and the
        // handler is asked to wrap up; read the signal here.
        seenCancelled.add(cmd.cancellation.isCancelled);
        // A late report does nothing and throws nothing.
        cmd.progress?.call('late');
        return const CommandOutcome(ok: true, data: {'late': true});
      },
    );
    try {
      final (ctype, text) = await streamPost(srv.port);
      expect(ctype, contains('text/event-stream'));
      final frames = framesOf(text);
      expect(frames, hasLength(2), reason: 'small progress then the refusal');
      expect(frames[0].$1, 'progress');
      expect(frames[1].$1, 'result');
      expect(frames[1].$2, contains('"progress_data_too_large"'));
      expect(seenCancelled.single, isTrue, reason: 'the handler saw the ask');
    } finally {
      protection.dispose();
      await srv.stop();
    }
  });

  test('result data over the reply cap reads the refusal contract as the '
      'final frame - never a truncation', () async {
    final (srv, protection) = await server(
      config: const BridgeConfig(allowStreamingReplies: true),
      onCommand: (cmd) async {
        cmd.progress?.call({'step': 1});
        return CommandOutcome(ok: true, data: 'd' * (70 * 1024));
      },
    );
    try {
      final (_, text) = await streamPost(srv.port);
      final frames = framesOf(text);
      expect(frames, hasLength(2));
      expect(frames[1].$1, 'result');
      expect(frames[1].$2, contains('"reply_data_too_large"'));
    } finally {
      protection.dispose();
      await srv.stop();
    }
  });

  test('a failing handler reads its failure contract as the final frame - '
      'the code rides and the standing fallback text follows for the '
      'listed (verbose) origin', () async {
    final (srv, protection) = await server(
      config: const BridgeConfig(allowStreamingReplies: true),
      onCommand: (cmd) async =>
          const CommandOutcome(ok: false, errorCode: 'printer_offline'),
    );
    try {
      final (_, text) = await streamPost(srv.port);
      final frames = framesOf(text);
      expect(frames, hasLength(1), reason: 'no progress, one result frame');
      expect(frames[0].$1, 'result');
      final result = jsonDecode(frames[0].$2) as Map;
      expect(result['ok'], false);
      expect(result['error'], 'printer_offline');
      expect(
        result['message'],
        'Command execution failed',
        reason:
            'the listed origin is verbose and sees the standing '
            'fallback text - the same contract the JSON reply carries',
      );
    } finally {
      protection.dispose();
      await srv.stop();
    }
  });

  test('the handler budget expiry mid-stream reads handler_timeout as the '
      'final frame and counts at the single tally', () async {
    final protection = IntakeProtection(telemetry: const SilentTelemetry())
      ..update(policy: const OriginPolicy(allowed: ['https://portal.example']));
    final srv = LocalIntakeServer(
      telemetry: const SilentTelemetry(),
      correlationIdGenerator: () => 'stream-2',
      protection: protection,
      onCommand: (cmd) async {
        cmd.progress?.call({'step': 1});
        await Future<void>.delayed(const Duration(milliseconds: 300));
        return const CommandOutcome(ok: true);
      },
      config: const BridgeConfig(allowStreamingReplies: true),
      handlerTimeout: const Duration(milliseconds: 50),
    );
    await srv.start(preferredPort: 0);
    try {
      final client = HttpClient();
      final req = await client.open('POST', '127.0.0.1', srv.port, '/');
      req.headers.set('Content-Type', 'application/json');
      req.headers.set('Origin', 'https://portal.example');
      req.headers.set('X-Bridge-Stream', 'events');
      req.add(utf8.encode('["SLOW"]'));
      final res = await req.close().timeout(const Duration(seconds: 8));
      final text = await res.transform(utf8.decoder).join();
      client.close(force: true);
      final frames = framesOf(text);
      expect(frames, hasLength(2), reason: 'one progress then the expiry');
      expect(frames[0].$1, 'progress');
      expect(frames.last.$1, 'result');
      expect(frames.last.$2, contains('"handler_timeout"'));
      final counters = srv.counters;
      expect(
        counters.rejectionsByCode['handler_timeout'],
        1,
        reason: 'the budget expiry is counted at the single tally',
      );
      expect(
        counters.orphanHandlers,
        1,
        reason: 'the still-running handler counts as an orphan',
      );
    } finally {
      protection.dispose();
      await srv.stop().timeout(const Duration(seconds: 10));
    }
  });

  test('the page closing mid-stream reaches the handler as cancellation '
      'and leaves no seat nor socket', () async {
    final cancellationFired = Completer<void>();
    final (srv, protection) = await server(
      config: const BridgeConfig(allowStreamingReplies: true),
      onCommand: (cmd) async {
        cmd.progress?.call({'step': 1});
        // المعالج التعاوني يقرأ الإشارة — الإغلاق من طرف الصفحة هو
        // ما يجب أن يشعلها
        while (!cmd.cancellation.isCancelled) {
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }
        cancellationFired.complete();
        return const CommandOutcome(ok: true);
      },
    );
    try {
      // الصفحة تفتح التدفق، تقرأ رأسه وإطارها الأول، ثم تقطع الاتصال
      final raw = await Socket.connect('127.0.0.1', srv.port);
      raw.add(
        utf8.encode(
          'POST / HTTP/1.1\r\nHost: 127.0.0.1:${srv.port}\r\n'
          'Origin: https://portal.example\r\n'
          'Content-Type: application/json\r\nX-Bridge-Stream: events\r\n'
          'Content-Length: 9\r\n\r\n["ABANDON"]',
        ),
      );
      await raw.flush();
      // قراءة محدودة: تجميع القطع حتى يعبر الرأس والإطار الأول — ثم القطع
      final seen = StringBuffer();
      final frameCrossed = Completer<void>();
      late final StreamSubscription<List<int>> rawSub;
      rawSub = raw.listen(
        (c) {
          seen.write(utf8.decode(c, allowMalformed: true));
          if (seen.toString().contains('event: progress')) {
            frameCrossed.complete();
            rawSub.cancel();
          }
        },
        onDone: () => frameCrossed.complete(),
        onError: (Object _) => frameCrossed.complete(),
      );
      await frameCrossed.future.timeout(const Duration(seconds: 5));
      final first = seen.toString();
      expect(first, contains('200'), reason: 'the stream head arrived');
      expect(first, contains('event: progress'), reason: 'a frame crossed');
      raw.destroy();
      await cancellationFired.future.timeout(const Duration(seconds: 5));
      final report = await srv.stop().timeout(const Duration(seconds: 5));
      expect(
        report.fullyDrained,
        isTrue,
        reason: 'the abandoned stream left nothing working at the stop',
      );
      expect(srv.counters.activeSeats, 0);
    } finally {
      protection.dispose();
      await srv.stop().timeout(const Duration(seconds: 5));
    }
  });
}
