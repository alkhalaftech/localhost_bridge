// الفحص العشوائي المبذور عبر السلك: بذور ثابتة مكتوبة نصاً ومولّد Dart
// (Random(seed)) يبني 240 حالة لكل بذرة من ثلاث عائلات — أجسام (مسافات
// وBOM وCR/LF ويونيكود وأعماق وسلاسل طويلة وسقف العناصر والعمق) وأصول
// (أشكال المتصفح السليمة والمعتلة وسقف الطول ±1) وتوكنات (قصيرة وطويلة
// وحد البايتات ±1) — ويحسب عقد كل حالة من ترتيب بوابات الاستقبال الموثق:
// كل حالة إما تُقبل 200 بمعالج استُدعي مرة واحدة وحمولات مطابقة أو تُرد
// بالحالة والرمز الثابت المحسوب حصراً، ولا تعليق (مهلة 5 ثوان لكل تبادل)
// ولا 500 إطلاقاً. سقوف العقد هي الافتراضيات الموثقة: جسم 1MiB وعناصر
// JSON ‏10,000 بعمق 32 وأصل 1,024 محرفاً وتوكن 1,024 بايتاً. والتخمينات
// الخاطئة للأصل كلٌّ بأصل فريد كي تبقى نوافذ إخفاق التوكن بمدخل واحد ولا
// يقفل قفلٌ حالةً تلو أخرى.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data' show BytesBuilder;

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

import 'support/wire.dart' show bodyJson, bodyText;

/// The seeds are part of the contract: a failure names its seed, and
/// rerunning reproduces the exact same cases in the same order.
const _seeds = <int>[2026, 1115, 424242];

const _casesPerSeed = 240;
const _listedCasesPerSeed = 180;
const _tokenCasesPerSeed = 60;

const _maxBodyBytes = 1024 * 1024;
const _maxJsonElements = 10000;
const _maxJsonDepth = 32;
const _maxOriginChars = 1024;
const _maxTokenBytes = 1024;

const _listedOrigin = 'https://a.example';
const _t64 = 'a3f1c52e94b7d068f5e2a9c4b1d7e8036f9a2c5e8b1d7f04a6c9e2d5f8b3a1c7';

/// A generated wire case together with the outcome its contract fixes:
/// either the accepted shape (200, handler served exactly the given
/// payloads) or the rejection (exact status and stable code). `acao` marks
/// the accepts where the CORS echo applies (listed origins only).
final class _Case {
  final String label;
  final List<int> bytes;
  final bool accepted;
  final List<String>? payloads;
  final int? status;
  final String? code;
  final bool acao;
  const _Case.reject(this.label, this.bytes, this.status, this.code)
    : accepted = false,
      payloads = null,
      acao = false;
  const _Case.accept(this.label, this.bytes, this.payloads, {this.acao = false})
    : accepted = true,
      status = null,
      code = null;
}

/// The bridge's live port for the exchange helper - one server is active
/// per phase, so a plain field beats threading the port through every
/// builder.
int _activePort = 0;

/// One exchange over the raw socket: the request bytes go out whole, the
/// reply is settled when the declared length arrives or the chunk
/// terminator does, and a timeout answers a synthetic -2 status so a hang
/// fails the case instead of holding the suite.
Future<Map<String, Object>> _exchange(List<int> requestBytes) async {
  final socket = await Socket.connect('127.0.0.1', _activePort);
  final buffer = BytesBuilder();
  final done = Completer<Map<String, Object>>();
  late final StreamSubscription<List<int>> sub;
  void settle(List<int> raw) {
    final text = latin1.decode(raw, allowInvalid: true);
    final sep = text.indexOf('\r\n\r\n');
    final head = sep < 0 ? text : text.substring(0, sep);
    final body = sep < 0 ? '' : text.substring(sep + 4);
    final statusLine = head.isEmpty ? '' : head.split('\r\n').first;
    final headers = <String, String>{};
    for (final line in head.split('\r\n').skip(1)) {
      final i = line.indexOf(':');
      if (i > 0) {
        headers[line.substring(0, i).trim().toLowerCase()] = line
            .substring(i + 1)
            .trim();
      }
    }
    done.complete({
      'status': statusLine.isEmpty
          ? -1
          : (int.tryParse(statusLine.split(' ')[1]) ?? -1),
      'headers': headers,
      'body': body,
    });
  }

  sub = socket.listen(
    (chunk) {
      buffer.add(chunk);
      if (done.isCompleted) return;
      final text = latin1.decode(buffer.toBytes(), allowInvalid: true);
      final sep = text.indexOf('\r\n\r\n');
      if (sep < 0) return;
      final head = text.substring(0, sep);
      final clMatch = RegExp(
        r'content-length:\s*(\d+)',
        caseSensitive: false,
      ).firstMatch(head);
      final bodyLen = text.length - (sep + 4);
      final hasCl = clMatch != null && bodyLen >= int.parse(clMatch.group(1)!);
      if (hasCl || text.endsWith('0\r\n\r\n')) settle(buffer.toBytes());
    },
    onDone: () {
      if (!done.isCompleted) settle(buffer.toBytes());
    },
  );
  socket.add(requestBytes);
  final result = await done.future.timeout(
    const Duration(seconds: 5),
    onTimeout: () => <String, Object>{
      'status': -2,
      'headers': <String, String>{},
      'body': 'NO-RESPONSE',
    },
  );
  await sub.cancel();
  socket.destroy();
  return result;
}

/// The whole raw request as bytes: an ASCII head (except a non-ASCII Origin
/// rides as its UTF-8 bytes - the shape verdict is byte-independent here)
/// and the body appended raw, with the Content-Length computed from the
/// actual body bytes unless the case declares a length of its own (the
/// over-cap declaration probe).
List<int> _request({
  String method = 'POST',
  String? origin,
  bool omitOrigin = false,
  String? fetchMode,
  String? fetchDest,
  String? token,
  List<String> extraHeaderLines = const [],
  String? contentType,
  required List<int> body,
  int? declaredLength,
}) {
  final head = StringBuffer()..write('$method / HTTP/1.1\r\n');
  head.write('Host: 127.0.0.1:$_activePort\r\n');
  if (!omitOrigin && origin != null) head.write('Origin: $origin\r\n');
  if (fetchMode != null) head.write('Sec-Fetch-Mode: $fetchMode\r\n');
  if (fetchDest != null) head.write('Sec-Fetch-Dest: $fetchDest\r\n');
  if (token != null) head.write('X-Bridge-Token: $token\r\n');
  for (final line in extraHeaderLines) {
    head.write('$line\r\n');
  }
  if (contentType != null) head.write('Content-Type: $contentType\r\n');
  head.write('Content-Length: ${declaredLength ?? body.length}\r\n\r\n');
  return <int>[...utf8.encode(head.toString()), ...body];
}

List<int> _bodyOf(String text) => utf8.encode(text);

/// A well-formed, unlisted Origin of exactly [n] characters - the length
/// boundary rides on pure ASCII host labels so the cap arithmetic stays
/// exact.
String _originOfLength(int n) => 'https://${'a' * (n - 16)}.example';

/// One generated case for the listed-policy phase: every verdict here is
/// stateless (closed default, no quota, no token, no consent callback), so
/// the contract of a case never depends on another case.
_Case _listedCase(Random rng, int index) {
  final tag = '$index';
  final pick = rng.nextInt(100);
  if (pick < 46) {
    return _bodyCase(rng, tag);
  } else if (pick < 56) {
    final unique = rng.nextInt(99999);
    return _Case.reject(
      'unlisted-origin-$tag',
      _request(
        origin: 'https://w$unique.example',
        contentType: 'application/json',
        body: _bodyOf('{"data":["CMD"]}'),
      ),
      403,
      'origin_not_listed',
    );
  } else if (pick < 66) {
    final kinds = <String, String>{
      'userinfo': 'https://portal.example@evil.example',
      'path': 'https://x.example/p$index',
      'query': 'https://x.example?q=$index',
      'fragment': 'https://x.example#f$index',
      'space': 'https://x exampl$index',
      'control': 'https://x.example\u0007',
      'control-esc': 'https://x.example\u001b',
    };
    final kind = kinds.keys.elementAt(rng.nextInt(kinds.length));
    return _Case.reject(
      'malformed-origin-$kind-$tag',
      _request(
        origin: kinds[kind]!,
        contentType: 'application/json',
        body: _bodyOf('{"data":["CMD"]}'),
      ),
      400,
      'origin_malformed',
    );
  } else if (pick < 72) {
    final n = _maxOriginChars + 1 + rng.nextInt(76);
    return _Case.reject(
      'overlong-origin-$n-$tag',
      _request(
        origin: _originOfLength(n),
        contentType: 'application/json',
        body: _bodyOf('{"data":["CMD"]}'),
      ),
      400,
      'origin_too_long',
    );
  } else if (pick < 76) {
    final n = <int>[1023, 1024, 1025][rng.nextInt(3)];
    return n > _maxOriginChars
        ? _Case.reject(
            'origin-cap-$n-$tag',
            _request(
              origin: _originOfLength(n),
              contentType: 'application/json',
              body: _bodyOf('{"data":["CMD"]}'),
            ),
            400,
            'origin_too_long',
          )
        : _Case.reject(
            'origin-cap-$n-$tag',
            _request(
              origin: _originOfLength(n),
              contentType: 'application/json',
              body: _bodyOf('{"data":["CMD"]}'),
            ),
            403,
            'origin_not_listed',
          );
  } else if (pick < 80) {
    return rng.nextBool()
        ? _Case.reject(
            'origin-absent-$tag',
            _request(
              omitOrigin: true,
              contentType: 'application/json',
              body: _bodyOf('{"data":["CMD"]}'),
            ),
            403,
            'origin_not_listed',
          )
        : _Case.reject(
            'origin-literal-null-$tag',
            _request(
              origin: 'null',
              contentType: 'application/json',
              body: _bodyOf('{"data":["CMD"]}'),
            ),
            403,
            'origin_not_listed',
          );
  } else if (pick < 86) {
    final byMode = rng.nextBool();
    final mode = byMode ? (rng.nextInt(2) == 0 ? 'navigate' : 'no-cors') : null;
    return byMode
        ? _Case.reject(
            'fetch-mode-$mode-$tag',
            _request(
              origin: _listedOrigin,
              fetchMode: mode,
              fetchDest: 'empty',
              contentType: 'application/json',
              body: _bodyOf('{"data":["CMD"]}'),
            ),
            403,
            'cross_site_blocked',
          )
        : _Case.reject(
            'fetch-dest-document-$tag',
            _request(
              origin: _listedOrigin,
              fetchMode: 'cors',
              fetchDest: 'document',
              contentType: 'application/json',
              body: _bodyOf('{"data":["CMD"]}'),
            ),
            403,
            'cross_site_blocked',
          );
  } else if (pick < 90) {
    final method = <String>['GET', 'PUT', 'DELETE'][rng.nextInt(3)];
    return _Case.reject(
      'method-$method-$tag',
      _request(method: method, origin: _listedOrigin, body: const <int>[]),
      405,
      'method_not_allowed',
    );
  } else if (pick < 95) {
    final name = rng.nextInt(3);
    final label = switch (name) {
      0 => 'duplicate-origin',
      1 => 'duplicate-token',
      _ => 'duplicate-corr',
    };
    final extra = switch (name) {
      0 => ['Origin: $_listedOrigin'],
      1 => ['X-Bridge-Token: $_t64'],
      _ => ['X-Correlation-Id: dup-a', 'X-Correlation-Id: dup-b'],
    };
    return _Case.reject(
      '$label-$tag',
      _request(
        origin: _listedOrigin,
        token: name == 1 ? _t64 : null,
        extraHeaderLines: extra,
        contentType: 'application/json',
        body: _bodyOf('{"data":["CMD"]}'),
      ),
      400,
      'duplicate_header',
    );
  } else if (pick < 98) {
    final form = rng.nextInt(2) == 0;
    return _Case.reject(
      'content-type-$tag',
      _request(
        origin: _listedOrigin,
        contentType: form
            ? 'application/x-www-form-urlencoded'
            : 'multipart/form-data; boundary=X',
        body: _bodyOf('data=CMD'),
      ),
      415,
      'unsupported_media_type',
    );
  }
  final n = _maxTokenBytes + 1 + rng.nextInt(500);
  return _Case.reject(
    'token-overlong-on-listed-$n-$tag',
    _request(
      origin: _listedOrigin,
      token: 'x' * n,
      contentType: 'application/json',
      body: _bodyOf('{"data":["CMD"]}'),
    ),
    400,
    'token_too_long',
  );
}

/// The body pipeline for an admitted origin: the Content-Type gate, the
/// declared-length gate, the UTF-8 decode, and the element/depth caps each
/// fix the verdict of the spec the rng picked. The element arithmetic is
/// analytic (the specs are built from pieces): '[],'*N+'[]' counts
/// 2N+1 elements at depth 2, and '['*D+']'*D counts D elements at depth D.
_Case _bodyCase(Random rng, String tag) {
  final spec = rng.nextInt(21);
  switch (spec) {
    case 0:
      return _Case.accept(
        'body-wrapper-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('{"data":["CMD-$tag"]}'),
        ),
        ['CMD-$tag'],
        acao: true,
      );
    case 1:
      return _Case.accept(
        'body-array-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('["A","B-$tag"]'),
        ),
        ['A', 'B-$tag'],
        acao: true,
      );
    case 2:
      return _Case.accept(
        'body-array-drops-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('[1,"keep-$tag","",2]'),
        ),
        ['keep-$tag'],
        acao: true,
      );
    case 3:
      return _Case.reject(
        'body-empty-array-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('[]'),
        ),
        400,
        'empty_payload',
      );
    case 4:
    case 5:
    case 6:
      final shapes = <String>['{}', '{"unknown-key":1}', '{"data":42}'];
      return _Case.reject(
        'body-shape-spec$spec-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf(shapes[spec - 4]),
        ),
        400,
        'unsupported_payload_shape',
      );
    case 7:
      final raws = <String>['42', 'true', 'null'];
      final raw = raws[rng.nextInt(raws.length)];
      return _Case.accept(
        'body-raw-json-$raw-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf(raw),
        ),
        [raw],
        acao: true,
      );
    case 8:
      return _Case.accept(
        'body-json-string-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('"PONG-$tag"'),
        ),
        ['PONG-$tag'],
        acao: true,
      );
    case 9:
      // BOM الافتتاحي يستهلكه utf8.decode عند الخادم فيعبر الجسم JSONً
      // سليماً — والحمولة قيمة المفتاح لا النص الخام.
      return _Case.accept(
        'body-bom-json-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('\uFEFF{"data":["BOM-$tag"]}'),
        ),
        ['BOM-$tag'],
        acao: true,
      );
    case 10:
      return _Case.reject(
        'body-bom-only-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('\uFEFF'),
        ),
        400,
        'empty_payload',
      );
    case 11:
      return _Case.accept(
        'body-crlf-text-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'text/plain',
          body: _bodyOf('PING\r\nLINE-$tag\r\n'),
        ),
        ['PING\r\nLINE-$tag'],
        acao: true,
      );
    case 12:
      return _Case.accept(
        'body-unicode-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('["مرحبا 🌍-$tag"]'),
        ),
        ['مرحبا 🌍-$tag'],
        acao: true,
      );
    case 13:
      return _Case.accept(
        'body-padded-json-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('  {"data":["PAD-$tag"]}\r\n'),
        ),
        ['PAD-$tag'],
        acao: true,
      );
    case 14:
      return _Case.accept(
        'body-long-string-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('["${'x' * 20000}"]'),
        ),
        ['x' * 20000],
        acao: true,
      );
    case 15:
      return rng.nextBool()
          ? _Case.reject(
              'body-depth-within-$tag',
              _request(
                origin: _listedOrigin,
                contentType: 'application/json',
                body: _bodyOf('${'[' * _maxJsonDepth}${']' * _maxJsonDepth}'),
              ),
              400,
              'empty_payload',
            )
          : _Case.reject(
              'body-depth-over-$tag',
              _request(
                origin: _listedOrigin,
                contentType: 'application/json',
                body: _bodyOf(
                  '${'[' * (_maxJsonDepth + 1)}${']' * (_maxJsonDepth + 1)}',
                ),
              ),
              413,
              'payload_too_complex',
            );
    case 16:
      // مصفوفة خارجية واحدة تحوي مصفوفات فارغة: '[' + '[],'*N + '[]' + ']'
      // — عناصرها الخارجية+الداخلية+الفواصل = 2N+2؛ بالضبط 10,000 يمر
      // بالعدّاد (يحسم فوقه حصراً) فيفك فيسقط كل عناصره غير النصية
      // ⟵ empty_payload، و10,001 يحسمه العدّاد قبل الفك ⟵ payload_too_complex.
      return rng.nextBool()
          ? _Case.reject(
              'body-elements-at-cap-$tag',
              _request(
                origin: _listedOrigin,
                contentType: 'application/json',
                body: _bodyOf('[${'[],' * ((_maxJsonElements - 2) ~/ 2)}[]]'),
              ),
              400,
              'empty_payload',
            )
          : _Case.reject(
              'body-elements-over-$tag',
              _request(
                origin: _listedOrigin,
                contentType: 'application/json',
                body: _bodyOf('[${'[],' * (_maxJsonElements ~/ 2)}[]]'),
              ),
              413,
              'payload_too_complex',
            );
    case 17:
      return _Case.reject(
        'body-empty-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: const <int>[],
        ),
        400,
        'empty_payload',
      );
    case 18:
      return _Case.reject(
        'body-invalid-utf8-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: const <int>[0xFF, 0xFE, 0x5A],
        ),
        400,
        'invalid_utf8',
      );
    case 19:
      return _Case.reject(
        'body-declared-overcap-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'application/json',
          body: _bodyOf('{"data":["CMD"]}'),
          declaredLength: _maxBodyBytes + 1,
        ),
        413,
        'payload_too_large',
      );
    default:
      return _Case.accept(
        'body-plain-text-$tag',
        _request(
          origin: _listedOrigin,
          contentType: 'text/plain',
          body: _bodyOf('RAW CMD $tag'),
        ),
        ['RAW CMD $tag'],
        acao: true,
      );
  }
}

/// One generated case for the token phase: the token layer passes on its
/// own (before the policy and before the fetch headers), the byte cap
/// refuses a bloated header before any comparison, and the closed policy
/// refuses a failed guess by its origin.
_Case _tokenCase(Random rng, int index) {
  final tag = 't$index';
  final pick = rng.nextInt(100);
  if (pick < 25) {
    final variant = rng.nextInt(3);
    return switch (variant) {
      0 => _Case.accept(
        'token-correct-$tag',
        _request(
          origin: 'https://tk$index.example',
          token: _t64,
          contentType: 'application/json',
          body: _bodyOf('{"data":["CMD-$tag"]}'),
        ),
        ['CMD-$tag'],
      ),
      1 => _Case.accept(
        'token-correct-originless-$tag',
        _request(
          omitOrigin: true,
          token: _t64,
          contentType: 'application/json',
          body: _bodyOf('["CMD-$tag"]'),
        ),
        ['CMD-$tag'],
      ),
      _ => _Case.accept(
        'token-correct-fetch-junk-$tag',
        _request(
          origin: 'https://tk$index.example',
          token: _t64,
          fetchMode: 'navigate',
          fetchDest: 'document',
          contentType: 'application/json',
          body: _bodyOf('{"data":["CMD-$tag"]}'),
        ),
        ['CMD-$tag'],
      ),
    };
  } else if (pick < 32) {
    return _Case.reject(
      'token-correct-malformed-origin-$tag',
      _request(
        origin: 'https://portal.example@evil.example',
        token: _t64,
        contentType: 'application/json',
        body: _bodyOf('{"data":["CMD"]}'),
      ),
      400,
      'origin_malformed',
    );
  } else if (pick < 72) {
    final n = <int>[64, 1023, 1024][rng.nextInt(3)];
    return _Case.reject(
      'token-wrong-$n-$tag',
      _request(
        origin: 'https://w$index.example',
        token: n == 64 ? 'b' * 64 : 'x' * n,
        contentType: 'application/json',
        body: _bodyOf('{"data":["CMD"]}'),
      ),
      403,
      'origin_not_listed',
    );
  } else if (pick < 82) {
    // محاسبة السلك الموثقة لقيمة الترويسة غير ASCII: البايتات تفكّ latin1
    // عند المحلل ثم يعيد الخادم عدّها utf8 — فكل بايت فوق 127 يتضاعف
    // حسبه — ولهذا يُجاب توكن 'é'*512 (1,024 بايتاً على السلك) بـ
    // token_too_long ولا يعبر الحد. الحد الدقيق 1,024±1 بالبايتات يحمله
    // حالتا ASCII (أعلى وأسفل).
    final atCap = rng.nextBool();
    final token = atCap ? 'é' * 512 : 'x' * _maxTokenBytes;
    return atCap
        ? _Case.reject(
            'token-bytes-nonascii-utf8-512ch-$tag',
            _request(
              origin: 'https://w$index.example',
              token: token,
              contentType: 'application/json',
              body: _bodyOf('{"data":["CMD"]}'),
            ),
            400,
            'token_too_long',
          )
        : _Case.reject(
            'token-bytes-at-cap-ascii-$tag',
            _request(
              origin: 'https://w$index.example',
              token: token,
              contentType: 'application/json',
              body: _bodyOf('{"data":["CMD"]}'),
            ),
            403,
            'origin_not_listed',
          );
  } else if (pick < 95) {
    final multibyte = rng.nextBool();
    final token = multibyte
        ? 'é' * 513
        : 'x' * (_maxTokenBytes + 1 + rng.nextInt(500));
    return _Case.reject(
      'token-overcap-${multibyte ? 'utf8-513ch' : 'ascii'}-$tag',
      _request(
        origin: 'https://w$index.example',
        token: token,
        contentType: 'application/json',
        body: _bodyOf('{"data":["CMD"]}'),
      ),
      400,
      'token_too_long',
    );
  }
  return _Case.reject(
    'token-and-origin-overcap-$tag',
    _request(
      origin: _originOfLength(1100),
      token: 'x' * (_maxTokenBytes + 6),
      contentType: 'application/json',
      body: _bodyOf('{"data":["CMD"]}'),
    ),
    400,
    'origin_too_long',
  );
}

/// Asserts the case's contract on the live reply, plus the two global
/// invariants the batch hangs its name on: never a hang (the 5s cap
/// answers -2) and never a 500/internal.
Future<void> _assertCase(
  _Case c,
  List<List<String>> served, {
  required int servedBefore,
}) async {
  final r = await _exchange(c.bytes);
  expect(
    r['status'],
    isNot(-2),
    reason: '[${c.label}] no hang: the reply must arrive within 5s',
  );
  expect(r['status'], isNot(500), reason: '[${c.label}] never 500');
  final headers = r['headers'] as Map<String, String>;
  expect(
    headers.containsKey('x-correlation-id'),
    isTrue,
    reason: '[${c.label}] every reply carries the correlation id',
  );
  final servedNow = served.length;
  if (c.accepted) {
    expect(r['status'], 200, reason: '[${c.label}] accepted by contract');
    expect(
      bodyText(r),
      '{"ok":true}',
      reason: '[${c.label}] the accepted reply shape',
    );
    expect(
      servedNow,
      servedBefore + 1,
      reason: '[${c.label}] the handler served exactly once',
    );
    expect(
      served.last,
      c.payloads,
      reason: '[${c.label}] the handler received the contract payloads',
    );
    if (c.acao) {
      expect(
        headers['access-control-allow-origin'],
        _listedOrigin,
        reason: '[${c.label}] the listed origin sees the CORS echo on accept',
      );
    }
  } else {
    expect(
      r['status'],
      c.status,
      reason: '[${c.label}] refusal status fixed by contract',
    );
    final json = bodyJson(r.cast<String, Object>());
    expect(json['ok'], false, reason: '[${c.label}] refusal shape');
    expect(
      json['error'],
      c.code,
      reason: '[${c.label}] the stable code fixed by contract',
    );
    expect(
      servedNow,
      servedBefore,
      reason: '[${c.label}] the handler never sees a refused case',
    );
  }
}

void main() {
  for (final seed in _seeds) {
    test('seeded random fuzz over the wire (seed $seed - $_casesPerSeed cases: '
        '$_listedCasesPerSeed origin+body, $_tokenCasesPerSeed token) - every '
        'case is accepted per its contract or refused with its stable code, '
        'never a hang and never 500', () async {
      final rng = Random(seed);
      final served = <List<String>>[];
      void record(List<String> payloads) => served.add(payloads);

      // المرحلة الأولى: سياسة قائمة بمغلق افتراضي وبلا حصة وبلا توكن —
      // كل قرار فيها حتمي بلا حالة تربط الحالات ببعضها.
      final listed = LocalIntakeServer(
        onCommand: (cmd) async {
          record(cmd.payloads);
          return const CommandOutcome(ok: true);
        },
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: () => 'fuzz-$seed',
        protection: IntakeProtection(telemetry: const SilentTelemetry())
          ..update(policy: OriginPolicy(allowed: [_listedOrigin])),
      );
      _activePort = await listed.start(preferredPort: 0);
      addTearDown(listed.stop);
      for (var i = 0; i < _listedCasesPerSeed; i++) {
        final c = _listedCase(rng, i);
        await _assertCase(c, served, servedBefore: served.length);
      }
      await listed.stop();
      final listedServed = served.length;

      // المرحلة الثانية: سياسة فارغة فوقها طبقة التوكن — الصحيح يعبر
      // وحده، والخاطئ تردّه السياسة المغلقة، وكل تخمين بأصل فريد كي لا
      // تتكوين نوافذ قفل تربط الحالات.
      final tokenServer = LocalIntakeServer(
        onCommand: (cmd) async {
          record(cmd.payloads);
          return const CommandOutcome(ok: true);
        },
        telemetry: const SilentTelemetry(),
        correlationIdGenerator: () => 'fuzz-$seed',
        protection: IntakeProtection(telemetry: const SilentTelemetry())
          ..update(policy: const OriginPolicy(), token: _t64),
      );
      _activePort = await tokenServer.start(preferredPort: 0);
      addTearDown(tokenServer.stop);
      for (var i = 0; i < _tokenCasesPerSeed; i++) {
        final c = _tokenCase(rng, i);
        await _assertCase(c, served, servedBefore: served.length);
      }
      expect(
        listedServed,
        greaterThan(0),
        reason:
            'the listed phase served its accept cases through the '
            'handler before the token phase began',
      );
    }, timeout: const Timeout(Duration(minutes: 2)));
  }
}
