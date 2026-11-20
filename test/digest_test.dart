// Official-vector witnesses for the internal digest primitives.
//
// SHA-256 is pinned to the FIPS "SHA-256 Examples" appendix: FIPS
// 180-2 Appendix B (sections B.1 one-block, B.2 multi-block, B.3
// long message of one million 'a'), the same examples NIST's CSRC
// page for SHA-256 example messages reproduces. FIPS 180-4's own
// Appendix B is References and points to that page, so the examples
// appendix of 180-2 is the printed source of record. The
// empty-message digest is not printed in either standard's appendix
// nor in the NIST example PDFs; it was verified live against two
// independent reference implementations (OpenSSL and Python's
// hashlib), and RFC 6234 section 8.5 carries the other three vectors
// as a cross-check.
//
// HMAC-SHA-256 is pinned to RFC 4231 Test Cases 1-7 (sections
// 4.2-4.8, the HMAC-SHA-256 line of each case). Case 5 is published
// truncated to 128 bits, so exactly the first 16 bytes are compared,
// as the RFC prints them. Cases 6 and 7 use a 131-byte key, which
// exercises the hash-the-key branch of RFC 2104.
import 'dart:convert';

import 'package:test/test.dart';
import 'package:localhost_bridge/src/digest.dart';

void main() {
  // الأنصبة الرسمية أدناه تثبت sha256 وhmacSha256 حرفا؛ وما يلي شاهود
  // المقارنة الزمن-الثابتة التي يتحقق بها توقيع الاقتران (عقد ج3: تُضاف
  // هنا باختبارها) — صواب المنطق في كل مواضع الاختلاف وأطوال الأطراف،
  // وزمن التنفيذ ثابت بالبناء فلا يتسرب موضع أول اختلاف ولا طول أي طرف
  group('fixedTimeEquals (the proof-verification comparison)', () {
    test('equal byte lists match at every length the wire can carry', () {
      expect(fixedTimeEquals(const <int>[], const <int>[]), isTrue);
      expect(
        fixedTimeEquals(const <int>[1, 2, 3], const <int>[1, 2, 3]),
        isTrue,
      );
      expect(
        fixedTimeEquals(List<int>.filled(32, 0xAB), List<int>.filled(32, 0xAB)),
        isTrue,
      );
      expect(
        fixedTimeEquals(List<int>.filled(64, 7), List<int>.filled(64, 7)),
        isTrue,
      );
    });

    test('a difference at any position fails - first, middle, and last', () {
      for (final position in const [0, 15, 31]) {
        final b = List<int>.filled(32, 0x11);
        b[position] = 0x12;
        expect(
          fixedTimeEquals(List<int>.filled(32, 0x11), b),
          isFalse,
          reason: 'position $position must fail',
        );
      }
    });

    test('length differences fail in both directions', () {
      final a = List<int>.filled(32, 5);
      expect(fixedTimeEquals(a, List<int>.filled(31, 5)), isFalse);
      expect(fixedTimeEquals(List<int>.filled(31, 5), a), isFalse);
      expect(fixedTimeEquals(a, List<int>.filled(33, 5)), isFalse);
      expect(fixedTimeEquals(List<int>.filled(33, 5), a), isFalse);
      expect(fixedTimeEquals(const <int>[], const <int>[1]), isFalse);
    });
  });

  group('SHA-256 official vectors (FIPS 180-2 Appendix B)', () {
    test('empty message digest matches the reference digest', () {
      final digest = sha256(const <int>[]);
      expect(
        hexEncode(digest),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        reason: 'the zero-length message - the padding-only block',
      );
      expect(digest.length, 32, reason: 'SHA-256 output is 256 bits');
    });

    test("'abc' matches the one-block example of FIPS 180-2 B.1", () {
      expect(
        hexEncode(sha256(utf8.encode('abc'))),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        reason: 'the 24-bit ASCII "abc" message, one padded block',
      );
    });

    test('the two-block 448-bit message matches FIPS 180-2 B.2', () {
      expect(
        hexEncode(
          sha256(
            utf8.encode(
              'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
            ),
          ),
        ),
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
        reason: 'the 448-bit message - the exact block-boundary padding case',
      );
    });

    test("one million 'a' characters match the long-message example of "
        'FIPS 180-2 B.3', () {
      expect(
        hexEncode(sha256(List<int>.filled(1000000, 0x61))),
        'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
        reason: '1,000,000 repetitions of the character a - 15,625 blocks',
      );
    });
  });

  group('HMAC-SHA-256 official vectors (RFC 4231 cases 1-7)', () {
    test('case 1 (RFC 4231 4.2): 20-byte key of 0x0b, data "Hi There"', () {
      final tag = hmacSha256(
        List<int>.filled(20, 0x0b),
        utf8.encode('Hi There'),
      );
      expect(
        hexEncode(tag),
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
        reason: 'key and data shorter than the block size',
      );
    });

    test('case 2 (RFC 4231 4.3): key "Jefe", data "what do ya want for '
        'nothing?"', () {
      expect(
        hexEncode(
          hmacSha256(
            utf8.encode('Jefe'),
            utf8.encode('what do ya want for nothing?'),
          ),
        ),
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
        reason: 'key shorter than the HMAC output length',
      );
    });

    test('case 3 (RFC 4231 4.4): 20-byte 0xaa key, 50 bytes of 0xdd', () {
      expect(
        hexEncode(
          hmacSha256(List<int>.filled(20, 0xaa), List<int>.filled(50, 0xdd)),
        ),
        '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
        reason: 'combined key and data length above the 64-byte block',
      );
    });

    test('case 4 (RFC 4231 4.5): 25-byte increasing key, 50 bytes of 0xdd', () {
      expect(
        hexEncode(
          hmacSha256(
            List<int>.generate(25, (i) => i + 1),
            List<int>.filled(50, 0xcd),
          ),
        ),
        '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
        reason: 'key between the block size and the output length',
      );
    });

    test('case 5 (RFC 4231 4.6): 20-byte 0x0c key, "Test With Truncation" - '
        'the RFC publishes only the 128-bit truncated tag', () {
      final tag = hmacSha256(
        List<int>.filled(20, 0x0c),
        utf8.encode('Test With Truncation'),
      );
      expect(
        hexEncode(tag.sublist(0, 16)),
        'a3b6167473100ee06e0c796c2955552b',
        reason: 'the RFC prints this case truncated to 128 bits',
      );
    });

    test(
      'case 6 (RFC 4231 4.7): 131-byte 0xaa key hashes to 32 bytes first',
      () {
        expect(
          hexEncode(
            hmacSha256(
              List<int>.filled(131, 0xaa),
              utf8.encode(
                'Test Using Larger Than Block-Size Key - Hash Key '
                'First',
              ),
            ),
          ),
          '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
          reason: 'key above the 64-byte block size - the hash-the-key branch',
        );
      },
    );

    test('case 7 (RFC 4231 4.8): 131-byte 0xaa key with a longer-than-block '
        'message', () {
      expect(
        hexEncode(
          hmacSha256(
            List<int>.filled(131, 0xaa),
            utf8.encode(
              'This is a test using a larger than block-size key '
              'and a larger than block-size data. The key needs to be '
              'hashed before being used by the HMAC algorithm.',
            ),
          ),
        ),
        '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
        reason: 'key and message both larger than the block size',
      );
    });
  });
}
