/// Internal SHA-256 and HMAC-SHA-256 primitives for localhost_bridge.
///
/// Pure `dart:` code with zero dependencies, written to FIPS 180-4
/// (SHA-256, section 6.2) and RFC 2104 (HMAC) as instantiated by
/// RFC 4231 for HMAC-SHA-256. This file is an implementation detail:
/// the package's export gate does not surface it, and later admission
/// work signs bytes against these contracts, so the surface stays
/// minimal - byte lists in, byte lists out.
///
/// Every function treats its arguments as bytes: each list element must
/// be in 0..255. Larger values are truncated to their low 8 bits rather
/// than rejected; callers at this layer pass byte lists by construction.
library;

import 'dart:typed_data';

/// The 64 round constants K[0..63] (FIPS 180-4, section 4.2.2): the
/// first 32 bits of the fractional parts of the cube roots of the
/// first 64 primes, in big-endian word order.
const List<int> _k = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, //
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, //
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, //
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, //
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, //
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, //
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, //
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, //
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The initial hash value H(0) (FIPS 180-4, section 5.3.3): the first
/// 32 bits of the fractional parts of the square roots of the first
/// 8 primes, in big-endian word order.
const List<int> _h0 = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// الحساب على أعداد صحيحة 32 بت بالقناع 0xFFFFFFFF: عدد Dart في الـVM
// سعته 64 بت موقّعة، وعلى الويب (JS) تتعامل البوابات المنطقية مع
// أعداد 32 بت موقّعة فتصبح الكلمات العالية سالبة - فكل عملية يتبعها
// قناع يرجع النمط الثنائي إلى 32 بت غير موقّعة فيظل السلوك واحداً.
// اللازمان الدائري يُبنى من إزاحة >> إشارية يقنَّع ناتجها؛ وإزاحتا
// σ0/σ1 المنطقيتان (3 و10 بت) تستعملان >>> لأن دلالته على JS هي
// أصلًا إزاحة منطقية 32 بت، والقناع يوحد النتيجة على المنصتين.
int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF;

/// Computes the SHA-256 digest of [data] (FIPS 180-4, section 6.2).
///
/// Returns exactly 32 bytes. [data] is read as a byte list (each
/// element 0..255).
List<int> sha256(List<int> data) {
  // التعبئة (القسم 5.1.1): بايت 0x80 ثم أصفار حتى يظل الطول ≡ 56 mod 64،
  // ثم طول البتات بـ8 بايتات كبيرة النهاية. المعادلة (طول + 9 + 63) & ~63
  // تعطي أصغر مضاعف للكتلة يتسع للبايتات الحقيقية + 0x80 + الطول معاً.
  final bitLength = data.length * 8;
  final paddedLength = (data.length + 9 + 63) & ~63;
  final padded = Uint8List(paddedLength);
  for (var i = 0; i < data.length; i++) {
    padded[i] = data[i] & 0xFF;
  }
  padded[data.length] = 0x80;
  // الطول بـ64 بتاً: الكلمة العالية بقسمة صحيحة بدل >>> لأن إزاحة JS
  // تُحسب mod 32 فتصبح >>> 32 بلا أثر؛ والكلمة الدنيا بقناع 32 بت.
  final lowWord = bitLength & 0xFFFFFFFF;
  final highWord = bitLength ~/ 4294967296;
  final lengthOffset = paddedLength - 8;
  padded[lengthOffset] = (highWord >> 24) & 0xFF;
  padded[lengthOffset + 1] = (highWord >> 16) & 0xFF;
  padded[lengthOffset + 2] = (highWord >> 8) & 0xFF;
  padded[lengthOffset + 3] = highWord & 0xFF;
  padded[lengthOffset + 4] = (lowWord >> 24) & 0xFF;
  padded[lengthOffset + 5] = (lowWord >> 16) & 0xFF;
  padded[lengthOffset + 6] = (lowWord >> 8) & 0xFF;
  padded[lengthOffset + 7] = lowWord & 0xFF;

  final h = List<int>.from(_h0);
  final w = List<int>.filled(64, 0);
  for (var block = 0; block < paddedLength; block += 64) {
    // جدول الرسالة: 16 كلمة من الكتلة ثم توسيعها بـ48 كلمة مشتقة (القسم 6.2.2).
    for (var t = 0; t < 16; t++) {
      final o = block + t * 4;
      w[t] =
          ((padded[o] << 24) |
              (padded[o + 1] << 16) |
              (padded[o + 2] << 8) |
              padded[o + 3]) &
          0xFFFFFFFF;
    }
    for (var t = 16; t < 64; t++) {
      final x = w[t - 15];
      final y = w[t - 2];
      final s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ ((x >>> 3) & 0xFFFFFFFF);
      final s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ ((y >>> 10) & 0xFFFFFFFF);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & 0xFFFFFFFF;
    }

    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var t = 0; t < 64; t++) {
      // دوال الضغط (القسم 4.1.2): Ch وMaj والجمع الثلاثي للازاحات الدائرية.
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g);
      final temp1 = (hh + s1 + ch + _k[t] + w[t]) & 0xFFFFFFFF;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (s0 + maj) & 0xFFFFFFFF;
      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xFFFFFFFF;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xFFFFFFFF;
    }
    // إضافة قيمة الكتلة إلى الحالة بينية (القسم 6.2.2، الخطوة الأخيرة).
    h[0] = (h[0] + a) & 0xFFFFFFFF;
    h[1] = (h[1] + b) & 0xFFFFFFFF;
    h[2] = (h[2] + c) & 0xFFFFFFFF;
    h[3] = (h[3] + d) & 0xFFFFFFFF;
    h[4] = (h[4] + e) & 0xFFFFFFFF;
    h[5] = (h[5] + f) & 0xFFFFFFFF;
    h[6] = (h[6] + g) & 0xFFFFFFFF;
    h[7] = (h[7] + hh) & 0xFFFFFFFF;
  }

  // الخلاصة: الكلمات الثماني مرتبة كبيرة النهاية في 32 بايتاً.
  final digest = Uint8List(32);
  for (var i = 0; i < 8; i++) {
    digest[i * 4] = (h[i] >> 24) & 0xFF;
    digest[i * 4 + 1] = (h[i] >> 16) & 0xFF;
    digest[i * 4 + 2] = (h[i] >> 8) & 0xFF;
    digest[i * 4 + 3] = h[i] & 0xFF;
  }
  return digest;
}

/// Computes the HMAC-SHA-256 authentication tag of [message] under
/// [key] (RFC 2104; test framework RFC 4231).
///
/// Returns exactly 32 bytes. Keys longer than the 64-byte SHA-256 block
/// size are first hashed to 32 bytes, exactly as RFC 2104 prescribes.
List<int> hmacSha256(List<int> key, List<int> message) {
  const blockSize = 64;
  // مفتاح أطول من كتلة التقطيع يُخفَّض أولاً - وهذا الفرع تحدّده
  // الحالتان 6 و7 من RFC 4231 بمفتاح 131 بايتة.
  final effective = key.length > blockSize ? sha256(key) : key;
  final k = Uint8List(blockSize);
  for (var i = 0; i < effective.length; i++) {
    k[i] = effective[i] & 0xFF;
  }
  // HMAC = H(K ^ opad || H(K ^ ipad || message))؛ قيم الوسادات 0x36
  // و0x5c هي نص RFC 2104، والتطبيق هنا كتلتان حتميتان لا أكثر.
  final innerInput = Uint8List(blockSize + message.length);
  for (var i = 0; i < blockSize; i++) {
    innerInput[i] = (k[i] ^ 0x36) & 0xFF;
  }
  for (var i = 0; i < message.length; i++) {
    innerInput[blockSize + i] = message[i] & 0xFF;
  }
  final innerDigest = sha256(innerInput);

  final outerInput = Uint8List(blockSize + 32);
  for (var i = 0; i < blockSize; i++) {
    outerInput[i] = (k[i] ^ 0x5c) & 0xFF;
  }
  for (var i = 0; i < 32; i++) {
    outerInput[blockSize + i] = innerDigest[i];
  }
  return sha256(outerInput);
}

/// Renders [bytes] as lowercase hexadecimal, two characters per byte.
String hexEncode(List<int> bytes) {
  const digits = '0123456789abcdef';
  final out = StringBuffer();
  for (final b in bytes) {
    out.write(digits[(b >> 4) & 0xF]);
    out.write(digits[b & 0xF]);
  }
  return out.toString();
}

/// Constant-time comparison of two byte lists - the verdict a signature
/// check reads, so a wrong guess learns nothing from how long the check
/// took. The iteration count is fixed before any byte logic: the longer
/// side's length, never the shorter's and never a shared prefix - a
/// difference at the first byte costs exactly what a difference at the
/// last costs, and a length difference folds into the accumulator like
/// any positional difference. Every byte of both sides is consumed (a
/// supplied side longer than the expected one is still fully read), so
/// equal lists match and nothing else does.
bool fixedTimeEquals(List<int> a, List<int> b) {
  var diff = a.length ^ b.length;
  final pad = a.length > b.length ? a.length : b.length;
  for (var i = 0; i < pad; i++) {
    diff |= (i < a.length ? a[i] : 0) ^ (i < b.length ? b[i] : 0);
  }
  // الأصفار وحدها تعني تطابقا — الطرفان بايتات صغيرة والفرق يبقى عددا
  // صغيرا على المنصتين فلا قناع لازما هنا
  return diff == 0;
}
