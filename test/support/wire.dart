// أدوات اختبار السلك الخام: فك ترميز المقاطع (chunked) وقراءة أجسام
// JSON من ردود المقابس الخام — الردود المكتوبة بلا content-length تصل
// مقطعة فيفشل jsonDecode على الترقيم لا على المحتوى.
import 'dart:convert';

/// Decodes chunks when the body is chunked and returns it clean - when it is
/// not valid chunk framing, the body is returned as received.
String dechunk(String raw) {
  var rest = raw;
  final out = StringBuffer();
  while (true) {
    final lineEnd = rest.indexOf('\r\n');
    if (lineEnd < 0) {
      out.write(rest);
      return out.toString();
    }
    final sizeToken = rest.substring(0, lineEnd).split(';').first.trim();
    final size = int.tryParse(sizeToken, radix: 16);
    // الحجم السالب قيمة معطوبة (العلامة مقبولة لدى tryParse) — أعد الخام
    if (size == null || size < 0) return raw;
    if (size == 0) return out.toString();
    final start = lineEnd + 2;
    final end = start + size;
    if (end + 2 > rest.length) {
      // مقطع ناقص (وصل جزئيا): أعِد ما وصل منه فقط
      if (start < rest.length) out.write(rest.substring(start));
      return out.toString();
    }
    // مقاس المقطع بايتات والسلسلة محارف: محرف متعدد البايتات يجعل
    // «end» يتخطى الحد الفاصل فيبتلع المنهي ويفشل السطر التالي —
    // التحقق من الحد يكتشف الانزياح والحد الفاصل الفعلي يصححه
    var chunkEnd = end;
    if (rest.substring(end, end + 2) != '\r\n') {
      final boundary = rest.indexOf('\r\n', start);
      if (boundary < 0) return raw;
      chunkEnd = boundary;
    }
    out.write(rest.substring(start, chunkEnd));
    rest = rest.substring(chunkEnd + 2);
  }
}

/// The body text after chunk decoding - chunking is detected from the header
/// or from the chunk terminator (the final zero-length chunk); some test readers return no headers.
String bodyText(Map<String, Object> response) {
  final raw = response['body'] as String;
  final headers = response['headers'];
  final declared =
      headers is Map<String, String> &&
      (headers['transfer-encoding'] ?? '').toLowerCase().contains('chunked');
  return declared || raw.endsWith('0\r\n\r\n') ? dechunk(raw) : raw;
}

/// The body decoded from JSON - the unified error shape {'ok','error','message'}.
Map<String, Object?> bodyJson(Map<String, Object> response) =>
    (jsonDecode(bodyText(response)) as Map).cast<String, Object?>();
