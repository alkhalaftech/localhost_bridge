// صحة سلطات المضيف المحلية: القيم المدمجة تحمل الصيغتين (بمنفذ وبلا
// منفذ)، والمدخل الإضافي للمضيف يجب أن يحمل صيغة المنفذ الفعلي أيضا —
// المتصفح يرسل Host بالمنفذ دائما فالمدخل المجرد لا يطابقه أبدا.
import 'package:test/test.dart';
import 'package:localhost_bridge/src/intake_invariants.dart';

void main() {
  test('built-in loopback authorities carry both forms', () {
    final a = computeAuthorities(9200, const []);
    expect(a.contains('127.0.0.1:9200'), isTrue);
    expect(a.contains('localhost:9200'), isTrue);
    expect(a.contains('127.0.0.1'), isTrue);
    expect(a.contains('localhost'), isTrue);
  });

  test('an extra host matches the bound port authority a browser sends', () {
    final a = computeAuthorities(9200, const ['portal.internal']);
    expect(
      a.contains('portal.internal:9200'),
      isTrue,
      reason:
          'browsers send Host: name:port — the bare entry never matches '
          'them',
    );
    expect(
      a.contains('portal.internal'),
      isTrue,
      reason: 'port-less local clients keep the bare form',
    );
  });

  test('an extra host with its own port is not double-suffixed', () {
    final a = computeAuthorities(9200, const ['alias.example:8443']);
    expect(a.contains('alias.example:8443'), isTrue);
    expect(a.contains('alias.example:8443:9200'), isFalse);
  });

  test('blank extra hosts are dropped', () {
    final a = computeAuthorities(9200, const ['  ', '']);
    expect(a.length, 4, reason: 'only the four built-in authorities remain');
  });
}
