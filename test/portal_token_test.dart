// Witness of the recommended token path: generatePortalToken() is the
// documented way to set up the token, so its shape and uniqueness are
// pinned here against the two gates the suite enforces elsewhere - the
// minimum update() accepts and the token_too_long header cap.
import 'dart:convert';

import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

void main() {
  test(
    'generatePortalToken matches its documented shape: 64 hex characters',
    () {
      final token = generatePortalToken();
      expect(token.length, 64, reason: '32 random bytes rendered in hex');
      expect(
        RegExp(r'^[0-9a-f]{64}$').hasMatch(token),
        isTrue,
        reason: 'lowercase hex only - the shape the token layer accepts',
      );
      expect(
        token.length,
        greaterThanOrEqualTo(32),
        reason: 'passes the minimum token length update() enforces',
      );
      expect(
        utf8.encode(token).length,
        lessThanOrEqualTo(1024),
        reason: 'fits under the token_too_long header byte cap',
      );
    },
  );

  test('one thousand generated tokens are pairwise distinct', () {
    final tokens = <String>{
      for (var i = 0; i < 1000; i++) generatePortalToken(),
    };
    expect(
      tokens.length,
      1000,
      reason: 'the secure generator must never repeat a minted secret',
    );
  });
}
