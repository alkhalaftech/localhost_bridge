// Witness of the settled allowlist port semantics - documentation made
// testable, no behavior change. The four entry forms gate differently and
// this is the contract: a full origin entry matches the exact origin
// string (scheme, host, and port exactly as written - a portless entry
// matches only the portless form, which is what browsers send for
// default ports); a bare-host entry matches the host name on any port;
// a *.domain entry matches its subdomains on any port. The page's port
// is chosen by whoever serves the page, so the bare and wildcard forms
// gate on the domain while the full form pins the origin.
import 'package:test/test.dart';
import 'package:localhost_bridge/localhost_bridge.dart';

IntakeProtection _policy() => IntakeProtection()
  ..update(
    policy: OriginPolicy(
      allowed: [
        'https://portal.example',
        'https://literal.example:8443',
        '*.sub.example',
        'bare.example',
      ],
    ),
  );

void main() {
  test(
    'a full origin entry without a port matches only the portless form',
    () async {
      final p = _policy();
      final portless = await p.admit(origin: 'https://portal.example');
      expect(portless.rejection, isNull);
      expect(portless.acceptedPath, IntakeAdmissionPath.listed);
      final ported = await p.admit(origin: 'https://portal.example:9443');
      expect(
        ported.rejection?.code,
        'origin_not_listed',
        reason:
            'the portless entry pins the exact origin - a page on a '
            'non-default port needs its own entry carrying that port',
      );
    },
  );

  test('a full origin entry with a port matches that port exactly', () async {
    final p = _policy();
    final exact = await p.admit(origin: 'https://literal.example:8443');
    expect(exact.rejection, isNull);
    expect(exact.acceptedPath, IntakeAdmissionPath.listed);
    final portless = await p.admit(origin: 'https://literal.example');
    expect(
      portless.rejection?.code,
      'origin_not_listed',
      reason: 'the ported entry never matches the portless form',
    );
    final otherPort = await p.admit(origin: 'https://literal.example:9443');
    expect(
      otherPort.rejection?.code,
      'origin_not_listed',
      reason: 'the ported entry never matches a different port',
    );
  });

  test('a bare-host entry admits the host on any port', () async {
    final p = _policy();
    final ported = await p.admit(origin: 'https://bare.example:60001');
    expect(
      ported.rejection,
      isNull,
      reason:
          'the bare entry gates on the domain - the page port is the '
          'serving party choice',
    );
    expect(ported.acceptedPath, IntakeAdmissionPath.listed);
  });

  test('a wildcard entry admits its subdomains on any port', () async {
    final p = _policy();
    final ported = await p.admit(origin: 'https://evil.sub.example:7777');
    expect(
      ported.rejection,
      isNull,
      reason: 'the wildcard gates on the domain, never on the port',
    );
    expect(ported.acceptedPath, IntakeAdmissionPath.listed);
    // والجذر لا يمر بالنمطي: النمطي للفروع حصراً والجذر يُدرج صريحاً
    final root = await p.admit(origin: 'https://sub.example:7777');
    expect(root.rejection?.code, 'origin_not_listed');
  });

  test(
    'every form keeps the scheme rule: http never passes outside local',
    () async {
      final p = _policy();
      final bareHttp = await p.admit(origin: 'http://bare.example:60001');
      expect(
        bareHttp.rejection?.code,
        'origin_not_listed',
        reason:
            'bare and wildcard entries admit https only - the port '
            'rule never widens the scheme rule',
      );
      final wildcardHttp = await p.admit(
        origin: 'http://evil.sub.example:7777',
      );
      expect(wildcardHttp.rejection?.code, 'origin_not_listed');
    },
  );
}
