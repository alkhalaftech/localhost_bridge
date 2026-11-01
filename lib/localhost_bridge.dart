/// localhost_bridge - the trusted passage from a web page to a local program.
///
/// The only export gate: what is not exported here is not public. Exports
/// stay neutral - no printing code beyond the documented allowlist.
library;

export 'src/arrival_guard.dart';
export 'src/bridge_config.dart';
export 'src/bridge_telemetry.dart';
export 'src/intake_protection.dart';
export 'src/local_intake_server.dart';
export 'src/trusted_command.dart';
