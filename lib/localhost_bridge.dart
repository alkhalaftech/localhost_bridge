/// localhost_bridge - the trusted passage from a web page to a local program.
///
/// The only export gate: what is not exported here is not public. Exports
/// stay neutral - no domain code beyond the documented allowlist.
library;

export 'src/arrival_guard.dart';
export 'src/bridge_config.dart';
export 'src/bridge_presets.dart';
export 'src/bridge_telemetry.dart';
// ساعة الدفتر الافتراضية مساعدٌ داخلي (بند شهود قفزة الساعة حصراً) —
// تخفى عن السطح العام وتبقى تظهر لمن يستورد الملف المصدر مباشرة
export 'src/command_dedup.dart' hide dedupMonotonicClock;
export 'src/intake_protection.dart';
export 'src/intake_rejections.dart';
export 'src/local_intake_server.dart';
export 'src/trusted_command.dart';
