/// Local host authorities - the one guard over every route.
///
/// Design: authorities are computed by [computeAuthorities] from the port
/// actually bound - never derived from allowedOrigins or startsWith (the
/// `[::1]:port` trap). Rejection is never silent: every deny reaches the
/// host through the protection counter and its log.
library;

/// {127.0.0.1:port, localhost:port, 127.0.0.1, localhost} ∪ extraHosts.
/// The `[::1]` forms join only when [ipv6Loopback] is true - the optional
/// `::1` listener is actually bound then, so those spellings name a live
/// address; with the option off (the default) they stay out and a request
/// naming them is refused exactly as before, because nothing listens there.
Set<String> computeAuthorities(
  int boundPort,
  List<String> extraHosts, {
  bool ipv6Loopback = false,
}) {
  final authorities = <String>{
    '127.0.0.1:$boundPort',
    'localhost:$boundPort',
    '127.0.0.1',
    'localhost',
    if (ipv6Loopback) '[::1]:$boundPort',
    if (ipv6Loopback) '::1',
  };
  for (final extra in extraHosts) {
    final cleaned = extra.trim().toLowerCase();
    if (cleaned.isEmpty) continue;
    authorities.add(cleaned);
    // المتصفح يرسل Host بالمنفذ دائما فالمدخل المجرد لا يطابقه أبدا —
    // كل مدخل بلا منفذ يكتسب صيغة المنفذ الفعلي أيضا (كالمدمجين)،
    // ومدخل يحمل منفذه (أو صيغة IPv6) يبقى كما كتبه صاحبه
    if (!cleaned.contains(':')) {
      authorities.add('$cleaned:$boundPort');
    }
  }
  return authorities;
}

/// The authority check result for a single request.
enum AuthorityVerdict { allow, rejectHost, rejectAbsoluteForm }

/// The single per-request check: the Host header (as Dart reads it, folded
/// to the last value) plus the absolute request line (absolute-form).
AuthorityVerdict checkAuthority({
  required String? hostHeader,
  required bool requestUriIsAbsolute,
  required Set<String> authorities,
}) {
  if (requestUriIsAbsolute) return AuthorityVerdict.rejectAbsoluteForm;
  final host = hostHeader?.trim().toLowerCase();
  if (host == null || host.isEmpty) return AuthorityVerdict.rejectHost;
  if (host.contains('@') || host.contains('/') || host.contains('\\')) {
    return AuthorityVerdict.rejectHost;
  }
  if (authorities.contains(host)) return AuthorityVerdict.allow;
  return AuthorityVerdict.rejectHost;
}
