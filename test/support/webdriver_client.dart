// عميل W3C WebDriver واحد على dart:io حصراً: HttpClient يتكلم البروتوكول
// المعياري مباشرة مع عملية المشغّل (safaridriver أو geckodriver أو أي
// مشغّل W3C) بلا أي اعتمادية خارجية. الطرفان المختلفان يخدمان بالواجهة
// نفسها لأن العميل لا يستعمل إلا البوابات المعيارية: /status للجهوز،
// POST /session، POST /url، POST /timeouts، find element، element text،
// وDELETE /session. ما ليس معياراً لا واجهة له هنا: جمع «سجل المتصفح»
// هو قراءة عنصر سجل صفحة المختبر نفسها (pre#lab-results الذي تكتب فيه
// الصفحة علامات LAB-*) — المواصفة لا توحد نقطة نهاية لسجل وحدة
// التحكم، ومسار السجل الواحد الموحد بين المشغّلين هو سجل الصفحة ذاتها.
//
// مصادر الاتفاق: مواصفة W3C WebDriver (التماسات الثمانية أعلاه بأشكالها
// المعيارية حرفاً: مفتاح العنصر element-6066-11e4-a52e-4f735466cecf،
// مغلف الجواب {value: ...}، وأخطاء {value: {error, message}})، وطريقة
// الإطلاق من توثيق كل مشغّل الرسمي: safaridriver --port N وgeckodriver
// --port N يفتحان HTTP على الحلقة، و/قبلها فحص /status حتى ready.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// The W3C capability key every element response carries its id under.
const String _elementKey = 'element-6066-11e4-a52e-4f735466cecf';

/// A WebDriver endpoint answered with an error envelope, or the driver
/// could not be reached at all: the wire truth, not a guess.
final class WebDriverFailure implements Exception {
  /// The W3C error code (`no such element`, `session not created`, ...)
  /// or `driver-unreachable` when the socket itself refused.
  final String error;

  /// The driver's own message, kept verbatim for the test log.
  final String message;

  final int httpStatus;

  const WebDriverFailure(this.error, this.message, this.httpStatus);

  @override
  String toString() => 'WebDriverFailure($error, http=$httpStatus): $message';
}

/// One live W3C session: the id plus the capabilities the driver reported
/// (browser name and version read from here, never guessed).
final class WebDriverSessionInfo {
  final String sessionId;

  /// What the driver reported at creation (`browserName`, `browserVersion`,
  /// and the driver's own extensions) - lowercased keys as they arrived.
  final Map<String, Object?> capabilities;

  const WebDriverSessionInfo(this.sessionId, this.capabilities);

  /// The reported browser version string, or '' when the driver named none.
  String get browserVersion =>
      (capabilities['browserVersion'] as String?) ?? '';

  /// The reported browser name, or '' when the driver named none.
  String get browserName => (capabilities['browserName'] as String?) ?? '';
}

/// The single WebDriver client of the browser labs: one driver process,
/// one HTTP client, sessions created and closed on demand - the identical
/// door for safaridriver and geckodriver.
final class WebDriverClient {
  final Process _process;
  final Uri _base;
  final HttpClient _http;
  final List<String> _driverLines = <String>[];
  String? _sessionId;

  WebDriverClient._(this._process, this._base, this._http);

  /// The driver-reported capabilities of the current session, or null
  /// while no session is open.
  WebDriverSessionInfo? get session => _currentSession;

  WebDriverSessionInfo? _currentSession;

  /// The last driver log lines kept in memory (bounded), so a red scene
  /// names what the driver itself said instead of a bare timeout.
  List<String> get driverLogTail => List.unmodifiable(_driverLines);

  /// Starts the driver process on an ephemeral loopback port and waits
  /// until its /status reports ready. The driver's own log lines ride the
  /// test stdout prefixed WD-DRIVER, and the tail is kept for failures.
  static Future<WebDriverClient> spawn({
    required String executable,
    List<String> extraArgs = const [],
    Duration readyTimeout = const Duration(seconds: 40),
  }) async {
    // منفذ محجوز لحظياً ثم يُحرر: المشغّل يفتحه بعدها مباشرة
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    final Process process;
    try {
      process = await Process.start(executable, <String>[
        '--port',
        '$port',
        ...extraArgs,
      ]);
    } on Object catch (e) {
      throw WebDriverFailure(
        'driver-unreachable',
        'the driver process "$executable" did not start: $e',
        0,
      );
    }
    final client = WebDriverClient._(
      process,
      Uri.parse('http://127.0.0.1:$port'),
      HttpClient(),
    );
    process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(client._recordLine);
    process.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(client._recordLine);
    final deadline = DateTime.now().add(readyTimeout);
    while (true) {
      if (DateTime.now().isAfter(deadline)) {
        await client.shutdown();
        throw WebDriverFailure(
          'driver-unreachable',
          'the driver /status never reported ready within '
              '${readyTimeout.inSeconds}s; driver tail: '
              '${client.driverLogTail.take(8).join(' | ')}',
          0,
        );
      }
      try {
        if (await client._ready()) break;
      } on Object {
        // لم يفتح الباب بعد: لا يهم إلا عند نفاد المهلة
      }
      await Future<void>.delayed(const Duration(milliseconds: 200));
    }
    return client;
  }

  void _recordLine(String line) {
    print('WD-DRIVER: $line');
    _driverLines.add(line);
    if (_driverLines.length > 40) _driverLines.removeAt(0);
  }

  Future<Map<String, Object?>> _send(
    String method,
    String path, {
    Object? body,
    Duration timeout = const Duration(seconds: 30),
  }) async {
    final request = await _http
        .openUrl(method, _base.resolve(path))
        .timeout(timeout);
    request.headers.contentType = ContentType.json;
    if (body != null) {
      request.add(utf8.encode(jsonEncode(body)));
    }
    final response = await request.close().timeout(timeout);
    final text = await utf8.decoder.bind(response).join().timeout(timeout);
    if (response.statusCode < 200 || response.statusCode > 299) {
      var error = 'unknown-error';
      var message = text;
      try {
        final decoded = jsonDecode(text) as Map;
        final value = decoded['value'];
        if (value is Map) {
          error = (value['error'] as String?) ?? error;
          message = (value['message'] as String?) ?? message;
        }
      } on FormatException {
        // جسم غير JSON: النص الخام هو الرسالة
      }
      throw WebDriverFailure(error, message, response.statusCode);
    }
    if (text.trim().isEmpty) return <String, Object?>{};
    final decoded = jsonDecode(text) as Map;
    final value = decoded['value'];
    if (value is Map) {
      return value.cast<String, Object?>();
    }
    return <String, Object?>{'value': value};
  }

  Future<bool> _ready() async {
    final value = await _send('GET', 'status');
    return value['ready'] == true;
  }

  /// Creates a W3C session from an alwaysMatch capability map and stores
  /// it as this client's current session. Session creation is slow on a
  /// real browser's first run, so it waits [timeout] at most.
  Future<WebDriverSessionInfo> newSession(
    Map<String, Object?> alwaysMatch, {
    Duration timeout = const Duration(seconds: 90),
  }) async {
    final value = await _send(
      'POST',
      'session',
      body: <String, Object?>{
        'capabilities': <String, Object?>{'alwaysMatch': alwaysMatch},
      },
      timeout: timeout,
    );
    final id = value['sessionId'];
    if (id is! String || id.isEmpty) {
      throw WebDriverFailure(
        'session not created',
        'the driver returned no session id (value: $value)',
        200,
      );
    }
    _sessionId = id;
    final caps =
        (value['capabilities'] as Map?)?.cast<String, Object?>() ??
        const <String, Object?>{};
    _currentSession = WebDriverSessionInfo(id, caps);
    return _currentSession!;
  }

  /// The standard W3C timeouts for the current session: page loads and
  /// scripts bounded by the lab, no implicit element wait (the lab waits
  /// explicitly and measures itself).
  Future<void> setTimeouts({
    Duration pageLoad = const Duration(seconds: 60),
    Duration script = const Duration(seconds: 60),
  }) async {
    _requireSession();
    await _send(
      'POST',
      'session/$_sessionId/timeouts',
      body: <String, Object?>{
        'pageLoad': pageLoad.inMilliseconds,
        'script': script.inMilliseconds,
        'implicit': 0,
      },
    );
  }

  /// Opens [url] in the current session (POST /session/{id}/url).
  Future<void> navigate(
    String url, {
    Duration timeout = const Duration(seconds: 90),
  }) async {
    _requireSession();
    await _send(
      'POST',
      'session/$_sessionId/url',
      body: <String, Object?>{'url': url},
      timeout: timeout,
    );
  }

  /// Finds the element by CSS selector and returns its id, or null when
  /// the driver answers `no such element`.
  Future<String?> _findElement(String css) async {
    _requireSession();
    try {
      final value = await _send(
        'POST',
        'session/$_sessionId/element',
        body: <String, Object?>{'using': 'css selector', 'value': css},
      );
      final id = value[_elementKey];
      return id is String ? id : null;
    } on WebDriverFailure catch (e) {
      if (e.error == 'no such element') return null;
      rethrow;
    }
  }

  Future<String> _elementText(String elementId) async {
    final value = await _send(
      'GET',
      'session/$_sessionId/element/$elementId/text',
    );
    return (value['value'] as String?) ?? '';
  }

  /// Waits until the element named by [css] exists and its text contains
  /// [untilContains], then returns the element's full text - the browser
  /// log the lab page wrote into its own DOM. Without [untilContains] it
  /// waits for a stable reading (two identical polls past a short floor)
  /// and returns that. The final reading rides out even on failure, so a
  /// red scene names the last log the browser actually wrote.
  Future<String> waitForElementText(
    String css, {
    String? untilContains,
    Duration timeout = const Duration(seconds: 60),
    Duration interval = const Duration(milliseconds: 300),
  }) async {
    _requireSession();
    var lastText = '';
    var stableReads = 0;
    final deadline = DateTime.now().add(timeout);
    var floorPassed = false;
    final floor = DateTime.now().add(const Duration(seconds: 1));
    while (true) {
      if (!floorPassed && DateTime.now().isAfter(floor)) floorPassed = true;
      final id = await _findElement(css);
      if (id != null) {
        final text = await _elementText(id);
        if (untilContains == null) {
          if (floorPassed && text == lastText) {
            stableReads++;
            if (stableReads >= 2) return text;
          } else {
            stableReads = 0;
          }
        } else if (text.contains(untilContains)) {
          return text;
        }
        lastText = text;
      }
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException(
          'the element "$css" never reached the wanted reading within '
          '${timeout.inSeconds}s'
          '${untilContains == null ? '' : ' (wanted: "$untilContains")'}; '
          'last text: ${lastText.length > 600 ? lastText.substring(0, 600) : lastText}',
        );
      }
      await Future<void>.delayed(interval);
    }
  }

  /// Reads the element's text right now, or null when it does not exist
  /// yet - an immediate reading, no waiting.
  Future<String?> readElementTextNow(String css) async {
    final id = await _findElement(css);
    if (id == null) return null;
    return _elementText(id);
  }

  /// Closes the current session (DELETE /session/{id}); safe to call
  /// with none open.
  Future<void> closeSession() async {
    final id = _sessionId;
    if (id == null) return;
    _sessionId = null;
    _currentSession = null;
    try {
      await _send(
        'DELETE',
        'session/$id',
        timeout: const Duration(seconds: 20),
      );
    } on Object {
      // جلسة انتهت من طرف المشغّل: الإغلاق الحالي هدفه النظافة لا الحكم
    }
  }

  /// Ends the session, then the driver process (SIGTERM, then SIGKILL
  /// after a short wait), then the HTTP client.
  Future<void> shutdown() async {
    await closeSession();
    _http.close(force: true);
    _process.kill();
    final exited = _process.exitCode.timeout(
      const Duration(seconds: 5),
      onTimeout: () {
        _process.kill(ProcessSignal.sigkill);
        return _process.exitCode;
      },
    );
    await exited;
  }

  void _requireSession() {
    if (_sessionId == null) {
      throw StateError('no WebDriver session is open on this client');
    }
  }
}
