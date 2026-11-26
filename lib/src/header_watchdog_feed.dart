// تلقيمة مهلة اكتمال الترويسات: باب القبول لكل نقلٍ لا يمرّ من بوابة
// مصافحة TLS - وغلاف كل مقبس يُسلَّم إلى HttpServer على النقل الآمن بعد
// بوابته. ملكية المقبس هي المقبض الوحيد للقطع: الطلبات الناقصة ترويساتها
// لا تُولّد HttpRequest أصلاً (توثيق dart:io حرفاً: «Incomplete requests,
// in which all or part of the header is missing, are ignored») ولا مهلة
// ترويسات في سطح HttpServer، فالقطع تحت HttpServer حيث المقبس في اليد
// حصراً. الساعة مسلَّحة عند ولادة الغلاف (القبول على الأبواب العادية،
// والتسليم على النقل الآمن الذي تغطيه مهلة المصافحة قبله)، ولا تُعاد
// بالبايتات، وتُلغى عند مُنهي الترويسات؛ وعلى اتصال مُبقى تُسلَّح عند أول
// بايت من الطلب التالي حصراً لا عند انتهاء الرد السابق - فالمُبقى الخامل
// لا ساعة عليه ويبقى تحت مهلة الخمول. والقطع هادئ: تدمير المقبس الداخلي
// يبلغ النظير على السلك بلا بايت ولا رد ولا رمز جديد. وتفريص الطلب
// التالي لا يحتاج إعادة بناء محلل: ماسح أسطر واحد يجمع آخر
// Content-Length وTransfer-Encoding وUpgrade، وكل ما لا يُفهم يُسحب
// (التسريح يوقف التسليح المستقبلي ويُبقي ساعة الطلب الجاري صادقة حتى
// مُنهي ترويساته يُلغيها) - اتجاه السلامة هو تسريحٌ لا قطعٌ كاذب، والأجسام
// المعلنة بالعدد تُعدّ عدداً حصراً فلا بايت جسم يُمسّ ولا يُفحص نمطه
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show Uint8List;

/// The header-completion deadline feed: the plain acceptance door. It
/// wraps a bound [ServerSocket] and delivers every accepted socket wrapped
/// in a [HeaderDeadlineSocket] whose clock runs from the accept - a client
/// that stalls inside its request headers (silent or dripping alike) is
/// cut on the wire at the deadline and cannot hold the open socket past
/// it. `HttpServer.listenOn` consumes exactly [listen], [port],
/// [address], and [close] - the measured narrow surface, the same one the
/// TLS feed proves. Closing the feed stops the accept loop, stops every
/// live deadline clock (the connections themselves belong to the owning
/// server's close), and closes the delivered-socket stream; `HttpServer`
/// close never passes through here, so the owning server closes the feed
/// by its own hand in `stop` and in the orphan path.
class HeaderWatchdogFeed extends Stream<Socket> implements ServerSocket {
  /// Builds the feed over [door]. [deadline] is the header-completion
  /// deadline every delivered connection carries.
  HeaderWatchdogFeed({required ServerSocket door, required Duration deadline})
    : _door = door,
      _deadline = deadline {
    _door.listen(_onAccepted, onError: (Object error) => _out.addError(error));
  }

  final ServerSocket _door;
  final Duration _deadline;
  final StreamController<Socket> _out = StreamController<Socket>();
  final Set<HeaderDeadlineSocket> _live = <HeaderDeadlineSocket>{};
  bool _closed = false;

  // هل استُمع على دفق التسليم قط؟ listenOn لا تشترك إلا حين ينادي
  // المضيف listen على HttpServer، وفشلٌ بين الولادة والاستماع (مسار
  // يونكس مشغول مثلاً) يغلق التلقيمة بلا مستمع قط — وإغلاق متحكم
  // باشتراك واحد لم يُستمع قط لا يكتمل أبداً لأنه ينتظر مستهلكاً لن
  // يأتي، فالإغلاق ينتظر المنفذ حين وُجد وحده حين لم يوجد
  bool _hasListener = false;

  void _onAccepted(Socket socket) {
    if (_closed) {
      // قبول كان في الطريق عند الإغلاق: بلا مستمع بعد الإغلاق
      socket.destroy();
      return;
    }
    late final HeaderDeadlineSocket wrapped;
    wrapped = HeaderDeadlineSocket(
      socket,
      _deadline,
      onDead: () => _live.remove(wrapped),
    );
    _live.add(wrapped);
    _out.add(wrapped);
  }

  @override
  Future<ServerSocket> close() async {
    _closed = true;
    // ساعات الأحياء تُوقف عند إغلاق التلقيمة: المقابس نفسها ملك إغلاق
    // الخادم، والقطع بعد الإغلاق لا معنى له
    for (final wrapped in _live.toList()) {
      wrapped.stopClock();
    }
    _live.clear();
    await _door.close();
    if (_hasListener) {
      await _out.close();
    } else {
      // بلا مستمع قط: الإغلاق يُعلَّم ولا يُنتظر — انتظارُه هنا كان
      // يعلّق البدء الفاشل كله إلى أبد (مقيس في حاوية لينكس)
      unawaited(_out.close());
    }
    return this;
  }

  @override
  StreamSubscription<Socket> listen(
    void Function(Socket event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) {
    _hasListener = true;
    return _out.stream.listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );
  }

  @override
  int get port => _door.port;

  @override
  InternetAddress get address => _door.address;
}

/// A `Socket`-shaped watchdog over a delivered connection: everything
/// passes through to the wrapped socket untouched (reads, writes, options,
/// the closing contract), and one thing is added - the request headers'
/// completion deadline. The clock arms at construction (the accept on the
/// plain transports, the delivery on the TLS transport whose handshake
/// window covers the path before it), is never restarted by arriving
/// bytes, is cancelled the moment the header terminator crosses the wire,
/// and on a kept-alive connection arms again at the first byte of the
/// next request only - a connection that sends nothing after its reply
/// carries no clock and stays under the idle timeout. At the deadline the
/// cut is quiet: the wrapped socket is destroyed, the peer reads the
/// close, and no byte is written - no reply, no wire code. The tracker
/// under the clock reads only what a request line needs: lines end at LF
/// (a superset of CRLF, so every header block the server's own parser
/// terminates, this scan terminates too), the last `Content-Length` and a
/// clean `Transfer-Encoding: chunked` and an `Upgrade` header are
/// remembered, and everything the scan cannot make sense of retires it:
/// retirement stops all future arming on the connection while the clock
/// of the request in flight stays honest until its terminator cancels it
/// - the safe direction is a retired tracker, never a false cut. Bodies
/// are never scanned for shape: a declared length is counted byte-wise,
/// and a chunked declaration serves its cycle then retires the tracker.
class HeaderDeadlineSocket implements Socket {
  HeaderDeadlineSocket(this._inner, this._deadline, {void Function()? onDead})
    : _onDead = onDead {
    _out = StreamController<Uint8List>(
      sync: true,
      onPause: () => _sub.pause(),
      onResume: () => _sub.resume(),
      onCancel: () {
        // المستهلك انصرف: الساعة تُوقف معه لا قطعٌ على مقبس مُهجور
        stopClock();
        _markDead();
        return _sub.cancel();
      },
    );
    // اتصال جديد: الساعة من لحظة الولادة (القبول عادياً، والتسليم آمناً)
    _arm();
    _sub = _inner.listen(
      _onInnerData,
      onError: (Object _) => _onInnerGone(),
      onDone: _onInnerGone,
    );
  }

  final Socket _inner;
  final Duration _deadline;
  final void Function()? _onDead;
  late final StreamController<Uint8List> _out;
  late final StreamSubscription<Uint8List> _sub;
  Timer? _timer;
  bool _dead = false;

  // انتظار أول بايت من الطلب التالي على اتصال مُبقى: لا ساعة قبله
  bool _awaitingFirstByte = false;

  // ── مُفرِّص الترويسات: أسطر الطلب، وعدّ الجسم المعلن، والتسريح ──
  static const int _maxLineBytes = 16384;
  static const int _maxHeaderLines = 256;
  static const int _phaseHeaders = 0;
  static const int _phaseBody = 1;
  static const int _phaseRetired = 2;

  int _phase = _phaseHeaders;
  final List<int> _line = <int>[];
  int _headerLines = 0;
  int? _contentLength;
  bool _chunked = false;
  bool _upgrade = false;
  int _bodyLeft = 0;

  // ── الساعة ──

  void _arm() {
    if (_dead) return;
    _timer ??= Timer(_deadline, _cut);
  }

  /// Stops the deadline clock without touching the connection - the feed's
  /// close and the consumer's departure use it; the socket itself belongs
  /// to the owning server's close.
  void stopClock() {
    _timer?.cancel();
    _timer = null;
  }

  void _cut() {
    _timer = null;
    _markDead();
    // القطع الهادئ: تدمير المقبس الداخلي يبلغ النظير على السلك - لا بايت
    // ولا رد ولا رمز جديد، والإغلاق نفسه هو التقرير
    _inner.destroy();
    if (!_out.isClosed) _out.close();
  }

  void _markDead() {
    if (_dead) return;
    _dead = true;
    _onDead?.call();
  }

  void _onInnerData(Uint8List chunk) {
    if (_dead) return;
    _track(chunk);
    if (!_dead && !_out.isClosed) _out.add(chunk);
  }

  void _onInnerGone() {
    _markDead();
    stopClock();
    if (!_out.isClosed) _out.close();
  }

  // ── التفريص ──

  void _track(Uint8List chunk) {
    var i = 0;
    while (i < chunk.length) {
      if (_awaitingFirstByte) {
        // أول بايت من الطلب التالي على اتصال مُبقى: ساعته من هنا حصراً
        _awaitingFirstByte = false;
        _arm();
      }
      switch (_phase) {
        case _phaseHeaders:
          final b = chunk[i++];
          if (b == 0x0A) {
            // نص السطر يُلتقط قبل التفريغ: التفريغ أولاً يجعل كل سطر
            // يُقرأ فارغاً فلا Content-Length يُسجَّل أبداً
            final empty = _lineIsEmpty();
            final text = empty ? '' : _lineText();
            _line.clear();
            if (empty) {
              _headersComplete();
            } else {
              _headerLines++;
              if (_headerLines > _maxHeaderLines || !_noteHeaderLine(text)) {
                _retire();
              }
            }
          } else {
            _line.add(b);
            if (_line.length > _maxLineBytes) {
              _retire();
            }
          }
        case _phaseBody:
          final take = (chunk.length - i) < _bodyLeft
              ? (chunk.length - i)
              : _bodyLeft;
          _bodyLeft -= take;
          i += take;
          if (_bodyLeft == 0) {
            _cycleEnded();
          }
        case _phaseRetired:
          // مسلَّح تسريحه: السكان للمُنهي وحده - ساعة الطلب الجاري تبقى
          // صادقة حتى يلغيها مُنهي ترويساته، ولا تسليح بعده أبداً
          final b = chunk[i++];
          if (b == 0x0A) {
            final empty = _lineIsEmpty();
            _line.clear();
            if (empty) {
              _timer?.cancel();
              _timer = null;
            }
          } else {
            _line.add(b);
            if (_line.length > _maxLineBytes) {
              _line.clear();
              _timer?.cancel();
              _timer = null;
            }
          }
      }
      if (_phase == _phaseRetired && _timer == null) {
        // ساعة الطلب الجاري حُسمت بعد التسريح: لا شيء يُفحص بعدُ
        return;
      }
    }
  }

  // نص السطر بلا \r الختامية: CRLF يُجرد، وLF المجرد يُقبل نهاية سطر
  // قبولاً أشمل مما يقبل محلل الخادم فلا مُنهي ترويسات يعرفه الخادم
  // ويغفل هذا الماسح
  bool _lineIsEmpty() {
    if (_line.isEmpty) return true;
    return _line.length == 1 && _line[0] == 0x0D;
  }

  String _lineText() {
    var end = _line.length;
    if (end > 0 && _line[end - 1] == 0x0D) {
      end--;
    }
    return latin1.decode(_line.sublist(0, end), allowInvalid: true);
  }

  bool _noteHeaderLine(String line) {
    final lower = line.toLowerCase();
    if (lower.startsWith('content-length:')) {
      final value = int.tryParse(line.substring(15).trim());
      if (value == null || value < 0) {
        return false;
      }
      if (_contentLength != null && _contentLength != value) {
        return false;
      }
      _contentLength = value;
    } else if (lower.startsWith('transfer-encoding:')) {
      if (line.substring(18).trim().toLowerCase() != 'chunked') {
        return false;
      }
      _chunked = true;
    } else if (lower.startsWith('upgrade:')) {
      _upgrade = true;
    }
    return true;
  }

  void _headersComplete() {
    // مُنهي الترويسات: ساعة القبول تنتهي هنا - طور الجسم له حده القائم
    stopClock();
    if (_upgrade) {
      // إطارات القناة ليست طلبات: تسريح دائم - القناة بمهلاتها هي
      _phase = _phaseRetired;
      _awaitingFirstByte = false;
      return;
    }
    if (_chunked) {
      // خدمة الدورة ثم تسريح: الآمن فوق التغطية، وحدها الجسم المعلن
      // بالعدد هو الذي يُعدّ
      _phase = _phaseRetired;
      _awaitingFirstByte = false;
      return;
    }
    final length = _contentLength ?? 0;
    if (length > 0) {
      _bodyLeft = length;
      _phase = _phaseBody;
      return;
    }
    _cycleEnded();
  }

  void _cycleEnded() {
    _phase = _phaseHeaders;
    _headerLines = 0;
    _contentLength = null;
    _chunked = false;
    _upgrade = false;
    _bodyLeft = 0;
    _awaitingFirstByte = true;
  }

  void _retire() {
    _phase = _phaseRetired;
    _awaitingFirstByte = false;
  }

  // ── سطح Socket المُفوَّض: كل شيء يمرّ كما هو، والقطع وحده المضاف ──

  @override
  StreamSubscription<Uint8List> listen(
    void Function(Uint8List event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => _out.stream.listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );

  @override
  void add(List<int> data) => _inner.add(data);

  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      _inner.addError(error, stackTrace);

  @override
  Future<void> addStream(Stream<List<int>> stream) => _inner.addStream(stream);

  @override
  void write(Object? object) => _inner.write(object);

  @override
  void writeAll(Iterable objects, [String separator = '']) =>
      _inner.writeAll(objects, separator);

  @override
  void writeln([Object? object = '']) => _inner.writeln(object);

  @override
  void writeCharCode(int charCode) => _inner.writeCharCode(charCode);

  @override
  Encoding get encoding => _inner.encoding;

  @override
  set encoding(Encoding value) => _inner.encoding = value;

  @override
  Future flush() => _inner.flush();

  @override
  Future close() => _inner.close();

  @override
  Future get done => _inner.done;

  @override
  void destroy() {
    _markDead();
    stopClock();
    _inner.destroy();
    if (!_out.isClosed) _out.close();
  }

  @override
  bool setOption(SocketOption option, bool enabled) =>
      _inner.setOption(option, enabled);

  @override
  Uint8List getRawOption(RawSocketOption option) => _inner.getRawOption(option);

  @override
  void setRawOption(RawSocketOption option) => _inner.setRawOption(option);

  @override
  int get port => _inner.port;

  @override
  int get remotePort => _inner.remotePort;

  @override
  InternetAddress get address => _inner.address;

  @override
  InternetAddress get remoteAddress => _inner.remoteAddress;

  @override
  dynamic noSuchMethod(Invocation invocation) {
    throw UnsupportedError(
      'HeaderDeadlineSocket: ${invocation.memberName} is not implemented',
    );
  }
}
