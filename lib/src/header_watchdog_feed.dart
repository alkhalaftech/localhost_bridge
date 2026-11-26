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

/// The clock and the request-header scanner for one connection - one
/// class shared by both transports: the plain wrapper
/// (HeaderDeadlineSocket) and the TLS adapter. The clock arms at
/// construction (accept on the plain transports, delivery on TLS whose
/// handshake window covers the path before it), is never restarted by
/// arriving bytes, is dropped at the header terminator, and on a
/// kept-alive connection arms again at the first byte of the next
/// request only - a connection that sends nothing after its reply
/// carries no clock and stays under the idle timeout. At the deadline
/// the cut is quiet through [onCut]: the owner destroys its socket and
/// closes its delivered stream - no bytes, no reply, no new wire code.
/// The scanner reads only what a request line needs: lines end at LF (a
/// superset of CRLF, so every header block the server's own parser
/// terminates, this scan terminates too), the last `Content-Length` and
/// a `Transfer-Encoding` that ends in `chunked` and an `Upgrade` header
/// are remembered, and everything the scan cannot make sense of is NOT
/// retired - in every such shape dart:io itself refuses the request and
/// closes the connection (the parser sources are cited at
/// _noteCandidate), so the clock stays honest and the connection stays
/// covered. Bodies are never scanned for shape: a declared length is
/// counted byte-wise, and a chunked body is tracked by the chunked
/// grammar to its cycle end.
// الساعة ومُفرِّص الترويسات معاً لاتصال واحد — صنفٌ واحد يُستعمل في
// المسارين: الغلاف العادي (HeaderDeadlineSocket) والمحوّل الآمن
// (_RawSecureAdapter). الساعة تُسلَّح عند الولادة (القبول عادياً،
// والتسليم آمناً حيث تغطي مهلة المصافحة ما قبلها)، ولا تُعاد بالبايتات،
// وتُنزع عند مُنهي الترويسات، وعلى الاتصال المُبقى تُسلَّح عند أول بايت
// من الطلب التالي حصراً — اتصالٌ لا يرسل شيئاً بعد ردّه بلا ساعة ويبقى
// تحت مهلة الخمول. عند الموعد القطع هادئاً عبر نداء _onCut: المالك
// يدمّر مقبسه ويغلق دفق تسليمه — لا بايت ولا رد ولا رمز جديد.
// المُفرِّص يقرأ ما يحتاجه سطر الطلب وحده: الأسطر تنتهي بـ LF (أشمل من
// CRLF فكل مُنهي يعرفه الخادم يُنهيه هذا الماسح)، وآخر Content-Length
// وTransfer-Encoding المحصور بـ chunked وUpgrade تُحفظ، وما لا يفهمه
// الفاحص لا يُسرَّح — في كل حالة من تلك يرفضه dart:io ويغلق الاتصال
// (برهان مصدر SDK بأرقام الأسطر في تعليق _noteCandidate) فلا اتصال
// يعاد استعماله ليُقطع خطأً. الأجسام لا تُفحص شكلاً: المعلن يُعدّ
// بايتاً بايتاً، والمقطّع يُتتبع بقواعد نهاية دورته حصراً.
class _HeaderTracker {
  _HeaderTracker({required Duration deadline, required void Function() onCut})
    : _deadline = deadline,
      _onCut = onCut {
    // الساعة من لحظة الولادة (القبول عادياً، والتسليم آمناً)
    _arm();
  }

  final Duration _deadline;
  final void Function() _onCut;
  Timer? _timer;
  bool _dead = false;
  bool _armed = false;
  int _deadlineAtUs = 0;

  // انتظار أول بايت من الطلب التالي على اتصال مُبقى: لا ساعة قبله
  bool _awaitingFirstByte = false;

  // ── مُفرِّص الترويسات: أسطر الطلب، وعدّ الجسم المعلن، والتسريح ──
  static const int _maxLineBytes = 16384;
  static const int _phaseHeaders = 0;
  static const int _phaseBody = 1;
  static const int _phaseRetired = 2;
  static const int _phaseChunked = 3;

  int _phase = _phaseHeaders;
  int? _contentLength;
  bool _chunked = false;
  int _bodyLeft = 0;
  // حقائق التأطير المرآة من محلل dart:io: هل Connection يحمل الرمز
  // upgrade (هو وحده معيار الترقية عنده)، وهل مُرّت ترويسة
  // Transfer-Encoding (فالطلب الذي لا تنتهي بترميزه الأخير chunked
  // يرفضه ويغلق)
  bool _connUpgrade = false;
  bool _te = false;
  // قواعد الجسم المقطّع كما يقرؤها dart:io: حجم ست عشري ثم امتداد
  // منقوط بفاصلة منقوطة ثم CRLF ثم البيانات ثم CRLF، إلى قطعة الصفر،
  // ثم ترويسات ختامية، ثم سطر فارغ، فنهاية الدورة
  int _ck = 0;
  int _ckSize = 0;
  bool _ckDigits = false;
  int _ckLeft = 0;
  int _ckLine = 0;

  // ── الساعة ──

  // المؤقت كسول واحد لكل اتصال: التسليح يخزّن موعداً مطلقاً وينشئ
  // المؤقت إن لم يوجد، ومُنهي الترويسات ينزع العلم دون إلغاء (فلا
  // إنشاء وإلغاء لكل طلب على اتصال مُبقى)، وعند انطلاق المؤقت يعيد
  // الجدولة إن بقي من الموعد، فلا قطع مبكر
  static final Stopwatch _mono = Stopwatch()..start();

  void _arm() {
    if (_dead || _armed) return;
    _armed = true;
    _deadlineAtUs = _mono.elapsedMicroseconds + _deadline.inMicroseconds;
    _timer ??= Timer(_deadline, _onTimer);
  }

  // نزع العلم دون إلغاء المؤقت: مُنهي الترويسات وحده يستعمله — المؤقت
  // يبقى معلقاً للاتصال يعاد جدولته عند التسليح التالي
  void _disarm() {
    _armed = false;
  }

  void _onTimer() {
    _timer = null;
    if (_dead || !_armed) return;
    final left = _deadlineAtUs - _mono.elapsedMicroseconds;
    if (left > 0) {
      _timer = Timer(Duration(microseconds: left), _onTimer);
      return;
    }
    _cut();
  }

  /// Stops the deadline clock without touching the connection - the feed's
  /// close and the consumer's departure use it; the socket itself belongs
  /// to the owning server's close.
  void stopClock() {
    _armed = false;
    _timer?.cancel();
    _timer = null;
  }

  void _cut() {
    _timer = null;
    _armed = false;
    _markDead();
    // القطع الهادئ: المالك يدمّر مقبسه الداخلي فيبلغ النظير على السلك
    // - لا بايت ولا رد ولا رمز جديد، والإغلاق نفسه هو التقرير
    _onCut();
  }

  void _markDead() {
    if (_dead) return;
    _dead = true;
  }

  void track(Uint8List chunk) {
    if (_dead) return;
    _track(chunk);
  }

  // انصراف المستهلك أو موت الاتصال من مالكه: الساعة توقف ولا قطع على
  // مقبس مُهجور
  void retire() {
    _markDead();
    stopClock();
  }

  // ── التفريص ──

  // فاحص مقطعي: السطر يُتتبع بطوله وأول بايت فيه، ولا نسخ إلا لسطر
  // مرشّح يبدأ بـ c أو t أو u (أول حرف لأسماء الترويسات الثلاث
  // المتتبعة)، في مخزن بايتات واحد لكل اتصال يتضاعف عند الحاجة، وفك
  // النص لواحدة من الترويسات المطابقة وحدها. بلا قائمة تنمو بايتاً
  // بايتاً وبلا نص لكل سطر — فكل ما يُحسب هو الطول.
  int _lineLen = 0;
  int _lineFirst = -1;
  bool _lineCand = false;
  Uint8List _cand = Uint8List(64);
  int _candLen = 0;

  void _candAdd(Uint8List chunk, int from, int to) {
    final n = to - from;
    if (_candLen + n > _cand.length) {
      var cap = _cand.length * 2;
      while (cap < _candLen + n) {
        cap *= 2;
      }
      final grown = Uint8List(cap);
      grown.setRange(0, _candLen, _cand);
      _cand = grown;
    }
    _cand.setRange(_candLen, _candLen + n, chunk, from);
    _candLen += n;
  }

  void _lineStart(int b) {
    _lineFirst = b;
    final l = b | 0x20;
    _lineCand = l == 0x63 || l == 0x74 || l == 0x75;
    _candLen = 0;
  }

  void _lineReset() {
    _lineLen = 0;
    _lineFirst = -1;
    _lineCand = false;
    _candLen = 0;
  }

  // السطر الفارغ: لا بايتات، أو بايت CR وحده (CRLF مُجرد طرفه)
  bool get _lineEmpty => _lineLen == 0 || (_lineLen == 1 && _lineFirst == 0x0D);

  void _track(Uint8List chunk) {
    var i = 0;
    final n = chunk.length;
    while (i < n) {
      if (_awaitingFirstByte) {
        _awaitingFirstByte = false;
        _arm();
      }
      switch (_phase) {
        case _phaseHeaders:
          // بحث LF بالمقطع لا بايتاً بايتاً: [i, j) امتداد السطر الجاري
          var j = i;
          while (j < n && chunk[j] != 0x0A) {
            j++;
          }
          if (j > i) {
            if (_lineLen == 0) _lineStart(chunk[i]);
            if (_lineCand) {
              if (_candLen + (j - i) <= _maxLineBytes) {
                _candAdd(chunk, i, j);
              } else {
                // سطر تأطير أطول من السقف: لا يُفهم فلا يُسرَّح والساعة
                // باقية — والعقدة المغلقة من dart:io نفسه: ما لم يُفهم
                // هنا يرفضه ويغلق الاتصال فلا اتصال يعاد استعماله ليُقطع
                // خطأً (البرهان بمصدر SDK في تعليق _noteCandidate)
                _lineCand = false;
                _candLen = 0;
              }
            }
            _lineLen += j - i;
            if (_lineLen > (1 << 30)) _lineLen = 1 << 30;
          }
          if (j == n) {
            i = n;
            break;
          }
          i = j + 1; // الـLF
          if (_lineEmpty) {
            _lineReset();
            _headersComplete();
          } else {
            // القيمة التي لا يفهمها الفاحص لا تُسرّح — البرهان في
            // تعليق _noteCandidate
            if (_lineCand) _noteCandidate();
            _lineReset();
          }
        case _phaseBody:
          final take = (n - i) < _bodyLeft ? (n - i) : _bodyLeft;
          _bodyLeft -= take;
          i += take;
          if (_bodyLeft == 0) {
            _cycleEnded();
          }
        case _phaseChunked:
          i = _trackChunked(chunk, i, n);
        case _phaseRetired:
          // مسلَّح تسريحه (ترقية dart:io وحدها تُسرّح الآن): السكان
          // للمُنهي وحده، والسطر يُتتبع بالطول لا بالقائمة
          var j = i;
          while (j < n && chunk[j] != 0x0A) {
            j++;
          }
          final room = _maxLineBytes - _lineLen;
          if (j > i && j - i > room) {
            _lineReset();
            _disarm();
            i = i + room + 1;
          } else {
            if (j > i) {
              if (_lineLen == 0) _lineFirst = chunk[i];
              _lineLen += j - i;
            }
            if (j == n) {
              i = n;
              break;
            }
            i = j + 1;
            final empty = _lineEmpty;
            _lineReset();
            if (empty) {
              _disarm();
            }
          }
      }
      if (_phase == _phaseRetired && !_armed) {
        // ساعة الطلب الجاري حُسمت بعد التسريح: لا شيء يُفحص بعدُ
        return;
      }
    }
  }

  // قواعد الجسم المقطّع كما يقرؤها dart:io: حجم ست عشري (أرقام و
  // a-f بأي حالة) ثم امتداد منقوط بفاصلة منقوطة ثم CRLF ثم البيانات
  // ثم CRLF، وهكذا إلى قطعة حجمها صفر، ثم ترويسات ختامية، ثم سطر
  // فارغ، فنهاية الدورة. وبايت خارج القواعد يجعل dart:io يفشل الطلب
  // ويغلق الاتصال، فيعود الفاحص إلى طور الترويسات مغلقاً — ولا
  // تسريح
  int _trackChunked(Uint8List chunk, int i, int n) {
    while (i < n && _phase == _phaseChunked) {
      final b = chunk[i];
      switch (_ck) {
        case 0:
          i++;
          final h = b | 0x20;
          if (b >= 0x30 && b <= 0x39) {
            _ckSize = _ckSize * 16 + (b - 0x30);
            _ckDigits = true;
          } else if (h >= 0x61 && h <= 0x66) {
            _ckSize = _ckSize * 16 + (h - 0x61 + 10);
            _ckDigits = true;
          } else if (b == 0x3B) {
            _ck = 1;
          } else if (b == 0x0D) {
            // CR قبل LF: لا حال
          } else if (b == 0x0A && _ckDigits) {
            _ckEndSize();
          } else {
            _cycleEnded();
          }
          if (_ckSize > 0x7FFFFFFF) _cycleEnded();
        case 1:
          i++;
          if (b == 0x0A) _ckEndSize();
        case 2:
          final take = (n - i) < _ckLeft ? (n - i) : _ckLeft;
          _ckLeft -= take;
          i += take;
          if (_ckLeft == 0) _ck = 3;
        case 3:
          i++;
          if (b == 0x0A) {
            _ck = 0;
            _ckSize = 0;
            _ckDigits = false;
          } else if (b != 0x0D) {
            _cycleEnded();
          }
        case 4:
          i++;
          if (b == 0x0A) {
            if (_ckLine == 0) {
              _cycleEnded();
            } else {
              _ckLine = 0;
            }
          } else if (b != 0x0D || _ckLine > 0) {
            _ckLine++;
          }
      }
    }
    return i;
  }

  void _ckEndSize() {
    if (_ckSize == 0) {
      _ck = 4;
      _ckLine = 0;
    } else {
      _ck = 2;
      _ckLeft = _ckSize;
    }
  }

  // مطابقة اسم الترويسة على البايتات بأي حالة، بلا نص
  bool _candStarts(List<int> name) {
    if (_candLen < name.length) return false;
    for (var k = 0; k < name.length; k++) {
      var b = _cand[k];
      if (b >= 0x41 && b <= 0x5A) b += 0x20;
      if (b != name[k]) return false;
    }
    return true;
  }

  // قيمة الترويسة المطابقة وحدها تُفك نصاً، بلا CR الختامية
  String _candValue(int from) {
    var end = _candLen;
    if (end > 0 && _cand[end - 1] == 0x0D) end--;
    return latin1.decode(
      Uint8List.sublistView(_cand, from, end),
      allowInvalid: true,
    );
  }

  // القرارات الثلاثة نفسها التي كانت _noteHeaderLine تأخذها، على
  // البايتات — والرابعة (Connection) لأجل معيار ترقية dart:io.
  // **وعائدها لا يُسرّح شيئاً:** كل حالة لا يفهمها الفاحص هنا هي
  // حالة يرفضها dart:io ويغلق الاتصال، فلا اتصال يعاد استعماله
  // ليُقطع خطأً (برهان مصدر SDK بإصدارات CI الثلاثة):
  // • تكرار Content-Length يرمي — 3.8.0: http_parser.dart:729-735 ·
  //   3.13.0/stable: :771-779
  // • القيمة غير الرقمية ترمي — http_headers.dart: 3.8.0:386-388 ·
  //   3.13.0/stable: :379-395
  // • Transfer-Encoding لا ينتهي بـ chunked في طلب يرمي —
  //   3.13.0/stable: http_parser.dart:407-415؛ وفي 3.8.0 يبقى الطلب
  //   بلا تأطير (القيمة تُقارن كاملة لا بآخر رمز: :740-743) فيقرؤه
  //   بلا جسم فيفشل في بايتاته التالية ويغلق
  // • الاسم الذي فيه مسافة لا يطابق "content-length" عند dart:io —
  //   فطلب يحتاج جسماً يرمي "no ContentLength"
  //   (http_headers.dart: 3.8.0:147 · 3.13.0/stable: :145)
  // فبقاء الساعة على غير المفهوم آمن، والقطع لا يصيب طلباً سليماً
  void _noteCandidate() {
    if (_candStarts(_nCl)) {
      final value = int.tryParse(_candValue(15).trim());
      if (value == null || value < 0) return;
      if (_contentLength != null && _contentLength != value) return;
      _contentLength = value;
    } else if (_candStarts(_nTe)) {
      _te = true;
      final tokens = _candValue(18).split(',');
      _chunked = tokens.last.trim().toLowerCase() == 'chunked';
    } else if (_candStarts(_nCo)) {
      for (final t in _candValue(11).split(',')) {
        if (t.trim().toLowerCase() == 'upgrade') _connUpgrade = true;
      }
    }
  }

  static const List<int> _nCl = [
    99,
    111,
    110,
    116,
    101,
    110,
    116,
    45,
    108,
    101,
    110,
    103,
    116,
    104,
    58,
  ];
  static const List<int> _nTe = [
    116,
    114,
    97,
    110,
    115,
    102,
    101,
    114,
    45,
    101,
    110,
    99,
    111,
    100,
    105,
    110,
    103,
    58,
  ];
  static const List<int> _nCo = [
    99,
    111,
    110,
    110,
    101,
    99,
    116,
    105,
    111,
    110,
    58,
  ];

  void _headersComplete() {
    // مُنهي الترويسات: ساعة القبول تنتهي هنا بنزع العلم دون إلغاء،
    // وطور الجسم له حده القائم
    _disarm();
    if (_connUpgrade) {
      // ترقية dart:io وحدها تُسرّح: Connection يحمل الرمز upgrade
      // (3.8.0: http_parser.dart:752-759 · 3.13.0/stable: :801-808) —
      // عندها يُفصل المقبس إلى القناة بمهلاتها أو يُدمَّر بعد الرد،
      // فلا اتصال HTTP يعاد استعماله ليظل بلا حاكم
      _phase = _phaseRetired;
      _awaitingFirstByte = false;
      return;
    }
    if (_te && !_chunked) {
      // TE لا ينتهي بـ chunked في طلب: dart:io يرفضه ويغلق (برهان
      // _noteCandidate) — البقاء مغلقاً لا تسريح
      _cycleEnded();
      return;
    }
    if (_chunked) {
      // الجسم المقطّع يُتتبع بقواعده إلى نهاية الدورة فلا تسريح،
      // وحدها الجسم المعلن بالعدد هو الذي يُعدّ
      _phase = _phaseChunked;
      _ck = 0;
      _ckSize = 0;
      _ckDigits = false;
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
    _contentLength = null;
    _chunked = false;
    _bodyLeft = 0;
    _connUpgrade = false;
    _te = false;
    _awaitingFirstByte = true;
  }
}

/// The plain-transport wrapper: everything passes through to the wrapped
/// socket untouched (reads, writes, options, the closing contract), and
/// one thing is added - the request headers' completion deadline, carried
/// by the shared [HeaderTracker]. The cut is quiet through the tracker's
/// onCut: this wrapper destroys the inner socket and closes its delivered
/// stream - no bytes, no reply, no new wire code. The TLS transport
/// carries the same tracker inside its adapter instead of a wrapper, so
/// the delivered object stays a `SecureSocket`.
// غلاف `Socket` على الأبواب العادية: كل شيء يمرّ للمقبس الداخلي كما هو
// (القراءة والكتابة وعقد الإغلاق)، والحارس وحده المضاف — ساعة ومُفرِّص
// من `_HeaderTracker` الصنف المشترك مع محوّل TLS. القطع: المالك يدمّر
// المقبس الداخلي ويغلق دفق تسليمه، فيبلغ النظير على السلك بلا بايت
// ولا رد ولا رمز جديد.
class HeaderDeadlineSocket implements Socket {
  HeaderDeadlineSocket(this._inner, this._deadline, {void Function()? onDead})
    : _onDead = onDead {
    _out = StreamController<Uint8List>(
      sync: true,
      onPause: () => _sub.pause(),
      onResume: () => _sub.resume(),
      onCancel: () {
        // المستهلك انصرف: الساعة تُوقف معه لا قطعٌ على مقبس مُهجور
        _scanner.retire();
        return _sub.cancel();
      },
    );
    _scanner = _HeaderTracker(
      deadline: _deadline,
      onCut: () {
        // القطع الهادئ: تدمير المقبس الداخلي يبلغ النظير على السلك - لا
        // بايت ولا رد ولا رمز جديد، والإغلاق نفسه هو التقرير
        _inner.destroy();
        if (!_out.isClosed) _out.close();
        _markDead();
      },
    );
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
  late _HeaderTracker _scanner;
  bool _dead = false;

  void _markDead() {
    if (_dead) return;
    _dead = true;
    _onDead?.call();
  }

  void _onInnerData(Uint8List chunk) {
    if (_dead) return;
    _scanner.track(chunk);
    if (!_dead && !_out.isClosed) _out.add(chunk);
  }

  void _onInnerGone() {
    _markDead();
    _scanner.retire();
    if (!_out.isClosed) _out.close();
  }

  /// Stops the deadline clock without touching the connection - the feed's
  /// close and the consumer's departure use it; the socket itself belongs
  /// to the owning server's close.
  void stopClock() {
    _scanner.stopClock();
  }

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
    // أعضاء Stream الأخرى غير المُمرَّرة تُرفض مسمّاة كما في سلف الغلاف
    // - الاتصال المُسلَّم عبر هذا الغلاف يُستهلك من HttpServer فحسب
    throw UnsupportedError(
      'HeaderDeadlineSocket: ${invocation.memberName} is not implemented',
    );
  }

  @override
  void destroy() {
    _markDead();
    _scanner.retire();
    _inner.destroy();
    if (!_out.isClosed) _out.close();
  }
}
