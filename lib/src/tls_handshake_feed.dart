// تلقيمة مصافحة TLS: باب النقل الآمن للجسر. القبول ينزل إلى
// RawServerSocket فتصل التلقيمة مقابس RawSocket — وهذا هو المقبض الذي
// يُقتل: المرجع الخام يبقى في اليد من لحظة القبول حتى التسليم، فالقتل
// (إغلاق المقبس الخام تحت المحرك) يبلغ النظير في الحالات الثلاث حصراً:
// مهلة المصافحة، وحصاد stop، وما تجاوز مهلة الإغلاق بعدها. البوابة على
// أول سجل TLS كاملاً لا أول بايت: البايت الأول غير بدء المصافحة (0x16)
// عميل HTTP عادي على المنفذ الآمن فيُقتل فوراً، والطول المعلن فوق
// السقف يُقتل فوراً — والتدميران الفوريان خارج الساعة لا تحكمهما
// مهلة. القراءة في البوابة واحدة لكل حدث قراءة: نداء read ثانٍ بلا
// بيانات يصطدم بتوكيد المحرك فيغلق المقبس، والنداء الواحد يأخذ كل
// المتاح فلا بايت يفقد. التسليح بـRawSecureSocket.secureServer والاشتراك
// القائم ينتقل للمحرك بينما البايتات المقروءة تعود إليه عبر
// bufferedData، والتسليم محوّل فوق RawSecureSocket يرتدي شكل SecureSocket
// لأن HttpServer.listenOn لا يستهلك غيره — وساعة مهلة الترويسات حين
// تُضبط تعيش داخل المحوّل نفسه (الصنف المشترك مع الغلاف العادي) فلا
// غلاف ثانٍ فوقه والمسلَّم يبقى SecureSocket بلا وسيط — بعقد إغلاق يطابق ما يبنيه
// SecureSocket العام فوق الخام نفسه: flush يسلّم البايتات المعلقة
// للمحرك ولا ينتظر السلك، وclose يغلق جهة الكتابة وحدها بعد التسليم
// (shutdown(send) — جهة القراءة لا تُمسّ فوق جسم غير مقروء)، وdestroy
// إغلاق مفاجئ للخام — وما بقي من السطح يمرّر إلى الخام، والأعضاء التي
// لم يقسها الاستهلاك ترمي UnsupportedError باسم عضوها لا سلوكاً صامتاً
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder, Uint8List;

import 'header_watchdog_feed.dart';

/// The bridge's TLS transport feed: the plain [RawServerSocket] the
/// bridge binds is wrapped here, and every accepted raw socket must
/// complete the first TLS record before it is armed with
/// `RawSecureSocket.secureServer` (the bytes read before arming are
/// handed back to the TLS engine through `bufferedData`, and the
/// existing read subscription moves to the engine with it) and
/// delivered to `HttpServer.listenOn` as the `SecureSocket` shape that
/// consumer requires - the adapter itself is that shape, and the
/// request-header deadline lives inside it when armed, so a delivered
/// socket stays a real `SecureSocket` to `is SecureSocket` and reads
/// its scheme and certificate by construction.
///
/// The gate is the first full TLS record, not the first byte: a first
/// byte that is not a handshake record (a plain HTTP client on the
/// TLS port) is cut at once, and a first record declaring a length
/// over the cap is cut at once - both outside the clock, at the
/// moment of the fact. The whole handshake - from accept to delivery
/// - is bounded by one deadline ([handshakeTimeout]): a client that
/// sends nothing, drips its first record slowly, or completes its
/// first record and then goes silent is cut at the deadline. The cut
/// closes the raw socket the feed still holds, so it reaches the wire
/// in every state: before arming, after arming, and through `stop`'s
/// harvest. `destroy` on a delivered connection also closes the raw
/// socket (the adapter maps it so), which is what makes the past-
/// close-deadline cut reach the wire too.
///
/// The gate reads exactly once per read event: a second `read()` call
/// without data trips the engine's own assertion and closes the raw
/// socket, and the single call already takes everything available.
///
/// The accept-time ceilings stay: the host's `maxOpenConnections`
/// over the whole listener set while that option is on, or
/// [internalHandshakeCap] over the in-flight handshakes alone while
/// it is off - a delivered connection never counts as an in-flight
/// handshake. Every cut lands in the cumulative cut counter through
/// [onCut]; every delivered handshake lands in the delivered counter
/// through [onDelivered].
///
/// The class shape is the measured narrow one: `extends Stream<Socket>`
/// `implements ServerSocket`, and `HttpServer.listenOn` consumes exactly
/// [listen], [port], [address], and [close]. Closing the feed stops the
/// accept loop, cuts every socket still in flight (pre-arming and
/// armed alike - the raw handle is held in both states), and closes
/// the delivered-socket stream. `HttpServer.close` does not pass
/// through this feed: `listenOn` never closes the socket handed to
/// it, so the owning server closes the feed by its own hand - in
/// `stop`, after closing the listeners and before the seats drain,
/// and in the orphan path.
class TlsHandshakeFeed extends Stream<Socket> implements ServerSocket {
  /// The in-flight handshake ceiling while the host's
  /// `maxOpenConnections` option is off. It counts handshakes in flight
  /// only - a socket accepted but undelivered - and never a delivered
  /// connection: a completed handshake is the intake's connection,
  /// bounded by the host's own option and never by this ceiling. The
  /// ceiling bounds the transient handshake window (every in-flight
  /// handshake is cut at [handshakeTimeout] at the latest), so it stays
  /// well under an OS default file-descriptor budget such as macOS's
  /// 256 while sixty-four completed connections with the option off
  /// never refuse the next sender.
  static const int internalHandshakeCap = 64;

  /// The largest first record the gate accepts: the TLS record maximum
  /// (16,384) plus the maximum expansion a handshake record may carry.
  /// A first record declaring more is hostile or broken - cut before
  /// arming, never buffered toward the engine.
  static const int maxFirstRecordBytes = 16384 + 256;

  final RawServerSocket _raw;
  final SecurityContext _context;
  final Duration _handshakeTimeout;
  final Duration? _headerTimeout;
  final int _openConnectionCap;
  final int _inFlightHandshakeCap;
  final int Function() _openConnectionTotal;
  final int Function() _inFlightHandshakesTotal;
  final void Function() _onCut;
  final void Function() _onDelivered;
  final void Function(int inFlightNow, int cap) _onOverHandshakeCap;
  final void Function(int openNow, int cap) _onOverConnectionCap;

  // المقابس قبل التسليح: وصلت ولم يكتمل أول سجل لها بعد — عدّها حي
  // وقطعها يصل السلك
  final Set<_PreArm> _pending = <_PreArm>{};

  // المقابس المسلَّحة: المحرك يتولى مصافحتها ومستقبل التسليح غير محسوم
  // بعد — عدّها حي والمرجع الخام باقٍ في اليد فالقطع يصل السلك
  final Set<_PreArm> _arming = <_PreArm>{};

  final StreamController<Socket> _out = StreamController<Socket>();
  bool _closed = false;

  /// Builds the feed over [raw]. The callbacks are the seam to the
  /// owning server: [openConnectionTotal] reads the whole listener set -
  /// delivered sockets of every transport plus the in-flight handshakes
  /// of every feed - and governs the accept gate while the host's
  /// connection cap is on; [inFlightHandshakesTotal] reads the feeds'
  /// in-flight handshakes only and governs the internal ceiling while
  /// that cap is off; [onCut] and [onDelivered] feed the cumulative
  /// counters; the two on-over callbacks carry the rejected accept to
  /// the throttled warning line of its own position.
  TlsHandshakeFeed({
    required RawServerSocket raw,
    required SecurityContext context,
    required Duration handshakeTimeout,
    Duration? headerTimeout,
    required int openConnectionCap,
    required int inFlightHandshakeCap,
    required int Function() openConnectionTotal,
    required int Function() inFlightHandshakesTotal,
    required void Function() onCut,
    required void Function() onDelivered,
    required void Function(int inFlightNow, int cap) onOverHandshakeCap,
    required void Function(int openNow, int cap) onOverConnectionCap,
  }) : _raw = raw,
       _context = context,
       _handshakeTimeout = handshakeTimeout,
       _headerTimeout = headerTimeout,
       _openConnectionCap = openConnectionCap,
       _inFlightHandshakeCap = inFlightHandshakeCap,
       _openConnectionTotal = openConnectionTotal,
       _inFlightHandshakesTotal = inFlightHandshakesTotal,
       _onCut = onCut,
       _onDelivered = onDelivered,
       _onOverHandshakeCap = onOverHandshakeCap,
       _onOverConnectionCap = onOverConnectionCap {
    _raw.listen(_onAccepted, onError: (Object error) => _out.addError(error));
  }

  // المصافحات الجارية الآن: ما قبل التسليح والمسلَّح معاً — والعدّ
  // ينتهي لحظة تسليم المقبس إلى HttpServer فلا عدّ مزدوج مع
  // connectionsInfo
  int get ongoingHandshakes => _pending.length + _arming.length;

  void _onAccepted(RawSocket socket) {
    if (_closed) {
      // قبول كان في الطريق عند الإغلاق: بلا مرجع بعد الإغلاق
      socket.close();
      return;
    }
    // سقفا القبول بالترتيب: سقف الخيار فوق المجموع الكلي (اتصالات
    // مسلَّمة ومصافحات جارية معاً) حين يكون مسلَّحاً، وسقف المصافحات
    // الجارية الداخلي حين يكون الخيار مطفأً حصراً — فالمسلَّم ليس
    // مصافحة جارية أبداً ولا يعدّه السقف الداخلي — وفوق أي سقف يُقتل
    // المقبس الجديد قبل تسليحه حيث يصل القتل إلى السلك
    if (_openConnectionCap > 0) {
      final openNow = _openConnectionTotal();
      if (openNow + 1 > _openConnectionCap) {
        socket.close();
        _onCut();
        _onOverConnectionCap(openNow + 1, _openConnectionCap);
        return;
      }
    } else {
      final inFlightNow = _inFlightHandshakesTotal();
      if (inFlightNow + 1 > _inFlightHandshakeCap) {
        socket.close();
        _onCut();
        _onOverHandshakeCap(inFlightNow + 1, _inFlightHandshakeCap);
        return;
      }
    }
    final handshake = _PreArm(socket);
    _pending.add(handshake);
    // الساعة الكاملة للمصافحة من لحظة القبول: الصامت وقاطر السجل
    // البطيء يُقتلان عندها قبل التسليح — والقطع لا يعاد تشغيله لكل بايت
    handshake.deadline = Timer(_handshakeTimeout, () => _cut(handshake));
    try {
      socket.readEventsEnabled = true;
      handshake.subscription = socket.listen(
        (event) {
          if (handshake.armed) {
            // المحرك يملك المقبس بعد التسليح: لا تولٍّ ثانية
            return;
          }
          if (event == RawSocketEvent.readClosed ||
              event == RawSocketEvent.closed) {
            // إغلاق النظير على الخام حدثٌ في الدفق لا onDone: الانصراف
            // نفسه يسحب من العدّ ويهدم المرجع
            _abandon(handshake);
            return;
          }
          if (event != RawSocketEvent.read) {
            return;
          }
          // قراءة واحدة لكل حدث قراءة: نداء read ثانٍ بلا بيانات يصطدم
          // بتوكيد المحرك (assert(available > 0)) فيغلق المقبس عبر مسار
          // الخطأ — والنداء الواحد يُصرِّف بنفسه كل المتاح فلا بايت يفقد
          final chunk = socket.read();
          if (chunk != null && chunk.isNotEmpty) {
            handshake.buffered.addAll(chunk);
          }
          _inspect(handshake);
        },
        onError: (Object _) => _abandon(handshake),
        onDone: () => _abandon(handshake),
        cancelOnError: true,
      );
    } on Object {
      // قبول وصل ميتاً (النظير هدم قبل إقلاع قراءته): خصائص الخام على
      // مقبس مغلق ترمي فيضيع onDone — الانصرافُ نفسهُ يسحب من العدّ
      // ويهدم المرجع فلا مقبض يتسرب من سباق الولادة والموت
      _abandon(handshake);
    }
  }

  // فحص الرأس الخماسي على كل وصول: البايت الأول غير 0x16 قتل فوري،
  // والطول المعلن فوق السقف قتل فوري، واكتمال الرأس والحمولة
  // المعلنة تسليح — والتدميران الفوريان خارج الساعة لا تحكمهما مهلة
  void _inspect(_PreArm handshake) {
    if (handshake.armed) {
      return;
    }
    final bytes = handshake.buffered;
    if (bytes.isEmpty) {
      return;
    }
    if (bytes[0] != 0x16) {
      _cut(handshake);
      return;
    }
    if (bytes.length < 5) {
      return;
    }
    final declared = (bytes[3] << 8) | bytes[4];
    if (declared > maxFirstRecordBytes) {
      _cut(handshake);
      return;
    }
    if (bytes.length < 5 + declared) {
      return;
    }
    _arm(handshake);
  }

  // القتل بمساره: ما قبل التسليح قتله فوري عند الحقيقة (أول بايت غير
  // 0x16 أو طول معلن فوق السقف) وعند انقضاء ساعة المصافحة، والمسلَّح
  // يقطعه انقضاء الساعة نفسها — ساعة واحدة من القبول لا تُعاد بالتسليح
  // — بإغلاق المقبس الخام تحت المحرك فهو الذي يبلغ النظير على السلك،
  // والعدّ قطع تراكمي من الخادم لا من العميل الذي انصرف وحده
  void _cut(_PreArm handshake) {
    if (_pending.remove(handshake)) {
      handshake.deadline?.cancel();
      handshake.subscription?.cancel();
      handshake.raw.close();
      _onCut();
      return;
    }
    if (_arming.remove(handshake)) {
      handshake.raw.close();
      _onCut();
    }
  }

  // انصراف النظير وحده قبل التسليح (خطأ أو إغلاق): يسحب من العدّ بلا
  // قطع محسوب — القطع عدّ ما قطعته التلقيمة لا ما تركه نظيره — ويهدم
  // المقبس لحظة الانصراف حصراً: تركه حياً هنا يسرّب مقبض النظام
  // (حلقة «اتصال ثم إغلاق» من خارج العملية تستنزف واصفات الجسر حتى
  // نفادها) والهدم هنا يصل السلك قبل التسليح كبقية الأهدمات
  void _abandon(_PreArm handshake) {
    if (_pending.remove(handshake)) {
      handshake.deadline?.cancel();
      handshake.subscription?.cancel();
      handshake.raw.close();
    }
  }

  // التسليح: البايتات المقروءة قبل التسليح تعاد للمحرك عبر
  // bufferedData والاشتراك ينتقل إليه به، وساعة المصافحة باقية على
  // دورتها من لحظة القبول لا تُعاد بالتسليح: انقضاءها والمقبس ما يزال
  // مسلَّحاً غير مسلَّم يقتله خاماً فيبلغ النظير على السلك، والعدّ يبقى
  // على المقبس حتى يُسلَّم إلى HttpServer أو تفشل المصافحة
  void _arm(_PreArm handshake) {
    if (!_pending.remove(handshake)) {
      // سبقه الإغلاق أو الانصراف: لا تسليح بعد لا مرجع
      return;
    }
    handshake.armed = true;
    _arming.add(handshake);
    RawSecureSocket.secureServer(
      handshake.raw,
      _context,
      subscription: handshake.subscription,
      bufferedData: handshake.buffered,
    ).then<void>(
      (secure) {
        if (!_arming.remove(handshake)) {
          // حسم وصل بعد قتل المهلة أو الحصاد: لا تسليم بعد لا مرجع
          unawaited(secure.close());
          return;
        }
        handshake.deadline?.cancel();
        if (_closed) {
          // تسليم وصل بعد الإغلاق: بلا مستمع — إغلاق فوري
          unawaited(secure.close());
          return;
        }
        // العدّ ينتهي هنا لحظة التسليم: يُعدّ من الآن في connectionsInfo
        // وحده، والتلقيمة لا تعدّه ثانية
        _onDelivered();
        _out.add(
          // مهلة اكتمال الترويسات تعيش داخل المحوّل نفسه حين تُضبط:
          // الساعة تُسلَّح عند التسليم حصراً والمصافحة قبلها ساعة
          // _handshakeTimeout كما هي — والمسلَّم يبقى SecureSocket
          // حقيقياً بلا غلاف ثانٍ فيقرأ HttpServer مخططه من شكله الأصلي
          _RawSecureAdapter(secure, headerTimeout: _headerTimeout),
        );
      },
      onError: (Object _) {
        // المصافحة الفاشلة تنقص العدّ: المقعد تحرر للمرسل التالي —
        // والمحرك أغلق الخام عند الخطأ بنفسه. وساعة المصافحة تُلغى هنا
        // كما في مسار التسليم: المقبس خرج من القائمتين فلن تجد قطعاً
        // لو انقضت، وبقاؤها حياً إلى أجله مؤقتٌ بلا عمل
        handshake.deadline?.cancel();
        _arming.remove(handshake);
      },
    );
  }

  // الإغلاق: إيقاف القبول، وحصد كل ما في الطريق — ما قبل التسليح
  // والمسلَّح معاً: المرجع الخام باقٍ في اليد في الحالتين فالقتل يبلغ
  // النظير، وكل حصاد قطعةٌ معدودة. نداء HttpServer.close لا يمر من
  // هنا: المستمع الممرَّر له لا يُغلق من عنده، فالمالك هو من يغلق
  // التلقيمة بيده في stop وفي مسار اليتامى.
  @override
  Future<ServerSocket> close() async {
    _closed = true;
    for (final handshake in _pending.toList()) {
      _pending.remove(handshake);
      handshake.deadline?.cancel();
      handshake.subscription?.cancel();
      handshake.raw.close();
      _onCut();
    }
    for (final handshake in _arming.toList()) {
      _arming.remove(handshake);
      handshake.deadline?.cancel();
      handshake.raw.close();
      _onCut();
    }
    await _raw.close();
    await _out.close();
    // العائد عقد ServerSocket.close نفسه: التلقيمة ذاتها المغلقة —
    // فالخام ليس ServerSocket (عنصرا دفقه مختلفان)
    return this;
  }

  @override
  StreamSubscription<Socket> listen(
    void Function(Socket event)? onData, {
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
  int get port => _raw.port;

  @override
  InternetAddress get address => _raw.address;
}

// حالة مقبس واحد قبل حسم مصافحته: البايتات المجموعة، وساعة المصافحة
// الكاملة، واشتراك القراءة، وعلم التسليح الذي يمنع أي قطع من بوابة
// القراءة بعده
class _PreArm {
  final RawSocket raw;
  final List<int> buffered = <int>[];
  Timer? deadline;
  StreamSubscription<RawSocketEvent>? subscription;
  bool armed = false;

  _PreArm(this.raw);
}

/// A `SecureSocket`-shaped adapter over a `RawSecureSocket` - the
/// delivery shape `HttpServer.listenOn` consumes, since `RawSecureSocket`
/// itself is neither a `Socket` nor wrapped by any public dart:io API.
/// Reads flow through a pausable controller that honors the consumer's
/// backpressure by toggling the raw read events; writes go through the
/// non-blocking raw write and wait for WRITE events when the kernel
/// buffer is full. The closing contract mirrors what the public
/// `SecureSocket` builds over the same raw socket: `flush` hands every
/// buffered byte to the engine and completes without waiting for the
/// wire, `close` shuts the write side alone after the hand-off (the
/// read side stays open over an unread body), and `destroy` closes the
/// raw socket outright. Members no consumption ever invoked throw an
/// `UnsupportedError` naming the member - a named error, never silent
/// behavior - and everything else passes through to the raw socket.
///
/// When [headerTimeout] is armed, the shared [HeaderTracker] lives
/// inside the adapter: its clock arms at construction (the delivery -
/// the handshake window before it belongs to the handshake timeout),
/// every read chunk passes through it before the consumer sees it, and
/// its cut is quiet - the raw socket closes under the engine and the
/// delivered stream closes, no bytes, no reply, no new wire code. The
/// deadline is why the tracker is hosted here instead of a wrapper
/// above: a wrapper would hide the `SecureSocket` shape from
/// `HttpServer.listenOn`'s `is SecureSocket` reads.
class _RawSecureAdapter implements SecureSocket {
  _RawSecureAdapter(this.raw, {this.headerTimeout}) : _rp = raw.remotePort {
    _out = StreamController<Uint8List>(
      sync: true,
      onListen: () {
        _g(() => raw.readEventsEnabled = true);
      },
      onPause: () {
        _g(() => raw.readEventsEnabled = false);
      },
      onResume: () {
        _g(() => raw.readEventsEnabled = true);
      },
      onCancel: () {
        // المستهلك انصرف: الساعة تُوقف معه لا قطعٌ على مقبس مُهجور
        _tracker?.retire();
        _g(() => raw.readEventsEnabled = false);
        unawaited(_sub.cancel());
      },
    );
    _sub = raw.listen(
      _onRawEvent,
      onError: (Object e, StackTrace s) {
        // خطأ يصل بعد إغلاق دفق التسليم لا مستقبل له، وإضافته على دفق
        // مغلق ترمي داخل هذا النداء الراجع — فيُترك والنداء يعود
        _tracker?.retire();
        if (!_out.isClosed) _out.addError(e, s);
      },
      onDone: () {
        if (!_out.isClosed) _out.close();
      },
    );
    // الساعة المشتركة تُولد مع المحوّل حصراً حين تُضبط المهلة: الولادة
    // هنا هي لحظة التسليم — المصافحة قبلها ساعة handshakeTimeout كما هي
    _tracker = headerTimeout == null
        ? null
        : HeaderTracker(
            deadline: headerTimeout,
            onCut: () {
              // القطع الهادئ: إغلاق الخام يبلغ النظير على السلك — لا
              // بايت ولا رد ولا رمز جديد، وتعليم الموت يمنع تمرير ما
              // بقي في حدث القراءة الجاري
              _rawDead = true;
              try {
                raw.close();
              } on SocketException {
                // الخام ميت أصلاً: لا شيء يبلغ السلك
              }
              if (!_out.isClosed) _out.close();
            },
          );
  }

  final RawSecureSocket raw;

  // منفذ النظير يُلتقط عند البناء: قراءة الخام بعد إغلاقه ترمي، والتقطيع
  // المبكر يجعل أعضاء العنوان تقرأ حقها من اليد لا من مقبس ميت
  final int _rp;

  /// The request-header completion deadline this adapter carries, null
  /// when the host runs without one - the same value the plain wrapper
  /// takes; here it arms the shared [HeaderTracker] at the delivery.
  final Duration? headerTimeout;
  HeaderTracker? _tracker;
  late final StreamController<Uint8List> _out;
  late final StreamSubscription<RawSocketEvent> _sub;
  final Encoding _encoding = utf8;
  Completer<void>? _writeReady;
  bool _rawDead = false;

  /// A raw access after the raw closed throws SocketException.closed;
  /// inside a controller callback that would surface as an unhandled
  /// error. The guard marks the adapter dead and swallows that one
  /// exception shape.
  T? _g<T>(T Function() f) {
    if (_rawDead) return null;
    try {
      return f();
    } on SocketException catch (_) {
      _rawDead = true;
      return null;
    }
  }

  void _onRawEvent(RawSocketEvent event) {
    if (_rawDead) return;
    if (event == RawSocketEvent.read) {
      // الصب حتى null داخل حدث القراءة الواحد: المحرك الآمن يعيد null
      // بلا توكيد قاتل على عكس الخام قبل التسليح
      Uint8List? chunk;
      while ((chunk = _g<Uint8List?>(() => raw.read())) != null) {
        if (chunk!.isEmpty) continue;
        // كل قطعة تمر بالساعة المشتركة قبل المستهلك: القطع إن وقعت في
        // وسطها عُلّم الموت وأُغلق الدفق فلا تُمرَّر بعدها بايتات
        _tracker?.track(chunk);
        if (!_rawDead && !_out.isClosed) _out.add(chunk);
      }
    } else if (event == RawSocketEvent.write) {
      final ready = _writeReady;
      _writeReady = null;
      if (_rest.isNotEmpty && !_writing) {
        unawaited(_drainRest());
      }
      ready?.complete();
    } else if (event == RawSocketEvent.readClosed ||
        event == RawSocketEvent.closed) {
      // النظير أغلق: ساعة الاتصال تنزع معه — لا قطع على مقبس ميت
      _tracker?.retire();
      if (!_out.isClosed) _out.close();
    }
  }

  final BytesBuilder _rest = BytesBuilder(copy: false);
  bool _writing = false;

  // الكتابة العابرة: ما أخذته عازلة النواة يخرج فوراً والبقية تنتظر
  // حدث الكتابة — مسارات القطع تدمّر المقبس بعد كتابة ردها مباشرة فالرد
  // يجب أن يبلغ السلك داخل add لا بعدها
  void _enqueue(List<int> data) {
    if (_rest.isEmpty && !_writing) {
      final n = raw.write(data);
      if (n >= data.length) return;
      _rest.add(data.sublist(n));
    } else {
      _rest.add(data);
    }
    raw.writeEventsEnabled = true;
  }

  Future<void> _drainRest() async {
    while (_rest.isNotEmpty) {
      final buf = _rest.takeBytes();
      var off = 0;
      _writing = true;
      while (off < buf.length) {
        final n = raw.write(buf, off, buf.length - off);
        off += n;
        if (off < buf.length) {
          raw.writeEventsEnabled = true;
          _writeReady ??= Completer<void>();
          await _writeReady!.future;
          _writeReady = null;
        }
      }
      _writing = false;
      if (_rest.isEmpty) break;
    }
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
  Future<Socket> close() async {
    await _drainRest();
    // عقد الإغلاق العادي: تسليم كل بايت معلّق للمحرك ثم إغلاق جهة
    // الكتابة وحدها (shutdown(send)) — وجهة القراءة لا تُمسّ فوق جسم
    // غير مقروء فلا إعادة تعيين تقتل الرد الذي سلّمه المحرك للتو
    _g(() => raw.shutdown(SocketDirection.send));
    return this;
  }

  @override
  void destroy() {
    // ساعة الاتصال تنزع مع الهدم: لا قطع على مقبس مدمَّر
    _tracker?.retire();
    // الإغلاق المفاجئ: إغلاق الخام بلا شرط. لا يُستعمل هنا الواقي _g —
    // فقد علّم المحوّل ميتاً من قبل (قراءة على جهة قراءة مغلقة مثلاً)
    // فيتخطى الإغلاق، وكل قطع يبدؤه الخادم بعد التسليم يمر من هنا:
    // تفريغ الجسم غير المكتمل، ومؤقت الخمول، والإغلاق القسري في stop.
    try {
      raw.close();
    } on SocketException {
      // الخام ميت أصلاً: لا شيء يبلغ السلك
    }
    _rawDead = true;
  }

  @override
  Future<void> flush() async {
    // تسليم كل بايت معلّق للمحرك بلا انتظار السلك: المحرك يُخرج ما
    // سُلّم إليه أثناء معالجة أحداثه
    await _drainRest();
  }

  @override
  void add(List<int> data) {
    _enqueue(Uint8List.fromList(data));
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      throw UnsupportedError('_RawSecureAdapter.addError is not supported');

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      _enqueue(Uint8List.fromList(chunk));
      await _drainRest();
    }
  }

  @override
  void write(Object? object) =>
      throw UnsupportedError('_RawSecureAdapter.write is not supported');

  @override
  void writeAll(Iterable objects, [String separator = '']) =>
      throw UnsupportedError('_RawSecureAdapter.writeAll is not supported');

  @override
  void writeln([Object? object = '']) =>
      throw UnsupportedError('_RawSecureAdapter.writeln is not supported');

  @override
  void writeCharCode(int charCode) => throw UnsupportedError(
    '_RawSecureAdapter.writeCharCode is not supported',
  );

  @override
  Encoding get encoding => _encoding;

  @override
  set encoding(Encoding value) =>
      throw UnsupportedError('_RawSecureAdapter.encoding is not supported');

  @override
  Future<Socket> get done =>
      throw UnsupportedError('_RawSecureAdapter.done is not supported');

  /// Not part of the `SecureSocket` surface - declared to keep any
  /// dynamic call on the named error path instead of a silent miss.
  void shutdown(SocketDirection direction) =>
      throw UnsupportedError('_RawSecureAdapter.shutdown is not supported');

  @override
  bool setOption(SocketOption option, bool enabled) =>
      raw.setOption(option, enabled);

  @override
  Uint8List getRawOption(RawSocketOption option) => raw.getRawOption(option);

  @override
  void setRawOption(RawSocketOption option) => raw.setRawOption(option);

  @override
  int get port => raw.port;

  @override
  int get remotePort => _rp;

  @override
  InternetAddress get remoteAddress => raw.remoteAddress;

  @override
  InternetAddress get address => raw.address;

  @override
  X509Certificate? get peerCertificate => raw.peerCertificate;

  @override
  String? get selectedProtocol => raw.selectedProtocol;

  @override
  // ignore: deprecated_member_use
  void renegotiate({
    bool useSessionCache = true,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
  }) =>
      // ignore: deprecated_member_use
      raw.renegotiate(
        useSessionCache: useSessionCache,
        requestClientCertificate: requestClientCertificate,
        requireClientCertificate: requireClientCertificate,
      );

  @override
  dynamic noSuchMethod(Invocation invocation) {
    throw UnsupportedError(
      '_RawSecureAdapter: ${invocation.memberName} is not implemented',
    );
  }
}
