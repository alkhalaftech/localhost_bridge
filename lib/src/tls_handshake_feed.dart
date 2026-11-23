// تلقيمة مصافحة TLS: باب النقل الآمن للجسر. المستمع الخام يُربط عادياً
// والتلقيمة تحرس قبوله ثم تغذي HttpServer.listenOn بالمقابس التي أكملت
// مصافحتها. البوابة على أول سجل TLS كاملاً لا أول بايت: البايت الأول
// غير بدء المصافحة (0x16) عميل HTTP عادي على المنفذ الآمن فيُدمَّر
// فوراً، والطول المعلن فوق السقف يُدمَّر فوراً، وعدم اكتمال أول سجل
// داخل مهلة [firstRecordTimeout] يُدمَّر عند المهلة — والدمار هنا يصل
// السلك لأنه قبل تسليح محرك TLS: تدمير المقبس يبلغ النظير قبل التسليح
// حصراً، وبعد التسليح لا يملك البندُ إلا الغلافَ المنفصل فدماره
// وإغلاقه لا يبلغان النظير ولا يحصده stop، ولا يقدم dart:io واجهة
// عامة تعيد مقبس المحرك الخام إلى صورة Socket التي يستهلكها
// HttpServer.listenOn فالبند لا يبني ذلك القتل — حده السقف الداخلي
// والسقف الاختياري وسطر الإعلان عند stop.
import 'dart:async';
import 'dart:io';

/// The bridge's TLS transport feed: the plain [ServerSocket] the bridge
/// binds is wrapped here, and every accepted socket must complete the
/// first TLS record before it is armed with `SecureSocket.secureServer`
/// (the bytes read before arming are handed back to the TLS engine
/// through `bufferedData`) and delivered to `HttpServer.listenOn`.
///
/// The gate is the first full TLS record, not the first byte: a first
/// byte that is not a handshake record (a plain HTTP client on the TLS
/// port) is destroyed at once, a first record declaring a length over
/// the cap is destroyed at once, and a first record that does not
/// complete inside the given deadline is destroyed at the deadline -
/// all three while the socket is still unarmed, which is the one state
/// where destroying it reaches the wire. A socket whose handshake fails
/// after arming, or that stays silent past arming (a client that sent
/// its ClientHello and went quiet), cannot be cut by this package:
/// after arming the package holds only the detached wrapper socket, so
/// destroying or closing it does not reach the peer and `stop` does not
/// reap it, and dart:io exposes no public API that hands the raw engine
/// socket back wrapped as the `Socket` shape `HttpServer.listenOn`
/// consumes. Those sockets are bounded by the
/// accept-time ceilings this feed enforces: the host's
/// `maxOpenConnections` over the whole listener set while that option is
/// on, or [internalHandshakeCap] over the in-flight handshakes alone
/// while it is off - a delivered connection never counts as an in-flight
/// handshake. They are counted while in flight and announced by the
/// count at stop.
///
/// The class shape is the measured narrow one: `extends Stream<Socket>`
/// `implements ServerSocket`, and `HttpServer.listenOn` consumes exactly
/// [listen], [port], [address], and [close]. Closing the feed stops the
/// accept loop, destroys every socket still before arming (the harvest
/// that reaches the wire), and closes the delivered-socket stream.
/// `HttpServer.close` does not pass through this feed: `listenOn` never
/// closes the socket handed to it, so the owning server closes the feed
/// by its own hand - in `stop`, after closing the listeners and before
/// the seats drain, and in the orphan path.
class TlsHandshakeFeed extends Stream<Socket> implements ServerSocket {
  /// The in-flight handshake ceiling while the host's
  /// `maxOpenConnections` option is off. It counts handshakes in flight
  /// only - a socket accepted but undelivered - and never a delivered
  /// connection: a completed handshake is the intake's connection, bounded
  /// by the host's own option and never by this ceiling. The value is
  /// deliberately tighter than the destructible-socket ceilings: a socket
  /// stuck past arming can never be freed by the server (after arming the
  /// package holds only the detached wrapper socket, and destroying it
  /// does not reach the peer), so it holds its slot forever;
  /// one page opens at most a handful of connections to one origin; and
  /// the ceiling stays well under an OS default file-descriptor budget
  /// such as macOS's 256.
  static const int internalHandshakeCap = 64;

  /// The largest first record the gate accepts: the TLS record maximum
  /// (16,384) plus the maximum expansion a handshake record may carry.
  /// A first record declaring more is hostile or broken - destroyed
  /// before arming, never buffered toward the engine.
  static const int maxFirstRecordBytes = 16384 + 256;

  final ServerSocket _raw;
  final SecurityContext _context;
  final Duration _firstRecordTimeout;
  final int _openConnectionCap;
  final int _inFlightHandshakeCap;
  final int Function() _openConnectionTotal;
  final int Function() _inFlightHandshakesTotal;
  final void Function() _onCut;
  final void Function() _onDelivered;
  final void Function(int inFlightNow, int cap) _onOverHandshakeCap;
  final void Function(int openNow, int cap) _onOverConnectionCap;

  /// المقابس قبل التسليح: وصلت ولم يكتمل أول سجل لها بعد — عدّها حي
  /// ودمارها يصل السلك
  final Set<_PreArm> _pending = <_PreArm>{};

  /// المقابس المسلَّحة: المحرك يتولى مصافحتها ومستقبل التسليح غير محسوم
  /// بعد — عدّها حي ودمارها لا يصل السلك
  final Set<_PreArm> _arming = <_PreArm>{};

  final StreamController<Socket> _out = StreamController<Socket>();
  bool _closed = false;

  /// عالق ما بعد التسليح لحظة الإغلاق: العدد الذي يعلنه stop بسطر واحد
  /// (صفر لا يُعلن) — يُقرأ بعد [close] وحصراً
  int stuckArmingAtClose = 0;

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
    required ServerSocket raw,
    required SecurityContext context,
    required Duration firstRecordTimeout,
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
       _firstRecordTimeout = firstRecordTimeout,
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

  /// المصافحات الجارية الآن: ما قبل التسليح والمسلَّح معاً — والعدّ
  /// ينتهي لحظة تسليم المقبس إلى HttpServer فلا عدّ مزدوج مع
  /// connectionsInfo
  int get ongoingHandshakes => _pending.length + _arming.length;

  void _onAccepted(Socket socket) {
    if (_closed) {
      // قبول كان في الطريق عند الإغلاق: بلا مرجع بعد الإغلاق
      socket.destroy();
      return;
    }
    // سقفا القبول بالترتيب: سقف الخيار فوق المجموع الكلي (اتصالات
    // مسلَّمة ومصافحات جارية معاً) حين يكون مسلَّحاً، وسقف المصافحات
    // الجارية الداخلي حين يكون الخيار مطفأً حصراً — فالمسلَّم ليس
    // مصافحة جارية أبداً ولا يعدّه السقف الداخلي — وفوق أي سقف يُدمَّر
    // المقبس الجديد قبل تسليحه حيث يصل التدمير إلى السلك
    if (_openConnectionCap > 0) {
      final openNow = _openConnectionTotal();
      if (openNow + 1 > _openConnectionCap) {
        socket.destroy();
        _onCut();
        _onOverConnectionCap(openNow + 1, _openConnectionCap);
        return;
      }
    } else {
      final inFlightNow = _inFlightHandshakesTotal();
      if (inFlightNow + 1 > _inFlightHandshakeCap) {
        socket.destroy();
        _onCut();
        _onOverHandshakeCap(inFlightNow + 1, _inFlightHandshakeCap);
        return;
      }
    }
    final handshake = _PreArm(socket);
    _pending.add(handshake);
    // المهلة على اكتمال أول سجل كاملاً من لحظة القبول: الصامت يُقطع
    // عندها، وقاطر بايتات بطيء كذلك — والقطع لا يعاد تشغيله لكل بايت
    handshake.deadline = Timer(_firstRecordTimeout, () => _cut(handshake));
    handshake.subscription = socket.listen(
      (chunk) {
        handshake.buffered.addAll(chunk);
        _inspect(handshake);
      },
      onError: (Object _) => _abandon(handshake),
      onDone: () => _abandon(handshake),
      cancelOnError: true,
    );
  }

  /// فحص الرأس الخماسي على كل وصول: البايت الأول غير 0x16 تدمير فوري،
  /// والطول المعلن فوق السقف تدمير فوري، واكتمال الرأس والحمولة
  /// المعلنة تسليح
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
    _arm(handshake, bytes);
  }

  /// القطع قبل التسليح حصراً: إلغاء المهلة والاشتراك وتدمير المقبس —
  /// والعدّ قطع تراكمي من الخادم لا من العميل الذي انصرف وحده
  void _cut(_PreArm handshake) {
    if (handshake.armed) {
      // بعد التسليح لا قطع يصل السلك — لا يُكتب سلوك لا يفعل شيئاً
      return;
    }
    if (!_pending.remove(handshake)) {
      return;
    }
    handshake.deadline?.cancel();
    handshake.subscription?.cancel();
    handshake.socket.destroy();
    _onCut();
  }

  /// انصراف النظير وحده قبل التسليح (خطأ أو إغلاق): يسحب من العدّ بلا
  /// قطع محسوب — القطع عدّ ما قطعته التلقيمة لا ما تركه نظيره — ويهدم
  /// المقبس لحظة الانصراف حصراً: تركه حياً هنا يسرّب مقبض النظام
  /// (حلقة «اتصال ثم إغلاق» من خارج العملية تستنزف واصفات الجسر حتى
  /// نفادها) والهدم هنا يصل السلك قبل التسليح كبقية الأهدمات
  void _abandon(_PreArm handshake) {
    if (_pending.remove(handshake)) {
      handshake.deadline?.cancel();
      handshake.subscription?.cancel();
      handshake.socket.destroy();
    }
  }

  /// التسليح: البايتات المقروءة قبل التسليح تعاد للمحرك عبر
  /// bufferedData، والاشتراك ينتقل للمحرك به بينما مهلة أول سجل تُلغى،
  /// والعدّ يبقى
  /// على المقبس حتى يُسلَّم إلى HttpServer أو تفشل المصافحة
  void _arm(_PreArm handshake, List<int> bytes) {
    if (!_pending.remove(handshake)) {
      // سبقه الإغلاق أو الانصراف: لا تسليح بعد لا مرجع
      return;
    }
    handshake.armed = true;
    handshake.deadline?.cancel();
    _arming.add(handshake);
    SecureSocket.secureServer(
      handshake.socket,
      _context,
      bufferedData: bytes,
    ).then<void>(
      (secure) {
        _arming.remove(handshake);
        if (_closed) {
          // تسليم وصل بعد الإغلاق: بلا مستمع — تدمير فوري
          secure.destroy();
          return;
        }
        // العدّ ينتهي هنا لحظة التسليم: يُعدّ من الآن في connectionsInfo
        // وحده، والتلقيمة لا تعدّه ثانية
        _onDelivered();
        _out.add(secure);
      },
      // المصافحة الفاشلة تنقص العدّ: المقعد تحرر للمرسل التالي
      onError: (Object _) => _arming.remove(handshake),
    );
  }

  /// الإغلاق: إيقاف القبول، وحصد كل ما قبل التسليح فوراً (تدمير يصل
  /// السلك)، وتسجيل عدد العالق بعد التسليح للإعلان، وإنهاء مستقبل
  /// التسليم. نداء HttpServer.close يمر من هنا فيسلك كل مسارات الإغلاق
  /// القائمة الحصاد نفسه.
  @override
  Future<ServerSocket> close() async {
    _closed = true;
    stuckArmingAtClose = _arming.length;
    for (final handshake in _pending.toList()) {
      _pending.remove(handshake);
      handshake.deadline?.cancel();
      handshake.subscription?.cancel();
      handshake.socket.destroy();
    }
    for (final handshake in _arming.toList()) {
      // التدمير هنا لا يصل السلك (المحرك مسلّح) — لكنه ينهي دفاتر
      // التلقيمة عند حسم مستقبل التسليح، والسطر المعلن حمل العدد قبله
      handshake.socket.destroy();
    }
    _arming.clear();
    final closed = await _raw.close();
    await _out.close();
    return closed;
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

/// حالة مقبس واحد قبل حسم مصافحته: البايتات المجموعة، ومهلة أول سجل،
/// واشتراك القراءة، وعلم التسليح الذي يمنع أي قطع بعده
class _PreArm {
  final Socket socket;
  final List<int> buffered = <int>[];
  Timer? deadline;
  StreamSubscription<List<int>>? subscription;
  bool armed = false;

  _PreArm(this.socket);
}
