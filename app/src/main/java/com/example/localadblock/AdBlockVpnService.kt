package com.example.localadblock

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * ローカルVPN。
 *  - 仮想DNSサーバー(10.111.222.2)宛ての経路 → DNS 問い合わせを受け取り、広告ドメインを NXDOMAIN にする
 *  - 「IPでもブロック」に書いたホストのIPアドレス宛ての経路 → TCP は RST を返して即失敗させ、UDP は捨てる
 *    （DNSを使わずに広告サーバーへ直接つなぐアプリへの対策）
 *  - それ以外の通信は VPN を通らない
 *  - setHttpProxy() でローカルプロキシ(127.0.0.1:8899)を配布 → HTTPS検査・URL単位のブロック
 */
class AdBlockVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.example.localadblock.START"
        const val ACTION_STOP = "com.example.localadblock.STOP"
        const val ACTION_RELOAD = "com.example.localadblock.RELOAD"
        const val PROXY_PORT = 8899

        private const val VPN_ADDRESS = "10.111.222.1"
        private const val VPN_DNS = "10.111.222.2"
        private const val VPN_ADDRESS6 = "fd66:6164:626c:6f63::1"
        private const val FALLBACK_DNS = "1.1.1.1"
        private const val CHANNEL = "vpn"
        private const val NOTIF_ID = 1
        private const val MAX_IP_ROUTES = 1000
        private const val IP_REFRESH_MS = 30 * 60 * 1000L
        private val VPN_DNS_BYTES = byteArrayOf(10, 111, 222.toByte(), 2)
        private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

        @Volatile var isRunning = false
            private set
        @Volatile var mitmActive = false
            private set
        @Volatile var lastError: String? = null
        @Volatile var ipRouteCount = 0
            private set
    }

    @Volatile private var filter: FilterEngine = FilterEngine.Builder().build()
    /** IPアドレス → ホスト名 */
    @Volatile private var blockedIps: Map<String, String> = emptyMap()
    private var worker: TunWorker? = null
    private var proxy: MitmProxy? = null
    private var dnsPool: ExecutorService? = null
    private var store: RuleStore? = null
    private var refresher: Thread? = null
    private val lock = Any()
    private val ipLogTimes = ConcurrentHashMap<String, Long>()
    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }

    @Volatile private var cachedDns: InetAddress? = null
    @Volatile private var cachedDnsAt = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> {
                if (isRunning) thread { reload() } else stopSelf()
                return START_NOT_STICKY
            }
        }
        startInForeground()
        thread(name = "vpn-start") { startVpn() }
        return START_STICKY
    }

    private fun startVpn() {
        synchronized(lock) {
            if (isRunning) return
            try {
                lastError = null
                val st = RuleStore(this).also { store = it }
                filter = st.buildEngine()
                val ca = CertificateAuthority.get(this)
                mitmActive = st.mitmEnabled && ca.isInstalledInUserStore()

                proxy = MitmProxy(PROXY_PORT, { filter }, ca, st, { mitmActive }, { ip -> blockedIps[ip] })
                    .also { it.start() }
                dnsPool = Executors.newFixedThreadPool(8)

                blockedIps = resolveIpBlocks(st)
                worker = establishTunnel(blockedIps)
                isRunning = true
                refresher = thread(name = "ip-refresh", isDaemon = true) { refreshLoop() }

                val msg = "ブロック規則 ${filter.blockRuleCount} 件 / 許可規則 ${filter.allowRuleCount} 件 / " +
                    "IP遮断 ${blockedIps.size} 件 / HTTPS検査 ${if (mitmActive) "ON" else "OFF"}"
                Stats.log("開始: $msg")
                if (st.mitmEnabled && !mitmActive) Stats.log("CA証明書が未インストールのため HTTPS検査は OFF です")
                updateNotification(msg)
            } catch (e: Exception) {
                lastError = e.message ?: e.toString()
                Stats.log("開始失敗: $lastError")
                stopVpn()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun establishTunnel(ips: Map<String, String>): TunWorker {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_DNS, 32)
            .addDnsServer(VPN_DNS)
            .setMtu(1500)
            .setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", PROXY_PORT))
        var hasV6 = false
        var count = 0
        for (ip in ips.keys) {
            try {
                val a = InetAddress.getByName(ip) // 数値表記なので名前解決はしない
                if (a is Inet6Address) {
                    builder.addRoute(a, 128); hasV6 = true
                } else {
                    builder.addRoute(a, 32)
                }
                count++
            } catch (_: Exception) {
            }
        }
        if (hasV6) builder.addAddress(VPN_ADDRESS6, 128)
        // 自分自身は VPN の外に出す（上流への接続がループしないように）
        runCatching { builder.addDisallowedApplication(packageName) }

        val fd = builder.establish()
            ?: throw IllegalStateException("VPNの許可がありません。アプリの画面から開始してください")
        ipRouteCount = count
        return TunWorker(fd).also { it.start() }
    }

    /** 「IPでもブロック」のホストを名前解決する（このアプリは VPN の外なので実際のDNSが使われる） */
    private fun resolveIpBlocks(st: RuleStore): Map<String, String> {
        val result = LinkedHashMap<String, String>()
        for (host in st.ipBlockHosts()) {
            if (result.size >= MAX_IP_ROUTES) break
            try {
                val literal = IPV4.matches(host) || host.contains(':')
                val addrs = if (literal) arrayOf(InetAddress.getByName(host)) else InetAddress.getAllByName(host)
                for (a in addrs) {
                    if (a.isLoopbackAddress || a.isAnyLocalAddress || a.isLinkLocalAddress || a.isSiteLocalAddress) continue
                    val key = a.hostAddress ?: continue
                    result.putIfAbsent(key, host)
                }
            } catch (_: Exception) {
                // 名前解決できないホストは飛ばす
            }
        }
        return result
    }

    /** CDN のIPは変わるので定期的に解決し直す */
    private fun refreshLoop() {
        while (isRunning) {
            try { Thread.sleep(IP_REFRESH_MS) } catch (_: InterruptedException) { break }
            if (!isRunning) break
            refreshIpBlocks()
        }
    }

    private fun refreshIpBlocks() {
        val st = store ?: return
        val newIps = resolveIpBlocks(st)
        synchronized(lock) {
            if (!isRunning) return
            if (newIps.keys == blockedIps.keys) {
                blockedIps = newIps
                return
            }
            try {
                val old = worker
                blockedIps = newIps
                worker = establishTunnel(newIps)
                old?.stop()
                Stats.log("IP遮断リストを更新: ${newIps.size} 件")
            } catch (e: Exception) {
                Stats.log("IP遮断リストの更新に失敗: ${e.message}")
            }
        }
    }

    private fun reload() {
        val st = store ?: return
        st.reloadBypass()
        filter = st.buildEngine()
        Stats.log("ルール再読込: ブロック ${filter.blockRuleCount} 件 / 許可 ${filter.allowRuleCount} 件")
        refreshIpBlocks()
    }

    private fun stopVpn() {
        synchronized(lock) {
            val wasRunning = isRunning
            isRunning = false
            refresher?.interrupt()
            refresher = null
            worker?.stop()
            worker = null
            proxy?.stop()
            proxy = null
            dnsPool?.shutdownNow()
            dnsPool = null
            mitmActive = false
            ipRouteCount = 0
            if (wasRunning) Stats.log("停止しました")
        }
    }

    /** 1つの tun インターフェースを読み続けるスレッド */
    private inner class TunWorker(private val pfd: ParcelFileDescriptor) {
        private val pipe = Os.pipe()
        private val output = FileOutputStream(pfd.fileDescriptor)
        @Volatile private var stopped = false

        fun start() {
            thread(name = "vpn-tun", isDaemon = true) { loop() }
        }

        fun stop() {
            if (stopped) return
            stopped = true
            runCatching { Os.write(pipe[1], byteArrayOf(1), 0, 1) }
            runCatching { Os.close(pipe[1]) }
            runCatching { pfd.close() }
        }

        private fun loop() {
            val tunFd = pfd.fileDescriptor
            val input = FileInputStream(tunFd)
            val buf = ByteArray(32767)
            try {
                while (!stopped) {
                    val pTun = StructPollfd().also { it.fd = tunFd; it.events = OsConstants.POLLIN.toShort() }
                    val pWake = StructPollfd().also { it.fd = pipe[0]; it.events = OsConstants.POLLIN.toShort() }
                    try {
                        Os.poll(arrayOf(pTun, pWake), -1)
                    } catch (e: ErrnoException) {
                        if (e.errno == OsConstants.EINTR) continue else throw e
                    }
                    if (pWake.revents.toInt() != 0) break
                    if ((pTun.revents.toInt() and OsConstants.POLLIN) == 0) continue
                    val n = input.read(buf)
                    if (n < 0) break
                    handlePacket(buf, n, output)
                }
            } catch (e: Exception) {
                if (!stopped) Stats.log("VPN処理エラー: ${e.message}")
            } finally {
                runCatching { Os.close(pipe[0]) }
            }
        }
    }

    private fun handlePacket(buf: ByteArray, n: Int, output: FileOutputStream) {
        val ip = Packets.parseIp(buf, n) ?: return
        if (ip.version == 4 && ip.proto == 17 && ip.dst.contentEquals(VPN_DNS_BYTES)) {
            val udp = Packets.parseIpv4Udp(buf, n) ?: return
            if (udp.dstPort == 53) handleDns(udp, output)
            return
        }
        // ここに来るのは「IPでもブロック」の経路に一致した通信だけ
        val addr = ip.dstAddress
        val host = blockedIps[addr] ?: return
        Stats.ipBlocked.incrementAndGet()
        logIpBlock(host, addr)
        if (ip.proto == 6) Packets.buildTcpRst(buf, ip)?.let { write(output, it) }
        // UDP（QUIC など）は捨てる
    }

    private fun logIpBlock(host: String, addr: String) {
        val now = SystemClock.elapsedRealtime()
        val last = ipLogTimes[addr] ?: 0L
        if (now - last < 60_000) return // 同じIPのログは1分に1回まで
        ipLogTimes[addr] = now
        Stats.log("IP遮断 $host ($addr)")
    }

    private fun handleDns(pkt: Packets.Udp, output: FileOutputStream) {
        val name = Dns.questionName(pkt.payload)
        if (name != null) {
            val f = filter
            val st = store
            val decision = f.checkHost(name)
            val blocked = decision == FilterEngine.Decision.BLOCKED ||
                (decision == FilterEngine.Decision.PASS && st != null && AutoBlocker.tryBlock(f, st, name))
            recordQuery(name, pkt, blocked)
            if (!blocked) return forwardDns(pkt, output)
            Stats.dnsBlocked.incrementAndGet()
            Stats.log("DNS遮断 $name")
            val resp = Dns.blockedResponse(pkt.payload) ?: return
            write(output, Packets.buildIpv4Udp(pkt.dstIp, pkt.srcIp, pkt.dstPort, pkt.srcPort, resp))
            return
        }
        forwardDns(pkt, output)
    }

    /** どのアプリの問い合わせかを調べて履歴に残す（「広告が出た」画面用） */
    private fun recordQuery(name: String, pkt: Packets.Udp, blocked: Boolean) {
        try {
            dnsPool?.execute {
                val uid = try {
                    cm.getConnectionOwnerUid(
                        OsConstants.IPPROTO_UDP,
                        InetSocketAddress(InetAddress.getByAddress(pkt.srcIp), pkt.srcPort),
                        InetSocketAddress(InetAddress.getByAddress(pkt.dstIp), pkt.dstPort),
                    )
                } catch (_: Exception) {
                    -1
                }
                DnsHistory.add(name, uid, blocked, DnsHistory.VIA_DNS)
            }
        } catch (_: Exception) {
        }
    }

    private fun forwardDns(pkt: Packets.Udp, output: FileOutputStream) {
        try {
            dnsPool?.execute {
                try {
                    DatagramSocket().use { s ->
                        protect(s)
                        s.soTimeout = 5000
                        s.send(DatagramPacket(pkt.payload, pkt.payload.size, upstreamDns(), 53))
                        val rb = ByteArray(4096)
                        val rp = DatagramPacket(rb, rb.size)
                        s.receive(rp)
                        write(output, Packets.buildIpv4Udp(pkt.dstIp, pkt.srcIp, pkt.dstPort, pkt.srcPort, rb.copyOf(rp.length)))
                    }
                } catch (_: Exception) {
                    // タイムアウト等。アプリ側が再送する
                }
            }
        } catch (_: Exception) {
            // 停止処理中
        }
    }

    private fun write(out: FileOutputStream, bytes: ByteArray) {
        synchronized(out) {
            try { out.write(bytes) } catch (_: IOException) {}
        }
    }

    /** VPN ではない実ネットワークの DNS サーバーを使う（30秒キャッシュ） */
    @Suppress("DEPRECATION")
    private fun upstreamDns(): InetAddress {
        val now = SystemClock.elapsedRealtime()
        cachedDns?.let { if (now - cachedDnsAt < 30_000) return it }
        val cm = getSystemService(ConnectivityManager::class.java)
        val found = cm.allNetworks
            .mapNotNull { n -> cm.getNetworkCapabilities(n)?.let { n to it } }
            .filter { (_, c) ->
                c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
            .sortedByDescending { (_, c) -> c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) }
            .flatMap { (n, _) -> cm.getLinkProperties(n)?.dnsServers.orEmpty() }
            .firstOrNull { it is Inet4Address }
        val r = found ?: InetAddress.getByName(FALLBACK_DNS)
        cachedDns = r
        cachedDnsAt = now
        return r
    }

    // ---- 通知 ----

    private fun startInForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "広告ブロック", NotificationManager.IMPORTANCE_LOW))
        val n = buildNotification("起動中…")
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val finder = PendingIntent.getActivity(
            this, 2,
            Intent(this, AdFinderActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, AdBlockVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_menu_search), "広告が出た", finder,
                ).build(),
            )
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_media_pause), "停止", stop,
                ).build(),
            )
            .build()
    }

    override fun onRevoke() {
        stopVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
