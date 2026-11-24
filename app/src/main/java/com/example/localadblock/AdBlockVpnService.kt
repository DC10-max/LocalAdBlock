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
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * ローカルVPN。
 *  - tun には「仮想DNSサーバー(10.111.222.2)」宛ての経路だけを張る → DNS 問い合わせだけを受け取り、広告ドメインを NXDOMAIN にする
 *  - それ以外の通信は VPN を通らない（通信速度・電池への影響が小さい）
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
        private const val FALLBACK_DNS = "1.1.1.1"
        private const val CHANNEL = "vpn"
        private const val NOTIF_ID = 1

        @Volatile var isRunning = false
            private set
        @Volatile var mitmActive = false
            private set
        @Volatile var lastError: String? = null
    }

    @Volatile private var filter: FilterEngine = FilterEngine.Builder().build()
    private var tun: ParcelFileDescriptor? = null
    private var proxy: MitmProxy? = null
    private var dnsPool: ExecutorService? = null
    private var wakeRead: FileDescriptor? = null
    private var wakeWrite: FileDescriptor? = null
    private var store: RuleStore? = null
    private val lock = Any()

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

                proxy = MitmProxy(PROXY_PORT, { filter }, ca, st, { mitmActive }).also { it.start() }
                dnsPool = Executors.newFixedThreadPool(8)

                val builder = Builder()
                    .setSession(getString(R.string.app_name))
                    .addAddress(VPN_ADDRESS, 32)
                    .addRoute(VPN_DNS, 32)
                    .addDnsServer(VPN_DNS)
                    .setMtu(1500)
                    .setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", PROXY_PORT))
                // 自分自身は VPN の外に出す（上流への接続がループしないように）
                runCatching { builder.addDisallowedApplication(packageName) }

                val fd = builder.establish()
                    ?: throw IllegalStateException("VPNの許可がありません。アプリの画面から開始してください")
                tun = fd
                val pipe = Os.pipe()
                wakeRead = pipe[0]
                wakeWrite = pipe[1]
                isRunning = true
                thread(name = "vpn-dns") { dnsLoop(fd, pipe[0]) }

                val msg = "ブロック規則 ${filter.blockRuleCount} 件 / 許可規則 ${filter.allowRuleCount} 件 / " +
                    "HTTPS検査 ${if (mitmActive) "ON" else "OFF"}"
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

    private fun reload() {
        val st = store ?: return
        st.reloadBypass()
        filter = st.buildEngine()
        Stats.log("ルール再読込: ブロック ${filter.blockRuleCount} 件 / 許可 ${filter.allowRuleCount} 件")
    }

    private fun stopVpn() {
        synchronized(lock) {
            val wasRunning = isRunning
            isRunning = false
            wakeWrite?.let { runCatching { Os.write(it, byteArrayOf(1), 0, 1) } }
            runCatching { tun?.close() }
            tun = null
            proxy?.stop()
            proxy = null
            dnsPool?.shutdownNow()
            dnsPool = null
            wakeWrite?.let { runCatching { Os.close(it) } }
            wakeWrite = null
            mitmActive = false
            if (wasRunning) Stats.log("停止しました")
        }
    }

    private fun dnsLoop(tunPfd: ParcelFileDescriptor, wake: FileDescriptor) {
        val tunFd = tunPfd.fileDescriptor
        val input = FileInputStream(tunFd)
        val output = FileOutputStream(tunFd)
        val buf = ByteArray(32767)
        try {
            while (isRunning) {
                val pTun = StructPollfd().also { it.fd = tunFd; it.events = OsConstants.POLLIN.toShort() }
                val pWake = StructPollfd().also { it.fd = wake; it.events = OsConstants.POLLIN.toShort() }
                try {
                    Os.poll(arrayOf(pTun, pWake), -1)
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EINTR) continue else throw e
                }
                if (pWake.revents.toInt() != 0) break
                if ((pTun.revents.toInt() and OsConstants.POLLIN) == 0) continue
                val n = input.read(buf)
                if (n < 0) break
                val pkt = Packets.parseIpv4Udp(buf, n) ?: continue
                if (pkt.dstPort != 53) continue
                handleDns(pkt, output)
            }
        } catch (e: Exception) {
            if (isRunning) Stats.log("DNS処理エラー: ${e.message}")
        } finally {
            runCatching { Os.close(wake) }
        }
    }

    private fun handleDns(pkt: Packets.Udp, output: FileOutputStream) {
        val name = Dns.questionName(pkt.payload)
        if (name != null && filter.checkHost(name) == FilterEngine.Decision.BLOCKED) {
            Stats.dnsBlocked.incrementAndGet()
            Stats.log("DNS遮断 $name")
            val resp = Dns.blockedResponse(pkt.payload) ?: return
            write(output, Packets.buildIpv4Udp(pkt.dstIp, pkt.srcIp, pkt.dstPort, pkt.srcPort, resp))
            return
        }
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
