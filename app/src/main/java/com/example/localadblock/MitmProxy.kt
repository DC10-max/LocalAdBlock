package com.example.localadblock

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.thread

/**
 * 127.0.0.1 で待ち受ける HTTP/HTTPS プロキシ。VPN の setHttpProxy() で各アプリに配布される。
 *
 *  - CONNECT 時点でホスト名をチェック（ブロック対象なら 403）
 *  - HTTPS検査が有効かつバイパス対象でなければ、自前CAで TLS を終端して URL 単位で判定
 *  - 許可リストに一致したものは必ず通す
 *  - 上流サーバーの証明書は通常どおり厳密に検証する
 */
class MitmProxy(
    private val port: Int,
    private val filter: () -> FilterEngine,
    private val ca: CertificateAuthority,
    private val store: RuleStore,
    private val mitmActive: () -> Boolean,
) {
    private var server: ServerSocket? = null
    private val pool: ExecutorService = Executors.newCachedThreadPool()
    @Volatile private var running = false
    private val upstreamFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
    private val hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()

    fun start() {
        val s = ServerSocket()
        s.reuseAddress = true
        s.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 256)
        server = s
        running = true
        thread(name = "proxy-accept", isDaemon = true) {
            while (running) {
                val c = try { s.accept() } catch (e: IOException) { break }
                pool.execute { handleClient(c) }
            }
        }
    }

    fun stop() {
        running = false
        runCatching { server?.close() }
        pool.shutdownNow()
    }

    private fun handleClient(client: Socket) {
        try {
            client.soTimeout = 30_000
            client.tcpNoDelay = true
            val cin = BufferedInputStream(client.getInputStream())
            val cout = BufferedOutputStream(client.getOutputStream())
            val head = HttpHead.read(cin) ?: return
            if (head.method.equals("CONNECT", ignoreCase = true)) {
                handleConnect(client, cin, cout, head)
            } else {
                serveHttp(client, cin, cout, head, connectHost = null, connectPort = 80, tls = false)
            }
        } catch (_: Exception) {
        } finally {
            runCatching { client.close() }
        }
    }

    private fun handleConnect(client: Socket, cin: BufferedInputStream, cout: OutputStream, head: HttpHead) {
        val (host, port) = splitHostPort(head.target, 443) ?: return writeSimple(cout, 400, "Bad Request")
        // 200 を返す前に判定する（クライアントは 200 を受け取るまで TLS を始めない）
        val inspect = mitmActive() && !store.isBypassed(host) && cin.available() == 0
        if (filter().checkHost(host, inspectable = inspect) == FilterEngine.Decision.BLOCKED) {
            Stats.httpBlocked.incrementAndGet()
            Stats.log("接続遮断 $host")
            writeSimple(cout, 403, "Blocked by LocalAdBlock")
            return
        }
        cout.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
        cout.flush()
        if (inspect) intercept(client, host, port) else tunnel(client, cin, host, port)
    }

    /** 中身を見ずにそのまま中継 */
    private fun tunnel(client: Socket, cin: InputStream, host: String, port: Int) {
        Socket().use { up ->
            up.connect(InetSocketAddress(host, port), 10_000)
            up.tcpNoDelay = true
            client.soTimeout = 0
            relay(cin, client.getOutputStream(), up.getInputStream(), up.getOutputStream()) {
                runCatching { client.close() }
                runCatching { up.close() }
            }
        }
    }

    /** 自前CAで TLS を終端して中身を検査 */
    private fun intercept(client: Socket, host: String, port: Int) {
        val ssl = ca.sslContextFor(host).socketFactory
            .createSocket(client, client.inetAddress.hostAddress, client.port, true) as SSLSocket
        ssl.useClientMode = false
        try {
            ssl.startHandshake()
        } catch (e: SSLException) {
            // CAを信頼しないアプリ・証明書ピンニングしているアプリ。次回からは素通しにする
            store.addAutoBypass(host)
            Stats.tlsBypassed.incrementAndGet()
            Stats.log("HTTPS検査不可 → 以後バイパス: $host")
            runCatching { ssl.close() }
            return
        } catch (e: IOException) {
            runCatching { ssl.close() }
            return
        }
        ssl.use {
            it.soTimeout = 60_000
            serveHttp(it, BufferedInputStream(it.inputStream), BufferedOutputStream(it.outputStream), null, host, port, tls = true)
        }
    }

    private class Target(val host: String, val port: Int, val originForm: String, val url: String, val secure: Boolean)

    private fun serveHttp(
        sock: Socket, cin: InputStream, cout: OutputStream,
        first: HttpHead?, connectHost: String?, connectPort: Int, tls: Boolean,
    ) {
        var head = first ?: HttpHead.read(cin) ?: return
        while (true) {
            val target = resolveTarget(head, connectHost, connectPort, tls) ?: return writeSimple(cout, 400, "Bad Request")
            when (filter().checkUrl(target.url, target.host)) {
                FilterEngine.Decision.BLOCKED -> {
                    Stats.httpBlocked.incrementAndGet()
                    Stats.log("遮断 ${shorten(target.url)}")
                    HttpBody.skip(head, cin)
                    cout.write(BLOCKED_RESPONSE)
                    cout.flush()
                    head = HttpHead.read(cin) ?: return // keep-alive で次のリクエストへ
                    continue
                }
                FilterEngine.Decision.ALLOWED_BY_LIST -> {
                    Stats.allowedByList.incrementAndGet()
                    Stats.log("許可リスト ${shorten(target.url)}")
                }
                FilterEngine.Decision.PASS -> {}
            }
            forward(sock, head, cin, cout, target)
            return // 転送したリクエストは Connection: close で 1 往復ごとに閉じる
        }
    }

    private fun resolveTarget(head: HttpHead, connectHost: String?, connectPort: Int, tls: Boolean): Target? {
        val t = head.target
        if (t.startsWith("http://", true) || t.startsWith("https://", true)) {
            val uri = try { URI(t) } catch (e: Exception) { return null }
            val host = uri.host?.removePrefix("[")?.removeSuffix("]") ?: return null
            val secure = uri.scheme.equals("https", true)
            val port = if (uri.port != -1) uri.port else if (secure) 443 else 80
            val origin = (uri.rawPath?.ifEmpty { "/" } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
            return Target(host, port, origin, t, secure)
        }
        val defaultPort = if (tls) 443 else 80
        val hostHeader = head.header("Host")?.let { splitHostPort(it, defaultPort) }
        val host = connectHost ?: hostHeader?.first ?: return null
        val port = if (connectHost != null) connectPort else hostHeader?.second ?: defaultPort
        val scheme = if (tls) "https" else "http"
        val url = "$scheme://$host${if (port != defaultPort) ":$port" else ""}$t"
        return Target(host, port, t, url, tls)
    }

    private fun forward(sock: Socket, head: HttpHead, cin: InputStream, cout: OutputStream, target: Target) {
        val upstream = try {
            openUpstream(target)
        } catch (e: Exception) {
            runCatching { HttpBody.skip(head, cin) }
            writeSimple(cout, 502, "Upstream error: ${e.message}")
            return
        }
        upstream.use { up ->
            up.soTimeout = 60_000
            val uout = BufferedOutputStream(up.getOutputStream())
            val uin = up.getInputStream()
            val upgrade = head.header("Upgrade")

            if (head.header("Expect")?.contains("100-continue", true) == true) {
                cout.write("HTTP/1.1 100 Continue\r\n\r\n".toByteArray())
                cout.flush()
            }
            val sb = StringBuilder()
            sb.append(head.method).append(' ').append(target.originForm).append(' ').append(head.version).append("\r\n")
            for ((k, v) in head.headers) {
                if (k.lowercase() in HOP_HEADERS) continue
                sb.append(k).append(": ").append(v).append("\r\n")
            }
            if (upgrade != null) sb.append("Connection: Upgrade\r\nUpgrade: ").append(upgrade).append("\r\n")
            else sb.append("Connection: close\r\n")
            sb.append("\r\n")
            uout.write(sb.toString().toByteArray(Charsets.ISO_8859_1))

            if (upgrade != null) { // WebSocket など
                uout.flush()
                sock.soTimeout = 0
                up.soTimeout = 0
                relay(cin, cout, uin, uout) {
                    runCatching { sock.close() }
                    runCatching { up.close() }
                }
                return
            }
            HttpBody.copy(head, cin, uout)
            uout.flush()
            pump(uin, cout)
        }
    }

    private fun openUpstream(t: Target): Socket {
        val raw = Socket()
        raw.connect(InetSocketAddress(t.host, t.port), 10_000)
        raw.tcpNoDelay = true
        if (!t.secure) return raw
        val ssl = upstreamFactory.createSocket(raw, t.host, t.port, true) as SSLSocket
        ssl.startHandshake()
        if (!hostnameVerifier.verify(t.host, ssl.session)) {
            ssl.close()
            throw SSLPeerUnverifiedException("証明書のホスト名が一致しません: ${t.host}")
        }
        return ssl
    }

    /** 双方向中継。どちらかが終わったら両方閉じる */
    private fun relay(aIn: InputStream, aOut: OutputStream, bIn: InputStream, bOut: OutputStream, close: () -> Unit) {
        val t = thread(isDaemon = true) {
            try { pump(aIn, bOut) } catch (_: Exception) {} finally { close() }
        }
        try { pump(bIn, aOut) } catch (_: Exception) {} finally { close() }
        t.join(1000)
    }

    private fun writeSimple(out: OutputStream, code: Int, msg: String) {
        val body = msg.toByteArray()
        val reason = when (code) { 400 -> "Bad Request"; 403 -> "Forbidden"; 502 -> "Bad Gateway"; else -> "Error" }
        out.write(
            ("HTTP/1.1 $code $reason\r\nContent-Type: text/plain; charset=utf-8\r\n" +
                "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n").toByteArray(),
        )
        out.write(body)
        out.flush()
    }

    private fun shorten(url: String) = if (url.length > 120) url.take(117) + "..." else url

    companion object {
        private val BLOCKED_RESPONSE = (
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n" +
                "Access-Control-Allow-Origin: *\r\nCache-Control: no-store\r\n\r\n"
            ).toByteArray()
        private val HOP_HEADERS = setOf(
            "connection", "proxy-connection", "keep-alive", "proxy-authorization",
            "proxy-authenticate", "te", "trailer", "upgrade", "expect",
        )
    }
}
