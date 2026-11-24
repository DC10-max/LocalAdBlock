package com.example.localadblock

import android.content.Context
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/** 許可リスト・ブロックリスト・購読リスト・バイパス設定の保存と読み込み */
class RuleStore(private val ctx: Context) {
    private val dir = File(ctx.filesDir, "rules").apply { mkdirs() }
    private val listsDir = File(dir, "lists").apply { mkdirs() }

    val allowFile = File(dir, "allowlist.txt")
    val customBlockFile = File(dir, "custom_block.txt")
    val subscriptionsFile = File(dir, "subscriptions.txt")
    val bypassFile = File(dir, "bypass.txt")
    val ipBlockFile = File(dir, "ip_block.txt")
    private val autoBypassFile = File(dir, "auto_bypass.txt")

    private val prefs = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)

    @Volatile private var bypass: Set<String> = emptySet()
    private val autoBypass: MutableSet<String> = Collections.newSetFromMap(ConcurrentHashMap())

    init {
        ensureDefaults()
        reloadBypass()
    }

    /** 広告っぽい通信先を自動で追加ブロックリストに登録する */
    var autoBlockEnabled: Boolean
        get() = prefs.getBoolean("autoBlock", true)
        set(v) = prefs.edit().putBoolean("autoBlock", v).apply()

    /** 追加ブロックリストの末尾に ||domain^ 形式で追記する。追加した行を返す */
    fun appendBlockRules(domains: Collection<String>, header: String): List<String> = synchronized(FILE_LOCK) {
        val existing = readText(customBlockFile).lines().map { it.trim().lowercase() }.toSet()
        val toAdd = domains.map { "||${FilterEngine.normalize(it)}^" }.distinct().filter { it !in existing }
        if (toAdd.isEmpty()) return emptyList()
        val cur = readText(customBlockFile)
        val sb = StringBuilder()
        if (cur.isNotEmpty() && !cur.endsWith("\n")) sb.append('\n')
        sb.append("! ").append(header).append('\n')
        toAdd.forEach { sb.append(it).append('\n') }
        customBlockFile.appendText(sb.toString())
        toAdd
    }

    var mitmEnabled: Boolean
        get() = prefs.getBoolean("mitm", true)
        set(v) = prefs.edit().putBoolean("mitm", v).apply()

    private fun ensureDefaults() {
        listOf(
            allowFile to "default_allowlist.txt",
            customBlockFile to "default_custom_block.txt",
            subscriptionsFile to "default_subscriptions.txt",
            bypassFile to "default_bypass.txt",
            ipBlockFile to "default_ip_block.txt",
        ).forEach { (f, asset) ->
            if (!f.exists()) ctx.assets.open(asset).use { i -> f.outputStream().use { i.copyTo(it) } }
        }
    }

    fun readText(f: File): String = if (f.exists()) f.readText() else ""

    fun writeText(f: File, text: String) {
        f.writeText(text)
        if (f == bypassFile) reloadBypass()
    }

    // ---- バイパス（HTTPS検査をしないホスト） ----

    fun reloadBypass() {
        bypass = readDomainList(bypassFile)
        autoBypass.clear()
        autoBypass.addAll(readDomainList(autoBypassFile))
    }

    private fun readDomainList(f: File): Set<String> =
        if (!f.exists()) emptySet()
        else f.readLines()
            .map { it.substringBefore('#').trim().lowercase().removePrefix("*.").removePrefix("||").removeSuffix("^") }
            .filter { it.isNotEmpty() }
            .toSet()

    fun isBypassed(host: String): Boolean {
        val h = FilterEngine.normalize(host)
        return FilterEngine.matchDomain(bypass, h) || h in autoBypass
    }

    @Synchronized
    fun addAutoBypass(host: String) {
        val h = FilterEngine.normalize(host)
        if (autoBypass.add(h)) autoBypassFile.appendText(h + "\n")
    }

    fun autoBypassList(): List<String> = readDomainList(autoBypassFile).sorted()

    @Synchronized
    fun clearAutoBypass() {
        autoBypass.clear()
        autoBypassFile.delete()
    }

    // ---- IPブロック（DNSを使わないアプリ対策） ----

    /** IPアドレスでも遮断するホスト名（またはIPアドレス）の一覧 */
    fun ipBlockHosts(): List<String> =
        readText(ipBlockFile).lines()
            .map { it.substringBefore('#').trim().lowercase().removePrefix("||").removeSuffix("^") }
            .filter { it.isNotEmpty() && !it.startsWith("!") && !it.contains('/') && !it.contains('*') }
            .distinct()

    // ---- 購読リスト ----

    fun subscriptionUrls(): List<String> =
        readText(subscriptionsFile).lines().map { it.trim() }.filter { it.startsWith("http") }

    private fun fileFor(url: String): File {
        val hash = MessageDigest.getInstance("SHA-1").digest(url.toByteArray()).joinToString("") { "%02x".format(it) }
        return File(listsDir, "$hash.txt")
    }

    /** 購読リストをダウンロードする（ネットワーク処理なのでバックグラウンドで呼ぶこと） */
    fun updateSubscriptions(): String {
        val urls = subscriptionUrls()
        val keep = urls.map { fileFor(it).name }.toSet()
        listsDir.listFiles()?.filter { it.name !in keep }?.forEach { it.delete() }
        val sb = StringBuilder()
        for (u in urls) {
            try {
                val conn = URL(u).openConnection() as HttpURLConnection
                conn.connectTimeout = 15_000
                conn.readTimeout = 30_000
                conn.setRequestProperty("User-Agent", "LocalAdBlock/0.1")
                if (conn.responseCode != 200) throw IOException("HTTP ${conn.responseCode}")
                val tmp = File(listsDir, "download.tmp")
                conn.inputStream.use { i -> tmp.outputStream().use { i.copyTo(it) } }
                val dest = fileFor(u)
                dest.delete()
                tmp.renameTo(dest)
                sb.append("OK  ").append(u).append('\n')
            } catch (e: Exception) {
                sb.append("NG  ").append(u).append(" : ").append(e.message).append('\n')
            }
        }
        return sb.toString()
    }

    companion object {
        private val FILE_LOCK = Any()
    }

    fun buildEngine(): FilterEngine {
        val b = FilterEngine.Builder()
        ctx.assets.open("default_blocklist.txt").bufferedReader().useLines { lines -> lines.forEach { b.addBlockLine(it) } }
        if (customBlockFile.exists()) customBlockFile.forEachLine { b.addBlockLine(it) }
        listsDir.listFiles()?.filter { it.name.endsWith(".txt") }?.forEach { f -> f.forEachLine { b.addBlockLine(it) } }
        if (allowFile.exists()) allowFile.forEachLine { b.addAllowLine(it) }
        return b.build()
    }
}
