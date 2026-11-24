package com.example.localadblock

/** 直近の通信先（DNS問い合わせ・プロキシ接続）の履歴。「広告が出た」画面で使う */
object DnsHistory {
    const val VIA_DNS = "DNS"
    const val VIA_PROXY = "プロキシ"

    class Entry(val time: Long, val host: String, val uid: Int, val blocked: Boolean, val via: String)

    private val entries = ArrayDeque<Entry>()

    @Synchronized
    fun add(host: String, uid: Int, blocked: Boolean, via: String) {
        entries.addLast(Entry(System.currentTimeMillis(), FilterEngine.normalize(host), uid, blocked, via))
        while (entries.size > 5000) entries.removeFirst()
    }

    @Synchronized
    fun since(ms: Long): List<Entry> {
        val t = System.currentTimeMillis() - ms
        return entries.filter { it.time >= t }
    }
}
