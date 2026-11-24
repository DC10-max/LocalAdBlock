package com.example.localadblock

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/** 広告っぽい通信先を見つけたら、その場で遮断して追加ブロックリストに登録する */
object AutoBlocker {
    private val pool = Executors.newSingleThreadExecutor()
    private val fmt = SimpleDateFormat("MM/dd HH:mm", Locale.US)

    /** ブロックした場合 true */
    fun tryBlock(filter: FilterEngine, store: RuleStore, host: String): Boolean {
        if (!store.autoBlockEnabled || filter.isUserAllowed(host)) return false
        val r = AdHeuristics.classify(host)
        if (r.level != AdHeuristics.Level.STRONG) return false
        filter.addDynamicBlock(r.rule)
        Stats.autoAdded.incrementAndGet()
        Stats.log("自動ブロック追加 ${r.rule}（${r.reason}: $host）")
        val header = synchronized(fmt) { "自動追加 ${fmt.format(Date())} ${r.reason}" }
        pool.execute { runCatching { store.appendBlockRules(listOf(r.rule), header) } }
        return true
    }
}
