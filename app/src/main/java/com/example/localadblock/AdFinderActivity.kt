package com.example.localadblock

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.os.Process
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * 「広告が出た」画面。
 * 直前の数分間に各アプリが通信したドメインを一覧にして、選んだものを追加ブロックリストに登録する。
 */
class AdFinderActivity : Activity() {
    private lateinit var list: LinearLayout
    private lateinit var tvHeader: TextView
    private var rangeMin = 3
    private val checks = ArrayList<Triple<CheckBox, String, String>>() // チェック, ホスト, 登録するルール
    private val justAdded = HashSet<String>()
    private val labelCache = HashMap<Int, String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = dp(16)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            fitsSystemWindows = true
        }
        root.addView(TextView(this).apply {
            text = "広告を見つける"
            textSize = 20f
            setTypeface(typeface, Typeface.BOLD)
        })
        tvHeader = TextView(this).apply { setPadding(0, dp(4), 0, dp(8)) }
        root.addView(tvHeader)

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        listOf(1, 3, 10).forEach { m ->
            row.addView(Button(this).apply {
                text = "${m}分"
                setOnClickListener { rangeMin = m; render() }
            }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        }
        row.addView(Button(this).apply {
            text = "更新"
            setOnClickListener { render() }
        }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        root.addView(row)

        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(ScrollView(this).apply { addView(list) }, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        root.addView(Button(this).apply {
            text = "チェックしたものを追加ブロックリストに登録"
            setOnClickListener { blockChecked() }
        }, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        setContentView(root)
        render()
    }

    private fun render() {
        list.removeAllViews()
        checks.clear()
        val entries = DnsHistory.since(rangeMin * 60_000L)
        val blockedHosts = entries.filter { it.blocked }.map { it.host }.toSet()
        val candidates = entries.filter { !it.blocked && it.host !in blockedHosts && it.host !in justAdded }

        tvHeader.text = "直前${rangeMin}分間に通信したドメインです（ブロック済み ${blockedHosts.size} 件は非表示）。\n" +
            "広告が出たアプリの欄から、ブロックするものにチェックを入れてください。\n" +
            "★ 広告の可能性が高い（最初からチェック済み）　☆ 計測・追跡の可能性"

        if (!AdBlockVpnService.isRunning) {
            list.addView(TextView(this).apply { text = "VPNが停止中です。開始してから広告を表示させてください。" })
        }
        if (candidates.isEmpty()) {
            list.addView(TextView(this).apply { text = "該当する通信はありません。" })
            return
        }

        val groups = candidates.groupBy { appLabel(it.uid, it.via) }
            .entries.sortedByDescending { (_, es) -> es.maxOf { it.time } }
        for ((app, es) in groups) {
            list.addView(TextView(this).apply {
                text = app
                textSize = 16f
                setTypeface(typeface, Typeface.BOLD)
                setPadding(0, dp(12), 0, dp(4))
            })
            val hosts = es.groupBy { it.host }
                .map { (h, v) -> h to v.maxOf { it.time } }
                .sortedWith(compareByDescending<Pair<String, Long>> { AdHeuristics.classify(it.first).level == AdHeuristics.Level.STRONG }
                    .thenByDescending { it.second })
            for ((host, _) in hosts) {
                val r = AdHeuristics.classify(host)
                val mark = when (r.level) {
                    AdHeuristics.Level.STRONG -> "★ "
                    AdHeuristics.Level.WEAK -> "☆ "
                    AdHeuristics.Level.NONE -> ""
                }
                val cb = CheckBox(this).apply {
                    text = mark + host + if (r.rule != host) "\n   → ${r.rule} ごとブロック" else ""
                    textSize = 13f
                    isChecked = r.level == AdHeuristics.Level.STRONG
                }
                list.addView(cb)
                checks += Triple(cb, host, r.rule)
            }
        }
    }

    private fun blockChecked() {
        val rules = checks.filter { it.first.isChecked }.map { it.third }.distinct()
        if (rules.isEmpty()) {
            toast("チェックされたものがありません")
            return
        }
        val header = "広告探しで追加 " + SimpleDateFormat("MM/dd HH:mm", Locale.US).format(Date())
        thread {
            val added = RuleStore(this).appendBlockRules(rules, header)
            runOnUiThread {
                justAdded += checks.filter { it.first.isChecked }.map { it.second }
                toast(if (added.isEmpty()) "すでに登録済みでした" else "${added.size} 件を追加ブロックリストに登録しました")
                if (AdBlockVpnService.isRunning) {
                    startService(Intent(this, AdBlockVpnService::class.java).setAction(AdBlockVpnService.ACTION_RELOAD))
                }
                render()
            }
        }
    }

    private fun appLabel(uid: Int, via: String): String {
        if (uid < 0) return if (via == DnsHistory.VIA_PROXY) "ブラウザなど（プロキシ経由）" else "アプリ不明"
        return labelCache.getOrPut(uid) {
            if (uid < Process.FIRST_APPLICATION_UID) {
                "システム（アプリを特定できません）"
            } else {
                val pkg = packageManager.getPackagesForUid(uid)?.firstOrNull()
                if (pkg == null) {
                    "UID $uid"
                } else {
                    try {
                        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
                    } catch (e: Exception) {
                        pkg
                    }
                }
            }
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
}
