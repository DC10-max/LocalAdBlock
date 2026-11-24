package com.example.localadblock

import android.Manifest
import android.app.Activity
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import kotlin.concurrent.thread

class MainActivity : Activity() {
    private lateinit var store: RuleStore
    private val handler = Handler(Looper.getMainLooper())

    private lateinit var tvStatus: TextView
    private lateinit var tvStats: TextView
    private lateinit var tvLog: TextView
    private lateinit var tvCa: TextView
    private lateinit var tvSubsResult: TextView
    private lateinit var tvAutoBypass: TextView
    private lateinit var tvWarn: TextView
    private lateinit var etIpBlock: EditText
    private lateinit var btnToggle: Button
    private lateinit var swMitm: Switch
    private lateinit var swAuto: Switch
    private lateinit var etAllow: EditText
    private lateinit var etBlock: EditText
    private lateinit var etSubs: EditText
    private lateinit var etBypass: EditText

    private val refresher = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        store = RuleStore(this)

        tvStatus = findViewById(R.id.tvStatus)
        tvStats = findViewById(R.id.tvStats)
        tvLog = findViewById(R.id.tvLog)
        tvCa = findViewById(R.id.tvCa)
        tvSubsResult = findViewById(R.id.tvSubsResult)
        tvAutoBypass = findViewById(R.id.tvAutoBypass)
        tvWarn = findViewById(R.id.tvWarn)
        etIpBlock = findViewById(R.id.etIpBlock)
        btnToggle = findViewById(R.id.btnToggle)
        swMitm = findViewById(R.id.swMitm)
        swAuto = findViewById(R.id.swAuto)
        etAllow = findViewById(R.id.etAllow)
        etBlock = findViewById(R.id.etBlock)
        etSubs = findViewById(R.id.etSubs)
        etBypass = findViewById(R.id.etBypass)

        etAllow.setText(store.readText(store.allowFile))
        etBlock.setText(store.readText(store.customBlockFile))
        etSubs.setText(store.readText(store.subscriptionsFile))
        etBypass.setText(store.readText(store.bypassFile))
        etIpBlock.setText(store.readText(store.ipBlockFile))

        swMitm.isChecked = store.mitmEnabled
        swMitm.setOnCheckedChangeListener { _, checked ->
            store.mitmEnabled = checked
            toast("次回の開始から反映されます")
        }

        swAuto.isChecked = store.autoBlockEnabled
        swAuto.setOnCheckedChangeListener { _, checked -> store.autoBlockEnabled = checked }
        findViewById<Button>(R.id.btnFinder).setOnClickListener {
            startActivity(Intent(this, AdFinderActivity::class.java))
        }

        btnToggle.setOnClickListener {
            if (AdBlockVpnService.isRunning) sendToService(AdBlockVpnService.ACTION_STOP) else requestStart()
        }
        findViewById<Button>(R.id.btnExportCa).setOnClickListener { exportCa() }
        findViewById<Button>(R.id.btnOpenSettings).setOnClickListener {
            startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
        }
        findViewById<Button>(R.id.btnSaveRules).setOnClickListener {
            store.writeText(store.allowFile, etAllow.text.toString())
            store.writeText(store.customBlockFile, etBlock.text.toString())
            store.writeText(store.ipBlockFile, etIpBlock.text.toString())
            reloadService()
            toast("保存しました")
        }
        findViewById<Button>(R.id.btnUpdateSubs).setOnClickListener {
            store.writeText(store.subscriptionsFile, etSubs.text.toString())
            tvSubsResult.text = "ダウンロード中…"
            thread {
                val result = store.updateSubscriptions()
                runOnUiThread {
                    tvSubsResult.text = result
                    reloadService()
                }
            }
        }
        findViewById<Button>(R.id.btnSaveBypass).setOnClickListener {
            store.writeText(store.bypassFile, etBypass.text.toString())
            reloadService()
            toast("保存しました")
        }
        findViewById<Button>(R.id.btnClearAuto).setOnClickListener {
            store.clearAutoBypass()
            reloadService()
            refreshAutoBypass()
            toast("自動バイパスを消去しました")
        }

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresher)
        refreshCaState()
        refreshAutoBypass()
        refreshWarnings()
        // 自動登録・広告探しで追記された内容を反映（編集中は上書きしない）
        if (!etBlock.hasFocus()) etBlock.setText(store.readText(store.customBlockFile))
    }

    /** DNSブロックを迂回させる設定を検出して警告する */
    @Suppress("DEPRECATION")
    private fun refreshWarnings() {
        val strict = try {
            val cm = getSystemService(ConnectivityManager::class.java)
            cm.allNetworks.any { n ->
                val c = cm.getNetworkCapabilities(n)
                c != null && !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    cm.getLinkProperties(n)?.privateDnsServerName != null
            }
        } catch (e: Exception) {
            false
        }
        if (strict) {
            tvWarn.text = "⚠ プライベートDNSが「ホスト名を指定」になっています。DNSでのブロックが効かない場合があります。" +
                "設定 → ネットワーク → プライベートDNS を「自動」か「OFF」にしてください。"
            tvWarn.visibility = android.view.View.VISIBLE
        } else {
            tvWarn.visibility = android.view.View.GONE
        }
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refresher)
    }

    private fun requestStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, REQ_VPN) else startVpnService()
    }

    @Deprecated("Activity#onActivityResult")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) startVpnService()
    }

    private fun startVpnService() {
        startForegroundService(Intent(this, AdBlockVpnService::class.java).setAction(AdBlockVpnService.ACTION_START))
    }

    private fun sendToService(action: String) {
        startService(Intent(this, AdBlockVpnService::class.java).setAction(action))
    }

    private fun reloadService() {
        if (AdBlockVpnService.isRunning) sendToService(AdBlockVpnService.ACTION_RELOAD)
    }

    private fun exportCa() {
        thread {
            try {
                val der = CertificateAuthority.get(this).caDer()
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, "LocalAdBlock-CA.crt")
                    put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: throw IllegalStateException("保存先を作れませんでした")
                contentResolver.openOutputStream(uri)!!.use { it.write(der) }
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                contentResolver.update(uri, values, null, null)
                runOnUiThread {
                    toast("「ダウンロード」に LocalAdBlock-CA.crt を保存しました")
                }
            } catch (e: Exception) {
                runOnUiThread { toast("保存に失敗: ${e.message}") }
            }
        }
    }

    private fun refreshCaState() {
        tvCa.text = "確認中…"
        thread {
            val ok = CertificateAuthority.get(this).isInstalledInUserStore()
            runOnUiThread {
                tvCa.text = if (ok) {
                    "✅ CA証明書はインストール済みです"
                } else {
                    "⚠ CA証明書が未インストールです。HTTPS検査を使うには:\n" +
                        "1.「CA証明書を保存」を押す\n" +
                        "2.「設定を開く」→ 暗号化と認証情報 → 証明書のインストール → CA証明書\n" +
                        "3.「ダウンロード」の LocalAdBlock-CA.crt を選ぶ\n" +
                        "（機種により項目名が異なります。設定の検索で「CA証明書」と入力しても見つかります）"
                }
            }
        }
    }

    private fun refreshAutoBypass() {
        val list = store.autoBypassList()
        tvAutoBypass.text = if (list.isEmpty()) "（なし）" else list.joinToString("\n")
    }

    private fun refresh() {
        val running = AdBlockVpnService.isRunning
        tvStatus.text = when {
            running -> "● 動作中（HTTPS検査: ${if (AdBlockVpnService.mitmActive) "ON" else "OFF"}）"
            AdBlockVpnService.lastError != null -> "停止中 — ${AdBlockVpnService.lastError}"
            else -> "停止中"
        }
        btnToggle.text = if (running) "停止" else "開始"
        tvStats.text = "DNSで遮断: ${Stats.dnsBlocked.get()}　URLで遮断: ${Stats.httpBlocked.get()}\n" +
            "IPで遮断: ${Stats.ipBlocked.get()}（対象 ${AdBlockVpnService.ipRouteCount} 件）　自動登録: ${Stats.autoAdded.get()}\n" +
            "許可リストで通過: ${Stats.allowedByList.get()}　HTTPS検査不可: ${Stats.tlsBypassed.get()}"
        tvLog.text = Stats.recent().take(60).joinToString("\n")
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

    companion object {
        private const val REQ_VPN = 1
        private const val REQ_NOTIF = 2
    }
}
