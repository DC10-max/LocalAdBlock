package com.example.localadblock

/**
 * ドメイン名から「広告っぽさ」を判定する。
 *  STRONG: 既知の広告ネットワーク、または名前が明らかに広告用（ads. / adserver など）→ 自動ブロック対象
 *  WEAK  : 計測・追跡っぽい名前（track / analytics など）→ 候補として表示するだけ
 */
object AdHeuristics {
    enum class Level { STRONG, WEAK, NONE }

    /** rule: ブロックリストに登録するドメイン（サブドメイン含めてブロックされる） */
    class Result(val level: Level, val rule: String, val reason: String)

    /** 既知の広告ネットワーク（ここに一致したらこの単位でブロック） */
    private val NETWORKS = setOf(
        // Google / 一般 DSP・SSP
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
        "adnxs.com", "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "amazon-adsystem.com",
        "adsrvr.org", "rubiconproject.com", "pubmatic.com", "openx.net", "smartadserver.com", "moatads.com",
        // アプリ内広告 SDK
        "applovin.com", "applvn.com", "ironsrc.com", "ironsrc.mobi", "ironsource.mobi", "supersonicads.com",
        "vungle.com", "liftoff.io", "chartboost.com", "inmobi.com", "adcolony.com", "fyber.com",
        "tapjoy.com", "tapjoyads.com", "mintegral.com", "mintegral.net", "rayjump.com", "mtgglobals.com",
        "pangle.io", "pangle-b.io", "pangle-ads.com", "pangolin-sdk-toutiao.com", "pangolin-sdk-toutiao-b.com",
        "pglstatp-toutiao.com", "i18n-pglstatp.com", "moloco.com", "adsmoloco.com", "smaato.net",
        "bidmachine.io", "startappservice.com", "mopub.com", "inner-active.mobi", "digitalturbine.com",
        "adtiming.com", "pubnative.net", "presage.io", "yandexadexchange.net",
        "unityads.unity3d.com", "iads.unity3d.com", "isx.unity3d.com", "mediation.unity3d.com",
        // 計測（アトリビューション）
        "adjust.com", "appsflyer.com", "appsflyersdk.com", "kochava.com",
        // 日本の広告ネットワーク
        "i-mobile.co.jp", "microad.jp", "ad-stir.com", "fluct.jp", "adingo.jp", "impact-ad.jp",
        "nend.net", "zucks.net", "maio.jp", "socdm.com", "gssprt.jp", "logly.co.jp", "popin.cc",
    )

    /** 自動ではブロックしない（壊れると困る）ドメイン */
    private val PROTECTED = setOf(
        "google.com", "googleapis.com", "gstatic.com", "gvt1.com", "gvt2.com", "googlevideo.com",
        "youtube.com", "ytimg.com", "googleusercontent.com", "android.com",
        "apple.com", "icloud.com", "microsoft.com", "windows.net", "live.com", "office.com",
        "cloudfront.net", "akamaihd.net", "akamaized.net", "akamai.net", "edgekey.net", "edgesuite.net",
        "fastly.net", "amazonaws.com", "azureedge.net", "cloudflare.com", "cloudflare.net",
        "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net", "whatsapp.com",
        "line.me", "line-apps.com", "line-scdn.net", "tiktokv.com", "tiktokcdn.com", "byteoversea.com",
        "ibytedtos.com", "twitter.com", "x.com", "twimg.com", "github.com", "githubusercontent.com",
        "localhost", "local",
    )

    private val STRONG_TOKENS = setOf(
        "ad", "ads", "adserver", "adservers", "adserving", "adservice", "adsdk", "adx", "adnet",
        "adnetwork", "adtrack", "adtracking", "rtb", "ssp", "dsp", "bidder", "adsrv", "adsystem",
    )
    private val WEAK_TOKENS = setOf(
        "track", "tracking", "tracker", "analytics", "pixel", "beacon", "auction", "bid", "bidding",
        "imp", "impression", "impressions", "click", "clk", "promo", "creative", "creatives", "banner", "banners",
    )

    fun isProtected(host: String): Boolean = FilterEngine.matchDomain(PROTECTED, FilterEngine.normalize(host))

    fun classify(rawHost: String): Result {
        val host = FilterEngine.normalize(rawHost)
        networkMatch(host)?.let { return Result(Level.STRONG, it, "広告ネットワーク") }
        if (isProtected(host)) return Result(Level.NONE, host, "")
        val tokens = host.split('.').dropLast(1)
            .flatMap { it.split('-', '_') }
            .map { t -> t.trimEnd { it.isDigit() } }
        if (tokens.any { it in STRONG_TOKENS }) return Result(Level.STRONG, host, "広告用の名前")
        if (tokens.any { it in WEAK_TOKENS }) return Result(Level.WEAK, host, "計測・追跡用の名前")
        return Result(Level.NONE, host, "")
    }

    private fun networkMatch(host: String): String? {
        var d = host
        while (true) {
            if (d in NETWORKS) return d
            val i = d.indexOf('.')
            if (i < 0) return null
            d = d.substring(i + 1)
        }
    }
}
