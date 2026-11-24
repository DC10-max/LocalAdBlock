package com.example.localadblock

/** 画面で「許可する／しない」を選べる主な広告ネットワーク */
object AdNetworks {
    class Network(val id: String, val name: String, val domains: List<String>)

    val all: List<Network> = listOf(
        Network("google", "Google（AdMob / AdSense）", listOf("doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com")),
        Network("applovin", "AppLovin（MAX）", listOf("applovin.com", "applvn.com")),
        Network("unity", "Unity Ads", listOf("unityads.unity3d.com", "iads.unity3d.com", "isx.unity3d.com", "mediation.unity3d.com")),
        Network("ironsource", "ironSource（LevelPlay）", listOf("ironsrc.com", "ironsrc.mobi", "ironsource.mobi", "supersonicads.com")),
        Network("pangle", "Pangle（TikTok系）", listOf("pangle.io", "pangle-b.io", "pangle-ads.com", "pangolin-sdk-toutiao.com", "pangolin-sdk-toutiao-b.com", "pglstatp-toutiao.com", "i18n-pglstatp.com")),
        Network("mintegral", "Mintegral", listOf("mintegral.com", "mintegral.net", "rayjump.com", "mtgglobals.com")),
        Network("moloco", "Moloco", listOf("moloco.com", "adsmoloco.com")),
        Network("liftoff", "Liftoff / Vungle", listOf("vungle.com", "liftoff.io")),
        Network("dtexchange", "DT Exchange（Fyber）", listOf("fyber.com", "inner-active.mobi", "digitalturbine.com")),
        Network("chartboost", "Chartboost", listOf("chartboost.com")),
        Network("inmobi", "InMobi", listOf("inmobi.com")),
        Network("amazon", "Amazon 広告", listOf("amazon-adsystem.com")),
        Network("maio", "maio", listOf("maio.jp")),
        Network("nend", "nend", listOf("nend.net")),
        Network("imobile", "i-mobile", listOf("i-mobile.co.jp")),
        Network("zucks", "Zucks", listOf("zucks.net")),
    )

    /** host がどの広告ネットワークのものか（一覧にあるものだけ） */
    fun find(host: String): Network? {
        val h = FilterEngine.normalize(host)
        return all.firstOrNull { n -> FilterEngine.matchDomain(n.domains.toSet(), h) }
    }
}
