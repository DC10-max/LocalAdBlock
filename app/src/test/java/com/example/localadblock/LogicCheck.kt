import com.example.localadblock.*
import com.example.localadblock.FilterEngine.Decision.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

fun check(name: String, cond: Boolean) { println((if (cond) "PASS " else "FAIL ") + name); if (!cond) failed++ }
var failed = 0

fun main() {
    val b = FilterEngine.Builder()
    listOf(
        "! comment", "[Adblock Plus 2.0]", "example.com##.ad", "||doubleclick.net^", "||ads.example.com^\$third-party",
        "||tracker.example^\$domain=foo.com", "0.0.0.0 hostsad.example # c", "||cdn.example.com/ads/*", "/banner/ad_",
        "@@||doubleclick.net/allowed/", "|https://exact.example/x.js|", "ads.js", "/regex.*/",
    ).forEach { b.addBlockLine(it) }
    listOf("good-ads.example", "||partner.ads.example.com/campaign/*").forEach { b.addAllowLine(it) }
    b.addBlockLine("||good-ads.example^")
    val f = b.build()

    check("exception host inspectable", f.checkHost("doubleclick.net", inspectable = true) == PASS)
    check("domain block", f.checkHost("doubleclick.net") == BLOCKED)
    check("subdomain block", f.checkHost("stats.g.doubleclick.net") == BLOCKED)
    check("not suffix-substring", f.checkHost("notdoubleclick.net") == PASS)
    check("hosts format", f.checkHost("hostsad.example") == BLOCKED)
    check("domain= rule skipped", f.checkHost("tracker.example") == PASS)
    check("allowlist beats blocklist", f.checkHost("good-ads.example") == ALLOWED_BY_LIST)
    check("URL-allowed host not DNS-blocked", f.checkHost("partner.ads.example.com") == PASS)
    check("other subdomain still blocked", f.checkHost("x.ads.example.com") == BLOCKED)
    check("url allowed", f.checkUrl("https://partner.ads.example.com/campaign/1.png", "partner.ads.example.com") == ALLOWED_BY_LIST)
    check("url not allowed path", f.checkUrl("https://partner.ads.example.com/other", "partner.ads.example.com") == BLOCKED)
    check("url pattern block", f.checkUrl("https://cdn.example.com/ads/a.png", "cdn.example.com") == BLOCKED)
    check("url pattern pass", f.checkUrl("https://cdn.example.com/img/a.png", "cdn.example.com") == PASS)
    check("substring block", f.checkUrl("https://site.jp/banner/ad_1.gif", "site.jp") == BLOCKED)
    check("exception url", f.checkUrl("https://doubleclick.net/allowed/x", "doubleclick.net") == ALLOWED_BY_LIST)
    check("exact anchor", f.checkUrl("https://exact.example/x.js", "exact.example") == BLOCKED)
    check("exact anchor no match", f.checkUrl("https://exact.example/x.js?y", "exact.example") == PASS)
    check("ads.js is not a domain", f.checkUrl("https://a.com/ads.js", "a.com") == BLOCKED && f.checkHost("ads.js") == PASS)

    // DNS
    val q = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) +
        byteArrayOf(11) + "doubleclick".toByteArray() + byteArrayOf(3) + "net".toByteArray() + byteArrayOf(0, 0, 1, 0, 1)
    check("dns name", Dns.questionName(q) == "doubleclick.net")
    val r = Dns.blockedResponse(q)!!
    check("dns nxdomain", r[2].toInt() and 0xFF == 0x81 && r[3].toInt() and 0xFF == 0x83 && r[0] == q[0])
    val pkt = Packets.buildIpv4Udp(byteArrayOf(10, 0, 0, 1), byteArrayOf(10, 0, 0, 2), 5353, 53, q)
    val parsed = Packets.parseIpv4Udp(pkt, pkt.size)!!
    check("ip roundtrip", parsed.dstPort == 53 && parsed.srcPort == 5353 && parsed.payload.contentEquals(q))
    // checksum verifies to 0
    var sum = 0L; for (i in 0 until 20 step 2) sum += Packets.u16(pkt, i); while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
    check("ip checksum", sum == 0xFFFFL)

    // HTTP
    val raw = "\r\nPOST /a HTTP/1.1\r\nHost: x.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /next HTTP/1.1\r\n\r\n"
    val inp = ByteArrayInputStream(raw.toByteArray())
    val h = HttpHead.read(inp)!!
    check("http head", h.method == "POST" && h.target == "/a" && h.header("host") == "x.com")
    val out = ByteArrayOutputStream(); HttpBody.copy(h, inp, out)
    check("chunked copy", out.toString() == "5\r\nhello\r\n0\r\n\r\n")
    check("next request", HttpHead.read(inp)!!.target == "/next")
    check("hostport", splitHostPort("[::1]:8443", 443) == ("::1" to 8443) && splitHostPort("a.com", 443) == ("a.com" to 443) && splitHostPort("a.com:8080", 80) == ("a.com" to 8080))

    // TCP RST (IPv4: SYN を受けて RST+ACK)
    fun verifyTcp(rst: ByteArray, v: Int): Boolean {
        val ip = Packets.parseIp(rst, rst.size)!!
        val seg = rst.copyOfRange(ip.headerLen, ip.totalLen)
        val pseudo = if (v == 4) ByteArray(12).also { System.arraycopy(ip.src,0,it,0,4); System.arraycopy(ip.dst,0,it,4,4); it[9]=6; Packets.put16(it,10,seg.size) }
                     else ByteArray(40).also { System.arraycopy(ip.src,0,it,0,16); System.arraycopy(ip.dst,0,it,16,16); Packets.put32(it,32,seg.size.toLong()); it[39]=6 }
        var s = Packets.sum16(pseudo) + Packets.sum16(seg); while (s shr 16 != 0L) s = (s and 0xFFFF) + (s shr 16)
        return s == 0xFFFFL
    }
    val syn = ByteArray(40).also {
        it[0]=0x45; Packets.put16(it,2,40); it[8]=64; it[9]=6
        byteArrayOf(10,0,0,5).copyInto(it,12); byteArrayOf(93,184.toByte(),216.toByte(),34).copyInto(it,16)
        Packets.put16(it,20,40000); Packets.put16(it,22,443); Packets.put32(it,24,1000L); it[32]=0x50; it[33]=0x02
    }
    val sip = Packets.parseIp(syn, syn.size)!!
    check("parse v4 tcp", sip.version == 4 && sip.proto == 6 && sip.dstAddress == "93.184.216.34")
    val rst = Packets.buildTcpRst(syn, sip)!!
    val rip = Packets.parseIp(rst, rst.size)!!
    check("rst v4 addresses/ports", rip.dstAddress == "10.0.0.5" && Packets.u16(rst,20) == 443 && Packets.u16(rst,22) == 40000)
    check("rst v4 flags/ack", rst[33].toInt() == 0x14 && Packets.u32(rst,28) == 1001L)
    check("rst v4 tcp checksum", verifyTcp(rst, 4))
    var hs = 0L; for (i in 0 until 20 step 2) hs += Packets.u16(rst, i); while (hs shr 16 != 0L) hs = (hs and 0xFFFF) + (hs shr 16)
    check("rst v4 ip checksum", hs == 0xFFFFL)
    check("no reply to rst", Packets.buildTcpRst(rst, rip) == null)
    // IPv6 ACK 付きデータ → RST(seq=相手のack)
    val v6 = ByteArray(60).also {
        it[0]=0x60; Packets.put16(it,4,20); it[6]=6; it[7]=64
        java.net.InetAddress.getByName("fd00::2").address.copyInto(it,8); java.net.InetAddress.getByName("2001:db8::1").address.copyInto(it,24)
        Packets.put16(it,40,50000); Packets.put16(it,42,443); Packets.put32(it,44,5L); Packets.put32(it,48,77777L); it[52]=0x50; it[53]=0x10
    }
    val ip6 = Packets.parseIp(v6, v6.size)!!
    val rst6 = Packets.buildTcpRst(v6, ip6)!!
    check("rst v6", Packets.parseIp(rst6, rst6.size)!!.dstAddress == java.net.InetAddress.getByName("fd00::2").hostAddress && rst6[53].toInt() == 0x04 && Packets.u32(rst6,44) == 77777L)
    check("rst v6 tcp checksum", verifyTcp(rst6, 6))

    // 広告判定
    fun lv(h: String) = AdHeuristics.classify(h).level
    check("network", AdHeuristics.classify("auction-load.unityads.unity3d.com").rule == "unityads.unity3d.com" && lv("x.mintegral.net") == AdHeuristics.Level.STRONG)
    check("strong label", lv("ads.example.co.jp") == AdHeuristics.Level.STRONG && lv("adserver2.foo.com") == AdHeuristics.Level.STRONG && lv("rtb-jp.bar.net") == AdHeuristics.Level.STRONG)
    check("strong rule is exact host", AdHeuristics.classify("ads.example.co.jp").rule == "ads.example.co.jp")
    check("weak", lv("tracking.shop.jp") == AdHeuristics.Level.WEAK && lv("analytics.foo.com") == AdHeuristics.Level.WEAK)
    check("no false positive", lv("downloads.example.com") == AdHeuristics.Level.NONE && lv("adobe.com") == AdHeuristics.Level.NONE && lv("uploads.github.com") == AdHeuristics.Level.NONE && lv("shadow.jp") == AdHeuristics.Level.NONE)
    check("protected", lv("ads.google.com") == AdHeuristics.Level.NONE && lv("ads-cdn.cloudfront.net") == AdHeuristics.Level.NONE)
    check("unity3d not whole", lv("config.uca.cloud.unity3d.com") == AdHeuristics.Level.NONE)
    // 動的ブロック
    f.addDynamicBlock("newads.example")
    check("dynamic block", f.checkHost("x.newads.example") == BLOCKED && f.checkUrl("https://newads.example/a", "newads.example") == BLOCKED)
    check("user allowed", f.isUserAllowed("good-ads.example") && f.isUserAllowed("partner.ads.example.com") && !f.isUserAllowed("ads.example.com"))
    DnsHistory.add("A.Example.", 10123, false, DnsHistory.VIA_DNS)
    check("history", DnsHistory.since(60_000).last().host == "a.example")
    println(if (failed == 0) "ALL PASSED" else "$failed FAILED")
}
