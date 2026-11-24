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
    println(if (failed == 0) "ALL PASSED" else "$failed FAILED")
}
