package com.example.localadblock

/** VPN(tun) で受け取る IPv4/UDP パケットの最小限の解析・生成 */
object Packets {
    class Udp(
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val payload: ByteArray,
    )

    fun parseIpv4Udp(b: ByteArray, len: Int): Udp? {
        if (len < 28) return null
        if (((b[0].toInt() shr 4) and 0x0F) != 4) return null
        val ihl = (b[0].toInt() and 0x0F) * 4
        if (ihl < 20 || b[9].toInt() != 17) return null // 17 = UDP
        val total = u16(b, 2)
        if (total > len || total < ihl + 8) return null
        val flagsFrag = u16(b, 6)
        if ((flagsFrag and 0x1FFF) != 0 || (flagsFrag and 0x2000) != 0) return null // 断片化パケットは扱わない
        val udpLen = u16(b, ihl + 4)
        val end = minOf(ihl + udpLen, total)
        if (end < ihl + 8) return null
        return Udp(
            srcIp = b.copyOfRange(12, 16),
            dstIp = b.copyOfRange(16, 20),
            srcPort = u16(b, ihl),
            dstPort = u16(b, ihl + 2),
            payload = b.copyOfRange(ihl + 8, end),
        )
    }

    fun buildIpv4Udp(src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val total = 28 + payload.size
        val p = ByteArray(total)
        p[0] = 0x45
        put16(p, 2, total)
        put16(p, 6, 0x4000) // DF
        p[8] = 64           // TTL
        p[9] = 17           // UDP
        System.arraycopy(src, 0, p, 12, 4)
        System.arraycopy(dst, 0, p, 16, 4)
        put16(p, 10, checksum(p, 0, 20))
        put16(p, 20, srcPort)
        put16(p, 22, dstPort)
        put16(p, 24, 8 + payload.size)
        put16(p, 26, 0) // IPv4 では UDP チェックサム省略可
        System.arraycopy(payload, 0, p, 28, payload.size)
        return p
    }

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i < off + len - 1) { sum += u16(b, i); i += 2 }
        if ((len and 1) == 1) sum += ((b[off + len - 1].toInt() and 0xFF) shl 8).toLong()
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v shr 8).toByte()
        b[off + 1] = v.toByte()
    }
}

object Dns {
    /** 問い合わせドメイン名（最初の質問のみ） */
    fun questionName(msg: ByteArray): String? {
        if (msg.size < 12 || Packets.u16(msg, 4) < 1) return null
        val sb = StringBuilder()
        var i = 12
        while (true) {
            if (i >= msg.size) return null
            val len = msg[i].toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) != 0) return null
            if (i + 1 + len > msg.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (k in 1..len) sb.append((msg[i + k].toInt() and 0xFF).toChar())
            i += 1 + len
        }
        return sb.toString().lowercase()
    }

    private fun questionEnd(msg: ByteArray): Int {
        var i = 12
        while (i < msg.size) {
            val len = msg[i].toInt() and 0xFF
            if (len == 0) return if (i + 5 <= msg.size) i + 5 else -1
            if ((len and 0xC0) != 0) return -1
            i += 1 + len
        }
        return -1
    }

    /** NXDOMAIN 応答を作る */
    fun blockedResponse(query: ByteArray): ByteArray? {
        val end = questionEnd(query)
        if (end < 0) return null
        val r = query.copyOf(end)
        r[2] = (0x80 or (query[2].toInt() and 0x79)).toByte() // QR=1, OPCODE/RD はそのまま
        r[3] = 0x83.toByte()                                   // RA=1, RCODE=3 (NXDOMAIN)
        Packets.put16(r, 4, 1)
        Packets.put16(r, 6, 0)
        Packets.put16(r, 8, 0)
        Packets.put16(r, 10, 0)
        return r
    }
}
