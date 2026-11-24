package com.example.localadblock

import java.net.InetAddress

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

    // ---- IPv4 / IPv6 共通（IPブロック用） ----

    class Ip(
        val version: Int,
        val proto: Int,
        val headerLen: Int,
        val totalLen: Int,
        val src: ByteArray,
        val dst: ByteArray,
    ) {
        val dstAddress: String get() = InetAddress.getByAddress(dst).hostAddress ?: ""
    }

    fun parseIp(b: ByteArray, len: Int): Ip? {
        if (len < 1) return null
        return when ((b[0].toInt() shr 4) and 0x0F) {
            4 -> {
                if (len < 20) return null
                val ihl = (b[0].toInt() and 0x0F) * 4
                val total = u16(b, 2)
                if (ihl < 20 || total > len || total < ihl) return null
                if ((u16(b, 6) and 0x1FFF) != 0) return null // 2つ目以降の断片
                Ip(4, b[9].toInt() and 0xFF, ihl, total, b.copyOfRange(12, 16), b.copyOfRange(16, 20))
            }
            6 -> {
                if (len < 40) return null
                val total = 40 + u16(b, 4)
                if (total > len) return null
                Ip(6, b[6].toInt() and 0xFF, 40, total, b.copyOfRange(8, 24), b.copyOfRange(24, 40))
            }
            else -> null
        }
    }

    /** 受け取った TCP パケットに対する RST を作る（接続をすぐに失敗させる） */
    fun buildTcpRst(b: ByteArray, ip: Ip): ByteArray? {
        val off = ip.headerLen
        if (ip.proto != 6 || ip.totalLen < off + 20) return null
        val flags = b[off + 13].toInt() and 0xFF
        if ((flags and 0x04) != 0) return null // RST には応答しない
        val dataOff = ((b[off + 12].toInt() shr 4) and 0x0F) * 4
        var segLen = (ip.totalLen - off - dataOff).toLong()
        if (dataOff < 20 || segLen < 0) return null
        if ((flags and 0x02) != 0) segLen++ // SYN
        if ((flags and 0x01) != 0) segLen++ // FIN
        val tcp = ByteArray(20)
        put16(tcp, 0, u16(b, off + 2))
        put16(tcp, 2, u16(b, off))
        if ((flags and 0x10) != 0) { // ACK あり → seq = 相手の ack
            put32(tcp, 4, u32(b, off + 8))
            tcp[13] = 0x04
        } else {
            put32(tcp, 8, (u32(b, off + 4) + segLen) and 0xFFFFFFFFL)
            tcp[13] = 0x14 // RST + ACK
        }
        tcp[12] = 0x50
        return buildIp(ip.version, ip.dst, ip.src, 6, tcp, checksumOffset = 16)
    }

    private fun buildIp(version: Int, src: ByteArray, dst: ByteArray, proto: Int, seg: ByteArray, checksumOffset: Int): ByteArray {
        val pseudo = if (version == 4) {
            ByteArray(12).also {
                System.arraycopy(src, 0, it, 0, 4); System.arraycopy(dst, 0, it, 4, 4)
                it[9] = proto.toByte(); put16(it, 10, seg.size)
            }
        } else {
            ByteArray(40).also {
                System.arraycopy(src, 0, it, 0, 16); System.arraycopy(dst, 0, it, 16, 16)
                put32(it, 32, seg.size.toLong()); it[39] = proto.toByte()
            }
        }
        put16(seg, checksumOffset, 0)
        put16(seg, checksumOffset, fold(sum16(pseudo) + sum16(seg)))
        val p: ByteArray
        if (version == 4) {
            p = ByteArray(20 + seg.size)
            p[0] = 0x45
            put16(p, 2, p.size)
            put16(p, 6, 0x4000)
            p[8] = 64
            p[9] = proto.toByte()
            System.arraycopy(src, 0, p, 12, 4)
            System.arraycopy(dst, 0, p, 16, 4)
            put16(p, 10, checksum(p, 0, 20))
            System.arraycopy(seg, 0, p, 20, seg.size)
        } else {
            p = ByteArray(40 + seg.size)
            p[0] = 0x60
            put16(p, 4, seg.size)
            p[6] = proto.toByte()
            p[7] = 64
            System.arraycopy(src, 0, p, 8, 16)
            System.arraycopy(dst, 0, p, 24, 16)
            System.arraycopy(seg, 0, p, 40, seg.size)
        }
        return p
    }

    fun sum16(b: ByteArray): Long {
        var sum = 0L
        var i = 0
        while (i < b.size - 1) { sum += u16(b, i); i += 2 }
        if ((b.size and 1) == 1) sum += ((b[b.size - 1].toInt() and 0xFF) shl 8).toLong()
        return sum
    }

    private fun fold(s: Long): Int {
        var sum = s
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    fun u32(b: ByteArray, off: Int): Long = (u16(b, off).toLong() shl 16) or u16(b, off + 2).toLong()

    fun put32(b: ByteArray, off: Int, v: Long) {
        put16(b, off, ((v shr 16) and 0xFFFF).toInt())
        put16(b, off + 2, (v and 0xFFFF).toInt())
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
