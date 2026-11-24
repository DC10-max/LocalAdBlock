package com.example.localadblock

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

class HttpHead(
    val method: String,
    val target: String,
    val version: String,
    val headers: List<Pair<String, String>>,
) {
    fun header(name: String): String? =
        headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second?.trim()

    companion object {
        private const val MAX_HEAD = 64 * 1024

        /** リクエストヘッダーを読む。接続が閉じられていれば null */
        fun read(input: InputStream): HttpHead? {
            val lines = ArrayList<String>()
            var total = 0
            while (true) {
                val line = readLine(input)
                    ?: return if (lines.isEmpty()) null else throw IOException("ヘッダーの途中で切断されました")
                total += line.length + 2
                if (total > MAX_HEAD) throw IOException("ヘッダーが大きすぎます")
                if (line.isEmpty()) {
                    if (lines.isEmpty()) continue else break
                }
                lines.add(line)
            }
            val parts = lines[0].split(' ', limit = 3)
            if (parts.size < 3) throw IOException("不正なリクエスト行: ${lines[0]}")
            val headers = lines.drop(1).mapNotNull { l ->
                val i = l.indexOf(':')
                if (i <= 0) null else l.substring(0, i).trim() to l.substring(i + 1).trim()
            }
            return HttpHead(parts[0], parts[1], parts[2], headers)
        }

        fun readLine(input: InputStream, limit: Int = 16 * 1024): String? {
            val sb = StringBuilder()
            while (true) {
                val b = input.read()
                if (b == -1) return if (sb.isEmpty()) null else sb.toString()
                if (b == '\n'.code) {
                    if (sb.endsWith('\r')) sb.setLength(sb.length - 1)
                    return sb.toString()
                }
                sb.append(b.toChar())
                if (sb.length > limit) throw IOException("行が長すぎます")
            }
        }
    }
}

object HttpBody {
    /** リクエストボディを Content-Length / chunked に従ってそのまま転送 */
    fun copy(head: HttpHead, input: InputStream, out: OutputStream) {
        if (head.header("Transfer-Encoding")?.contains("chunked", ignoreCase = true) == true) {
            copyChunked(input, out)
        } else {
            head.header("Content-Length")?.toLongOrNull()?.let { copyExact(input, out, it) }
        }
    }

    fun skip(head: HttpHead, input: InputStream) = copy(head, input, NullOutputStream)

    private fun copyExact(input: InputStream, out: OutputStream, n: Long) {
        var left = n
        val buf = ByteArray(16 * 1024)
        while (left > 0) {
            val r = input.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
            if (r == -1) throw EOFException()
            out.write(buf, 0, r)
            left -= r
        }
    }

    private fun copyChunked(input: InputStream, out: OutputStream) {
        while (true) {
            val line = HttpHead.readLine(input) ?: throw EOFException()
            out.write((line + "\r\n").toByteArray(Charsets.ISO_8859_1))
            val size = line.substringBefore(';').trim().toLongOrNull(16) ?: throw IOException("不正なchunkサイズ")
            if (size == 0L) {
                while (true) { // trailer
                    val t = HttpHead.readLine(input) ?: break
                    out.write((t + "\r\n").toByteArray(Charsets.ISO_8859_1))
                    if (t.isEmpty()) break
                }
                return
            }
            copyExact(input, out, size)
            HttpHead.readLine(input) ?: throw EOFException()
            out.write("\r\n".toByteArray())
        }
    }

    private object NullOutputStream : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {}
    }
}

/** 読めた分をすぐ書き出す（ストリーミングや WebSocket 向け） */
fun pump(input: InputStream, out: OutputStream) {
    val buf = ByteArray(16 * 1024)
    while (true) {
        val n = input.read(buf)
        if (n < 0) break
        out.write(buf, 0, n)
        out.flush()
    }
}

fun splitHostPort(s: String, defaultPort: Int): Pair<String, Int>? {
    val v = s.trim()
    if (v.isEmpty()) return null
    if (v.startsWith("[")) {
        val end = v.indexOf(']')
        if (end < 0) return null
        val rest = v.substring(end + 1)
        val port = if (rest.startsWith(":")) rest.substring(1).toIntOrNull() ?: return null else defaultPort
        return v.substring(1, end) to port
    }
    val i = v.lastIndexOf(':')
    if (i > 0 && v.indexOf(':') == i) {
        val port = v.substring(i + 1).toIntOrNull() ?: return null
        return v.substring(0, i) to port
    }
    return v to defaultPort
}
