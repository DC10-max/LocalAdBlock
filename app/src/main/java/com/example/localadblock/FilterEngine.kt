package com.example.localadblock

/**
 * ブロックリスト + 許可リスト（ホワイトリスト）の判定エンジン。
 *
 * 判定の優先順位:  許可リスト  >  ブロックリスト  >  素通し
 *
 * 対応する書式（Adblock Plus / uBlock / hosts のサブセット）:
 *   ||example.com^          ドメイン（サブドメイン含む）
 *   example.com, *.example.com   ドメイン（自前リスト向けの簡易表記）
 *   0.0.0.0 example.com     hosts 形式
 *   ||example.com/ads/xx*   URL パターン（* と ^ と | アンカーに対応）
 *   /banner/ad_             URL 部分一致
 *   @@...                   例外（= 許可）
 * 非対応のため読み飛ばすもの: 要素隠し(##)、正規表現ルール、domain= などのオプション付きルール
 */
class FilterEngine private constructor(
    private val blockDomains: Set<String>,
    private val allowDomains: Set<String>,
    private val allowUrlHosts: Set<String>,
    private val exceptionUrlHosts: Set<String>,
    private val blockUrlRules: List<UrlRule>,
    private val allowUrlRules: List<UrlRule>,
) {
    enum class Decision { ALLOWED_BY_LIST, BLOCKED, PASS }

    val blockRuleCount: Int get() = blockDomains.size + blockUrlRules.size
    val allowRuleCount: Int get() = allowDomains.size + allowUrlRules.size

    /**
     * DNS / CONNECT 段階の判定（ホスト名しか分からない段階）。
     * @param inspectable このあと HTTPS検査でURLを見られるか（プロキシ経由かつ検査対象のとき true）
     */
    fun checkHost(host: String, inspectable: Boolean = false): Decision {
        val h = normalize(host)
        if (matchDomain(allowDomains, h)) return Decision.ALLOWED_BY_LIST
        // ユーザーの許可URLルールが参照しているホストは、URLを見るまで判定できないので通す
        if (matchDomain(allowUrlHosts, h)) return Decision.PASS
        // 購読リストの例外(@@)ルールは、URLを検査できる場合だけ考慮する
        if (inspectable && matchDomain(exceptionUrlHosts, h)) return Decision.PASS
        if (matchDomain(blockDomains, h)) return Decision.BLOCKED
        return Decision.PASS
    }

    /** HTTPS検査後（URL全体が分かる段階）の判定 */
    fun checkUrl(url: String, host: String): Decision {
        val h = normalize(host)
        val u = url.lowercase()
        if (matchDomain(allowDomains, h) || allowUrlRules.any { it.matches(u) }) return Decision.ALLOWED_BY_LIST
        if (matchDomain(blockDomains, h) || blockUrlRules.any { it.matches(u) }) return Decision.BLOCKED
        return Decision.PASS
    }

    class Builder {
        private val blockDomains = HashSet<String>()
        private val allowDomains = HashSet<String>()
        private val allowUrlHosts = HashSet<String>()
        private val exceptionUrlHosts = HashSet<String>()
        private val blockUrlRules = ArrayList<UrlRule>()
        private val allowUrlRules = ArrayList<UrlRule>()

        fun addBlockLine(line: String) = parse(line, allowList = false)
        fun addAllowLine(line: String) = parse(line, allowList = true)

        fun build() = FilterEngine(blockDomains, allowDomains, allowUrlHosts, exceptionUrlHosts, blockUrlRules, allowUrlRules)

        private fun parse(raw: String, allowList: Boolean) {
            var s = raw.trim()
            if (s.isEmpty() || s[0] == '!' || s[0] == '[' || s[0] == '#') return
            if (COSMETIC.containsMatchIn(s)) return

            var exception = allowList
            if (s.startsWith("@@")) {
                exception = true
                s = s.substring(2)
            }
            val domains = if (exception) allowDomains else blockDomains

            HOSTS_LINE.matchEntire(s)?.let { m ->
                val d = normalize(m.groupValues[1])
                if (d !in IGNORED_HOSTS && isDomain(d)) domains.add(d)
                return
            }
            if (s.length > 2 && s.startsWith("/") && s.endsWith("/")) return // 正規表現ルールは未対応

            val dollar = s.lastIndexOf('$')
            if (dollar >= 0) {
                val opts = s.substring(dollar + 1).lowercase().split(',').map { it.trim() }
                val safe = if (exception) SAFE_EXCEPTION_OPTIONS else SAFE_BLOCK_OPTIONS
                if (opts.any { it !in safe }) return // 適用範囲を正しく再現できないルールは使わない
                s = s.substring(0, dollar)
            }
            if (s.isEmpty() || s == "*" || s == "|" || s == "||") return

            PURE_DOMAIN.matchEntire(s.lowercase())?.let {
                domains.add(normalize(it.groupValues[1])); return
            }
            val bare = s.lowercase().removePrefix("*.")
            if (isDomain(bare)) {
                domains.add(normalize(bare)); return
            }

            val rule = UrlRule.compile(s) ?: return
            if (exception) {
                allowUrlRules.add(rule)
                if (s.startsWith("||")) {
                    val host = s.substring(2).lowercase()
                        .takeWhile { it.isLetterOrDigit() || it == '.' || it == '-' }
                    if (host.contains('.')) (if (allowList) allowUrlHosts else exceptionUrlHosts).add(host)
                }
            } else {
                blockUrlRules.add(rule)
            }
        }
    }

    class UrlRule private constructor(private val substring: String?, private val regex: Regex?) {
        fun matches(lowerUrl: String): Boolean =
            if (substring != null) lowerUrl.contains(substring) else regex!!.containsMatchIn(lowerUrl)

        companion object {
            private const val REGEX_SPECIAL = "\\.+?()[]{}$"

            fun compile(pattern: String): UrlRule? {
                var p = pattern.lowercase()
                if (p.none { it == '*' || it == '^' || it == '|' }) {
                    return if (p.length >= 4) UrlRule(p, null) else null // 短すぎる部分一致は誤爆するので捨てる
                }
                val sb = StringBuilder()
                when {
                    p.startsWith("||") -> { sb.append("^[a-z][a-z0-9+.-]*://(?:[^/?#]*\\.)?"); p = p.substring(2) }
                    p.startsWith("|") -> { sb.append('^'); p = p.substring(1) }
                }
                val anchoredEnd = p.endsWith("|")
                if (anchoredEnd) p = p.dropLast(1)
                for (c in p) {
                    when (c) {
                        '*' -> sb.append(".*")
                        '^' -> sb.append("(?:[^a-z0-9_.%-]|$)")
                        '|' -> sb.append("\\|")
                        in REGEX_SPECIAL -> sb.append('\\').append(c)
                        else -> sb.append(c)
                    }
                }
                if (anchoredEnd) sb.append('$')
                return try { UrlRule(null, Regex(sb.toString())) } catch (e: Exception) { null }
            }
        }
    }

    companion object {
        private val COSMETIC = Regex("#[@?$%]?#|#@[?$]#")
        private val HOSTS_LINE = Regex("""^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+(\S+).*$""")
        private val PURE_DOMAIN = Regex("""^\|\|([a-z0-9.-]+)\^\|?$""")
        private val DOMAIN = Regex("""^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$""")
        private val FILE_EXT = setOf("js", "css", "php", "html", "htm", "gif", "png", "jpg", "jpeg", "swf", "json", "cgi", "aspx", "asp", "jsp", "xml", "txt", "webp", "svg", "mp4")
        private val IGNORED_HOSTS = setOf("localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0", "ip6-localhost", "ip6-loopback")

        private val SAFE_BLOCK_OPTIONS = setOf(
            "third-party", "3p", "script", "image", "stylesheet", "css", "xmlhttprequest", "xhr",
            "subdocument", "frame", "media", "object", "ping", "other", "font", "websocket", "important", "all",
        )
        private val SAFE_EXCEPTION_OPTIONS = SAFE_BLOCK_OPTIONS + setOf("document", "doc")

        fun normalize(host: String) = host.lowercase().trim().trimEnd('.').removePrefix("[").removeSuffix("]")

        private fun isDomain(s: String): Boolean {
            if (!DOMAIN.matches(s)) return false
            val tld = s.substringAfterLast('.')
            return tld.length >= 2 && tld.all { it in 'a'..'z' } && tld !in FILE_EXT
        }

        /** host 自身、またはその親ドメインのどれかが set に含まれるか */
        fun matchDomain(set: Set<String>, host: String): Boolean {
            if (set.isEmpty()) return false
            var d = host
            while (true) {
                if (d in set) return true
                val i = d.indexOf('.')
                if (i < 0) return false
                d = d.substring(i + 1)
            }
        }
    }
}
