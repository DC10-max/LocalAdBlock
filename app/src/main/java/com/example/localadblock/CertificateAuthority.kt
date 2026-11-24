package com.example.localadblock

import android.content.Context
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/**
 * 端末ごとに一意なルートCAを生成し、HTTPS検査用のサーバー証明書をホストごとに発行する。
 * CA の秘密鍵はアプリ専用領域にのみ保存され、端末外には出ない。
 */
class CertificateAuthority private constructor(private val dir: File) {
    private val ksFile = File(dir, "ca.p12")
    private val pass = "localadblock".toCharArray() // アプリ専用領域内のみで使う保護用パスワード
    private val random = SecureRandom()

    lateinit var caCert: X509Certificate
        private set
    private lateinit var caKey: PrivateKey

    private val leafKeys: KeyPair by lazy { rsa() }
    private val cache = object : LinkedHashMap<String, SSLContext>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, SSLContext>) = size > 300
    }

    @Synchronized
    private fun loadOrCreate() {
        dir.mkdirs()
        if (ksFile.exists()) {
            try {
                val ks = KeyStore.getInstance("PKCS12")
                ksFile.inputStream().use { ks.load(it, pass) }
                caKey = ks.getKey("ca", pass) as PrivateKey
                caCert = ks.getCertificate("ca") as X509Certificate
                return
            } catch (e: Exception) {
                ksFile.delete()
            }
        }
        createCa()
    }

    private fun createCa() {
        val kp = rsa()
        val name = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, "LocalAdBlock Root CA (${java.lang.Long.toHexString(random.nextLong()).take(8)})")
            .addRDN(BCStyle.O, "LocalAdBlock (on-device)")
            .build()
        val now = System.currentTimeMillis()
        val ext = JcaX509ExtensionUtils()
        val builder = JcaX509v3CertificateBuilder(
            name, serial(), Date(now - DAY), Date(now + 3650 * DAY), name, kp.public,
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(0))
            .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
            .addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(kp.public))
        val cert = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private)),
        )
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("ca", kp.private, pass, arrayOf(cert))
        ksFile.outputStream().use { ks.store(it, pass) }
        caKey = kp.private
        caCert = cert
    }

    /** ユーザーがインストールする CA 証明書（DER 形式） */
    fun caDer(): ByteArray = caCert.encoded

    /** 端末の「ユーザー証明書」に、このCAがインストール済みか */
    fun isInstalledInUserStore(): Boolean = try {
        val ks = KeyStore.getInstance("AndroidCAStore")
        ks.load(null)
        ks.aliases().toList().any { it.startsWith("user:") && ks.getCertificate(it) == caCert }
    } catch (e: Exception) {
        false
    }

    fun sslContextFor(host: String): SSLContext {
        synchronized(cache) { cache[host]?.let { return it } }
        val ctx = createContext(host)
        synchronized(cache) { cache[host] = ctx }
        return ctx
    }

    private fun createContext(host: String): SSLContext {
        val now = System.currentTimeMillis()
        val ext = JcaX509ExtensionUtils()
        val subject: X500Name = X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, host).build()
        val isIp = IPV4.matches(host) || host.contains(':')
        val san = GeneralNames(GeneralName(if (isIp) GeneralName.iPAddress else GeneralName.dNSName, host))
        val builder = JcaX509v3CertificateBuilder(
            caCert, serial(), Date(now - DAY), Date(now + 365 * DAY), subject, leafKeys.public,
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))
            .addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
            .addExtension(Extension.subjectAlternativeName, false, san)
            .addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(caCert))
            .addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(leafKeys.public))
        val leaf = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withRSA").build(caKey)),
        )
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("leaf", leafKeys.private, pass, arrayOf(leaf, caCert))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, pass)
        return SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
    }

    private fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048, random) }.generateKeyPair()
    private fun serial(): BigInteger = BigInteger(63, random).add(BigInteger.ONE)

    companion object {
        private const val DAY = 24L * 60 * 60 * 1000
        private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

        @Volatile private var instance: CertificateAuthority? = null

        fun get(ctx: Context): CertificateAuthority = instance ?: synchronized(this) {
            instance ?: CertificateAuthority(File(ctx.filesDir, "ca")).also {
                it.loadOrCreate()
                instance = it
            }
        }
    }
}
