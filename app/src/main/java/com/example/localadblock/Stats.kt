package com.example.localadblock

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

object Stats {
    val dnsBlocked = AtomicLong()
    val httpBlocked = AtomicLong()
    val allowedByList = AtomicLong()
    val tlsBypassed = AtomicLong()
    val ipBlocked = AtomicLong()
    val autoAdded = AtomicLong()

    private val recent = ArrayDeque<String>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    @Synchronized
    fun log(msg: String) {
        recent.addFirst("${fmt.format(Date())} $msg")
        while (recent.size > 150) recent.removeLast()
    }

    @Synchronized
    fun recent(): List<String> = recent.toList()
}
