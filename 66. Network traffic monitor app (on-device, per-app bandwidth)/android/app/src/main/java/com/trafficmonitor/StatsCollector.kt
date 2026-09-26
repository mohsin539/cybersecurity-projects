package com.trafficmonitor

import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process

data class AppInfo(val uid: Int, val pkg: String, val label: String, val cat: String, val color: Int)

/**
 * Android equivalent of `collector.ps1`: samples per-app bandwidth from the
 * OS network stats service (per-UID byte counters) and TCP/UDP socket counts
 * from /proc/net. Throughput is real per-process data (the OS provides it),
 * unlike the Windows heuristic.
 */
class LiveCollector(private val ctx: Context) {

    private val pm: PackageManager = ctx.packageManager
    private val nsm: NetworkStatsManager =
        ctx.getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager

    private var cached: List<AppInfo>? = null

    private val NETWORK_TYPES = intArrayOf(
        ConnectivityManager.TYPE_WIFI,
        ConnectivityManager.TYPE_MOBILE,
        ConnectivityManager.TYPE_ETHERNET,
        ConnectivityManager.TYPE_BLUETOOTH
    )

    companion object {
        /** PACKAGE_USAGE_STATS is granted via Settings > Usage access (no root). */
        fun hasUsageAccess(ctx: Context): Boolean {
            return try {
                val appOps = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
                val mode = if (Build.VERSION.SDK_INT >= 29) {
                    @Suppress("DEPRECATION")
                    appOps.unsafeCheckOpNoThrow(
                        AppOpsManager.OPSTR_GET_USAGE_STATS,
                        Process.myUid(),
                        ctx.packageName
                    )
                } else {
                    @Suppress("DEPRECATION")
                    appOps.checkOpNoThrow(
                        AppOpsManager.OPSTR_GET_USAGE_STATS,
                        Process.myUid(),
                        ctx.packageName
                    )
                }
                mode == AppOpsManager.MODE_ALLOWED
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun installedApps(): List<AppInfo> {
        cached?.let { return it }
        val base = ArrayList<AppInfo>()
        val all: List<ApplicationInfo> = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }
        for (ai: ApplicationInfo in all) {
            if (ai.uid <= 0 || ai.uid >= 10000) continue
            val cat = Category.classify(ai.uid, ai.packageName)
            base.add(
                AppInfo(
                    ai.uid,
                    ai.packageName,
                    pm.getApplicationLabel(ai).toString(),
                    cat,
                    Category.color(cat)
                )
            )
        }
        val system = ArrayList<AppInfo>()
        system.add(AppInfo(0, "root", "root", Category.CAT_SYSTEM, Category.color(Category.CAT_SYSTEM)))
        system.add(AppInfo(1000, "system", "Android system", Category.CAT_SYSTEM, Category.color(Category.CAT_SYSTEM)))
        base.sortBy { it.label.lowercase() }
        cached = system + base
        return cached!!
    }

    /** Returns per-app rates (bytes/sec) for the last sample window, or null when broken. */
    fun sample(intervalMs: Long): List<AppSample> {
        val infos = installedApps()
        val now = System.currentTimeMillis()
        val start = now - intervalMs
        val sockets = readTcpSockets()

        val out = ArrayList<AppSample>(infos.size + 2)
        for (info in infos) {
            var rx = 0L
            var tx = 0L
            for (type in NETWORK_TYPES) {
                try {
                    val stats = nsm.queryDetailsForUid(type, null, start, now, info.uid)
                    val bucket = NetworkStats.Bucket()
                    while (stats.getNextBucket(bucket)) {
                        rx += bucket.getRxBytes()
                        tx += bucket.getTxBytes()
                    }
                    if (Build.VERSION.SDK_INT >= 29) stats.close()
                } catch (_: Exception) {
                    // template not available on this device — skip
                }
            }
            val rxBps = rx * 1000L / intervalMs
            val txBps = tx * 1000L / intervalMs
            if (rxBps > 0 || txBps > 0) {
                out.add(
                    AppSample(info.uid, info.label, info.cat, info.color, rxBps, txBps, sockets[info.uid] ?: 0)
                )
            }
        }
        return out
    }

    /** Counts ESTABLISHED TCP sockets per UID from /proc/net/tcp{,6}. */
    private fun readTcpSockets(): Map<Int, Int> {
        val counts = HashMap<Int, Int>()
        for (path in listOf("/proc/net/tcp", "/proc/net/tcp6")) {
            try {
                val lines = java.io.File(path).readLines()
                if (lines.size < 2) continue
                val header = lines[0].trim().split(Regex("\\s+"))
                val stIdx = header.indexOf("st")
                val uidIdx = header.indexOf("uid")
                if (stIdx < 0 || uidIdx < 0) continue
                for (i in 1 until lines.size) {
                    val parts = lines[i].trim().split(Regex("\\s+"))
                    if (parts.size <= maxOf(stIdx, uidIdx)) continue
                    if (parts[stIdx] == "01") {
                        val uid = parts[uidIdx].toIntOrNull() ?: continue
                        counts[uid] = (counts[uid] ?: 0) + 1
                    }
                }
            } catch (_: Exception) {
                // ignore unreadable proc entries
            }
        }
        return counts
    }
}

/**
 * D5-fallback — keeps the dashboard meaningful when usage access is missing
 * or live sampling fails (mirrors server.js simulation mode).
 */
class SimCollector {
    fun sample(): List<AppSample> {
        val t = System.currentTimeMillis() / 1000.0 / 60.0
        fun rate(base: Double, amp: Double, freq: Double, phase: Double): Long =
            (base + amp * Math.sin(freq * t + phase)).coerceAtLeast(0.0).toLong()

        fun app(uid: Int, name: String, pkg: String, base: Long, amp: Long, freq: Double, phase: Double): AppSample {
            val rx = rate(base.toDouble(), amp.toDouble(), freq, phase)
            val tx = rate(base.toDouble() * 0.15, amp.toDouble() * 0.1, freq * 1.7, phase + 1.0)
            return AppSample(uid, name, Category.classify(uid, pkg), Category.color(Category.classify(uid, pkg)), rx, tx, (rx / 18000).toInt())
        }

        return listOf(
            app(10100, "Chrome", "com.android.chrome", 480_000, 300_000, 0.8, 0.0),
            app(10101, "YouTube", "com.google.android.youtube", 720_000, 420_000, 0.6, 2.1),
            app(10102, "Spotify", "com.spotify.music", 96_000, 40_000, 1.2, 4.0),
            app(10103, "Steam", "com.valvesoftware.android.steam.community", 64_000, 30_000, 0.4, 1.3),
            app(10104, "Sync", "com.sync.android", 140_000, 110_000, 0.3, 5.0),
            app(10105, "Mail", "com.google.android.gm", 12_000, 28_000, 1.6, 0.7)
        )
    }
}