package com.trafficmonitor

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.max

/**
 * Android equivalent of the server.js core engine: aggregation, a 300-sample
 * ring buffer of history (≈10 min), per-app detail windows (80 samples), plus
 * the simulation fallback rule (2 failed live ticks → SIM mode).
 */
class MonitorEngine(private val ctx: Context) {

    enum class Mode { LIVE, SIM }

    private val live = LiveCollector(ctx)
    private val sim = SimCollector()

    private var failures = 0
    var mode: Mode = if (LiveCollector.hasUsageAccess(ctx)) Mode.LIVE else Mode.SIM
        private set

    val labels = ArrayList<String>()
    val rxHistory = ArrayList<Long>()
    val txHistory = ArrayList<Long>()
    val appHistory = HashMap<String, ArrayList<AppPoint>>()

    var lastSnapshot: Snapshot? = null
        private set

    var samples = 0
        private set

    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun hasUsageAccess(): Boolean = LiveCollector.hasUsageAccess(ctx)

    fun tick(intervalMs: Long = 2000L): Snapshot {
        var apps: List<AppSample>? = null
        var modeNow = mode

        if (LiveCollector.hasUsageAccess(ctx)) {
            apps = try {
                live.sample(intervalMs)
            } catch (_: Exception) {
                null
            }
            if (apps != null && apps.isNotEmpty()) {
                failures = 0
                modeNow = Mode.LIVE
            } else {
                failures++
                if (mode == Mode.LIVE && failures >= 2) modeNow = Mode.SIM
            }
        } else {
            failures++
            if (mode == Mode.LIVE && failures >= 2) modeNow = Mode.SIM
        }

        if (apps == null || apps.isEmpty()) {
            modeNow = Mode.SIM
            apps = sim.sample()
        }
        mode = modeNow

        val ranked = apps.sortedByDescending { it.totalBps }.take(MAX_APPS)
        var totalRx = 0L
        var totalTx = 0L
        for (a in ranked) {
            totalRx += a.rxBps
            totalTx += a.txBps
        }

        val snap = Snapshot(System.currentTimeMillis(), totalRx, totalTx, ranked, mode.name)
        lastSnapshot = snap
        samples++

        val label = timeFmt.format(Date(snap.ts))
        labels.add(label)
        rxHistory.add(totalRx)
        txHistory.add(totalTx)
        while (labels.size > MAX_HISTORY) labels.removeAt(0)
        while (rxHistory.size > MAX_HISTORY) rxHistory.removeAt(0)
        while (txHistory.size > MAX_HISTORY) txHistory.removeAt(0)

        val seen = HashSet<String>()
        for (a in ranked) {
            val key = "${a.uid}:${a.name}"
            seen.add(key)
            val win = appHistory.getOrPut(key) { ArrayList() }
            win.add(AppPoint(a.rxBps, a.txBps))
            while (win.size > MAX_DETAIL) win.removeAt(0)
        }
        val it = appHistory.entries.iterator()
        while (it.hasNext()) {
            if (!seen.contains(it.next().key)) it.remove()
        }
        return snap
    }

    fun peak(): AppPoint {
        var rx = 0L
        var tx = 0L
        for (i in rxHistory.indices) {
            rx = max(rx, rxHistory[i])
            tx = max(tx, txHistory[i])
        }
        return AppPoint(rx, tx)
    }

    companion object {
        const val MAX_APPS = 25
        const val MAX_HISTORY = 300
        const val MAX_DETAIL = 80
    }
}