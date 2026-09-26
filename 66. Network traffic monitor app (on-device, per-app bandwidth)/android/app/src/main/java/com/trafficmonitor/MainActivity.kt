package com.trafficmonitor

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.trafficmonitor.ui.AppRowView
import com.trafficmonitor.ui.AreaChartView
import com.trafficmonitor.ui.RankBarView
import com.trafficmonitor.ui.SparklineView
import com.trafficmonitor.ui.Theme

/**
 * Port of the web dashboard (public/index.html + app.js): KPI cards, live
 * area chart, top-apps ranking, per-app table, detail dialog with sparkline.
 * Polls the engine every 2 s — mirroring the web dashboard's polling loop.
 */
class MainActivity : Activity() {

    companion object {
        private const val POLL_MS = 2000L
    }

    private lateinit var engine: MonitorEngine
    private lateinit var handler: Handler
    private lateinit var modeBadge: TextView
    private lateinit var permBanner: LinearLayout
    private lateinit var downKpi: TextView
    private lateinit var upKpi: TextView
    private lateinit var peakKpi: TextView
    private lateinit var chart: AreaChartView
    private lateinit var rankCard: LinearLayout
    private lateinit var appCard: LinearLayout
    private lateinit var sampleCount: TextView

    private val tick = object : Runnable {
        override fun run() {
            render(engine.tick())
            handler.postDelayed(this, POLL_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        engine = MonitorEngine(this)
        handler = Handler(Looper.getMainLooper())
        buildUi()
        render(engine.tick())
    }

    override fun onStart() {
        super.onStart()
        handler.removeCallbacks(tick)
        handler.postDelayed(tick, POLL_MS)
    }

    override fun onStop() {
        super.onStop()
        handler.removeCallbacks(tick)
    }

    private fun buildUi() {
        val root = ScrollView(this).apply { isFillViewport = true }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(Theme.dp(this@MainActivity, 16), Theme.dp(this@MainActivity, 20), Theme.dp(this@MainActivity, 16), Theme.dp(this@MainActivity, 24))
        }
        root.addView(col)
        setContentView(root)

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(Theme.text(this, "NETWORK TRAFFIC MONITOR", sizeSp = 15f, bold = true))
        header.addView(Theme.space(this, 8, 1))
        modeBadge = Theme.text(this, "● LIVE", sizeSp = 11f, bold = true, mono = true)
        modeBadge.setPadding(Theme.dp(this, 8), 0, Theme.dp(this, 8), 0)
        header.addView(modeBadge)
        col.addView(header)

        col.addView(Theme.space(this, 1, 8))
        val sub = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        sub.addView(Theme.text(this, "on-device · per-app bandwidth · every 2 s", color = Theme.TEXT_SEC, sizeSp = 11f))
        col.addView(sub)

        permBanner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(Theme.dp(this@MainActivity, 14), Theme.dp(this@MainActivity, 12), Theme.dp(this@MainActivity, 14), Theme.dp(this@MainActivity, 12))
            background = Theme.card(0x1A5B21B6.toInt(), Theme.dp(this@MainActivity, 12).toFloat())
            isClickable = true
            isFocusable = true
            setOnClickListener {
                startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
            }
        }
        val dot = View(this).apply { background = Theme.oval(Color.rgb(0xEF, 0x44, 0x44)) }
        permBanner.addView(dot, Theme.dp(this, 10), Theme.dp(this, 10))
        permBanner.addView(Theme.space(this, 10, 1))
        val permText = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        permText.addView(Theme.text(this, "Usage access needed", sizeSp = 13f, bold = true))
        permText.addView(Theme.text(this, "Tap to open Settings → Usage access, then allow Traffic Monitor (keeps everything on-device).", color = Theme.TEXT_SEC, sizeSp = 11f))
        permBanner.addView(permText)
        col.addView(permBanner)

        val kpiRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        downKpi = kpiCell(kpiRow, "DOWNLOAD", Category.RX)
        upKpi = kpiCell(kpiRow, "UPLOAD", Category.TX)
        peakKpi = kpiCell(kpiRow, "PEAK", Color.rgb(0xF0, 0xAB, 0xFC))
        col.addView(kpiRow)

        val chartCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(Theme.dp(this@MainActivity, 12), Theme.dp(this@MainActivity, 12), Theme.dp(this@MainActivity, 12), Theme.dp(this@MainActivity, 8))
            background = Theme.card(radiusPx = Theme.dp(this@MainActivity, 16).toFloat())
        }
        val legend = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        legend.addView(Theme.text(this, "● RX  ", color = Category.RX, sizeSp = 11f, bold = true, mono = true))
        legend.addView(Theme.text(this, "● TX", color = Category.TX, sizeSp = 11f, bold = true, mono = true))
        legend.addView(Theme.space(this, 8, 1))
        sampleCount = Theme.text(this, "", color = Theme.TEXT_SEC, sizeSp = 11f, mono = true)
        legend.addView(sampleCount)
        chartCard.addView(legend)
        chart = AreaChartView(this)
        chartCard.addView(
            chart,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Theme.dp(this, 230))
        )
        col.addView(chartCard)

        col.addView(Theme.space(this, 5, 14))
        col.addView(Theme.text(this, "TOP APPS", sizeSp = 11f, bold = true, color = Theme.TEXT_SEC))
        col.addView(Theme.space(this, 5, 6))
        rankCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(rankCard)

        col.addView(Theme.space(this, 5, 14))
        col.addView(Theme.text(this, "PER-APP BANDWIDTH", sizeSp = 11f, bold = true, color = Theme.TEXT_SEC))
        col.addView(Theme.space(this, 5, 6))
        appCard = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(appCard)

        col.addView(Theme.space(this, 5, 18))
        col.addView(Theme.text(this, "v1.0 · zero-exfil: no network permission, all stats stay on-device", color = Theme.TEXT_SEC, sizeSp = 10f, alpha = 0.7f))
    }

    private fun kpiCell(parent: LinearLayout, title: String, color: Int): TextView {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(Theme.dp(this@MainActivity, 12), Theme.dp(this@MainActivity, 12), Theme.dp(this@MainActivity, 12), Theme.dp(this@MainActivity, 12))
            background = Theme.card(radiusPx = Theme.dp(this@MainActivity, 14).toFloat())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        card.addView(Theme.text(this, title, color = color, sizeSp = 10f, bold = true, mono = true))
        val value = Theme.text(this, "—", sizeSp = 17f, bold = true, mono = true)
        card.addView(value)
        val lp = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        lp.setMargins(0, Theme.dp(this, 8), 0, 0)
        value.layoutParams = lp
        parent.addView(card)
        return value
    }

    private fun render(s: Snapshot) {
        modeBadge.text = when {
            !engine.hasUsageAccess() -> "■ NO USE-ACCESS"
            s.mode == "LIVE" -> "● LIVE"
            else -> "● SIMULATION"
        }
        modeBadge.setTextColor(
            when {
                !engine.hasUsageAccess() -> Color.rgb(0xEF, 0x44, 0x44)
                s.mode == "LIVE" -> Color.rgb(0x34, 0xD3, 0x99)
                else -> Color.rgb(0xFB, 0xBF, 0x24)
            }
        )
        permBanner.visibility = if (engine.hasUsageAccess()) View.GONE else View.VISIBLE

        downKpi.text = Theme.fmtBps(s.totalRx)
        upKpi.text = Theme.fmtBps(s.totalTx)
        val peak = engine.peak()
        peakKpi.text = Theme.fmtBps(peak.rx)

        chart.setData(ArrayList(engine.rxHistory), ArrayList(engine.txHistory), ArrayList(engine.labels))
        sampleCount.text = "${engine.samples} samples · ${engine.mode.name}"

        val apps = s.apps
        rankCard.removeAllViews()
        for ((i, a) in apps.take(5).withIndex()) {
            val total = apps.sumOf { it.totalBps }
            val share = if (total <= 0) 0f else a.totalBps.toFloat() / total
            rankCard.addView(RankBarView(this, a, share, i + 1))
            if (i < apps.take(5).size - 1) rankCard.addView(Theme.space(this, 1, 6))
        }

        appCard.removeAllViews()
        val maxTotal = apps.maxOfOrNull { it.totalBps } ?: 0L
        for (a in apps) {
            appCard.addView(AppRowView(this, a, maxTotal) { showDetail(a) })
            appCard.addView(Theme.space(this, 1, 7))
        }
    }

    private fun showDetail(a: AppSample) {
        val key = "${a.uid}:${a.name}"
        val points = engine.appHistory[key] ?: emptyList()
        val rxSum = points.sumOf { it.rx }
        val txSum = points.sumOf { it.tx }

        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(Theme.dp(this@MainActivity, 20), Theme.dp(this@MainActivity, 16), Theme.dp(this@MainActivity, 20), Theme.dp(this@MainActivity, 16))
        }
        body.addView(Theme.text(this, a.name, sizeSp = 16f, bold = true))
        body.addView(Theme.text(this, "${a.cat} · PID ${a.uid} · ${a.conns} connections", color = a.color, sizeSp = 11f))
        body.addView(Theme.space(this, 1, 6))
        body.addView(Theme.text(this, "current: ↓${Theme.fmtBps(a.rxBps)} · ↑${Theme.fmtBps(a.txBps)}", sizeSp = 12f, mono = true))
        if (points.isNotEmpty()) {
            body.addView(Theme.text(this, "last 80 samples: ↓${Theme.fmtBytes(rxSum / points.size)}/s avg · ↑${Theme.fmtBytes(txSum / points.size)}/s avg", color = Theme.TEXT_SEC, sizeSp = 11f))
            body.addView(Theme.space(this, 1, 10))
            val spark = SparklineView(this)
            spark.setPoints(points)
            body.addView(spark, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Theme.dp(this, 150)))
        }

        AlertDialog.Builder(this)
            .setTitle("App detail")
            .setView(body)
            .setPositiveButton("Close", null)
            .create()
            .apply {
                window?.setBackgroundDrawable(Theme.card(radiusPx = Theme.dp(this@MainActivity, 18).toFloat()))
                show()
            }
    }
}