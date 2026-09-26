package com.trafficmonitor.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Shader
import android.view.View

/**
 * Port of the dashboard's canvas area chart (public/app.js drawArea()):
 * RX cyan + TX violet area series on a dark grid.
 */
class AreaChartView(context: Context) : View(context) {

    private var rx: List<Long> = emptyList()
    private var tx: List<Long> = emptyList()
    private var labels: List<String> = emptyList()

    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(15, 255, 255, 255)
        strokeWidth = 1f
    }
    private val rxFill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val txFill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rxLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Theme.rxColor()
        strokeWidth = dp(2f)
        style = Paint.Style.STROKE
        strokeJoin = Paint.Join.ROUND
        strokeCap = Paint.Cap.ROUND
    }
    private val txLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Theme.txColor()
        strokeWidth = dp(2f)
        style = Paint.Style.STROKE
        strokeJoin = Paint.Join.ROUND
        strokeCap = Paint.Cap.ROUND
    }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Theme.TEXT_SEC
        textSize = sp(9f)
    }
    private val emptyPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Theme.TEXT_SEC
        textSize = sp(11f)
        textAlign = Paint.Align.CENTER
    }
    private val path = Path()

    fun setData(rx: List<Long>, tx: List<Long>, labels: List<String>) {
        this.rx = rx
        this.tx = tx
        this.labels = labels
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        val padBottom = sp(16f)
        val padTop = dp(8f)

        if (rx.isEmpty() || tx.isEmpty()) {
            canvas.drawText("awaiting first sample…", w / 2, h / 2, emptyPaint)
            return
        }

        var maxV = 1L
        for (v in rx) if (v > maxV) maxV = v
        for (v in tx) if (v > maxV) maxV = v
        maxV = (maxV * 115L) / 100L

        val chartH = h - padBottom - padTop
        val n = maxOf(rx.size, tx.size)
        val stepX = if (n <= 1) w else w / (n - 1)

        for (i in 0 until 4) {
            val y = padTop + chartH * i / 3f
            canvas.drawLine(0f, y, w, y, gridPaint)
        }

        drawSeries(canvas, rx, maxV, stepX, w, padTop, chartH, rxFill, rxLine, Theme.rxColor())
        drawSeries(canvas, tx, maxV, stepX, w, padTop, chartH, txFill, txLine, Theme.txColor())

        if (labels.isNotEmpty()) {
            canvas.drawText(labels.first(), dp(4f), h - sp(3f), labelPaint)
            val end = labels.last()
            canvas.drawText(end, w - labelPaint.measureText(end) - dp(4f), h - sp(3f), labelPaint)
        }
    }

    private fun drawSeries(
        canvas: Canvas,
        values: List<Long>,
        maxV: Long,
        stepX: Float,
        w: Float,
        padTop: Float,
        chartH: Float,
        fill: Paint,
        line: Paint,
        color: Int
    ) {
        if (values.isEmpty()) return
        path.reset()
        val n = values.size
        for (i in values.indices) {
            val x = if (n <= 1) 0f else i * stepX
            val y = padTop + chartH - (values[i].toFloat() / maxV) * chartH
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        val area = Path(path)
        val lastX = if (n <= 1) w else (n - 1) * stepX
        area.lineTo(lastX, padTop + chartH)
        area.lineTo(0f, padTop + chartH)
        area.close()

        fill.shader = LinearGradient(
            0f, padTop, 0f, padTop + chartH,
            color,
            Color.argb(0, Color.red(color), Color.green(color), Color.blue(color)),
            Shader.TileMode.CLAMP
        )
        canvas.drawPath(area, fill)
        canvas.drawPath(path, line)
    }

    private fun dp(v: Float): Float = v * resources.displayMetrics.density
    private fun sp(v: Float): Float = v * resources.displayMetrics.scaledDensity
}