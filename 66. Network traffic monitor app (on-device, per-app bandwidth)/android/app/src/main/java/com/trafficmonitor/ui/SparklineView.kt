package com.trafficmonitor.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Shader
import android.view.View
import com.trafficmonitor.AppPoint

/** Port of the drawer's 80-sample sparkline (public/app.js renderDrawer()). */
class SparklineView(context: Context) : View(context) {

    private var points: List<AppPoint> = emptyList()

    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(12, 255, 255, 255)
        strokeWidth = 1f
    }
    private val rxFill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val txFill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rxLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Theme.rxColor(); strokeWidth = dp(1.6f); style = Paint.Style.STROKE
    }
    private val txLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Theme.txColor(); strokeWidth = dp(1.6f); style = Paint.Style.STROKE
    }
    private val path = Path()

    fun setPoints(points: List<AppPoint>) {
        this.points = points
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        if (points.size < 2) return

        var maxV = 1L
        for (p in points) {
            if (p.rx > maxV) maxV = p.rx
            if (p.tx > maxV) maxV = p.tx
        }
        maxV = (maxV * 120L) / 100L

        for (i in 0 until 3) {
            val y = h * i / 2f
            canvas.drawLine(0f, y, w, y, gridPaint)
        }

        val step = w / (points.size - 1)
        draw(canvas, points.map { it.rx }, maxV, step, w, h, rxFill, rxLine, Theme.rxColor())
        draw(canvas, points.map { it.tx }, maxV, step, w, h, txFill, txLine, Theme.txColor())
    }

    private fun draw(
        canvas: Canvas,
        values: List<Long>,
        maxV: Long,
        step: Float,
        w: Float,
        h: Float,
        fill: Paint,
        line: Paint,
        color: Int
    ) {
        path.reset()
        for (i in values.indices) {
            val x = i * step
            val y = h - (values[i].toFloat() / maxV) * h
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        val area = Path(path)
        area.lineTo(w, h)
        area.lineTo(0f, h)
        area.close()
        fill.shader = LinearGradient(
            0f, 0f, 0f, h,
            color, Color.argb(0, Color.red(color), Color.green(color), Color.blue(color)),
            Shader.TileMode.CLAMP
        )
        canvas.drawPath(area, fill)
        canvas.drawPath(path, line)
    }

    private fun dp(v: Float): Float = v * resources.displayMetrics.density
}