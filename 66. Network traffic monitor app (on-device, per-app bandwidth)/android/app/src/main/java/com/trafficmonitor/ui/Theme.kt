package com.trafficmonitor.ui

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.View
import android.widget.TextView
import com.trafficmonitor.Category

object Theme {
    val BG = Color.rgb(0x0B, 0x11, 0x20)
    val TEXT_PRI = Color.rgb(0xF1, 0xF5, 0xF9)
    val TEXT_SEC = Color.rgb(0x94, 0xA3, 0xB8)

    fun dp(ctx: Context, v: Int): Int = (v * ctx.resources.displayMetrics.density).toInt()

    fun card(color: Int = 0x14FFFFFF.toInt(), radiusPx: Float = 0f): GradientDrawable =
        GradientDrawable().apply {
            cornerRadius = radiusPx
            setColor(color)
            setStroke(1, 0x14FFFFFF.toInt())
        }

    fun oval(color: Int): GradientDrawable =
        GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(color)
        }

    fun text(
        ctx: Context,
        value: String,
        color: Int = TEXT_PRI,
        sizeSp: Float = 13f,
        bold: Boolean = false,
        mono: Boolean = false,
        alpha: Float = 1f
    ): TextView = TextView(ctx).apply {
        text = value
        setTextColor(color)
        textSize = sizeSp
        typeface = if (mono) Typeface.MONOSPACE else if (bold) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
        setLineSpacing(0f, 1.1f)
        this.alpha = alpha
    }

    fun fmtBps(v: Long): String = when {
        v >= 1_000_000 -> String.format("%.1f MB/s", v / 1_000_000.0)
        v >= 1_000 -> String.format("%.1f KB/s", v / 1_000.0)
        else -> "$v B/s"
    }

    fun fmtBytes(v: Long): String = when {
        v >= 1_073_741_824 -> String.format("%.1f GB", v / 1_073_741_824.0)
        v >= 1_048_576 -> String.format("%.1f MB", v / 1_048_576.0)
        v >= 1_024 -> String.format("%.0f KB", v / 1_024.0)
        else -> "$v B"
    }

    fun space(ctx: Context, wDp: Int, hDp: Int): View = View(ctx).apply {
        layoutParams = android.view.ViewGroup.LayoutParams(dp(ctx, wDp), dp(ctx, hDp))
    }

    fun rxColor(): Int = Category.RX
    fun txColor(): Int = Category.TX
}