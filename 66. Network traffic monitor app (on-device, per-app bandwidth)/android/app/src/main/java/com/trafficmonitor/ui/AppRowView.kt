package com.trafficmonitor.ui

import android.content.Context
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import com.trafficmonitor.AppSample
import com.trafficmonitor.Category

/** One per-app dashboard row: color chip, name/category, live rates, RX/TX bars. */
class AppRowView(context: Context, private val a: AppSample, maxTotal: Long, onClick: () -> Unit) :
    LinearLayout(context) {

    init {
        orientation = LinearLayout.VERTICAL
        setPadding(Theme.dp(context, 12), Theme.dp(context, 10), Theme.dp(context, 12), Theme.dp(context, 10))
        background = Theme.card(radiusPx = Theme.dp(context, 12).toFloat())
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }

        val topRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        topRow.addView(View(context).apply { background = Theme.oval(a.color) }, Theme.dp(context, 10), Theme.dp(context, 10))
        topRow.addView(Theme.space(context, 10, 1))

        val nameCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        nameCol.addView(Theme.text(context, a.name, sizeSp = 13f, bold = true).apply {
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        })
        val catLabel = "${a.cat} · ${a.conns} conns"
        nameCol.addView(
            Theme.text(context, catLabel, color = a.color, sizeSp = 10f, alpha = 0.85f)
        )
        topRow.addView(nameCol)

        val speeds = Theme.text(
            context,
            "↓${Theme.fmtBps(a.rxBps)}  ↑${Theme.fmtBps(a.txBps)}",
            sizeSp = 11f,
            mono = true,
            alpha = 0.9f
        )
        topRow.addView(speeds)

        addView(topRow, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT))

        addView(Theme.space(context, 1, 7))
        addView(bar(context, a.rxBps, maxTotal, Category.RX))
        addView(Theme.space(context, 1, 4))
        addView(bar(context, a.txBps, maxTotal, Category.TX))
    }

    private fun bar(context: Context, bps: Long, maxTotal: Long, color: Int): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        row.addView(Theme.text(context, if (color == Category.RX) "↓" else "↑", color = color, sizeSp = 9f, bold = true, mono = true))

        val frac = if (maxTotal <= 0) 0f else (bps.toFloat() / maxTotal).coerceIn(0f, 1f)

        val track = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = GradientDrawable().apply {
                cornerRadius = Theme.dp(context, 3).toFloat()
                setColor(0x0DFFFFFF.toInt())
            }
            setPadding(1, 1, 1, 1)
            layoutParams = LinearLayout.LayoutParams(0, Theme.dp(context, 5), 1f)
        }
        val fill = View(context).apply {
            background = GradientDrawable().apply {
                cornerRadius = Theme.dp(context, 2).toFloat()
                setColor(color)
            }
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, frac)
        }
        track.addView(fill)
        row.addView(track)
        return row
    }
}