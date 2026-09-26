package com.trafficmonitor.ui

import android.content.Context
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import com.trafficmonitor.AppSample

/** Horizontal "top apps" ranking bar (mirrors the web dashboard's ranking list). */
class RankBarView(context: Context, a: AppSample, share: Float, rank: Int) : LinearLayout(context) {

    init {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        )
        setPadding(Theme.dp(context, 12), Theme.dp(context, 9), Theme.dp(context, 12), Theme.dp(context, 9))
        background = Theme.card(radiusPx = Theme.dp(context, 12).toFloat())

        addView(Theme.text(context, "#$rank", color = a.color, sizeSp = 11f, bold = true, mono = true))
        addView(Theme.space(context, 12, 1))

        val nameCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        nameCol.addView(Theme.text(context, a.name, sizeSp = 12f, bold = true).apply {
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        })
        nameCol.addView(Theme.text(context, "${a.cat}", color = a.color, sizeSp = 9f, alpha = 0.85f))
        addView(nameCol)

        addView(Theme.space(context, 10, 1))
        addView(Theme.text(context, Theme.fmtBps(a.totalBps), sizeSp = 11f, mono = true, alpha = 0.9f))
    }
}