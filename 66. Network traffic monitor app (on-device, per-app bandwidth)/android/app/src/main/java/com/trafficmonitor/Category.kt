package com.trafficmonitor

import android.graphics.Color

object Category {
    val RX: Int = Color.rgb(0x22, 0xD3, 0xEE) // #22d3ee
    val TX: Int = Color.rgb(0xA7, 0x8B, 0xFA) // #a78bfa

    const val CAT_BROWSER = "browser"
    const val CAT_STREAMING = "streaming"
    const val CAT_GAMING = "gaming"
    const val CAT_SYSTEM = "system"
    const val CAT_OTHER = "other"

    fun classify(uid: Int, pkg: String): String {
        if (uid < 10000) return CAT_SYSTEM
        val p = pkg.lowercase()
        return when {
            p.contains("chrome") || p.contains("mozilla") || p.contains("firefox") ||
                p.contains("opera") || p.contains("browser") || p.contains("brave") ||
                p.contains("duckduckgo") || p.contains("edge") || p.contains("kiwi") -> CAT_BROWSER

            p.contains("youtube") || p.contains("twitch") || p.contains("netflix") ||
                p.contains("hulu") || p.contains("primevideo") || p.contains("spotify") ||
                p.contains("deezer") || p.contains("soundcloud") || p.contains("pandora") ||
                p.contains("radio") || p.contains("music") -> CAT_STREAMING

            p.contains("supercell") || p.contains("roblox") || p.contains("epicgames") ||
                p.contains("tencent") || p.contains("miHoYo") || p.contains("glu") ||
                p.contains("game.") || p.contains(".games.") || p.contains("videogame") -> CAT_GAMING

            else -> CAT_OTHER
        }
    }

    fun color(cat: String): Int = when (cat) {
        CAT_BROWSER -> Color.parseColor("#4fc3f7")
        CAT_STREAMING -> Color.parseColor("#7c4dff")
        CAT_GAMING -> Color.parseColor("#f472b6")
        CAT_SYSTEM -> Color.parseColor("#94a3b8")
        else -> Color.parseColor("#fbbf24")
    }
}