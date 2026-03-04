package com.followcat.zagora.ui

import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import com.followcat.zagora.R

enum class TerminalFontPack(val id: String, val title: String) {
    System("system", "System Mono"),
    JetBrains("jetbrains", "JetBrains Mono"),
    JetBrainsNerd("jetbrains_nerd", "JetBrains + Nerd");

    companion object {
        fun fromId(id: String): TerminalFontPack = entries.firstOrNull { it.id == id } ?: System
    }
}

fun terminalFontFamily(pack: TerminalFontPack): FontFamily = when (pack) {
    TerminalFontPack.System -> FontFamily.Monospace
    TerminalFontPack.JetBrains -> FontFamily(Font(R.font.jetbrainsmono_regular))
    TerminalFontPack.JetBrainsNerd -> FontFamily(Font(R.font.jetbrainsmono_nerd_regular))
}
