package com.followcat.zagora.ui

import java.nio.charset.StandardCharsets

sealed interface TerminalKeyAction {
    data class Text(val value: String) : TerminalKeyAction
    data class Ctrl(val letter: Char) : TerminalKeyAction
    data class Alt(val letter: Char) : TerminalKeyAction
    data object CtrlC : TerminalKeyAction
    data object Escape : TerminalKeyAction
    data object Tab : TerminalKeyAction
    data object ShiftTab : TerminalKeyAction
    data object ArrowUp : TerminalKeyAction
    data object ArrowDown : TerminalKeyAction
    data object ArrowLeft : TerminalKeyAction
    data object ArrowRight : TerminalKeyAction
    data object PageUp : TerminalKeyAction
    data object PageDown : TerminalKeyAction
    data object Home : TerminalKeyAction
    data object End : TerminalKeyAction
}

data class StickyModifiers(
    val ctrl: Boolean = false,
    val alt: Boolean = false
)

object TerminalKeyMapper {
    fun encode(action: TerminalKeyAction): ByteArray {
        return when (action) {
            is TerminalKeyAction.Text -> action.value.toByteArray(StandardCharsets.UTF_8)
            is TerminalKeyAction.Ctrl -> ctrlBytes(action.letter)
            is TerminalKeyAction.Alt -> byteArrayOf(0x1B, action.letter.code.toByte())
            TerminalKeyAction.CtrlC -> byteArrayOf(3)
            TerminalKeyAction.Escape -> byteArrayOf(0x1B)
            TerminalKeyAction.Tab -> byteArrayOf('\t'.code.toByte())
            TerminalKeyAction.ShiftTab -> "\u001B[Z".toByteArray(StandardCharsets.UTF_8)
            TerminalKeyAction.ArrowUp -> "\u001B[A".toByteArray(StandardCharsets.UTF_8)
            TerminalKeyAction.ArrowDown -> "\u001B[B".toByteArray(StandardCharsets.UTF_8)
            TerminalKeyAction.ArrowRight -> "\u001B[C".toByteArray(StandardCharsets.UTF_8)
            TerminalKeyAction.ArrowLeft -> "\u001B[D".toByteArray(StandardCharsets.UTF_8)
            TerminalKeyAction.PageUp -> "\u001B[5~".toByteArray(StandardCharsets.UTF_8)
            TerminalKeyAction.PageDown -> "\u001B[6~".toByteArray(StandardCharsets.UTF_8)
            TerminalKeyAction.Home -> "\u001B[H".toByteArray(StandardCharsets.UTF_8)
            TerminalKeyAction.End -> "\u001B[F".toByteArray(StandardCharsets.UTF_8)
        }
    }

    fun applySticky(text: String, sticky: StickyModifiers): ByteArray {
        if (text.isEmpty()) return ByteArray(0)
        if (!sticky.ctrl && !sticky.alt) {
            return text.toByteArray(StandardCharsets.UTF_8)
        }
        if (text.length == 1) {
            val c = text[0]
            if (sticky.ctrl && c.isLetter()) {
                val ctrl = ctrlBytes(c)
                return if (sticky.alt) byteArrayOf(0x1B) + ctrl else ctrl
            }
            if (sticky.alt) {
                return byteArrayOf(0x1B, c.code.toByte())
            }
        }
        val base = text.toByteArray(StandardCharsets.UTF_8)
        return if (sticky.alt) byteArrayOf(0x1B) + base else base
    }

    private fun ctrlBytes(letter: Char): ByteArray {
        val upper = letter.uppercaseChar()
        return if (upper in 'A'..'Z') {
            byteArrayOf((upper.code - 64).toByte())
        } else {
            ByteArray(0)
        }
    }
}

