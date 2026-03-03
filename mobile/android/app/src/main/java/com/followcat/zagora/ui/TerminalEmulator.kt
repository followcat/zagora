package com.followcat.zagora.ui

private const val ESC = '\u001B'

class TerminalEmulator(
    private val cols: Int = 100,
    private val rows: Int = 36,
    private val scrollbackLimit: Int = 1500
) {
    private enum class ParseState { NORMAL, ESCAPE, CSI, OSC }

    private var state = ParseState.NORMAL
    private val csiBuf = StringBuilder()
    private val oscBuf = StringBuilder()
    private var oscEscSeen = false

    private val history = ArrayDeque<String>()
    private var primary = emptyScreen()
    private var alternate = emptyScreen()
    private var useAlternate = false

    private var cursorRow = 0
    private var cursorCol = 0
    private var savedRow = 0
    private var savedCol = 0

    fun reset() {
        state = ParseState.NORMAL
        csiBuf.setLength(0)
        oscBuf.setLength(0)
        oscEscSeen = false
        history.clear()
        primary = emptyScreen()
        alternate = emptyScreen()
        useAlternate = false
        cursorRow = 0
        cursorCol = 0
        savedRow = 0
        savedCol = 0
    }

    fun feed(text: String) {
        for (ch in text) {
            when (state) {
                ParseState.NORMAL -> onNormal(ch)
                ParseState.ESCAPE -> onEscape(ch)
                ParseState.CSI -> onCsi(ch)
                ParseState.OSC -> onOsc(ch)
            }
        }
    }

    fun renderText(): String {
        val lines = ArrayList<String>(history.size + rows)
        lines.addAll(history)
        val screen = activeScreen()
        for (r in 0 until rows) {
            val line = String(screen[r]).trimEnd()
            lines.add(line)
        }
        return lines.joinToString("\n")
    }

    private fun onNormal(ch: Char) {
        when (ch) {
            ESC -> state = ParseState.ESCAPE
            '\n' -> lineFeed()
            '\r' -> cursorCol = 0
            '\b' -> cursorCol = (cursorCol - 1).coerceAtLeast(0)
            '\t' -> {
                val nextStop = ((cursorCol / 8) + 1) * 8
                cursorCol = nextStop.coerceAtMost(cols - 1)
            }
            else -> {
                if (ch >= ' ') {
                    putChar(ch)
                }
            }
        }
    }

    private fun onEscape(ch: Char) {
        when (ch) {
            '[' -> {
                csiBuf.setLength(0)
                state = ParseState.CSI
            }
            ']' -> {
                oscBuf.setLength(0)
                oscEscSeen = false
                state = ParseState.OSC
            }
            '7' -> {
                savedRow = cursorRow
                savedCol = cursorCol
                state = ParseState.NORMAL
            }
            '8' -> {
                cursorRow = savedRow.coerceIn(0, rows - 1)
                cursorCol = savedCol.coerceIn(0, cols - 1)
                state = ParseState.NORMAL
            }
            'D' -> {
                lineFeed()
                state = ParseState.NORMAL
            }
            'M' -> {
                reverseIndex()
                state = ParseState.NORMAL
            }
            'E' -> {
                lineFeed()
                cursorCol = 0
                state = ParseState.NORMAL
            }
            else -> {
                state = ParseState.NORMAL
            }
        }
    }

    private fun onCsi(ch: Char) {
        val code = ch.code
        if (code in 0x40..0x7E) {
            handleCsi(csiBuf.toString(), ch)
            csiBuf.setLength(0)
            state = ParseState.NORMAL
            return
        }
        csiBuf.append(ch)
    }

    private fun onOsc(ch: Char) {
        if (ch == '\u0007') {
            state = ParseState.NORMAL
            oscBuf.setLength(0)
            oscEscSeen = false
            return
        }
        if (oscEscSeen && ch == '\\') {
            state = ParseState.NORMAL
            oscBuf.setLength(0)
            oscEscSeen = false
            return
        }
        oscEscSeen = (ch == ESC)
        oscBuf.append(ch)
    }

    private fun handleCsi(raw: String, final: Char) {
        val isPrivate = raw.startsWith("?")
        val body = if (isPrivate) raw.drop(1) else raw
        val params = body.split(';').map { it.toIntOrNull() ?: 0 }
        val p1 = params.firstOrNull() ?: 0
        when (final) {
            'A' -> cursorRow = (cursorRow - (if (p1 == 0) 1 else p1)).coerceAtLeast(0)
            'B' -> cursorRow = (cursorRow + (if (p1 == 0) 1 else p1)).coerceAtMost(rows - 1)
            'C' -> cursorCol = (cursorCol + (if (p1 == 0) 1 else p1)).coerceAtMost(cols - 1)
            'D' -> cursorCol = (cursorCol - (if (p1 == 0) 1 else p1)).coerceAtLeast(0)
            'H', 'f' -> {
                val r = ((params.getOrNull(0) ?: 1) - 1).coerceIn(0, rows - 1)
                val c = ((params.getOrNull(1) ?: 1) - 1).coerceIn(0, cols - 1)
                cursorRow = r
                cursorCol = c
            }
            'J' -> eraseInDisplay(p1)
            'K' -> eraseInLine(p1)
            'm' -> {
                // Ignore colors/styles for now.
            }
            's' -> {
                savedRow = cursorRow
                savedCol = cursorCol
            }
            'u' -> {
                cursorRow = savedRow.coerceIn(0, rows - 1)
                cursorCol = savedCol.coerceIn(0, cols - 1)
            }
            'h' -> if (isPrivate) handlePrivateMode(body, true)
            'l' -> if (isPrivate) handlePrivateMode(body, false)
            else -> {
                // Unsupported CSI: ignore safely.
            }
        }
    }

    private fun handlePrivateMode(body: String, enabled: Boolean) {
        if (body == "1049" || body == "47" || body == "1047") {
            useAlternate = enabled
            if (enabled) {
                alternate = emptyScreen()
                cursorRow = 0
                cursorCol = 0
            } else {
                cursorRow = cursorRow.coerceIn(0, rows - 1)
                cursorCol = cursorCol.coerceIn(0, cols - 1)
            }
        }
    }

    private fun eraseInDisplay(mode: Int) {
        when (mode) {
            2 -> {
                val screen = activeScreen()
                for (r in 0 until rows) {
                    screen[r].fill(' ')
                }
                cursorRow = 0
                cursorCol = 0
            }
            0 -> {
                val screen = activeScreen()
                // Cursor to end of screen
                for (c in cursorCol until cols) screen[cursorRow][c] = ' '
                for (r in (cursorRow + 1) until rows) screen[r].fill(' ')
            }
            1 -> {
                val screen = activeScreen()
                // Start of screen to cursor
                for (r in 0 until cursorRow) screen[r].fill(' ')
                for (c in 0..cursorCol.coerceAtMost(cols - 1)) screen[cursorRow][c] = ' '
            }
        }
    }

    private fun eraseInLine(mode: Int) {
        val line = activeScreen()[cursorRow]
        when (mode) {
            0 -> for (c in cursorCol until cols) line[c] = ' '
            1 -> for (c in 0..cursorCol.coerceAtMost(cols - 1)) line[c] = ' '
            2 -> line.fill(' ')
        }
    }

    private fun putChar(ch: Char) {
        val screen = activeScreen()
        screen[cursorRow][cursorCol] = ch
        cursorCol++
        if (cursorCol >= cols) {
            cursorCol = 0
            lineFeed()
        }
    }

    private fun lineFeed() {
        if (cursorRow == rows - 1) {
            scrollUp()
        } else {
            cursorRow++
        }
    }

    private fun reverseIndex() {
        if (cursorRow == 0) {
            val screen = activeScreen()
            for (r in (rows - 1) downTo 1) {
                screen[r] = screen[r - 1].copyOf()
            }
            screen[0] = CharArray(cols) { ' ' }
        } else {
            cursorRow--
        }
    }

    private fun scrollUp() {
        val screen = activeScreen()
        if (!useAlternate) {
            history.addLast(String(screen[0]))
            while (history.size > scrollbackLimit) history.removeFirst()
        }
        for (r in 0 until rows - 1) {
            screen[r] = screen[r + 1]
        }
        screen[rows - 1] = CharArray(cols) { ' ' }
    }

    private fun activeScreen(): Array<CharArray> = if (useAlternate) alternate else primary

    private fun emptyScreen(): Array<CharArray> = Array(rows) { CharArray(cols) { ' ' } }
}
