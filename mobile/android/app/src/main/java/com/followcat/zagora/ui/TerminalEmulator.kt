package com.followcat.zagora.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle

private const val ESC = '\u001B'

private data class Cell(
    var ch: Char = ' ',
    var fg: Int = AnsiColor.DEFAULT,
    var bg: Int = AnsiColor.DEFAULT
)

private typealias CellArray = Array<Cell>

private object AnsiColor {
    const val DEFAULT = -1
    private val NORMAL = listOf(
        Color(0xFF111111), // black
        Color(0xFFE05A5A), // red
        Color(0xFF7ACB88), // green
        Color(0xFFE0C46A), // yellow
        Color(0xFF7AA2F7), // blue
        Color(0xFFC792EA), // magenta
        Color(0xFF7DCFFF), // cyan
        Color(0xFFE5E9F0)  // white
    )
    private val BRIGHT = listOf(
        Color(0xFF4B5563),
        Color(0xFFF87171),
        Color(0xFF86EFAC),
        Color(0xFFFDE68A),
        Color(0xFF93C5FD),
        Color(0xFFD8B4FE),
        Color(0xFF67E8F9),
        Color(0xFFF8FAFC)
    )

    fun resolve(code: Int): Color = when {
        code in 0..7 -> NORMAL[code]
        code in 8..15 -> BRIGHT[code - 8]
        else -> Color.Unspecified
    }
}

data class TerminalColorPalette(
    val defaultForeground: Color,
    val defaultBackground: Color
)

class TerminalEmulator(
    cols: Int = 100,
    rows: Int = 36,
    private val scrollbackLimit: Int = 1500,
    private var allowPrivateUseGlyphs: Boolean = false
) {
    private enum class ParseState { NORMAL, ESCAPE, CSI, OSC, CHARSET }

    private var cols = cols.coerceAtLeast(8)
    private var rows = rows.coerceAtLeast(4)

    private var state = ParseState.NORMAL
    private val csiBuf = StringBuilder()
    private val oscBuf = StringBuilder()
    private var oscEscSeen = false
    private var charsetPrefix: Char = '('

    private val history = ArrayDeque<CellArray>()
    private var primary = emptyScreen()
    private var alternate = emptyScreen()
    private var useAlternate = false

    private var cursorRow = 0
    private var cursorCol = 0
    private var savedRow = 0
    private var savedCol = 0
    private var currentFg = AnsiColor.DEFAULT
    private var currentBg = AnsiColor.DEFAULT
    private var decLineDrawing = false

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
        currentFg = AnsiColor.DEFAULT
        currentBg = AnsiColor.DEFAULT
        decLineDrawing = false
    }

    fun setAllowPrivateUseGlyphs(enabled: Boolean) {
        allowPrivateUseGlyphs = enabled
    }

    fun resize(newCols: Int, newRows: Int) {
        val targetCols = newCols.coerceAtLeast(8)
        val targetRows = newRows.coerceAtLeast(4)
        if (targetCols == cols && targetRows == rows) return

        primary = resizeScreen(primary, cols, rows, targetCols, targetRows)
        alternate = resizeScreen(alternate, cols, rows, targetCols, targetRows)

        val resizedHistory = ArrayDeque<CellArray>()
        for (line in history) {
            resizedHistory.addLast(resizeRow(line, cols, targetCols))
            while (resizedHistory.size > scrollbackLimit) resizedHistory.removeFirst()
        }
        history.clear()
        history.addAll(resizedHistory)

        cols = targetCols
        rows = targetRows
        cursorRow = cursorRow.coerceIn(0, rows - 1)
        cursorCol = cursorCol.coerceIn(0, cols - 1)
        savedRow = savedRow.coerceIn(0, rows - 1)
        savedCol = savedCol.coerceIn(0, cols - 1)
    }

    fun feed(text: String) {
        for (ch in text) {
            when (state) {
                ParseState.NORMAL -> onNormal(ch)
                ParseState.ESCAPE -> onEscape(ch)
                ParseState.CSI -> onCsi(ch)
                ParseState.OSC -> onOsc(ch)
                ParseState.CHARSET -> onCharset(ch)
            }
        }
    }

    fun renderText(): String {
        val lines = ArrayList<String>(history.size + rows)
        for (line in history) {
            lines.add(charsFromRow(line).trimEnd())
        }
        val screen = activeScreen()
        for (r in 0 until rows) {
            lines.add(charsFromRow(screen[r]).trimEnd())
        }
        return lines.joinToString("\n")
    }

    fun renderAnnotated(palette: TerminalColorPalette): AnnotatedString {
        val lines = ArrayList<CellArray>(history.size + rows)
        for (line in history) {
            lines.add(line)
        }
        val screen = activeScreen()
        for (r in 0 until rows) {
            lines.add(screen[r])
        }
        return buildAnnotatedString {
            lines.forEachIndexed { index, row ->
                appendRowWithStyles(row, palette)
                if (index < lines.lastIndex) append('\n')
            }
        }
    }

    private fun onNormal(ch: Char) {
        when (ch) {
            ESC -> state = ParseState.ESCAPE
            '\u009B' -> {
                csiBuf.setLength(0)
                state = ParseState.CSI
            }
            '\u009D' -> {
                oscBuf.setLength(0)
                oscEscSeen = false
                state = ParseState.OSC
            }
            '\u000E' -> decLineDrawing = true
            '\u000F' -> decLineDrawing = false
            '\n' -> lineFeed()
            '\r' -> cursorCol = 0
            '\b' -> cursorCol = (cursorCol - 1).coerceAtLeast(0)
            '\t' -> {
                val nextStop = ((cursorCol / 8) + 1) * 8
                cursorCol = nextStop.coerceAtMost(cols - 1)
            }
            else -> if (ch >= ' ' && !Character.isISOControl(ch)) putChar(mapChar(ch))
        }
    }

    private fun onEscape(ch: Char) {
        when (ch) {
            '[' -> {
                csiBuf.setLength(0)
                state = ParseState.CSI
            }
            '(',
            ')' -> {
                charsetPrefix = ch
                state = ParseState.CHARSET
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
            else -> state = ParseState.NORMAL
        }
    }

    private fun onCharset(ch: Char) {
        if (charsetPrefix == '(' || charsetPrefix == ')') {
            decLineDrawing = (ch == '0')
        }
        state = ParseState.NORMAL
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
            'm' -> applySgr(params)
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
            else -> Unit
        }
    }

    private fun applySgr(params: List<Int>) {
        if (params.isEmpty()) {
            currentFg = AnsiColor.DEFAULT
            currentBg = AnsiColor.DEFAULT
            return
        }
        for (code in params) {
            when {
                code == 0 -> {
                    currentFg = AnsiColor.DEFAULT
                    currentBg = AnsiColor.DEFAULT
                }
                code == 39 -> currentFg = AnsiColor.DEFAULT
                code == 49 -> currentBg = AnsiColor.DEFAULT
                code in 30..37 -> currentFg = code - 30
                code in 90..97 -> currentFg = (code - 90) + 8
                code in 40..47 -> currentBg = code - 40
                code in 100..107 -> currentBg = (code - 100) + 8
                else -> Unit
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
        val screen = activeScreen()
        when (mode) {
            2 -> {
                for (r in 0 until rows) {
                    clearRow(screen[r])
                }
                cursorRow = 0
                cursorCol = 0
            }
            0 -> {
                for (c in cursorCol until cols) clearCell(screen[cursorRow][c])
                for (r in (cursorRow + 1) until rows) clearRow(screen[r])
            }
            1 -> {
                for (r in 0 until cursorRow) clearRow(screen[r])
                for (c in 0..cursorCol.coerceAtMost(cols - 1)) clearCell(screen[cursorRow][c])
            }
        }
    }

    private fun eraseInLine(mode: Int) {
        val line = activeScreen()[cursorRow]
        when (mode) {
            0 -> for (c in cursorCol until cols) clearCell(line[c])
            1 -> for (c in 0..cursorCol.coerceAtMost(cols - 1)) clearCell(line[c])
            2 -> clearRow(line)
        }
    }

    private fun putChar(ch: Char) {
        val screen = activeScreen()
        val cell = screen[cursorRow][cursorCol]
        cell.ch = ch
        cell.fg = currentFg
        cell.bg = currentBg
        cursorCol++
        if (cursorCol >= cols) {
            cursorCol = 0
            lineFeed()
        }
    }

    private fun mapChar(ch: Char): Char {
        val safe = sanitizeGlyph(ch)
        if (!decLineDrawing) return safe
        return when (safe) {
            // DEC special graphics fallback to portable ASCII to avoid tofu glyphs.
            '`' -> '*'
            'a' -> '#'
            'f' -> 'o'
            'g' -> '+'
            'j', 'k', 'l', 'm', 'n' -> '+'
            'o', 'p', 'q', 'r', 's' -> '-'
            't', 'u', 'v', 'w' -> '+'
            'x' -> '|'
            'y' -> '<'
            'z' -> '>'
            '{' -> 'p'
            '|' -> '!'
            '}' -> 'L'
            '~' -> '.'
            else -> safe
        }
    }

    private fun sanitizeGlyph(ch: Char): Char {
        // Replacement char usually means decoding mismatch in upstream chunks.
        if (ch == '\uFFFD') return '?'
        // Private Use Area (e.g., nerd-font glyphs) often renders as boxes on Android.
        if (!allowPrivateUseGlyphs && ch.code in 0xE000..0xF8FF) return ' '
        // Zero-width or formatting marks can produce visual artifacts in monospaced terminal view.
        val type = Character.getType(ch)
        if (type == Character.FORMAT.toInt()) return ' '
        return ch
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
                screen[r] = cloneRow(screen[r - 1])
            }
            screen[0] = emptyRow()
        } else {
            cursorRow--
        }
    }

    private fun scrollUp() {
        val screen = activeScreen()
        if (!useAlternate) {
            history.addLast(cloneRow(screen[0]))
            while (history.size > scrollbackLimit) history.removeFirst()
        }
        for (r in 0 until rows - 1) {
            screen[r] = screen[r + 1]
        }
        screen[rows - 1] = emptyRow()
    }

    private fun AnnotatedString.Builder.appendRowWithStyles(
        row: CellArray,
        palette: TerminalColorPalette,
        trimEnd: Boolean = true
    ) {
        var end = row.size
        if (trimEnd) {
            while (end > 0 && row[end - 1].ch == ' ') end--
        }
        if (end == 0) return

        var i = 0
        while (i < end) {
            val fg = row[i].fg
            val bg = row[i].bg
            val start = i
            i++
            while (i < end && row[i].fg == fg && row[i].bg == bg) i++

            val fgColor = if (fg == AnsiColor.DEFAULT) palette.defaultForeground else AnsiColor.resolve(fg)
            val bgColor = if (bg == AnsiColor.DEFAULT) palette.defaultBackground else AnsiColor.resolve(bg)
            val style = if (bg == AnsiColor.DEFAULT) {
                SpanStyle(color = fgColor)
            } else {
                SpanStyle(color = fgColor, background = bgColor)
            }
            withStyle(style) {
                for (idx in start until i) append(row[idx].ch)
            }
        }
    }

    private fun activeScreen(): Array<CellArray> = if (useAlternate) alternate else primary

    private fun emptyScreen(): Array<CellArray> = Array(rows) { emptyRow() }

    private fun emptyRow(): CellArray = Array(cols) { Cell() }

    private fun clearRow(row: CellArray) {
        row.forEach { clearCell(it) }
    }

    private fun clearCell(cell: Cell) {
        cell.ch = ' '
        cell.fg = AnsiColor.DEFAULT
        cell.bg = AnsiColor.DEFAULT
    }

    private fun cloneRow(row: CellArray): CellArray = Array(row.size) { idx -> row[idx].copy() }

    private fun charsFromRow(row: CellArray): String = buildString(row.size) {
        row.forEach { append(it.ch) }
    }

    private fun resizeScreen(
        src: Array<CellArray>,
        oldCols: Int,
        oldRows: Int,
        newCols: Int,
        newRows: Int
    ): Array<CellArray> {
        val dst = Array(newRows) { Array(newCols) { Cell() } }
        val rowCount = minOf(oldRows, newRows)
        val colCount = minOf(oldCols, newCols)
        for (r in 0 until rowCount) {
            for (c in 0 until colCount) {
                dst[r][c] = src[r][c].copy()
            }
        }
        return dst
    }

    private fun resizeRow(src: CellArray, oldCols: Int, newCols: Int): CellArray {
        val dst = Array(newCols) { Cell() }
        val colCount = minOf(oldCols, newCols)
        for (c in 0 until colCount) {
            dst[c] = src[c].copy()
        }
        return dst
    }
}
