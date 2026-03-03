package com.followcat.zagora.ui

import org.junit.Assert.assertArrayEquals
import org.junit.Test

class TerminalKeyMapperTest {
    @Test
    fun ctrlCharEncodesToControlByte() {
        val bytes = TerminalKeyMapper.encode(TerminalKeyAction.Ctrl('c'))
        assertArrayEquals(byteArrayOf(3), bytes)
    }

    @Test
    fun altCharPrependsEscape() {
        val bytes = TerminalKeyMapper.encode(TerminalKeyAction.Alt('f'))
        assertArrayEquals(byteArrayOf(0x1B, 'f'.code.toByte()), bytes)
    }

    @Test
    fun stickyCtrlAppliesToSingleLetter() {
        val bytes = TerminalKeyMapper.applySticky("d", StickyModifiers(ctrl = true))
        assertArrayEquals(byteArrayOf(4), bytes)
    }

    @Test
    fun stickyAltPrefixesEscapeForText() {
        val bytes = TerminalKeyMapper.applySticky("ls", StickyModifiers(alt = true))
        assertArrayEquals(byteArrayOf(0x1B, 'l'.code.toByte(), 's'.code.toByte()), bytes)
    }
}

