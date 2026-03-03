package com.followcat.zagora.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.followcat.zagora.data.AttachState
import com.followcat.zagora.data.SshAttachRepository
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets

class AttachViewModel : ViewModel() {
    private val repo = SshAttachRepository()
    val state: StateFlow<AttachState> = repo.state

    fun connect(host: String, user: String, password: String, sessionName: String) {
        viewModelScope.launch {
            repo.connect(host = host, user = user, password = password, sessionName = sessionName)
        }
    }

    fun sendLine(line: String) {
        repo.sendLine(line)
    }

    fun sendCtrlC() {
        repo.sendRaw(byteArrayOf(3))
    }

    fun sendCtrlChar(letter: Char) {
        val upper = letter.uppercaseChar()
        if (upper in 'A'..'Z') {
            repo.sendRaw(byteArrayOf((upper.code - 64).toByte()))
        }
    }

    fun sendEscape() {
        repo.sendRaw(byteArrayOf(0x1B))
    }

    fun sendTab() {
        repo.sendRaw(byteArrayOf('\t'.code.toByte()))
    }

    fun sendShiftTab() {
        repo.sendRaw("\u001B[Z".toByteArray(StandardCharsets.UTF_8))
    }

    fun sendArrowUp() {
        repo.sendRaw("\u001B[A".toByteArray(StandardCharsets.UTF_8))
    }

    fun sendArrowDown() {
        repo.sendRaw("\u001B[B".toByteArray(StandardCharsets.UTF_8))
    }

    fun sendArrowRight() {
        repo.sendRaw("\u001B[C".toByteArray(StandardCharsets.UTF_8))
    }

    fun sendArrowLeft() {
        repo.sendRaw("\u001B[D".toByteArray(StandardCharsets.UTF_8))
    }

    fun sendAltChar(letter: Char) {
        repo.sendRaw(byteArrayOf(0x1B, letter.code.toByte()))
    }

    fun sendTextRaw(text: String) {
        if (text.isNotEmpty()) {
            repo.sendRaw(text.toByteArray(StandardCharsets.UTF_8))
        }
    }

    fun sendPageUp() {
        repo.sendRaw("\u001B[5~".toByteArray(StandardCharsets.UTF_8))
    }

    fun sendPageDown() {
        repo.sendRaw("\u001B[6~".toByteArray(StandardCharsets.UTF_8))
    }

    fun sendHome() {
        repo.sendRaw("\u001B[H".toByteArray(StandardCharsets.UTF_8))
    }

    fun sendEnd() {
        repo.sendRaw("\u001B[F".toByteArray(StandardCharsets.UTF_8))
    }

    fun pasteRaw(text: String) {
        if (text.isNotEmpty()) {
            repo.sendRaw(text.toByteArray(StandardCharsets.UTF_8))
        }
    }

    fun disconnect() {
        repo.disconnect()
    }

    override fun onCleared() {
        repo.close()
        super.onCleared()
    }
}
