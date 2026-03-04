package com.followcat.zagora.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.followcat.zagora.data.AttachState
import com.followcat.zagora.data.SshAttachRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class AttachViewModel : ViewModel() {
    private val repo = SshAttachRepository()
    val state: StateFlow<AttachState> = repo.state
    private val _sticky = MutableStateFlow(StickyModifiers())
    val sticky: StateFlow<StickyModifiers> = _sticky.asStateFlow()
    private var lastConnectParams: ConnectParams? = null
    private var resumeAfterBackground = false

    fun setReconnectPolicy(policy: String) {
        repo.setReconnectPolicy(policy)
    }

    fun connect(host: String, user: String, password: String, sessionName: String) {
        lastConnectParams = ConnectParams(host = host, user = user, password = password, sessionName = sessionName)
        resumeAfterBackground = false
        viewModelScope.launch {
            repo.connect(host = host, user = user, password = password, sessionName = sessionName)
        }
    }

    fun onAppBackground() {
        val st = state.value
        val hasTarget = lastConnectParams != null
        if (!hasTarget) return
        if (st.connected || st.connecting) {
            resumeAfterBackground = true
            repo.disconnect()
        }
    }

    fun onAppForeground() {
        val st = state.value
        val params = lastConnectParams ?: return
        if (!resumeAfterBackground) return
        if (st.connected || st.connecting) return
        resumeAfterBackground = false
        viewModelScope.launch {
            repo.connect(
                host = params.host,
                user = params.user,
                password = params.password,
                sessionName = params.sessionName,
                isReconnect = true
            )
        }
    }

    fun sendLine(line: String) {
        repo.sendLine(line)
    }

    fun setStickyCtrl(enabled: Boolean) {
        _sticky.value = _sticky.value.copy(ctrl = enabled)
    }

    fun setStickyAlt(enabled: Boolean) {
        _sticky.value = _sticky.value.copy(alt = enabled)
    }

    fun toggleStickyCtrl() {
        setStickyCtrl(!_sticky.value.ctrl)
    }

    fun toggleStickyAlt() {
        setStickyAlt(!_sticky.value.alt)
    }

    fun clearSticky() {
        _sticky.value = StickyModifiers()
    }

    fun sendKey(action: TerminalKeyAction) {
        when (action) {
            is TerminalKeyAction.Text -> {
                val stickyNow = _sticky.value
                val bytes = TerminalKeyMapper.applySticky(action.value, stickyNow)
                if (bytes.isNotEmpty()) repo.sendRaw(bytes)
                if (stickyNow.ctrl || stickyNow.alt) clearSticky()
            }
            else -> {
                val bytes = TerminalKeyMapper.encode(action)
                if (bytes.isNotEmpty()) repo.sendRaw(bytes)
            }
        }
    }

    fun sendCtrlC() {
        sendKey(TerminalKeyAction.CtrlC)
    }

    fun sendCtrlChar(letter: Char) {
        sendKey(TerminalKeyAction.Ctrl(letter))
    }

    fun sendEscape() {
        sendKey(TerminalKeyAction.Escape)
    }

    fun sendTab() {
        sendKey(TerminalKeyAction.Tab)
    }

    fun sendShiftTab() {
        sendKey(TerminalKeyAction.ShiftTab)
    }

    fun sendArrowUp() {
        sendKey(TerminalKeyAction.ArrowUp)
    }

    fun sendArrowDown() {
        sendKey(TerminalKeyAction.ArrowDown)
    }

    fun sendArrowRight() {
        sendKey(TerminalKeyAction.ArrowRight)
    }

    fun sendArrowLeft() {
        sendKey(TerminalKeyAction.ArrowLeft)
    }

    fun sendAltChar(letter: Char) {
        sendKey(TerminalKeyAction.Alt(letter))
    }

    fun sendTextRaw(text: String) {
        if (text.isNotEmpty()) {
            sendKey(TerminalKeyAction.Text(text))
        }
    }

    fun sendPageUp() {
        sendKey(TerminalKeyAction.PageUp)
    }

    fun sendPageDown() {
        sendKey(TerminalKeyAction.PageDown)
    }

    fun sendHome() {
        sendKey(TerminalKeyAction.Home)
    }

    fun sendEnd() {
        sendKey(TerminalKeyAction.End)
    }

    fun pasteRaw(text: String) {
        if (text.isNotEmpty()) {
            sendKey(TerminalKeyAction.Text(text))
        }
    }

    fun disconnect() {
        resumeAfterBackground = false
        repo.disconnect()
    }

    override fun onCleared() {
        repo.close()
        super.onCleared()
    }

    private data class ConnectParams(
        val host: String,
        val user: String,
        val password: String,
        val sessionName: String
    )
}
