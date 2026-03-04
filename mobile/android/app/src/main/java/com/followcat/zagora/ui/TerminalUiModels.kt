package com.followcat.zagora.ui

data class TerminalUiState(
    val hostLabel: String,
    val sessionName: String,
    val conn: ConnState,
    val follow: Boolean = true,
    val selectionMode: Boolean = false,
    val fontSizeSp: Int = 14,
    val termEnv: String = "xterm-256color",
    val inBytes: Long = 0,
    val outBytes: Long = 0,
    val stickyCtrl: Boolean = false,
    val stickyAlt: Boolean = false
)

sealed class ConnState {
    data object Idle : ConnState()
    data object Connecting : ConnState()
    data object Connected : ConnState()
    data class Reconnecting(val attempt: Int) : ConnState()
    data class Disconnected(val reason: String? = null) : ConnState()
}

sealed interface TerminalAction {
    data object DetachOrBack : TerminalAction
    data object OpenMenu : TerminalAction
    data object CloseMenu : TerminalAction
    data object ToggleStickyCtrl : TerminalAction
    data object ToggleStickyAlt : TerminalAction
    data object CopySelection : TerminalAction
    data object PasteFromClipboard : TerminalAction
    data object Reconnect : TerminalAction
    data object ToggleFollow : TerminalAction
    data object EnterSelectionMode : TerminalAction
    data class SendKey(val action: TerminalKeyAction) : TerminalAction
    data class SendBytes(val bytes: ByteArray) : TerminalAction
}

