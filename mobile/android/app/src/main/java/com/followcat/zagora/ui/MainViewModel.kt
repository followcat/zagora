package com.followcat.zagora.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.followcat.zagora.data.ZagoraRepository
import com.followcat.zagora.model.Session
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class UiState(
    val loading: Boolean = false,
    val message: String = "",
    val sessions: List<Session> = emptyList()
)

class MainViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    fun loadSessions(server: String, token: String, hostFilter: String) {
        if (server.isBlank()) {
            _uiState.value = _uiState.value.copy(message = "Server is required")
            return
        }
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, message = "")
            runCatching {
                val repo = ZagoraRepository(server, token)
                repo.listSessions(hostFilter)
            }.onSuccess { sessions ->
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    sessions = sessions,
                    message = "Loaded ${sessions.size} sessions"
                )
            }.onFailure { err ->
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    message = "Load failed: ${err.message ?: err::class.simpleName}"
                )
            }
        }
    }

    fun deleteSession(server: String, token: String, session: Session) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, message = "")
            runCatching {
                val repo = ZagoraRepository(server, token)
                repo.removeSession(session.name, session.host)
            }.onSuccess {
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    sessions = _uiState.value.sessions.filterNot { it.name == session.name && it.host == session.host },
                    message = "Removed ${session.name}@${session.host}"
                )
            }.onFailure { err ->
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    message = "Remove failed: ${err.message ?: err::class.simpleName}"
                )
            }
        }
    }
}

