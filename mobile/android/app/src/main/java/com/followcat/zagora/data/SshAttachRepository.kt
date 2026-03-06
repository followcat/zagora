package com.followcat.zagora.data

import com.jcraft.jsch.JSchException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.nio.charset.StandardCharsets

enum class AttachPhase {
    Idle,
    Connecting,
    Attaching,
    Connected,
    Reconnecting,
    Disconnected,
    Error
}

enum class AttachErrorCode {
    None,
    RegistryUnreachable,
    SshNetwork,
    SshAuth,
    ZellijMissing,
    Timeout,
    Unknown
}

data class AttachState(
    val host: String = "",
    val sessionName: String = "",
    val user: String = "",
    val connecting: Boolean = false,
    val connected: Boolean = false,
    val phase: AttachPhase = AttachPhase.Idle,
    val errorCode: AttachErrorCode = AttachErrorCode.None,
    val latencyMs: Long? = null,
    val canRetry: Boolean = false,
    val rawBytesIn: Long = 0,
    val rawBytesOut: Long = 0,
    val message: String = "",
    val output: String = ""
)

class SshAttachRepository(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {
    companion object {
        private const val MIN_ZELLIJ_COLS = 80
        private const val MIN_ZELLIJ_ROWS = 35
    }

    private val scope = CoroutineScope(SupervisorJob() + ioDispatcher)
    private val shellSession = SshShellConnection(scope = scope, ioDispatcher = ioDispatcher)
    private val _state = MutableStateFlow(AttachState())
    val state: StateFlow<AttachState> = _state.asStateFlow()
    private val _incomingBytes = MutableSharedFlow<ByteArray>()
    val incomingBytes: SharedFlow<ByteArray> = _incomingBytes.asSharedFlow()

    private var reconnectJob: Job? = null
    private var reconnectPolicy: String = "manual"
    private var manualDisconnect = false
    @Volatile
    private var ptyCols: Int = 80
    @Volatile
    private var ptyRows: Int = 24
    @Volatile
    private var ptyPixelWidth: Int = 0
    @Volatile
    private var ptyPixelHeight: Int = 0
    private var lastHost: String = ""
    private var lastUser: String = ""
    private var lastPassword: String = ""
    private var lastSessionName: String = ""

    fun setReconnectPolicy(policy: String) {
        reconnectPolicy = policy
    }

    fun resizePty(cols: Int, rows: Int, pixelWidth: Int = 0, pixelHeight: Int = 0) {
        val safeCols = cols.coerceAtLeast(20)
        val safeRows = rows.coerceAtLeast(8)
        ptyCols = safeCols
        ptyRows = safeRows
        ptyPixelWidth = pixelWidth.coerceAtLeast(0)
        ptyPixelHeight = pixelHeight.coerceAtLeast(0)
        shellSession.resize(currentPtySpec())
    }

    suspend fun connect(host: String, user: String, password: String, sessionName: String, isReconnect: Boolean = false) {
        val target = AttachTarget(
            host = host.trim(),
            user = user.trim(),
            password = password,
            sessionName = sessionName.trim()
        )
        val current = _state.value
        val sameTarget = current.host == target.host &&
            current.user == target.user &&
            current.sessionName == target.sessionName
        val activePhase = current.phase == AttachPhase.Connecting ||
            current.phase == AttachPhase.Attaching ||
            current.phase == AttachPhase.Connected ||
            current.phase == AttachPhase.Reconnecting
        if (sameTarget && activePhase && shellSession.isActive()) {
            _state.update {
                it.copy(
                    canRetry = true,
                    message = "Attach already active for ${target.sessionName.ifBlank { "default" }}"
                )
            }
            return
        }
        if (target.host.isBlank() || target.user.isBlank()) {
            _state.update {
                it.copy(
                    host = target.host,
                    sessionName = target.sessionName,
                    user = target.user,
                    phase = AttachPhase.Error,
                    errorCode = AttachErrorCode.Unknown,
                    connecting = false,
                    connected = false,
                    canRetry = false,
                    message = "Host and SSH user are required"
                )
            }
            return
        }
        if (!isReconnect) {
            reconnectJob?.cancel()
            reconnectJob = null
        }
        disconnect(updateState = false, cancelReconnectJob = !isReconnect)
        manualDisconnect = false
        lastHost = target.host
        lastUser = target.user
        lastPassword = target.password
        lastSessionName = target.sessionName
        val startAt = System.currentTimeMillis()
        _state.value = AttachState(
            host = target.host,
            sessionName = target.sessionName,
            user = target.user,
            connecting = true,
            connected = false,
            phase = if (isReconnect) AttachPhase.Reconnecting else AttachPhase.Connecting,
            errorCode = AttachErrorCode.None,
            canRetry = false,
            rawBytesIn = 0,
            rawBytesOut = 0,
            output = "",
            message = if (isReconnect) "Reconnecting ${target.user}@${target.host} ..." else "Connecting ${target.user}@${target.host} ..."
        )

        runCatching {
            val startupCommand = AttachStartupCommandBuilder.build(target.sessionName, currentPtySpec())
            shellSession.connect(
                target = target,
                ptySpec = currentPtySpec(),
                startupCommand = startupCommand,
                onChunk = { chunk -> handleReadChunk(chunk) },
                onClosed = { closeInfo -> handleSessionClosed(closeInfo) }
            )
        }.onSuccess {
            _state.update {
                it.copy(
                    connecting = false,
                    connected = true,
                    phase = AttachPhase.Connected,
                    errorCode = AttachErrorCode.None,
                    canRetry = false,
                    latencyMs = (System.currentTimeMillis() - startAt).coerceAtLeast(1),
                    message = "Connected ${target.user}@${target.host}"
                )
            }
            val startupCommand = AttachStartupCommandBuilder.build(target.sessionName, currentPtySpec())
            _state.update { it.copy(rawBytesOut = it.rawBytesOut + startupCommand.length) }
        }.onFailure { err ->
            val (code, readable) = mapError(err)
            disconnect(updateState = false, cancelReconnectJob = !isReconnect)
            _state.update {
                it.copy(
                    host = target.host,
                    sessionName = target.sessionName,
                    user = target.user,
                    connecting = false,
                    connected = false,
                    phase = AttachPhase.Error,
                    errorCode = code,
                    canRetry = true,
                    message = "Connect failed (${target.user}@${target.host}): $readable"
                )
            }
        }
    }

    fun sendLine(line: String) {
        if (!shellSession.isActive()) {
            _state.update { it.copy(message = "Not connected", canRetry = true) }
            return
        }
        scope.launch {
            runCatching {
                val payload = (line + "\n").toByteArray(StandardCharsets.UTF_8)
                shellSession.sendLine(line)
                _state.update { it.copy(rawBytesOut = it.rawBytesOut + payload.size) }
            }.onFailure { err ->
                _state.update { it.copy(message = "Send failed: ${err.message ?: err::class.simpleName}") }
            }
        }
    }

    fun sendRaw(bytes: ByteArray) {
        if (!shellSession.isActive()) return
        scope.launch {
            runCatching {
                shellSession.sendRaw(bytes)
                _state.update { it.copy(rawBytesOut = it.rawBytesOut + bytes.size) }
            }
        }
    }

    fun disconnect(updateState: Boolean = true, cancelReconnectJob: Boolean = true) {
        if (cancelReconnectJob) {
            reconnectJob?.cancel()
            reconnectJob = null
        }
        manualDisconnect = true
        shellSession.disconnect()
        if (updateState) {
            _state.update {
                it.copy(
                    connecting = false,
                    connected = false,
                    phase = AttachPhase.Disconnected,
                    canRetry = true,
                    message = "Detached"
                )
            }
        }
    }

    fun close() {
        disconnect()
        scope.cancel()
    }

    private suspend fun handleReadChunk(chunk: AttachReadChunk) {
        _incomingBytes.emit(chunk.bytes)
        _state.update { st ->
            val mergedOutput = (st.output + chunk.text).takeLast(120_000)
            val zellijMissing = chunk.text.contains("zellij not found", ignoreCase = true)
            val zellijPanic = chunk.text.contains("panicked at", ignoreCase = true) ||
                chunk.text.contains("ENOTTY", ignoreCase = true)
            val newMsg = if (zellijMissing) {
                "Failed to start zellij: not installed on remote host"
            } else if (zellijPanic) {
                "Failed to start zellij in terminal environment"
            } else if (st.phase == AttachPhase.Attaching || st.phase == AttachPhase.Reconnecting || st.phase == AttachPhase.Connecting) {
                "Attached to ${st.sessionName.ifBlank { "default" }}"
            } else {
                st.message
            }
            st.copy(
                output = mergedOutput,
                rawBytesIn = st.rawBytesIn + chunk.bytes.size,
                connecting = false,
                connected = !zellijMissing && !zellijPanic,
                phase = if (zellijMissing || zellijPanic) AttachPhase.Error else if (
                    st.phase == AttachPhase.Attaching || st.phase == AttachPhase.Reconnecting || st.phase == AttachPhase.Connecting
                ) AttachPhase.Connected else st.phase,
                errorCode = if (zellijMissing) AttachErrorCode.ZellijMissing else if (zellijPanic) AttachErrorCode.Unknown else st.errorCode,
                message = newMsg
            )
        }
    }

    private suspend fun handleSessionClosed(closeInfo: AttachCloseInfo) {
        val exitStatus = closeInfo.exitStatus
        val stderrTail = closeInfo.stderrTail
        val reason = when {
            stderrTail.isNotBlank() -> stderrTail.lineSequence().lastOrNull { it.isNotBlank() } ?: stderrTail
            exitStatus >= 0 -> "Remote process exited ($exitStatus)"
            closeInfo.stillConnected -> "Connection stalled"
            else -> "Disconnected"
        }
        _state.update {
            it.copy(
                connected = false,
                connecting = false,
                phase = if (reconnectPolicy == "auto3" && !manualDisconnect) AttachPhase.Reconnecting else AttachPhase.Disconnected,
                canRetry = true,
                message = reason
            )
        }
        if (!manualDisconnect && reconnectPolicy == "auto3") {
            startReconnectLoop()
        }
    }

    private fun startReconnectLoop() {
        val target = currentTarget()
        if (target.host.isBlank() || target.user.isBlank()) return
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            for (attempt in 1..3) {
                _state.update {
                    it.copy(
                        phase = AttachPhase.Reconnecting,
                        connecting = true,
                        connected = false,
                        canRetry = false,
                        message = "Reconnecting ($attempt/3) ..."
                    )
                }
                delay((attempt * 1000L).coerceAtMost(4_000L))
                runCatching {
                    connect(
                        host = target.host,
                        user = target.user,
                        password = target.password,
                        sessionName = target.sessionName,
                        isReconnect = true
                    )
                }.onSuccess {
                    if (_state.value.connected) return@launch
                }
            }
            _state.update {
                it.copy(
                    phase = AttachPhase.Disconnected,
                    connecting = false,
                    connected = false,
                    canRetry = true,
                    message = "Reconnect failed. Tap Retry."
                )
            }
        }
    }

    private fun currentTarget(): AttachTarget = AttachTarget(
        host = lastHost,
        user = lastUser,
        password = lastPassword,
        sessionName = lastSessionName
    )

    private fun currentPtySpec(): PtySpec = PtySpec(
        cols = ptyCols.coerceAtLeast(MIN_ZELLIJ_COLS),
        rows = ptyRows.coerceAtLeast(MIN_ZELLIJ_ROWS),
        pixelWidth = ptyPixelWidth,
        pixelHeight = ptyPixelHeight
    )

    private fun mapError(err: Throwable): Pair<AttachErrorCode, String> {
        val root = rootCause(err)
        return when (root) {
            is UnknownHostException -> AttachErrorCode.SshNetwork to "host not found (DNS)"
            is ConnectException -> AttachErrorCode.SshNetwork to "connection refused (port 22 unreachable)"
            is NoRouteToHostException -> AttachErrorCode.SshNetwork to "no route to host"
            is SocketTimeoutException -> AttachErrorCode.Timeout to "connection timeout"
            is JSchException -> {
                val msg = root.message?.lowercase().orEmpty()
                when {
                    "auth fail" in msg || "authentication failed" in msg ->
                        AttachErrorCode.SshAuth to "authentication failed (check user/password)"
                    "timeout" in msg -> AttachErrorCode.Timeout to "connection timeout"
                    "unknownhostexception" in msg -> AttachErrorCode.SshNetwork to "host not found (DNS)"
                    "connection refused" in msg -> AttachErrorCode.SshNetwork to "connection refused (port 22 unreachable)"
                    else -> AttachErrorCode.Unknown to (root.message ?: "ssh error")
                }
            }
            else -> AttachErrorCode.Unknown to (root.message ?: err.message ?: err::class.simpleName.orEmpty())
        }
    }

    private fun rootCause(err: Throwable): Throwable {
        var cur: Throwable = err
        while (cur.cause != null && cur.cause !== cur) {
            cur = cur.cause!!
        }
        return cur
    }
}
