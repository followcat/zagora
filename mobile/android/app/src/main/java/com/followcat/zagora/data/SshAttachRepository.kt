package com.followcat.zagora.data

import com.jcraft.jsch.ChannelShell
import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.Session as JschSession
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
    private val scope = CoroutineScope(SupervisorJob() + ioDispatcher)
    private val _state = MutableStateFlow(AttachState())
    val state: StateFlow<AttachState> = _state.asStateFlow()

    @Volatile
    private var sshSession: JschSession? = null

    @Volatile
    private var shell: ChannelShell? = null

    @Volatile
    private var shellInput: java.io.OutputStream? = null
    private var readJob: Job? = null

    suspend fun connect(host: String, user: String, password: String, sessionName: String) {
        val cleanHost = host.trim()
        val cleanUser = user.trim()
        val cleanSession = sessionName.trim()
        if (cleanHost.isBlank() || cleanUser.isBlank()) {
            _state.update {
                it.copy(
                    host = cleanHost,
                    sessionName = cleanSession,
                    user = cleanUser,
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
        disconnect(updateState = false)
        val startAt = System.currentTimeMillis()
        _state.value = AttachState(
            host = cleanHost,
            sessionName = cleanSession,
            user = cleanUser,
            connecting = true,
            connected = false,
            phase = AttachPhase.Connecting,
            errorCode = AttachErrorCode.None,
            canRetry = false,
            message = "Connecting $cleanUser@$cleanHost ..."
        )

        runCatching {
            withContext(ioDispatcher) {
                val jsch = JSch()
                val session = jsch.getSession(cleanUser, cleanHost, 22)
                if (password.isNotBlank()) {
                    session.setPassword(password)
                }
                session.setConfig("StrictHostKeyChecking", "no")
                session.connect(10_000)

                val channel = session.openChannel("shell") as ChannelShell
                channel.setPtyType("xterm-256color", 180, 48, 0, 0)
                channel.connect(10_000)

                sshSession = session
                shell = channel
                shellInput = channel.outputStream
                startReadLoop(channel)
            }
        }.onSuccess {
            _state.update {
                it.copy(
                    connecting = true,
                    connected = true,
                    phase = AttachPhase.Attaching,
                    errorCode = AttachErrorCode.None,
                    canRetry = false,
                    latencyMs = (System.currentTimeMillis() - startAt).coerceAtLeast(1),
                    message = "Connected $cleanUser@$cleanHost. Attaching zellij..."
                )
            }
            sendLine(buildAttachCommand(cleanSession))
            _state.update {
                it.copy(
                    connecting = false,
                    connected = true,
                    phase = AttachPhase.Connected,
                    errorCode = AttachErrorCode.None,
                    canRetry = true,
                    message = "Attach command sent for ${cleanSession.ifBlank { "default" }} (waiting remote output)"
                )
            }
        }.onFailure { err ->
            val (code, readable) = mapError(err)
            disconnect(updateState = false)
            _state.update {
                it.copy(
                    host = cleanHost,
                    sessionName = cleanSession,
                    user = cleanUser,
                    connecting = false,
                    connected = false,
                    phase = AttachPhase.Error,
                    errorCode = code,
                    canRetry = true,
                    message = "Connect failed ($cleanUser@$cleanHost): $readable"
                )
            }
        }
    }

    fun sendLine(line: String) {
        val target = shellInput
        if (target == null) {
            _state.update { it.copy(message = "Not connected", canRetry = true) }
            return
        }
        scope.launch {
            runCatching {
                val payload = (line + "\n").toByteArray(StandardCharsets.UTF_8)
                target.write(payload)
                target.flush()
                _state.update { it.copy(rawBytesOut = it.rawBytesOut + payload.size) }
            }.onFailure { err ->
                _state.update { it.copy(message = "Send failed: ${err.message ?: err::class.simpleName}") }
            }
        }
    }

    fun sendRaw(bytes: ByteArray) {
        val target = shellInput ?: return
        scope.launch {
            runCatching {
                target.write(bytes)
                target.flush()
                _state.update { it.copy(rawBytesOut = it.rawBytesOut + bytes.size) }
            }
        }
    }

    fun disconnect(updateState: Boolean = true) {
        readJob?.cancel()
        readJob = null
        runCatching { shellInput?.close() }
        shellInput = null
        runCatching { shell?.disconnect() }
        shell = null
        runCatching { sshSession?.disconnect() }
        sshSession = null
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

    private fun startReadLoop(channel: ChannelShell) {
        readJob?.cancel()
        readJob = scope.launch {
            val input = channel.inputStream ?: return@launch
            val buf = ByteArray(4096)
            while (!Thread.currentThread().isInterrupted && channel.isConnected) {
                val n = runCatching { input.read(buf) }.getOrElse { -1 }
                if (n <= 0) {
                    break
                }
                val chunk = String(buf, 0, n, StandardCharsets.UTF_8)
                _state.update { st ->
                    val merged = (st.output + chunk).takeLast(120_000)
                    val zellijMissing = chunk.contains("zellij not found", ignoreCase = true)
                    val newMsg = if (zellijMissing) {
                        "Failed to start zellij: not installed on remote host"
                    } else {
                        st.message
                    }
                    st.copy(
                        output = merged,
                        rawBytesIn = st.rawBytesIn + n,
                        errorCode = if (zellijMissing) AttachErrorCode.ZellijMissing else st.errorCode,
                        message = newMsg
                    )
                }
            }
            _state.update {
                it.copy(
                    connected = false,
                    connecting = false,
                    phase = AttachPhase.Disconnected,
                    canRetry = true,
                    message = "Disconnected"
                )
            }
        }
    }

    private fun shellEscape(raw: String): String {
        if (raw.isBlank()) return ""
        return "'" + raw.replace("'", "'\"'\"'") + "'"
    }

    private fun buildAttachCommand(sessionName: String): String {
        val qName = shellEscape(sessionName)
        return (
            "if command -v zellij >/dev/null 2>&1; then _zg_bin=zellij; " +
                "elif [ -x \"\$HOME/.local/bin/zellij\" ]; then _zg_bin=\"\$HOME/.local/bin/zellij\"; " +
                "else echo \"zagora: zellij not found on remote; run: zagora install-zellij -c <host>\"; unset _zg_bin; fi; " +
                "if [ -n \"\$_zg_bin\" ]; then \"\$_zg_bin\" attach $qName || \"\$_zg_bin\" attach; fi"
            )
    }

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
