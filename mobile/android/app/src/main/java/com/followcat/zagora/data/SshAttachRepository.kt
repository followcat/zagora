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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
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
    private val _incomingBytes = MutableSharedFlow<ByteArray>(extraBufferCapacity = 256)
    val incomingBytes: SharedFlow<ByteArray> = _incomingBytes.asSharedFlow()

    @Volatile
    private var sshSession: JschSession? = null

    @Volatile
    private var shell: ChannelShell? = null

    @Volatile
    private var shellInput: java.io.OutputStream? = null
    private var readJob: Job? = null
    private var reconnectJob: Job? = null
    private var reconnectPolicy: String = "manual"
    private var manualDisconnect = false
    @Volatile
    private var ptyCols: Int = 100
    @Volatile
    private var ptyRows: Int = 40
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
        // Keep PTY size aligned with real terminal viewport; aggressive minima
        // (e.g. 100x40) make remote TUIs render for a larger canvas than mobile has.
        val safeCols = cols.coerceAtLeast(20)
        val safeRows = rows.coerceAtLeast(8)
        ptyCols = safeCols
        ptyRows = safeRows
        ptyPixelWidth = pixelWidth.coerceAtLeast(0)
        ptyPixelHeight = pixelHeight.coerceAtLeast(0)

        val channel = shell
        if (channel != null && channel.isConnected) {
            runCatching {
                channel.setPtySize(ptyCols, ptyRows, ptyPixelWidth, ptyPixelHeight)
            }
        }
    }

    suspend fun connect(host: String, user: String, password: String, sessionName: String, isReconnect: Boolean = false) {
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
        if (!isReconnect) {
            reconnectJob?.cancel()
            reconnectJob = null
        }
        disconnect(updateState = false, cancelReconnectJob = !isReconnect)
        manualDisconnect = false
        lastHost = cleanHost
        lastUser = cleanUser
        lastPassword = password
        lastSessionName = cleanSession
        val startAt = System.currentTimeMillis()
        _state.value = AttachState(
            host = cleanHost,
            sessionName = cleanSession,
            user = cleanUser,
            connecting = true,
            connected = false,
            phase = if (isReconnect) AttachPhase.Reconnecting else AttachPhase.Connecting,
            errorCode = AttachErrorCode.None,
            canRetry = false,
            message = if (isReconnect) "Reconnecting $cleanUser@$cleanHost ..." else "Connecting $cleanUser@$cleanHost ..."
        )

        runCatching {
            withContext(ioDispatcher) {
                val jsch = JSch()
                val session = jsch.getSession(cleanUser, cleanHost, 22)
                if (password.isNotBlank()) {
                    session.setPassword(password)
                }
                session.setConfig("StrictHostKeyChecking", "no")
                // Detect dead network paths faster after screen-off / wake-up.
                session.serverAliveInterval = 10_000
                session.serverAliveCountMax = 1
                session.connect(10_000)

                val channel = session.openChannel("shell") as ChannelShell
                // Best-effort: prevent connect-time helper commands from polluting remote shell history.
                channel.setEnv("HISTFILE", "/dev/null")
                channel.setEnv("HISTSIZE", "0")
                channel.setEnv("SAVEHIST", "0")
                channel.setEnv("HISTCONTROL", "ignorespace:ignoredups")
                channel.setPtyType("xterm-256color", ptyCols, ptyRows, ptyPixelWidth, ptyPixelHeight)
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
            sendLine(buildHistoryGuardCommand())
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
            disconnect(updateState = false, cancelReconnectJob = !isReconnect)
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

    fun disconnect(updateState: Boolean = true, cancelReconnectJob: Boolean = true) {
        if (cancelReconnectJob) {
            reconnectJob?.cancel()
            reconnectJob = null
        }
        manualDisconnect = true
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
            val decoder = StandardCharsets.UTF_8.newDecoder().apply {
                onMalformedInput(CodingErrorAction.REPLACE)
                onUnmappableCharacter(CodingErrorAction.REPLACE)
            }
            var pending = ByteArray(0)
            while (!Thread.currentThread().isInterrupted && channel.isConnected) {
                val n = runCatching { input.read(buf) }.getOrElse { -1 }
                if (n <= 0) {
                    break
                }
                _incomingBytes.tryEmit(buf.copyOfRange(0, n))
                val merged = if (pending.isEmpty()) {
                    buf.copyOfRange(0, n)
                } else {
                    ByteArray(pending.size + n).also {
                        System.arraycopy(pending, 0, it, 0, pending.size)
                        System.arraycopy(buf, 0, it, pending.size, n)
                    }
                }
                val byteBuffer = ByteBuffer.wrap(merged)
                val charBuffer = CharBuffer.allocate((merged.size * decoder.maxCharsPerByte()).toInt() + 2)
                decoder.decode(byteBuffer, charBuffer, false)
                charBuffer.flip()
                val chunk = charBuffer.toString()
                pending = if (byteBuffer.hasRemaining()) {
                    ByteArray(byteBuffer.remaining()).also { byteBuffer.get(it) }
                } else {
                    ByteArray(0)
                }
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
                    phase = if (reconnectPolicy == "auto3" && !manualDisconnect) AttachPhase.Reconnecting else AttachPhase.Disconnected,
                    canRetry = true,
                    message = "Disconnected"
                )
            }
            if (!manualDisconnect && reconnectPolicy == "auto3") {
                startReconnectLoop()
            }
        }
    }

    private fun startReconnectLoop() {
        if (lastHost.isBlank() || lastUser.isBlank()) return
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
                        host = lastHost,
                        user = lastUser,
                        password = lastPassword,
                        sessionName = lastSessionName,
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

    private fun shellEscape(raw: String): String {
        if (raw.isBlank()) return ""
        return "'" + raw.replace("'", "'\"'\"'") + "'"
    }

    private fun buildHistoryGuardCommand(): String {
        return (
            "unset HISTFILE; export HISTFILE=/dev/null; export HISTSIZE=0; export SAVEHIST=0; " +
                "set +o history 2>/dev/null || true; " +
                "unsetopt SHARE_HISTORY INC_APPEND_HISTORY INC_APPEND_HISTORY_TIME 2>/dev/null || true"
            )
    }

    private fun buildAttachCommand(sessionName: String): String {
        val cleanName = sessionName.trim()
        val qName = shellEscape(cleanName)
        val attachCmd = if (cleanName.isBlank()) {
            "exec zellij attach"
        } else {
            "exec zellij attach -c $qName"
        }
        val fallbackAttachCmd = if (cleanName.isBlank()) {
            "exec \"\$HOME/.local/bin/zellij\" attach"
        } else {
            "exec \"\$HOME/.local/bin/zellij\" attach -c $qName"
        }
        val script = (
            "stty cols $ptyCols rows $ptyRows 2>/dev/null || true; " +
                "if command -v zellij >/dev/null 2>&1; then $attachCmd; " +
                "elif [ -x \"\$HOME/.local/bin/zellij\" ]; then $fallbackAttachCmd; " +
                "else echo \"zagora: zellij not found on remote; run: zagora install-zellij -c <host>\"; fi"
            )
        return "/bin/sh -lc ${shellEscape(script)}"
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
