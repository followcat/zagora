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
import java.nio.charset.StandardCharsets
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

data class AttachState(
    val host: String = "",
    val sessionName: String = "",
    val connecting: Boolean = false,
    val connected: Boolean = false,
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
        if (host.isBlank() || user.isBlank()) {
            _state.update { it.copy(message = "Host and SSH user are required") }
            return
        }
        disconnect()
        _state.value = AttachState(
            host = host.trim(),
            sessionName = sessionName.trim(),
            connecting = true,
            message = "Connecting ${user.trim()}@${host.trim()} ..."
        )

        runCatching {
            withContext(ioDispatcher) {
                val jsch = JSch()
                val session = jsch.getSession(user.trim(), host.trim(), 22)
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
                    connecting = false,
                    connected = true,
                    message = "Connected ${user.trim()}@${host.trim()}. Attaching zellij..."
                )
            }
            sendLine(buildAttachCommand(sessionName))
            _state.update {
                it.copy(
                    message = "Attach command sent for ${sessionName.ifBlank { "default" }} (waiting remote output)"
                )
            }
        }.onFailure { err ->
            disconnect()
            _state.update {
                it.copy(
                    connecting = false,
                    connected = false,
                    message = "Connect failed (${user.trim()}@${host.trim()}): ${readableConnectError(err)}"
                )
            }
        }
    }

    fun sendLine(line: String) {
        val target = shellInput
        if (target == null) {
            _state.update { it.copy(message = "Not connected") }
            return
        }
        scope.launch {
            runCatching {
                target.write((line + "\n").toByteArray(StandardCharsets.UTF_8))
                target.flush()
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
            }
        }
    }

    fun disconnect() {
        readJob?.cancel()
        readJob = null
        runCatching { shellInput?.close() }
        shellInput = null
        runCatching { shell?.disconnect() }
        shell = null
        runCatching { sshSession?.disconnect() }
        sshSession = null
        _state.update { it.copy(connecting = false, connected = false) }
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
                    st.copy(output = merged)
                }
            }
            _state.update { it.copy(connected = false, connecting = false, message = "Disconnected") }
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

    private fun readableConnectError(err: Throwable): String {
        val root = rootCause(err)
        return when (root) {
            is UnknownHostException -> "host not found (DNS)"
            is ConnectException -> "connection refused (port 22 unreachable)"
            is NoRouteToHostException -> "no route to host"
            is SocketTimeoutException -> "connection timeout"
            is JSchException -> {
                val msg = root.message?.lowercase().orEmpty()
                when {
                    "auth fail" in msg || "authentication failed" in msg -> "authentication failed (check user/password)"
                    "timeout" in msg -> "connection timeout"
                    "unknownhostexception" in msg -> "host not found (DNS)"
                    "connection refused" in msg -> "connection refused (port 22 unreachable)"
                    else -> root.message ?: "ssh error"
                }
            }
            else -> root.message ?: err.message ?: err::class.simpleName.orEmpty()
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
