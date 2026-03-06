package com.followcat.zagora.data

import com.jcraft.jsch.ChannelShell
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session as JschSession
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

internal data class AttachTarget(
    val host: String,
    val user: String,
    val password: String,
    val sessionName: String
)

internal data class PtySpec(
    val cols: Int,
    val rows: Int,
    val pixelWidth: Int,
    val pixelHeight: Int
)

internal data class AttachReadChunk(
    val bytes: ByteArray,
    val text: String
)

internal object AttachStartupCommandBuilder {
    fun build(sessionName: String, ptySpec: PtySpec): String {
        return buildHistoryGuardCommand() + "; " + buildAttachCommand(sessionName, ptySpec)
    }

    private fun buildHistoryGuardCommand(): String {
        return (
            "stty -echo 2>/dev/null || true; " +
                "unset HISTFILE; export HISTFILE=/dev/null; export HISTSIZE=0; export SAVEHIST=0; " +
                "set +o history 2>/dev/null || true; " +
                "unsetopt SHARE_HISTORY INC_APPEND_HISTORY INC_APPEND_HISTORY_TIME 2>/dev/null || true"
            )
    }

    private fun buildAttachCommand(sessionName: String, ptySpec: PtySpec): String {
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
        return (
            "stty cols ${ptySpec.cols} rows ${ptySpec.rows} 2>/dev/null || true; " +
                "if command -v zellij >/dev/null 2>&1; then $attachCmd; " +
                "elif [ -x \"\$HOME/.local/bin/zellij\" ]; then $fallbackAttachCmd; " +
                "else echo \"zagora: zellij not found on remote; run: zagora install-zellij -c <host>\"; fi"
            )
    }

    private fun shellEscape(raw: String): String {
        if (raw.isBlank()) return ""
        return "'" + raw.replace("'", "'\"'\"'") + "'"
    }
}

internal class SshShellConnection(
    private val scope: CoroutineScope,
    private val ioDispatcher: CoroutineDispatcher
) {
    @Volatile
    private var sshSession: JschSession? = null

    @Volatile
    private var shell: ChannelShell? = null

    @Volatile
    private var shellInput: java.io.OutputStream? = null

    private var readJob: Job? = null

    fun isActive(): Boolean = sshSession?.isConnected == true && shell?.isConnected == true

    suspend fun connect(
        target: AttachTarget,
        ptySpec: PtySpec,
        onChunk: suspend (AttachReadChunk) -> Unit,
        onClosed: suspend (Boolean) -> Unit
    ) {
        withContext(ioDispatcher) {
            val jsch = JSch()
            val session = jsch.getSession(target.user, target.host, 22)
            if (target.password.isNotBlank()) {
                session.setPassword(target.password)
            }
            session.setConfig("StrictHostKeyChecking", "no")
            session.serverAliveInterval = 10_000
            session.serverAliveCountMax = 1
            session.connect(10_000)

            val channel = session.openChannel("shell") as ChannelShell
            channel.setEnv("HISTFILE", "/dev/null")
            channel.setEnv("HISTSIZE", "0")
            channel.setEnv("SAVEHIST", "0")
            channel.setEnv("HISTCONTROL", "ignorespace:ignoredups")
            channel.setPtyType("xterm-256color", ptySpec.cols, ptySpec.rows, ptySpec.pixelWidth, ptySpec.pixelHeight)
            channel.connect(10_000)

            sshSession = session
            shell = channel
            shellInput = channel.outputStream
            startReadLoop(channel, onChunk, onClosed)
        }
    }

    fun resize(ptySpec: PtySpec) {
        val channel = shell
        if (channel != null && channel.isConnected) {
            runCatching {
                channel.setPtySize(ptySpec.cols, ptySpec.rows, ptySpec.pixelWidth, ptySpec.pixelHeight)
            }
        }
    }

    fun sendLine(line: String) {
        sendRaw((line + "\n").toByteArray(StandardCharsets.UTF_8))
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
    }

    private fun startReadLoop(
        channel: ChannelShell,
        onChunk: suspend (AttachReadChunk) -> Unit,
        onClosed: suspend (Boolean) -> Unit
    ) {
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
                if (n < 0) break
                if (n == 0) {
                    delay(25)
                    continue
                }
                val bytes = buf.copyOfRange(0, n)
                val merged = if (pending.isEmpty()) {
                    bytes
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
                onChunk(AttachReadChunk(bytes = bytes, text = chunk))
            }
            onClosed(channel.isConnected)
        }
    }
}
