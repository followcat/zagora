package com.followcat.zagora.data

import android.util.Log
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

internal data class AttachCloseInfo(
    val stillConnected: Boolean,
    val exitStatus: Int,
    val stderrTail: String,
    val outputTail: String
)

internal object AttachStartupCommandBuilder {
    fun build(sessionName: String, ptySpec: PtySpec): String {
        return buildAttachCommand(sessionName, ptySpec)
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
            "export TERM=xterm-256color; " +
                "if command -v zellij >/dev/null 2>&1; then $attachCmd; " +
                "elif [ -x \"\$HOME/.local/bin/zellij\" ]; then $fallbackAttachCmd; " +
                "else echo \"zagora: zellij not found on remote; run: zagora install-zellij -c <host>\"; fi"
            )
    }

    private fun shellEscape(raw: String): String = "'" + raw.replace("'", "'\"'\"'") + "'"
}

internal class SshShellConnection(
    private val scope: CoroutineScope,
    private val ioDispatcher: CoroutineDispatcher
) {
    companion object {
        private const val TAG = "ZagoraAttach"
    }

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
        startupCommand: String,
        onChunk: suspend (AttachReadChunk) -> Unit,
        onClosed: suspend (AttachCloseInfo) -> Unit
    ) {
        withContext(ioDispatcher) {
            Log.d(TAG, "connect start host=${target.host} user=${target.user} session=${target.sessionName}")
            val jsch = JSch()
            val session = jsch.getSession(target.user, target.host, 22)
            if (target.password.isNotBlank()) {
                session.setPassword(target.password)
            }
            session.setConfig("StrictHostKeyChecking", "no")
            session.serverAliveInterval = 30_000
            session.serverAliveCountMax = 3
            session.connect(10_000)

            val channel = session.openChannel("shell") as ChannelShell
            channel.setPty(true)
            channel.setEnv("HISTFILE", "/dev/null")
            channel.setEnv("HISTSIZE", "0")
            channel.setEnv("SAVEHIST", "0")
            channel.setEnv("HISTCONTROL", "ignorespace:ignoredups")
            channel.setPtyType("xterm-256color", ptySpec.cols, ptySpec.rows, ptySpec.pixelWidth, ptySpec.pixelHeight)
            Log.d(TAG, "shell startup command=$startupCommand")
            channel.connect(10_000)
            Log.d(TAG, "channel connected")

            sshSession = session
            shell = channel
            shellInput = channel.outputStream
            delay(200)
            shellInput?.write((startupCommand + "\n").toByteArray(StandardCharsets.UTF_8))
            shellInput?.flush()
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
        onClosed: suspend (AttachCloseInfo) -> Unit
    ) {
        readJob?.cancel()
        readJob = scope.launch {
            val input = channel.inputStream ?: return@launch
            val errInput = runCatching { channel.extInputStream }.getOrNull()
            val buf = ByteArray(4096)
            val errBuf = ByteArray(4096)
            val decoder = StandardCharsets.UTF_8.newDecoder().apply {
                onMalformedInput(CodingErrorAction.REPLACE)
                onUnmappableCharacter(CodingErrorAction.REPLACE)
            }
            val errDecoder = StandardCharsets.UTF_8.newDecoder().apply {
                onMalformedInput(CodingErrorAction.REPLACE)
                onUnmappableCharacter(CodingErrorAction.REPLACE)
            }
            var pending = ByteArray(0)
            var errPending = ByteArray(0)
            val outputTail = StringBuilder()
            val stderrTail = StringBuilder()
            suspend fun drainErr(nonBlocking: Boolean) {
                if (errInput == null) return
                while (true) {
                    val errAvailable = runCatching { errInput.available() }.getOrDefault(0)
                    if (nonBlocking && errAvailable <= 0) break
                    val limit = if (errAvailable > 0) minOf(errBuf.size, errAvailable) else errBuf.size
                    val errRead = runCatching { errInput.read(errBuf, 0, limit) }.getOrElse { -1 }
                    if (errRead <= 0) break
                    val errBytes = errBuf.copyOfRange(0, errRead)
                    val errMerged = if (errPending.isEmpty()) {
                        errBytes
                    } else {
                        ByteArray(errPending.size + errRead).also {
                            System.arraycopy(errPending, 0, it, 0, errPending.size)
                            System.arraycopy(errBuf, 0, it, errPending.size, errRead)
                        }
                    }
                    val errByteBuffer = ByteBuffer.wrap(errMerged)
                    val errCharBuffer = CharBuffer.allocate((errMerged.size * errDecoder.maxCharsPerByte()).toInt() + 2)
                    errDecoder.decode(errByteBuffer, errCharBuffer, false)
                    errCharBuffer.flip()
                    val errChunk = errCharBuffer.toString()
                    errPending = if (errByteBuffer.hasRemaining()) {
                        ByteArray(errByteBuffer.remaining()).also { errByteBuffer.get(it) }
                    } else {
                        ByteArray(0)
                    }
                    Log.w(TAG, "stderr chunk=$errChunk")
                    stderrTail.append(errChunk)
                    if (stderrTail.length > 4000) {
                        stderrTail.delete(0, stderrTail.length - 4000)
                    }
                    onChunk(AttachReadChunk(bytes = errBytes, text = errChunk))
                    if (nonBlocking) break
                }
            }
            while (!Thread.currentThread().isInterrupted && channel.isConnected) {
                drainErr(nonBlocking = true)
                val n = runCatching { input.read(buf) }.getOrElse { -1 }
                if (n < 0) {
                    drainErr(nonBlocking = false)
                    break
                }
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
                outputTail.append(chunk)
                if (outputTail.length > 4000) {
                    outputTail.delete(0, outputTail.length - 4000)
                }
                onChunk(AttachReadChunk(bytes = bytes, text = chunk))
            }
            Log.d(TAG, "channel closed connected=${channel.isConnected} exitStatus=${channel.exitStatus}")
            val outputTailValue = outputTail.toString().trim()
            if (outputTailValue.isNotBlank()) {
                Log.w(TAG, "stdout tail=${outputTailValue.takeLast(1200)}")
            }
            onClosed(
                AttachCloseInfo(
                    stillConnected = channel.isConnected,
                    exitStatus = channel.exitStatus,
                    stderrTail = stderrTail.toString().trim(),
                    outputTail = outputTailValue
                )
            )
        }
    }
}
