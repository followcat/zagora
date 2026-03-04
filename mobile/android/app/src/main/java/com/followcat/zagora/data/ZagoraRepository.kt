package com.followcat.zagora.data

import com.followcat.zagora.model.Session
import com.followcat.zagora.net.ZagoraApiFactory
import com.followcat.zagora.net.CreateSessionRequest
import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

class ZagoraRepository(
    private val server: String,
    private val token: String
) {
    private val api = ZagoraApiFactory.create(server, token)

    suspend fun listSessions(host: String?): List<Session> = api.listSessions(host?.takeIf { it.isNotBlank() })

    suspend fun removeSession(name: String, host: String) {
        api.deleteSession(name = name, host = host)
    }

    suspend fun killAndRemoveSession(name: String, host: String, sshUser: String, sshPassword: String) {
        val user = sshUser.trim()
        if (host.isBlank() || name.isBlank()) error("Session host/name is required")
        if (user.isBlank()) error("SSH user is required for kill")

        runCatching {
            withContext(Dispatchers.IO) {
                runRemoteKill(host = host.trim(), user = user, password = sshPassword, sessionName = name.trim())
            }
        }.getOrElse { err ->
            val root = rootCause(err)
            if (root is JSchException && root.message?.contains("auth fail", ignoreCase = true) == true) {
                throw IllegalStateException("SSH auth failed for $user@$host")
            }
            // Same as CLI stale-clean behavior for unreachable hosts: ignore and remove stale registry entry.
            Unit
        }
        api.deleteSession(name = name, host = host)
    }

    suspend fun createSession(name: String, host: String): Session {
        return api.createSession(CreateSessionRequest(name = name, host = host))
    }

    private fun runRemoteKill(host: String, user: String, password: String, sessionName: String) {
        val jsch = JSch()
        val session = jsch.getSession(user, host, 22)
        if (password.isNotBlank()) {
            session.setPassword(password)
        }
        session.setConfig("StrictHostKeyChecking", "no")
        session.connect(10_000)

        val channel = (session.openChannel("exec") as ChannelExec)
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        channel.setErrStream(err)
        val q = shellEscape(sessionName)
        channel.setCommand(
            "if command -v zellij >/dev/null 2>&1; then " +
                "zellij kill-session $q >/dev/null 2>&1 || zellij delete-session $q >/dev/null 2>&1 || true; " +
                "else echo __ZG_NO_ZELLIJ__; fi"
        )
        channel.connect(10_000)
        val stdout = channel.inputStream
        val tmp = ByteArray(1024)
        while (!channel.isClosed) {
            while (stdout.available() > 0) {
                val n = stdout.read(tmp, 0, tmp.size)
                if (n <= 0) break
                out.write(tmp, 0, n)
            }
            Thread.sleep(40)
        }
        while (stdout.available() > 0) {
            val n = stdout.read(tmp, 0, tmp.size)
            if (n <= 0) break
            out.write(tmp, 0, n)
        }
        val exit = channel.exitStatus
        val output = (out.toString(Charsets.UTF_8.name()) + "\n" + err.toString(Charsets.UTF_8.name())).trim()
        channel.disconnect()
        session.disconnect()

        // If remote host reachable but command failed with explicit auth/permission-like signal, fail fast.
        if (exit != 0 && output.contains("permission denied", ignoreCase = true)) {
            error("Remote kill failed: permission denied")
        }
        // zellij missing / non-zero are tolerated by caller for stale cleanup semantics.
    }

    private fun shellEscape(raw: String): String {
        if (raw.isBlank()) return "''"
        return "'" + raw.replace("'", "'\"'\"'") + "'"
    }

    private fun rootCause(err: Throwable): Throwable {
        var cur: Throwable = err
        while (cur.cause != null && cur.cause !== cur) {
            cur = cur.cause!!
        }
        return cur
    }
}
