package com.followcat.zagora.data

import com.followcat.zagora.model.Session
import com.followcat.zagora.net.ZagoraApiFactory

class ZagoraRepository(
    private val server: String,
    private val token: String
) {
    private val api = ZagoraApiFactory.create(server, token)

    suspend fun listSessions(host: String?): List<Session> = api.listSessions(host?.takeIf { it.isNotBlank() })

    suspend fun removeSession(name: String, host: String) {
        api.deleteSession(name = name, host = host)
    }
}

