package com.followcat.zagora.model

import com.squareup.moshi.Json

data class Session(
    @field:Json(name = "name") val name: String = "",
    @field:Json(name = "host") val host: String = "",
    @field:Json(name = "status") val status: String = "",
    @field:Json(name = "last_seen") val lastSeen: String? = null,
    @field:Json(name = "host_reachable") val hostReachable: Boolean? = null
)

