package com.followcat.zagora.data

import android.content.Context

private const val PREF_NAME = "zagora_settings"
private const val KEY_SERVER = "server"
private const val KEY_TOKEN = "token"
private const val KEY_SSH_USER = "ssh_user"

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    fun loadServer(): String = prefs.getString(KEY_SERVER, "") ?: ""
    fun loadToken(): String = prefs.getString(KEY_TOKEN, "") ?: ""
    fun loadSshUser(): String = prefs.getString(KEY_SSH_USER, "") ?: ""

    fun save(server: String, token: String, sshUser: String) {
        prefs.edit()
            .putString(KEY_SERVER, server.trim())
            .putString(KEY_TOKEN, token.trim())
            .putString(KEY_SSH_USER, sshUser.trim())
            .apply()
    }
}

