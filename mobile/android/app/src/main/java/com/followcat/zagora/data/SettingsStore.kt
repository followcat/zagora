package com.followcat.zagora.data

import android.content.Context

private const val PREF_NAME = "zagora_settings"
private const val KEY_SERVER = "server"
private const val KEY_TOKEN = "token"
private const val KEY_SSH_USER = "ssh_user"
private const val KEY_TERM_FONT_SIZE = "term_font_size"
private const val KEY_CONFIRM_MULTI_PASTE = "confirm_multi_paste"
private const val KEY_RECONNECT_POLICY = "reconnect_policy"

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    fun loadServer(): String = prefs.getString(KEY_SERVER, "") ?: ""
    fun loadToken(): String = prefs.getString(KEY_TOKEN, "") ?: ""
    fun loadSshUser(): String = prefs.getString(KEY_SSH_USER, "") ?: ""
    fun loadTerminalFontSize(): Float = prefs.getFloat(KEY_TERM_FONT_SIZE, 14f)
    fun loadConfirmMultilinePaste(): Boolean = prefs.getBoolean(KEY_CONFIRM_MULTI_PASTE, true)
    fun loadReconnectPolicy(): String = prefs.getString(KEY_RECONNECT_POLICY, "manual") ?: "manual"

    fun save(server: String, token: String, sshUser: String) {
        prefs.edit()
            .putString(KEY_SERVER, server.trim())
            .putString(KEY_TOKEN, token.trim())
            .putString(KEY_SSH_USER, sshUser.trim())
            .apply()
    }

    fun saveTerminalPrefs(fontSize: Float, confirmMultilinePaste: Boolean, reconnectPolicy: String = "manual") {
        prefs.edit()
            .putFloat(KEY_TERM_FONT_SIZE, fontSize.coerceIn(11f, 18f))
            .putBoolean(KEY_CONFIRM_MULTI_PASTE, confirmMultilinePaste)
            .putString(KEY_RECONNECT_POLICY, reconnectPolicy)
            .apply()
    }
}
