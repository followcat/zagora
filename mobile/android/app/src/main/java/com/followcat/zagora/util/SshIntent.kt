package com.followcat.zagora.util

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast

fun openInExternalSshApp(context: Context, host: String, user: String) {
    val target = if (user.isBlank()) host else "$user@$host"
    val uri = Uri.parse("ssh://$target")
    val intent = Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    val manager = context.packageManager
    if (intent.resolveActivity(manager) != null) {
        context.startActivity(intent)
        return
    }

    val cmd = "ssh $target"
    val clip = ClipData.newPlainText("ssh command", cmd)
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(clip)
    Toast.makeText(context, "No SSH app found. Copied: $cmd", Toast.LENGTH_LONG).show()
}

