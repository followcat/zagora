package com.followcat.zagora.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val ZagoraDarkScheme = darkColorScheme(
    background = Color(0xFF0B0F14),
    surface = Color(0xFF0F1621),
    surfaceVariant = Color(0xFF162233),
    onBackground = Color(0xFFE6EDF3),
    onSurface = Color(0xFFE6EDF3),
    onSurfaceVariant = Color(0xFFB7C3D0),
    primary = Color(0xFF22D3EE),
    onPrimary = Color(0xFF001316),
)

@Composable
fun ZagoraTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = ZagoraDarkScheme,
        typography = MaterialTheme.typography,
        content = content
    )
}
