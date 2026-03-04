package com.followcat.zagora.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

enum class ZagoraThemeVariant(val id: String, val title: String) {
    Neon("neon", "Neon Terminal"),
    Graphite("graphite", "Graphite Pro");

    companion object {
        fun fromId(id: String): ZagoraThemeVariant = entries.firstOrNull { it.id == id } ?: Neon
    }
}

private val ZagoraNeonScheme = darkColorScheme(
    background = Color(0xFF0B0F14),
    surface = Color(0xFF0F1621),
    surfaceVariant = Color(0xFF162233),
    surfaceContainer = Color(0xFF111B2A),
    surfaceContainerHigh = Color(0xFF152436),
    outline = Color(0xFF33485D),
    onBackground = Color(0xFFE6EDF3),
    onSurface = Color(0xFFE6EDF3),
    onSurfaceVariant = Color(0xFFB7C3D0),
    primary = Color(0xFF22D3EE),
    secondary = Color(0xFF5CC8FF),
    tertiary = Color(0xFF7FC5FF),
    error = Color(0xFFFF7E8A),
    onPrimary = Color(0xFF001316),
)

private val ZagoraGraphiteScheme = darkColorScheme(
    background = Color(0xFF0C0E12),
    surface = Color(0xFF141821),
    surfaceVariant = Color(0xFF1B2230),
    surfaceContainer = Color(0xFF171D29),
    surfaceContainerHigh = Color(0xFF1E2737),
    outline = Color(0xFF3A4659),
    onBackground = Color(0xFFE9EDF4),
    onSurface = Color(0xFFE9EDF4),
    onSurfaceVariant = Color(0xFFC0CAD8),
    primary = Color(0xFF66E0FF),
    secondary = Color(0xFF7AB7FF),
    tertiary = Color(0xFF9EC5FF),
    error = Color(0xFFFF8B98),
    onPrimary = Color(0xFF05151B),
)

private val ZagoraTypography = Typography(
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 30.sp,
        letterSpacing = 0.15.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 19.sp,
        lineHeight = 24.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 23.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 18.sp
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp
    )
)

@Composable
fun ZagoraTheme(
    variant: ZagoraThemeVariant = ZagoraThemeVariant.Neon,
    content: @Composable () -> Unit
) {
    val scheme = when (variant) {
        ZagoraThemeVariant.Neon -> ZagoraNeonScheme
        ZagoraThemeVariant.Graphite -> ZagoraGraphiteScheme
    }
    MaterialTheme(
        colorScheme = scheme,
        typography = ZagoraTypography,
        content = content
    )
}
