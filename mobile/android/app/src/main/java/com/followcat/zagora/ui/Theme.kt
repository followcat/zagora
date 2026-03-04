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

private val ZagoraDarkScheme = darkColorScheme(
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
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = ZagoraDarkScheme,
        typography = ZagoraTypography,
        content = content
    )
}
