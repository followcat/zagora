package com.followcat.zagora

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.followcat.zagora.data.SettingsStore
import com.followcat.zagora.ui.ZagoraApp
import com.followcat.zagora.ui.ZagoraTheme
import com.followcat.zagora.ui.ZagoraThemeVariant

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val store = remember { SettingsStore(this@MainActivity) }
            var themeVariant by remember {
                mutableStateOf(ZagoraThemeVariant.fromId(store.loadThemeVariant()))
            }
            ZagoraTheme(variant = themeVariant) {
                Surface(color = MaterialTheme.colorScheme.background) {
                    ZagoraApp(
                        themeVariant = themeVariant,
                        onThemeVariantChange = { next ->
                            themeVariant = next
                            store.saveThemeVariant(next.id)
                        }
                    )
                }
            }
        }
    }
}
