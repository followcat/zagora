package com.followcat.zagora

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import com.followcat.zagora.ui.ZagoraApp
import com.followcat.zagora.ui.ZagoraTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ZagoraTheme {
                Surface(color = MaterialTheme.colorScheme.background) {
                    ZagoraApp()
                }
            }
        }
    }
}
