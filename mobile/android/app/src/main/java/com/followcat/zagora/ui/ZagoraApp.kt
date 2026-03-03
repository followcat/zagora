package com.followcat.zagora.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.followcat.zagora.data.SettingsStore
import com.followcat.zagora.model.Session
import com.followcat.zagora.util.openInExternalSshApp

@Composable
fun ZagoraApp(vm: MainViewModel = viewModel()) {
    val ctx = LocalContext.current
    val store = remember { SettingsStore(ctx) }
    val ui by vm.uiState.collectAsState()

    var server by remember { mutableStateOf(store.loadServer()) }
    var token by remember { mutableStateOf(store.loadToken()) }
    var hostFilter by remember { mutableStateOf("") }
    var sshUser by remember { mutableStateOf(store.loadSshUser()) }

    val topBg = Color(0xFF0F172A)
    val bottomBg = Color(0xFF1F2937)
    val accent = Color(0xFF06B6D4)
    val ok = Color(0xFF10B981)
    val warn = Color(0xFFF59E0B)

    MaterialTheme {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(colors = listOf(topBg, bottomBg)))
        ) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        color = Color(0xFF111827).copy(alpha = 0.94f),
                        tonalElevation = 2.dp
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                text = "Zagora Mobile",
                                style = MaterialTheme.typography.headlineSmall,
                                color = Color.White,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = "Session control with external SSH handoff",
                                color = Color(0xFFC7D2FE)
                            )
                        }
                    }
                }

                item {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(18.dp),
                        color = Color(0xFF111827).copy(alpha = 0.90f),
                        tonalElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            OutlinedTextField(
                                modifier = Modifier.fillMaxWidth(),
                                value = server,
                                onValueChange = { server = it },
                                label = { Text("Server (http://host:9876)") },
                                singleLine = true
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                modifier = Modifier.fillMaxWidth(),
                                value = token,
                                onValueChange = { token = it },
                                label = { Text("Token (optional)") },
                                singleLine = true
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                modifier = Modifier.fillMaxWidth(),
                                value = sshUser,
                                onValueChange = { sshUser = it },
                                label = { Text("SSH user (optional)") },
                                singleLine = true
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                modifier = Modifier.fillMaxWidth(),
                                value = hostFilter,
                                onValueChange = { hostFilter = it },
                                label = { Text("Host filter (optional)") },
                                singleLine = true
                            )
                            Spacer(Modifier.height(10.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                FilledTonalButton(onClick = { store.save(server, token, sshUser) }) {
                                    Text("Save")
                                }
                                Button(onClick = { vm.loadSessions(server, token, hostFilter) }) {
                                    Text("Load Sessions")
                                }
                            }
                        }
                    }
                }

                item {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        color = if (ui.loading) accent.copy(alpha = 0.22f) else Color(0xFF0B1220).copy(alpha = 0.80f)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            if (ui.loading) {
                                CircularProgressIndicator(modifier = Modifier.height(18.dp), strokeWidth = 2.dp)
                            }
                            Text(
                                text = if (ui.message.isBlank()) "Ready" else ui.message,
                                color = Color.White
                            )
                        }
                    }
                }

                items(ui.sessions) { session ->
                    SessionCard(
                        session = session,
                        okColor = ok,
                        warnColor = warn,
                        onOpenSsh = { openInExternalSshApp(ctx, session.host, sshUser) },
                        onDelete = { vm.deleteSession(server, token, session) }
                    )
                }
            }
        }
    }
}

@Composable
private fun SessionCard(
    session: Session,
    okColor: Color,
    warnColor: Color,
    onOpenSsh: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                "${session.name} @ ${session.host}",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                StatusBadge(
                    text = session.status.ifBlank { "unknown" },
                    bg = if (session.status == "running") okColor else warnColor
                )
                val reach = when (session.hostReachable) {
                    true -> "host: up"
                    false -> "host: down"
                    null -> "host: ?"
                }
                StatusBadge(
                    text = reach,
                    bg = if (session.hostReachable == false) warnColor else okColor
                )
            }
            session.lastSeen?.takeIf { it.isNotBlank() }?.let {
                Spacer(Modifier.height(6.dp))
                Text("last_seen: $it")
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onOpenSsh) {
                    Text("Open SSH")
                }
                TextButton(onClick = onDelete) {
                    Text("Remove")
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(text: String, bg: Color) {
    Surface(
        shape = RoundedCornerShape(999.dp),
        color = bg.copy(alpha = 0.18f)
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            color = bg,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Medium
        )
    }
}
