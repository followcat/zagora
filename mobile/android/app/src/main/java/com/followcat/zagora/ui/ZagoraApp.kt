package com.followcat.zagora.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.lifecycle.viewmodel.compose.viewModel
import com.followcat.zagora.data.SettingsStore
import com.followcat.zagora.model.Session
import com.followcat.zagora.util.openInExternalSshApp
import kotlinx.coroutines.launch

@Composable
fun ZagoraApp(
    vm: MainViewModel = viewModel(),
    attachVm: AttachViewModel = viewModel()
) {
    val ctx = LocalContext.current
    val store = remember { SettingsStore(ctx) }
    val ui by vm.uiState.collectAsState()
    val attachState by attachVm.state.collectAsState()

    var server by remember { mutableStateOf(store.loadServer()) }
    var token by remember { mutableStateOf(store.loadToken()) }
    var hostFilter by remember { mutableStateOf("") }
    var sshUser by remember { mutableStateOf(store.loadSshUser()) }
    var attachTarget by remember { mutableStateOf<Session?>(null) }

    val topBg = Color(0xFF0F172A)
    val bottomBg = Color(0xFF1F2937)
    val accent = Color(0xFF06B6D4)
    val ok = Color(0xFF10B981)
    val warn = Color(0xFFF59E0B)

    MaterialTheme {
        val bgModifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(colors = listOf(topBg, bottomBg)))
        if (attachTarget != null) {
            Box(modifier = bgModifier) {
                AttachScreen(
                    target = attachTarget!!,
                    attachState = attachState,
                    initialUser = sshUser,
                    onBack = {
                        attachVm.disconnect()
                        attachTarget = null
                    },
                    onConnect = { user, password ->
                        if (user.isNotBlank()) {
                            sshUser = user
                            store.save(server, token, sshUser)
                        }
                        attachVm.connect(
                            host = attachTarget!!.host,
                            user = user,
                            password = password,
                            sessionName = attachTarget!!.name
                        )
                    },
                    onDisconnect = { attachVm.disconnect() },
                    onSendLine = { line -> attachVm.sendLine(line) },
                    onSendCtrlC = { attachVm.sendCtrlC() },
                    onSendCtrl = { c -> attachVm.sendCtrlChar(c) },
                    onSendAlt = { c -> attachVm.sendAltChar(c) },
                    onSendTab = { attachVm.sendTab() },
                    onSendShiftTab = { attachVm.sendShiftTab() },
                    onSendEsc = { attachVm.sendEscape() },
                    onSendArrowUp = { attachVm.sendArrowUp() },
                    onSendArrowDown = { attachVm.sendArrowDown() },
                    onSendArrowLeft = { attachVm.sendArrowLeft() },
                    onSendArrowRight = { attachVm.sendArrowRight() },
                    onSendVimNav = { txt -> attachVm.sendTextRaw(txt) },
                    onSendPageUp = { attachVm.sendPageUp() },
                    onSendPageDown = { attachVm.sendPageDown() },
                    onSendHome = { attachVm.sendHome() },
                    onSendEnd = { attachVm.sendEnd() },
                    onPasteRaw = { txt -> attachVm.pasteRaw(txt) }
                )
            }
        } else {
            Box(modifier = bgModifier) {
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
                                color = Color(0xFFF8FAFC),
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = "Session control with external SSH handoff",
                                color = Color(0xFFE2E8F0)
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
                                singleLine = true,
                                colors = zagoraFieldColors()
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                modifier = Modifier.fillMaxWidth(),
                                value = token,
                                onValueChange = { token = it },
                                label = { Text("Token (optional)") },
                                singleLine = true,
                                colors = zagoraFieldColors()
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                modifier = Modifier.fillMaxWidth(),
                                value = sshUser,
                                onValueChange = { sshUser = it },
                                label = { Text("SSH user (optional)") },
                                singleLine = true,
                                colors = zagoraFieldColors()
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                modifier = Modifier.fillMaxWidth(),
                                value = hostFilter,
                                onValueChange = { hostFilter = it },
                                label = { Text("Host filter (optional)") },
                                singleLine = true,
                                colors = zagoraFieldColors()
                            )
                            Spacer(Modifier.height(10.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                FilledTonalButton(
                                    onClick = { store.save(server, token, sshUser) },
                                    colors = zagoraTonalButtonColors()
                                ) {
                                    Text("Save")
                                }
                                Button(
                                    onClick = { vm.loadSessions(server, token, hostFilter) },
                                    colors = zagoraPrimaryButtonColors()
                                ) {
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
                            onAttach = {
                                attachVm.disconnect()
                                attachTarget = session
                            },
                            onOpenSsh = { openInExternalSshApp(ctx, session.host, sshUser) },
                            onDelete = { vm.deleteSession(server, token, session) }
                        )
                    }
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
    onAttach: () -> Unit,
    onOpenSsh: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A).copy(alpha = 0.94f))
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                "${session.name} @ ${session.host}",
                style = MaterialTheme.typography.titleMedium,
                color = Color(0xFFF1F5F9),
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
                Text("last_seen: $it", color = Color(0xFF94A3B8))
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onAttach, colors = zagoraPrimaryButtonColors()) {
                    Text("Attach")
                }
                Button(onClick = onOpenSsh, colors = zagoraTonalButtonColors()) {
                    Text("Open SSH")
                }
                TextButton(onClick = onDelete, colors = zagoraDangerTextButtonColors()) {
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

@Composable
private fun AttachScreen(
    target: Session,
    attachState: com.followcat.zagora.data.AttachState,
    initialUser: String,
    onBack: () -> Unit,
    onConnect: (String, String) -> Unit,
    onDisconnect: () -> Unit,
    onSendLine: (String) -> Unit,
    onSendCtrlC: () -> Unit,
    onSendCtrl: (Char) -> Unit,
    onSendAlt: (Char) -> Unit,
    onSendTab: () -> Unit,
    onSendShiftTab: () -> Unit,
    onSendEsc: () -> Unit,
    onSendArrowUp: () -> Unit,
    onSendArrowDown: () -> Unit,
    onSendArrowLeft: () -> Unit,
    onSendArrowRight: () -> Unit,
    onSendVimNav: (String) -> Unit,
    onSendPageUp: () -> Unit,
    onSendPageDown: () -> Unit,
    onSendHome: () -> Unit,
    onSendEnd: () -> Unit,
    onPasteRaw: (String) -> Unit
) {
    var user by remember(target.host, target.name) { mutableStateOf(initialUser) }
    var password by remember(target.host, target.name) { mutableStateOf("") }
    var command by remember(target.host, target.name) { mutableStateOf("") }
    var showSessionDrawer by remember(target.host, target.name) { mutableStateOf(false) }
    var quickKeysExpanded by remember(target.host, target.name) { mutableStateOf(false) }
    var terminalFontSize by remember(target.host, target.name) { mutableStateOf(13f) }
    val outputScroll = rememberScrollState()
    val outputXScroll = rememberScrollState()
    val clipboard = LocalClipboardManager.current
    var followOutput by remember(target.host, target.name) { mutableStateOf(true) }
    val screenScope = rememberCoroutineScope()
    val term = remember(target.host, target.name) { TerminalEmulator(cols = 100, rows = 36) }
    var processedLen by remember(target.host, target.name) { mutableStateOf(0) }
    var renderedTerminal by remember(target.host, target.name) { mutableStateOf("# waiting for shell output...") }
    val density = LocalDensity.current
    val keyboardVisible = WindowInsets.ime.getBottom(density) > 0

    LaunchedEffect(attachState.output) {
        val out = attachState.output
        if (out.length < processedLen) {
            term.reset()
            processedLen = 0
            renderedTerminal = "# waiting for shell output..."
        }
        if (out.length > processedLen) {
            val delta = out.substring(processedLen)
            term.feed(delta)
            processedLen = out.length
            renderedTerminal = term.renderText().ifBlank { "# waiting for shell output..." }
        }
    }

    val terminalAnnotated = remember(renderedTerminal) { buildTerminalAnnotated(renderedTerminal) }

    LaunchedEffect(attachState.output, followOutput) {
        if (followOutput) {
            outputScroll.scrollTo(outputScroll.maxValue)
        }
    }
    LaunchedEffect(keyboardVisible) {
        if (!keyboardVisible) quickKeysExpanded = false
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            color = Color(0xFF0B1220).copy(alpha = 0.95f)
        ) {
            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilledTonalButton(onClick = onBack, colors = zagoraTonalButtonColors()) { Text("Back") }
                    FilledTonalButton(onClick = { showSessionDrawer = !showSessionDrawer }, colors = zagoraTonalButtonColors()) {
                        Text(if (showSessionDrawer) "Session -" else "Session +")
                    }
                    FilledTonalButton(onClick = { terminalFontSize = (terminalFontSize - 1f).coerceAtLeast(11f) }, colors = zagoraTonalButtonColors()) {
                        Text("A-")
                    }
                    FilledTonalButton(onClick = { terminalFontSize = (terminalFontSize + 1f).coerceAtMost(17f) }, colors = zagoraTonalButtonColors()) {
                        Text("A+")
                    }
                    FilledTonalButton(
                        onClick = onDisconnect,
                        enabled = attachState.connected,
                        colors = zagoraTonalButtonColors()
                    ) {
                        Text("Disconnect")
                    }
                }
                Text("${target.name}@${target.host}", color = Color(0xFFF1F5F9), fontWeight = FontWeight.SemiBold)
                Text("user:${user.ifBlank { "<ssh-user>" }}  font:${terminalFontSize.toInt()}sp", color = Color(0xFF94A3B8))
            }
        }

        AnimatedVisibility(visible = showSessionDrawer) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = Color(0xFF0B1220).copy(alpha = 0.92f)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = user,
                        onValueChange = { user = it },
                        label = { Text("SSH user") },
                        singleLine = true,
                        colors = zagoraFieldColors()
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("SSH password (optional)") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        colors = zagoraFieldColors()
                    )
                    Spacer(Modifier.height(8.dp))
                    Button(
                        onClick = { onConnect(user.trim(), password) },
                        enabled = !attachState.connecting,
                        colors = zagoraPrimaryButtonColors()
                    ) {
                        Text(if (attachState.connecting) "Connecting..." else "Connect + Attach")
                    }
                }
            }
        }

        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            shape = RoundedCornerShape(14.dp),
            color = Color(0xFF020617).copy(alpha = 0.96f)
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    FilledTonalButton(onClick = { followOutput = !followOutput }, colors = zagoraTonalButtonColors()) {
                        Text(if (followOutput) "Follow: ON" else "Follow: OFF")
                    }
                    FilledTonalButton(onClick = onSendCtrlC, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Ctrl+C") }
                    FilledTonalButton(onClick = { clipboard.setText(AnnotatedString(renderedTerminal)) }, colors = zagoraTonalButtonColors()) { Text("Copy") }
                    FilledTonalButton(onClick = { screenScope.launch { outputScroll.scrollTo(0) } }, colors = zagoraTonalButtonColors()) { Text("Top") }
                    FilledTonalButton(onClick = { screenScope.launch { outputScroll.scrollTo(outputScroll.maxValue) } }, colors = zagoraTonalButtonColors()) { Text("Bottom") }
                }
                Text(
                    text = attachState.message.ifBlank { "Ready" },
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 2.dp),
                    color = if (attachState.message.contains("fail", true) || attachState.message.contains("error", true)) Color(0xFFFCA5A5) else Color(0xFFE2E8F0)
                )
                SelectionContainer {
                    Text(
                        text = terminalAnnotated,
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(outputScroll)
                            .horizontalScroll(outputXScroll)
                            .padding(12.dp),
                        color = Color(0xFFE2E8F0),
                        fontFamily = FontFamily.Monospace,
                        fontSize = terminalFontSize.sp,
                        softWrap = false
                    )
                }
            }
        }

        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            color = Color(0xFF0B1220).copy(alpha = 0.90f)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                OutlinedTextField(
                    modifier = Modifier.fillMaxWidth(),
                    value = command,
                    onValueChange = { command = it },
                    label = { Text("Command") },
                    singleLine = true,
                    colors = zagoraFieldColors()
                )
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            val cmd = command.trim()
                            if (cmd.isNotBlank()) {
                                onSendLine(cmd)
                                command = ""
                            }
                        },
                        enabled = attachState.connected,
                        colors = zagoraPrimaryButtonColors()
                    ) { Text("Send") }
                    FilledTonalButton(onClick = onSendCtrlC, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Ctrl+C") }
                    FilledTonalButton(
                        onClick = {
                            val clip = clipboard.getText()?.text?.toString().orEmpty()
                            if (clip.isNotEmpty()) onPasteRaw(clip)
                        },
                        enabled = attachState.connected,
                        colors = zagoraTonalButtonColors()
                    ) { Text("Paste->Shell") }
                }

                if (keyboardVisible) {
                    Spacer(Modifier.height(8.dp))
                    FilledTonalButton(onClick = { quickKeysExpanded = !quickKeysExpanded }, colors = zagoraTonalButtonColors()) {
                        Text(if (quickKeysExpanded) "快捷键 收起" else "快捷键 展开")
                    }
                }
                AnimatedVisibility(visible = keyboardVisible && quickKeysExpanded) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text("导航", color = Color(0xFF94A3B8))
                        Row(modifier = Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            FilledTonalButton(onClick = onSendArrowUp, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Up") }
                            FilledTonalButton(onClick = onSendArrowDown, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Down") }
                            FilledTonalButton(onClick = onSendArrowLeft, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Left") }
                            FilledTonalButton(onClick = onSendArrowRight, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Right") }
                            FilledTonalButton(onClick = { onSendVimNav("h") }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("h") }
                            FilledTonalButton(onClick = { onSendVimNav("j") }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("j") }
                            FilledTonalButton(onClick = { onSendVimNav("k") }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("k") }
                            FilledTonalButton(onClick = { onSendVimNav("l") }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("l") }
                        }
                        Row(modifier = Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            FilledTonalButton(onClick = onSendEsc, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Esc") }
                            FilledTonalButton(onClick = onSendTab, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Tab") }
                            FilledTonalButton(onClick = onSendShiftTab, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("S-Tab") }
                            FilledTonalButton(onClick = onSendPageUp, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("PgUp") }
                            FilledTonalButton(onClick = onSendPageDown, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("PgDn") }
                            FilledTonalButton(onClick = onSendHome, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Home") }
                            FilledTonalButton(onClick = onSendEnd, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("End") }
                        }
                        Text("控制", color = Color(0xFF94A3B8))
                        Row(modifier = Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            FilledTonalButton(onClick = { onSendCtrl('A') }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Ctrl+A") }
                            FilledTonalButton(onClick = { onSendCtrl('D') }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Ctrl+D") }
                            FilledTonalButton(onClick = { onSendCtrl('L') }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Ctrl+L") }
                            FilledTonalButton(onClick = { onSendCtrl('Z') }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Ctrl+Z") }
                        }
                        Row(modifier = Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            FilledTonalButton(onClick = { onSendAlt('b') }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Alt+B") }
                            FilledTonalButton(onClick = { onSendAlt('f') }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Alt+F") }
                            FilledTonalButton(onClick = { onSendAlt('d') }, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("Alt+D") }
                        }
                    }
                }
            }
        }
    }
}

private fun buildTerminalAnnotated(text: String): AnnotatedString {
    val error = Regex("(?i)(error|failed|exception|traceback)")
    val warn = Regex("(?i)(warn|warning)")
    val ok = Regex("(?i)(success|connected|attached|done|ok\\b)")
    val prompt = Regex("^\\s*([\\w.-]+@[^\\s]+[:~].*[#$]|[#$>]\\s)")
    val cmdEcho = Regex("^\\s*\\$\\s+.+")
    return androidx.compose.ui.text.buildAnnotatedString {
        val lines = text.split('\n')
        lines.forEachIndexed { i, line ->
            val style = when {
                prompt.containsMatchIn(line) -> SpanStyle(color = Color(0xFF22D3EE))
                cmdEcho.containsMatchIn(line) -> SpanStyle(color = Color(0xFF93C5FD))
                error.containsMatchIn(line) -> SpanStyle(color = Color(0xFFFCA5A5))
                warn.containsMatchIn(line) -> SpanStyle(color = Color(0xFFFBBF24))
                ok.containsMatchIn(line) -> SpanStyle(color = Color(0xFF86EFAC))
                else -> SpanStyle(color = Color(0xFFE2E8F0))
            }
            withStyle(style) { append(line) }
            if (i < lines.lastIndex) append('\n')
        }
    }
}

@Composable
private fun zagoraFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = Color.White,
    unfocusedTextColor = Color(0xFFE5E7EB),
    focusedContainerColor = Color(0xFF0B1220),
    unfocusedContainerColor = Color(0xFF0B1220),
    cursorColor = Color(0xFF22D3EE),
    focusedBorderColor = Color(0xFF38BDF8),
    unfocusedBorderColor = Color(0xFF475569),
    focusedLabelColor = Color(0xFF93C5FD),
    unfocusedLabelColor = Color(0xFF94A3B8),
    focusedPlaceholderColor = Color(0xFF64748B),
    unfocusedPlaceholderColor = Color(0xFF64748B)
)

@Composable
private fun zagoraPrimaryButtonColors() = ButtonDefaults.buttonColors(
    containerColor = Color(0xFF22D3EE),
    contentColor = Color(0xFF032230),
    disabledContainerColor = Color(0xFF164E63),
    disabledContentColor = Color(0xFF94A3B8)
)

@Composable
private fun zagoraTonalButtonColors() = ButtonDefaults.filledTonalButtonColors(
    containerColor = Color(0xFF334155),
    contentColor = Color(0xFFF8FAFC),
    disabledContainerColor = Color(0xFF1E293B),
    disabledContentColor = Color(0xFF64748B)
)

@Composable
private fun zagoraDangerTextButtonColors() = ButtonDefaults.textButtonColors(
    contentColor = Color(0xFFFCA5A5),
    disabledContentColor = Color(0xFF7F1D1D)
)
