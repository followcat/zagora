package com.followcat.zagora.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.clickable
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
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
import androidx.lifecycle.viewmodel.compose.viewModel
import com.followcat.zagora.data.SettingsStore
import com.followcat.zagora.model.Session
import com.followcat.zagora.util.openInExternalSshApp
import kotlinx.coroutines.launch

private enum class MobileScreen {
    Sessions,
    Settings
}

private enum class SessionScopeFilter(val label: String) {
    All("All"),
    Prod("Prod"),
    Staging("Staging"),
    Dev("Dev"),
    Offline("Offline");

    fun matches(session: Session): Boolean {
        val h = session.host.lowercase()
        return when (this) {
            All -> true
            Prod -> "prod" in h
            Staging -> "stag" in h
            Dev -> ("dev" in h) || ("test" in h)
            Offline -> session.hostReachable == false || session.status.lowercase() != "running"
        }
    }
}

@Composable
fun ZagoraApp(
    vm: MainViewModel = viewModel(),
    attachVm: AttachViewModel = viewModel()
) {
    val ctx = LocalContext.current
    val store = remember { SettingsStore(ctx) }
    val ui by vm.uiState.collectAsState()
    val attachState by attachVm.state.collectAsState()
    val sticky by attachVm.sticky.collectAsState()

    var server by remember { mutableStateOf(store.loadServer()) }
    var token by remember { mutableStateOf(store.loadToken()) }
    var hostFilter by remember { mutableStateOf("") }
    var sshUser by remember { mutableStateOf(store.loadSshUser()) }
    var terminalFontSizePref by remember { mutableStateOf(store.loadTerminalFontSize()) }
    var confirmMultilinePaste by remember { mutableStateOf(store.loadConfirmMultilinePaste()) }
    var reconnectPolicy by remember { mutableStateOf(store.loadReconnectPolicy()) }
    var screen by remember { mutableStateOf(MobileScreen.Sessions) }
    var attachTarget by remember { mutableStateOf<Session?>(null) }
    var scopeFilter by remember { mutableStateOf(SessionScopeFilter.All) }

    val topBg = Color(0xFF0F172A)
    val bottomBg = Color(0xFF1F2937)
    val accent = Color(0xFF06B6D4)
    val ok = Color(0xFF10B981)
    val warn = Color(0xFFF59E0B)

    LaunchedEffect(reconnectPolicy) {
        attachVm.setReconnectPolicy(reconnectPolicy)
    }

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
                        attachVm.setReconnectPolicy(reconnectPolicy)
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
                    onSendTab = { attachVm.sendTab() },
                    onSendShiftTab = { attachVm.sendShiftTab() },
                    onSendEsc = { attachVm.sendEscape() },
                    onSendArrowUp = { attachVm.sendArrowUp() },
                    onSendArrowDown = { attachVm.sendArrowDown() },
                    onSendArrowLeft = { attachVm.sendArrowLeft() },
                    onSendArrowRight = { attachVm.sendArrowRight() },
                    onSendPageUp = { attachVm.sendPageUp() },
                    onSendPageDown = { attachVm.sendPageDown() },
                    onSendHome = { attachVm.sendHome() },
                    onSendEnd = { attachVm.sendEnd() },
                    onPasteRaw = { txt -> attachVm.pasteRaw(txt) },
                    stickyCtrl = sticky.ctrl,
                    stickyAlt = sticky.alt,
                    onToggleStickyCtrl = { attachVm.toggleStickyCtrl() },
                    onToggleStickyAlt = { attachVm.toggleStickyAlt() },
                    initialFontSize = terminalFontSizePref,
                    confirmMultilinePaste = confirmMultilinePaste,
                )
            }
        } else {
            when (screen) {
                MobileScreen.Sessions -> SessionsScreen(
                    ui = ui,
                    sessions = ui.sessions.filter { scopeFilter.matches(it) }.filter { s ->
                        if (hostFilter.isBlank()) true
                        else s.name.contains(hostFilter, ignoreCase = true) || s.host.contains(hostFilter, ignoreCase = true)
                    },
                    server = server,
                    token = token,
                    hostFilter = hostFilter,
                    scopeFilter = scopeFilter,
                    onScopeFilterChange = { scopeFilter = it },
                    onServerChange = { server = it },
                    onTokenChange = { token = it },
                    onHostFilterChange = { hostFilter = it },
                    onLoad = { vm.loadSessions(server, token, "") },
                    onSave = { store.save(server, token, sshUser) },
                    onGoSettings = { screen = MobileScreen.Settings },
                    onAttachSession = { session ->
                        attachVm.disconnect()
                        attachTarget = session
                    },
                    onOpenSsh = { session -> openInExternalSshApp(ctx, session.host, sshUser) },
                    onDelete = { session -> vm.deleteSession(server, token, session) },
                    okColor = ok,
                    warnColor = warn,
                    accent = accent
                )
                MobileScreen.Settings -> SettingsScreen(
                    server = server,
                    token = token,
                    sshUser = sshUser,
                    terminalFontSize = terminalFontSizePref,
                    confirmMultilinePaste = confirmMultilinePaste,
                    reconnectPolicy = reconnectPolicy,
                    onBack = { screen = MobileScreen.Sessions },
                    onSave = { newServer, newToken, newUser, newFont, newConfirm, newPolicy ->
                        server = newServer
                        token = newToken
                        sshUser = newUser
                        terminalFontSizePref = newFont
                        confirmMultilinePaste = newConfirm
                        reconnectPolicy = newPolicy
                        attachVm.setReconnectPolicy(reconnectPolicy)
                        store.save(server, token, sshUser)
                        store.saveTerminalPrefs(
                            fontSize = terminalFontSizePref,
                            confirmMultilinePaste = confirmMultilinePaste,
                            reconnectPolicy = reconnectPolicy
                        )
                    }
                )
            }
        }
    }
}

@Composable
private fun SessionsScreen(
    ui: UiState,
    sessions: List<Session>,
    server: String,
    token: String,
    hostFilter: String,
    scopeFilter: SessionScopeFilter,
    onScopeFilterChange: (SessionScopeFilter) -> Unit,
    onServerChange: (String) -> Unit,
    onTokenChange: (String) -> Unit,
    onHostFilterChange: (String) -> Unit,
    onLoad: () -> Unit,
    onSave: () -> Unit,
    onGoSettings: () -> Unit,
    onAttachSession: (Session) -> Unit,
    onOpenSsh: (Session) -> Unit,
    onDelete: (Session) -> Unit,
    okColor: Color,
    warnColor: Color,
    accent: Color
) {
    Box(modifier = Modifier.fillMaxSize()) {
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
                            text = "Sessions",
                            style = MaterialTheme.typography.headlineSmall,
                            color = Color(0xFFF8FAFC),
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "List -> Attach -> Terminal",
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
                    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = server,
                            onValueChange = onServerChange,
                            label = { Text("Server (http://host:9876)") },
                            singleLine = true,
                            colors = zagoraFieldColors()
                        )
                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = token,
                            onValueChange = onTokenChange,
                            label = { Text("Token (optional)") },
                            singleLine = true,
                            colors = zagoraFieldColors()
                        )
                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = hostFilter,
                            onValueChange = onHostFilterChange,
                            label = { Text("Search by session / host") },
                            singleLine = true,
                            colors = zagoraFieldColors()
                        )
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            SessionScopeFilter.entries.forEach { chip ->
                                FilterChip(
                                    selected = scopeFilter == chip,
                                    onClick = { onScopeFilterChange(chip) },
                                    label = { Text(chip.label) },
                                    colors = FilterChipDefaults.filterChipColors(
                                        selectedContainerColor = Color(0xFF0E7490),
                                        selectedLabelColor = Color(0xFFECFEFF),
                                        containerColor = Color(0xFF334155),
                                        labelColor = Color(0xFFF8FAFC)
                                    )
                                )
                            }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilledTonalButton(onClick = onSave, colors = zagoraTonalButtonColors()) { Text("Save") }
                            Button(onClick = onLoad, colors = zagoraPrimaryButtonColors()) { Text("Load Sessions") }
                            FilledTonalButton(onClick = onGoSettings, colors = zagoraTonalButtonColors()) { Text("Settings") }
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
                        Text(text = if (ui.message.isBlank()) "Ready" else ui.message, color = Color.White)
                    }
                }
            }
            items(sessions) { session ->
                SessionCard(
                    session = session,
                    okColor = okColor,
                    warnColor = warnColor,
                    onAttach = { onAttachSession(session) },
                    onOpenSsh = { onOpenSsh(session) },
                    onDelete = { onDelete(session) }
                )
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    server: String,
    token: String,
    sshUser: String,
    terminalFontSize: Float,
    confirmMultilinePaste: Boolean,
    reconnectPolicy: String,
    onBack: () -> Unit,
    onSave: (String, String, String, Float, Boolean, String) -> Unit
) {
    var localServer by remember { mutableStateOf(server) }
    var localToken by remember { mutableStateOf(token) }
    var localUser by remember { mutableStateOf(sshUser) }
    var localFont by remember { mutableStateOf(terminalFontSize) }
    var localConfirm by remember { mutableStateOf(confirmMultilinePaste) }
    var localPolicy by remember { mutableStateOf(reconnectPolicy) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                color = Color(0xFF111827).copy(alpha = 0.94f)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilledTonalButton(onClick = onBack, colors = zagoraTonalButtonColors()) { Text("Back") }
                        Text("Settings", color = Color(0xFFF8FAFC), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleLarge)
                    }
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = localServer,
                        onValueChange = { localServer = it },
                        label = { Text("Base URL") },
                        singleLine = true,
                        colors = zagoraFieldColors()
                    )
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = localToken,
                        onValueChange = { localToken = it },
                        label = { Text("Bearer Token") },
                        singleLine = true,
                        colors = zagoraFieldColors()
                    )
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = localUser,
                        onValueChange = { localUser = it },
                        label = { Text("Default SSH User") },
                        singleLine = true,
                        colors = zagoraFieldColors()
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        FilledTonalButton(
                            onClick = { localFont = (localFont - 1f).coerceAtLeast(11f) },
                            colors = zagoraTonalButtonColors()
                        ) { Text("A-") }
                        FilledTonalButton(
                            onClick = { localFont = (localFont + 1f).coerceAtMost(18f) },
                            colors = zagoraTonalButtonColors()
                        ) { Text("A+") }
                        Text("Font ${localFont.toInt()}sp", color = Color(0xFF94A3B8))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilledTonalButton(
                            onClick = { localConfirm = !localConfirm },
                            colors = zagoraTonalButtonColors()
                        ) { Text(if (localConfirm) "Paste Confirm: ON" else "Paste Confirm: OFF") }
                        FilledTonalButton(
                            onClick = { localPolicy = if (localPolicy == "auto3") "manual" else "auto3" },
                            colors = zagoraTonalButtonColors()
                        ) { Text("Reconnect: $localPolicy") }
                    }
                    Button(
                        onClick = { onSave(localServer, localToken, localUser, localFont, localConfirm, localPolicy) },
                        colors = zagoraPrimaryButtonColors()
                    ) {
                        Text("Save Settings")
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
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onAttach),
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
    onSendTab: () -> Unit,
    onSendShiftTab: () -> Unit,
    onSendEsc: () -> Unit,
    onSendArrowUp: () -> Unit,
    onSendArrowDown: () -> Unit,
    onSendArrowLeft: () -> Unit,
    onSendArrowRight: () -> Unit,
    onSendPageUp: () -> Unit,
    onSendPageDown: () -> Unit,
    onSendHome: () -> Unit,
    onSendEnd: () -> Unit,
    onPasteRaw: (String) -> Unit,
    stickyCtrl: Boolean,
    stickyAlt: Boolean,
    onToggleStickyCtrl: () -> Unit,
    onToggleStickyAlt: () -> Unit,
    initialFontSize: Float,
    confirmMultilinePaste: Boolean
) {
    var user by remember(target.host, target.name) { mutableStateOf(initialUser) }
    var password by remember(target.host, target.name) { mutableStateOf("") }
    var command by remember(target.host, target.name) { mutableStateOf("") }
    var showSessionDrawer by remember(target.host, target.name) { mutableStateOf(false) }
    var extraKeysVisible by remember(target.host, target.name) { mutableStateOf(true) }
    var terminalFontSize by remember(target.host, target.name, initialFontSize) { mutableStateOf(initialFontSize) }
    var showPasteConfirm by remember(target.host, target.name) { mutableStateOf(false) }
    var pendingPaste by remember(target.host, target.name) { mutableStateOf("") }
    val outputScroll = rememberScrollState()
    val outputXScroll = rememberScrollState()
    val clipboard = LocalClipboardManager.current
    var followOutput by remember(target.host, target.name) { mutableStateOf(true) }
    val screenScope = rememberCoroutineScope()
    val term = remember(target.host, target.name) { TerminalEmulator(cols = 100, rows = 36) }
    var processedLen by remember(target.host, target.name) { mutableStateOf(0) }
    var renderedTerminal by remember(target.host, target.name) { mutableStateOf("# waiting for shell output...") }

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
    val statusText = phaseLabel(attachState.phase)
    val statusColor = phaseColor(attachState.phase)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            color = Color(0xFF0B1220).copy(alpha = 0.96f)
        ) {
            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilledTonalButton(onClick = onBack, colors = zagoraTonalButtonColors()) { Text("Back") }
                    Text(
                        "${target.host} · ${target.name}",
                        color = Color(0xFFF8FAFC),
                        fontWeight = FontWeight.SemiBold
                    )
                    StatusBadge(statusText, statusColor)
                    FilledTonalButton(
                        onClick = onDisconnect,
                        enabled = attachState.connected,
                        colors = zagoraTonalButtonColors()
                    ) { Text("Detach") }
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilledTonalButton(onClick = { showSessionDrawer = !showSessionDrawer }, colors = zagoraTonalButtonColors()) {
                        Text(if (showSessionDrawer) "Session -" else "Session +")
                    }
                    FilledTonalButton(
                        onClick = { extraKeysVisible = !extraKeysVisible },
                        colors = zagoraTonalButtonColors()
                    ) {
                        Text(if (extraKeysVisible) "Keys -" else "Keys +")
                    }
                    FilledTonalButton(
                        onClick = { onConnect(user.trim(), password) },
                        enabled = !attachState.connecting,
                        colors = zagoraTonalButtonColors()
                    ) { Text("Retry") }
                }
                Text(
                    "user:${user.ifBlank { "<ssh-user>" }} · in:${attachState.rawBytesIn}B out:${attachState.rawBytesOut}B",
                    color = Color(0xFF94A3B8)
                )
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
            shape = RoundedCornerShape(12.dp),
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
                    FilledTonalButton(onClick = { clipboard.setText(AnnotatedString(renderedTerminal)) }, colors = zagoraTonalButtonColors()) { Text("Copy") }
                    FilledTonalButton(onClick = { screenScope.launch { outputScroll.scrollTo(outputScroll.maxValue) } }, colors = zagoraTonalButtonColors()) { Text("Bottom") }
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = attachState.message.ifBlank { "Ready" },
                        color = if (attachState.message.contains("fail", true) || attachState.message.contains("error", true)) Color(0xFFFCA5A5) else Color(0xFFE2E8F0)
                    )
                    StatusBadge(
                        text = attachState.errorCode.name,
                        bg = if (attachState.errorCode == com.followcat.zagora.data.AttachErrorCode.None) Color(0xFF34D399) else Color(0xFFF59E0B)
                    )
                }
                SelectionContainer {
                    Text(
                        text = terminalAnnotated,
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(outputScroll)
                            .horizontalScroll(outputXScroll)
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        color = Color(0xFFE2E8F0),
                        fontFamily = FontFamily.Monospace,
                        fontSize = terminalFontSize.sp,
                        lineHeight = (terminalFontSize + 6f).sp,
                        softWrap = false
                    )
                }
            }
        }

        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = 230.dp),
            shape = RoundedCornerShape(14.dp),
            color = Color(0xFF0B1220).copy(alpha = 0.90f)
        ) {
            Column(
                modifier = Modifier
                    .padding(12.dp)
                    .verticalScroll(rememberScrollState())
            ) {
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
                            if (clip.isEmpty()) return@FilledTonalButton
                            if (confirmMultilinePaste && clip.contains('\n')) {
                                pendingPaste = clip
                                showPasteConfirm = true
                            } else {
                                onPasteRaw(clip)
                            }
                        },
                        enabled = attachState.connected,
                        colors = zagoraTonalButtonColors()
                    ) { Text("Paste->Shell") }
                }
                Spacer(Modifier.height(8.dp))
                AnimatedVisibility(visible = extraKeysVisible) {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(
                            modifier = Modifier.horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            FilledTonalButton(onClick = onSendEsc, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("ESC") }
                            FilledTonalButton(onClick = onSendTab, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("TAB") }
                            FilledTonalButton(
                                onClick = onToggleStickyCtrl,
                                enabled = attachState.connected,
                                colors = if (stickyCtrl) zagoraPrimaryButtonColors() else zagoraTonalButtonColors()
                            ) { Text("CTRL*") }
                            FilledTonalButton(
                                onClick = onToggleStickyAlt,
                                enabled = attachState.connected,
                                colors = if (stickyAlt) zagoraPrimaryButtonColors() else zagoraTonalButtonColors()
                            ) { Text("ALT*") }
                            FilledTonalButton(onClick = onSendArrowLeft, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("←") }
                            FilledTonalButton(onClick = onSendArrowDown, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("↓") }
                            FilledTonalButton(onClick = onSendArrowUp, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("↑") }
                            FilledTonalButton(onClick = onSendArrowRight, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("→") }
                        }
                        Row(
                            modifier = Modifier.horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            FilledTonalButton(onClick = onSendPageUp, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("PGUP") }
                            FilledTonalButton(onClick = onSendPageDown, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("PGDN") }
                            FilledTonalButton(onClick = onSendHome, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("HOME") }
                            FilledTonalButton(onClick = onSendEnd, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("END") }
                            FilledTonalButton(onClick = { clipboard.setText(AnnotatedString(renderedTerminal)) }, colors = zagoraTonalButtonColors()) { Text("COPY") }
                            FilledTonalButton(
                                onClick = {
                                    val clip = clipboard.getText()?.text?.toString().orEmpty()
                                    if (clip.isNotBlank()) onPasteRaw(clip)
                                },
                                enabled = attachState.connected,
                                colors = zagoraTonalButtonColors()
                            ) { Text("PASTE") }
                            FilledTonalButton(onClick = onSendShiftTab, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("S-TAB") }
                            FilledTonalButton(onClick = onDisconnect, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("DETACH") }
                        }
                    }
                }
            }
        }

        if (showPasteConfirm) {
            AlertDialog(
                onDismissRequest = { showPasteConfirm = false },
                title = { Text("Paste confirmation") },
                text = { Text("Clipboard has multiple lines. Paste to remote shell?") },
                confirmButton = {
                    Button(
                        onClick = {
                            onPasteRaw(pendingPaste)
                            pendingPaste = ""
                            showPasteConfirm = false
                        },
                        colors = zagoraPrimaryButtonColors()
                    ) { Text("Paste") }
                },
                dismissButton = {
                    TextButton(onClick = { showPasteConfirm = false }, colors = zagoraDangerTextButtonColors()) {
                        Text("Cancel")
                    }
                }
            )
        }
    }
}

private fun phaseLabel(phase: com.followcat.zagora.data.AttachPhase): String = when (phase) {
    com.followcat.zagora.data.AttachPhase.Idle -> "Idle"
    com.followcat.zagora.data.AttachPhase.Connecting -> "Connecting"
    com.followcat.zagora.data.AttachPhase.Attaching -> "Attaching"
    com.followcat.zagora.data.AttachPhase.Connected -> "Connected"
    com.followcat.zagora.data.AttachPhase.Reconnecting -> "Reconnecting"
    com.followcat.zagora.data.AttachPhase.Disconnected -> "Disconnected"
    com.followcat.zagora.data.AttachPhase.Error -> "Error"
}

private fun phaseColor(phase: com.followcat.zagora.data.AttachPhase): Color = when (phase) {
    com.followcat.zagora.data.AttachPhase.Connected -> Color(0xFF34D399)
    com.followcat.zagora.data.AttachPhase.Connecting,
    com.followcat.zagora.data.AttachPhase.Attaching,
    com.followcat.zagora.data.AttachPhase.Reconnecting -> Color(0xFF38BDF8)
    com.followcat.zagora.data.AttachPhase.Error -> Color(0xFFFCA5A5)
    com.followcat.zagora.data.AttachPhase.Disconnected -> Color(0xFF94A3B8)
    com.followcat.zagora.data.AttachPhase.Idle -> Color(0xFF94A3B8)
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
