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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.IconButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
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
import kotlinx.coroutines.delay

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
    val ok = Color(0xFF10B981)
    val warn = Color(0xFFF59E0B)

    LaunchedEffect(reconnectPolicy) {
        attachVm.setReconnectPolicy(reconnectPolicy)
    }
    LaunchedEffect(screen, server, token) {
        if (screen == MobileScreen.Sessions && server.isNotBlank()) {
            vm.loadSessions(server, token, "")
        }
    }

    MaterialTheme {
        val bgModifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(colors = listOf(topBg, bottomBg)))
        if (attachTarget != null) {
            val savedSessionSsh = store.loadSessionSsh(attachTarget!!.host, attachTarget!!.name)
            Box(modifier = bgModifier) {
                AttachScreen(
                    target = attachTarget!!,
                    attachState = attachState,
                    initialUser = savedSessionSsh.first.ifBlank { sshUser },
                    initialPassword = savedSessionSsh.second,
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
                        store.saveSessionSsh(
                            host = attachTarget!!.host,
                            session = attachTarget!!.name,
                            sshUser = user,
                            sshPassword = password
                        )
                    },
                    onDisconnect = { attachVm.disconnect() },
                    onSendCtrlC = { attachVm.sendCtrlC() },
                    onSendTab = { attachVm.sendTab() },
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
                    serverConfigured = server.isNotBlank(),
                    hostFilter = hostFilter,
                    scopeFilter = scopeFilter,
                    onScopeFilterChange = { scopeFilter = it },
                    onHostFilterChange = { hostFilter = it },
                    onRefresh = { vm.loadSessions(server, token, "") },
                    onGoSettings = { screen = MobileScreen.Settings },
                    onAttachSession = { session ->
                        attachVm.disconnect()
                        attachTarget = session
                    },
                    onOpenSsh = { session -> openInExternalSshApp(ctx, session.host, sshUser) },
                    onDelete = { session -> vm.deleteSession(server, token, session) },
                    okColor = ok,
                    warnColor = warn
                )
                MobileScreen.Settings -> SettingsScreen(
                    server = server,
                    token = token,
                    sshUser = sshUser,
                    terminalFontSize = terminalFontSizePref,
                    confirmMultilinePaste = confirmMultilinePaste,
                    reconnectPolicy = reconnectPolicy,
                    onBack = { screen = MobileScreen.Sessions },
                    onChange = { newServer, newToken, newUser, newFont, newConfirm, newPolicy ->
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
@OptIn(ExperimentalMaterial3Api::class)
private fun SessionsScreen(
    ui: UiState,
    sessions: List<Session>,
    serverConfigured: Boolean,
    hostFilter: String,
    scopeFilter: SessionScopeFilter,
    onScopeFilterChange: (SessionScopeFilter) -> Unit,
    onHostFilterChange: (String) -> Unit,
    onRefresh: () -> Unit,
    onGoSettings: () -> Unit,
    onAttachSession: (Session) -> Unit,
    onOpenSsh: (Session) -> Unit,
    onDelete: (Session) -> Unit,
    okColor: Color,
    warnColor: Color
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val pullState = rememberPullToRefreshState()

    LaunchedEffect(ui.message) {
        if (ui.message.isNotBlank()) {
            snackbarHostState.showSnackbar(ui.message)
        }
    }

    val screenState = remember(serverConfigured, ui.loading, ui.message, sessions) {
        when {
            !serverConfigured -> "ConfigMissing"
            ui.loading -> "Loading"
            ui.message.contains("failed", ignoreCase = true) || ui.message.contains("error", ignoreCase = true) -> "Error"
            sessions.isEmpty() -> "Empty"
            else -> "Ready"
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Sessions") },
                actions = {
                    FilledTonalButton(onClick = onRefresh, colors = zagoraTonalButtonColors()) { Text("↻") }
                    FilledTonalButton(onClick = onGoSettings, colors = zagoraTonalButtonColors()) { Text("⚙") }
                }
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
    ) { innerPadding ->
        PullToRefreshBox(
            isRefreshing = ui.loading,
            onRefresh = onRefresh,
            state = pullState,
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (!serverConfigured) {
                    item {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = Color(0xFF1E293B)
                        ) {
                            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("未配置 server，请先去 Settings。", color = Color(0xFFE2E8F0))
                                FilledTonalButton(onClick = onGoSettings, colors = zagoraTonalButtonColors()) { Text("Go Settings") }
                            }
                        }
                    }
                }
                item {
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = hostFilter,
                        onValueChange = onHostFilterChange,
                        label = { Text("Search by session / host") },
                        singleLine = true,
                        colors = zagoraFieldColors()
                    )
                }
                item {
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
                }
                item { HorizontalDivider(color = Color(0xFF334155)) }
                if (screenState == "Empty") {
                    item {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = Color(0xFF0F172A)
                        ) {
                            Text("No sessions", modifier = Modifier.padding(12.dp), color = Color(0xFFCBD5E1))
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
    onChange: (String, String, String, Float, Boolean, String) -> Unit
) {
    var localServer by remember { mutableStateOf(server) }
    var localToken by remember { mutableStateOf(token) }
    var localUser by remember { mutableStateOf(sshUser) }
    var localFont by remember { mutableStateOf(terminalFontSize) }
    var localConfirm by remember { mutableStateOf(confirmMultilinePaste) }
    var localPolicy by remember { mutableStateOf(reconnectPolicy) }
    LaunchedEffect(localServer, localToken, localUser, localFont, localConfirm, localPolicy) {
        onChange(localServer, localToken, localUser, localFont, localConfirm, localPolicy)
    }

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
                    Text("Auto-saved", color = Color(0xFF94A3B8), style = MaterialTheme.typography.labelMedium)
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

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun AttachScreen(
    target: Session,
    attachState: com.followcat.zagora.data.AttachState,
    initialUser: String,
    initialPassword: String,
    onBack: () -> Unit,
    onConnect: (String, String) -> Unit,
    onDisconnect: () -> Unit,
    onSendCtrlC: () -> Unit,
    onSendTab: () -> Unit,
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
    var password by remember(target.host, target.name) { mutableStateOf(initialPassword) }
    var showCredentialsDialog by remember(target.host, target.name) { mutableStateOf(false) }
    var extraKeysVisible by remember(target.host, target.name) { mutableStateOf(true) }
    var terminalFontSize by remember(target.host, target.name, initialFontSize) { mutableStateOf(initialFontSize) }
    var showPasteConfirm by remember(target.host, target.name) { mutableStateOf(false) }
    var pendingPaste by remember(target.host, target.name) { mutableStateOf("") }
    var menuExpanded by remember(target.host, target.name) { mutableStateOf(false) }
    var followOutput by remember(target.host, target.name) { mutableStateOf(true) }
    var selectionMode by remember(target.host, target.name) { mutableStateOf(false) }
    var showGestureHint by remember(target.host, target.name) { mutableStateOf(true) }
    val outputScroll = rememberScrollState()
    val outputXScroll = rememberScrollState()
    val clipboard = LocalClipboardManager.current
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
    LaunchedEffect(showGestureHint) {
        if (showGestureHint) {
            delay(2500)
            showGestureHint = false
        }
    }
    LaunchedEffect(target.host, target.name) {
        if (user.isBlank()) {
            showCredentialsDialog = true
        }
    }
    val connState = remember(attachState.phase, attachState.message) {
        when (attachState.phase) {
            com.followcat.zagora.data.AttachPhase.Idle -> ConnState.Idle
            com.followcat.zagora.data.AttachPhase.Connecting,
            com.followcat.zagora.data.AttachPhase.Attaching -> ConnState.Connecting
            com.followcat.zagora.data.AttachPhase.Connected -> ConnState.Connected
            com.followcat.zagora.data.AttachPhase.Reconnecting -> ConnState.Reconnecting(attempt = 0)
            com.followcat.zagora.data.AttachPhase.Disconnected,
            com.followcat.zagora.data.AttachPhase.Error -> ConnState.Disconnected(attachState.message)
        }
    }
    val terminalState = remember(
        attachState.phase,
        followOutput,
        selectionMode,
        terminalFontSize,
        attachState.rawBytesIn,
        attachState.rawBytesOut,
        stickyCtrl,
        stickyAlt
    ) {
        TerminalUiState(
            hostLabel = target.host,
            sessionName = target.name,
            conn = connState,
            follow = followOutput,
            selectionMode = selectionMode,
            fontSizeSp = terminalFontSize.toInt(),
            inBytes = attachState.rawBytesIn,
            outBytes = attachState.rawBytesOut,
            stickyCtrl = stickyCtrl,
            stickyAlt = stickyAlt
        )
    }

    Scaffold(
        topBar = {
            Surface(color = Color(0xFF0B1220).copy(alpha = 0.96f)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilledTonalButton(onClick = onBack, colors = zagoraTonalButtonColors()) { Text("Back") }
                    Text(
                        text = "${terminalState.hostLabel} · ${terminalState.sessionName}",
                        color = Color(0xFFF8FAFC),
                        fontWeight = FontWeight.SemiBold
                    )
                    StatusBadge(phaseLabel(attachState.phase), phaseColor(attachState.phase))
                    FilledTonalButton(
                        onClick = { menuExpanded = true },
                        colors = zagoraTonalButtonColors()
                    ) { Text("⋯") }
                }
            }
        },
        bottomBar = {
            AnimatedVisibility(visible = extraKeysVisible) {
                Surface(color = Color(0xFF0B1220).copy(alpha = 0.95f)) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp, vertical = 6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
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
                            ) { Text("PASTE") }
                            FilledTonalButton(onClick = onDisconnect, enabled = attachState.connected, colors = zagoraTonalButtonColors()) { Text("DETACH") }
                        }
                    }
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                shape = RoundedCornerShape(10.dp),
                color = Color(0xFF020617).copy(alpha = 0.97f)
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    SelectionContainer {
                        Text(
                            text = terminalAnnotated,
                        modifier = Modifier
                            .fillMaxSize()
                            .combinedClickable(
                                onClick = { showGestureHint = false },
                                onLongClick = {
                                    selectionMode = true
                                    showGestureHint = false
                                }
                            )
                            .verticalScroll(outputScroll)
                            .horizontalScroll(outputXScroll)
                            .padding(horizontal = 10.dp, vertical = 8.dp),
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
                    .align(Alignment.TopEnd)
                    .padding(10.dp),
                shape = RoundedCornerShape(999.dp),
                color = Color(0xFF111827).copy(alpha = 0.8f)
            ) {
                Text(
                    text = "in:${terminalState.inBytes} out:${terminalState.outBytes}",
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    color = Color(0xFFCBD5E1),
                    style = MaterialTheme.typography.labelSmall
                )
            }

            if (showGestureHint) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = if (extraKeysVisible) 70.dp else 12.dp),
                    shape = RoundedCornerShape(999.dp),
                    color = Color(0xFF0B1220).copy(alpha = 0.85f)
                ) {
                    Text(
                        text = "Tap to focus · Long press to select",
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        color = Color(0xFFCBD5E1),
                        style = MaterialTheme.typography.labelMedium
                    )
                }
            }

            if (terminalState.conn is ConnState.Connecting || terminalState.conn is ConnState.Reconnecting) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 10.dp),
                    shape = RoundedCornerShape(999.dp),
                    color = Color(0xFF0E7490).copy(alpha = 0.85f)
                ) {
                    Text(
                        text = attachState.message.ifBlank { "Connecting..." },
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        color = Color(0xFFE0F2FE)
                    )
                }
            }

            if (terminalState.conn is ConnState.Disconnected && attachState.message.isNotBlank()) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .padding(16.dp),
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFF111827).copy(alpha = 0.95f)
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text("Disconnected", color = Color(0xFFF8FAFC), fontWeight = FontWeight.Bold)
                        Text(attachState.message, color = Color(0xFFCBD5E1))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { onConnect(user.trim(), password) },
                                colors = zagoraPrimaryButtonColors()
                            ) { Text("Retry") }
                            FilledTonalButton(onClick = onBack, colors = zagoraTonalButtonColors()) { Text("Back") }
                        }
                    }
                }
            }
        }
    }

    DropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
        DropdownMenuItem(text = { Text("Session") }, enabled = false, onClick = {})
        DropdownMenuItem(
            text = { Text("SSH Credentials") },
            onClick = {
                showCredentialsDialog = true
                menuExpanded = false
            }
        )
        DropdownMenuItem(text = { Text("Terminal") }, enabled = false, onClick = {})
        DropdownMenuItem(
            text = { Text(if (followOutput) "Follow: ON" else "Follow: OFF") },
            onClick = {
                followOutput = !followOutput
                menuExpanded = false
            }
        )
        DropdownMenuItem(
            text = { Text("Selection Mode") },
            onClick = {
                selectionMode = !selectionMode
                menuExpanded = false
            }
        )
        DropdownMenuItem(
            text = { Text("A-") },
            onClick = {
                terminalFontSize = (terminalFontSize - 1f).coerceAtLeast(11f)
                menuExpanded = false
            }
        )
        DropdownMenuItem(
            text = { Text("A+") },
            onClick = {
                terminalFontSize = (terminalFontSize + 1f).coerceAtMost(18f)
                menuExpanded = false
            }
        )
        DropdownMenuItem(text = { Text("Control") }, enabled = false, onClick = {})
        DropdownMenuItem(
            text = { Text("Send Ctrl+C") },
            onClick = {
                onSendCtrlC()
                menuExpanded = false
            }
        )
        DropdownMenuItem(text = { Text("Connection") }, enabled = false, onClick = {})
        DropdownMenuItem(
            text = { Text("Reconnect") },
            onClick = {
                onConnect(user.trim(), password)
                menuExpanded = false
            }
        )
        DropdownMenuItem(
            text = { Text(if (extraKeysVisible) "Hide Keys" else "Show Keys") },
            onClick = {
                extraKeysVisible = !extraKeysVisible
                menuExpanded = false
            }
        )
        DropdownMenuItem(
            text = { Text("Detach") },
            onClick = {
                onDisconnect()
                menuExpanded = false
            }
        )
    }

    if (showCredentialsDialog) {
        AlertDialog(
            onDismissRequest = { showCredentialsDialog = false },
            title = { Text("SSH Credentials") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = user,
                        onValueChange = { user = it },
                        label = { Text("SSH user") },
                        singleLine = true,
                        colors = zagoraFieldColors()
                    )
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("SSH password (optional)") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        colors = zagoraFieldColors()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        onConnect(user.trim(), password)
                        showCredentialsDialog = false
                    },
                    enabled = !attachState.connecting,
                    colors = zagoraPrimaryButtonColors()
                ) { Text(if (attachState.connecting) "Connecting..." else "Connect + Attach") }
            },
            dismissButton = {
                TextButton(onClick = { showCredentialsDialog = false }, colors = zagoraDangerTextButtonColors()) {
                    Text("Cancel")
                }
            }
        )
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
