package com.followcat.zagora.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.animation.animateContentSize
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.foundation.layout.isImeVisible
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.followcat.zagora.data.SettingsStore
import com.followcat.zagora.model.Session
import com.followcat.zagora.util.openInExternalSshApp
import android.util.Log
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.connectbot.terminal.Terminal
import org.connectbot.terminal.TerminalEmulatorFactory
import java.net.HttpURLConnection
import java.net.URL

private enum class MobileScreen {
    Sessions,
    Settings
}

// Temporary kill-switch: some devices still crash inside termlib renderer path.
// Keep attach usable via fallback renderer until we finish device-specific stabilization.
private const val ENABLE_TERMLIB_RENDERER = false

@Composable
fun ZagoraApp(
    vm: MainViewModel = viewModel(),
    attachVm: AttachViewModel = viewModel(),
    themeVariant: ZagoraThemeVariant = ZagoraThemeVariant.Neon,
    onThemeVariantChange: (ZagoraThemeVariant) -> Unit = {}
) {
    val ctx = LocalContext.current
    val store = remember { SettingsStore(ctx) }
    val uiScope = rememberCoroutineScope()
    val ui by vm.uiState.collectAsState()
    val attachState by attachVm.state.collectAsState()
    val sticky by attachVm.sticky.collectAsState()

    var server by remember { mutableStateOf(store.loadServer()) }
    var token by remember { mutableStateOf(store.loadToken()) }
    var hostFilter by remember { mutableStateOf("") }
    var sshUser by remember { mutableStateOf(store.loadSshUser()) }
    var terminalFontSizePref by remember { mutableStateOf(store.loadTerminalFontSize()) }
    var terminalFontPackPref by remember { mutableStateOf(TerminalFontPack.fromId(store.loadTerminalFontPack())) }
    var confirmMultilinePaste by remember { mutableStateOf(store.loadConfirmMultilinePaste()) }
    var reconnectPolicy by remember { mutableStateOf(store.loadReconnectPolicy()) }
    var screen by remember { mutableStateOf(MobileScreen.Sessions) }
    var attachTarget by remember { mutableStateOf<Session?>(null) }

    LaunchedEffect(reconnectPolicy) {
        attachVm.setReconnectPolicy(reconnectPolicy)
    }
    LaunchedEffect(screen, server, token) {
        if (screen == MobileScreen.Sessions && server.isNotBlank()) {
            vm.loadSessions(server, token, "")
        }
    }

    if (attachTarget != null) {
        val savedSessionSsh = store.loadSessionSsh(attachTarget!!.host, attachTarget!!.name)
        Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
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
                onSendRaw = { bytes -> attachVm.sendRaw(bytes) },
                onPasteRaw = { txt -> attachVm.pasteRaw(txt) },
                onResizeTerminal = { cols, rows, pxWidth, pxHeight ->
                    attachVm.resizeTerminal(cols, rows, pxWidth, pxHeight)
                },
                incomingBytes = attachVm.incomingBytes,
                stickyCtrl = sticky.ctrl,
                stickyAlt = sticky.alt,
                onToggleStickyCtrl = { attachVm.toggleStickyCtrl() },
                onToggleStickyAlt = { attachVm.toggleStickyAlt() },
                initialFontSize = terminalFontSizePref,
                terminalFontPack = terminalFontPackPref,
                confirmMultilinePaste = confirmMultilinePaste,
                onAppBackground = { attachVm.onAppBackground() },
                onAppForeground = { attachVm.onAppForeground() }
            )
        }
    } else {
        when (screen) {
            MobileScreen.Sessions -> SessionsScreen(
                ui = ui,
                sessions = ui.sessions.filter { s ->
                    if (hostFilter.isBlank()) true
                    else s.name.contains(hostFilter, ignoreCase = true) || s.host.contains(hostFilter, ignoreCase = true)
                },
                serverConfigured = server.isNotBlank(),
                hostFilter = hostFilter,
                onHostFilterChange = { hostFilter = it },
                onRefresh = { vm.loadSessions(server, token, "") },
                onGoSettings = { screen = MobileScreen.Settings },
                onCreateSession = { name, host ->
                    if (server.isBlank()) return@SessionsScreen
                    uiScope.launch {
                        val result = vm.createSession(server, token, name, host)
                        result.getOrNull()?.let { created ->
                            attachVm.disconnect()
                            attachTarget = created
                        }
                    }
                },
                onAttachSession = { session ->
                    attachVm.disconnect()
                    attachTarget = session
                },
                onOpenSsh = { session -> openInExternalSshApp(ctx, session.host, sshUser) },
                onDelete = { session ->
                    val (savedUser, savedPass) = store.loadSessionSsh(session.host, session.name)
                    val killUser = savedUser.ifBlank { sshUser }
                    vm.deleteSession(server, token, session, killUser, savedPass)
                }
            )
            MobileScreen.Settings -> SettingsScreen(
                server = server,
                token = token,
                sshUser = sshUser,
                terminalFontSize = terminalFontSizePref,
                terminalFontPack = terminalFontPackPref,
                confirmMultilinePaste = confirmMultilinePaste,
                reconnectPolicy = reconnectPolicy,
                themeVariant = themeVariant,
                onBack = { screen = MobileScreen.Sessions },
                onChange = { newServer, newToken, newUser, newFont, newFontPack, newConfirm, newPolicy, newThemeVariant ->
                    server = newServer
                    token = newToken
                    sshUser = newUser
                    terminalFontSizePref = newFont
                    terminalFontPackPref = newFontPack
                    confirmMultilinePaste = newConfirm
                    reconnectPolicy = newPolicy
                    onThemeVariantChange(newThemeVariant)
                    attachVm.setReconnectPolicy(reconnectPolicy)
                    store.save(server, token, sshUser)
                    store.saveThemeVariant(newThemeVariant.id)
                    store.saveTerminalPrefs(
                        fontSize = terminalFontSizePref,
                        confirmMultilinePaste = confirmMultilinePaste,
                        reconnectPolicy = reconnectPolicy,
                        terminalFontPack = terminalFontPackPref.id
                    )
                }
            )
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
    onHostFilterChange: (String) -> Unit,
    onRefresh: () -> Unit,
    onGoSettings: () -> Unit,
    onCreateSession: (name: String, host: String) -> Unit,
    onAttachSession: (Session) -> Unit,
    onOpenSsh: (Session) -> Unit,
    onDelete: (Session) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    val snackbarHostState = remember { SnackbarHostState() }
    val pullState = rememberPullToRefreshState()
    var showCreateSheet by remember { mutableStateOf(false) }
    var newSessionName by remember { mutableStateOf("") }
    var newSessionHost by remember { mutableStateOf("") }
    val knownHosts = remember(sessions) {
        sessions.map { it.host.trim() }.filter { it.isNotBlank() }.distinct()
    }

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
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                    navigationIconContentColor = MaterialTheme.colorScheme.onSurface,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurface
                ),
                actions = {
                    IconButton(onClick = onRefresh) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Refresh sessions",
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    IconButton(onClick = onGoSettings) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Open settings",
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    if (!serverConfigured) return@FloatingActionButton
                    if (newSessionHost.isBlank()) {
                        newSessionHost = knownHosts.firstOrNull().orEmpty()
                    }
                    showCreateSheet = true
                },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary
            ) {
                Text("New")
            }
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
                    .background(zagoraScreenBrush())
                    .padding(horizontal = ZagoraSpacing.page, vertical = ZagoraSpacing.item),
                verticalArrangement = Arrangement.spacedBy(ZagoraSpacing.compact)
            ) {
                if (!serverConfigured) {
                    item {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(ZagoraRadius.card),
                            color = MaterialTheme.colorScheme.surfaceContainerHigh,
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
                        ) {
                            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("未配置 server，请先去 Settings。", color = MaterialTheme.colorScheme.onSurface)
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
                item { HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant) }
                if (screenState == "Empty") {
                    item {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(ZagoraRadius.card),
                            color = MaterialTheme.colorScheme.surfaceContainer
                        ) {
                            Text("No sessions", modifier = Modifier.padding(12.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
                items(sessions) { session ->
                    SessionRow(
                        session = session,
                        onAttach = { onAttachSession(session) },
                        onOpenSsh = { onOpenSsh(session) },
                        onDelete = { onDelete(session) },
                        onCopy = {
                            clipboard.setText(AnnotatedString("${session.name}@${session.host}"))
                        }
                    )
                }
            }
        }

        if (showCreateSheet) {
            ModalBottomSheet(
                onDismissRequest = { showCreateSheet = false },
                containerColor = MaterialTheme.colorScheme.surface
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("New Session", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                    OutlinedTextField(
                        value = newSessionName,
                        onValueChange = { newSessionName = it },
                        label = { Text("Session name") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        colors = zagoraFieldColors()
                    )
                    OutlinedTextField(
                        value = newSessionHost,
                        onValueChange = { newSessionHost = it },
                        label = { Text("Host") },
                        singleLine = true,
                        placeholder = { Text(knownHosts.firstOrNull() ?: "e.g. v100") },
                        modifier = Modifier.fillMaxWidth(),
                        colors = zagoraFieldColors()
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 12.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        CompactTonalButton(
                            text = "Cancel",
                            onClick = { showCreateSheet = false }
                        )
                        CompactFilledButton(
                            text = "Open",
                            onClick = {
                                val name = newSessionName.trim()
                                val host = newSessionHost.trim().ifBlank { knownHosts.firstOrNull().orEmpty() }
                                if (name.isBlank() || host.isBlank()) return@CompactFilledButton
                                onCreateSession(name, host)
                                showCreateSheet = false
                                newSessionName = ""
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
private fun SettingsScreen(
    server: String,
    token: String,
    sshUser: String,
    terminalFontSize: Float,
    terminalFontPack: TerminalFontPack,
    confirmMultilinePaste: Boolean,
    reconnectPolicy: String,
    themeVariant: ZagoraThemeVariant,
    onBack: () -> Unit,
    onChange: (String, String, String, Float, TerminalFontPack, Boolean, String, ZagoraThemeVariant) -> Unit
) {
    var localServer by remember { mutableStateOf(server) }
    var localToken by remember { mutableStateOf(token) }
    var localUser by remember { mutableStateOf(sshUser) }
    var localFont by remember { mutableStateOf(terminalFontSize) }
    var localFontPack by remember(terminalFontPack) { mutableStateOf(terminalFontPack) }
    var localConfirm by remember { mutableStateOf(confirmMultilinePaste) }
    var localPolicy by remember { mutableStateOf(reconnectPolicy) }
    var localThemeVariant by remember(themeVariant) { mutableStateOf(themeVariant) }
    var tokenVisible by remember { mutableStateOf(false) }
    var testingConnection by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(localServer, localToken, localUser, localFont, localFontPack, localConfirm, localPolicy, localThemeVariant) {
        onChange(localServer, localToken, localUser, localFont, localFontPack, localConfirm, localPolicy, localThemeVariant)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                    navigationIconContentColor = MaterialTheme.colorScheme.onSurface,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurface
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            )
        },
        snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(zagoraScreenBrush())
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(ZagoraSpacing.page),
            verticalArrangement = Arrangement.spacedBy(ZagoraSpacing.page)
        ) {
            ElevatedCard(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(ZagoraRadius.card),
                colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Server", color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleMedium)
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
                        label = { Text("Bearer Token (optional)") },
                        singleLine = true,
                        visualTransformation = if (tokenVisible) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            TextButton(onClick = { tokenVisible = !tokenVisible }) {
                                Text(if (tokenVisible) "Hide" else "Show")
                            }
                        },
                        colors = zagoraFieldColors()
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        CompactTonalButton(
                            text = if (testingConnection) "Testing..." else "Test Connection",
                            onClick = {
                                scope.launch {
                                    if (localServer.isBlank()) {
                                        snackbarHostState.showSnackbar("Base URL is empty")
                                        return@launch
                                    }
                                    testingConnection = true
                                    val (ok, detail) = probeHealth(localServer, localToken)
                                    testingConnection = false
                                    snackbarHostState.showSnackbar(
                                        if (ok) "Connection OK ($detail)" else "Connection failed ($detail)"
                                    )
                                }
                            },
                            enabled = !testingConnection
                        )
                    }
                }
            }

            ElevatedCard(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(ZagoraRadius.card),
                colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("SSH", color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = localUser,
                        onValueChange = { localUser = it },
                        label = { Text("Default SSH User") },
                        singleLine = true,
                        colors = zagoraFieldColors()
                    )
                }
            }

            ElevatedCard(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(ZagoraRadius.card),
                colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Terminal", color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleMedium)
                    ListItem(
                        colors = zagoraListItemColors(),
                        headlineContent = { Text("Font size", color = MaterialTheme.colorScheme.onSurface) },
                        supportingContent = { Text("${localFont.toInt()}sp", color = MaterialTheme.colorScheme.onSurfaceVariant) },
                        trailingContent = {
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                                CompactTonalButton(
                                    text = "A-",
                                    onClick = { localFont = (localFont - 1f).coerceAtLeast(11f) },
                                )
                                CompactTonalButton(
                                    text = "A+",
                                    onClick = { localFont = (localFont + 1f).coerceAtMost(18f) },
                                )
                            }
                        }
                    )
                    ListItem(
                        colors = zagoraListItemColors(),
                        headlineContent = { Text("Paste confirm", color = MaterialTheme.colorScheme.onSurface) },
                        supportingContent = { Text("Confirm before multi-line paste", color = MaterialTheme.colorScheme.onSurfaceVariant) },
                        trailingContent = {
                            Switch(
                                checked = localConfirm,
                                onCheckedChange = { localConfirm = it }
                            )
                        }
                    )
                    ListItem(
                        colors = zagoraListItemColors(),
                        headlineContent = { Text("Terminal font", color = MaterialTheme.colorScheme.onSurface) },
                        supportingContent = { Text(localFontPack.title, color = MaterialTheme.colorScheme.onSurfaceVariant) },
                        trailingContent = {
                            SingleChoiceSegmentedButtonRow {
                                SegmentedButton(
                                    selected = localFontPack == TerminalFontPack.System,
                                    onClick = { localFontPack = TerminalFontPack.System },
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 3)
                                ) { Text("Sys") }
                                SegmentedButton(
                                    selected = localFontPack == TerminalFontPack.JetBrains,
                                    onClick = { localFontPack = TerminalFontPack.JetBrains },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 3)
                                ) { Text("JB") }
                                SegmentedButton(
                                    selected = localFontPack == TerminalFontPack.JetBrainsNerd,
                                    onClick = { localFontPack = TerminalFontPack.JetBrainsNerd },
                                    shape = SegmentedButtonDefaults.itemShape(index = 2, count = 3)
                                ) { Text("Nerd") }
                            }
                        }
                    )
                    ListItem(
                        colors = zagoraListItemColors(),
                        headlineContent = { Text("Theme style", color = MaterialTheme.colorScheme.onSurface) },
                        supportingContent = { Text(localThemeVariant.title, color = MaterialTheme.colorScheme.onSurfaceVariant) },
                        trailingContent = {
                            SingleChoiceSegmentedButtonRow {
                                SegmentedButton(
                                    selected = localThemeVariant == ZagoraThemeVariant.Neon,
                                    onClick = { localThemeVariant = ZagoraThemeVariant.Neon },
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                                ) { Text("A") }
                                SegmentedButton(
                                    selected = localThemeVariant == ZagoraThemeVariant.Graphite,
                                    onClick = { localThemeVariant = ZagoraThemeVariant.Graphite },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                                ) { Text("B") }
                            }
                        }
                    )
                }
            }

            ElevatedCard(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(ZagoraRadius.card),
                colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Connection", color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleMedium)
                    Text("Reconnect policy", color = MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.bodyMedium)
                    SingleChoiceSegmentedButtonRow {
                        SegmentedButton(
                            selected = localPolicy == "manual",
                            onClick = { localPolicy = "manual" },
                            shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                        ) {
                            Text("Manual")
                        }
                        SegmentedButton(
                            selected = localPolicy == "auto3",
                            onClick = { localPolicy = "auto3" },
                            shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                        ) {
                            Text("Auto")
                        }
                    }
                }
            }

            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(ZagoraRadius.card),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.92f)
            ) {
                Text(
                    "Auto-saved",
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.labelMedium
                )
            }
        }
    }
}

@Composable
private fun zagoraListItemColors() = androidx.compose.material3.ListItemDefaults.colors(
    containerColor = Color.Transparent
)

private suspend fun probeHealth(baseUrl: String, token: String): Pair<Boolean, String> = withContext(Dispatchers.IO) {
    val normalizedBase = baseUrl.trim().trimEnd('/')
    if (normalizedBase.isBlank()) return@withContext false to "empty url"
    val healthUrl = "$normalizedBase/health"
    return@withContext runCatching {
        val conn = (URL(healthUrl).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 3000
            readTimeout = 3000
            if (token.isNotBlank()) setRequestProperty("Authorization", "Bearer ${token.trim()}")
        }
        conn.useCaches = false
        val code = conn.responseCode
        conn.disconnect()
        if (code in 200..299) true to "$code" else false to "$code"
    }.getOrElse { false to (it.message ?: "request error") }
}

@Composable
private fun SessionRow(
    session: Session,
    onAttach: () -> Unit,
    onOpenSsh: () -> Unit,
    onDelete: () -> Unit,
    onCopy: () -> Unit
) {
    var menuExpanded by remember(session.host, session.name) { mutableStateOf(false) }
    var showDeleteConfirm by remember(session.host, session.name) { mutableStateOf(false) }

    val statusColor = if (session.status.equals("running", ignoreCase = true)) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.tertiary
    }
    val statusText = session.status.ifBlank { "unknown" }
    val seenAgo = session.lastSeen?.takeIf { it.isNotBlank() }?.let { " · ${_shortLabelTime(it)}" }.orEmpty()

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .animateContentSize()
            .clickable(onClick = onAttach),
        shape = RoundedCornerShape(ZagoraRadius.card),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.40f)),
        tonalElevation = 1.dp
    ) {
        ListItem(
            colors = zagoraListItemColors(),
            headlineContent = {
                Text(session.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            },
            supportingContent = {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .background(statusColor, CircleShape)
                    )
                    Text(
                        "${session.host} · $statusText$seenAgo",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            },
            trailingContent = {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    CompactFilledButton(
                        text = "Attach",
                        onClick = onAttach,
                        enabled = true,
                        heightDp = 32
                    )
                    Box {
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(
                                imageVector = Icons.Default.MoreVert,
                                contentDescription = "Session actions",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text("Open SSH") },
                                onClick = {
                                    menuExpanded = false
                                    onOpenSsh()
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Copy") },
                                onClick = {
                                    menuExpanded = false
                                    onCopy()
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Remove") },
                                onClick = {
                                    menuExpanded = false
                                    showDeleteConfirm = true
                                }
                            )
                        }
                    }
                }
            }
        )
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text("Remove session") },
            text = { Text("Kill remote session and remove ${session.name} from registry?") },
            confirmButton = {
                CompactFilledButton(
                    text = "Remove",
                    onClick = {
                        showDeleteConfirm = false
                        onDelete()
                    }
                )
            },
            dismissButton = {
                CompactTonalButton(text = "Cancel", onClick = { showDeleteConfirm = false })
            }
        )
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

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
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
    onSendRaw: (ByteArray) -> Unit,
    onPasteRaw: (String) -> Unit,
    onResizeTerminal: (Int, Int, Int, Int) -> Unit,
    incomingBytes: SharedFlow<ByteArray>,
    stickyCtrl: Boolean,
    stickyAlt: Boolean,
    onToggleStickyCtrl: () -> Unit,
    onToggleStickyAlt: () -> Unit,
    initialFontSize: Float,
    terminalFontPack: TerminalFontPack,
    confirmMultilinePaste: Boolean,
    onAppBackground: () -> Unit,
    onAppForeground: () -> Unit
) {
    val lifecycleOwner = LocalLifecycleOwner.current
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
    var showTransientStats by remember(target.host, target.name) { mutableStateOf(false) }
    var suppressAutoReconnect by remember(target.host, target.name) { mutableStateOf(false) }
    var termlibInitError by remember(target.host, target.name) { mutableStateOf<String?>(null) }
    val outputScroll = rememberScrollState()
    val outputScrollX = rememberScrollState()
    val clipboard = LocalClipboardManager.current
    val imeVisible = WindowInsets.isImeVisible
    val terminalFocusRequester = remember(target.host, target.name) { FocusRequester() }
    val density = LocalDensity.current
    val defaultForeground = MaterialTheme.colorScheme.onBackground
    val defaultBackground = MaterialTheme.colorScheme.background
    val term = if (ENABLE_TERMLIB_RENDERER) {
        remember(target.host, target.name) {
            runCatching {
                TerminalEmulatorFactory.create(
                    initialRows = 24,
                    initialCols = 64,
                    defaultForeground = defaultForeground,
                    defaultBackground = defaultBackground,
                    onKeyboardInput = { bytes -> onSendRaw(bytes) },
                    onResize = { dim -> onResizeTerminal(dim.columns, dim.rows, 0, 0) }
                )
            }.onFailure { err ->
                termlibInitError = err.message ?: err::class.simpleName
                Log.e("ZagoraAttach", "Failed to init termlib terminal", err)
            }.getOrNull()
        }
    } else {
        termlibInitError = "termlib disabled (temporary safe mode)"
        null
    }
    var terminalViewportPx by remember(target.host, target.name) { mutableStateOf(IntSize.Zero) }
    var lastAppliedGrid by remember(target.host, target.name) { mutableStateOf(IntSize(0, 0)) }
    var renderedTerminal by remember(target.host, target.name) { mutableStateOf("# waiting for shell output...") }
    val requestIme: () -> Unit = {
        terminalFocusRequester.requestFocus()
    }

    val manualDetach: () -> Unit = {
        suppressAutoReconnect = true
        onDisconnect()
    }

    DisposableEffect(lifecycleOwner, target.host, target.name) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> onAppBackground()
                Lifecycle.Event.ON_RESUME -> onAppForeground()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    LaunchedEffect(incomingBytes, target.host, target.name) {
        incomingBytes.collect { chunk ->
            if (chunk.isNotEmpty() && term != null) {
                term.writeInput(chunk, 0, chunk.size)
            }
        }
    }

    LaunchedEffect(terminalViewportPx, terminalFontSize, extraKeysVisible) {
        if (terminalViewportPx.width <= 0 || terminalViewportPx.height <= 0) return@LaunchedEffect
        val viewportWidth = terminalViewportPx.width.toFloat().coerceAtLeast(1f)
        val viewportHeight = terminalViewportPx.height.toFloat().coerceAtLeast(1f)
        val horizontalPaddingPx = with(density) { 20.dp.toPx() }
        val verticalPaddingPx = with(density) { if (extraKeysVisible) 12.dp.toPx() else 8.dp.toPx() }
        val availableWidth = (viewportWidth - horizontalPaddingPx).coerceAtLeast(1f)
        val availableHeight = (viewportHeight - verticalPaddingPx).coerceAtLeast(1f)
        val charWidthPx = with(density) { (terminalFontSize.sp.toPx() * 0.66f).coerceAtLeast(6f) }
        val lineHeightPx = with(density) { ((terminalFontSize + 5f).sp.toPx()).coerceAtLeast(10f) }
        val rawCols = (availableWidth / charWidthPx).toInt().coerceAtLeast(1)
        val rawRows = (availableHeight / lineHeightPx).toInt().coerceAtLeast(1)
        // Keep emulator grid and remote PTY size in the same realistic range for phones.
        val cols = rawCols.coerceIn(20, 240)
        val rows = rawRows.coerceIn(8, 120)
        val grid = IntSize(cols, rows)
        if (grid == lastAppliedGrid) return@LaunchedEffect
        lastAppliedGrid = grid
        term?.resize(rows, cols)
        onResizeTerminal(cols, rows, terminalViewportPx.width, terminalViewportPx.height)
    }
    LaunchedEffect(attachState.output) {
        renderedTerminal = attachState.output.takeLast(120_000)
    }
    LaunchedEffect(attachState.output, followOutput, term) {
        if (term == null && followOutput) {
            outputScroll.scrollTo(outputScroll.maxValue)
        }
    }
    LaunchedEffect(showGestureHint) {
        if (showGestureHint) {
            delay(2500)
            showGestureHint = false
        }
    }
    LaunchedEffect(attachState.rawBytesIn, attachState.rawBytesOut) {
        val hasTraffic = attachState.rawBytesIn > 0 || attachState.rawBytesOut > 0
        if (!hasTraffic) return@LaunchedEffect
        showTransientStats = true
        delay(2000)
        showTransientStats = false
    }
    LaunchedEffect(attachState.phase, attachState.message, user, password) {
        if (attachState.phase != com.followcat.zagora.data.AttachPhase.Disconnected) return@LaunchedEffect
        if (!attachState.message.contains("Detached", ignoreCase = true)) return@LaunchedEffect
        if (suppressAutoReconnect) {
            suppressAutoReconnect = false
            return@LaunchedEffect
        }
        delay(500)
        onConnect(user.trim(), password)
    }
    LaunchedEffect(target.host, target.name) {
        if (user.isBlank()) {
            showCredentialsDialog = true
        }
        delay(120)
        requestIme()
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
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                    navigationIconContentColor = MaterialTheme.colorScheme.onSurface,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurface
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    }
                },
                title = {
                    Text(
                        text = "${terminalState.hostLabel} · ${terminalState.sessionName}",
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.SemiBold
                    )
                },
                actions = {
                    Row(
                        modifier = Modifier.padding(end = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        val phaseDotColor by animateColorAsState(
                            targetValue = phaseColor(attachState.phase),
                            label = "phaseDotColor"
                        )
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .background(phaseDotColor, CircleShape)
                        )
                        Text(
                            text = phaseLabel(attachState.phase),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.labelMedium
                        )
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(
                                imageVector = Icons.Default.MoreVert,
                                contentDescription = "Menu",
                                tint = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            )
        },
        bottomBar = {
            AnimatedVisibility(visible = extraKeysVisible && !imeVisible) {
                Surface(color = MaterialTheme.colorScheme.surface.copy(alpha = 0.95f)) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 6.dp, vertical = 4.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Row(
                            modifier = Modifier.horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            KeyPill(label = "ESC", enabled = attachState.connected, onClick = onSendEsc)
                            KeyPill(label = "TAB", enabled = attachState.connected, onClick = onSendTab)
                            KeyPill(
                                label = "CTRL*",
                                latched = stickyCtrl,
                                enabled = attachState.connected,
                                onClick = onToggleStickyCtrl
                            )
                            KeyPill(
                                label = "ALT*",
                                latched = stickyAlt,
                                enabled = attachState.connected,
                                onClick = onToggleStickyAlt
                            )
                            KeyPill(label = "←", enabled = attachState.connected, onClick = onSendArrowLeft)
                            KeyPill(label = "↓", enabled = attachState.connected, onClick = onSendArrowDown)
                            KeyPill(label = "↑", enabled = attachState.connected, onClick = onSendArrowUp)
                            KeyPill(label = "→", enabled = attachState.connected, onClick = onSendArrowRight)
                        }
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            item { KeyPill(label = "PGUP", enabled = attachState.connected, onClick = onSendPageUp) }
                            item { KeyPill(label = "PGDN", enabled = attachState.connected, onClick = onSendPageDown) }
                            item { KeyPill(label = "HOME", enabled = attachState.connected, onClick = onSendHome) }
                            item { KeyPill(label = "END", enabled = attachState.connected, onClick = onSendEnd) }
                            item { KeyPill(label = "KB", onClick = requestIme) }
                            item { KeyPill(label = "COPY", onClick = { clipboard.setText(AnnotatedString(renderedTerminal)) }) }
                            item {
                                KeyPill(
                                    label = "PASTE",
                                    enabled = attachState.connected,
                                    onClick = {
                                        val clip = clipboard.getText()?.text?.toString().orEmpty()
                                        if (clip.isEmpty()) return@KeyPill
                                        if (confirmMultilinePaste && clip.contains('\n')) {
                                            pendingPaste = clip
                                            showPasteConfirm = true
                                        } else {
                                            onPasteRaw(clip)
                                        }
                                    }
                                )
                            }
                            item { KeyPill(label = "DETACH", enabled = attachState.connected, onClick = manualDetach) }
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
                .imePadding()
                .background(zagoraScreenBrush())
        ) {
            BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
                if (term != null) {
                    Terminal(
                        terminalEmulator = term,
                        modifier = Modifier
                            .fillMaxSize()
                            .onSizeChanged { terminalViewportPx = it }
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        initialFontSize = terminalFontSize.sp,
                        minFontSize = 10.sp,
                        maxFontSize = 22.sp,
                        backgroundColor = MaterialTheme.colorScheme.background,
                        foregroundColor = MaterialTheme.colorScheme.onBackground,
                        keyboardEnabled = true,
                        focusRequester = terminalFocusRequester,
                        onTerminalTap = {
                            showGestureHint = false
                            terminalFocusRequester.requestFocus()
                        }
                    )
                } else {
                    SelectionContainer {
                        Text(
                            text = renderedTerminal.ifBlank { "# waiting for shell output..." },
                            modifier = Modifier
                                .fillMaxSize()
                                .onSizeChanged { terminalViewportPx = it }
                                .horizontalScroll(outputScrollX)
                                .verticalScroll(outputScroll)
                                .padding(horizontal = 10.dp, vertical = 8.dp),
                            color = MaterialTheme.colorScheme.onBackground,
                            fontSize = terminalFontSize.sp,
                            lineHeight = (terminalFontSize + 6f).sp,
                            softWrap = false
                        )
                    }
                }
            }

            if (termlibInitError != null) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 10.dp),
                    shape = RoundedCornerShape(999.dp),
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.9f)
                ) {
                    Text(
                        text = "Terminal fallback mode: $termlibInitError",
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        style = MaterialTheme.typography.labelMedium
                    )
                }
            }

            AnimatedVisibility(
                visible = showTransientStats,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(10.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(999.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.8f)
                ) {
                    Text(
                        text = "in:${terminalState.inBytes} out:${terminalState.outBytes}",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        color = MaterialTheme.colorScheme.onSurface,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }

            if (showGestureHint) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = if (extraKeysVisible && !imeVisible) 70.dp else 12.dp),
                    shape = RoundedCornerShape(999.dp),
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.85f)
                ) {
                    Text(
                        text = "Tap to focus · Long press to select",
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
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
                    color = MaterialTheme.colorScheme.primary.copy(alpha = 0.85f)
                ) {
                    Text(
                        text = attachState.message.ifBlank { "Connecting..." },
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                }
            }

            if (terminalState.conn is ConnState.Disconnected && attachState.message.isNotBlank()) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .padding(ZagoraSpacing.page),
                    shape = RoundedCornerShape(ZagoraRadius.card),
                    color = MaterialTheme.colorScheme.surfaceContainer.copy(alpha = 0.95f),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text("Disconnected", color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Bold)
                        Text(attachState.message, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            CompactFilledButton(
                                text = "Retry",
                                onClick = { onConnect(user.trim(), password) }
                            )
                            CompactTonalButton(text = "Back", onClick = onBack)
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
            text = { Text("Traffic in:${terminalState.inBytes} out:${terminalState.outBytes}") },
            enabled = false,
            onClick = {}
        )
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
                manualDetach()
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

@Composable
private fun CompactFilledButton(
    text: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    heightDp: Int = 40,
    modifier: Modifier = Modifier
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.height(heightDp.dp),
        shape = RoundedCornerShape(ZagoraRadius.field),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
        colors = zagoraPrimaryButtonColors()
    ) {
        Text(text, fontSize = 13.sp)
    }
}

@Composable
private fun CompactTonalButton(
    text: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    heightDp: Int = 40,
    modifier: Modifier = Modifier
) {
    FilledTonalButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.height(heightDp.dp),
        shape = RoundedCornerShape(ZagoraRadius.field),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
        colors = zagoraTonalButtonColors()
    ) {
        Text(text, fontSize = 13.sp)
    }
}

@Composable
private fun KeyPill(
    label: String,
    enabled: Boolean = true,
    latched: Boolean = false,
    onClick: () -> Unit
) {
    val bg = when {
        !enabled -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
        latched -> MaterialTheme.colorScheme.primary.copy(alpha = 0.22f)
        else -> MaterialTheme.colorScheme.surfaceVariant
    }
    val fg = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant
    Surface(
        modifier = Modifier
            .height(34.dp)
            .clickable(enabled = enabled, onClick = onClick),
        shape = RoundedCornerShape(ZagoraRadius.field),
        color = bg
    ) {
        Box(
            modifier = Modifier.padding(horizontal = 10.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(label, color = fg, fontSize = 11.sp)
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

@Composable
private fun phaseColor(phase: com.followcat.zagora.data.AttachPhase): Color = when (phase) {
    com.followcat.zagora.data.AttachPhase.Connected -> MaterialTheme.colorScheme.primary
    com.followcat.zagora.data.AttachPhase.Connecting,
    com.followcat.zagora.data.AttachPhase.Attaching,
    com.followcat.zagora.data.AttachPhase.Reconnecting -> MaterialTheme.colorScheme.tertiary
    com.followcat.zagora.data.AttachPhase.Error -> MaterialTheme.colorScheme.error
    com.followcat.zagora.data.AttachPhase.Disconnected -> MaterialTheme.colorScheme.onSurfaceVariant
    com.followcat.zagora.data.AttachPhase.Idle -> MaterialTheme.colorScheme.onSurfaceVariant
}

private fun _shortLabelTime(raw: String): String {
    val s = raw.trim().replace("T", " ")
    return if (s.length >= 16) s.substring(5, 16) else s
}

@Composable
private fun terminalColorPalette(): TerminalColorPalette = TerminalColorPalette(
    defaultForeground = MaterialTheme.colorScheme.onBackground,
    defaultBackground = MaterialTheme.colorScheme.background
)

@Composable
private fun zagoraScreenBrush(): Brush = Brush.verticalGradient(
    0f to MaterialTheme.colorScheme.background,
    0.45f to MaterialTheme.colorScheme.surface.copy(alpha = 0.98f),
    1f to MaterialTheme.colorScheme.surfaceContainer.copy(alpha = 0.96f)
)

@Composable
private fun zagoraFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = MaterialTheme.colorScheme.onSurface,
    unfocusedTextColor = MaterialTheme.colorScheme.onSurface,
    focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainer,
    cursorColor = MaterialTheme.colorScheme.primary,
    focusedBorderColor = MaterialTheme.colorScheme.primary,
    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.75f),
    focusedLabelColor = MaterialTheme.colorScheme.primary,
    unfocusedLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
    focusedPlaceholderColor = MaterialTheme.colorScheme.onSurfaceVariant,
    unfocusedPlaceholderColor = MaterialTheme.colorScheme.onSurfaceVariant
)

@Composable
private fun zagoraPrimaryButtonColors() = ButtonDefaults.buttonColors(
    containerColor = MaterialTheme.colorScheme.primary,
    contentColor = MaterialTheme.colorScheme.onPrimary,
    disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
    disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant
)

@Composable
private fun zagoraTonalButtonColors() = ButtonDefaults.filledTonalButtonColors(
    containerColor = MaterialTheme.colorScheme.surfaceVariant,
    contentColor = MaterialTheme.colorScheme.onSurface,
    disabledContainerColor = MaterialTheme.colorScheme.surface,
    disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant
)

@Composable
private fun zagoraDangerTextButtonColors() = ButtonDefaults.textButtonColors(
    contentColor = MaterialTheme.colorScheme.error,
    disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant
)
