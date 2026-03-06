package com.followcat.zagora.ui

import android.graphics.Typeface
import android.os.Looper
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
import androidx.compose.foundation.text.BasicTextField
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
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.followcat.zagora.data.SettingsStore
import com.followcat.zagora.model.Session
import com.followcat.zagora.util.openInExternalSshApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.connectbot.terminal.ModifierManager
import org.connectbot.terminal.Terminal as ConnectBotTerminal
import org.connectbot.terminal.TerminalEmulatorFactory
import java.net.HttpURLConnection
import java.net.URL

private enum class MobileScreen {
    Sessions,
    Settings
}

// Temporary kill-switch: some devices still crash inside termlib renderer path.
// Keep attach usable via fallback renderer until we finish device-specific stabilization.
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
                incomingBytes = attachVm.incomingBytes,
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
                onSendTextRaw = { txt -> attachVm.sendTextRaw(txt) },
                onSendRawBytes = { bytes -> attachVm.sendRaw(bytes) },
                onResizeTerminal = { cols, rows, pxWidth, pxHeight ->
                    attachVm.resizeTerminal(cols, rows, pxWidth, pxHeight)
                },
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
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
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
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
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
                    SettingsChoiceGroup(
                        title = "Terminal font",
                        subtitle = localFontPack.title
                    ) {
                        SingleChoiceSegmentedButtonRow(
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            SegmentedButton(
                                modifier = Modifier.weight(1f),
                                selected = localFontPack == TerminalFontPack.System,
                                onClick = { localFontPack = TerminalFontPack.System },
                                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 3)
                            ) { Text("Sys", maxLines = 1) }
                            SegmentedButton(
                                modifier = Modifier.weight(1f),
                                selected = localFontPack == TerminalFontPack.JetBrains,
                                onClick = { localFontPack = TerminalFontPack.JetBrains },
                                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 3)
                            ) { Text("JB", maxLines = 1) }
                            SegmentedButton(
                                modifier = Modifier.weight(1f),
                                selected = localFontPack == TerminalFontPack.JetBrainsNerd,
                                onClick = { localFontPack = TerminalFontPack.JetBrainsNerd },
                                shape = SegmentedButtonDefaults.itemShape(index = 2, count = 3)
                            ) { Text("Nerd", maxLines = 1) }
                        }
                    }
                    SettingsChoiceGroup(
                        title = "Theme style",
                        subtitle = localThemeVariant.title
                    ) {
                        SingleChoiceSegmentedButtonRow(
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            SegmentedButton(
                                modifier = Modifier.weight(1f),
                                selected = localThemeVariant == ZagoraThemeVariant.Neon,
                                onClick = { localThemeVariant = ZagoraThemeVariant.Neon },
                                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                            ) { Text("A", maxLines = 1) }
                            SegmentedButton(
                                modifier = Modifier.weight(1f),
                                selected = localThemeVariant == ZagoraThemeVariant.Graphite,
                                onClick = { localThemeVariant = ZagoraThemeVariant.Graphite },
                                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                            ) { Text("B", maxLines = 1) }
                        }
                    }
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
private fun SettingsChoiceGroup(
    title: String,
    subtitle: String,
    content: @Composable () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .animateContentSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = title,
                color = MaterialTheme.colorScheme.onSurface,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = subtitle,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        content()
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

private fun _shortLabelTime(raw: String): String {
    val s = raw.trim().replace("T", " ")
    return if (s.length >= 16) s.substring(5, 16) else s
}

@Composable
internal fun terminalColorPalette(): TerminalColorPalette = TerminalColorPalette(
    defaultForeground = MaterialTheme.colorScheme.onBackground,
    defaultBackground = MaterialTheme.colorScheme.background
)

@Composable
internal fun zagoraScreenBrush(): Brush = Brush.verticalGradient(
    0f to MaterialTheme.colorScheme.background,
    0.45f to MaterialTheme.colorScheme.surface.copy(alpha = 0.98f),
    1f to MaterialTheme.colorScheme.surfaceContainer.copy(alpha = 0.96f)
)

@Composable
internal fun zagoraFieldColors() = OutlinedTextFieldDefaults.colors(
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
internal fun zagoraPrimaryButtonColors() = ButtonDefaults.buttonColors(
    containerColor = MaterialTheme.colorScheme.primary,
    contentColor = MaterialTheme.colorScheme.onPrimary,
    disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
    disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant
)

@Composable
internal fun zagoraTonalButtonColors() = ButtonDefaults.filledTonalButtonColors(
    containerColor = MaterialTheme.colorScheme.surfaceVariant,
    contentColor = MaterialTheme.colorScheme.onSurface,
    disabledContainerColor = MaterialTheme.colorScheme.surface,
    disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant
)

@Composable
internal fun zagoraDangerTextButtonColors() = ButtonDefaults.textButtonColors(
    contentColor = MaterialTheme.colorScheme.error,
    disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant
)
