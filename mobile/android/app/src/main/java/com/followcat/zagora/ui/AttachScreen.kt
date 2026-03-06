package com.followcat.zagora.ui

import android.graphics.Typeface
import android.os.Looper
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.followcat.zagora.data.AttachPhase
import com.followcat.zagora.data.AttachState
import com.followcat.zagora.model.Session
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharedFlow
import org.connectbot.terminal.ModifierManager
import org.connectbot.terminal.Terminal as ConnectBotTerminal
import org.connectbot.terminal.TerminalEmulatorFactory

@OptIn(ExperimentalFoundationApi::class, ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
internal fun AttachScreen(
    target: Session,
    attachState: AttachState,
    incomingBytes: SharedFlow<ByteArray>,
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
    onSendTextRaw: (String) -> Unit,
    onSendRawBytes: (ByteArray) -> Unit,
    onResizeTerminal: (Int, Int, Int, Int) -> Unit,
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
    var didInitialConnect by remember(target.host, target.name) { mutableStateOf(false) }
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
    val outputScroll = rememberScrollState()
    val outputScrollX = rememberScrollState()
    val clipboard = LocalClipboardManager.current
    val keyboardController = LocalSoftwareKeyboardController.current
    val imeVisible = WindowInsets.isImeVisible
    val density = LocalDensity.current
    val inputFocusRequester = remember(target.host, target.name) { FocusRequester() }
    val fallbackTerm = remember(target.host, target.name) { TerminalEmulator(cols = 64, rows = 24) }
    val terminalPalette = terminalColorPalette()
    val terminalTypefaceFamily = remember(terminalFontPack) { terminalFontFamily(terminalFontPack) }
    val termlibTerminal = remember(target.host, target.name) {
        runCatching {
            TerminalEmulatorFactory.Companion.create(
                Looper.getMainLooper(),
                24,
                64,
                terminalPalette.defaultForeground,
                terminalPalette.defaultBackground,
                { bytes ->
                    if (bytes.isNotEmpty()) onSendRawBytes(bytes)
                },
                {},
                null,
                { copied ->
                    if (copied.isNotBlank()) {
                        clipboard.setText(AnnotatedString(copied))
                    }
                },
                null
            )
        }.getOrNull()
    }
    val useFallbackTerminal = termlibTerminal == null
    var terminalViewportPx by remember(target.host, target.name) { mutableStateOf(IntSize.Zero) }
    var lastAppliedGrid by remember(target.host, target.name) { mutableStateOf(IntSize(0, 0)) }
    var processedLen by remember(target.host, target.name) { mutableStateOf(0) }
    var renderedTerminal by remember(target.host, target.name) { mutableStateOf("# waiting for shell output...") }
    var hiddenInput by remember(target.host, target.name) { mutableStateOf(TextFieldValue("")) }
    val requestIme: () -> Unit = {
        inputFocusRequester.requestFocus()
        keyboardController?.show()
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

    LaunchedEffect(attachState.output, useFallbackTerminal) {
        if (!useFallbackTerminal) return@LaunchedEffect
        val out = attachState.output
        if (out.length < processedLen) {
            fallbackTerm.reset()
            processedLen = 0
            renderedTerminal = "# waiting for shell output..."
        }
        if (out.length > processedLen) {
            val delta = out.substring(processedLen)
            fallbackTerm.feed(delta)
            processedLen = out.length
            renderedTerminal = fallbackTerm.renderText().ifBlank { "# waiting for shell output..." }
        }
    }

    val terminalAnnotated = remember(renderedTerminal, terminalPalette) {
        fallbackTerm.renderAnnotated(terminalPalette)
    }
    LaunchedEffect(termlibTerminal, incomingBytes) {
        val terminal = termlibTerminal ?: return@LaunchedEffect
        incomingBytes.collect { bytes ->
            if (bytes.isNotEmpty()) {
                terminal.writeInput(bytes, 0, bytes.size)
            }
        }
    }

    LaunchedEffect(terminalViewportPx, terminalFontSize, extraKeysVisible, termlibTerminal, useFallbackTerminal) {
        if (terminalViewportPx.width <= 0 || terminalViewportPx.height <= 0) return@LaunchedEffect
        val viewportWidth = terminalViewportPx.width.toFloat().coerceAtLeast(1f)
        val viewportHeight = terminalViewportPx.height.toFloat().coerceAtLeast(1f)
        val horizontalPaddingPx = with(density) { 20.dp.toPx() }
        val verticalPaddingPx = with(density) { if (extraKeysVisible) 12.dp.toPx() else 8.dp.toPx() }
        val availableWidth = (viewportWidth - horizontalPaddingPx).coerceAtLeast(1f)
        val availableHeight = (viewportHeight - verticalPaddingPx).coerceAtLeast(1f)
        val charWidthPx = with(density) { (terminalFontSize.sp.toPx() * 0.66f).coerceAtLeast(6f) }
        val lineHeightPx = with(density) { ((terminalFontSize + 5f).sp.toPx()).coerceAtLeast(10f) }
        val cols = (availableWidth / charWidthPx).toInt().coerceAtLeast(1).coerceIn(20, 240)
        val rows = (availableHeight / lineHeightPx).toInt().coerceAtLeast(1).coerceIn(8, 120)
        val grid = IntSize(cols, rows)
        if (grid == lastAppliedGrid) return@LaunchedEffect
        lastAppliedGrid = grid
        if (useFallbackTerminal) {
            fallbackTerm.resize(cols, rows)
        } else {
            termlibTerminal?.resize(rows, cols)
        }
        onResizeTerminal(cols, rows, terminalViewportPx.width, terminalViewportPx.height)
    }
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
    LaunchedEffect(attachState.rawBytesIn, attachState.rawBytesOut) {
        val hasTraffic = attachState.rawBytesIn > 0 || attachState.rawBytesOut > 0
        if (!hasTraffic) return@LaunchedEffect
        showTransientStats = true
        delay(2000)
        showTransientStats = false
    }
    LaunchedEffect(attachState.phase) {
        if (attachState.phase == AttachPhase.Disconnected && suppressAutoReconnect) {
            suppressAutoReconnect = false
        }
    }
    LaunchedEffect(target.host, target.name) {
        if (user.isBlank()) {
            showCredentialsDialog = true
            didInitialConnect = true
        } else if (!didInitialConnect) {
            didInitialConnect = true
            onConnect(user.trim(), password)
        }
        delay(120)
        requestIme()
    }

    val connState = remember(attachState.phase, attachState.message) {
        when (attachState.phase) {
            AttachPhase.Idle -> ConnState.Idle
            AttachPhase.Connecting, AttachPhase.Attaching -> ConnState.Connecting
            AttachPhase.Connected -> ConnState.Connected
            AttachPhase.Reconnecting -> ConnState.Reconnecting(attempt = 0)
            AttachPhase.Disconnected, AttachPhase.Error -> ConnState.Disconnected(attachState.message)
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
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = MaterialTheme.colorScheme.onSurface)
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
                        val phaseDotColor by animateColorAsState(targetValue = phaseColor(attachState.phase), label = "phaseDotColor")
                        Box(Modifier.size(8.dp).background(phaseDotColor, CircleShape))
                        Text(phaseLabel(attachState.phase), color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelMedium)
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = "Menu", tint = MaterialTheme.colorScheme.onSurface)
                        }
                    }
                }
            )
        },
        bottomBar = {
            AnimatedVisibility(visible = extraKeysVisible && !imeVisible) {
                AttachExtraKeysBar(
                    attachState = attachState,
                    stickyCtrl = stickyCtrl,
                    stickyAlt = stickyAlt,
                    copyText = if (useFallbackTerminal) renderedTerminal else attachState.output,
                    clipboardText = clipboard.getText()?.text?.toString().orEmpty(),
                    confirmMultilinePaste = confirmMultilinePaste,
                    onSendEsc = onSendEsc,
                    onSendTab = onSendTab,
                    onToggleStickyCtrl = onToggleStickyCtrl,
                    onToggleStickyAlt = onToggleStickyAlt,
                    onSendArrowLeft = onSendArrowLeft,
                    onSendArrowDown = onSendArrowDown,
                    onSendArrowUp = onSendArrowUp,
                    onSendArrowRight = onSendArrowRight,
                    onSendPageUp = onSendPageUp,
                    onSendPageDown = onSendPageDown,
                    onSendHome = onSendHome,
                    onSendEnd = onSendEnd,
                    onRequestIme = requestIme,
                    onCopy = { text -> clipboard.setText(AnnotatedString(text)) },
                    onPaste = { text ->
                        if (confirmMultilinePaste && text.contains('\n')) {
                            pendingPaste = text
                            showPasteConfirm = true
                        } else {
                            onPasteRaw(text)
                        }
                    },
                    onDetach = manualDetach
                )
            }
        }
    ) { innerPadding ->
        AttachTerminalScaffoldBody(
            attachState = attachState,
            terminalState = terminalState,
            innerPadding = innerPadding,
            imeVisible = imeVisible,
            extraKeysVisible = extraKeysVisible,
            showGestureHint = showGestureHint,
            showTransientStats = showTransientStats,
            terminalViewportPx = terminalViewportPx,
            onViewportChange = { terminalViewportPx = it },
            terminalFontSize = terminalFontSize,
            terminalTypefaceFamily = terminalTypefaceFamily,
            terminalPalette = terminalPalette,
            terminalAnnotated = terminalAnnotated,
            renderedTerminal = renderedTerminal,
            useFallbackTerminal = useFallbackTerminal,
            termlibTerminal = termlibTerminal,
            outputScrollX = outputScrollX,
            outputScroll = outputScroll,
            inputFocusRequester = inputFocusRequester,
            hiddenInput = hiddenInput,
            onHiddenInputChange = { next ->
                val text = next.text
                if (text.isNotEmpty()) {
                    onSendTextRaw(text)
                    hiddenInput = TextFieldValue("")
                } else {
                    hiddenInput = next
                }
            },
            onRequestIme = requestIme,
            onSendArrowLeft = onSendArrowLeft,
            onSendArrowDown = onSendArrowDown,
            onSendArrowUp = onSendArrowUp,
            onSendArrowRight = onSendArrowRight,
            onSendPageUp = onSendPageUp,
            onSendPageDown = onSendPageDown,
            onPasteText = { text ->
                if (confirmMultilinePaste && text.contains('\n')) {
                    pendingPaste = text
                    showPasteConfirm = true
                } else {
                    onPasteRaw(text)
                }
            },
            clipboardText = clipboard.getText()?.text?.toString().orEmpty(),
            stickyCtrl = stickyCtrl,
            stickyAlt = stickyAlt,
            onToggleStickyCtrl = onToggleStickyCtrl,
            onToggleStickyAlt = onToggleStickyAlt,
            onSendEsc = onSendEsc,
            onSendTab = onSendTab,
            onDisconnect = manualDetach,
            onRetry = { onConnect(user.trim(), password) },
            onBack = onBack,
            onSendTextRaw = onSendTextRaw
        )
    }

    AttachOverflowMenu(
        expanded = menuExpanded,
        attachState = attachState,
        terminalState = terminalState,
        extraKeysVisible = extraKeysVisible,
        followOutput = followOutput,
        onDismiss = { menuExpanded = false },
        onShowCredentials = { showCredentialsDialog = true },
        onToggleFollow = { followOutput = !followOutput },
        onToggleSelection = { selectionMode = !selectionMode },
        onFontDown = { terminalFontSize = (terminalFontSize - 1f).coerceAtLeast(11f) },
        onFontUp = { terminalFontSize = (terminalFontSize + 1f).coerceAtMost(18f) },
        onSendCtrlC = onSendCtrlC,
        onReconnect = { onConnect(user.trim(), password) },
        onToggleKeys = { extraKeysVisible = !extraKeysVisible },
        onDetach = manualDetach
    )

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
private fun AttachExtraKeysBar(
    attachState: AttachState,
    stickyCtrl: Boolean,
    stickyAlt: Boolean,
    copyText: String,
    clipboardText: String,
    confirmMultilinePaste: Boolean,
    onSendEsc: () -> Unit,
    onSendTab: () -> Unit,
    onToggleStickyCtrl: () -> Unit,
    onToggleStickyAlt: () -> Unit,
    onSendArrowLeft: () -> Unit,
    onSendArrowDown: () -> Unit,
    onSendArrowUp: () -> Unit,
    onSendArrowRight: () -> Unit,
    onSendPageUp: () -> Unit,
    onSendPageDown: () -> Unit,
    onSendHome: () -> Unit,
    onSendEnd: () -> Unit,
    onRequestIme: () -> Unit,
    onCopy: (String) -> Unit,
    onPaste: (String) -> Unit,
    onDetach: () -> Unit
) {
    Surface(color = MaterialTheme.colorScheme.surface.copy(alpha = 0.95f)) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 6.dp, vertical = 4.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Row(modifier = Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                KeyPill(label = "ESC", enabled = attachState.connected, onClick = onSendEsc)
                KeyPill(label = "TAB", enabled = attachState.connected, onClick = onSendTab)
                KeyPill(label = "CTRL*", latched = stickyCtrl, enabled = attachState.connected, onClick = onToggleStickyCtrl)
                KeyPill(label = "ALT*", latched = stickyAlt, enabled = attachState.connected, onClick = onToggleStickyAlt)
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
                item { KeyPill(label = "KB", onClick = onRequestIme) }
                item { KeyPill(label = "COPY", onClick = { onCopy(copyText) }) }
                item {
                    KeyPill(
                        label = "PASTE",
                        enabled = attachState.connected,
                        onClick = {
                            if (clipboardText.isNotEmpty()) {
                                onPaste(clipboardText)
                            }
                        }
                    )
                }
                item { KeyPill(label = "DETACH", enabled = attachState.connected, onClick = onDetach) }
            }
        }
    }
}

@Composable
private fun AttachTerminalScaffoldBody(
    attachState: AttachState,
    terminalState: TerminalUiState,
    innerPadding: PaddingValues,
    imeVisible: Boolean,
    extraKeysVisible: Boolean,
    showGestureHint: Boolean,
    showTransientStats: Boolean,
    terminalViewportPx: IntSize,
    onViewportChange: (IntSize) -> Unit,
    terminalFontSize: Float,
    terminalTypefaceFamily: androidx.compose.ui.text.font.FontFamily,
    terminalPalette: TerminalColorPalette,
    terminalAnnotated: AnnotatedString,
    renderedTerminal: String,
    useFallbackTerminal: Boolean,
    termlibTerminal: org.connectbot.terminal.TerminalEmulator?,
    outputScrollX: androidx.compose.foundation.ScrollState,
    outputScroll: androidx.compose.foundation.ScrollState,
    inputFocusRequester: FocusRequester,
    hiddenInput: TextFieldValue,
    onHiddenInputChange: (TextFieldValue) -> Unit,
    onRequestIme: () -> Unit,
    onSendArrowLeft: () -> Unit,
    onSendArrowDown: () -> Unit,
    onSendArrowUp: () -> Unit,
    onSendArrowRight: () -> Unit,
    onSendPageUp: () -> Unit,
    onSendPageDown: () -> Unit,
    onPasteText: (String) -> Unit,
    clipboardText: String,
    stickyCtrl: Boolean,
    stickyAlt: Boolean,
    onToggleStickyCtrl: () -> Unit,
    onToggleStickyAlt: () -> Unit,
    onSendEsc: () -> Unit,
    onSendTab: () -> Unit,
    onDisconnect: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    onSendTextRaw: (String) -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
            .background(zagoraScreenBrush())
    ) {
        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            Box(modifier = Modifier.fillMaxSize().clickable { onRequestIme() }) {
                if (useFallbackTerminal) {
                    SelectionContainer {
                        Text(
                            text = terminalAnnotated,
                            modifier = Modifier
                                .fillMaxSize()
                                .onSizeChanged(onViewportChange)
                                .horizontalScroll(outputScrollX)
                                .verticalScroll(outputScroll)
                                .padding(horizontal = 10.dp, vertical = 8.dp),
                            color = MaterialTheme.colorScheme.onBackground,
                            fontFamily = terminalTypefaceFamily,
                            fontSize = terminalFontSize.sp,
                            lineHeight = (terminalFontSize + 6f).sp,
                            softWrap = false
                        )
                    }
                } else {
                    ConnectBotTerminal(
                        terminalEmulator = termlibTerminal!!,
                        modifier = Modifier.fillMaxSize().onSizeChanged(onViewportChange).padding(horizontal = 8.dp, vertical = 6.dp),
                        typeface = Typeface.MONOSPACE,
                        initialFontSize = terminalFontSize.sp,
                        minFontSize = 10.sp,
                        maxFontSize = 22.sp,
                        backgroundColor = terminalPalette.defaultBackground,
                        foregroundColor = terminalPalette.defaultForeground,
                        keyboardEnabled = false,
                        showSoftKeyboard = false,
                        focusRequester = inputFocusRequester,
                        onTerminalTap = onRequestIme,
                        onImeVisibilityChanged = {},
                        forcedSize = null,
                        modifierManager = remember(stickyCtrl, stickyAlt) {
                            object : ModifierManager {
                                override fun isCtrlActive(): Boolean = stickyCtrl
                                override fun isAltActive(): Boolean = stickyAlt
                                override fun isShiftActive(): Boolean = false
                                override fun clearTransients() = Unit
                            }
                        },
                        onSelectionControllerAvailable = {},
                        onHyperlinkClick = {},
                        onComposeControllerAvailable = {}
                    )
                }
                BasicTextField(
                    value = hiddenInput,
                    onValueChange = onHiddenInputChange,
                    modifier = Modifier
                        .size(1.dp)
                        .align(Alignment.BottomStart)
                        .focusRequester(inputFocusRequester)
                        .onPreviewKeyEvent { event ->
                            if (event.type != KeyEventType.KeyDown) return@onPreviewKeyEvent false
                            when (event.key) {
                                Key.Backspace -> {
                                    onSendTextRaw("\u007f")
                                    true
                                }
                                Key.Enter -> {
                                    onSendTextRaw("\n")
                                    true
                                }
                                else -> false
                            }
                        },
                    textStyle = MaterialTheme.typography.bodySmall.copy(color = Color.Transparent),
                    cursorBrush = Brush.verticalGradient(listOf(Color.Transparent, Color.Transparent))
                )
            }
        }

        AnimatedVisibility(visible = showTransientStats && !imeVisible, modifier = Modifier.align(Alignment.TopEnd).padding(10.dp)) {
            Surface(shape = RoundedCornerShape(999.dp), color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.8f)) {
                Text(
                    text = "in:${terminalState.inBytes} out:${terminalState.outBytes}",
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    color = MaterialTheme.colorScheme.onSurface,
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }

        if (showGestureHint && !imeVisible) {
            Surface(
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = if (extraKeysVisible && !imeVisible) 70.dp else 12.dp),
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

        if ((terminalState.conn is ConnState.Connecting || terminalState.conn is ConnState.Reconnecting) && !imeVisible) {
            Surface(
                modifier = Modifier.align(Alignment.TopCenter).padding(top = 10.dp),
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
                    .align(if (imeVisible) Alignment.TopCenter else Alignment.Center)
                    .padding(
                        top = if (imeVisible) 12.dp else ZagoraSpacing.page,
                        start = ZagoraSpacing.page,
                        end = ZagoraSpacing.page,
                        bottom = ZagoraSpacing.page
                    ),
                shape = RoundedCornerShape(ZagoraRadius.card),
                color = MaterialTheme.colorScheme.surfaceContainer.copy(alpha = 0.95f),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
            ) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Disconnected", color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Bold)
                    Text(attachState.message, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CompactFilledButton(text = "Retry", onClick = onRetry)
                        CompactTonalButton(text = "Back", onClick = onBack)
                    }
                }
            }
        }

        AnimatedVisibility(visible = extraKeysVisible && imeVisible, modifier = Modifier.align(Alignment.BottomCenter).imePadding()) {
            Surface(color = MaterialTheme.colorScheme.surface.copy(alpha = 0.96f), tonalElevation = 4.dp, shadowElevation = 6.dp) {
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 6.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    KeyPill(label = "ESC", enabled = attachState.connected, onClick = onSendEsc)
                    KeyPill(label = "TAB", enabled = attachState.connected, onClick = onSendTab)
                    KeyPill(label = "CTRL*", latched = stickyCtrl, enabled = attachState.connected, onClick = onToggleStickyCtrl)
                    KeyPill(label = "ALT*", latched = stickyAlt, enabled = attachState.connected, onClick = onToggleStickyAlt)
                    KeyPill(label = "←", enabled = attachState.connected, onClick = onSendArrowLeft)
                    KeyPill(label = "↓", enabled = attachState.connected, onClick = onSendArrowDown)
                    KeyPill(label = "↑", enabled = attachState.connected, onClick = onSendArrowUp)
                    KeyPill(label = "→", enabled = attachState.connected, onClick = onSendArrowRight)
                    KeyPill(label = "PGUP", enabled = attachState.connected, onClick = onSendPageUp)
                    KeyPill(label = "PGDN", enabled = attachState.connected, onClick = onSendPageDown)
                    KeyPill(label = "PASTE", enabled = attachState.connected, onClick = {
                        if (clipboardText.isNotEmpty()) onPasteText(clipboardText)
                    })
                }
            }
        }
    }
}

@Composable
private fun AttachOverflowMenu(
    expanded: Boolean,
    attachState: AttachState,
    terminalState: TerminalUiState,
    extraKeysVisible: Boolean,
    followOutput: Boolean,
    onDismiss: () -> Unit,
    onShowCredentials: () -> Unit,
    onToggleFollow: () -> Unit,
    onToggleSelection: () -> Unit,
    onFontDown: () -> Unit,
    onFontUp: () -> Unit,
    onSendCtrlC: () -> Unit,
    onReconnect: () -> Unit,
    onToggleKeys: () -> Unit,
    onDetach: () -> Unit
) {
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        DropdownMenuItem(text = { Text("Session") }, enabled = false, onClick = {})
        DropdownMenuItem(text = { Text("SSH Credentials") }, onClick = { onShowCredentials(); onDismiss() })
        DropdownMenuItem(text = { Text("Terminal") }, enabled = false, onClick = {})
        DropdownMenuItem(text = { Text("Traffic in:${terminalState.inBytes} out:${terminalState.outBytes}") }, enabled = false, onClick = {})
        DropdownMenuItem(text = { Text(if (followOutput) "Follow: ON" else "Follow: OFF") }, onClick = { onToggleFollow(); onDismiss() })
        DropdownMenuItem(text = { Text("Selection Mode") }, onClick = { onToggleSelection(); onDismiss() })
        DropdownMenuItem(text = { Text("A-") }, onClick = { onFontDown(); onDismiss() })
        DropdownMenuItem(text = { Text("A+") }, onClick = { onFontUp(); onDismiss() })
        DropdownMenuItem(text = { Text("Control") }, enabled = false, onClick = {})
        DropdownMenuItem(text = { Text("Send Ctrl+C") }, onClick = { onSendCtrlC(); onDismiss() })
        DropdownMenuItem(text = { Text("Connection") }, enabled = false, onClick = {})
        DropdownMenuItem(text = { Text("Reconnect") }, onClick = { onReconnect(); onDismiss() })
        DropdownMenuItem(text = { Text(if (extraKeysVisible) "Hide Keys" else "Show Keys") }, onClick = { onToggleKeys(); onDismiss() })
        DropdownMenuItem(text = { Text("Detach") }, onClick = { onDetach(); onDismiss() })
    }
}

@Composable
internal fun CompactFilledButton(
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
internal fun CompactTonalButton(
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
        modifier = Modifier.height(34.dp).clickable(enabled = enabled, onClick = onClick),
        shape = RoundedCornerShape(ZagoraRadius.field),
        color = bg
    ) {
        Box(modifier = Modifier.padding(horizontal = 10.dp), contentAlignment = Alignment.Center) {
            Text(label, color = fg, fontSize = 11.sp)
        }
    }
}

private fun phaseLabel(phase: AttachPhase): String = when (phase) {
    AttachPhase.Idle -> "Idle"
    AttachPhase.Connecting -> "Connecting"
    AttachPhase.Attaching -> "Attaching"
    AttachPhase.Connected -> "Connected"
    AttachPhase.Reconnecting -> "Reconnecting"
    AttachPhase.Disconnected -> "Disconnected"
    AttachPhase.Error -> "Error"
}

@Composable
private fun phaseColor(phase: AttachPhase): Color = when (phase) {
    AttachPhase.Connected -> MaterialTheme.colorScheme.primary
    AttachPhase.Connecting, AttachPhase.Attaching, AttachPhase.Reconnecting -> MaterialTheme.colorScheme.tertiary
    AttachPhase.Error -> MaterialTheme.colorScheme.error
    AttachPhase.Disconnected, AttachPhase.Idle -> MaterialTheme.colorScheme.onSurfaceVariant
}
