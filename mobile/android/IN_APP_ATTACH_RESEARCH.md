# App 内 Attach（zellij）技术方案研究

目标：在手机里不跳外部 SSH 客户端，直接在 Zagora App 中继续目标 shell，并进入指定 zellij session。

## 结论（建议路线）

优先走 **SSH 通道 + 终端组件内嵌**：
- App 直接建立 SSH（带 PTY）
- 执行 `zellij attach <session>`（失败时降级到 `zellij attach` 或提示创建）
- 在 Compose 页面渲染终端字节流（stdin/stdout 双向）

这条路线不需要改 Zagora Server 协议，和现有 `list/delete/open` 逻辑兼容。

## 分阶段落地

### P0：最小可用（1-2 周）

1. 新增 `Attach` 页面（`SessionCard` 进入二级页）。
2. 引入 SSH 客户端库，建立 `session.allocateDefaultPTY()`。
3. 连接后执行：
   - `zellij attach <name>`
4. 提供基础输入输出、断线重连、手动断开按钮。
5. 保留“Open SSH（外部）”作为兜底。

验收标准：
- 手机内可看到远端 shell 输出。
- 可在 zellij 内执行命令、切 pane/tab。
- 弱网断开时界面能提示并回到可重连状态。

### P1：体验增强

1. 软键盘快捷键栏（`Ctrl`, `Esc`, `Tab`, `|`, `-`）。
2. 长按复制、粘贴、滚动回看、字体缩放。
3. 自动重连到同一 host/session（可配置）。
4. 会话状态指示（connecting/attached/disconnected）。

## 关键技术点

1. **PTY 必须开启**：否则 zellij/TUI 无法正确工作。
2. **I/O 模型**：使用协程分别处理读写，避免主线程阻塞。
3. **终端渲染**：Compose 本身不是终端仿真器，需要接入现成 terminal view 或自建 ANSI 解析层。
4. **安全**：首选 ssh key；密码仅临时内存使用，不落盘。

## 与当前代码的改动点

- `ui/ZagoraApp.kt`：`SessionCard` 增加 `Attach` 按钮，跳转 `AttachScreen`。
- `data/`：新增 `SshAttachRepository`（连接、重连、断开）。
- `model/`：新增 `AttachState`（连接状态与错误码）。
- `SettingsStore`：增加可选 SSH key 引用与“自动重连”开关。

## 风险与规避

- 风险：终端组件不稳定导致输入法/复制体验差。  
  规避：保留外部 SSH 跳转作为 fallback，并在 P0 先保证可用性。
- 风险：不同主机 zellij 版本差异。  
  规避：attach 前先探测 `zellij --version`，失败给出可读提示。
