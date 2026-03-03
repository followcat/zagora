# Zagora Android MVP（方案 1）

该模块是 `zagora` 的轻量移动控制端。

当前范围：
- 从 `zagora` 服务端读取会话（`GET /sessions`）
- 从 registry 删除会话（`DELETE /sessions/{name}?host=...`）
- 通过 Android Intent 跳转外部 SSH 客户端（`ssh://host`）
- App 内 Attach（P0）：通过 SSH + PTY 连接并执行 `zellij attach <session>`

当前不包含：
- 完整终端高级交互（快捷键栏/粘贴板增强/重连策略）
- 在手机上直接执行 `zagora open/sync/refresh` 全流程

## App 内 Attach 研究

已提供实现方案与分阶段计划：
- `mobile/android/IN_APP_ATTACH_RESEARCH.md`

建议按文档中的 P0 -> P1 里程碑推进，先做“可用 attach”，再补体验细节（复制/快捷键/重连）。

## 运行

1. 用 Android Studio 打开 `mobile/android`（建议 Hedgehog+）。
2. 等待 Gradle 同步完成。
3. 在模拟器或真机运行 `app`。

## 构建验证

### 本地（Android Studio / SDK）

1. 使用 JDK 17+（本项目要求 Java 17）。
2. 确保已安装 Android SDK，且设置了 `ANDROID_SDK_ROOT`。
3. 运行环境检查：

```bash
cd mobile/android
bash scripts/verify_android_env.sh
```

4. 在 Android Studio 构建：
- `Build` -> `Make Project`
- 或 `Build` -> `Build APK(s)`

### CI（GitHub Actions）

工作流：`.github/workflows/android-verify.yml`

在 `mobile/android/**` 相关 `push/PR` 触发，执行：
- Java 17 环境准备
- Android SDK 准备
- 环境检查脚本
- `gradle :app:assembleDebug`

## 首次使用

1. 填写服务端地址（示例：`http://t14:9876`）
2. 可选填写 token
3. 点击 **Save**
4. 点击 **Load Sessions**

可在每个会话卡片点击 **Open SSH** 跳转外部 SSH 客户端。

## App 内 Attach（P0）使用

1. 在会话卡片点击 **Attach**
2. 输入 SSH 用户名（和目标机一致），必要时输入密码
3. 点击 **Connect + Attach**
4. 连接成功后会自动执行 `zellij attach <session>`
5. 下方输入框可发送命令，`Ctrl+C` 可中断当前命令

说明：
- 该版本为 P0，可用性优先；高级终端体验（快捷键栏、粘贴板增强）会在后续 P1 完成。
- 仍保留 **Open SSH** 作为回退路径。

## Attach UI（P1）更新

- 终端页顶部新增连接状态机标签：`Connecting / Attaching / Connected / Disconnected / Error`。
- Extra Keys Row 调整为两行默认键位：
  - Row1: `ESC TAB S-TAB CTRL* ALT* ← ↓ ↑ →`
  - Row2: `PGUP PGDN HOME END INS DEL COPY PASTE DETACH`
- `CTRL* / ALT*` 为粘滞键，开启后按钮高亮，下一次发送后自动释放。
- 多行粘贴默认二次确认（可在 Settings 面板中关闭）。
- 顶部展示流量统计（`in/out` 字节）和错误码，便于诊断连通性问题。

## Attach 快捷键与触摸操作（当前版本）

在 Attach 页面已内置快捷操作栏：
- `Ctrl`: `Ctrl+A / Ctrl+D / Ctrl+L / Ctrl+Z / Ctrl+C`
- `Alt`: `Alt+B / Alt+F / Alt+D`
- `Shift`: `Shift+Tab`
- 其他常用键：`Esc / Tab / Up / Down / Left / Right`
- 剪贴板：`Copy`（复制输出区内容）、`Paste`（粘贴到命令输入框）、`Paste->Shell`（直接发送到远端 shell）

触摸与滚屏优化：
- 输出区支持 **文本选择复制**（长按选择）
- 支持 **纵向滚动 + 横向滚动**（查看长命令行）
- 提供 `Top / Bottom` 快速跳转
- `Follow: ON/OFF` 可切换“是否自动跟随最新输出”

## 通过 Wi-Fi 安装到手机（Debug）

1. 手机开启 `USB 调试` 与 `无线调试`
2. 在 Android Studio Device Manager 完成 Wi-Fi 配对（`Pair using Wi-Fi`）
3. 在 Android Studio 运行应用，APK 会通过 Wi-Fi 安装

### CLI 安装命令（你当前流程）

```bash
cd /home/followcat/Projects/zagora/mobile/android
export ANDROID_SDK_ROOT=$HOME/Android/Sdk
export ANDROID_HOME=$HOME/Android/Sdk
export GRADLE_USER_HOME=$PWD/.gradle-home
./gradlew :app:installDebug
```

该命令会将最新 Debug 包直接推送到已配对/已连接设备。

## 交互打磨流程

建议先在 `mobile/web` 快速打磨交互，再同步到 Android：

1. 在 Web（`mobile/web`）先调交互  
   - 状态流转、文案、按钮优先级、错误反馈
   - 迭代速度高于 Android 构建安装循环
2. 将确认后的交互映射到 Android Compose
3. 通过 `:app:installDebug` 在真机做最终验证

完整流程见 `mobile/README.md`。
