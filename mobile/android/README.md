# Zagora Android

`mobile/android` 是 zagora 的移动端控制器（Jetpack Compose + Retrofit + JSch）。

## 当前能力

- 会话列表：`GET /sessions`
- 创建会话记录：`POST /sessions`
- Remove 语义：先远端 `zellij kill-session`，再删除 registry 记录（等价移动端 kill）
- App 内 Attach：SSH + PTY + `zellij attach -c <session>`
- 自动重连策略：`manual / auto3`
- 终端快捷键栏：`ESC/TAB/CTRL*/ALT*/方向键/PgUp/PgDn/Home/End/Copy/Paste/Detach`
- 会话级 SSH 记忆：按 `host+session` 保存上次输入的 SSH 用户/密码
- 终端字体包：`System Mono / JetBrains Mono / JetBrains Mono Nerd`
- 主题切换：`Neon / Graphite`

## 不在当前范围

- 在手机端完整执行 `zagora open/sync/refresh` 全 CLI 流程
- 完整 xterm 协议覆盖（当前已覆盖常见 zellij/htop 场景）

## 构建环境

- JDK 17
- Android SDK（建议已安装 Build Tools 34+）
- 可用 `adb`（真机安装/调试时）

环境校验：

```bash
cd mobile/android
bash scripts/verify_android_env.sh
```

## 本地构建

```bash
cd mobile/android
export ZAGORA_ANDROID_USE_MIRROR=1   # 可选：国内镜像
export GRADLE_USER_HOME=$PWD/.gradle-home
./gradlew --no-daemon :app:assembleDebug
```

## 安装到真机

```bash
cd mobile/android
export ANDROID_SDK_ROOT=$HOME/Android/Sdk
export ANDROID_HOME=$HOME/Android/Sdk
export GRADLE_USER_HOME=$PWD/.gradle-home
./gradlew :app:installDebug
```

如果出现 `No connected devices!`，先确认设备已连接：

```bash
adb devices
```

## Wi‑Fi 调试（ADB over WLAN）

安卓 11+ 推荐“无线调试”配对：

```bash
# 1) 手机开发者选项开启“无线调试”，获取 ip:port 与配对码
adb pair <phone_ip:pair_port>
# 输入配对码

# 2) 连接调试端口
adb connect <phone_ip:debug_port>
adb devices
```

显示 `device` 后即可继续 `./gradlew :app:installDebug`。

## 使用说明

1. 打开 `Settings` 配置 `Base URL / Token / Default SSH User`
2. 返回 `Sessions` 页面，应用会自动加载会话列表
3. 点击某个 session 进入 Attach
4. 在 Attach 页面输入 SSH 凭据并 `Connect + Attach`
5. 点击终端区域可呼出系统键盘并直接输入

## 关键交互语义

### Remove（移动端 kill）

- 先 SSH 到目标机执行 `zellij kill-session`（失败回退 `delete-session`）
- 再删除 registry 记录
- 网络不可达时可按 stale 记录清理；认证失败会直接报错

### 自动重连

- `manual`：仅手动重连
- `auto3`：断线后自动最多重试 3 次
- 应用进入后台会断开当前连接；回到前台按策略执行重连

### 终端输入

- 单击终端：聚焦并弹出系统键盘
- 长按终端：进入选择/复制模式
- 快捷键栏用于发送控制键与导航键（含粘滞 `CTRL* / ALT*`）

## 字体与字符显示

- 默认：`System Mono`
- 推荐：`JetBrains Mono`
- 如果终端图标/私有区字符显示异常，切换到 `JetBrains Mono Nerd`

字体文件与来源见 [FONTS.md](./FONTS.md)。

## 常见问题

### 1) `CLEARTEXT communication not permitted`

请使用 `https://` 服务地址，或在开发环境按需放开明文策略。

### 2) 构建下载 Gradle 很慢

可启用镜像并复用本地缓存：

```bash
export ZAGORA_ANDROID_USE_MIRROR=1
export GRADLE_USER_HOME=$PWD/.gradle-home
```

### 3) 终端乱码/方块字符

- 先确认远端 `TERM=xterm-256color`
- 切换字体包为 `JetBrains Mono Nerd`
- 某些私有控制序列仍可能受远端程序输出方式影响
