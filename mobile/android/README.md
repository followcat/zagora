# Zagora Android MVP（方案 1）

该模块是 `zagora` 的轻量移动控制端。

当前范围：
- 从 `zagora` 服务端读取会话（`GET /sessions`）
- 从 registry 删除会话（`DELETE /sessions/{name}?host=...`）
- 通过 Android Intent 跳转外部 SSH 客户端（`ssh://host`）

当前不包含：
- App 内嵌终端渲染
- 在手机上直接执行 `zagora open/sync/refresh` 全流程

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
