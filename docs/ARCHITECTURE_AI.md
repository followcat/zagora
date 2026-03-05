# Zagora 架构与 AI 协作手册

本文档用于快速让其他 AI / Web ChatGPT 理解当前代码结构、关键数据流和改动边界，避免重复探索。

## 1. 仓库结构（高频目录）

- `zagora/`：Python CLI + registry server（核心后端）
- `tests/`：Python `unittest`
- `mobile/web/`：Web 交互原型（快速迭代）
- `mobile/android/`：Android 客户端（Compose + Retrofit + SSH attach）
- `mobile/android/app/src/main/java/com/followcat/zagora/`
  - `ui/`：页面与状态管理
  - `data/`：网络/SSH 数据源
  - `net/`：Retrofit API 定义
  - `model/`：会话模型

## 2. 后端（Python）模块边界

- `cli.py`：命令入口、参数解析、REPL、命令语义（open/attach/ls/kill/sync/refresh）
- `server.py`：HTTP JSON registry 服务、会话存储与健康探测
- `registry.py`：客户端访问 server 的 API 封装
- `exec.py`：本地命令执行、SSH/tailscale 执行桥接
- `config.py`：配置优先级（CLI > ENV > 文件）

后端关键原则：
- session 记录是元数据，不转发终端流
- 终端交互走客户端到目标机的直连 SSH

## 3. Android 客户端当前架构

主入口与状态：
- `MainActivity.kt` -> `ZagoraApp.kt`
- `MainViewModel.kt`：session 列表/创建/删除（remove=kill+remove）
- `AttachViewModel.kt`：SSH attach 生命周期、重连策略、按键映射

数据层：
- `ZagoraRepository.kt`：HTTP 会话 API + remove 的 kill 语义
- `SshAttachRepository.kt`：JSch 连接、PTY resize、输出流、输入流
- `SettingsStore.kt`：本地配置持久化

终端层（现状）：
- 已迁移到 ConnectBot `termlib` 渲染链路（字节流直喂终端）
- `ZagoraApp.kt` 的 AttachScreen 负责：
  - incoming bytes -> terminal emulator
  - keyboard bytes -> SSH stdin
  - terminal resize -> PTY resize

## 4. 已知风险与后续整理建议

1. `ZagoraApp.kt` 体积过大（页面、组件、状态、行为混合）
- 建议拆分：
  - `ui/screens/SessionsScreen.kt`
  - `ui/screens/AttachScreen.kt`
  - `ui/screens/SettingsScreen.kt`
  - `ui/components/TerminalKeyBar.kt`

2. Attach 逻辑分散在 UI 与 VM
- 建议收敛为 `AttachCoordinator`（连接、重连、前后台策略）

3. Android 构建依赖升级敏感
- 若使用 `termlib`，需要跟进 AGP/compileSdk 兼容矩阵

## 5. AI 协作输入模板（建议直接复制）

```text
你现在是本仓库协作工程师，请先阅读：
1) docs/ARCHITECTURE_AI.md
2) AGENTS.md
3) 目标模块文件（我会补充路径）

目标：<一句话目标>
范围：<仅允许改动的目录/文件>
约束：
- 保持现有命令语义不变
- 分步提交 commit
- 每步给出验证命令

请先输出：
1) 你理解的当前数据流
2) 你要改的最小文件列表
3) 逐步提交计划（1,2,3）
```

## 6. 常用验证命令（给 AI 用）

后端：
- `python -m unittest discover -s tests -v`
- `python -m zagora --help`

Android：
- `cd mobile/android && bash scripts/verify_android_env.sh`
- `cd mobile/android && ./gradlew --no-daemon :app:assembleDebug`

Web 原型：
- `cd mobile/web && python3 dev_server.py --port 4174 --upstream http://<server>:9876`

## 7. 文档维护规则

当下列任一项变化时，必须同步更新本文档：
- 目录结构重构
- 终端渲染链路变化（如 termlib / 自研 emulator）
- remove/kill/reconnect 的行为语义变化
- 构建基线（AGP / compileSdk / JDK）变化
