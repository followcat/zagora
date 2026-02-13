```
███████╗ █████╗  ██████╗  ██████╗ ██████╗  █████╗
╚══███╔╝██╔══██╗██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗
  ███╔╝ ███████║██║  ███╗██║   ██║██████╔╝███████║
 ███╔╝  ██╔══██║██║   ██║██║   ██║██╔══██╗██╔══██║
███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

zagora — centralized zellij sessions over tailscale
```

跨机器 **zellij** 终端会话的中心化管理工具，基于 Tailscale 组网。

在家里操作办公室电脑、在办公室继续家里的工作 —— 所有机器上的 shell session 统一管理，断点续"做"。

## 架构

```
                         ┌──────────────────────┐
                         │   zagora server       │
                         │   (registry, HTTP)    │
                         │   存储 session 元信息  │
                         └──────┬───────┬────────┘
                           HTTP │       │ HTTP
                   ┌────────────┘       └────────────┐
                   │                                 │
            ┌──────┴──────┐                   ┌──────┴──────┐
            │  客户端 A    │                   │  客户端 B    │
            │  (家里笔记本)│                   │  (办公室电脑)│
            └──────┬──────┘                   └──────┬──────┘
                   │ SSH (tailscale)                  │ SSH
                   │                                 │
            ┌──────┴──────┐  ┌──────────┐  ┌────────┴─────┐
            │  目标机器    │  │ 目标机器  │  │  目标机器     │
            │  v100       │  │ t14      │  │  jdvm        │
            │  (zellij)   │  │ (zellij) │  │  (zellij)    │
            └─────────────┘  └──────────┘  └──────────────┘
```

- **Server**（`zagora serve`）：轻量 HTTP JSON API，仅存储 session 元信息（名称、所在机器、状态）。不转发任何终端流量。
- **Client**（`zagora open/attach/ls/kill`）：通过 HTTP 与 server 交互查询/注册 session，然后通过 SSH 直连目标机器操作 zellij。
- **目标机器**：运行 zellij 的远程 Linux 机器，通过 Tailscale 可达。


## 前提条件

| 角色 | 要求 |
|------|------|
| **客户端** | `tailscale` + `ssh`，已加入 tailnet |
| **Server** | Python ≥ 3.11，已加入 tailnet |
| **目标机器** | `zellij` 已安装（可用 `zagora install-zellij` 远程安装） |

## 安装

### 一键安装（推荐，用于客户端机器）

> 说明：会在本机创建独立 venv：`~/.local/share/zagora/venv`，并把 `zagora` 链接到 `~/.local/bin/zagora`。

```bash
curl -fsSL https://raw.githubusercontent.com/followcat/zagora/main/install.sh | bash
```

### 开发安装（本仓库）

```bash
pip install -e .
```

## Shell 自动补全（Tab completion）

zagora 内置生成补全脚本：

```bash
zagora completion --shell bash
zagora completion --shell zsh
zagora completion --shell fish
```

### Bash

```bash
# 方式 1：临时生效（当前 shell）
source <(zagora completion --shell bash)

# 方式 2：持久化（推荐）
mkdir -p ~/.local/share/bash-completion/completions
zagora completion --shell bash > ~/.local/share/bash-completion/completions/zagora
# 重新打开 shell 或 source ~/.bashrc
```

### Zsh

```zsh
# zsh 会自动启用 bashcompinit 并复用 bash completion
source <(zagora completion --shell zsh)
```

### Fish

```fish
mkdir -p ~/.config/fish/completions
zagora completion --shell fish > ~/.config/fish/completions/zagora.fish
```

## 交互模式（REPL）

如果你希望像"进入一个控制台"一样操作：

```bash
zagora --host http://t14:9876
# 或
zagora --host http://t14:9876 i

zagora> ls
zagora> open v100 NT        # REPL 简写：等价于 open -c v100 -n NT
zagora> a NT                # 等价于 a -n NT
zagora> kill v100 NT        # 等价于 kill -c v100 -n NT
zagora> exit
```

> 注意：`open/attach` 会进入交互式 zellij；退出远端会话后会返回 REPL。若 session 已被 `session quit` 结束，会自动从 registry 清理。
>
> 为避免与 Copilot 快捷键冲突，zagora 启动的远端 zellij 默认会进入 `lock` 模式（通过注入配置实现）。
> 需要退出 zellij 时先 `Ctrl-g` 退出 lock，再按 `Ctrl-q` 退出；`Ctrl-d` 默认被拦截，不会直接退出。
>
> REPL 输入历史会保存到 server（不同机器/不同终端共享，↑/↓ 可翻阅），并支持 Tab 自动补全命令。

## 维护 / 清理 registry

当你换电脑、重装、或远端 session 被手动关闭后，registry 里可能会残留失效条目。

```bash
# 刷新并自动清理失效 session（默认会删除 missing + unreachable）
zagora refresh

# 仅查看将发生的动作，不实际写入
zagora refresh --dry-run

# 保留 missing（仅标记状态）
zagora refresh --no-prune

# 保留 unreachable（仅标记状态）
zagora refresh --no-prune-unreachable

# 主动从目标机扫描并同步 session（可用于修复 registry 漂移）
zagora sync -c v100
```

> 安全保护：若 `refresh` 检测到 SSH 密码提示/鉴权异常等“非可靠输出”，会标记 `unreachable`，不会按 `missing` 误删。

## 快速开始

### 1. 启动 Server

选一台常驻开机的机器（如 `v100`）运行 server：

```bash
zagora serve --port 9876 --health-interval 30
# 监听 0.0.0.0:9876，session 数据保存在 ~/.local/share/zagora/sessions.json
```

带 token 鉴权：

```bash
zagora serve --port 9876 --token my-secret
```

### 2. 配置客户端

三种方式（优先级从高到低）：

**方式 A：命令行参数**

```bash
zagora --host http://v100:9876 ls
```

**方式 B：环境变量**

```bash
export ZAGORA_HOST=http://v100:9876
export ZAGORA_TOKEN=my-secret    # 如果 server 开了 token
export ZAGORA_SSH_CONTROL_PERSIST=15m   # 可选：密码缓存窗口（off 可关闭）
```

**方式 C：配置文件** `~/.config/zagora/config.json`

```json
{
  "server": "http://v100:9876",
  "token": "my-secret",
  "ssh_control_persist": "15m"
}
```

### 3. 远程安装 zellij（首次使用目标机器时）

```bash
zagora install-zellij -c v100
# 在 v100 上下载 zellij 到 ~/.local/bin/（无需 sudo）
```

支持 x86_64 和 aarch64 Linux。

### 4. 创建 session

```bash
zagora open -c v100 --name Work
# 1. SSH 到 v100
# 2. 创建（或 attach）名为 "Work" 的 zellij session
# 3. 向 server 注册该 session
# 4. 进入交互式终端
```

若目标机存在同名 dead/exited session，zagora 会先尝试清理该 dead 记录再重试 open。

### 5. 查看所有 session

从任意客户端查询 server：

```bash
zagora ls
#   Work    v100    running    host:up      seen:2026-02-12 08:10:20  health:2026-02-12 08:10:22  created:2026-02-12 07:00:00
#   Debug   t14     missing    host:down    seen:2026-02-12 08:05:00  health:2026-02-12 08:10:21  created:2026-02-12 06:40:00
```

按目标机器过滤：

```bash
zagora ls -c v100
#   Work    v100    running    host:up      seen:2026-02-12 08:10:20  health:2026-02-12 08:10:22  created:2026-02-12 07:00:00
```

### 6. 从另一台机器恢复 session

```bash
zagora attach --name Work
# 自动从 server 查到 "Work" 在 v100 上，然后 SSH attach
# 等价简写：
zagora a Work
```

也可以显式指定目标机器：

```bash
zagora attach --name Work -c v100
```

若同名 session 存在于多台机器（例如 `Work@v100` 与 `Work@t14`），`attach` 会提示歧义，此时请加 `-c` 指定目标机器。

### 7. 杀死 session

```bash
zagora kill --name Work
# 1. 查 server 得知 "Work" 在 v100
# 2. SSH 到 v100 执行 zellij kill-session Work
# 3. 从 server 删除记录
```

### 8. 环境检查

```bash
zagora doctor
#   ✓ tailscale
#   ✓ ssh
#   tailscale 1.90.9
#   ✓ server http://v100:9876
```

## 完整命令参考

```
zagora [--host HOST] [--token TOKEN] [--transport {auto,tailscale,ssh}] [--ssh-control-persist DUR] <command>

命令:
  serve                启动 zagora registry server
  open                 在目标机器上创建并 attach 一个 zellij session
  attach               attach 到已有 session（自动发现目标机器）
  ls                   列出 server 上注册的所有 session
  kill                 杀死一个 session（自动发现目标机器）
  sync                 扫描目标机器 zellij sessions 并同步到 server
  doctor               检查本地工具和 server 连通性
  install-zellij       在远程机器上安装 zellij
```

### `zagora serve`

```bash
zagora serve [--port PORT] [--bind BIND] [--token TOKEN] [--health-interval SEC] [--health-timeout SEC]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--port` | `9876` | 监听端口 |
| `--bind` | `0.0.0.0` | 绑定地址 |
| `--token` | 无 | 鉴权 token，设置后所有请求需带此 token |
| `--health-interval` | `30` | 定期检查 host 可达性的间隔秒数（`0` 为关闭） |
| `--health-timeout` | `2` | 单次 host 可达性检查超时秒数 |

### `zagora open`

```bash
zagora open -c <target> --name <session_name>
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `-c` / `--connect` | ✅ | 目标机器（如 `v100`） |
| `--name` | ✅ | session 名称 |

### `zagora attach`

```bash
zagora attach [--name <session_name> | <session_name>] [-c <target>]
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `--name` 或位置参数 `<session_name>` | ✅（二选一） | session 名称 |
| `-c` / `--connect` | ❌ | 目标机器（不指定则从 server 自动查询） |

说明：同名 session 可存在于不同目标机器；当自动查询出现多匹配时需用 `-c` 消歧。

### `zagora ls`

```bash
zagora ls [-c <target>]
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `-c` / `--connect` | ❌ | 按目标机器过滤（输出含 session 状态、host 可达性、seen/health/created 时间） |

### `zagora kill`

```bash
zagora kill --name <session_name> [-c <target>]
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `--name` | ✅ | session 名称 |
| `-c` / `--connect` | ❌ | 目标机器（不指定则从 server 自动查询） |

### `zagora sync`

```bash
zagora sync -c <target>
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `-c` / `--connect` | ✅ | 目标机器（主动扫描 zellij sessions） |

行为：将目标机器上 `zellij ls` 扫描到的 session 注册为 `running`，并删除该机器在 registry 中已不存在的旧记录。  
兼容清理：会自动清理旧版本遗留的 ANSI/控制字符别名记录，避免同名重复。  
安全保护：若检测到 SSH 密码提示/鉴权异常且扫描结果为空，`sync` 会跳过删除，避免误清理。

### `zagora install-zellij`

```bash
zagora install-zellij -c <target> [--dir DIR]
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `-c` / `--connect` | ✅ | 目标机器 |
| `--dir` | ❌ | 安装目录（默认 `~/.local/bin`） |

## Server API

| Method | Path | Body / Query | 说明 |
|--------|------|-------------|------|
| `GET` | `/sessions` | `?host=xxx`（可选过滤） | 列出所有 session |
| `GET` | `/sessions/<name>` | — | 获取单个 session 详情 |
| `POST` | `/sessions` | `{"name": "...", "host": "...", "status": "running"}` | 注册或更新 session |
| `DELETE` | `/sessions/<name>` | — | 删除 session |
| `GET` | `/health` | — | 健康检查 |

鉴权：如果 server 启动时设了 `--token`，所有请求需带 `Authorization: Bearer <token>` header。

Session 数据结构：

```json
{
  "name": "Work",
  "host": "v100",
  "status": "running",
  "created_at": "2026-02-10T08:00:00+00:00",
  "last_seen": "2026-02-10T08:30:00+00:00"
}
```

## SSH 传输方式

zagora 通过 Tailscale 网络连接目标机器，支持两种 SSH 传输模式：

| 模式 | 命令 | 说明 |
|------|------|------|
| `auto`（默认） | — | 优先 `tailscale ssh`，遇 host key 问题自动回退 |
| `tailscale` | `--transport tailscale` | 强制使用 `tailscale ssh`（基于 tailnet ACL 身份认证） |
| `ssh` | `--transport ssh` | 使用系统 `ssh` + `ProxyCommand=tailscale nc %h %p` |

`auto` 模式处理逻辑：先尝试 `tailscale ssh`（利用 tailnet 身份认证，无需密码/密钥），如果遇到 host key 验证失败则自动回退到系统 `ssh`（设置 `StrictHostKeyChecking=accept-new`）。

系统 `ssh` 路径默认启用连接复用（`ControlPersist=12h`），可通过 `--ssh-control-persist` / `ZAGORA_SSH_CONTROL_PERSIST` / `config.json` 的 `ssh_control_persist` 调整，如 `15m`、`1h`；设为 `off` 可关闭。


## License

MIT
