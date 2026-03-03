# Zagora Web 原型

这是一个浏览器快速原型，用于在移动端打包前先打磨交互。

## 功能

- 配置 `server`、`token`、可选 `ssh user`（保存到 localStorage）
- 读取会话列表（`GET /sessions`）
- 创建/刷新会话记录（`POST /sessions`）
- 删除会话（`DELETE /sessions/{name}?host=...`）
- 通过 `ssh://user@host` 跳转外部 SSH 客户端（并提供剪贴板 fallback）

## 运行

在仓库根目录执行：

```bash
cd mobile/web
python3 -m http.server 4173
```

浏览器打开：

`http://127.0.0.1:4173`

## 无 CORS 服务端时的推荐启动方式（开发代理）

如果服务端不支持 CORS（例如 `OPTIONS /sessions` 返回 501），请改用内置开发代理：

```bash
cd mobile/web
python3 dev_server.py --port 4173 --upstream http://t14:9876
```

然后浏览器里 `Server` 输入框留空，或填 `/api`。
前端会走同源 `/api`，由本地代理转发到 `--upstream`，无需服务端改造。

## 前端交互打磨

本模块是“先打磨交互”的主战场。

当前默认流程向 CLI 靠拢：

1. 填写并 `Save` server（会存入 localStorage，下次自动回填）
2. 页面若有已保存 server，会自动 `Connect + ls`
3. 也可手动点击 `Connect`
4. `ls` 在连接后自动执行（不再提供单独 ls 按钮）
5. `open` 在二级视图中单独填写表单（name/host）后创建
6. 会话卡片支持 `attach` / `kill`，其中 `kill` 带二次确认
7. `Host Filter` 为本地搜索过滤（name/host/status/last_seen）

建议循环：

1. 修改 `index.html` / `styles.css` / `app.js`
2. 浏览器刷新并验证：
   - 操作层级（主按钮/次按钮）
   - 状态与反馈文案
   - 错误态与空态
3. 交互确认后，再同步到 `mobile/android`

这样可以显著减少 Android 构建和安装次数。

## 服务端要求

该原型会直接从浏览器请求 Zagora server，因此服务端必须支持 CORS。
当前仓库的 `zagora/server.py` 已包含 CORS 支持。
