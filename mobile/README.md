# 移动端开发指南

本目录包含两条开发路径：

- `mobile/web`：浏览器快速交互原型
- `mobile/android`：Android 打包与真机验证

## 推荐流程

1. **先在 Web 打磨交互**
   - 快速迭代布局、文案、按钮层级、错误反馈等。
   - 启动方式：

   ```bash
   cd /home/followcat/Projects/zagora/mobile/web
   python3 -m http.server 4173
   ```

   浏览器打开 `http://127.0.0.1:4173`。

2. **将确认后的交互同步到 Android**
   - 保持数据模型与操作语义和 Web 一致。
   - Android 侧重点放在平台能力（如外部 SSH 意图跳转、设备行为）。

3. **通过 Wi-Fi 在真机做最终验证**
   - 用 Android Studio 设备配对或 `adb` 无线调试。
   - 安装命令见 `mobile/android/README.md`。

## 为什么这样分层

- Web 反馈快，适合高频 UI/交互调整。
- Android 更接近最终使用环境，适合发布前验证。

## App 内 Shell（zellij attach）研发入口

- Android 端技术方案文档：`mobile/android/IN_APP_ATTACH_RESEARCH.md`
- 建议流程：先完成 P0（App 内 attach 可用），再进入 P1（复制粘贴/快捷键/重连体验）。
