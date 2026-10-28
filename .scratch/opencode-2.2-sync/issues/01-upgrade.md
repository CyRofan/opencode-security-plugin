# 同步 OpenCode 2.2.0 SDK

Status: resolved
Type: task
Date: 2026-10-28

## Goal

核对 2.2.0 发布变化，升级项目 SDK 并验证现有接口，同步文档的当前版本与历史验证边界。不升级全局宿主、不调用真实 Jev、不改写历史宿主报告。

## Answer

- [官方 v2.2.0 发布记录](https://github.com/anomalyco/opencode/releases/tag/v2.2.0)：AI 根导出调整为 Promise API；TUI 插件要求 OpenTUI 0.7；新增 Decision API、会话指令条目及事件类型筛选。本项目不直接导入 AI、不自定义 OpenTUI renderable，也没有锁定旧版 OpenTUI，无需为新增能力扩展检测范围。
- package.json 的 @opencode/plugin 从精确 2.1.0 升至 2.2.0；package-lock.json 同步 SDK 依赖。检查安装后的 SDK：其 AI／client／protocol／schema／util 依赖为 2.2.0，OpenTUI 可选 peer 为 0.7.0。
- session.prompt 可变正文、现有 hook 注册、RPC 定义及清理、事件订阅与 toast 类型仍兼容。未改生产接口实现，未将独立 Jev 适配器替换为宿主 Decision API。
- npm run typecheck、npm test（57 项）通过。npm ls 确认依赖安装版本；CLI 使用工作区隔离的 XDG 数据／配置／缓存目录执行 --version，实际输出 opencode v2.2.0。没有更改全局安装或使用真实模型凭据。
- README、架构、用户正文文档和状态文档同步当前 SDK 与证据范围。历史 2.0.32／SDK 2.1.0 宿主记录原样保留；2.2.0 的实际宿主加载、持久正文替换及 TUI 交互尚未重跑。该任务完成仅指 SDK 同步与本地兼容检查，不能解释为新宿主完整验收。

## Comments

- 2026-10-28 用户另行要求真实终端验证，并授权最多 6 次真实 Jev。通过终端 PTY 启动真实 2.2.0 TUI，正常与恶意输入各提交一次，实际共 2 次，返回 benign／malicious、模型 jev-1.14.0。插件 server／tui／rpc active，正常正文保存且发给受控主模型，恶意正文持久替换、替换 toast 可见，主模型收到替换文本且未收到原攻击。报告见 [host-real-jev-report.json](../validation/host-real-jev-report.json)。上文未重跑描述为升级阶段历史；此项补充验证不覆盖 uncertain／检查未完成 toast、重载或完整质量评测。
- TUI 经 Ctrl+C 退出码 0，隔离服务器和本地中继停止。真实凭据仅由配置加载器读入中继内存，宿主使用本地假密钥；未复制真实凭据到隔离项目。首次 TUI 因默认 state 目录权限失败，改为隔离 XDG_STATE_HOME 后正常启动，该启动失败未产生真实请求。剩余 4 次授权未使用。

- 用户请求更新当前项目，无显式记忆更新请求，故不修改全局记忆。已有手工测试目录继续只保留正常与诱导行为案例。
