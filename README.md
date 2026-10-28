# OpenCode Security Plugin

基于 OpenCode v2 插件 API 的 Agent 运行时安全检测骨架，面向记忆投毒、工具滥用、资源过载和 RCE 四个检测域。

当前插件 SDK 锁定 `2.2.0`。能力、验证结果与未完成事项的权威入口是[交接状态](docs/status.md)。

**用户正文已在 `session.prompt` 接入检测：最终恶意时整条固定替换，未决或检查失败时保留原文并告警。** 已连接 TUI 显示原生提示，同时保留服务器日志；不拒绝提交。工具返回、上下文和其他检测域仍为占位，不能把空发现列表解释为安全。

## 开发

使用 Node.js 24 和 npm：

```sh
npm install
npm run typecheck
npm test
```

当前锁定 `@opencode/plugin@2.2.0`，面向 OpenCode `2.2.0`。类型检查及 57 项本地测试通过；真实 2.2.0 TUI + 真实 Jev 已验证正常正文保留、恶意正文持久替换及替换提示，主模型为本地受控服务。未决／失败提示及重载的新版验证尚未重跑，证据与完整质量验收缺口见[交接状态](docs/status.md)。

在使用 OpenCode 的项目 `opencode.jsonc` 中配置 `"plugins": ["C:/Study/opencode-security-plugin"]`，按实际仓库位置调整路径。使用官方 v2 的 `plugins` 配置字段及 `Plugin.define` 默认导出。

本地目录加载器使用根目录 `index.ts`／`tui.ts`，npm 的主导出与 `./tui` 指向同一实现。终端没有连接时，实时通知不会补投，仍可查看结构化服务器日志。

## 结构

Windows 终端行为案例位于 [manual-tests/](manual-tests/README.md)，当前提供记忆投毒 `session.prompt` 的正常行为和诱导行为案例。

```text
index.ts / tui.ts              # 本地目录加载入口，转发同一实现
src/
  index.ts                    # v2 插件入口
  tui.ts / rpc.ts             # 终端通知与共享 RPC 契约
  adapters/opencode-v2.ts      # 注册 hook、订阅公共事件、卸载清理
  core/types.ts               # 安全事件、发现、结果、处置决定
  core/runtime.ts             # 按 hook 路由到检测域
  domains/                    # 用户正文记忆投毒检测与其他入口的占位实现
  engine/                     # YAML 规则、关键词/正则、Jev 与结果汇总
rules/user-input/             # 插件加载的本地用户正文规则及来源说明
evaluation/                   # 评测样本及演示规则
scripts/evaluate-text.ts      # 显式运行的真实模型评测入口
docs/text-engine.md           # 引擎 API、规则格式与评测说明
docs/architecture.md          # hook 映射与实现边界
GLOSSARY.md                   # 项目领域术语
```

## 当前能力与边界

- 记忆投毒不限于工具返回污染；本轮只检测当前用户正文，不解析附件、技能或关联历史，不提供持久记忆文件防护。
- YAML 使用本项目最小模型，借鉴 ATR；尚不兼容或导入 ATR 原始规则。
- 独立引擎从本地 YAML 初始化规则快照，对文本执行关键词、正则与一次 Jev Choice 三分类，返回整体结论、规则原文证据、阶段状态、概率、置信度及实际模型版本。
- 仅支持 Jev 原生 HTTP 接口，已移除生成式 Judge；不按置信度自动改判。
- 将 `.env.example` 复制为本地 `.env`，填入 `JEV_API_KEY`、完整 `JEV_API_URL` 和 `JEV_MODEL`。实际文件被 Git 忽略，已有环境变量优先。日常测试不调用外部模型。
- 已提取 prompt 正文；其他 hook 内容提取、HTTP/SSE 解析、会话统计、阻断策略及审计存储尚未实现。
- 资源方向目前建模为应用预算；不提供操作系统沙箱。

独立 API 和通用评测见[文本检测引擎](docs/text-engine.md)。用户输入质量评测命令 `npm run evaluate:prompt` 使用六类 60 条样本各 3 轮，规划 180 次真实请求，执行前需单独确认预算。历史两批质量评测未通过；已完成概率舍入兼容修复，但完整三轮未重跑。当前验证与调用预算见[交接状态](docs/status.md)。

插件在初始化时读取加载位置项目目录的 `.env`，并加载随插件提供的 `rules/user-input/`。日志和通知仅包含关联标识、结论、处置及检查状态，不记录正文。配置或规则不可用时明确提示未检测，仍保留提交。详细范围与字段见 [用户输入检测](docs/user-input-poisoning.md)。

## 文档入口

- [架构与 hook 边界](docs/architecture.md)：区分运行时接线和独立引擎。
- [引擎接入与故障排查](docs/text-engine.md)：配置、API、规则和评测。
- [交接状态](docs/status.md)：已完成能力、验证记录和未完成事项。

`.scratch/` 保留需求与任务历史，不替代当前使用文档；旧生成式 Judge 要求已由 Jev 规格取代。

## 参考

- [OpenCode v2 插件文档](https://opencode.ai/v2/docs/build/plugins/)
- [v1 到 v2 迁移文档](https://opencode.ai/v2/docs/build/plugins/migrate-v1/)
- [OpenCode v2 API](https://opencode.ai/v2/docs/api)
- [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
- [ATR 规则规范](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SPEC.md)
