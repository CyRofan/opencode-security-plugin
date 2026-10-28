## Agent skills

### Issue tracker

使用本地 Markdown 跟踪任务，文件位于 `.scratch/<feature>/`。
具体约定见 `docs/agents/issue-tracker.md`。

### Domain docs

采用单上下文布局：根目录 `GLOSSARY.md` 和 `docs/adr/`。
读取规则见 `docs/agents/domain.md`。

## 工程约定

- 独立文本引擎与 OpenCode hook 保持分离；仅 session.prompt 用户正文执行检测，最终 malicious 整条固定替换，uncertain 或技术未完成保留并告警；其他入口和检测域仍为占位，不得把替换称为拒绝提交。
- Judge 仅使用 Jev 原生 Choice 三分类，不恢复生成式适配器、解释生成或其他模型兜底。
- 不增加置信度阈值、检测超时、正则执行时限或自动重试，除非用户明确变更这些决策。
- 记忆投毒的领域定义不限定内容来源；本轮仅检测当前用户正文，不读取会话历史、附件或技能，不提供持久记忆文件防护。YAML 是项目自有模型，不声称完整 ATR 兼容。
- 配置项为 `JEV_API_KEY`、`JEV_API_URL`、`JEV_MODEL`；由显式入口读取 `.env` 并注入，已有进程变量优先。不得读取或输出真实凭据用于测试，也不得提交实际环境文件；只提交占位 `.env.example`。
- Jev 概率校验保留原有 1e-6 容差；仅额外兼容三类均为两位小数且总和 0.99／1.01，保留原值并标记 probabilityRounding=two-decimal，不擅自归一化或扩大边界。
- 检查未完成不能视为安全。规则原文位置使用 UTF-16 半开区间，正文长度上限使用 Unicode 码点，两者不得混用。
- 测试通过引擎公开入口与评测命令验证，使用本地 YAML、可控 Jev 或本地 HTTP 服务；真实质量评测单独显式运行。
- 修改后按需运行 `npm run typecheck` 与 `npm test`；不得用替身测试结果宣称真实 Jev 准确率或宿主集成已验证。
- 实际 Jev 质量评测须单独确认调用预算；已用完的历史预算不代表后续授权。原始失败和未决结果必须保留，不补跑掩盖失败或降低验收标准。

## 深入文档

| 主题 | 文档 |
| --- | --- |
| 数据路径与 hook 边界 | `docs/architecture.md` |
| 配置、API、规则与故障排查 | `docs/text-engine.md` |
| 用户正文替换、终端提示与评测 | `docs/user-input-poisoning.md` |
| 当前能力与验证状态 | `docs/status.md` |

`.scratch/` 中已完成的规格与任务是历史证据，涉及旧 Judge 的要求以 Jev 后续规格和当前文档为准。
