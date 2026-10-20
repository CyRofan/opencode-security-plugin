# OpenCode Security Plugin

基于 OpenCode v2 插件 API 的 Agent 运行时安全检测骨架，面向记忆投毒、工具滥用、资源过载和 RCE 四个检测域。

**独立文本检测引擎已实现，插件中的四个检测域仍是占位实现，尚未自动接入引擎，也不执行安全阻断。** 占位检测器返回 `not-implemented`，不能把空发现列表解释为安全。

## 开发

使用 Node.js 24 和 npm：

```sh
npm install
npm run typecheck
npm test
```

当前锁定 `@opencode/plugin@2.1.0`，使用其真实类型检查 hook，未在真实 OpenCode v2 宿主中完成加载验证。这里的 SDK 版本不等同于宿主发行版本。

本地加载配置见 `examples/opencode.jsonc`，需要根据实际项目位置调整插件目录路径。使用官方 v2 的 `plugins` 配置字段及 `Plugin.define` 默认导出。

## 结构

```text
src/
  index.ts                    # v2 插件入口
  adapters/opencode-v2.ts      # 注册 hook、订阅公共事件、卸载清理
  core/types.ts               # 安全事件、发现、结果、处置决定
  core/runtime.ts             # 按 hook 路由到检测域
  domains/                    # 四个检测域的空实现
  engine/                     # YAML 规则、关键词/正则、Jev 与结果汇总
rules/example.yaml            # 禁用的规则示意
evaluation/                   # 评测样本及演示规则
scripts/evaluate-text.ts      # 显式运行的真实模型评测入口
docs/text-engine.md           # 引擎 API、规则格式与评测说明
docs/architecture.md          # hook 映射与实现边界
GLOSSARY.md                   # 项目领域术语
```

## 本轮范围

- 记忆投毒仅指工具返回内容进入模型上下文后的污染，不覆盖持久记忆文件。
- YAML 使用本项目最小模型，借鉴 ATR；尚不兼容或导入 ATR 原始规则。
- 独立引擎从本地 YAML 初始化规则快照，对文本执行关键词、正则与一次 Jev Choice 三分类，返回整体结论、规则原文证据、阶段状态、概率、置信度及实际模型版本。
- 仅支持 Jev 原生 HTTP 接口，已移除生成式 Judge；不按置信度自动改判。
- 将 `.env.example` 复制为本地 `.env`，填入 `JEV_API_KEY`、完整 `JEV_API_URL` 和 `JEV_MODEL`。实际文件被 Git 忽略，已有环境变量优先。日常测试不调用外部模型。
- 尚未实现 hook 内容提取、HTTP/SSE 解析、会话统计、策略求值、阻断执行及审计存储。
- 资源方向目前建模为应用预算；不提供操作系统沙箱。

使用方法见 [文本检测引擎](docs/text-engine.md)。配置好本地 `.env` 后显式执行 `npm run evaluate:text -- --runs 3`；尚未测得真实 Jev 的准确率。

## 参考

- [OpenCode v2 插件文档](https://opencode.ai/v2/docs/build/plugins/)
- [v1 到 v2 迁移文档](https://opencode.ai/v2/docs/build/plugins/migrate-v1/)
- [OpenCode v2 API](https://opencode.ai/v2/docs/api)
- [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
- [ATR 规则规范](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SPEC.md)
