# 用户正文规则

这些启用规则是项目自有 YAML 模型中的窄模式，不是完整 ATR 规则移植，也不代表完整投毒覆盖。规则命中是风险证据；Jev 为 benign 时整体保持 uncertain，不自动阻断。引擎中保留的匹配原文不写入插件告警日志。

参考来源在 2026-10-22 通过 GitHub 文件接口读取，记录的是文件 blob SHA，不是仓库提交 SHA：

| 本地规则 | 上游来源 | 上游 rule_version | 上游 blob SHA |
| --- | --- | --- | --- |
| LOCAL-USER-001 | [ATR-2026-00001](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00001-direct-prompt-injection.yaml) | 1 | a62472058643d016ebea11664702baf7aa103e3b |
| LOCAL-USER-002 | [ATR-2026-00005](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00005-multi-turn-injection.yaml) | 1 | ef57bfd5524a2828af1bc335e7dd076867d15db6 |

上游为 MIT 许可。此处借鉴威胁语义并重写模式，加入中文表达；未沿用其来源筛选、复杂条件、response 动作或内联正则标志。模式使用本地 ECMAScript 正则及独立 flags 字段。

LOCAL-USER-001 参考指令覆盖技术，但要求明确出现安全或系统约束目标。正常“忽略我之前的任务”“以后用中文回答”不属于该模式。攻击样本引用仍可能命中，因此不能把模式结果直接当作恶意结论。

LOCAL-USER-002 参考历史授权和身份声明技术，要求同一段当前文本中还出现跳过授权、权限或安全检查的要求。不照搬单独的历史引用、赞美、身份声明或迭代请求模式；不验证历史是否真实，也不声称拥有跨轮检测能力。

正反样本在公开引擎入口测试中验证；受控 Judge 只用于观察模式与汇总行为，不证明真实 Jev 分类质量。独立评测仍需显式运行。
