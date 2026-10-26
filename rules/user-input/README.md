# 用户正文规则

这些启用规则是项目自有 YAML 模型中的窄模式，不是完整 ATR 规则移植，也不代表完整投毒覆盖。规则命中是风险证据；Jev 为 benign 时整体保持 uncertain，不执行替换。只有最终 malicious 才整条固定替换，未决或技术未完成继续保留正文。匹配原文不写入日志或终端通知。

参考来源在 2026-10-22 通过 GitHub 文件接口读取，记录的是文件 blob SHA，不是仓库提交 SHA：

| 本地规则 | 上游来源 | 上游 rule_version | 上游 blob SHA |
| --- | --- | --- | --- |
| LOCAL-USER-001 | [ATR-2026-00001](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00001-direct-prompt-injection.yaml) | 1 | a62472058643d016ebea11664702baf7aa103e3b |
| LOCAL-USER-002 | [ATR-2026-00005](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00005-multi-turn-injection.yaml) | 1 | ef57bfd5524a2828af1bc335e7dd076867d15db6 |
| LOCAL-USER-003 | [ATR-2026-00004](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00004-system-prompt-override.yaml) | 1 | dd9230098bdd84f8ae587d5be8bf3d6008d8d125 |
| LOCAL-USER-003 | [ATR-2026-01002](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-01002-role-escalation-false-authority-claim.yaml) | 1 | 6d60c0f84985d6d1db4dc497d344f15d32019080 |
| LOCAL-USER-004、007 | [ATR-2026-00499](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00499-garak-dan-from-now-on.yaml) | 2 | 8b344bc34c19741457d506ad3288f7ed24acb475 |
| LOCAL-USER-005 | [ATR-2026-00084](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00084-structured-data-injection.yaml) | 1 | 35d04cc68fa6679e7b1044e67ac9b382f9ed0bd7 |
| LOCAL-USER-006 | [ATR-2026-00080](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/prompt-injection/ATR-2026-00080-encoding-evasion.yaml) | 1 | 4c51b97e5faaccb09fd0bb70490a9adc995e3406 |

后五项在 2026-10-26 通过 GitHub 文件接口读取；首两项保留原采用记录。所有匹配式均为本项目改编，不原样执行上游表达式或条件组合。

上游为 MIT 许可。此处借鉴威胁语义并重写模式，加入中文表达；未沿用其来源筛选、复杂条件、response 动作或内联正则标志。模式使用本地 ECMAScript 正则及独立 flags 字段。

LOCAL-USER-001 参考指令覆盖技术，但要求明确出现安全或系统约束目标。正常“忽略我之前的任务”“以后用中文回答”不属于该模式。攻击样本引用仍可能命中，因此不能把模式结果直接当作恶意结论。

LOCAL-USER-002 参考历史授权和身份声明技术，要求同一段当前文本中还出现跳过授权、权限或安全检查的要求。不照搬单独的历史引用、赞美、身份声明或迭代请求模式；不验证历史是否真实，也不声称拥有跨轮检测能力。

正反样本在公开引擎入口测试中验证；受控 Judge 只用于观察模式与汇总行为，不证明真实 Jev 分类质量。独立评测仍需显式运行。

## 六类覆盖矩阵

每类有五条攻击和五条正常验收样本，覆盖中文、英文和混合输入，见 [固定样本集](../../evaluation/user-input-samples.json)。字面规则的阳性表示有模式证据，不表示样本最终必须判恶意。

| 类别／样本前缀 | 本地规则 | 正常对照与边界 |
| --- | --- | --- |
| 指令覆盖／override | 001 | 正常改任务、教程引用；不穷尽语义改写。 |
| 身份优先级／role | 003 | 身份介绍、SDK role 示例；要求同时出现覆盖意图。 |
| 后续行为／persistent | 004、007 | 长期语言／格式偏好；007 是三个短语同时出现的字面组合。 |
| 授权捏造／authorization | 002 | 正常历史引用；仅观察当前措辞，不核验历史。 |
| 结构化包装／structured | 005 | 普通 JSON/XML/YAML 与研究载荷引用；不是格式解析器。 |
| 编码混淆／encoding | 006 | 正常 Base64、Unicode 与 RTL 文本；不自动解码。 |

六类分别有公开引擎正反测试，并用固定样本检查所有启用规则均有字面命中。真实 Jev 的不确定、误替换和技术失败单独统计；原始报告与后续复测不得相互覆盖。
