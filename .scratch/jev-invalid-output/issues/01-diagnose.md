# 定位 Jev invalid-output

Status: resolved
Type: task
Date: 2026-10-28

## Goal

定位 structured-a4 无效响应，按用户后续明确批准增加有边界的舍入兼容；保持其他响应校验与未完成处置，不自动重试或覆盖历史报告。

## Answer

最终结果（2026-10-28）：用户明确同意三个概率均符合两位小数精度且总和 0.99／1.01 的兼容方案。已实现并保留原概率，在 decision／评测报告增加 probabilityRounding=two-decimal。其他非法响应仍失败，原 1e-6 校验继续适用。57 项测试及类型检查通过，覆盖真实失败分布、1.01、其他总和、非两位小数、最高类别和非法数值，以及评测报告的标记及原值。

使用上轮剩余 10 次授权完成定向验证，10 次均 completed / malicious，模型 jev-1.14.0；本批全部总和为 1，未触发舍入兼容。兼容分支由已捕获失败数值的本地回归验证，不宣称本批真实请求验证了该分支。见[修复后报告](../../user-input-poisoning-completion/validation/jev-rounding-verification-2026-10-28.json)。20 次预算累计全部用完。此任务关闭表示已知 0.99 格式兼容修复完成，完整质量验收规格仍 open；历史失败与下列诊断过程保留。

- 增加固定 invalidOutputReason，区分响应结构、概率总和与最高类别校验失败；通过公开引擎测试诊断与敏感服务字段不泄漏。类型检查及 55 项测试通过。
- 用户另行授权最多 10 次真实定向调用，已全部使用。相同 structured-a4 样本第 6 次复现 invalid-output，诊断为 probability-sum；其余 9 次 completed / malicious。失败没有因后续成功而删除或改判。
- 第 6 次未记录概率值，无法确定偏差大小或断言为舍入误差；随后 4 次仅提取有限概率数值均合法，未再次复现。不能追溯证明历史第三轮故障与此次完全同因。
- 这是定位进展，不是故障修复或严格质量验收通过。未放宽 1e-6 容差、归一化概率、增加重试或更换模型。下一步需取得失败时数值证据并确认服务契约，再决定是否存在适配器修复；若服务返回不合约数据，需上游修复或用户明确变更契约。
- [独立报告](../../user-input-poisoning-completion/validation/jev-diagnostic-2026-10-28.json)。历史验收报告保持原样。

## Comments

- 继续修复阶段另获批最多 20 次真实定向请求：实际执行 10 次，第 10 次捕获 probability-sum 后停止，剩余 10 次未使用。本批独立报告为 [数值诊断](../../user-input-poisoning-completion/validation/jev-diagnostic-numeric-2026-10-28.json)。失败概率为 benign=0.05、malicious=0.93、uncertain=0.01，总和 0.9900000000000001；明显超出 1e-6，并非 JS 浮点尾差。前 9 次 completed / malicious。
- 官方 [Choice 响应契约](https://docs.typesafe.ai/primitives/choice)明确要求概率总和为 1，所选类别为最高概率。本次请求经项目现有原生 HTTP 适配器，概率未归一化或修改；现有校验正确识别不合约响应。不能据此确定上游服务内部是否舍入，也不能追溯确认历史失败同因。
- 增加失败数值白名单 invalidOutputDetails，并用此次 0.99 分布通过公开引擎添加回归，确保保留 uncertain / failed，不伪造成功。要消除服务不合约响应，需上游修复，或由用户明确批准改变概率契约；当前没有擅自放宽校验。类型检查和 56 项本地测试通过。

- 本轮先执行 6 次，复现后停止；后以剩余 4 次预算采集白名单有限数值，没有新增授权外请求。
