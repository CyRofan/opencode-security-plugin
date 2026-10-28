# 交接状态

核对日期：2026-10-28。当前工作区基于历史功能交付 `77fccee`，已追加概率舍入兼容及 SDK 2.2.0 同步。功能可运行，完整真实 Jev 严格质量验收仍未通过；本地测试和终端冒烟验证不替代质量验收。

## 当前能力

| 范围 | 状态 |
| --- | --- |
| 用户正文 | 仅 session.prompt 当前正文，以 user-input 来源检测；不读取历史、附件、技能或持久记忆文件。 |
| 检测与处置 | 本地关键词／正则提供证据，一次 Jev Choice 三分类；最终 malicious 整条固定替换后继续接纳，uncertain 或检查未完成保留原文并告警，不拒绝提交。 |
| 规则 | 七条规则覆盖六类用户输入模式，有中英文及混合正反样本；不承诺穷尽攻击或完整 ATR 兼容。 |
| 概率契约 | 原有总和 1 的 1e-6 容差继续适用；用户批准额外兼容三类均为两位小数且总和 0.99／1.01 的响应。原值不归一化，decision／评测报告标记 probabilityRounding=two-decimal；其他非法响应仍失败。 |
| 通知 | 已连接 TUI 经实时 RPC 显示固定提示，另保留脱敏服务器日志；无断线补投，通知失败不撤销替换。 |
| 配置与入口 | SDK 锁定 @opencode/plugin@2.2.0；显式加载 Jev 配置，进程变量优先。根 index.ts／tui.ts 转发到 src 实现，保留本地加载兼容及注册清理。 |
| 其他入口和域 | 工具返回、上下文等记忆投毒入口及工具滥用、资源过载、RCE 仍为 not-implemented，不把空发现当安全。 |

调用与故障排查见[文本引擎](text-engine.md)，加载和通知契约见[用户正文检测](user-input-poisoning.md)，数据路径见[架构](architecture.md)。[手工测试](../manual-tests/README.md)按检测域／hook 组织，只保留正常和诱导行为案例。

## 验证结果与证据边界

| 验证 | 结果与局限 |
| --- | --- |
| 本地确定性测试 | SDK 2.2.0 下类型检查和 57 项测试通过，覆盖根插件入口、公开引擎、TUI／RPC、评测命令及概率兼容。不证明真实模型准确率。 |
| OpenCode 2.2.0 + 真实 Jev | Windows PTY 中启动真实 TUI，插件 server／tui／rpc active。正常正文保存且发给本地受控主模型；恶意正文被持久替换，替换 toast 可见，主模型收到替换文本、未收到恶意原文。真实返回模型 jev-1.14.0。TUI 退出码 0，隔离服务已停止。[报告](../.scratch/opencode-2.2-sync/validation/host-real-jev-report.json) |
| 2.2.0 尚未重跑 | uncertain／检查未完成两种 toast、重载后单次检测。上述两条成功交互不能证明这些路径。 |
| 历史宿主验证 | 2026-10-26 OpenCode 2.0.32／SDK 2.1.0，以受控 Jev 和主模型验证持久替换、正常保留、三种 toast 及重载；不是新版宿主或真实模型质量证据。[报告](../.scratch/user-input-poisoning-completion/validation/host-report.json) |
| 历史真实 Jev 质量评测 | 首批 180 次有 60 次 service-error 及正常样本误替换；追加 180 次每轮攻击替换 30／30、30／30、29／30，正常样本均零误替换，但第三轮一次 invalid-output；每轮另有 5 条正常样本 uncertain。严格验收未通过。[原始记录](../.scratch/user-input-poisoning-completion/validation/README.md) |
| 概率兼容修复 | 定向诊断捕获 0.05／0.93／0.01，总和 0.99。已按用户批准的边界兼容并通过本地回归；修复后 10 次真实定向请求全部完成，但该批总和均为 1，未覆盖真实舍入分支。[任务及报告](../.scratch/jev-invalid-output/issues/01-diagnose.md) |
| 历史代码审查 | 77fccee 阶段 Standards／Spec 无待修代码差异，不代表此后工作区改动已重新双轴审查。 |

严格质量门槛仍为每轮正常样本零误替换、至少 27／30 攻击明确检出且替换、无技术未完成。概率兼容修复后尚未重新运行 60 条 × 3 轮，因此[完善规格](../.scratch/user-input-poisoning-completion/spec.md)仍为 **open**。不回写历史失败、不补跑覆盖失败、不降低验收门槛。不能确认历史 invalid-output 与本次 0.99 分布完全同因，也不能断言服务内部进行了舍入。

## 真实调用预算

| 范围 | 授权与使用 |
| --- | --- |
| 2026-10-26 两批质量评测 | 180 + 180 次，360 次全部用完。 |
| 2026-10-28 连通性检查 | 2 次授权，2 次使用。 |
| 首次定向诊断 | 10 次授权，10 次使用；第 6 次 probability-sum，后 4 次未再次复现。 |
| 数值诊断与兼容后验证 | 20 次授权，前 10 次捕获 0.99，后 10 次用于兼容后定向验证；全部用完。 |
| 2.2.0 真实终端验证 | 6 次授权，2 次使用，4 次未用；仅属于该终端验证任务，不是通用评测余额。[报告](../.scratch/opencode-2.2-sync/validation/host-real-jev-report.json) |

整理文档不发起真实请求。新批次或完整质量验收需另行明确预算；上述余额不自动授权其他任务。

## 待完成与范围边界

- 当前格式兼容问题已修复；后续重点是按原标准重跑完整质量验收，并按需补齐 2.2.0 未决／失败提示及重载验证。
- 超出舍入兼容边界的无效响应继续保留 failed／uncertain，可用固定 invalidOutputReason 和有限数值诊断定位，不擅自放宽校验。
- 历史、附件、技能、持久记忆文件和其他 hook 的内容采集不在当前正文范围内。
- 输出缓冲、HTTP/SSE／WebSocket 内容解析、拒绝提交、可靠告警历史、会话资源预算和操作系统隔离尚未实现，也不是已排定的后续任务。

## 阶段历史

历史规格保留原始需求；旧生成式 Judge、工具来源限定和“正文不改写”等约定不能覆盖后续决策。

| 阶段 | 记录 |
| --- | --- |
| 初始文本引擎 | `0ee3fd7`／`07d9b26`，[历史规格](../.scratch/text-detection-engine/spec.md)及五项 resolved 任务。 |
| Jev 与环境配置 | `141142d`，[规格](../.scratch/jev-judge/spec.md)，历史记录为 30 项本地测试通过。 |
| 首个 prompt 集成 | `9a5e091`，[规格](../.scratch/user-input-poisoning/spec.md)，历史记录为 46 项本地测试通过，阶段处置仅告警。 |
| 输入替换与 TUI | `77fccee`，[当前规格](../.scratch/user-input-poisoning-completion/spec.md)与 [ADR-0002](adr/0002-user-input-replacement.md)，功能交付、54 项本地测试通过，真实质量验收仍未通过。 |
