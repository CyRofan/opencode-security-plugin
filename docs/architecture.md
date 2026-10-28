# 架构与集成边界

## 运行时数据路径

```text
OpenCode v2 hook / 公共事件
          ↓
SecurityEvent（hook、时间、可选会话标识、原始事件）
          ↓
SecurityRuntime → 适用于该 hook 的检测域
          ↓
session.prompt：提取当前正文 → 独立文本引擎 → DetectionResult.text
  → 最终 malicious 整条固定替换；uncertain 原文保留并告警
  → 结构化日志与实时 RPC → 已连接 TUI 原生提示
其他入口：DetectionResult（not-implemented）

待实现：其他正文提取、阻断策略 / 执行器及审计存储
```

适配层使用官方 SDK 类型，核心接口不依赖宿主类型。payload 仍是内存中的原始事件引用；仅 prompt 正文提取为独立 TextInput，来源固定为 user-input，不解析其他内容或读取历史。记忆投毒域由初始化入口注入引擎，结果经共享处置实现映射为 allow／alert／replace，宿主层落实替换并移除失效 mention。引擎仍只返回检测事实，其他检测域保持占位。

## 独立文本引擎数据路径

```text
配置入口：.env 与进程环境 → Jev 配置 → 注入适配器
初始化：本地 YAML → 整体校验 → 固定规则快照与版本
检测：正文 / 来源 / 可选任务上下文
  → 输入和长度校验 → 关键词 → 正则 → 一次 Jev Choice
  → 原生响应校验 → 三态结果 / 规则证据 / 阶段状态 / 概率与模型版本
```

这条路径已实现，可由独立调用方、评测命令及 prompt 检测使用。运行时 DetectionResult.text 保留完整引擎结果，模式命中映射为 Finding；没有规则发现不代表 benign。环境文件仅由显式配置入口读取，引擎导入和每次检测不会自行加载配置。插件读取加载位置项目目录的环境文件，规则目录随插件模块定位；初始化不可用时逐消息提示未检测。

## 当前 hook 路由

| 检测域 | 已接入的主要 hook | 后续检测关注点 |
| --- | --- | --- |
| 记忆投毒 | session.prompt；tool.execute.after、session.context / compaction / generate 仍为占位 | 当前用户正文已检测；其他内容及传播尚未检测 |
| 工具滥用 | tool.execute.before / after、permission.evaluate、session.context | 调用目的、参数、授权范围及结果 |
| 资源过载 | 各类模型上下文、model.request、retry、工具前后、shell.create.before、公共事件 | 会话预算、调用数量、重试、令牌及执行时间 |
| RCE | tool.execute.before、permission.evaluate、shell.create.before | 未授权命令执行、解释器调用及危险参数 |

session.prompt 已提取正文并路由到记忆投毒检测域；session.http.response 和 session.experimental.ws.receive 虽已注册，流解析和内容来源标记尚未接入，不能将它们视作已覆盖的检测面。

## 监听与阻断边界

- prompt 在附件、技能解析及持久化收件箱接纳之前运行，只检测当前用户正文，不读取历史。最终 malicious 整条替换后接纳，uncertain 和技术未完成保留原文并告警；不修改 metadata 或 delivery，不将替换称为拒绝提交。
- 根目录 index／tui 入口用于本地目录加载，npm exports 使用同一实现。TUI 从共享 RPC 订阅脱敏结果后显示固定提示；事件只实时有效，无断线补投，通知失败不能撤销替换或造成隐式拒绝。
- 工具前 hook 可检查或修改输入。官方迁移示例使用抛出错误阻止工具执行；未来执行器可以在这里落实阻断，不能推断其他 hook 具有同样语义。
- permission.evaluate 提供明确的 allow / ask / deny 策略接口；已有显式 deny 不会进入该 hook。
- 工具后 hook 能检查成功和失败结果；已发生的文件写入、命令或网络操作不能靠后置检测撤销。
- context 只覆盖主 Agent 模型调用；compaction、generate 和 title 分别注册，避免遗漏辅助请求。
- http.response 接收一次性响应流。本阶段不读取响应体；后续解析必须处理 clone、替换、背压、取消和延迟。
- WebSocket 流量不经过 HTTP hook，experimental.ws.receive 是单独的实验性逐帧入口；不把帧等同于完整模型文本。
- ctx.event.subscribe 是观察通道，不能作为同步执行前否决接口。卸载时取消订阅并释放 hook；观察通道异常会报告停止，不记录事件正文。
- shell.create.before 没有会话标识，暂不做会话归属推断。公共事件也暂不提取其嵌套标识。
- 后续若要真正保证输出交付前拦截，必须单独设计缓冲与放行边界，不能把异步告警描述为实时阻断。

## 检测引擎与规则

独立文本引擎已实现本地 YAML 快照、关键词、正则、一次独立 Jev Choice 三分类及三态结果汇总。Jev 返回原生分类、概率、置信度及实际模型版本，不再要求生成式理由或原文引用；规则证据继续保留。调用方通过独立文本入口提供正文、来源和可选上下文；引擎不直接接收 SecurityEvent。具体接口、环境配置及评测方式见 [文本检测引擎](text-engine.md)。

仅记忆投毒域的 prompt 入口调用引擎；该域其他入口和其他三个域仍为占位。插件加载用户正文专用本地规则，来源与边界见 [用户输入检测](user-input-poisoning.md)。评测目录的演示规则不代表完整检测覆盖。

规则 ID 使用本地命名空间 `LOCAL-*`；完整 ATR 语义兼容与规则库导入留待后续验证，不声称 ATR 兼容。不得将字段形似视为执行语义兼容。

资源预算需要结构化统计或会话状态，不能仅依赖文本关键词。RCE 应区分合法命令与未授权执行，不能把所有 shell 调用一律视为攻击。

## 验证基线

2026-10-28 插件 SDK 升级并锁定 `@opencode/plugin@2.2.0`，对应 OpenCode 2.2.0；既有 hook、RPC、事件订阅与 toast 实现通过新 SDK 的类型检查及 57 项本地测试，无需迁移现有接口。2.2.0 发布说明中的 AI Promise 导出变更不涉及本项目直接导入，项目也没有自定义 OpenTUI renderable 或直接锁定旧版 OpenTUI。继续使用独立 Jev 原生适配器，不因宿主增加 Decision API 而迁移检测引擎。

历史功能基线为 `77fccee`；2026-10-26 在实际 OpenCode `2.0.32`、SDK `2.1.0` 下验证了本地加载、持久正文与主模型输入替换、三种 TUI 提示及重载。模型端点使用本地受控服务，不能当作真实 Jev 分类质量证据。2026-10-28 已在真实 2.2.0 TUI／宿主中使用真实 Jev 完成正常保留与恶意替换两条交互验证；替换 toast、持久正文及本地受控主模型收到的正文均核对通过。未重跑原生 uncertain／检查未完成提示及重载验证，不等同于完整质量验收。

历史完整质量评测为两批、各 180 次；追加复测仍有一次无效响应，严格质量验收未通过。之后已完成有边界的概率舍入兼容修复及定向验证，但完整三轮质量验收未重跑。当前验证状态和预算边界见[交接状态](status.md)，原始结果见[验证记录](../.scratch/user-input-poisoning-completion/validation/README.md)。下列官方链接用于说明契约，不替代宿主运行与质量证据。

- [插件 API、hook 及事件边界](https://opencode.ai/v2/docs/build/plugins/)
- [迁移示例与工具前阻断](https://opencode.ai/v2/docs/build/plugins/migrate-v1/)
- [会话统计与中断 API](https://opencode.ai/v2/docs/api)
- [ATR 规范](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SPEC.md)
