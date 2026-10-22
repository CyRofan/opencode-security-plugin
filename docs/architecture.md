# 初步架构

## 数据路径

```text
OpenCode v2 hook / 公共事件
          ↓
SecurityEvent（hook、时间、可选会话标识、原始事件）
          ↓
SecurityRuntime → 适用于该 hook 的检测域
          ↓
session.prompt：提取当前正文 → 独立文本引擎 → DetectionResult.text
  → malicious / uncertain 的结构化告警（保留原文、不阻断）
其他入口：DetectionResult（not-implemented）

待实现：其他正文提取、阻断策略 / 执行器及审计存储
```

适配层使用官方 SDK 类型，核心接口不依赖宿主类型。payload 仍是内存中的原始事件引用；仅 prompt 正文提取为独立 TextInput，来源固定为 user-input，不解析其他内容或读取历史。记忆投毒域由初始化入口注入引擎，结果回到适配层后仅输出风险或不确定告警。检测不修改原始事件，不执行阻断；其他检测域保持占位。

## 当前 hook 路由

| 检测域 | 已接入的主要 hook | 后续检测关注点 |
| --- | --- | --- |
| 记忆投毒 | session.prompt；tool.execute.after、session.context / compaction / generate 仍为占位 | 当前用户正文已检测；其他内容及传播尚未检测 |
| 工具滥用 | tool.execute.before / after、permission.evaluate、session.context | 调用目的、参数、授权范围及结果 |
| 资源过载 | 各类模型上下文、model.request、retry、工具前后、shell.create.before、公共事件 | 会话预算、调用数量、重试、令牌及执行时间 |
| RCE | tool.execute.before、permission.evaluate、shell.create.before | 未授权命令执行、解释器调用及危险参数 |

session.prompt 已提取正文并路由到记忆投毒检测域；session.http.response 和 session.experimental.ws.receive 虽已注册，流解析和内容来源标记尚未接入，不能将它们视作已覆盖的检测面。

## 监听与阻断边界

- prompt 在附件、技能解析及持久化收件箱接纳之前运行，只检测当前用户正文，不读取历史。malicious 和 uncertain 只告警，不修改原文、metadata 或 delivery；该入口没有类型化拒绝 API，本轮不推断抛错阻断能力。
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

仅记忆投毒域的 prompt 入口调用引擎；该域其他入口和其他三个域仍为占位。插件加载用户正文专用本地规则，来源与边界见 [用户输入检测](user-input-poisoning.md)。禁用示例规则不执行；评测目录的演示规则不代表完整检测覆盖。

规则 ID 使用本地命名空间 `LOCAL-*`；完整 ATR 语义兼容与规则库导入留待后续验证，不声称 ATR 兼容。不得将字段形似视为执行语义兼容。

资源预算需要结构化统计或会话状态，不能仅依赖文本关键词。RCE 应区分合法命令与未授权执行，不能把所有 shell 调用一律视为攻击。

## 验证基线

2026-10-20 查询 npm 的 latest 标签后安装并锁定 `@opencode/plugin@2.1.0`。实现对照安装包类型及下列官方文档；类型检查不替代真实宿主中的加载、异常传播和取消测试。

- [插件 API、hook 及事件边界](https://opencode.ai/v2/docs/build/plugins/)
- [迁移示例与工具前阻断](https://opencode.ai/v2/docs/build/plugins/migrate-v1/)
- [会话统计与中断 API](https://opencode.ai/v2/docs/api)
- [ATR 规范](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SPEC.md)
