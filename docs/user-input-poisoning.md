# 用户输入记忆投毒检测

插件在 OpenCode v2 的 `session.prompt` hook 读取当前用户提交的 `prompt.text`，以 `user-input` 来源交给独立文本引擎。检测发生在附件、技能解析和持久化收件箱接纳之前；等待检测会延迟接纳，没有应用层检测超时或自动重试。

## 加载

按根目录示例配置插件。插件初始化时从 `ctx.location.directory` 对应项目目录显式加载 `.env`，已有进程环境变量优先；需要 `JEV_API_KEY`、完整 `JEV_API_URL` 和 `JEV_MODEL`。只读取本地配置，不自动索取或填入凭据。

规则目录为随插件提供的 `rules/user-input/`，相对于插件模块位置，不相对于宿主工作目录。只在初始化时加载固定快照；更改规则或配置后需重新加载插件。配置、规则或 Jev 适配器初始化失败时，输出 `detection-unavailable` 并继续注册 hook；之后每条 prompt 都提示未检测，不能视为安全。

## 检测与告警

- 只检测当前正文，不修改原始消息、附件引用、技能、提及、metadata 或 delivery，不追加安全提示到模型上下文。
- 正常任务、偏好及先前要求的调整允许存在。越过信任边界、覆盖受保护安全要求、伪造更高权限或把引用材料提升为指令是攻击嫌疑；不从正文自称身份推导可信权限。
- 每条有效未超限正文进行关键词、正则及一次 Jev Choice，保留既有汇总。规则命中与 Jev benign 冲突时为 uncertain，不把规则命中直接当作恶意或投毒成功。
- 空正文不请求 Jev，提示 `empty-text`。只有附件或技能时，这个提示只涉及正文，不代表附件已检查。
- 超过 16,000 Unicode 码点或输入非法时为 uncertain，不截断或请求 Jev；模型失败和无效响应同样为 uncertain，并保留 failed 状态。
- benign 不产生风险告警；malicious 和 uncertain 通过 `console.warn` 输出 `[opencode-security]` 结构化对象。日志可在宿主捕获的插件警告输出中观察，尚未完成真实宿主可见性验证，不提供专用 UI。

逐消息告警字段为 sessionID、messageID、domain、verdict、reason、可用的 ruleVersion，以及 keyword／regex／judge 三阶段状态。`incomplete-check` 与 judge failed 表示技术检查不完整；原生 uncertain 的 judge 状态为 completed。初始化失败及空正文的三阶段为 not-run。

日志不包含正文、匹配原文、API Key、认证头、模型返回原始错误或完整配置。运行时 `DetectionResult.text` 在内存中保留引擎结果，包括规则证据、阶段错误、概率和实际模型版本；这是检测事实，不是公开日志或模型生成解释。缺少引擎为 unavailable，空正文为 skipped；二者均不得解释为 benign。其他未实现入口仍返回 not-implemented。

## 范围与验证

本轮没有安全阻断：包括模型失败、规则冲突、不确定及超长情况，均保留原文和提交方式。不调用权限决策接口或把空白重写当成拒绝。宿主本身可能因其他原因拒绝提交，本插件不将此描述为防护效果。

不读取会话历史，不核验历史授权，不扫描附件、技能或持久记忆文件。工具后置、主 Agent 上下文、压缩和临时生成的既有路由仍为占位。经由用户 prompt API 的命令会走同一 hook；synthetic、shell 消息等不在此范围。hook 遵循宿主的重试、并发和注册顺序，不提供 exactly-once 或抵御后续插件修改的保证。

本地测试通过插件 setup／hook 注册入口与公开引擎入口，使用临时项目配置、真实 YAML、可控 Jev 及本地 HTTP 服务。验证结果传递、原文不变、故障提示、配置优先级、规则正反样本和卸载，不证明真实 Jev 的语义质量，也不替代真实 OpenCode v2 集成验证。

首批规则的改编来源、上游 rule_version 和 blob SHA 见 [规则说明](../rules/user-input/README.md)。仅借鉴 ATR 模式与样本，不声称完整 ATR 兼容。安全研究中的攻击引用可能命中模式并与 benign 判断冲突，这是 uncertain 提示，不是攻击成功的结论。

参考：[OpenCode v2 prompt admission](https://opencode.ai/v2/docs/build/plugins/#prompt-admission)、[实现规格](../.scratch/user-input-poisoning/spec.md)。
