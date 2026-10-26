# 用户输入记忆投毒检测

插件在 OpenCode v2 的 `session.prompt` hook 读取当前用户提交的 `prompt.text`，以 `user-input` 来源交给独立文本引擎。检测发生在附件、技能解析和持久化收件箱接纳之前；等待检测会延迟接纳，没有应用层检测超时或自动重试。

## 加载

按根目录示例配置插件。插件初始化时从 `ctx.location.directory` 对应项目目录显式加载 `.env`，已有进程环境变量优先；需要 `JEV_API_KEY`、完整 `JEV_API_URL` 和 `JEV_MODEL`。只读取本地配置，不自动索取或填入凭据。

规则目录为随插件提供的 `rules/user-input/`，相对于插件模块位置，不相对于宿主工作目录。只在初始化时加载固定快照；更改规则或配置后需重新加载插件。配置、规则或 Jev 适配器初始化失败时，输出 `detection-unavailable` 并继续注册 hook；之后每条 prompt 都提示未检测，不能视为安全。

## 检测与告警

- 只检测当前正文。最终 malicious 时整条替换为固定中性提示；必要时移除失效的文件、技能和 agent mention 偏移，保留选择本身、metadata、delivery 与标识。
- 正常任务、偏好及先前要求的调整允许存在。越过信任边界、覆盖受保护安全要求、伪造更高权限或把引用材料提升为指令是攻击嫌疑；不从正文自称身份推导可信权限。
- 每条有效未超限正文进行关键词、正则及一次 Jev Choice，保留既有汇总。规则命中与 Jev benign 冲突时为 uncertain，不把规则命中直接当作恶意或投毒成功。
- 空正文不请求 Jev，提示 `empty-text`。只有附件或技能时，这个提示只涉及正文，不代表附件已检查。
- 超过 16,000 Unicode 码点或输入非法时为 uncertain，不截断或请求 Jev；模型失败和无效响应同样为 uncertain，并保留 failed 状态。
- benign 不产生风险告警；malicious 和 uncertain 通过 `console.warn` 输出 `[opencode-security]` 结构化对象，并由服务器 RPC 通知已连接 TUI 显示原生 toast。通知分别说明已替换、判断不确定或检测未完成，不展示原文。

逐消息告警字段为 sessionID、messageID、domain、verdict、action、applied、reason、可用的 ruleVersion，以及 keyword／regex／judge 三阶段状态。`applied` 区分决定与已执行的替换。`incomplete-check` 与 judge failed 表示检查不完整；原生 uncertain 的 judge 状态为 completed。初始化失败及空正文三阶段为 not-run。

输入替换会成为宿主保存的规范用户正文，并发往后续主模型。固定提示不拼接原文，不生成局部修复，不保留其中的合法任务，用户需重新提交。RPC 事件仅实时有效，终端断线时不补投；通知失败不会撤销替换或阻止提交。

日志不包含正文、匹配原文、API Key、认证头、模型返回原始错误或完整配置。运行时 `DetectionResult.text` 在内存中保留引擎结果，包括规则证据、阶段错误、概率和实际模型版本；这是检测事实，不是公开日志或模型生成解释。缺少引擎为 unavailable，空正文为 skipped；二者均不得解释为 benign。其他未实现入口仍返回 not-implemented。

## 范围与验证

本轮不拒绝提交：恶意正文替换后继续接纳，模型失败、规则冲突、不确定及超长情况保留原文并继续提交。后者是可用性取舍，不等于安全。不调用权限决策接口或把空白正文当成拒绝。

不读取会话历史，不核验历史授权，不扫描附件、技能或持久记忆文件。工具后置、主 Agent 上下文、压缩和临时生成的既有路由仍为占位。经由用户 prompt API 的命令会走同一 hook；synthetic、shell 消息等不在此范围。hook 遵循宿主的重试、并发和注册顺序，不提供 exactly-once 或抵御后续插件修改的保证。

本地测试通过根插件 setup／hook、公开引擎、TUI setup／订阅及评测命令入口验证。真实 OpenCode 2.0.32 另验证了本地加载、实际持久化及主模型收到替换正文、正常输入不变、三种 toast 与重载后不重复检测；其 Jev 和主模型是本地受控服务，不作为真实分类质量证据。

## 显式质量评测

`npm run evaluate:prompt` 使用与插件相同的规则、判断指令、汇总和输入替换逻辑，运行 60 条样本各 3 轮。每轮要求正常样本零误替换、攻击样本至少 27／30 明确恶意且执行替换、无检查未完成；uncertain 不算检出。分轮和分类报告不确定、误告警、技术失败和耗时。

可显式使用 `npm run evaluate:prompt -- --interval-ms 1200` 给评测请求增加间隔；这是样本间隔，不是检测超时或失败重试。一次合规验收规划 180 次真实请求，需先明确预算，不因失败自动补跑。退出码 3 表示用户输入验收未通过，2 表示所有检查未完成，1 表示配置／样本／初始化错误。

2026-10-26 已获批的两批、共 360 次全部用完。追加复测三轮正常样本零误替换、攻击检出 30／30、30／30、29／30，但第三轮一次 invalid-output 导致严格验收仍未通过。后续真实复测或诊断需要新的预算授权；本地功能可运行不等于质量验收完成。

首次真实评测与经用户追加预算的复测报告分别保留，见 [验证记录](../.scratch/user-input-poisoning-completion/validation/README.md)。HTTP 服务错误现在可保留脱敏 httpStatus；旧报告只有 service-error 的失败不能据此推断为限流。

首批规则的改编来源、上游 rule_version 和 blob SHA 见 [规则说明](../rules/user-input/README.md)。仅借鉴 ATR 模式与样本，不声称完整 ATR 兼容。安全研究中的攻击引用可能命中模式并与 benign 判断冲突，这是 uncertain 提示，不是攻击成功的结论。

参考：[OpenCode v2 prompt admission](https://opencode.ai/v2/docs/build/plugins/#prompt-admission)、[完善规格](../.scratch/user-input-poisoning-completion/spec.md)。
