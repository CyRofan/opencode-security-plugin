## Agent skills

### Issue tracker

使用本地 Markdown 跟踪任务，文件位于 `.scratch/<feature>/`。
具体约定见 `docs/agents/issue-tracker.md`。

### Domain docs

采用单上下文布局：根目录 `GLOSSARY.md` 和 `docs/adr/`。
读取规则见 `docs/agents/domain.md`。

## 工程约定

- 独立文本引擎与 OpenCode hook 保持分离；仅 session.prompt 用户正文接入记忆投毒检测与告警，其他入口和检测域仍为占位，不得声称已提供阻断。
- 记忆投毒的领域定义不限定内容来源；本轮仅检测当前用户正文，不读取会话历史、附件或技能，不提供持久记忆文件防护。YAML 是项目自有模型，不声称完整 ATR 兼容。
