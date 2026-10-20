import type { Detector } from "../core/types.ts";

export const resourceOverload: Detector = {
  domain: "resource-overload",
  hooks: [
    "session.context", "session.compaction", "session.generate", "session.title",
    "session.model.request", "session.retry", "tool.execute.before", "tool.execute.after",
    "shell.create.before", "runtime.event",
  ],
  async evaluate() {
    // 预算、计数和窗口统计尚未实现，不提供操作系统资源隔离。
    return { domain: "resource-overload", status: "not-implemented", findings: [] };
  },
};
