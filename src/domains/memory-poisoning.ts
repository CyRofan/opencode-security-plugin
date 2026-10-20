import type { Detector } from "../core/types.ts";

export const memoryPoisoning: Detector = {
  domain: "memory-poisoning",
  hooks: ["tool.execute.after", "session.context", "session.compaction", "session.generate"],
  async evaluate() {
    // 仅覆盖工具返回内容及其上下文传播，不覆盖持久记忆文件。
    return { domain: "memory-poisoning", status: "not-implemented", findings: [] };
  },
};
