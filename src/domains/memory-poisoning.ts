import type { Detector } from "../core/types.ts";
import type { TextEngine } from "../engine/index.ts";

export function createMemoryPoisoning(engine?: TextEngine): Detector {
  return {
    domain: "memory-poisoning",
    hooks: ["session.prompt", "tool.execute.after", "session.context", "session.compaction", "session.generate"],
    async evaluate(event) {
      if (event.hook !== "session.prompt") return { domain: "memory-poisoning", status: "not-implemented", findings: [] };
      if (!engine) return { domain: "memory-poisoning", status: "unavailable", reason: "detection-unavailable", findings: [] };
      if (!event.text) return { domain: "memory-poisoning", status: "unavailable", reason: "invalid-input", findings: [] };
      if (event.text.content === "") return { domain: "memory-poisoning", status: "skipped", reason: "empty-text", findings: [] };
      const text = await engine.detect(event.text);
      const matches = [...text.stages.keyword.matches, ...text.stages.regex.matches];
      return { domain: "memory-poisoning", status: "evaluated", text,
        findings: matches.map(({ ruleID, severity }) => ({ domain: "memory-poisoning", ruleID, severity, reason: "pattern-match" })) };
    },
  };
}

export const memoryPoisoning = createMemoryPoisoning();
