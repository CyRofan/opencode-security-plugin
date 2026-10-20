import type { Detector } from "../core/types.ts";

export const toolAbuse: Detector = {
  domain: "tool-abuse",
  hooks: ["tool.execute.before", "tool.execute.after", "permission.evaluate", "session.context"],
  async evaluate() {
    return { domain: "tool-abuse", status: "not-implemented", findings: [] };
  },
};
