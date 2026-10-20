import type { Detector } from "../core/types.ts";

export const rce: Detector = {
  domain: "rce",
  hooks: ["tool.execute.before", "permission.evaluate", "shell.create.before"],
  async evaluate() {
    return { domain: "rce", status: "not-implemented", findings: [] };
  },
};
