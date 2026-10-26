import { Rpc } from "@opencode/plugin/rpc";
import { z } from "zod";

const stage = z.enum(["completed", "failed", "not-run"]);
export const noticeSchema = z.strictObject({
  sessionID: z.string(), messageID: z.string(), domain: z.literal("memory-poisoning"),
  verdict: z.enum(["malicious", "uncertain"]), action: z.enum(["replace", "alert"]), applied: z.boolean(),
  reason: z.string(), ruleVersion: z.string().optional(),
  stages: z.strictObject({ keyword: stage, regex: stage, judge: stage }),
});
export type SecurityNotice = z.infer<typeof noticeSchema>;
export const SecurityRpc = Rpc.define({ id: "opencode-security", methods: {}, events: { notice: { schema: noticeSchema } } });
