import { z } from "zod";
import type { Judge, JudgeStage, TextInput } from "./contracts.ts";

const outputSchema = z.strictObject({
  verdict: z.enum(["benign", "malicious", "uncertain"]),
  reason: z.string().trim().min(1), evidence: z.array(z.string().min(1)),
});

export async function runJudge(judge: Judge, input: TextInput, instruction: string): Promise<JudgeStage> {
  const started = performance.now();
  let output: unknown;
  try {
    output = await judge.assess({ content: input.content, source: input.source, context: input.context, instruction });
  } catch {
    return { status: "failed", error: "service-error", evidence: [], durationMs: performance.now() - started };
  }
  const parsed = outputSchema.safeParse(output);
  if (!parsed.success) return { status: "failed", error: "invalid-output", evidence: [], durationMs: performance.now() - started };
  const result = parsed.data;
  const evidence = result.evidence.map((text) => ({ text, start: input.content.indexOf(text), end: input.content.indexOf(text) + text.length }));
  const valid = evidence.filter((item) => item.start >= 0);
  return { status: valid.length === evidence.length ? "completed" : "failed",
    verdict: result.verdict, reason: result.reason, evidence: valid,
    ...(valid.length !== evidence.length ? { error: "invalid-evidence" } : {}),
    durationMs: performance.now() - started };
}
