import { z } from "zod";
import type { Judge, JudgeStage, TextInput } from "./contracts.ts";

const probability = z.number().min(0).max(1);
const choiceSchema = z.object({
  type: z.literal("choice"), choice: z.enum(["benign", "malicious", "uncertain"]),
  probabilities: z.strictObject({ benign: probability, malicious: probability, uncertain: probability }),
  confidence: probability,
}).refine(({ probabilities, choice }) => {
  const values = Object.values(probabilities);
  // 允许服务端浮点序列化误差；这是格式校验，不是分类置信度阈值。
  return Math.abs(values.reduce((sum, value) => sum + value, 0) - 1) <= 1e-6
    && probabilities[choice] + 1e-6 >= Math.max(...values);
});
const outputSchema = z.object({ model: z.string().trim().min(1), answers: z.object({ injection: choiceSchema }) });

export async function runJudge(judge: Judge, input: TextInput, instruction: string): Promise<JudgeStage> {
  const started = performance.now();
  let output: unknown;
  try {
    output = await judge.assess({ content: input.content, source: input.source, context: input.context, instruction });
  } catch {
    return { status: "failed", error: "service-error", durationMs: performance.now() - started };
  }
  const parsed = outputSchema.safeParse(output);
  if (!parsed.success) return { status: "failed", error: "invalid-output", durationMs: performance.now() - started };
  const { choice, probabilities, confidence } = parsed.data.answers.injection;
  return { status: "completed", verdict: choice,
    decision: { model: parsed.data.model, choice, probabilities, confidence },
    durationMs: performance.now() - started };
}
