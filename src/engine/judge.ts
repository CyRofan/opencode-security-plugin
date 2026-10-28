import { z } from "zod";
import { JudgeHttpError, type Judge, type JudgeStage, type TextInput } from "./contracts.ts";

const probability = z.number().min(0).max(1);
const choiceSchema = z.object({
  type: z.literal("choice"), choice: z.enum(["benign", "malicious", "uncertain"]),
  probabilities: z.strictObject({ benign: probability, malicious: probability, uncertain: probability }),
  confidence: probability,
});
const outputSchema = z.object({ model: z.string().trim().min(1), answers: z.object({ injection: choiceSchema }) });

export async function runJudge(judge: Judge, input: TextInput, instruction: string): Promise<JudgeStage> {
  const started = performance.now();
  let output: unknown;
  try {
    output = await judge.assess({ content: input.content, source: input.source, context: input.context, instruction });
  } catch (error) {
    return { status: "failed", error: "service-error", httpStatus: error instanceof JudgeHttpError ? error.httpStatus : undefined,
      durationMs: performance.now() - started };
  }
  const parsed = outputSchema.safeParse(output);
  if (!parsed.success) return { status: "failed", error: "invalid-output", invalidOutputReason: "response-schema", durationMs: performance.now() - started };
  const { choice, probabilities, confidence } = parsed.data.answers.injection;
  const values = Object.values(probabilities);
  const sum = values.reduce((total, value) => total + value, 0);
  // 额外兼容两位小数独立舍入；只容忍浮点表示尾差，不归一化原值。
  const roundingCompatible = Math.abs(sum - 1) > 1e-6
    && values.every((value) => Math.abs(value * 100 - Math.round(value * 100)) <= Number.EPSILON * 100)
    && [0.99, 1.01].some((target) => Math.abs(sum - target) <= Number.EPSILON * 3);
  const invalidOutputReason = Math.abs(sum - 1) > 1e-6 && !roundingCompatible
    ? "probability-sum" : probabilities[choice] + 1e-6 < Math.max(...values) ? "choice-not-maximum" : undefined;
  if (invalidOutputReason) return { status: "failed", error: "invalid-output", invalidOutputReason,
    invalidOutputDetails: { probabilities, sum }, durationMs: performance.now() - started };
  return { status: "completed", verdict: choice,
    decision: { model: parsed.data.model, choice, probabilities, confidence,
      ...(roundingCompatible ? { probabilityRounding: "two-decimal" as const } : {}) },
    durationMs: performance.now() - started };
}
