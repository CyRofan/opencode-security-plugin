import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { z } from "zod";
import { initializeTextEngine } from "../src/engine/index.ts";
import { createChatCompletionsJudge } from "../src/engine/chat-completions.ts";

async function main() {
  const { values } = parseArgs({ options: {
    rules: { type: "string", default: "evaluation/rules" },
    samples: { type: "string", default: "evaluation/samples.json" },
    runs: { type: "string", default: "3" },
  } });
  const runs = Number(values.runs);
  if (!Number.isSafeInteger(runs) || runs < 1) throw new Error("Invalid runs");
  const endpoint = process.env.JUDGE_ENDPOINT;
  const model = process.env.JUDGE_MODEL;
  const apiKey = process.env.JUDGE_API_KEY;
  if (!endpoint || !model || !apiKey) throw new Error("Missing explicit model configuration");
  const samples = z.array(z.strictObject({
    id: z.string().min(1), content: z.string(), source: z.string().min(1), context: z.string().optional(),
    expected: z.enum(["benign", "malicious"]), category: z.string().optional(), rationale: z.string().optional(),
  })).min(1).parse(JSON.parse(await readFile(values.samples!, "utf8")));
  if (new Set(samples.map((sample) => sample.id)).size !== samples.length) throw new Error("Duplicate sample ID");
  const engine = await initializeTextEngine({ rulesDirectory: values.rules!,
    judge: createChatCompletionsJudge({ endpoint, model, apiKey }) });
  const results = [];
  for (let run = 1; run <= runs; run++) {
    for (const sample of samples) {
      // 标签、类别和标注理由仅用于评测，不发送给 Judge。
      const result = await engine.detect({ content: sample.content, source: sample.source, context: sample.context });
      const stages = Object.values(result.stages);
      results.push({ id: sample.id, run, expected: sample.expected, verdict: result.verdict,
        ruleVersion: result.ruleVersion, reason: result.reason,
        technicalFailure: stages.some((stage) => stage.status === "failed"),
        incompleteCheck: stages.some((stage) => stage.status !== "completed"),
        stages: Object.fromEntries(Object.entries(result.stages).map(([name, stage]) => [name, {
          status: stage.status, error: stage.error, durationMs: stage.durationMs,
        }])), durationMs: result.durationMs });
    }
  }
  const counts = {
    benignExpected: results.filter((result) => result.expected === "benign").length,
    maliciousExpected: results.filter((result) => result.expected === "malicious").length,
    falsePositive: results.filter((result) => result.expected === "benign" && result.verdict === "malicious").length,
    falseNegative: results.filter((result) => result.expected === "malicious" && result.verdict === "benign").length,
    uncertain: results.filter((result) => result.verdict === "uncertain").length,
    technicalFailure: results.filter((result) => result.technicalFailure).length,
    incompleteCheck: results.filter((result) => result.incompleteCheck).length,
  };
  const rate = (numerator: number, denominator: number) => ({ numerator, denominator, value: denominator ? numerator / denominator : null });
  console.log(JSON.stringify({ status: counts.incompleteCheck ? "incomplete" : "completed", model, runs,
    sampleCount: samples.length, total: results.length,
    ruleVersions: [...new Set(results.map((result) => result.ruleVersion))], counts,
    rates: { falsePositive: rate(counts.falsePositive, counts.benignExpected),
      falseNegative: rate(counts.falseNegative, counts.maliciousExpected),
      uncertain: rate(counts.uncertain, results.length),
      decided: rate(results.length - counts.uncertain, results.length) }, results }, null, 2));
  if (counts.incompleteCheck === results.length) process.exitCode = 2;
}

main().catch(() => {
  // 配置、规则或样本错误不打印原始异常，避免包含凭据或待检正文。
  console.error("评测未完成：请检查模型配置、规则、样本及命令参数；未生成真实模型效果结论。");
  process.exitCode = 1;
});
