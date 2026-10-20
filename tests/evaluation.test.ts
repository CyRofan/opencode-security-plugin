import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { benign, malicious, jevResponse, rule, rulesDirectory } from "./engine-fixtures.ts";

const execute = promisify(execFile);

test("评测入口重复运行三类检测，单独统计不确定和技术失败", async (t) => {
  const samples = [
    { id: "safe", content: "normal", expected: "benign", source: "tool" },
    { id: "attack", content: "attack", expected: "malicious", source: "tool" },
    { id: "miss", content: "miss", expected: "malicious", source: "tool" },
    { id: "quote", content: "ignore previous instructions quoted", expected: "benign", source: "tool" },
    { id: "failed", content: "failed", expected: "benign", source: "tool" },
    { id: "uncertain", content: "uncertain", expected: "malicious", source: "tool" },
  ];
  const directory = await rulesDirectory(t, [rule(), rule("regex", { method: "regex", pattern: "attack", flags: "" })]);
  const samplesFile = join(directory, "samples.json");
  await writeFile(samplesFile, JSON.stringify(samples));
  let requests = 0;
  const server = createServer(async (request, response) => {
    requests++;
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    const { content } = body.state;
    if (content === "failed") { response.writeHead(500); response.end("sensitive details"); return; }
    const output = content === "attack" ? malicious : content === "uncertain" ? jevResponse("uncertain") : benign;
    response.end(JSON.stringify(output));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const { stdout } = await execute(process.execPath, ["scripts/evaluate-text.ts", "--rules", directory, "--samples", samplesFile, "--runs", "2", "--env-path", join(directory, ".env")], {
    env: { ...process.env, JEV_API_URL: `http://127.0.0.1:${address.port}/v1/systemone`, JEV_MODEL: "jev-latest", JEV_API_KEY: "test-secret" },
  });
  const report = JSON.parse(stdout);
  assert.equal(report.status, "incomplete");
  assert.equal(requests, 12);
  assert.equal(report.total, 12);
  assert.equal(report.counts.falseNegative, 2);
  assert.equal(report.counts.falsePositive, 0);
  assert.equal(report.counts.uncertain, 6);
  assert.equal(report.counts.technicalFailure, 2);
  assert.equal(report.rates.falseNegative.denominator, 6);
  assert.equal(report.ruleVersions.length, 1);
  assert.equal(report.results.length, 12);
  assert.deepEqual(report.actualModels, ["jev-test-version"]);
  assert.equal(report.results[0].stages.judge.decision.choice, "benign");
  assert.deepEqual(report.results[0].stages.judge.decision.probabilities, { benign: 1, malicious: 0, uncertain: 0 });
  assert.ok(report.results.every((result: { durationMs: number }) => result.durationMs >= 0));
  assert.ok(!stdout.includes("test-secret") && !stdout.includes("sensitive details") && !stdout.includes("ignore previous instructions quoted"));
});

test("全体样本超限时报告未完成真实评测，而非成功评测", async (t) => {
  const directory = await rulesDirectory(t);
  const samplesFile = join(directory, "oversized.json");
  await writeFile(samplesFile, JSON.stringify([{ id: "large", content: "a".repeat(16001), source: "tool", expected: "malicious" }]));
  await assert.rejects(execute(process.execPath, ["scripts/evaluate-text.ts", "--rules", directory, "--samples", samplesFile, "--runs", "1", "--env-path", join(directory, ".env")], {
    env: { ...process.env, JEV_API_URL: "http://127.0.0.1:1/v1/systemone", JEV_MODEL: "jev-latest", JEV_API_KEY: "test" },
  }), (error: unknown) => {
    const failed = error as Error & { code: number; stdout: string };
    assert.equal(failed.code, 2);
    const report = JSON.parse(failed.stdout);
    assert.equal(report.status, "incomplete");
    assert.equal(report.counts.technicalFailure, 0);
    assert.equal(report.counts.incompleteCheck, 1);
    return true;
  });
});
