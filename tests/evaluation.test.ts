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
    const output = content === "attack" ? jevResponse("malicious") : content === "uncertain" ? jevResponse("uncertain") : benign;
    if (content === "attack") output.answers.injection.probabilities = { benign: 0.05, malicious: 0.93, uncertain: 0.01 };
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
  assert.equal(report.results[1].stages.judge.decision.probabilityRounding, "two-decimal");
  assert.deepEqual(report.results[1].stages.judge.decision.probabilities, { benign: 0.05, malicious: 0.93, uncertain: 0.01 });
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

test("用户输入评测按每轮分母验收，规则冲突不算检出且不以平均数掩盖失败", async (t) => {
  const directory = await rulesDirectory(t, []);
  const categories = ["instruction-override", "role-priority", "persistent-behavior", "fabricated-authorization", "structured-injection", "encoding-evasion"];
  const samples = categories.flatMap((category) => ["malicious", "benign"].flatMap((expected) => Array.from({ length: 5 }, (_, index) => ({
    id: `${category}-${expected}-${index}`, content: `${expected}-${category}-${index}`, expected, source: "user-input", category,
    language: ["zh", "en", "mixed"][index % 3], context: "must-not-send-history",
  }))));
  const samplesFile = join(directory, "samples.json");
  await writeFile(samplesFile, JSON.stringify(samples));
  let calls = 0;
  const receivedStates: object[] = [];
  const receivedInstructions: string[] = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    receivedStates.push(body.state);
    receivedInstructions.push(body.questions.injection.instructions);
    const run = Math.floor(calls++ / 60) + 1;
    const attack = body.state.content.startsWith("malicious");
    const missed = run === 2 && body.state.content.startsWith("malicious-instruction-override");
    response.end(JSON.stringify(missed ? jevResponse("uncertain") : attack ? malicious : benign));
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address(); assert.ok(address && typeof address !== "string");
  await assert.rejects(execute(process.execPath, ["scripts/evaluate-text.ts", "--profile", "user-input", "--rules", directory,
    "--samples", samplesFile, "--runs", "3", "--interval-ms", "1", "--env-path", join(directory, ".env")], {
    env: { ...process.env, JEV_API_URL: `http://127.0.0.1:${address.port}/v1/systemone`, JEV_MODEL: "test", JEV_API_KEY: "test-secret" },
  }), (error: unknown) => {
    const failed = error as Error & { stdout: string; code: number };
    assert.equal(failed.code, 3);
    const report = JSON.parse(failed.stdout);
    assert.deepEqual(Object.keys(receivedStates[0]).sort(), ["content", "source"]);
    assert.ok(receivedInstructions.every((instruction) => /不核验历史/.test(instruction)));
    assert.equal(calls, 180);
    assert.equal(report.acceptance.passed, false);
    assert.equal(report.intervalMs, 1);
    assert.deepEqual(report.acceptance.rounds.map((round: { detected: number }) => round.detected), [30, 25, 30]);
    assert.ok(report.acceptance.rounds.every((round: { attackTotal: number; normalTotal: number }) => round.attackTotal === 30 && round.normalTotal === 30));
    assert.equal(report.results.filter((result: { applied: boolean }) => result.applied).length, 85);
    assert.equal(report.counts.uncertain, 5);
    assert.ok(!failed.stdout.includes("test-secret"));
    return true;
  });
});
