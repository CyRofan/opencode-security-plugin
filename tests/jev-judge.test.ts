import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { once } from "node:events";
import { initializeTextEngine } from "../src/engine/index.ts";
import { createJevJudge, type JevRequest } from "../src/engine/jev.ts";
import { benign, malicious, jevResponse, rulesDirectory } from "./engine-fixtures.ts";

test("Jev 原生分类保留概率与实际版本，无理由证据也完成且不按置信度改判", async (t) => {
  const requests: JevRequest[] = [];
  const probabilities = { malicious: 0.4, benign: 0.35, uncertain: 0.25 };
  const judge = createJevJudge({ endpoint: "https://api.typesafe.ai/v1/systemone", model: "jev-latest", apiKey: "test-key",
    async transport(request) {
      requests.push(request);
      return { model: "jev-test-version", answers: { injection: {
        type: "choice", choice: "malicious", probabilities, confidence: 0.02,
      } } };
    } });
  const engine = await initializeTextEngine({ rulesDirectory: await rulesDirectory(t), judge });
  const result = await engine.detect({ content: "改写攻击", source: "tool:web", context: "总结网页" });
  assert.equal(result.verdict, "malicious");
  assert.equal(result.stages.judge.status, "completed");
  assert.deepEqual(result.stages.judge.decision, { model: "jev-test-version", choice: "malicious", probabilities, confidence: 0.02 });
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0].body.state, { content: "改写攻击", source: "tool:web", context: "总结网页" });
  assert.equal(requests[0].body.model, "jev-latest");
  assert.equal(requests[0].body.questions.injection.type, "choice");
  assert.deepEqual(Object.keys(requests[0].body.questions.injection.criteria).sort(), ["benign", "malicious", "uncertain"]);
  assert.ok(!JSON.stringify(requests[0].body.questions).includes("改写攻击"));
  assert.equal(requests[0].headers.authorization, "Bearer test-key");
});

test("Jev 非法类型、概率和缺失版本或答案均标记无效输出", async (t) => {
  const directory = await rulesDirectory(t);
  const answer = benign.answers.injection;
  const invalidAnswers = [
    { ...answer, type: "score" }, { ...answer, choice: "other" }, { ...answer, confidence: -1 },
    { ...answer, confidence: NaN }, { ...answer, probabilities: { benign: 0.2, malicious: 0.2, uncertain: 0.2 } },
    { ...answer, probabilities: { benign: 0.1, malicious: 0.8, uncertain: 0.1 } },
    { ...answer, probabilities: { benign: 1 } }, { ...answer, confidence: undefined },
  ];
  for (const output of [{}, { answers: { injection: answer } }, { model: "jev", answers: {} },
    ...invalidAnswers.map((injection) => ({ model: "jev", answers: { injection } }))]) {
    const judge = createJevJudge({ endpoint: "https://api.typesafe.ai/v1/systemone", model: "jev-latest", apiKey: "test",
      async transport() { return output; } });
    const result = await (await initializeTextEngine({ rulesDirectory: directory, judge })).detect({ content: "normal", source: "tool" });
    assert.equal(result.verdict, "uncertain");
    assert.equal(result.stages.judge.status, "failed");
    assert.equal(result.stages.judge.error, "invalid-output");
  }
});

test("原生 uncertain 正常完成，完整响应允许浮点序列化误差", async (t) => {
  const output = jevResponse("uncertain");
  output.answers.injection.probabilities = { benign: 0.3333333, malicious: 0.3333333, uncertain: 0.3333334 };
  output.answers.injection.confidence = 0;
  const engine = await initializeTextEngine({ rulesDirectory: await rulesDirectory(t), judge: { async assess() { return output; } } });
  const result = await engine.detect({ content: "ambiguous", source: "tool" });
  assert.equal(result.verdict, "uncertain");
  assert.equal(result.stages.judge.status, "completed");
  assert.equal(result.stages.judge.decision?.confidence, 0);
});

test("默认 HTTP 传输完成 Jev 请求，并将服务错误及断流映射为失败", async (t) => {
  let requests = 0;
  const server = createServer(async (request, response) => {
    requests++;
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    assert.equal(body.model, "jev-latest");
    assert.equal(body.messages, undefined);
    if (body.state.content === "http-error") {
      response.writeHead(503); response.write("private body");
      setImmediate(() => response.destroy()); return;
    }
    response.end(body.state.content === "bad-json" ? "not JSON" : JSON.stringify(malicious));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const judge = createJevJudge({ endpoint: `http://127.0.0.1:${address.port}/v1/systemone`, model: "jev-latest", apiKey: "test-key" });
  const engine = await initializeTextEngine({ rulesDirectory: await rulesDirectory(t), judge });
  assert.equal((await engine.detect({ content: "normal", source: "tool" })).verdict, "malicious");
  const invalid = await engine.detect({ content: "bad-json", source: "tool" });
  assert.equal(invalid.stages.judge.error, "invalid-output");
  const failed = await engine.detect({ content: "http-error", source: "tool" });
  assert.equal(failed.verdict, "uncertain");
  assert.equal(failed.stages.judge.error, "service-error");
  assert.equal(failed.stages.judge.httpStatus, 503);
  assert.equal(requests, 3);
  assert.ok(!JSON.stringify(failed).includes("private body"));
});

test("Jev 传输异常不自动重试或回显认证信息", async (t) => {
  let calls = 0;
  const judge = createJevJudge({ endpoint: "https://api.typesafe.ai/v1/systemone", model: "jev-latest", apiKey: "test-secret",
    async transport() { calls++; throw new Error("Authorization: Bearer test-secret"); } });
  const engine = await initializeTextEngine({ rulesDirectory: await rulesDirectory(t), judge });
  const result = await engine.detect({ content: "normal", source: "tool" });
  assert.equal(result.stages.judge.error, "service-error");
  assert.equal(calls, 1);
  assert.ok(!JSON.stringify(result).includes("test-secret"));
});
