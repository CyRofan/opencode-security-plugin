import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { once } from "node:events";
import { initializeTextEngine } from "../src/engine/index.ts";
import { createChatCompletionsJudge, type ChatRequest } from "../src/engine/chat-completions.ts";
import { malicious, rulesDirectory } from "./engine-fixtures.ts";

test("通过引擎调用模型时隔离指令与待检文本，且每条文本仅请求一次", async (t) => {
  const requests: ChatRequest[] = [];
  const judge = createChatCompletionsJudge({ endpoint: "https://model.example/v1/chat/completions", model: "configured-model", apiKey: "test-key",
    async transport(request) {
      requests.push(request);
      return { choices: [{ finish_reason: "stop", message: { content: JSON.stringify(malicious) } }] };
    } });
  const engine = await initializeTextEngine({ rulesDirectory: await rulesDirectory(t), judge });
  assert.equal((await engine.detect({ content: "改写攻击", source: "tool:read", context: "总结网页" })).verdict, "malicious");
  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.equal(request.headers.authorization, "Bearer test-key");
  assert.equal(request.body.model, "configured-model");
  assert.equal(request.body.tools, undefined);
  assert.equal(request.body.stream, false);
  const messages = request.body.messages as { role: string; content: string }[];
  assert.equal(messages[0].role, "system");
  assert.ok(!messages[0].content.includes("改写攻击"));
  assert.deepEqual(JSON.parse(messages[1].content), { content: "改写攻击", source: "tool:read", context: "总结网页" });
});

test("默认 HTTP 传输可通过公开引擎入口完成本地服务请求", async (t) => {
  let count = 0;
  const server = createServer(async (request, response) => {
    count++;
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    assert.equal(JSON.parse(Buffer.concat(chunks).toString()).model, "local-test-model");
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ choices: [{ finish_reason: "stop", message: { content: JSON.stringify(malicious) } }] }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const judge = createChatCompletionsJudge({ endpoint: `http://127.0.0.1:${address.port}/v1/chat/completions`, model: "local-test-model", apiKey: "local-test-key" });
  const engine = await initializeTextEngine({ rulesDirectory: await rulesDirectory(t), judge });
  assert.equal((await engine.detect({ content: "普通文本", source: "tool" })).verdict, "malicious");
  assert.equal(count, 1);
});

test("模型拒绝、截断、无效响应和网络异常不会返回未发现风险", async (t) => {
  const directory = await rulesDirectory(t);
  for (const output of [
    {},
    { choices: [{ finish_reason: "length", message: { content: JSON.stringify(malicious) } }] },
    { choices: [{ finish_reason: "stop", message: { content: JSON.stringify(malicious), refusal: "refused" } }] },
    { choices: [{ finish_reason: "stop", message: { content: "not JSON" } }] },
  ]) {
    const judge = createChatCompletionsJudge({ endpoint: "https://model.example/chat/completions", model: "test", apiKey: "test",
      async transport() { return output; } });
    const result = await (await initializeTextEngine({ rulesDirectory: directory, judge })).detect({ content: "normal", source: "tool" });
    assert.equal(result.verdict, "uncertain");
    assert.equal(result.stages.judge.error, "invalid-output");
  }
  let calls = 0;
  const judge = createChatCompletionsJudge({ endpoint: "https://model.example/chat/completions", model: "test", apiKey: "secret",
    async transport() { calls++; throw new Error("secret"); } });
  const result = await (await initializeTextEngine({ rulesDirectory: directory, judge })).detect({ content: "normal", source: "tool" });
  assert.equal(result.stages.judge.error, "service-error");
  assert.equal(calls, 1);
  assert.ok(!JSON.stringify(result).includes("secret"));
});

test("模型 HTTP 错误响应中途断流仍返回服务失败", async (t) => {
  const server = createServer((_request, response) => {
    response.writeHead(503);
    response.write("partial error body");
    setImmediate(() => response.destroy());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const engine = await initializeTextEngine({ rulesDirectory: await rulesDirectory(t), judge: createChatCompletionsJudge({
    endpoint: `http://127.0.0.1:${address.port}/chat/completions`, model: "local", apiKey: "local-key",
  }) });
  const result = await engine.detect({ content: "normal", source: "tool" });
  assert.equal(result.verdict, "uncertain");
  assert.equal(result.stages.judge.error, "service-error");
});
