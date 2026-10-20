import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { benign, rulesDirectory } from "./engine-fixtures.ts";

const execute = promisify(execFile);
const script = resolve("scripts/evaluate-text.ts");

function isolatedEnvironment() {
  const env = { ...process.env };
  for (const name of ["JEV_API_KEY", "JEV_API_URL", "JEV_MODEL"]) delete env[name];
  return env;
}

test("评测命令读取本地 .env，已有环境变量覆盖文件且输出不含密钥", async (t) => {
  const directory = await rulesDirectory(t);
  const samples = join(directory, "samples.json");
  await writeFile(samples, JSON.stringify([{ id: "normal", content: "normal", source: "tool", expected: "benign" }]));
  const received: { authorization?: string; model: string }[] = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    received.push({ authorization: request.headers.authorization, model: JSON.parse(Buffer.concat(chunks).toString()).model });
    response.end(JSON.stringify(benign));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const url = `http://127.0.0.1:${address.port}/v1/systemone`;
  await writeFile(join(directory, ".env"), `JEV_API_URL=${url}\nJEV_MODEL=file-model\nJEV_API_KEY=file-test-secret\n`);
  for (const overrides of [{}, { JEV_API_URL: url, JEV_MODEL: "env-model", JEV_API_KEY: "env-test-secret" }]) {
    const { stdout, stderr } = await execute(process.execPath, [script, "--rules", directory, "--samples", samples, "--runs", "1"], {
      cwd: directory, env: { ...isolatedEnvironment(), ...overrides },
    });
    assert.equal(JSON.parse(stdout).status, "completed");
    assert.ok(!`${stdout}${stderr}`.includes("file-test-secret") && !`${stdout}${stderr}`.includes("env-test-secret"));
  }
  assert.deepEqual(received, [
    { authorization: "Bearer file-test-secret", model: "file-model" },
    { authorization: "Bearer env-test-secret", model: "env-model" },
  ]);
});

test("缺失或非法 Jev 配置只提示变量名，不回显配置值", async (t) => {
  const directory = await rulesDirectory(t);
  const cases = [
    { env: {}, missing: ["JEV_API_KEY", "JEV_API_URL", "JEV_MODEL"] },
    { env: { JEV_API_KEY: "config-test-secret" }, missing: ["JEV_API_URL", "JEV_MODEL"] },
    { env: { JEV_API_KEY: "config-test-secret", JEV_API_URL: "secret-invalid-url", JEV_MODEL: "jev-latest" }, missing: ["JEV_API_URL"] },
  ];
  const samples = join(directory, "samples.json");
  await writeFile(samples, JSON.stringify([{ id: "normal", content: "normal", source: "tool", expected: "benign" }]));
  for (const entry of cases) {
    await assert.rejects(execute(process.execPath, [script, "--rules", directory, "--samples", samples], {
      cwd: directory, env: { ...isolatedEnvironment(), ...entry.env },
    }), (error: unknown) => {
      const failed = error as Error & { code: number; stdout: string; stderr: string };
      assert.equal(failed.code, 1);
      for (const name of entry.missing) assert.ok(failed.stderr.includes(name));
      assert.ok(!`${failed.stdout}${failed.stderr}`.includes("config-test-secret"));
      assert.ok(!`${failed.stdout}${failed.stderr}`.includes("secret-invalid-url"));
      return true;
    });
  }
});

test("已有空环境变量不回退到文件", async (t) => {
  const directory = await rulesDirectory(t);
  await writeFile(join(directory, ".env"), "JEV_API_KEY=file-test-secret\nJEV_API_URL=http://127.0.0.1:1/v1/systemone\nJEV_MODEL=jev-latest\n");
  await assert.rejects(execute(process.execPath, [script], {
    cwd: directory, env: { ...isolatedEnvironment(), JEV_API_KEY: "" },
  }), (error: unknown) => {
    const failed = error as Error & { code: number; stderr: string };
    assert.equal(failed.code, 1);
    assert.match(failed.stderr, /JEV_API_KEY/);
    assert.ok(!failed.stderr.includes("file-test-secret"));
    return true;
  });
});

test("Git 忽略实际环境文件和本地变体，保留仅含占位值的示例", async () => {
  for (const name of [".env", ".env.local", ".env.production", "nested/.env"]) {
    await execute("git", ["check-ignore", "--no-index", "--quiet", "--", name]);
  }
  await assert.rejects(execute("git", ["check-ignore", "--no-index", "--quiet", "--", ".env.example"]),
    (error: unknown) => (error as { code: number }).code === 1);
  const example = await readFile(resolve(".env.example"), "utf8");
  assert.match(example, /^JEV_API_KEY=replace-with-/m);
  assert.match(example, /^JEV_API_URL=https:\/\/your-jev-api\.example\//m);
  assert.match(example, /^JEV_MODEL=replace-with-/m);
});

test("评测报告不回显服务元数据中意外包含的 API Key", async (t) => {
  const directory = await rulesDirectory(t);
  const samples = join(directory, "samples.json");
  await writeFile(samples, JSON.stringify([{ id: "normal", content: "normal", source: "tool", expected: "benign" }]));
  const secret = "metadata-test-secret";
  const server = createServer((_request, response) => {
    response.end(JSON.stringify({ ...benign, model: `jev-${secret}` }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const { stdout, stderr } = await execute(process.execPath, [script, "--rules", directory, "--samples", samples, "--runs", "1"], {
    cwd: directory, env: { ...isolatedEnvironment(), JEV_API_KEY: secret, JEV_MODEL: "jev-latest", JEV_API_URL: `http://127.0.0.1:${address.port}/v1/systemone` },
  });
  assert.equal(JSON.parse(stdout).total, 1);
  assert.ok(!`${stdout}${stderr}`.includes(secret));
});
