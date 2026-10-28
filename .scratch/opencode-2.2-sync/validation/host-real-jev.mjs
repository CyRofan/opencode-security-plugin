// Opt-in OpenCode 2.2.0 host check. Real Jev budget: at most 6; local controlled main model.
import { createServer, request as proxyRequest } from "node:http";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

const root = await mkdtemp(join(tmpdir(), "opencode-prompt-host-"));
const expected = "本条输入检测到越权操纵风险，已由安全插件替换。请重新提交具体任务。";
const state = { jevCalls: 0, modelCalls: 0, modelSawReplacement: false, modelSawMalicious: false, modelSawNormal: false };
import { loadJevConfig } from "../../../src/engine/config.ts";
import { createJevJudge } from "../../../src/engine/jev.ts";
const realConfig = await loadJevConfig();
const realJudge = createJevJudge(realConfig);
let child;
let password;
const fixture = createServer(async (request, response) => {
  if (request.url.startsWith("/api/")) {
    if (!password) { response.writeHead(503); response.end("host not ready"); return; }
    const upstream = proxyRequest(serverURL + request.url, { method: request.method,
      headers: { ...request.headers, host: "127.0.0.1:42367", authorization: `Basic ${Buffer.from(`opencode:${password}`).toString("base64")}` } }, (incoming) => {
      response.writeHead(incoming.statusCode, incoming.headers); incoming.pipe(response);
    });
    upstream.on("error", () => { response.writeHead(502); response.end("local host unavailable"); });
    response.on("close", () => upstream.destroy()); request.pipe(upstream); return;
  }
  if (request.url === "/status") { response.end(JSON.stringify(state)); return; }
  if (request.url === "/stop") { child?.kill(); response.end("stopped"); fixture.close(); return; }
  const chunks = []; for await (const chunk of request) chunks.push(chunk);
  const body = JSON.parse(Buffer.concat(chunks).toString());
  if (request.url === "/v1/systemone") {
    state.jevCalls++;
    if (state.jevCalls > 6) { response.writeHead(429); response.end('{}'); return; }
    try {
      const output = await realJudge.assess({ ...body.state, instruction: body.questions.injection.instructions });
      console.error(JSON.stringify({ jevCall: state.jevCalls, choice: output?.answers?.injection?.choice, model: output?.model }));
      response.end(JSON.stringify(output));
    } catch { response.writeHead(502); response.end('{}'); }
    return;
  }
  state.modelCalls++;
  const users = JSON.stringify((body.messages ?? []).filter((message) => message.role === "user"));
  state.modelSawReplacement ||= users.includes(expected);
  state.modelSawMalicious ||= users.includes("HOST_MALICIOUS");
  state.modelSawNormal ||= users.includes("HOST_NORMAL");
  if (body.stream) {
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write('data: ' + JSON.stringify({ id: "validation", object: "chat.completion.chunk", model: "test", choices: [{ index: 0, delta: { role: "assistant", content: "Validation complete." }, finish_reason: null }] }) + '\n\n');
    response.end('data: ' + JSON.stringify({ id: "validation", object: "chat.completion.chunk", model: "test", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }) + '\n\ndata: [DONE]\n\n');
  } else response.end(JSON.stringify({ id: "validation", object: "chat.completion", model: "test", choices: [{ index: 0, message: { role: "assistant", content: "Validation complete." }, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 } }));
});
await new Promise((done) => fixture.listen(0, "127.0.0.1", done));
const fixtureURL = `http://127.0.0.1:${fixture.address().port}`;
for (const name of ["data", "config/opencode", "cache"]) await mkdir(join(root, name), { recursive: true });
await writeFile(join(root, "config/opencode/opencode.json"), JSON.stringify({ update: "disable" }));
await writeFile(join(root, "opencode.json"), JSON.stringify({ plugins: [resolve(".")], model: "validation/test", snapshots: false,
  policies: [{ action: "provider.use", resource: "*", effect: "deny" }, { action: "provider.use", resource: "validation", effect: "allow" }],
  providers: { validation: { name: "Local validation", env: ["VALIDATION_MODEL_KEY"], package: "@opencode/ai/providers/openai-compatible",
    settings: { baseURL: fixtureURL + "/v1" }, models: { test: { name: "Local test" } } } } }));
await writeFile(join(root, ".env"), `JEV_API_KEY=local-fixture-only\nJEV_API_URL=${fixtureURL}/v1/systemone\nJEV_MODEL=local-jev\n`);
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(JEV_|OPENCODE_|OPENAI_|ANTHROPIC_)/.test(key)));
Object.assign(env, { XDG_DATA_HOME: join(root, "data"), XDG_CONFIG_HOME: join(root, "config"), XDG_CACHE_HOME: join(root, "cache"), XDG_STATE_HOME: join(root, "state"), VALIDATION_MODEL_KEY: "local-fixture-only" });
const serverURL = "http://127.0.0.1:42367";
child = spawn("C:/Users/DELL/AppData/Roaming/npm/node_modules/@opencode/cli/bin/opencode.exe", ["serve", "--hostname", "127.0.0.1", "--port", "42367"], { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
const pending = { stdout: "", stderr: "" };
function writeLine(line) {
  const match = line.match(/server password (\S+)/);
  if (match) password = match[1];
  process.stderr.write(line.replace(/server password \S+/g, "server password [REDACTED]").replaceAll(realConfig.apiKey, "[REDACTED]"));
}
function capture(stream, chunk) {
  pending[stream] += chunk.toString();
  let newline;
  while ((newline = pending[stream].indexOf("\n")) !== -1) {
    writeLine(pending[stream].slice(0, newline + 1));
    pending[stream] = pending[stream].slice(newline + 1);
  }
}
child.stdout.on("data", (chunk) => capture("stdout", chunk));
child.stderr.on("data", (chunk) => capture("stderr", chunk));
child.on("close", (code) => {
  for (const stream of ["stdout", "stderr"]) if (pending[stream]) writeLine(pending[stream]);
  console.error(JSON.stringify({ hostExit: code }));
});
console.log(JSON.stringify({ root, fixtureURL, serverURL }));
