import assert from "node:assert/strict";
import test from "node:test";
import type { Context } from "@opencode/plugin/promise/plugin";
import { registerSecurityHooks } from "../src/adapters/opencode-v2.ts";

test("适配层保留响应流，卸载时取消订阅并释放注册", async () => {
  const callbacks = new Map<string, (event: unknown) => Promise<void>>();
  const disposed: string[] = [];
  let signal: AbortSignal | undefined;
  const domain = (prefix: string) => ({
    async hook(name: string, callback: (event: unknown) => Promise<void>) {
      const key = `${prefix}.${name}`;
      callbacks.set(key, callback);
      return { async dispose() { disposed.push(key); } };
    },
  });
  const context = {
    session: domain("session"), tool: domain("tool"),
    permission: domain("permission"), shell: domain("shell"),
    event: {
      async *subscribe(options: { signal: AbortSignal }) {
        signal = options.signal;
        await new Promise<void>((resolve) => signal!.addEventListener("abort", () => resolve(), { once: true }));
      },
    },
  } as unknown as Context;
  const observed: unknown[] = [];
  const cleanup = await registerSecurityHooks(context, {
    async inspect(event) { observed.push(event); return []; },
  });
  const response = new Response("unchanged");
  const payload = { sessionID: "test", response };
  await callbacks.get("session.http.response")!(payload);
  assert.equal(response.bodyUsed, false);
  assert.equal(payload.response, response);
  assert.equal(observed.length, 1);
  await cleanup();
  assert.equal(signal?.aborted, true);
  assert.equal(disposed.length, callbacks.size);
  assert.ok(callbacks.has("session.experimental.ws.receive"));
  assert.ok(callbacks.has("permission.evaluate"));
});
