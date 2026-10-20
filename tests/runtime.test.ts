import assert from "node:assert/strict";
import test from "node:test";
import { createSecurityRuntime } from "../src/core/runtime.ts";
import { memoryPoisoning } from "../src/domains/memory-poisoning.ts";
import { toolAbuse } from "../src/domains/tool-abuse.ts";
import { resourceOverload } from "../src/domains/resource-overload.ts";
import { rce } from "../src/domains/rce.ts";

const runtime = createSecurityRuntime([memoryPoisoning, toolAbuse, resourceOverload, rce]);

test("工具返回内容进入投毒检测域，尚未实现的检测不伪装成通过", async () => {
  const results = await runtime.inspect({
    hook: "tool.execute.after", timestamp: 0, sessionID: "test", payload: {},
  });
  assert.ok(results.some((result) => result.domain === "memory-poisoning"));
  assert.ok(results.every((result) => result.status === "not-implemented"));
});

test("RCE 仅进入执行前边界，不将后置结果路由为执行前检测", async () => {
  const results = await runtime.inspect({ hook: "shell.create.before", timestamp: 0, payload: {} });
  assert.deepEqual(results.map((result) => result.domain), ["resource-overload", "rce"]);
  const after = await runtime.inspect({ hook: "tool.execute.after", timestamp: 0, payload: {} });
  assert.ok(after.every((result) => result.domain !== "rce"));
});
