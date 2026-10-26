import { Plugin } from "@opencode/plugin";
import { join } from "node:path";
import { registerSecurityHooks } from "./adapters/opencode-v2.ts";
import { createSecurityRuntime } from "./core/runtime.ts";
import { createMemoryPoisoning } from "./domains/memory-poisoning.ts";
import { initializeTextEngine, createJevJudge, loadJevConfig, type TextEngine } from "./engine/index.ts";
import { toolAbuse } from "./domains/tool-abuse.ts";
import { resourceOverload } from "./domains/resource-overload.ts";
import { rce } from "./domains/rce.ts";
import { SecurityRpc } from "./rpc.ts";
import type { RpcRegistration } from "@opencode/plugin/promise/rpc";
import { userInputDetection } from "./domains/user-input.ts";

export default Plugin.define({
  id: "opencode-security-plugin",
  async setup(ctx) {
    let engine: TextEngine | undefined;
    try {
      const config = await loadJevConfig(join(ctx.location.directory, ".env"));
      engine = await initializeTextEngine({
        ...userInputDetection, judge: createJevJudge(config),
      });
    } catch {
      console.warn("[opencode-security]", { domain: "memory-poisoning", verdict: "uncertain", reason: "detection-unavailable" });
    }
    const runtime = createSecurityRuntime([createMemoryPoisoning(engine), toolAbuse, resourceOverload, rce]);
    let rpc: RpcRegistration<typeof SecurityRpc> | undefined;
    try { rpc = await ctx.rpc.register(SecurityRpc, {}); }
    catch { console.warn("[opencode-security]", { reason: "notification-unavailable" }); }
    try {
      const cleanup = await registerSecurityHooks(ctx, runtime, async (notice) => { await rpc?.events.emit("notice", notice); });
      return async () => { try { await cleanup(); } finally { await rpc?.dispose(); } };
    } catch (error) { await rpc?.dispose(); throw error; }
  },
});
