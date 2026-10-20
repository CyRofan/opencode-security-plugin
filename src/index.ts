import { Plugin } from "@opencode/plugin";
import { registerSecurityHooks } from "./adapters/opencode-v2.ts";
import { createSecurityRuntime } from "./core/runtime.ts";
import { memoryPoisoning } from "./domains/memory-poisoning.ts";
import { toolAbuse } from "./domains/tool-abuse.ts";
import { resourceOverload } from "./domains/resource-overload.ts";
import { rce } from "./domains/rce.ts";

export default Plugin.define({
  id: "opencode-security-plugin",
  async setup(ctx) {
    const runtime = createSecurityRuntime([memoryPoisoning, toolAbuse, resourceOverload, rce]);
    return registerSecurityHooks(ctx, runtime);
  },
});
