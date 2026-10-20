import type { Context } from "@opencode/plugin/promise/plugin";
import type { SecurityRuntime } from "../core/runtime.ts";
import type { SecurityHook } from "../core/types.ts";

export async function registerSecurityHooks(ctx: Context, runtime: SecurityRuntime) {
  const registrations: { dispose(): Promise<void> }[] = [];
  const controller = new AbortController();

  async function inspect(hook: SecurityHook, payload: unknown, sessionID?: string) {
    // 本阶段只连接事件与检测域，结果尚未进入策略与执行器。
    await runtime.inspect({ hook, timestamp: Date.now(), sessionID, payload });
  }

  async function cleanup() {
    controller.abort();
    for (const registration of registrations.reverse()) await registration.dispose();
  }

  try {
    for (const hook of ["prompt", "context", "compaction", "generate", "title", "model.request", "http.response", "experimental.ws.receive", "retry"] as const) {
      registrations.push(await ctx.session.hook(hook, async (event) => {
        await inspect(`session.${hook}`, event, event.sessionID);
      }));
    }
    for (const hook of ["execute.before", "execute.after"] as const) {
      registrations.push(await ctx.tool.hook(hook, async (event) => {
        await inspect(`tool.${hook}`, event, event.sessionID);
      }));
    }
    registrations.push(await ctx.permission.hook("evaluate", async (event) => {
      await inspect("permission.evaluate", event, event.sessionID);
    }));
    registrations.push(await ctx.shell.hook("create.before", async (event) => {
      await inspect("shell.create.before", event);
    }));
  } catch (error) {
    await cleanup();
    throw error;
  }

  const observing = (async () => {
    for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
      await inspect("runtime.event", event);
    }
  })().catch(() => {
    if (!controller.signal.aborted) {
      console.error("[opencode-security] 公共事件观察已停止；骨架尚未提供安全防护。");
    }
  });

  return async () => {
    await cleanup();
    await observing;
  };
}
