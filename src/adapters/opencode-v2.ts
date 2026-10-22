import type { Context } from "@opencode/plugin/promise/plugin";
import type { SecurityRuntime } from "../core/runtime.ts";
import type { SecurityHook } from "../core/types.ts";

export async function registerSecurityHooks(ctx: Context, runtime: SecurityRuntime) {
  const registrations: { dispose(): Promise<void> }[] = [];
  const controller = new AbortController();

  async function inspect(hook: SecurityHook, payload: unknown, sessionID?: string) {
    // 其他入口仍只连接事件与占位检测域。
    await runtime.inspect({ hook, timestamp: Date.now(), sessionID, payload });
  }

  async function cleanup() {
    controller.abort();
    for (const registration of registrations.reverse()) await registration.dispose();
  }

  try {
    registrations.push(await ctx.session.hook("prompt", async (event) => {
      const results = await runtime.inspect({ hook: "session.prompt", timestamp: Date.now(),
        sessionID: event.sessionID, messageID: event.messageID, payload: event,
        text: { content: event.prompt.text, source: "user-input" } });
      for (const result of results) {
        if (result.text?.verdict !== "benign") {
          const stages = result.text?.stages;
          console.warn("[opencode-security]", { sessionID: event.sessionID, messageID: event.messageID,
            domain: result.domain, verdict: result.text?.verdict ?? "uncertain",
            reason: result.text?.reason ?? result.reason, ruleVersion: result.text?.ruleVersion,
            stages: { keyword: stages?.keyword.status ?? "not-run", regex: stages?.regex.status ?? "not-run",
              judge: stages?.judge.status ?? "not-run" } });
        }
      }
    }));
    for (const hook of ["context", "compaction", "generate", "title", "model.request", "http.response", "experimental.ws.receive", "retry"] as const) {
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
