import assert from "node:assert/strict";
import test from "node:test";
import type { Context } from "@opencode/plugin/tui/plugin";
import plugin from "../tui.ts";

test("TUI 公开入口订阅脱敏安全结果、区分提示并在卸载时清理", async () => {
  let listener: (event: { data: unknown }) => void = () => {};
  let stopped = false;
  const shown: { message: string; variant: string; sessionID: string }[] = [];
  const context = {
    client: { rpc() { return { events: { on(name: string, handler: typeof listener) {
      assert.equal(name, "notice"); listener = handler; return () => { stopped = true; };
    } } }; } },
    ui: { toast: { show(toast: typeof shown[number]) { shown.push(toast); } } },
  } as unknown as Context;
  const cleanup = await plugin.setup(context);
  const notice = { sessionID: "session", messageID: "message", domain: "memory-poisoning", verdict: "malicious",
    action: "replace", applied: true, reason: "checks-completed",
    stages: { keyword: "completed", regex: "completed", judge: "completed" } };
  listener({ data: notice });
  listener({ data: { ...notice, verdict: "uncertain", action: "alert", applied: false, reason: "conflict-or-uncertain" } });
  listener({ data: { ...notice, verdict: "uncertain", action: "alert", applied: false, reason: "incomplete-check",
    stages: { keyword: "completed", regex: "completed", judge: "failed" } } });
  listener({ data: { ...notice, verdict: "benign", action: "allow", applied: false } });
  listener({ data: { ...notice, content: "must-not-display" } });
  assert.deepEqual(shown, [
    { message: "输入已替换，请重新提交具体任务。", variant: "warning", sessionID: "session" },
    { message: "输入判断不确定，已保留原文。", variant: "warning", sessionID: "session" },
    { message: "输入检测未完成，已保留原文；不代表安全。", variant: "error", sessionID: "session" },
  ]);
  assert.equal(typeof cleanup, "function");
  await cleanup!();
  assert.equal(stopped, true);
});
