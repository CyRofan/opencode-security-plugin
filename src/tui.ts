import type { Definition } from "@opencode/plugin/tui/plugin";
import { noticeSchema, SecurityRpc } from "./rpc.ts";

export default {
  id: "opencode-security-plugin.tui",
  setup(context) {
    return context.client.rpc(SecurityRpc).events.on("notice", (event) => {
      const parsed = noticeSchema.safeParse(event.data);
      if (!parsed.success) return;
      const notice = parsed.data;
      const incomplete = Object.values(notice.stages).some((stage) => stage !== "completed");
      context.ui.toast.show({
        sessionID: notice.sessionID,
        variant: incomplete ? "error" : "warning",
        message: notice.applied ? "输入已替换，请重新提交具体任务。"
          : incomplete ? "输入检测未完成，已保留原文；不代表安全。" : "输入判断不确定，已保留原文。",
      });
    });
  },
} satisfies Definition;
