import type { DetectionResult, SecurityDecision } from "./types.ts";

export const replacementText = "本条输入检测到越权操纵风险，已由安全插件替换。请重新提交具体任务。";

interface Prompt {
  text: string;
  files?: { mention?: { start: number; end: number; text: string } }[];
  skills?: { mention?: { start: number; end: number; text: string } }[];
  agents?: { mention?: { start: number; end: number; text: string } }[];
}

export function applyPromptDecision(prompt: Prompt, result: DetectionResult): SecurityDecision {
  const text = result.text;
  const complete = text && Object.values(text.stages).every((stage) => stage.status === "completed");
  const action = complete && text.verdict === "malicious" ? "replace"
    : complete && text.verdict === "benign" ? "allow" : "alert";
  if (action === "replace") {
    prompt.text = replacementText;
    for (const attachment of [...(prompt.files ?? []), ...(prompt.skills ?? []), ...(prompt.agents ?? [])]) {
      const mention = attachment.mention;
      if (mention && (mention.start < 0 || mention.end < mention.start || prompt.text.slice(mention.start, mention.end) !== mention.text)) {
        delete attachment.mention;
      }
    }
  }
  return { action, applied: action === "replace", reason: text?.reason ?? result.reason ?? "detection-unavailable" };
}
