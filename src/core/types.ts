import type { TextDetectionResult, TextInput } from "../engine/contracts.ts";

export type DetectionDomain =
  | "memory-poisoning"
  | "tool-abuse"
  | "resource-overload"
  | "rce";

export type SecurityHook =
  | "session.prompt"
  | "session.context"
  | "session.compaction"
  | "session.generate"
  | "session.title"
  | "session.model.request"
  | "session.http.response"
  | "session.experimental.ws.receive"
  | "session.retry"
  | "tool.execute.before"
  | "tool.execute.after"
  | "permission.evaluate"
  | "shell.create.before"
  | "runtime.event";

export interface SecurityEvent {
  readonly hook: SecurityHook;
  readonly timestamp: number;
  readonly sessionID?: string;
  readonly messageID?: string;
  readonly text?: TextInput;
  // 原始 SDK 事件仅在内存中传递；仅 prompt 正文已独立提取，流解析尚未实现。
  readonly payload: unknown;
}

export interface Finding {
  readonly domain: DetectionDomain;
  readonly ruleID: string;
  readonly severity: "low" | "medium" | "high" | "critical";
  readonly reason: string;
}

export interface DetectionResult {
  readonly domain: DetectionDomain;
  readonly status: "not-implemented" | "evaluated" | "unavailable" | "skipped";
  readonly findings: readonly Finding[];
  readonly text?: TextDetectionResult;
  readonly reason?: string;
}

export interface Detector {
  readonly domain: DetectionDomain;
  readonly hooks: readonly SecurityHook[];
  evaluate(event: SecurityEvent): Promise<DetectionResult>;
}

// 检测事实与处置决定分离，策略求值和执行留待后续实现。
export interface SecurityDecision {
  readonly action: "allow" | "alert" | "block";
  readonly reason: string;
}
