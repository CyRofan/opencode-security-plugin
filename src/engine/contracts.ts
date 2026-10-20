import type { DetectionDomain, Finding } from "../core/types.ts";

export type Verdict = "benign" | "malicious" | "uncertain";

export interface TextInput {
  readonly content: string;
  readonly source: string;
  readonly context?: string;
}

// 原文 UTF-16 半开区间，可直接使用 content.slice(start, end)。
export interface Evidence {
  readonly text: string;
  readonly start: number;
  readonly end: number;
}

export interface RuleMatch {
  readonly ruleID: string;
  readonly domain: DetectionDomain;
  readonly severity: Finding["severity"];
  readonly evidence: readonly Evidence[];
}

export interface SecurityRule {
  readonly schema_version: "0.1";
  readonly id: string;
  readonly title: string;
  readonly enabled: boolean;
  readonly domain: DetectionDomain;
  readonly severity: Finding["severity"];
  readonly detection: {
    readonly method: "keyword";
    readonly mode: "any" | "all";
    readonly keywords: readonly string[];
    readonly ignoreCase: boolean;
  } | {
    readonly method: "regex";
    readonly pattern: string;
    readonly flags: string;
  };
}

export interface PatternStage {
  readonly status: "completed" | "failed" | "not-run";
  readonly matches: readonly RuleMatch[];
  readonly error?: string;
  readonly durationMs: number;
}

export interface JudgeStage {
  readonly status: "completed" | "failed" | "not-run";
  readonly verdict?: Verdict;
  readonly reason?: string;
  readonly evidence: readonly Evidence[];
  readonly error?: string;
  readonly durationMs: number;
}

// 外部模型/适配器的返回值始终在引擎边界校验，不信任静态类型。
export interface Judge {
  assess(input: TextInput & { readonly instruction: string }): Promise<unknown>;
}

export interface TextDetectionResult {
  readonly verdict: Verdict;
  readonly reason: string;
  readonly ruleVersion: string;
  readonly stages: { readonly keyword: PatternStage; readonly regex: PatternStage; readonly judge: JudgeStage };
  readonly durationMs: number;
}

export interface AtrRuleAdapter {
  adapt(document: unknown): SecurityRule;
}
