import type { DetectionDomain, Finding, SecurityEvent, SecurityHook } from "../core/types.ts";

// 本项目的最小模型，并非 ATR wire format；解析和校验尚未实现。
export interface SecurityRule {
  readonly schema_version: "0.1";
  readonly id: string;
  readonly title: string;
  readonly enabled: boolean;
  readonly domain: DetectionDomain;
  readonly hooks: readonly SecurityHook[];
  readonly severity: Finding["severity"];
  readonly detection:
    | { readonly method: "keyword"; readonly keywords: readonly string[] }
    | { readonly method: "regex"; readonly pattern: string }
    | { readonly method: "judge"; readonly instruction: string };
}

export interface RuleEvaluator {
  evaluate(event: SecurityEvent, rules: readonly SecurityRule[]): Promise<readonly Finding[]>;
}

export interface Judge {
  assess(input: { readonly content: string; readonly instruction: string }): Promise<{
    readonly verdict: "benign" | "malicious" | "uncertain";
    readonly reason: string;
  }>;
}

export interface RuleSource {
  load(): Promise<readonly SecurityRule[]>;
}

export interface AtrRuleAdapter {
  adapt(document: unknown): SecurityRule;
}
