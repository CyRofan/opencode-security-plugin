import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import type { TestContext } from "node:test";
import { stringify } from "yaml";

export function rule(id = "LOCAL-001", detection: object = {
  method: "keyword", mode: "any", keywords: ["ignore previous instructions"],
}) {
  return { schema_version: "0.1", id, title: "投毒检测示例", enabled: true,
    domain: "memory-poisoning", severity: "high", detection };
}

export async function rulesDirectory(t: TestContext, rules: unknown[] = [rule()]) {
  const directory = await mkdtemp(join(tmpdir(), "opencode-security-"));
  t.after(async () => {
    assert.equal(dirname(directory), resolve(tmpdir()));
    assert.ok(basename(directory).startsWith("opencode-security-"));
    await rm(directory, { recursive: true, force: true });
  });
  for (const [index, value] of rules.entries()) {
    await writeFile(join(directory, `${index}.yaml`), stringify(value));
  }
  return directory;
}

export const benign = { verdict: "benign", reason: "正常内容", evidence: [] };
export const malicious = { verdict: "malicious", reason: "试图改变任务目标", evidence: [] };
