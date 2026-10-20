import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import type { TestContext } from "node:test";
import { stringify } from "yaml";
import type { Verdict } from "../src/engine/contracts.ts";

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

export function jevResponse(choice: Verdict) {
  return { model: "jev-test-version", answers: { injection: { type: "choice", choice,
    probabilities: { benign: choice === "benign" ? 1 : 0, malicious: choice === "malicious" ? 1 : 0, uncertain: choice === "uncertain" ? 1 : 0 },
    confidence: 1,
  } } };
}

export const benign = jevResponse("benign");
export const malicious = jevResponse("malicious");
