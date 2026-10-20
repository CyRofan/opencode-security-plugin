import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parseDocument } from "yaml";
import { z } from "zod";
import type { SecurityRule } from "./contracts.ts";

const nonempty = z.string().min(1);
const ruleSchema = z.strictObject({
  schema_version: z.literal("0.1"), id: nonempty, title: nonempty,
  enabled: z.boolean(),
  domain: z.enum(["memory-poisoning", "tool-abuse", "resource-overload", "rce"]),
  severity: z.enum(["low", "medium", "high", "critical"]),
  detection: z.discriminatedUnion("method", [z.strictObject({
    method: z.literal("keyword"), mode: z.enum(["any", "all"]),
    keywords: z.array(nonempty).min(1), ignoreCase: z.boolean().default(true),
  }), z.strictObject({
    method: z.literal("regex"), pattern: nonempty,
    flags: z.string().regex(/^[imsu]*$/).refine((flags) => new Set(flags).size === flags.length, "Duplicate flags"),
  })]),
});

export async function loadRules(directory: string) {
  const names = (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && /\.ya?ml$/i.test(entry.name))
    .map((entry) => entry.name).sort();
  const rules: SecurityRule[] = [];
  const ids = new Set<string>();
  for (const name of names) {
    const document = parseDocument(await readFile(join(directory, name), "utf8"), { prettyErrors: false });
    if (document.errors.length || document.warnings.length) throw new Error(`Invalid YAML: ${name}`);
    const parsed = ruleSchema.safeParse(document.toJS());
    if (!parsed.success) {
      throw new Error(`Invalid rule ${name}: ${parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ")}`);
    }
    if (ids.has(parsed.data.id)) throw new Error(`Duplicate rule ID: ${parsed.data.id}`);
    ids.add(parsed.data.id);
    if (parsed.data.detection.method === "regex") {
      try { new RegExp(parsed.data.detection.pattern, parsed.data.detection.flags); }
      catch { throw new Error(`Invalid regex: ${name}`); }
    }
    rules.push(parsed.data);
  }
  return { rules, version: createHash("sha256").update(JSON.stringify(rules)).digest("hex") };
}
