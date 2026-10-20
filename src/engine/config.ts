import { readFile } from "node:fs/promises";
import { parseEnv } from "node:util";

// 只有该类的消息可直接用于 CLI 配置提示，内容不得含配置值。
export class JevConfigurationError extends Error {}

export async function loadJevConfig(envFile = ".env") {
  let file: Record<string, string | undefined> = {};
  try {
    file = parseEnv(await readFile(envFile, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw new JevConfigurationError("无法读取 Jev 环境配置文件");
    }
  }
  const names = ["JEV_API_KEY", "JEV_API_URL", "JEV_MODEL"] as const;
  const values = names.map((name) => (process.env[name] ?? file[name])?.trim());
  const missing = names.filter((_name, index) => !values[index]);
  if (missing.length) throw new JevConfigurationError(`缺少配置：${missing.join(", ")}`);
  return { apiKey: values[0]!, endpoint: values[1]!, model: values[2]! };
}
