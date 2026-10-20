import type { DetectionResult, Detector, SecurityEvent } from "./types.ts";

export function createSecurityRuntime(detectors: readonly Detector[]) {
  return {
    async inspect(event: SecurityEvent): Promise<readonly DetectionResult[]> {
      const results: DetectionResult[] = [];
      for (const detector of detectors) {
        if (detector.hooks.includes(event.hook)) {
          results.push(await detector.evaluate(event));
        }
      }
      return results;
    },
  };
}

export type SecurityRuntime = ReturnType<typeof createSecurityRuntime>;
