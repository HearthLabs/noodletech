// Turns all stage results into one outcome for the database function record_scan_decision.
import type { Flag, Outcome, StageResult } from "./types.ts";

const RED_WEIGHT = 60;
const YELLOW_WEIGHT = 15;

export interface Summary {
  outcome: Outcome;
  score: number; // 0-100, higher is riskier
  reason: string;
}

export function summarize(results: StageResult[]): Summary {
  const flags: Flag[] = results.flatMap((r) => r.flags);
  const reds = flags.filter((f) => f.level === "red");
  const yellows = flags.filter((f) => f.level === "yellow");
  const outcome: Outcome = reds.length > 0 ? "red" : yellows.length > 0 ? "yellow" : "green";
  const score = Math.min(100, reds.length * RED_WEIGHT + yellows.length * YELLOW_WEIGHT);

  const describe = (f: Flag) => (f.file ? `${f.file} ${f.message}` : f.message);
  let reason: string;
  if (outcome === "green") {
    reason = "All automated checks passed";
  } else {
    // Most serious first, so the person reading the log sees the cause immediately.
    reason = [...reds, ...yellows].map(describe).join("; ");
  }
  if (reason.length > 800) reason = reason.slice(0, 797) + "...";
  return { outcome, score, reason };
}
