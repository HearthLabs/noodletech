// POST /scan-sweep  (server only; schedule it every few minutes)
// Picks up releases stuck in 'scanning' (malware scan or sandbox still running) and tries again.
import { adminClient, safeEqual, scanPorts, serviceKey } from "../_shared/adapter.ts";
import { json } from "../_shared/handlers.ts";
import { scanRelease } from "../_shared/pipeline.ts";

const BATCH = 5; // stay inside the function time limit and VirusTotal's rate limit

Deno.serve(async (req) => {
  const token = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token || !safeEqual(token, serviceKey())) return json(401, { error: "server only" });

  const db = adminClient();
  const ports = scanPorts(db);
  const { data, error } = await db.from("releases").select("id").eq("status", "scanning").order("created_at").limit(BATCH);
  if (error) return json(500, { error: "could not list releases" });

  const results: Record<string, string> = {};
  for (const r of data ?? []) {
    try {
      const out = await scanRelease(ports, r.id);
      results[r.id] = out.state === "decided" ? `decided: ${out.decision}` : `pending: ${out.message}`;
    } catch (e) {
      results[r.id] = `failed: ${(e as Error).message}`;
    }
  }
  return json(200, { checked: Object.keys(results).length, results });
});
