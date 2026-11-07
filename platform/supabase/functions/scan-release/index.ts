// POST /scan-release  { "release_id": "<uuid>" }
// Caller: a signed-in developer (their own release only) or the server (cron / sweep).
// Returns 200 decided, 202 pending (call again later), 4xx for problems the caller can fix.
import { adminClient, safeEqual, scanPorts, serviceKey } from "../_shared/adapter.ts";
import { type Caller, corsHeaders, handleScan, json } from "../_shared/handlers.ts";

const ALLOWED = (Deno.env.get("ALLOWED_ORIGINS") ?? "https://noodletechnology.com")
  .split(",").map((s) => s.trim()).filter(Boolean);

async function handle(req: Request): Promise<Response> {
  if (req.method !== "POST") return json(405, { error: "POST only" });
  const token = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return json(401, { error: "sign in first" });

  let body: { release_id?: unknown };
  try { body = await req.json(); } catch { return json(400, { error: "send JSON" }); }

  const db = adminClient();
  let caller: Caller;
  if (safeEqual(token, serviceKey())) {
    caller = { kind: "server" };
  } else {
    const { data, error } = await db.auth.getUser(token);
    if (error || !data.user) return json(401, { error: "invalid session" });
    caller = { kind: "user", id: data.user.id };
  }
  return await handleScan(body.release_id, caller, scanPorts(db));
}

Deno.serve(async (req) => {
  const cors = corsHeaders(req.headers.get("origin"), ALLOWED);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  const res = await handle(req);
  for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
  return res;
});
