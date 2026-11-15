// POST /listing-fee  { "app_id": "<uuid>", "renew": false }
// Caller: the app's developer (signed in). Starts a Stripe Checkout for whatever listing fee is
// due (new listing, renewal or upgrade to a bigger size) and returns { url } to send them to.
import { adminClient, feePorts } from "../_shared/adapter.ts";
import { corsHeaders, json } from "../_shared/handlers.ts";
import { handleListingFee } from "../_shared/fees.ts";

const ALLOWED = (Deno.env.get("ALLOWED_ORIGINS") ?? "https://noodletechnology.com")
  .split(",").map((s) => s.trim()).filter(Boolean);

async function handle(req: Request): Promise<Response> {
  if (req.method !== "POST") return json(405, { error: "POST only" });
  const token = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return json(401, { error: "sign in first" });
  let body: { app_id?: unknown; renew?: unknown };
  try { body = await req.json(); } catch { return json(400, { error: "send JSON" }); }
  const db = adminClient();
  const { data, error } = await db.auth.getUser(token);
  if (error || !data.user) return json(401, { error: "invalid session" });
  try {
    return await handleListingFee(body, { id: data.user.id, email: data.user.email }, feePorts(db));
  } catch (e) {
    console.error("listing fee checkout failed", (e as Error).message);
    return json(502, { error: "Couldn't start the payment. Try again in a moment." });
  }
}

Deno.serve(async (req) => {
  const cors = corsHeaders(req.headers.get("origin"), ALLOWED);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  const res = await handle(req);
  for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
  return res;
});
