// POST /stripe-webhook  (called by Stripe)
// Verifies the Stripe-Signature header, then records paid listing fees. Deploy with --no-verify-jwt.
import { adminClient, webhookPorts } from "../_shared/adapter.ts";
import { json } from "../_shared/handlers.ts";
import { handleStripeEvent, verifyStripeSignature } from "../_shared/fees.ts";

Deno.serve(async (req) => {
  if (req.method !== "POST") return json(405, { error: "POST only" });
  const payload = await req.text();
  const ok = await verifyStripeSignature(payload, req.headers.get("stripe-signature"), Deno.env.get("STRIPE_WEBHOOK_SECRET") ?? "");
  if (!ok) return json(400, { error: "bad signature" });
  try {
    return await handleStripeEvent(JSON.parse(payload), webhookPorts(adminClient()));
  } catch (e) {
    // A 500 makes Stripe retry, which is what we want if the database was briefly unreachable.
    console.error("stripe webhook failed", (e as Error).message);
    return json(500, { error: "could not record the event" });
  }
});
