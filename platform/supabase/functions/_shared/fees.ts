// Listing fees: starting a Stripe Checkout for the fee, and recording it when Stripe says it was paid.
// Written against small ports so it is tested without a network (tests/functions.test.ts).
import { isUuid, json } from "./handlers.ts";

export const TIER_LABEL: Record<number, string> = { 1: "up to 250 MB", 2: "250 MB to 1 GB" };
/** Must match listing_term() in migration 0006. */
export const TERM_YEARS = 3;

export interface Quote {
  developerId: string;
  appName: string;
  kind: "none" | "new" | "renewal" | "upgrade";
  tier: number;
  amountCents: number;
}

export interface FeePorts {
  /** The app's current quote, or null when the app does not exist. Throws "releases over 1 GB…" from the database. */
  quote(appId: string, renew: boolean): Promise<Quote | null>;
  /** Creates a Stripe Checkout session from form fields and returns its URL. */
  createCheckout(form: Record<string, string>): Promise<{ id: string; url: string }>;
  /** An extra fee an admin asked for, or null. */
  feeRequest(id: string): Promise<FeeRequest | null>;
  siteUrl: string;
}

export interface FeeRequest {
  id: string;
  appId: string;
  appName: string;
  developerId: string;
  amountCents: number;
  status: "open" | "paid" | "cancelled";
}

export function extraFeeForm(r: FeeRequest, siteUrl: string, email?: string): Record<string, string> {
  const meta = { purpose: "extra_fee", request_id: r.id, app_id: r.appId, amount_cents: String(r.amountCents) };
  const form: Record<string, string> = {
    mode: "payment",
    "line_items[0][quantity]": "1",
    "line_items[0][price_data][currency]": "usd",
    "line_items[0][price_data][unit_amount]": String(r.amountCents),
    "line_items[0][price_data][product_data][name]": `${r.appName}: extra hosting fee`,
    client_reference_id: r.appId,
    success_url: `${siteUrl}/developers/#/app/${r.appId}?paid=1`,
    cancel_url: `${siteUrl}/developers/#/app/${r.appId}`,
  };
  for (const [k, v] of Object.entries(meta)) {
    form[`metadata[${k}]`] = v;
    form[`payment_intent_data[metadata][${k}]`] = v;
  }
  if (email) form.customer_email = email;
  return form;
}

export function checkoutForm(appId: string, q: Quote, siteUrl: string, email?: string): Record<string, string> {
  const what = q.kind === "upgrade"
    ? `Listing upgrade to ${TIER_LABEL[q.tier]} (until your current year ends)`
    : `${TERM_YEARS} years of listing, releases ${TIER_LABEL[q.tier]}`;
  const meta = {
    purpose: "listing_fee", app_id: appId, kind: q.kind, tier: String(q.tier), amount_cents: String(q.amountCents),
  };
  const form: Record<string, string> = {
    mode: "payment",
    "line_items[0][quantity]": "1",
    "line_items[0][price_data][currency]": "usd",
    "line_items[0][price_data][unit_amount]": String(q.amountCents),
    "line_items[0][price_data][product_data][name]": `${q.appName}: ${what}`,
    client_reference_id: appId,
    success_url: `${siteUrl}/developers/#/app/${appId}?paid=1`,
    cancel_url: `${siteUrl}/developers/#/app/${appId}`,
  };
  for (const [k, v] of Object.entries(meta)) {
    form[`metadata[${k}]`] = v;
    form[`payment_intent_data[metadata][${k}]`] = v;
  }
  if (email) form.customer_email = email;
  return form;
}

/** POST /listing-fee {app_id, renew?} or {request_id} by the app's developer. Returns {url} to send them to Stripe. */
export async function handleListingFee(body: { app_id?: unknown; renew?: unknown; request_id?: unknown }, user: { id: string; email?: string }, ports: FeePorts): Promise<Response> {
  if (body.request_id !== undefined) {
    if (!isUuid(body.request_id)) return json(400, { error: "request_id must be a UUID" });
    const r = await ports.feeRequest(body.request_id);
    if (!r || r.developerId !== user.id) return json(404, { error: "fee request not found" });
    if (r.status !== "open") return json(409, { error: "This fee is already settled." });
    const session = await ports.createCheckout(extraFeeForm(r, ports.siteUrl, user.email));
    return json(200, { url: session.url });
  }
  if (!isUuid(body.app_id)) return json(400, { error: "app_id must be a UUID" });
  let q: Quote | null;
  try {
    q = await ports.quote(body.app_id, body.renew === true);
  } catch (e) {
    const m = (e as Error).message;
    if (/1 GB/.test(m)) return json(400, { error: "Releases over 1 GB are not accepted." });
    throw e;
  }
  if (!q || q.developerId !== user.id) return json(404, { error: "app not found" });
  if (q.kind === "none" || q.amountCents <= 0) return json(409, { error: "Nothing is due for this app right now." });
  const session = await ports.createCheckout(checkoutForm(body.app_id, q, ports.siteUrl, user.email));
  return json(200, { url: session.url });
}

// ------------------------------------------------------------------ webhook
/** Checks a Stripe-Signature header (v1, HMAC-SHA256 of "t.payload"). */
export async function verifyStripeSignature(
  payload: string, header: string | null, secret: string, nowSeconds = Math.floor(Date.now() / 1000), toleranceSeconds = 300,
): Promise<boolean> {
  if (!header || !secret) return false;
  const parts = header.split(",").map((p) => p.trim().split("="));
  const t = parts.find(([k]) => k === "t")?.[1];
  const sigs = parts.filter(([k]) => k === "v1").map(([, v]) => v);
  if (!t || !/^\d+$/.test(t) || sigs.length === 0) return false;
  if (Math.abs(nowSeconds - Number(t)) > toleranceSeconds) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${t}.${payload}`)));
  const expected = [...mac].map((b) => b.toString(16).padStart(2, "0")).join("");
  return sigs.some((s) => timingSafeHexEqual(s, expected));
}

function timingSafeHexEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

export interface WebhookPorts {
  recordPayment(p: { appId: string; kind: string; tier: number; amountCents: number; sessionId: string }): Promise<void>;
  recordExtraFee(p: { requestId: string; amountCents: number; sessionId: string }): Promise<void>;
}

type StripeEvent = { type?: string; data?: { object?: Record<string, unknown> } };

/** Handles a verified Stripe event. Anything that is not a paid listing fee is acknowledged and ignored. */
export async function handleStripeEvent(event: StripeEvent, ports: WebhookPorts): Promise<Response> {
  if (event.type !== "checkout.session.completed" && event.type !== "checkout.session.async_payment_succeeded") {
    return json(200, { ignored: event.type ?? "unknown" });
  }
  const s = event.data?.object ?? {};
  const meta = (s.metadata ?? {}) as Record<string, string>;
  if (meta.purpose !== "listing_fee" && meta.purpose !== "extra_fee") return json(200, { ignored: "not a listing fee" });
  if (s.payment_status !== "paid") return json(200, { waiting: "payment not finished" });
  if (meta.purpose === "extra_fee") {
    const amount = Number(meta.amount_cents);
    if (!isUuid(meta.request_id)) return json(400, { error: "extra fee metadata is incomplete" });
    if (typeof s.id !== "string" || s.amount_total !== amount || s.currency !== "usd") {
      return json(400, { error: "paid amount does not match the extra fee" });
    }
    await ports.recordExtraFee({ requestId: meta.request_id, amountCents: amount, sessionId: s.id });
    return json(200, { recorded: s.id });
  }
  const tier = Number(meta.tier), amount = Number(meta.amount_cents);
  if (!isUuid(meta.app_id) || !["new", "renewal", "upgrade"].includes(meta.kind) || ![1, 2].includes(tier)) {
    return json(400, { error: "listing fee metadata is incomplete" });
  }
  if (typeof s.id !== "string" || s.amount_total !== amount || s.currency !== "usd") {
    return json(400, { error: "paid amount does not match the listing fee" });
  }
  await ports.recordPayment({ appId: meta.app_id, kind: meta.kind, tier, amountCents: amount, sessionId: s.id });
  return json(200, { recorded: s.id });
}
