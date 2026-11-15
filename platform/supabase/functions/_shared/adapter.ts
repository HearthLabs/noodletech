// Connects the pipeline to Supabase. This file is the only place that knows about the database.
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Ports } from "./pipeline.ts";
import type { DownloadPorts } from "./handlers.ts";
import type { FeePorts, Quote, WebhookPorts } from "./fees.ts";
import { makeVirusTotal } from "./virustotal.ts";
import { notConfiguredSandbox } from "./sandbox.ts";
import { makeListingReviewer } from "./listing.ts";

const BUCKET = "app-files";

export function adminClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set");
  return createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
}

export function serviceKey(): string {
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
}

export { safeEqual } from "./handlers.ts";

function must<T>(r: { data: T; error: { message: string } | null }, what: string): NonNullable<T> {
  if (r.error) throw new Error(`${what}: ${r.error.message}`);
  if (r.data === null || r.data === undefined) throw new Error(`${what}: nothing returned`);
  return r.data as NonNullable<T>;
}

export function scanPorts(db: SupabaseClient): Ports {
  const num = (name: string, fallback: number) => {
    const v = Number(Deno.env.get(name));
    return Number.isFinite(v) && Deno.env.get(name) !== undefined && Deno.env.get(name) !== "" ? v : fallback;
  };
  return {
    config: {
      // Safe default: without a sandbox, nothing is auto-approved. Set REQUIRE_SANDBOX=false only on purpose.
      requireSandbox: Deno.env.get("REQUIRE_SANDBOX") !== "false",
      spotRate: num("SPOT_RATE", 0.05),
      maxAutoBytes: num("MAX_AUTO_BYTES", 64 * 1024 * 1024),
    },
    vt: makeVirusTotal({ apiKey: Deno.env.get("VIRUSTOTAL_API_KEY") }),
    sandbox: notConfiguredSandbox,
    listing: makeListingReviewer({ apiKey: Deno.env.get("ANTHROPIC_API_KEY"), model: Deno.env.get("LISTING_MODEL") ?? undefined }),

    async load(id) {
      const rel = await db.from("releases").select("id,status,version,release_notes,app_id").eq("id", id).maybeSingle();
      if (rel.error) throw new Error(`load release: ${rel.error.message}`);
      if (!rel.data) return null;
      const app = must(
        await db.from("apps").select("id,name,summary,description,developer_id").eq("id", rel.data.app_id).single(),
        "load app",
      );
      const files = must(
        await db.from("release_files").select("id,kind,file_name,storage_path,size_bytes,sha256").eq("release_id", id),
        "load files",
      );
      const { app_id: _drop, ...release } = rel.data;
      return { release, app, files };
    },
    async readFile(path) {
      const r = await db.storage.from(BUCKET).download(path);
      if (r.error || !r.data) throw new Error(`read file: ${r.error?.message ?? "empty"}`);
      return new Uint8Array(await r.data.arrayBuffer());
    },
    async markScanning(id) {
      const r = await db.from("releases").update({ status: "scanning" }).eq("id", id).in("status", ["uploaded", "scanning"]);
      if (r.error) throw new Error(`mark scanning: ${r.error.message}`);
    },
    async clearScans(id) {
      const r = await db.from("scans").delete().eq("release_id", id);
      if (r.error) throw new Error(`clear scans: ${r.error.message}`);
    },
    async saveScan(id, res) {
      const r = await db.from("scans").insert({
          release_id: id, stage: res.stage, engine: res.engine, verdict: res.verdict,
          detections: res.detections, score: res.score,
          report: { ...res.report, flags: res.flags.map((f) => ({ level: f.level, code: f.code, file: f.file })) },
        });
      if (r.error) throw new Error(`save scan: ${r.error.message}`);
    },
    async decide(id, outcome, score, reason, spotRate) {
      const r = await db.rpc("record_scan_decision", {
        p_release: id, p_outcome: outcome, p_score: Math.round(score), p_reason: reason, p_spot_rate: spotRate,
      });
      if (r.error) throw new Error(`record decision: ${r.error.message}`);
      return String(r.data);
    },
  };
}

export function downloadPorts(db: SupabaseClient): DownloadPorts {
  return {
    async findPublicFile(fileId) {
      // The public view only lists files of approved releases of published apps.
      const pub = await db.from("published_release_files").select("id,release_id,file_name,kind,app_price_cents").eq("id", fileId).maybeSingle();
      if (pub.error) throw new Error(`lookup: ${pub.error.message}`);
      if (!pub.data) return null;
      const row = must(await db.from("release_files").select("storage_path").eq("id", fileId).single(), "lookup path");
      return {
        storagePath: row.storage_path, fileName: pub.data.file_name, releaseId: pub.data.release_id, kind: pub.data.kind,
        paid: Number(pub.data.app_price_cents) > 0,
      };
    },
    async signedUrl(path, seconds, downloadName) {
      const r = await db.storage.from(BUCKET).createSignedUrl(path, seconds, { download: downloadName });
      return r.data?.signedUrl ?? null;
    },
    async logDownload(releaseId) {
      const r = await db.rpc("log_download", { p_release: releaseId });
      if (r.error) throw new Error(`log download: ${r.error.message}`);
    },
  };
}

export function feePorts(db: SupabaseClient): FeePorts {
  const stripeKey = Deno.env.get("STRIPE_SECRET_KEY") ?? "";
  return {
    siteUrl: (Deno.env.get("SITE_URL") ?? "https://noodletechnology.com").replace(/\/$/, ""),
    async quote(appId, renew) {
      const app = await db.from("apps").select("developer_id,name").eq("id", appId).maybeSingle();
      if (app.error) throw new Error(`load app: ${app.error.message}`);
      if (!app.data) return null;
      const q = await db.rpc("_listing_fee_quote", { p_app: appId, p_renew: renew });
      if (q.error) throw new Error(q.error.message);
      const row = (q.data as Array<{ kind: Quote["kind"]; tier: number; amount_cents: number }>)[0];
      return { developerId: app.data.developer_id, appName: app.data.name, kind: row.kind, tier: row.tier, amountCents: row.amount_cents };
    },
    async feeRequest(id) {
      const r = await db.from("fee_requests").select("id,app_id,developer_id,amount_cents,status, apps(name)").eq("id", id).maybeSingle();
      if (r.error) throw new Error(`load fee request: ${r.error.message}`);
      if (!r.data) return null;
      const app = r.data.apps as unknown as { name: string } | null;
      return {
        id: r.data.id, appId: r.data.app_id, developerId: r.data.developer_id, appName: app?.name ?? "Your app",
        amountCents: r.data.amount_cents, status: r.data.status,
      };
    },
    async createCheckout(form) {
      if (!stripeKey) throw new Error("STRIPE_SECRET_KEY is not set");
      const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
        method: "POST",
        headers: { authorization: `Bearer ${stripeKey}`, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(form),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(`stripe: ${body?.error?.message ?? res.status}`);
      return { id: body.id, url: body.url };
    },
  };
}

export function webhookPorts(db: SupabaseClient): WebhookPorts {
  return {
    async recordPayment(p) {
      const r = await db.rpc("record_listing_payment", {
        p_app: p.appId, p_kind: p.kind, p_tier: p.tier, p_amount_cents: p.amountCents, p_session: p.sessionId,
      });
      if (r.error) throw new Error(`record payment: ${r.error.message}`);
    },
    async recordExtraFee(p) {
      const r = await db.rpc("record_fee_request_payment", { p_request: p.requestId, p_amount_cents: p.amountCents, p_session: p.sessionId });
      if (r.error) throw new Error(`record extra fee: ${r.error.message}`);
    },
  };
}
