// Request handling for the two HTTP functions, written against ports so it can be tested.
import { type Ports, ScanError, scanRelease } from "./pipeline.ts";

/** Length-independent comparison so the service key cannot be guessed by timing. */
export function safeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < Math.max(ea.length, eb.length); i++) diff |= (ea[i] ?? 0) ^ (eb[i] ?? 0);
  return diff === 0;
}

export type Caller = { kind: "server" } | { kind: "user"; id: string };

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
}

/** Browser calls from the site need these headers. Only origins on the allow-list get them. */
export function corsHeaders(origin: string | null, allowed: string[]): Record<string, string> {
  if (!origin || !allowed.includes(origin)) return { vary: "origin" };
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type, apikey, x-client-info",
    "access-control-max-age": "600",
    vary: "origin",
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (s: unknown): s is string => typeof s === "string" && UUID.test(s);

/** A developer may scan their own releases; the server (cron, sweep) may scan any. */
export async function handleScan(releaseId: unknown, caller: Caller, ports: Ports): Promise<Response> {
  if (!isUuid(releaseId)) return json(400, { error: "release_id must be a UUID" });
  try {
    if (caller.kind === "user") {
      const bundle = await ports.load(releaseId);
      // Same answer for "missing" and "not yours" so ids cannot be probed.
      if (!bundle || bundle.app.developer_id !== caller.id) return json(404, { error: "release not found" });
    }
    const result = await scanRelease(ports, releaseId);
    if (result.state === "pending") return json(202, { status: "pending", message: result.message });
    return json(200, { status: "decided", decision: result.decision, outcome: result.outcome, reason: result.reason });
  } catch (e) {
    if (e instanceof ScanError) return json(e.status, { error: e.message });
    console.error("scan failed", (e as Error).message);
    return json(500, { error: "scan failed" });
  }
}

// ----------------------------------------------------------------- downloads
export interface DownloadPorts {
  /** Returns the storage path only when the file belongs to an approved release of a published app. */
  findPublicFile(fileId: string): Promise<{ storagePath: string; fileName: string; releaseId: string; kind: string } | null>;
  signedUrl(path: string, seconds: number, downloadName: string): Promise<string | null>;
  logDownload(releaseId: string): Promise<void>;
}

export const SIGNED_URL_SECONDS = 60;

export async function handleDownload(url: URL, ports: DownloadPorts): Promise<Response> {
  const id = url.searchParams.get("file");
  if (!isUuid(id)) return json(400, { error: "file must be a UUID" });
  const file = await ports.findPublicFile(id);
  if (!file) return json(404, { error: "not available" });
  const signed = await ports.signedUrl(file.storagePath, SIGNED_URL_SECONDS, file.fileName);
  if (!signed) return json(502, { error: "could not prepare the download" });
  if (file.kind === "executable") {
    // A failed counter must never block a download.
    try { await ports.logDownload(file.releaseId); } catch (e) { console.error("log_download failed", (e as Error).message); }
  }
  return new Response(null, { status: 302, headers: { location: signed, "cache-control": "no-store" } });
}
