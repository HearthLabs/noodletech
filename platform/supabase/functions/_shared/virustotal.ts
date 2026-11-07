// VirusTotal v3 client. [VERIFY] endpoints and the free-tier limits (about 4 requests a minute)
// against the current VirusTotal documentation before launch.

export type VtState = "clean" | "suspicious" | "malicious" | "pending" | "unavailable" | "error";

export interface VtResult {
  state: VtState;
  malicious: number;
  suspicious: number;
  total: number;
  message?: string;
}

export interface VtClient {
  check(
    file: { sha256: string; name: string; size: number },
    getBytes: () => Promise<Uint8Array>,
    canUpload: boolean,
  ): Promise<VtResult>;
}

const BASE = "https://www.virustotal.com/api/v3";
const SMALL_UPLOAD_LIMIT = 32 * 1024 * 1024;

// Thresholds. A handful of engines flag many harmless packaged Python/Electron apps,
// so a few detections go to a person; only many detections reject automatically.
export const MALICIOUS_REJECT_AT = 5;

export function classify(stats: Record<string, number>): VtResult {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const total = malicious + suspicious + (stats.undetected ?? 0) + (stats.harmless ?? 0);
  if (total === 0) return { state: "pending", malicious, suspicious, total, message: "analysis not finished" };
  if (malicious >= MALICIOUS_REJECT_AT) return { state: "malicious", malicious, suspicious, total };
  if (malicious >= 1 || suspicious >= 3) return { state: "suspicious", malicious, suspicious, total };
  return { state: "clean", malicious, suspicious, total };
}

export function makeVirusTotal(opts: { apiKey?: string; fetch?: typeof fetch }): VtClient {
  const f = opts.fetch ?? fetch;
  const headers = { "x-apikey": opts.apiKey ?? "" };

  async function upload(url: string, name: string, bytes: Uint8Array): Promise<Response> {
    const form = new FormData();
    form.append("file", new Blob([bytes as BlobPart]), name);
    return await f(url, { method: "POST", headers, body: form });
  }

  return {
    async check(file, getBytes, canUpload) {
      if (!opts.apiKey) {
        return { state: "unavailable", malicious: 0, suspicious: 0, total: 0, message: "VirusTotal is not configured" };
      }
      try {
        const res = await f(`${BASE}/files/${file.sha256}`, { headers });
        if (res.status === 429) return { state: "pending", malicious: 0, suspicious: 0, total: 0, message: "rate limited" };
        if (res.status === 200) {
          const body = await res.json();
          return classify(body?.data?.attributes?.last_analysis_stats ?? {});
        }
        if (res.status !== 404) {
          return { state: "error", malicious: 0, suspicious: 0, total: 0, message: `lookup failed (${res.status})` };
        }
        // Unknown to VirusTotal: submit it, then a later run finds the result by hash.
        if (!canUpload) {
          return { state: "error", malicious: 0, suspicious: 0, total: 0, message: "file unknown to VirusTotal and too large to submit" };
        }
        const bytes = await getBytes();
        let target = `${BASE}/files`;
        if (file.size > SMALL_UPLOAD_LIMIT) {
          const u = await f(`${BASE}/files/upload_url`, { headers });
          if (!u.ok) return { state: "pending", malicious: 0, suspicious: 0, total: 0, message: "could not get upload address" };
          target = (await u.json()).data;
        }
        const up = await upload(target, file.name, bytes);
        if (up.status === 429) return { state: "pending", malicious: 0, suspicious: 0, total: 0, message: "rate limited" };
        if (!up.ok) return { state: "error", malicious: 0, suspicious: 0, total: 0, message: `upload failed (${up.status})` };
        return { state: "pending", malicious: 0, suspicious: 0, total: 0, message: "submitted for analysis" };
      } catch (e) {
        return { state: "error", malicious: 0, suspicious: 0, total: 0, message: `request failed: ${(e as Error).message}` };
      }
    },
  };
}
