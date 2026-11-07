// Looks inside files for things that should not ship: embedded keys and passwords.
// Findings are reported as a type plus a masked preview. The full value is never stored or logged.

export interface SecretHit {
  type: string;
  preview: string; // first characters only
}

const PATTERNS: { type: string; re: RegExp }[] = [
  { type: "Anthropic API key", re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { type: "OpenAI API key", re: /sk-(?:proj-)?[A-Za-z0-9_-]{32,}/g },
  { type: "AWS access key", re: /AKIA[0-9A-Z]{16}/g },
  { type: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { type: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/g },
  { type: "Stripe live key", re: /sk_live_[0-9a-zA-Z]{24,}/g },
  { type: "Slack token", re: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { type: "Hugging Face token", re: /hf_[A-Za-z0-9]{34,}/g },
  { type: "Private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g },
];
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

const CHUNK = 4 * 1024 * 1024;
const OVERLAP = 512;
const MAX_HITS = 20;

function mask(value: string): string {
  return value.slice(0, 6) + "…";
}

function jwtIsPrivileged(token: string): boolean {
  try {
    const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(atob(payload + "=".repeat((4 - (payload.length % 4)) % 4)));
    return json.role === "service_role";
  } catch {
    return false;
  }
}

/** Text views of a chunk: single-byte text, and UTF-16 text at both alignments (common in .NET apps). */
function views(chunk: Uint8Array): string[] {
  const latin = new TextDecoder("latin1").decode(chunk);
  const u16a = new TextDecoder("utf-16le").decode(chunk.subarray(0, chunk.length - (chunk.length % 2)));
  const rest = chunk.subarray(1);
  const u16b = new TextDecoder("utf-16le").decode(rest.subarray(0, rest.length - (rest.length % 2)));
  return [latin, u16a, u16b];
}

export function findSecrets(buf: Uint8Array): SecretHit[] {
  const seen = new Set<string>();
  const hits: SecretHit[] = [];
  for (let start = 0; start < buf.length && hits.length < MAX_HITS; start += CHUNK) {
    const chunk = buf.subarray(start, Math.min(buf.length, start + CHUNK + OVERLAP));
    for (const text of views(chunk)) {
      for (const { type, re } of PATTERNS) {
        re.lastIndex = 0;
        for (const m of text.matchAll(re)) {
          // The Anthropic pattern also matches the OpenAI one: report the more specific type once.
          if (type === "OpenAI API key" && m[0].startsWith("sk-ant-")) continue;
          const key = type + ":" + m[0];
          if (seen.has(key)) continue;
          seen.add(key);
          hits.push({ type, preview: mask(m[0]) });
          if (hits.length >= MAX_HITS) return hits;
        }
      }
      JWT_RE.lastIndex = 0;
      for (const m of text.matchAll(JWT_RE)) {
        if (!jwtIsPrivileged(m[0])) continue;
        const key = "jwt:" + m[0];
        if (seen.has(key)) continue;
        seen.add(key);
        hits.push({ type: "Supabase service-role key", preview: mask(m[0]) });
      }
    }
  }
  return hits;
}

/** Domains the file contains links to. Used as context for the listing check; not a verdict. */
export function findDomains(buf: Uint8Array, limit = 40): string[] {
  const domains = new Set<string>();
  const re = /https?:\/\/([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/gi;
  for (let start = 0; start < buf.length && domains.size < limit; start += CHUNK) {
    const chunk = buf.subarray(start, Math.min(buf.length, start + CHUNK + OVERLAP));
    for (const text of views(chunk)) {
      for (const m of text.matchAll(re)) {
        domains.add(m[1].toLowerCase());
        if (domains.size >= limit) break;
      }
    }
  }
  return [...domains].sort();
}
