// The scan pipeline. It talks to the outside world only through `Ports`, so the whole thing can
// be tested with fakes. Stages: file checks -> malware scan -> static analysis -> sandbox ->
// listing check -> one decision recorded in the database.
import type { FileRow, Flag, ReleaseBundle, StageResult } from "./types.ts";
import type { VtClient } from "./virustotal.ts";
import type { SandboxProvider } from "./sandbox.ts";
import type { ListingReviewer } from "./listing.ts";
import { analyzePe } from "./pe.ts";
import { findDomains, findSecrets } from "./strings.ts";
import { checkDocument } from "./documents.ts";
import { summarize } from "./scoring.ts";

export interface Config {
  requireSandbox: boolean; // true: a release cannot be auto-approved without a sandbox run
  spotRate: number; // share of clean releases from trusted developers sent to a person anyway
  maxAutoBytes: number; // larger files get hash-only checks and go to a person
}

export interface Ports {
  load(releaseId: string): Promise<ReleaseBundle | null>;
  readFile(path: string): Promise<Uint8Array>;
  markScanning(releaseId: string): Promise<void>;
  clearScans(releaseId: string): Promise<void>;
  saveScan(releaseId: string, r: StageResult): Promise<void>;
  decide(releaseId: string, outcome: string, score: number, reason: string, spotRate: number): Promise<string>;
  vt: VtClient;
  sandbox: SandboxProvider;
  listing: ListingReviewer;
  config: Config;
}

export class ScanError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export type ScanOutcome =
  | { state: "decided"; decision: string; outcome: string; score: number; reason: string }
  | { state: "pending"; message: string };

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function stage(
  stage: StageResult["stage"], engine: string, flags: Flag[], report: Record<string, unknown>,
  verdict?: StageResult["verdict"],
): StageResult {
  const score = Math.min(100, flags.reduce((n, f) => n + (f.level === "red" ? 60 : 15), 0));
  const v = verdict ?? (flags.some((f) => f.level === "red") ? "malicious" : flags.length ? "suspicious" : "clean");
  return { stage, engine, verdict: v, detections: flags.length, score, flags, report };
}

export async function scanRelease(ports: Ports, releaseId: string): Promise<ScanOutcome> {
  const bundle = await ports.load(releaseId);
  if (!bundle) throw new ScanError(404, "release not found");
  const { release, app, files } = bundle;
  if (release.status !== "uploaded" && release.status !== "scanning") {
    throw new ScanError(409, `release is ${release.status}, not waiting for a scan`);
  }
  if (!files.some((f) => f.kind === "executable")) {
    throw new ScanError(422, "add the executable before scanning");
  }

  await ports.markScanning(releaseId);
  await ports.clearScans(releaseId); // a re-run replaces earlier attempts with fresh stage results

  const { maxAutoBytes } = ports.config;
  const cache = new Map<string, Uint8Array>();
  const bytesOf = async (f: FileRow) => {
    let b = cache.get(f.id);
    if (!b) {
      b = await ports.readFile(f.storage_path);
      cache.set(f.id, b);
    }
    return b;
  };
  const small = (f: FileRow) => f.size_bytes <= maxAutoBytes;

  // ---- 1. file checks: type, checksum, structure
  const fileFlags: Flag[] = [];
  const fileReport: Record<string, unknown> = {};
  const pe: Record<string, ReturnType<typeof analyzePe>> = {};
  for (const f of files) {
    if (!small(f)) {
      fileFlags.push({ level: "yellow", code: "too_large", message: "is too large for automated analysis", file: f.file_name });
      continue;
    }
    const bytes = await bytesOf(f);
    if (bytes.length !== f.size_bytes) {
      fileFlags.push({ level: "yellow", code: "size_mismatch", message: "size differs from the upload record", file: f.file_name });
    }
    if ((await sha256Hex(bytes)) !== f.sha256) {
      fileFlags.push({ level: "yellow", code: "checksum_mismatch", message: "does not match the checksum recorded at upload", file: f.file_name });
    }
    if (f.kind === "executable") {
      const info = analyzePe(bytes);
      pe[f.id] = info;
      fileReport[f.file_name] = {
        valid: info.valid, error: info.error, machine: info.machine, dll: info.isDll,
        sections: info.sections.map((s) => ({ name: s.name, entropy: Number(s.entropy.toFixed(2)) })),
      };
      if (!info.valid) {
        fileFlags.push({ level: "yellow", code: "not_a_program", message: `is not a valid Windows program (${info.error})`, file: f.file_name });
      } else if (info.isDll) {
        fileFlags.push({ level: "yellow", code: "is_dll", message: "is a library (DLL), not a standalone program", file: f.file_name });
      }
    } else {
      fileFlags.push(...checkDocument(f.file_name, bytes));
    }
  }
  const stage1 = stage("file_checks", "noodle-file-checks", fileFlags, { files: fileReport });

  // ---- 2. malware scan (VirusTotal)
  const vtFlags: Flag[] = [];
  const vtReport: Record<string, unknown> = {};
  let pending: string | null = null;
  let vtMalicious = 0;
  for (const f of files) {
    const r = await ports.vt.check(
      { sha256: f.sha256, name: f.file_name, size: f.size_bytes },
      () => bytesOf(f),
      small(f),
    );
    vtReport[f.file_name] = { state: r.state, malicious: r.malicious, suspicious: r.suspicious, engines: r.total, note: r.message };
    vtMalicious += r.malicious;
    if (r.state === "pending") pending = pending ?? `${f.file_name}: ${r.message ?? "waiting for malware scan"}`;
    else if (r.state === "malicious") {
      vtFlags.push({ level: "red", code: "malware", message: `flagged as malware by ${r.malicious} antivirus engines`, file: f.file_name });
    } else if (r.state === "suspicious") {
      vtFlags.push({ level: "yellow", code: "av_suspicious", message: `flagged by ${r.malicious} antivirus engine(s)`, file: f.file_name });
    } else if (r.state === "unavailable" || r.state === "error") {
      vtFlags.push({ level: "yellow", code: "malware_scan_unavailable", message: `malware scan could not run (${r.message ?? r.state})`, file: f.file_name });
    }
  }
  if (pending) {
    // Save what is finished so far and ask to be called again; no decision yet.
    await ports.saveScan(releaseId, stage1);
    return { state: "pending", message: pending };
  }
  const stage2 = stage("malware_scan", "virustotal", vtFlags, { files: vtReport }, undefined);
  stage2.detections = vtMalicious;

  // ---- 3. static analysis: packers, embedded keys
  const staticFlags: Flag[] = [];
  const staticReport: Record<string, unknown> = {};
  const domains = new Set<string>();
  let anySignature = false;
  let packer: string | undefined;
  for (const f of files) {
    if (!small(f)) continue;
    const bytes = await bytesOf(f);
    const info = pe[f.id];
    if (info?.valid) {
      if (info.likelyPacked) {
        packer = info.packer ?? packer;
        staticFlags.push({
          level: "yellow", code: "packed",
          message: info.packer ? `is packed with ${info.packer}` : "looks packed or encrypted", file: f.file_name,
        });
      }
      if (info.signaturePresent) anySignature = true;
    }
    const secrets = findSecrets(bytes);
    if (secrets.length > 0) {
      const types = [...new Set(secrets.map((s) => s.type))];
      staticFlags.push({ level: "yellow", code: "embedded_secret", message: `contains what looks like an embedded ${types.join(", ")}`, file: f.file_name });
    }
    if (f.kind === "executable") for (const d of findDomains(bytes)) domains.add(d);
    staticReport[f.file_name] = {
      signature: info?.valid ? (info.signaturePresent ? "present_unverified" : "none") : undefined,
      packer: info?.packer, secretsFound: secrets.map((s) => ({ type: s.type, preview: s.preview })),
    };
  }
  const stage3 = stage("static_analysis", "noodle-static", staticFlags, { files: staticReport, domains: [...domains].slice(0, 40) });

  // ---- 4. sandbox
  const sandboxFlags: Flag[] = [];
  let sandboxReport: Record<string, unknown> = {};
  let sandboxVerdict: StageResult["verdict"] = "clean";
  let sandboxRan = false;
  for (const f of files.filter((x) => x.kind === "executable" && small(x))) {
    const r = await ports.sandbox.run({ sha256: f.sha256, name: f.file_name }, () => bytesOf(f));
    sandboxReport[f.file_name] = { state: r.state, summary: r.summary };
    if (r.state === "pending") {
      pending = pending ?? `${f.file_name}: sandbox run in progress`;
    } else if (r.state === "skipped") {
      sandboxVerdict = "skipped";
    } else {
      sandboxRan = true;
      if (r.state === "malicious") sandboxFlags.push({ level: "red", code: "sandbox_malicious", message: "behaved like malware in the test environment", file: f.file_name });
      else if (r.state === "suspicious" || r.state === "error" || (r.concerns && r.concerns.length)) {
        const why = r.concerns?.length ? r.concerns.join(", ") : r.summary ?? r.state;
        sandboxFlags.push({ level: "yellow", code: "sandbox_concern", message: `showed unusual behavior in the test environment: ${why}`, file: f.file_name });
      }
    }
  }
  if (pending) {
    await ports.saveScan(releaseId, stage1);
    await ports.saveScan(releaseId, stage2);
    return { state: "pending", message: pending };
  }
  if (!sandboxRan && ports.config.requireSandbox) {
    sandboxFlags.push({ level: "yellow", code: "sandbox_unavailable", message: "was not run in a test environment (none available), so a person must check it" });
  }
  const stage4 = stage("sandbox", "sandbox", sandboxFlags, sandboxReport, sandboxRan ? undefined : sandboxVerdict);

  // ---- 5. listing check (can only add concerns)
  const listing = await ports.listing.review({
    name: app.name, summary: app.summary, description: app.description,
    files: files.map((f) => f.file_name), domains: [...domains].slice(0, 40),
    signaturePresent: anySignature, packer,
  });
  const listingFlags: Flag[] = (listing?.concerns ?? []).map((c) => ({ level: "yellow" as const, code: "listing_concern", message: `listing: ${c}` }));
  const stage5 = stage("listing_check", "listing-review", listingFlags, { concerns: listing?.concerns ?? [] }, listing ? undefined : "skipped");

  // ---- save every stage, then decide once
  const all = [stage1, stage2, stage3, stage4, stage5];
  for (const s of all) await ports.saveScan(releaseId, s);
  const { outcome, score, reason } = summarize(all);
  const decision = await ports.decide(releaseId, outcome, score, reason, ports.config.spotRate);
  return { state: "decided", decision, outcome, score, reason };
}
