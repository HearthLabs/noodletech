// Shared types for the scan pipeline and the download function.

export type Verdict = "clean" | "suspicious" | "malicious" | "error" | "skipped";
export type Stage = "file_checks" | "malware_scan" | "static_analysis" | "sandbox" | "listing_check";
export type Outcome = "green" | "yellow" | "red";

export interface FileRow {
  id: string;
  kind: "executable" | "document";
  file_name: string;
  storage_path: string;
  size_bytes: number;
  sha256: string;
}

export interface ReleaseBundle {
  release: { id: string; status: string; version: string; release_notes: string };
  app: { id: string; name: string; summary: string; description: string; developer_id: string };
  files: FileRow[];
}

/** One finding. red = reject and record a strike; yellow = send to a person. */
export interface Flag {
  level: "yellow" | "red";
  code: string;
  message: string;
  file?: string;
}

export interface StageResult {
  stage: Stage;
  engine: string;
  verdict: Verdict;
  detections: number;
  score: number; // 0-100 risk for this stage
  flags: Flag[];
  report: Record<string, unknown>; // never contains secrets, only masked previews
}
