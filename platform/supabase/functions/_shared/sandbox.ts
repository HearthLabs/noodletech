// Sandbox hook: run the program in an isolated Windows machine and report what it did.
// No provider is wired in yet. Plug one in by implementing SandboxProvider; until then the stage
// reports "skipped" and (by default) every release is routed to a person.

export interface SandboxReport {
  state: "clean" | "suspicious" | "malicious" | "pending" | "skipped" | "error";
  summary?: string;
  concerns?: string[]; // plain-language behaviors worth a person's attention
}

export interface SandboxProvider {
  run(file: { sha256: string; name: string }, getBytes: () => Promise<Uint8Array>): Promise<SandboxReport>;
}

export const notConfiguredSandbox: SandboxProvider = {
  run() {
    return Promise.resolve({ state: "skipped", summary: "no sandbox provider configured" });
  },
};
