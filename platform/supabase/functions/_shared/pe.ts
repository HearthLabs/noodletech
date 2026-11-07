// Minimal Windows executable (PE) inspector. It reads headers only; it never runs anything.
// It does not verify signatures cryptographically: it reports whether one is embedded.

export interface PeSection {
  name: string;
  rawSize: number;
  rawPtr: number;
  flags: number;
  entropy: number;
}

export interface PeInfo {
  valid: boolean;
  error?: string;
  machine?: string;
  is64?: boolean;
  isDll?: boolean;
  subsystem?: number;
  sections: PeSection[];
  signaturePresent: boolean;
  overlayBytes: number;
  packer?: string;
  likelyPacked: boolean;
}

const PACKER_SECTIONS: Record<string, string> = {
  "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
  ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma",
  ".petite": "Petite", "MPRESS1": "MPRESS", "MPRESS2": "MPRESS", ".nsp0": "NsPack",
  ".nsp1": "NsPack", ".perplex": "PELock", ".boom": "Boomerang",
};

const MACHINES: Record<number, string> = { 0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64" };
const IMAGE_FILE_DLL = 0x2000;
const IMAGE_SCN_CNT_CODE = 0x20;

export function entropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / bytes.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function fail(error: string): PeInfo {
  return { valid: false, error, sections: [], signaturePresent: false, overlayBytes: 0, likelyPacked: false };
}

export function analyzePe(buf: Uint8Array): PeInfo {
  if (buf.length < 0x40) return fail("file too small to be an executable");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (dv.getUint16(0, true) !== 0x5a4d) return fail("missing MZ header");
  const peOff = dv.getUint32(0x3c, true);
  if (peOff < 0x40 || peOff + 24 > buf.length) return fail("bad PE header offset");
  if (dv.getUint32(peOff, true) !== 0x00004550) return fail("missing PE signature");

  const machine = dv.getUint16(peOff + 4, true);
  const numSections = dv.getUint16(peOff + 6, true);
  const optSize = dv.getUint16(peOff + 20, true);
  const characteristics = dv.getUint16(peOff + 22, true);
  const optStart = peOff + 24;
  if (numSections === 0 || numSections > 96) return fail("implausible section count");
  if (optStart + optSize > buf.length || optSize < 70) return fail("truncated optional header");

  const magic = dv.getUint16(optStart, true);
  if (magic !== 0x10b && magic !== 0x20b) return fail("unknown optional header type");
  const is64 = magic === 0x20b;
  const subsystem = dv.getUint16(optStart + 68, true);
  const dirsOff = optStart + (is64 ? 112 : 96);
  const numDirs = dv.getUint32(optStart + (is64 ? 108 : 92), true);

  let certOff = 0;
  let certSize = 0;
  if (numDirs > 4 && dirsOff + 5 * 8 <= optStart + optSize) {
    certOff = dv.getUint32(dirsOff + 4 * 8, true); // certificate table address is a FILE offset
    certSize = dv.getUint32(dirsOff + 4 * 8 + 4, true);
  }

  const secStart = optStart + optSize;
  if (secStart + numSections * 40 > buf.length) return fail("truncated section table");

  const sections: PeSection[] = [];
  let lastEnd = 0;
  let packer: string | undefined;
  let likelyPacked = false;
  for (let i = 0; i < numSections; i++) {
    const o = secStart + i * 40;
    let name = "";
    for (let j = 0; j < 8 && buf[o + j] !== 0; j++) name += String.fromCharCode(buf[o + j]);
    const rawSize = dv.getUint32(o + 16, true);
    const rawPtr = dv.getUint32(o + 20, true);
    const flags = dv.getUint32(o + 36, true);
    const end = rawPtr + rawSize;
    if (rawPtr > buf.length || end > buf.length) {
      // Sections that point outside the file are a classic sign of a malformed or tampered binary.
      return fail(`section ${name || i} points outside the file`);
    }
    lastEnd = Math.max(lastEnd, end);
    const sample = buf.subarray(rawPtr, Math.min(end, rawPtr + 4 * 1024 * 1024));
    const ent = entropy(sample);
    sections.push({ name, rawSize, rawPtr, flags, entropy: ent });
    if (PACKER_SECTIONS[name]) packer = PACKER_SECTIONS[name];
    if ((flags & IMAGE_SCN_CNT_CODE) !== 0 && rawSize > 4096 && ent > 7.2) likelyPacked = true;
  }
  if (packer) likelyPacked = true;

  const signaturePresent = certSize > 0 && certOff > 0 && certOff + certSize <= buf.length;
  const overlayBytes = Math.max(0, buf.length - lastEnd - (signaturePresent && certOff >= lastEnd ? certSize : 0));

  return {
    valid: true,
    machine: MACHINES[machine] ?? `0x${machine.toString(16)}`,
    is64,
    isDll: (characteristics & IMAGE_FILE_DLL) !== 0,
    subsystem,
    sections,
    signaturePresent,
    overlayBytes,
    packer,
    likelyPacked,
  };
}
