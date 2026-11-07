// Checks for the document types a release may carry: .pdf, .txt, .md
import type { Flag } from "./types.ts";

const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const PDF_RISKS: { token: string; code: string; message: string }[] = [
  { token: "/JavaScript", code: "pdf_javascript", message: "contains embedded JavaScript" },
  { token: "/JS", code: "pdf_javascript", message: "contains embedded JavaScript" },
  { token: "/Launch", code: "pdf_launch", message: "can launch programs" },
  { token: "/EmbeddedFile", code: "pdf_embedded_file", message: "contains an embedded file" },
];

export function checkDocument(name: string, buf: Uint8Array): Flag[] {
  const flags: Flag[] = [];
  const lower = name.toLowerCase();

  // A document that is really a program is deceptive: reject it.
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    flags.push({ level: "red", code: "document_is_executable", message: "is a Windows program disguised as a document", file: name });
    return flags;
  }

  if (lower.endsWith(".pdf")) {
    const head = new TextDecoder("latin1").decode(buf.subarray(0, Math.min(buf.length, 1024)));
    if (!head.includes("%PDF-")) {
      flags.push({ level: "yellow", code: "pdf_bad_header", message: "is not a valid PDF", file: name });
      return flags;
    }
    const text = new TextDecoder("latin1").decode(buf);
    const reported = new Set<string>();
    for (const r of PDF_RISKS) {
      // Match the token as a PDF name: followed by a delimiter, not a longer word.
      const re = new RegExp(r.token.replace("/", "\\/") + "(?![A-Za-z])");
      if (re.test(text) && !reported.has(r.code)) {
        reported.add(r.code);
        flags.push({ level: "yellow", code: r.code, message: r.message, file: name });
      }
    }
    return flags;
  }

  // .txt and .md must be plain readable text.
  if (buf.length > MAX_TEXT_BYTES) {
    flags.push({ level: "yellow", code: "text_too_large", message: "is unusually large for a text document", file: name });
    return flags;
  }
  if (buf.includes(0)) {
    flags.push({ level: "yellow", code: "text_has_binary", message: "contains binary data", file: name });
    return flags;
  }
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(buf);
  } catch {
    flags.push({ level: "yellow", code: "text_not_utf8", message: "is not valid UTF-8 text", file: name });
  }
  return flags;
}
