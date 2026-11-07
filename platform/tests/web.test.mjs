// Tests for the browser helpers that do not need a browser.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { Sha256, hashFile } from "../../assets/sha256.js";
import { validateSelection } from "../../assets/upload.js";
import { fmtBytes, safeUrl, slugify } from "../../assets/dom.js";

const ref = (b) => createHash("sha256").update(b).digest("hex");

test("sha256: matches the standard on empty input and known values", () => {
  assert.equal(new Sha256().hex(), ref(Buffer.alloc(0)));
  assert.equal(new Sha256().update(Buffer.from("abc")).hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});
test("sha256: matches the standard at every length around block boundaries", () => {
  for (let n = 0; n <= 200; n++) {
    const b = randomBytes(n);
    assert.equal(new Sha256().update(b).hex(), ref(b), `length ${n}`);
  }
});
test("sha256: result does not depend on how the data is split into pieces", () => {
  const b = randomBytes(10_000);
  for (const step of [1, 7, 63, 64, 65, 1000, 4096]) {
    const s = new Sha256();
    for (let i = 0; i < b.length; i += step) s.update(b.subarray(i, i + step));
    assert.equal(s.hex(), ref(b), `step ${step}`);
  }
});
test("sha256: a file bigger than one slice hashes correctly with progress", async () => {
  const b = randomBytes(9 * 1024 * 1024 + 123);
  const seen = [];
  const hex = await hashFile(new Blob([b]), (p) => seen.push(p));
  assert.equal(hex, ref(b));
  assert.equal(seen.at(-1), 1);
  assert.ok(seen.length >= 3);
});

const f = (name, size = 10) => ({ name, size });
test("upload checks: a good selection has no problems", () => {
  assert.deepEqual(validateSelection(f("App.exe"), [f("Manual.pdf"), f("README.md"), f("License.txt")]), []);
});
test("upload checks: wrong types, empty files, odd names and duplicates are explained", () => {
  assert.match(validateSelection(null, [])[0], /Choose the program/);
  assert.match(validateSelection(f("setup.msi"), [])[0], /must be a \.exe/);
  assert.match(validateSelection(f("App.exe"), [f("guide.docx")])[0], /PDF, TXT or Markdown/);
  assert.match(validateSelection(f("App.exe"), [f("a.zip")])[0], /PDF, TXT or Markdown/);
  assert.match(validateSelection(f("App.exe", 0), [])[0], /is empty/);
  assert.match(validateSelection(f("../App.exe"), []).join(" "), /file names may use/);
  assert.match(validateSelection(f("App.exe"), [f("app.EXE.txt"), f("APP.exe.TXT")]).join(" "), /Two files are named/);
  assert.match(validateSelection(f("App.exe", 6 * 1024 ** 3), []).join(" "), /larger than 5 GB/);
});
test("upload checks: at most 20 files", () => {
  const docs = Array.from({ length: 20 }, (_, i) => f(`d${i}.txt`));
  assert.match(validateSelection(f("App.exe"), docs).join(" "), /at most 20/);
});
test("helpers: sizes, safe links and web addresses", () => {
  assert.equal(fmtBytes(512), "512 B"); assert.equal(fmtBytes(1536), "1.5 KB"); assert.equal(fmtBytes(5 * 1024 ** 2), "5.0 MB");
  assert.equal(safeUrl("https://example.com/x"), "https://example.com/x");
  assert.equal(safeUrl("javascript:alert(1)"), null); assert.equal(safeUrl("data:text/html,x"), null); assert.equal(safeUrl("not a url"), null);
  assert.equal(slugify("My Cool App!"), "my-cool-app"); assert.equal(slugify("  Ünïcode — Tool "), "unicode-tool");
});
