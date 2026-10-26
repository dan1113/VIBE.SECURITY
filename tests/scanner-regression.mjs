import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import vm from "node:vm";

const html = await readFile(process.env.SCANNER_HTML || new URL("../public/index.html", import.meta.url), "utf8");
const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)?.[1];
assert.ok(script, "scanner script exists in the Site page");

const elements = new Map();
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, { style: {}, setAttribute() {}, open: false, showModal() { this.open = true; }, close() { this.open = false; }, classList: { add() {}, remove() {}, toggle() {} }, append() {}, replaceChildren() {} });
    return elements.get(id);
  },
  createElement() { return { style: {}, append() {}, remove() {}, click() {} }; },
};
const context = {
  document, Blob, Response, TextDecoder, TextEncoder, DataView, Uint8Array, Uint32Array,
  DecompressionStream, URL, console, navigator: { clipboard: { writeText: async () => {} } },
  setTimeout, clearTimeout, fetch: async () => new Response(JSON.stringify({count:0})), localStorage: {getItem(){return "0"}},
};
context.window = context;
vm.createContext(context);
vm.runInContext(`${script}\nglobalThis.__scanZip = scanZip;`, context);
const scanZip = context.__scanZip;

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function makeZip(files, { corruptCrc = false, declaredFirstSize } = {}) {
  const local = [];
  const central = [];
  let localOffset = 0;
  for (const [name, source] of files) {
    const nameBytes = Buffer.from(name);
    const data = Buffer.from(source);
    const crc = (crc32(data) ^ (corruptCrc ? 1 : 0)) >>> 0;
    const declaredSize = declaredFirstSize && local.length === 0 ? declaredFirstSize : data.length;
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(nameBytes.length, 26);
    local.push(localHeader, nameBytes, data);

    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt16LE(0, 8);
    record.writeUInt16LE(0, 10);
    record.writeUInt32LE(crc, 16);
    record.writeUInt32LE(data.length, 20);
    record.writeUInt32LE(declaredSize, 24);
    record.writeUInt16LE(nameBytes.length, 28);
    record.writeUInt32LE(localOffset, 42);
    central.push(record, nameBytes);
    localOffset += localHeader.length + nameBytes.length + data.length;
  }
  const localBytes = Buffer.concat(local);
  const centralBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localBytes.length, 16);
  return Buffer.concat([localBytes, centralBytes, end]);
}

function archiveFile(bytes) {
  return { size: bytes.length, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
}

test("finds a secret, masks the value, and scans long minified output under dist", async () => {
  const zip = makeZip([
    [".env", "API_KEY=live_7f8d2a9c4e6b1f3a5d7c9e2a"],
    ["src/example.js", "const API_KEY = 'your_api_key_goes_here_123456';"],
    ["dist/index.html", `${" ".repeat(5000)}eval(userInput)`],
  ]);
  const report = await scanZip(archiveFile(zip));
  assert.equal(report.files_scanned, 3);
  assert.equal(report.counts["높음"], 2);
  assert.ok(report.issues.some((issue) => issue.file === "dist/index.html" && issue.rule === "DANGEROUS_EVAL"));
  assert.ok(report.issues.some((issue) => issue.rule === "SECRET_KEY" && issue.excerpt.includes("[숨김 처리]")));
  assert.ok(!report.issues.some((issue) => issue.file === "src/example.js"));
  assert.ok(!JSON.stringify(report).includes("live_7f8d2a9c4e6b1f3a5d7c9e2a"));
});

test("does not flag bound SQL or fixed HTML, but catches a composed SQL query", async () => {
  const zip = makeZip([
    ["src/db.js", `db.prepare("SELECT * FROM users WHERE id = ?").bind(id);\nconst q = "SELECT name FROM users WHERE name = '" + name + "'";`],
    ["src/view.js", `el.innerHTML = '<p>fixed content</p>';`],
  ]);
  const report = await scanZip(archiveFile(zip));
  assert.equal(report.issues.filter((issue) => issue.rule === "SQL_INJECTION").length, 1);
  assert.equal(report.issues.filter((issue) => issue.rule === "XSS_SINK").length, 0);
});

test("rejects a ZIP whose file contents fail the CRC check", async () => {
  const zip = makeZip([["src/app.js", "const ready = true;"]], { corruptCrc: true });
  await assert.rejects(scanZip(archiveFile(zip)), /손상됐거나 내용이 일치하지 않습니다/);
});

test("does not scan paths that try to escape the archive folder", async () => {
  const zip = makeZip([["../outside.js", "eval(userInput)"]]);
  await assert.rejects(scanZip(archiveFile(zip)), /검사할 코드 파일/);
});

test("rejects ZIP entries whose declared total size exceeds the scan limit", async () => {
  const zip = makeZip([["src/large.js", "x"]], { declaredFirstSize: 80 * 1024 * 1024 + 1 });
  await assert.rejects(scanZip(archiveFile(zip)), /80MB/);
});

test("shows the limitations warning before scanning and lets the user cancel or continue", async () => {
  const input = elements.get("file");
  input.files = [archiveFile(makeZip([["src/app.js", "const ready = true;"]]))];
  const warning = elements.get("warningDialog");
  const status = elements.get("status");

  elements.get("scan").onclick();
  assert.equal(warning.open, true);
  assert.notEqual(status.textContent, "진단 완료");
  elements.get("cancelScan").onclick();
  assert.equal(warning.open, false);

  elements.get("scan").onclick();
  await elements.get("confirmScan").onclick();
  assert.equal(warning.open, false);
  assert.equal(status.textContent, "진단 완료");
});

test("detects variable and function HTML assignments", async () => {
 const report=await scanZip(archiveFile(makeZip([["view.js", "el.innerHTML = userInput;\ndocument.write(request.query.html);\nel.innerHTML = renderUserComment(comment);"]])));
 assert.equal(report.issues.filter(x=>x.rule==="XSS_SINK").length,3);
});
test("keeps fixed HTML and explicit sanitizer excluded", async () => {
 const report=await scanZip(archiveFile(makeZip([["view.js", "el.innerHTML = '<p>fixed</p>';\nel.innerHTML = DOMPurify.sanitize(userInput);"]])));
 assert.equal(report.issues.filter(x=>x.rule==="XSS_SINK").length,0);
});
test("detects quoted secrets and environment variants without exposing values", async () => {
 const secret="live_0123456789abcdef0123456789";
 const report=await scanZip(archiveFile(makeZip([["config.json", JSON.stringify({api_key:secret})],[".env.production", "API_KEY="+secret]])));
 assert.equal(report.files_scanned,2);
 assert.equal(report.issues.filter(x=>x.rule==="SECRET_KEY").length,2);
 assert.ok(!JSON.stringify(report).includes(secret));
});
test("detects Python SQL f-string interpolation", async () => {
 const report=await scanZip(archiveFile(makeZip([["db.py", 'sql = f"SELECT * FROM users WHERE id = {user_id}"']])));
 assert.equal(report.issues.filter(x=>x.rule==="SQL_INJECTION").length,1);
});
test("does not call an image-only ZIP a completed clean scan", async () => {
 await assert.rejects(scanZip(archiveFile(makeZip([["cover.png","image"]]))), /검사할 코드 파일/);
});
test("reads a real deflated ZIP and its three code files", async () => {
 const report=await scanZip(archiveFile(Buffer.from("UEsDBBQAAAAIALpyWl1bfy5xGwAAABkAAAALAAAAc3JjL3ZpZXcuanNLzdHLzMtLLfII8fVRsFUoLU4t8swrKC2xBgBQSwMEFAAAAAgAunJaXcoU8bkwAAAAMQAAAAkAAABzcmMvZGIucHkrLsxRsFVIUwp29XF1DlHQUnAL8vdVKC1OLSpWCPdwDXJVyEwBKqgGicRnptQqAQBQSwMEFAAAAAgAunJaXSzHxYggAAAAJwAAAA8AAAAuZW52LnByb2R1Y3Rpb25zDPCM93aNtM3JLEuNNzA0MjYxNTO3sExMSk5JTUPwAVBLAQIUAxQAAAAIALpyWl1bfy5xGwAAABkAAAALAAAAAAAAAAAAAACAAQAAAABzcmMvdmlldy5qc1BLAQIUAxQAAAAIALpyWl3KFPG5MAAAADEAAAAJAAAAAAAAAAAAAACAAUQAAABzcmMvZGIucHlQSwECFAMUAAAACAC6clpdLMfFiCAAAAAnAAAADwAAAAAAAAAAAAAAgAGbAAAALmVudi5wcm9kdWN0aW9uUEsFBgAAAAADAAMArQAAAOgAAAAAAA==","base64")));
 assert.equal(report.files_scanned,3);
 assert.ok(report.issues.some(x=>x.rule==="XSS_SINK"));
 assert.ok(report.issues.some(x=>x.rule==="SQL_INJECTION"));
 assert.ok(report.issues.some(x=>x.rule==="SECRET_KEY"));
});
