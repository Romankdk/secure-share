// Tests for static/crypto.js, the browser-side encryption. Node 20+ ships the same Web Crypto API
// as browsers, so the exact file the browser loads is tested here.  Run: node --test tests/crypto.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DecryptionError,
  decryptBlob,
  encryptFile,
  fromBase64Url,
  isWellFormedKey,
  safeFilename,
  toBase64Url,
} from "../secure_share/static/crypto.js";

const sample = () => new File([new Uint8Array([1, 2, 3, 250, 251, 252])], "report 2026.pdf", { type: "application/pdf" });

test("roundtrip restores bytes, name and type", async () => {
  const { blob, key } = await encryptFile(sample());
  const out = await decryptBlob(blob, key);
  assert.deepEqual([...out.data], [1, 2, 3, 250, 251, 252]);
  assert.equal(out.name, "report 2026.pdf");
  assert.equal(out.type, "application/pdf");
});

test("ciphertext reveals neither the filename nor the content", async () => {
  const file = new File([new TextEncoder().encode("very secret text")], "passwords.txt", { type: "text/plain" });
  const { blob } = await encryptFile(file);
  const asText = new TextDecoder("latin1").decode(blob);
  assert.ok(!asText.includes("passwords"));
  assert.ok(!asText.includes("very secret"));
  // IV + 4-byte length + header + content + 16-byte tag
  assert.ok(blob.length > 12 + 16 + "very secret text".length);
});

test("every encryption uses a fresh key and IV", async () => {
  const a = await encryptFile(sample());
  const b = await encryptFile(sample());
  assert.notEqual(a.key, b.key);
  assert.notDeepEqual(a.blob.subarray(0, 12), b.blob.subarray(0, 12));
  assert.equal(fromBase64Url(a.key).length, 32); // 256-bit key
});

test("a wrong key fails with DecryptionError", async () => {
  const { blob } = await encryptFile(sample());
  const { key: otherKey } = await encryptFile(sample());
  await assert.rejects(decryptBlob(blob, otherKey), DecryptionError);
});

test("tampering with any part of the blob is detected", async () => {
  const { blob, key } = await encryptFile(sample());
  for (const index of [0, 12, blob.length - 1]) { // IV, ciphertext, auth tag
    const tampered = blob.slice();
    tampered[index] ^= 0x01;
    await assert.rejects(decryptBlob(tampered, key), DecryptionError, `byte ${index}`);
  }
  await assert.rejects(decryptBlob(blob.subarray(0, 20), key), DecryptionError); // truncated
});

test("key format checks", () => {
  const key = toBase64Url(new Uint8Array(32).fill(7));
  assert.ok(isWellFormedKey(key));
  assert.ok(!/[+/=]/.test(key)); // URL-safe, unpadded
  assert.ok(!isWellFormedKey(""));
  assert.ok(!isWellFormedKey(key.slice(0, -2)));
  assert.ok(!isWellFormedKey("not a key!"));
});

test("filenames from the encrypted header are made safe", () => {
  assert.equal(safeFilename("../../.ssh/authorized_keys"), "_.._.ssh_authorized_keys");
  assert.equal(safeFilename("C:\\Windows\\evil.exe"), "C__Windows_evil.exe");
  assert.equal(safeFilename("invoice\u202Efdp.exe"), "invoicefdp.exe"); // right-to-left override trick
  assert.equal(safeFilename("\u0000\u0007"), "download");
  assert.equal(safeFilename(".bashrc"), "bashrc");
  assert.equal(safeFilename("x".repeat(500)).length, 200);
  assert.equal(safeFilename("holiday photo.jpg"), "holiday photo.jpg");
});
