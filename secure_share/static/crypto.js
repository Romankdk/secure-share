// End-to-end encryption for secure-share, using the browser's built-in Web Crypto API.
//
// Everything secret is handled here, in the browser. The server receives only the output of
// encryptFile(): an opaque blob. The key travels in the link's #fragment, which browsers never send
// to the server, so the server cannot decrypt anything it stores.
//
// Plaintext layout (what gets encrypted):
//   [4-byte big-endian header length][JSON header {name, type}][file bytes]
// Encrypted blob layout (what gets uploaded):
//   [12-byte IV][ciphertext + 16-byte GCM authentication tag]
//
// The filename and MIME type are inside the encrypted part on purpose: "tax-return-2026.pdf" is
// itself sensitive, and the server has no need to know it.

const ALGORITHM = "AES-GCM";
const KEY_BITS = 256;
const KEY_BYTES = KEY_BITS / 8;
// 96-bit IVs are what GCM is designed for. A fresh random IV per file matters: reusing an IV with
// the same key breaks GCM badly. Here every file also gets its own fresh key, so even an IV
// collision couldn't cause reuse.
const IV_BYTES = 12;
const HEADER_LEN_BYTES = 4;
// The header is a short JSON object; anything bigger means the data is corrupt or hostile.
const MAX_HEADER_BYTES = 64 * 1024;

export class DecryptionError extends Error {}

// --- base64url (RFC 4648 §5): URL-safe, no padding, so the key survives in a link ---------------

export function toBase64Url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new DecryptionError("The key in this link is malformed.");
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** True if `text` decodes to a 256-bit key. Checked before downloading so a mistyped link doesn't
 *  waste a one-time download on something that could never decrypt. */
export function isWellFormedKey(text) {
  try {
    return fromBase64Url(text).length === KEY_BYTES;
  } catch {
    return false;
  }
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(new Uint8Array(p.buffer ?? p, p.byteOffset ?? 0, p.byteLength), offset);
    offset += p.byteLength;
  }
  return out;
}

// --- encrypt -------------------------------------------------------------------------------------

/**
 * Encrypt a file for upload.
 * @param {{name: string, type: string, arrayBuffer: () => Promise<ArrayBuffer>}} file  a File/Blob
 * @returns {Promise<{blob: Uint8Array, key: string}>} the upload body and the base64url key for the link
 */
export async function encryptFile(file) {
  // crypto.subtle uses the operating system's secure random generator. Never Math.random().
  // extractable=true only because we must export the key once, to put it in the link.
  const key = await crypto.subtle.generateKey({ name: ALGORITHM, length: KEY_BITS }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const header = new TextEncoder().encode(JSON.stringify({ name: file.name, type: file.type || "" }));
  const headerLen = new Uint8Array(HEADER_LEN_BYTES);
  new DataView(headerLen.buffer).setUint32(0, header.byteLength, false);
  const plaintext = concat(headerLen, header, new Uint8Array(await file.arrayBuffer()));

  // GCM is "authenticated encryption": besides hiding the data, it appends a 16-byte tag that
  // makes any change to the ciphertext (by the server, or anyone in between) fail decryption,
  // instead of silently producing a corrupted or attacker-modified file.
  const ciphertext = await crypto.subtle.encrypt({ name: ALGORITHM, iv }, key, plaintext);
  const rawKey = await crypto.subtle.exportKey("raw", key);
  return { blob: concat(iv, new Uint8Array(ciphertext)), key: toBase64Url(rawKey) };
}

// --- decrypt -------------------------------------------------------------------------------------

/**
 * Decrypt a downloaded blob.
 * @returns {Promise<{name: string, type: string, data: Uint8Array}>}
 * @throws {DecryptionError} wrong key, tampered data, or a malformed file
 */
export async function decryptBlob(buffer, keyText) {
  const rawKey = fromBase64Url(keyText);
  if (rawKey.length !== KEY_BYTES) throw new DecryptionError("The key in this link is the wrong length.");
  const bytes = new Uint8Array(buffer);
  if (bytes.length < IV_BYTES + 16 + HEADER_LEN_BYTES) throw new DecryptionError("The file is too short to be valid.");

  // extractable=false: once imported for decryption, the key can't be read back out by script.
  const key = await crypto.subtle.importKey("raw", rawKey, { name: ALGORITHM }, false, ["decrypt"]);
  let plaintext;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt({ name: ALGORITHM, iv: bytes.subarray(0, IV_BYTES) }, key, bytes.subarray(IV_BYTES)),
    );
  } catch {
    // Web Crypto deliberately reports only "it failed": a wrong key and a modified file look the
    // same, and no partial plaintext is ever released.
    throw new DecryptionError("Decryption failed: the key is wrong or the file was tampered with.");
  }

  // Even authenticated plaintext gets bounds-checked before use.
  const headerLen = new DataView(plaintext.buffer, plaintext.byteOffset, HEADER_LEN_BYTES).getUint32(0, false);
  if (headerLen > MAX_HEADER_BYTES || HEADER_LEN_BYTES + headerLen > plaintext.length) {
    throw new DecryptionError("The file's header is malformed.");
  }
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(plaintext.subarray(HEADER_LEN_BYTES, HEADER_LEN_BYTES + headerLen)));
  } catch {
    throw new DecryptionError("The file's header is malformed.");
  }
  return {
    name: typeof header.name === "string" ? header.name : "",
    type: typeof header.type === "string" ? header.type : "",
    data: plaintext.subarray(HEADER_LEN_BYTES + headerLen),
  };
}

/**
 * Make an uploader-supplied filename safe to save. The name came out of the encrypted header, so
 * it was chosen by whoever uploaded the file: strip path separators and control characters so it
 * can't point outside the downloads folder or confuse the save dialog.
 */
export function safeFilename(name) {
  const cleaned = String(name)
    .replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, "") // control + bidi-override chars
    .replace(/[\\/:*?"<>|]/g, "_")
    .replace(/^[.\s]+/, "")
    .trim()
    .slice(0, 200);
  return cleaned || "download";
}
