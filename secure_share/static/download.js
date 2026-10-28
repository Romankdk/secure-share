// Download page: fetch ciphertext, decrypt it in the browser, save it under its original name.

import { DecryptionError, decryptBlob, isWellFormedKey, safeFilename } from "./crypto.js";

const status = document.getElementById("status");
const details = document.getElementById("details");
const button = document.getElementById("download");

const fileId = location.pathname.split("/").pop();
// The key is everything after "#". It never left this browser: not in the request for this page,
// not in Referer headers, not in server logs.
const key = location.hash.slice(1);

function show(text, kind = "") {
  status.textContent = text; // never innerHTML
  status.className = `status ${kind}`.trim();
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function formatSize(bytes) {
  return bytes < 1024 * 1024 ? `${Math.ceil(bytes / 1024)} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function apiError(response) {
  const body = await response.json().catch(() => ({}));
  if (response.status === 410) return "This link has expired and the file has been deleted.";
  if (response.status === 404) return "This file doesn't exist. It may have already been downloaded, deleted, or expired.";
  return body.error || `Something went wrong (HTTP ${response.status}).`;
}

async function loadInfo() {
  if (!key) {
    return show("This link is missing its decryption key (the part after #). Ask the sender for the full link.", "error");
  }
  if (!isWellFormedKey(key)) {
    return show("The decryption key in this link is damaged. Ask the sender for the full link.", "error");
  }
  // /info is read-only on the server, so loading this page never uses up a download.
  const response = await fetch(`/api/files/${encodeURIComponent(fileId)}/info`);
  if (!response.ok) return show(await apiError(response), "error");
  const info = await response.json();
  details.textContent =
    `Encrypted file, ${formatSize(info.size)}. ${plural(info.downloads_left, "download")} left; ` +
    `expires ${new Date(info.expires_at * 1000).toLocaleString()}.`;
  show(info.downloads_left === 1 ? "This is a one-time link: the file is deleted after you download it." : "");
  button.hidden = false;
}

button.addEventListener("click", async () => {
  button.disabled = true;
  try {
    show("Downloading…");
    const response = await fetch(`/api/files/${encodeURIComponent(fileId)}`);
    if (!response.ok) {
      show(await apiError(response), "error");
      // 404/410: the file is gone for good. Anything else (e.g. a 500) didn't count a download,
      // so let the user try again.
      button.hidden = response.status === 404 || response.status === 410;
      button.disabled = false;
      return;
    }
    const left = Number(response.headers.get("X-Downloads-Left"));

    show("Decrypting…");
    const { name, data } = await decryptBlob(await response.arrayBuffer(), key);

    // Always save as application/octet-stream, never the stored MIME type. That type was chosen by
    // the uploader; a blob: URL inherits this site's origin, so a "text/html" blob opened in the
    // browser could run the uploader's script here. octet-stream is only ever downloaded.
    const url = URL.createObjectURL(new Blob([data], { type: "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = safeFilename(name);
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);

    details.textContent = `Saved as "${safeFilename(name)}".`;
    show(left > 0 ? `Done. ${plural(left, "download")} left on this link.` : "Done. This link has now self-destructed.", "ok");
    button.hidden = left <= 0;
    button.disabled = false;
  } catch (err) {
    // A wrong or tampered key fails here, AFTER the server counted the download: the server can't
    // tell a good key from a bad one, because it never sees keys. That's the price of zero knowledge.
    if (err instanceof DecryptionError) {
      // Retrying with the same key can only fail again and would waste another download.
      show(err.message, "error");
      button.hidden = true;
    } else {
      show("Something went wrong while downloading. Please try again.", "error");
      button.disabled = false;
    }
  }
});

loadInfo().catch(() => show("Could not reach the server.", "error"));
