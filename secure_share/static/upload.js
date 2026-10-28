// Upload page: encrypt in the browser, upload only ciphertext, then show the share link.

import { encryptFile } from "./crypto.js";

const MAX_FILE_BYTES = 25 * 1024 * 1024;

const form = document.getElementById("upload-form");
const fileInput = document.getElementById("file");
const submit = document.getElementById("submit");
const status = document.getElementById("status");
const result = document.getElementById("result");
const linkField = document.getElementById("link");
const copyButton = document.getElementById("copy");
const deleteButton = document.getElementById("delete");
const resultInfo = document.getElementById("result-info");

// Held only in memory for this page. Closing the tab forgets the delete token, which is fine:
// the link expires on its own.
let current = null;

function setStatus(text, kind = "") {
  status.textContent = text; // textContent, never innerHTML: no string here is ever parsed as HTML
  status.className = `status ${kind}`.trim();
}

// XMLHttpRequest instead of fetch() because fetch can't report upload progress.
function uploadBlob(formData, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/files");
    xhr.responseType = "json";
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    xhr.onload = () => {
      if (xhr.status === 201) resolve(xhr.response);
      else reject(new Error(xhr.response?.error || `Upload failed (HTTP ${xhr.status}).`));
    };
    xhr.onerror = () => reject(new Error("Network error during upload."));
    xhr.send(formData);
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = fileInput.files[0];
  if (!file) return setStatus("Choose a file first.", "error");
  if (file.size > MAX_FILE_BYTES) return setStatus("That file is over the 25 MB limit.", "error");

  submit.disabled = true;
  result.hidden = true;
  try {
    setStatus("Encrypting…");
    const { blob, key } = await encryptFile(file);

    const formData = new FormData();
    // The multipart filename is a fixed dummy: the real name is inside the encrypted blob.
    formData.append("blob", new Blob([blob], { type: "application/octet-stream" }), "blob.bin");
    formData.append("expires", form.expires.value);
    formData.append("max_downloads", form.max_downloads.value);

    setStatus("Uploading… 0%");
    const response = await uploadBlob(formData, (p) => setStatus(`Uploading… ${Math.round(p * 100)}%`));

    // The key goes after "#": browsers never send the fragment to the server.
    const link = `${location.origin}/f/${response.id}#${key}`;
    current = { id: response.id, deleteToken: response.delete_token };
    linkField.value = link;
    const downloads = Number(form.max_downloads.value);
    resultInfo.textContent =
      `Expires ${new Date(response.expires_at * 1000).toLocaleString()} or after ` +
      `${downloads} download${downloads === 1 ? "" : "s"}, whichever comes first.`;
    result.hidden = false;
    deleteButton.disabled = false;
    setStatus("Done. Only people with this exact link can open the file.", "ok");
    form.reset();
  } catch (err) {
    setStatus(err.message || "Something went wrong.", "error");
  } finally {
    submit.disabled = false;
  }
});

copyButton.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(linkField.value);
    copyButton.textContent = "Copied";
  } catch {
    linkField.select(); // clipboard API unavailable (e.g. plain http): let the user copy manually
    copyButton.textContent = "Press Ctrl/Cmd+C";
  }
  setTimeout(() => (copyButton.textContent = "Copy"), 2000);
});

deleteButton.addEventListener("click", async () => {
  if (!current) return;
  deleteButton.disabled = true;
  let response;
  try {
    response = await fetch(`/api/files/${encodeURIComponent(current.id)}`, {
      method: "DELETE",
      headers: { "X-Delete-Token": current.deleteToken },
    });
  } catch {
    // Keep the token and re-enable the button so the user can retry once they're back online.
    setStatus("Couldn't reach the server. Check your connection and try again.", "error");
    deleteButton.disabled = false;
    return;
  }
  if (response.status === 204 || response.status === 404) {
    // 404: already gone (downloaded or expired). Either way it no longer exists.
    setStatus("Deleted. The link no longer works.", "ok");
    linkField.value = "";
    result.hidden = true;
    current = null;
  } else {
    const body = await response.json().catch(() => ({}));
    setStatus(body.error || `Delete failed (HTTP ${response.status}).`, "error");
    deleteButton.disabled = false;
  }
});
