const enc = new TextEncoder();
const dec = new TextDecoder();

export const ITER = 600000;
const CHECK_TEXT = "couple-chat-check-v1";

export function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s);
}

export function unb64(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export function newSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

export async function deriveRoomKey(passphrase, saltBytes, iterations) {
  const base = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptText(key, text, aad) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: enc.encode(aad) },
    key, enc.encode(text)
  );
  return { nonce: b64(nonce), ct: b64(ct) };
}

export async function decryptText(key, payload, aad) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(payload.nonce), additionalData: enc.encode(aad) },
    key, unb64(payload.ct)
  );
  return dec.decode(pt);
}

export function makeCheck(key) {
  return encryptText(key, CHECK_TEXT, "check");
}

export async function verifyCheck(key, check) {
  try {
    return (await decryptText(key, check, "check")) === CHECK_TEXT;
  } catch {
    return false;
  }
}

const DB_NAME = "couple-chat-keys";
const STORE = "keys";

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run(mode, fn) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const req = fn(tx.objectStore(STORE));
    tx.oncomplete = () => { db.close(); resolve(req.result); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

export const saveKey = (key) => run("readwrite", (s) => s.put(key, "roomKey"));
export const loadKey = () => run("readonly", (s) => s.get("roomKey"));
export const clearKey = () => run("readwrite", (s) => s.delete("roomKey"));
