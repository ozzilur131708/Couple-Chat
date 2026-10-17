import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import {
  getAuth, setPersistence, browserLocalPersistence,
  signInWithEmailAndPassword, signOut, onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, serverTimestamp, collection,
  query, orderBy, limit, startAfter, onSnapshot, getDocs
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js";
import { firebaseConfig } from "./firebase-config.js";
import {
  ITER, newSalt, b64, unb64, deriveRoomKey, makeCheck, verifyCheck,
  encryptText, decryptText, saveKey, loadKey, clearKey
} from "./crypto.js";

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const metaRef = doc(db, "rooms", "main", "meta", "crypto");
const msgsCol = collection(db, "rooms", "main", "messages");
const PAGE = 50;

const $ = (id) => document.getElementById(id);
const screens = ["loading", "login", "setup", "unlock", "chat", "settings"];

function show(id) {
  screens.forEach((s) => $(s).classList.add("hidden"));
  $(id).classList.remove("hidden");
}

let roomKey = null;
let meta = null;

/* ---------- state chat (hanya di memori) ---------- */
let unsub = null;
let chain = Promise.resolve();
const store = new Map();     // id -> {id, from, text, ts, pending}
const snaps = new Map();     // id -> docSnapshot (yang sudah dikonfirmasi server)
const plain = new Map();     // id -> teks hasil dekripsi (atau null)
const failedOut = new Map(); // id -> {from, text, ts, data}
let hasMore = false, hasMoreInit = false, serverLoaded = false;
let fromCache = true, stickBottom = true;

function loginError(code) {
  if (code === "auth/too-many-requests") return "Terlalu banyak percobaan. Coba lagi nanti.";
  if (code === "auth/network-request-failed") return "Tidak ada koneksi internet.";
  return "Email atau password salah.";
}

function wordCount(s) {
  return s.trim().split(/\s+/).filter(Boolean).length;
}

function fmt(ts) {
  return new Date(ts).toLocaleString("id-ID", {
    day: "numeric", month: "short", hour: "2-digit", minute: "2-digit"
  });
}

/* ---------- koneksi ---------- */
function updateConn() {
  const el = $("conn");
  if (!navigator.onLine) { el.textContent = "Offline"; el.className = "conn bad"; }
  else if (fromCache) { el.textContent = "Menghubungkan…"; el.className = "conn"; }
  else { el.textContent = "Online"; el.className = "conn ok"; }
}
window.addEventListener("online", updateConn);
window.addEventListener("offline", updateConn);

/* ---------- dekripsi dan penyimpanan di memori ---------- */
async function decryptDoc(id, d) {
  if (plain.has(id)) return plain.get(id);
  let t = null;
  try {
    t = await decryptText(roomKey, { nonce: d.nonce, ct: d.ct }, id + "|" + d.from);
  } catch { t = null; }
  plain.set(id, t);
  return t;
}

async function upsert(docSnap) {
  const d = docSnap.data({ serverTimestamps: "estimate" });
  const id = docSnap.id;
  let text = null;
  if (typeof d.ct === "string" && typeof d.nonce === "string" && typeof d.from === "string") {
    text = await decryptDoc(id, d);
  }
  const pending = docSnap.metadata.hasPendingWrites;
  store.set(id, {
    id, from: d.from, text, pending,
    ts: d.ts && d.ts.toMillis ? d.ts.toMillis() : Date.now()
  });
  if (!pending) snaps.set(id, docSnap);
}

function oldestSnap() {
  let best = null, bt = Infinity;
  for (const s of snaps.values()) {
    const t = s.data().ts;
    if (t && t.toMillis() < bt) { bt = t.toMillis(); best = s; }
  }
  return best;
}

/* ---------- tampilan pesan ---------- */
function buildItem(m) {
  const mine = m.from === auth.currentUser.uid;
  const li = document.createElement("li");
  li.className = "msg" + (mine ? " me" : "") + (m.failed ? " failed" : "");
  const t = document.createElement("span");
  t.className = "txt";
  t.textContent = m.text !== null && m.text !== undefined
    ? m.text
    : "🔒 Pesan tidak dapat dibuka (kunci tidak cocok atau data berubah)";
  const meta = document.createElement("span");
  meta.className = "meta";
  let status = "";
  if (mine) {
    status = m.failed ? " · Gagal. Ketuk untuk kirim ulang"
      : (m.pending ? " · Mengirim…" : " · Terkirim");
  }
  meta.textContent = (mine ? "Saya" : "Pasangan") + " · " + fmt(m.ts) + status;
  li.append(t, meta);
  if (m.failed) li.addEventListener("click", () => retry(m.id));
  return li;
}

function render() {
  const box = $("msgs");
  const nearBottom = stickBottom || box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const items = [
    ...store.values(),
    ...[...failedOut.entries()].map(([id, v]) => ({
      id, from: v.from, text: v.text, ts: v.ts, failed: true
    }))
  ];
  items.sort((a, b) => a.ts - b.ts || (a.id < b.id ? -1 : 1));
  $("msgList").replaceChildren(...items.map(buildItem));
  $("emptyMsg").classList.toggle("hidden", !(serverLoaded && items.length === 0));
  $("olderBtn").classList.toggle("hidden", !hasMore);
  if (nearBottom) box.scrollTop = box.scrollHeight;
  stickBottom = false;
}

/* ---------- listener real-time ---------- */
async function handleSnap(snap) {
  fromCache = snap.metadata.fromCache;
  if (!fromCache) {
    serverLoaded = true;
    if (!hasMoreInit) { hasMore = snap.size >= PAGE; hasMoreInit = true; }
  }
  for (const ch of snap.docChanges({ includeMetadataChanges: true })) {
    if (ch.type === "removed") continue; // penghapusan pesan baru ditangani di Tahap 5
    await upsert(ch.doc);
  }
  render();
  updateConn();
}

function stopChat() {
  if (unsub) { unsub(); unsub = null; }
  chain = Promise.resolve();
  store.clear(); snaps.clear(); plain.clear(); failedOut.clear();
  hasMore = false; hasMoreInit = false; serverLoaded = false;
  fromCache = true; stickBottom = true;
  $("msgList").replaceChildren();
  $("msgInput").value = "";
  $("testOut").textContent = "";
}

function startChat() {
  stopChat();
  const q = query(msgsCol, orderBy("ts", "desc"), limit(PAGE));
  unsub = onSnapshot(
    q,
    { includeMetadataChanges: true },
    (snap) => { chain = chain.then(() => handleSnap(snap)).catch(() => {}); },
    (err) => {
      const el = $("conn");
      el.textContent = err.code === "permission-denied" ? "Akses ditolak" : "Gangguan koneksi";
      el.className = "conn bad";
    }
  );
  updateConn();
  show("chat");
}

/* ---------- kirim dan kirim ulang ---------- */
async function doSend(id, data, text) {
  const ref = doc(db, "rooms", "main", "messages", id);
  try {
    await setDoc(ref, data);
    failedOut.delete(id);
  } catch (e) {
    if (e.code === "permission-denied") {
      try {
        const s = await getDoc(ref);
        if (s.exists()) { failedOut.delete(id); render(); return; } // sudah terkirim sebelumnya
      } catch { /* abaikan */ }
    }
    store.delete(id);
    failedOut.set(id, { from: data.from, text, ts: Date.now(), data });
    render();
  }
}

async function retry(id) {
  const f = failedOut.get(id);
  if (!f) return;
  failedOut.delete(id);
  stickBottom = true;
  render();
  await doSend(id, f.data, f.text);
}

$("sendForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("msgInput").value.trim();
  if (!text || !roomKey) return;
  const id = crypto.randomUUID();
  const uid = auth.currentUser.uid;
  let payload;
  try {
    payload = await encryptText(roomKey, text, id + "|" + uid);
  } catch {
    return;
  }
  $("msgInput").value = "";
  plain.set(id, text);
  stickBottom = true;
  const data = { from: uid, ct: payload.ct, nonce: payload.nonce, kv: 1, ts: serverTimestamp() };
  doSend(id, data, text);
});

$("olderBtn").addEventListener("click", async () => {
  const btn = $("olderBtn");
  const box = $("msgs");
  const oldest = oldestSnap();
  if (!oldest) return;
  btn.disabled = true;
  try {
    const s = await getDocs(query(msgsCol, orderBy("ts", "desc"), startAfter(oldest), limit(PAGE)));
    const prev = box.scrollHeight;
    for (const d of s.docs) await upsert(d);
    hasMore = s.size >= PAGE;
    render();
    box.scrollTop += box.scrollHeight - prev;
  } catch { /* abaikan */ } finally {
    btn.disabled = false;
  }
});

/* ---------- alur autentikasi dan kunci ---------- */
async function route() {
  $("loading").textContent = "Memuat…";
  show("loading");
  try {
    const snap = await getDoc(metaRef);
    meta = snap.exists() ? snap.data() : null;
  } catch (e) {
    $("loading").textContent = e.code === "permission-denied"
      ? "Akses ditolak untuk akun ini."
      : "Tidak dapat terhubung ke server. Muat ulang halaman.";
    return;
  }
  if (!meta) {
    roomKey = null;
    await clearKey().catch(() => {});
    show("setup");
    return;
  }
  roomKey = await loadKey().catch(() => null);
  if (roomKey && (await verifyCheck(roomKey, meta.check))) {
    startChat();
    return;
  }
  roomKey = null;
  await clearKey().catch(() => {});
  show("unlock");
}

await setPersistence(auth, browserLocalPersistence);

onAuthStateChanged(auth, async (user) => {
  if (!user) {
    stopChat();
    roomKey = null;
    meta = null;
    await clearKey().catch(() => {});
    show("login");
    return;
  }
  await route();
});

$("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("loginBtn");
  btn.disabled = true;
  $("loginMsg").textContent = "";
  try {
    await signInWithEmailAndPassword(auth, $("email").value.trim(), $("password").value);
  } catch (err) {
    $("loginMsg").textContent = loginError(err.code);
  } finally {
    $("password").value = "";
    btn.disabled = false;
  }
});

$("setupForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const p1 = $("pass1").value;
  const p2 = $("pass2").value;
  const msg = $("setupMsg");
  const btn = $("setupBtn");
  if (p1 !== p2) { msg.textContent = "Kedua passphrase tidak sama."; return; }
  if (wordCount(p1) < 5 || p1.length < 24) {
    msg.textContent = "Gunakan minimal 5 kata acak (24+ karakter).";
    return;
  }
  btn.disabled = true;
  msg.textContent = "Memproses… (beberapa detik)";
  try {
    const salt = newSalt();
    const key = await deriveRoomKey(p1, salt, ITER);
    const check = await makeCheck(key);
    await setDoc(metaRef, {
      v: 1, kdf: "PBKDF2-SHA256", iter: ITER,
      salt: b64(salt), check,
      by: auth.currentUser.uid, at: serverTimestamp()
    });
    await saveKey(key);
    roomKey = key;
    meta = (await getDoc(metaRef)).data();
    msg.textContent = "";
    startChat();
  } catch (err) {
    msg.textContent = err.code === "permission-denied"
      ? "Pengaturan enkripsi sudah ada. Muat ulang halaman lalu masukkan passphrase."
      : "Gagal menyimpan. Coba lagi.";
  } finally {
    $("pass1").value = "";
    $("pass2").value = "";
    btn.disabled = false;
  }
});

$("unlockForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("unlockMsg");
  const btn = $("unlockBtn");
  btn.disabled = true;
  msg.textContent = "Memproses…";
  try {
    const key = await deriveRoomKey($("unlockPass").value, unb64(meta.salt), meta.iter);
    if (await verifyCheck(key, meta.check)) {
      await saveKey(key);
      roomKey = key;
      msg.textContent = "";
      startChat();
    } else {
      msg.textContent = "Passphrase salah.";
    }
  } catch {
    msg.textContent = "Gagal memproses. Coba lagi.";
  } finally {
    $("unlockPass").value = "";
    btn.disabled = false;
  }
});

/* ---------- pengaturan ---------- */
$("settingsBtn").addEventListener("click", () => show("settings"));
$("backBtn").addEventListener("click", () => show("chat"));

$("testBtn").addEventListener("click", async () => {
  const out = $("testOut");
  out.textContent = "Menguji…";
  try {
    const p = await encryptText(roomKey, "uji enkripsi", "selftest");
    const back = await decryptText(roomKey, p, "selftest");
    let tamper = "DITERIMA (GAGAL)";
    try { await decryptText(roomKey, p, "selftest-x"); } catch { tamper = "ditolak (OK)"; }
    const p2 = await encryptText(roomKey, "uji enkripsi", "selftest");
    out.textContent =
      "Dekripsi: " + (back === "uji enkripsi" ? "OK" : "GAGAL") + "\n" +
      "Data diubah: " + tamper + "\n" +
      "Ciphertext tiap kirim berbeda: " + (p.ct !== p2.ct ? "OK" : "GAGAL");
  } catch {
    out.textContent = "Uji gagal.";
  }
});

$("logoutBtn").addEventListener("click", async () => {
  stopChat();
  await clearKey().catch(() => {});
  roomKey = null;
  meta = null;
  await signOut(auth);
  $("email").value = "";
  $("password").value = "";
});
