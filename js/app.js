import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import {
  getAuth, setPersistence, browserLocalPersistence,
  signInWithEmailAndPassword, signOut, onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, serverTimestamp
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

const $ = (id) => document.getElementById(id);
const screens = ["loading", "login", "setup", "unlock", "home"];

function show(id) {
  screens.forEach((s) => $(s).classList.add("hidden"));
  $(id).classList.remove("hidden");
}

let roomKey = null;
let meta = null;

function loginError(code) {
  if (code === "auth/too-many-requests") return "Terlalu banyak percobaan. Coba lagi nanti.";
  if (code === "auth/network-request-failed") return "Tidak ada koneksi internet.";
  return "Email atau password salah.";
}

function wordCount(s) {
  return s.trim().split(/\s+/).filter(Boolean).length;
}

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
    show("home");
    return;
  }
  roomKey = null;
  await clearKey().catch(() => {});
  show("unlock");
}

await setPersistence(auth, browserLocalPersistence);

onAuthStateChanged(auth, async (user) => {
  if (!user) {
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
    show("home");
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
      show("home");
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
      "Ciphertext tiap kirim berbeda: " + (p.ct !== p2.ct ? "OK" : "GAGAL") + "\n" +
      "Contoh ciphertext: " + p.ct.slice(0, 24) + "…";
  } catch {
    out.textContent = "Uji gagal.";
  }
});

$("logoutBtn").addEventListener("click", async () => {
  await clearKey().catch(() => {});
  roomKey = null;
  meta = null;
  await signOut(auth);
  $("email").value = "";
  $("password").value = "";
});
