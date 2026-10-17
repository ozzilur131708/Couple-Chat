import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import {
  getAuth, setPersistence, browserLocalPersistence,
  signInWithEmailAndPassword, signOut, onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";
import { getFirestore, doc, getDoc } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js";
import { firebaseConfig } from "./firebase-config.js";

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

const $ = (id) => document.getElementById(id);
const loading = $("loading"), login = $("login"), home = $("home");

function show(section) {
  [loading, login, home].forEach((el) => el.classList.add("hidden"));
  section.classList.remove("hidden");
}

function loginError(code) {
  if (code === "auth/too-many-requests") return "Terlalu banyak percobaan. Coba lagi nanti.";
  if (code === "auth/network-request-failed") return "Tidak ada koneksi internet.";
  return "Email atau password salah.";
}

await setPersistence(auth, browserLocalPersistence);

onAuthStateChanged(auth, async (user) => {
  if (!user) { show(login); return; }
  show(home);
  $("status").textContent = "Memeriksa akses…";
  try {
    await getDoc(doc(db, "rooms", "main"));
    $("status").textContent = "Akses ruang pasangan: DIIZINKAN";
  } catch (e) {
    $("status").textContent = e.code === "permission-denied"
      ? "Akses ruang pasangan: DITOLAK"
      : "Tidak dapat terhubung ke server.";
  }
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

$("logoutBtn").addEventListener("click", async () => {
  await signOut(auth);
  $("email").value = "";
  $("password").value = "";
});
