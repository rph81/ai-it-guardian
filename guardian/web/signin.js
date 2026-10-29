"use strict";
const $ = id => document.getElementById(id);
const VIEWS = ["setup", "start", "passkey", "recovery", "key"];
const ERRORS = {
  "not-invited": "This account hasn't been invited. Ask an admin for an invite.",
  "wrong-account": "The invite is for a different e-mail address. Sign in with the invited account.",
  "invite": "This invite link has expired or was already used.",
  "provider": "Sign-in with the provider failed. Try again.",
  "expired": "The sign-in took too long. Try again.",
  "cancelled": "Sign-in was cancelled.",
  "exists": "That account already exists: sign in normally.",
};
let state = null;

function show(v, step) {
  VIEWS.forEach(x => $("v-" + x).classList.toggle("hidden", x !== v));
  [...$("steps").children].forEach((s, i) => s.classList.toggle("on", i < step));
  $("err").textContent = "";
}
function err(e) { $("err").textContent = typeof e === "string" ? e : Passkey.explain(e); }

function providerButton(key, label) {
  const a = document.createElement("a");
  a.className = "btn big"; a.href = `/auth/${key}/start`;
  a.innerHTML = key === "google"
    ? '<svg class="prov" viewBox="0 0 48 48"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>'
    : '<svg class="prov" viewBox="0 0 23 23"><path fill="#f35325" d="M1 1h10v10H1z"/><path fill="#81bc06" d="M12 1h10v10H12z"/><path fill="#05a6f0" d="M1 12h10v10H1z"/><path fill="#ffba08" d="M12 12h10v10H12z"/></svg>';
  a.append(` Continue with ${label}`);
  return a;
}

function showKey(key) {
  show("key", 2);
  $("key-text").textContent = key;
  $("key-ok").onchange = () => { $("key-done").disabled = !$("key-ok").checked; };
  $("key-copy").onclick = async () => { try { await navigator.clipboard.writeText(key); $("key-copy").textContent = "Copied"; } catch (e) { getSelection().selectAllChildren($("key-text")); } };
  $("key-done").onclick = () => location.replace("/");
}

function done(r) {
  if (r.recovery_key) return showKey(r.recovery_key);
  if (r.note) { sessionStorage.setItem("guardian-note", r.note); }
  location.replace("/");
}

// passkey step: create one (first time) or confirm with an existing one
function passkeyStep(st) {
  show("passkey", 2);
  const first = st.passkeys === 0;
  $("pk-title").textContent = first ? `Welcome ${st.user.name}` : `Hi ${st.user.name}`;
  $("pk-note").textContent = first
    ? `Create a passkey on this device. It signs you in from now on${["admin", "operator"].includes(st.user.role) ? " and is the key to the vault" : ""}.`
    : `Signed in as ${st.user.email}. Confirm with your passkey${st.can_unlock ? " to unlock Guardian" : ""}.`;
  $("pk-name-box").classList.toggle("hidden", !first);
  $("pk-name").value = Passkey.deviceName();
  $("pk-go").textContent = first ? "Create passkey" : (st.can_unlock ? "Unlock with passkey" : "Confirm with passkey");
  $("pk-readonly-box").classList.toggle("hidden", first || !st.can_unlock);
  $("pk-go").onclick = async () => {
    $("pk-go").disabled = true; err("");
    try {
      if (first) await Passkey.register($("pk-name").value || Passkey.deviceName());
      done(await Passkey.authenticate(true));
    } catch (e) { err(e); }
    $("pk-go").disabled = false;
  };
  $("pk-readonly").onclick = async () => { try { done(await Passkey.authenticate(false)); } catch (e) { err(e); } };
}

$("v-setup").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    await Passkey.post("/api/setup/start", {code: $("s-code").value, name: $("s-name").value, email: $("s-email").value});
    state = await (await fetch("/api/auth/state")).json();
    passkeyStep(state);
  } catch (x) { err(x); }
});

$("pk-direct").onclick = async () => { try { done(await Passkey.authenticate(true)); } catch (e) { err(e); } };
$("invite-pk").onclick = async () => {
  try { await Passkey.post("/api/auth/invite-passkey"); state = await (await fetch("/api/auth/state")).json(); passkeyStep(state); }
  catch (e) { err(e); }
};
$("to-recovery").onclick = e => { e.preventDefault(); show("recovery", 1); };
$("v-recovery").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    await Passkey.post("/api/auth/recovery", {email: $("r-email").value, key: $("r-key").value});
    $("r-key").value = "";
    state = await (await fetch("/api/auth/state")).json();
    state.passkeys = 0;
    passkeyStep(state);
    $("pk-note").textContent = "Vault unlocked with the recovery key. Create a new passkey on this device: your old ones no longer work.";
  } catch (x) { err(x); }
});

(async () => {
  state = await (await fetch("/api/auth/state")).json();
  const q = new URLSearchParams(location.search);
  if (state.wrong_host) {
    $("warn").classList.remove("hidden");
    $("warn").replaceChildren("Passkeys only work at ", Object.assign(document.createElement("a"), {href: state.base + "/signin", textContent: state.base}), ".");
  }
  if (!Passkey.supported) err("This browser doesn't support passkeys.");
  if (q.get("error")) err(ERRORS[q.get("error")] || "Sign-in failed.");
  if (state.setup) return show("setup", 1);
  if (state.stage === "active") return location.replace("/");
  if (state.stage === "identified" && state.user) return passkeyStep(state);
  show("start", 1);
  const provs = Object.entries(state.providers);
  $("providers").replaceChildren(...provs.map(([k, l]) => providerButton(k, l)));
  $("or").classList.toggle("hidden", !provs.length);
  if (state.invite || q.get("invite")) {
    $("start-title").textContent = "You've been invited";
    $("start-note").textContent = provs.length ? "Sign in with the account the invite was sent to." : "Create a passkey to accept the invite.";
    $("pk-direct").classList.add("hidden");
    $("invite-pk").classList.toggle("hidden", !!provs.length);
    $("or").classList.add("hidden");
  }
})();
