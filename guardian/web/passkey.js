"use strict";
// Passkey ceremonies shared by the sign-in, console and settings pages.
// The PRF result (the per-passkey secret that opens the vault) is sent once to the server over TLS and never stored here.
const Passkey = (() => {
  const toBuf = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); s += "=".repeat((4 - s.length % 4) % 4);
    return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer; };
  const toB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  async function post(path, body) {
    const r = await fetch(path, {method: "POST", headers: {"Content-Type": "application/json", "X-Guardian": "1"}, body: JSON.stringify(body || {})});
    const out = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(out.detail || `Request failed (${r.status})`); e.status = r.status; throw e; }
    return out;
  }

  function explain(e) {
    if (e && e.name === "NotAllowedError") return "The passkey request was cancelled or timed out.";
    if (e && e.name === "InvalidStateError") return "This device already has a passkey for Guardian.";
    if (e && e.name === "SecurityError") return "Passkeys only work at the Guardian address with its certificate, not at an IP address.";
    return (e && e.message) || "Something went wrong.";
  }

  async function register(name) {
    const o = await post("/api/auth/register/options");
    const publicKey = {...o, challenge: toBuf(o.challenge), user: {...o.user, id: toBuf(o.user.id)},
      excludeCredentials: (o.excludeCredentials || []).map(c => ({...c, id: toBuf(c.id)}))};
    const cred = await navigator.credentials.create({publicKey});
    const res = cred.response;
    return post("/api/auth/register/verify", {name, credential: {
      id: cred.id, rawId: toB64u(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment,
      response: {clientDataJSON: toB64u(res.clientDataJSON), attestationObject: toB64u(res.attestationObject),
                 transports: res.getTransports ? res.getTransports() : []}}});
  }

  async function authenticate(unlock = true) {
    const o = await post("/api/auth/passkey/options");
    const ext = o.extensions && o.extensions.prf ? {prf: {eval: {first: toBuf(o.extensions.prf.eval.first)}}} : {};
    const publicKey = {...o, challenge: toBuf(o.challenge), extensions: ext,
      allowCredentials: (o.allowCredentials || []).map(c => ({...c, id: toBuf(c.id)}))};
    const cred = await navigator.credentials.get({publicKey});
    const res = cred.response;
    const prf = cred.getClientExtensionResults().prf;
    return post("/api/auth/passkey/verify", {unlock, prf: prf && prf.results && prf.results.first ? toB64u(prf.results.first) : null,
      credential: {id: cred.id, rawId: toB64u(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment,
        response: {clientDataJSON: toB64u(res.clientDataJSON), authenticatorData: toB64u(res.authenticatorData),
                   signature: toB64u(res.signature), userHandle: res.userHandle ? toB64u(res.userHandle) : null}}});
  }

  function deviceName() {
    const ua = navigator.userAgent;
    if (/iPhone/.test(ua)) return "iPhone";
    if (/iPad/.test(ua)) return "iPad";
    if (/Android/.test(ua)) return "Android phone";
    if (/Mac OS X/.test(ua)) return "Mac";
    if (/Windows/.test(ua)) return "Windows Hello";
    return "Passkey";
  }

  return {register, authenticate, post, explain, deviceName, supported: !!window.PublicKeyCredential};
})();
