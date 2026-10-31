"use strict";
// Public vulnerability-disclosure page: no sign-in. Everything shown is set as text, never as HTML.
(() => {
  const $ = id => document.getElementById(id);
  const base = location.pathname.replace(/\/+$/, "");
  fetch(base + "/info").then(r => r.json()).then(d => {
    $("org").textContent = d.organisation || "";
    $("policy").textContent = d.policy || "";
    if (d.contact) $("contact").textContent = `You can also write to ${d.contact}.`;
    document.title = `Report a Vulnerability · ${d.organisation || ""}`;
  }).catch(() => {});
  $("vdp-form").addEventListener("submit", async e => {
    e.preventDefault();
    const btn = e.target.querySelector("button");
    btn.disabled = true; $("v-out").textContent = "Sending…";
    try {
      const r = await fetch(base + "/report", {method: "POST", headers: {"Content-Type": "application/json", "X-Guardian": "1"},
        body: JSON.stringify({title: $("v-title").value, affected: $("v-affected").value, description: $("v-desc").value, contact: $("v-contact").value})});
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || `Failed (${r.status})`);
      e.target.replaceChildren(Object.assign(document.createElement("p"), {className: "note",
        textContent: `Thank you. Your report was received (reference ${d.reference}). We'll look at it and, if you left a contact, get back to you.`}));
    } catch (err) { $("v-out").textContent = err.message; btn.disabled = false; }
  });
})();
