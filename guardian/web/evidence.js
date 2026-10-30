"use strict";
// Settings › Evidence library. Uses $, el and api from settings.js.
const Evidence = (() => {
  const STATE = {valid: ["ok", "Valid"], expiring: ["warn", "Expires soon"], expired: ["error", "Expired"]};
  const kb = n => n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`;

  async function load() {
    let d;
    try { d = await api("/api/evidence"); } catch (e) {
      $("ev-locked").classList.toggle("hidden", !/vault/i.test(e.message)); $("ev-rows").replaceChildren(); return;
    }
    $("ev-locked").classList.add("hidden");
    $("ev-count").textContent = `${d.evidence.length} file${d.evidence.length === 1 ? "" : "s"}`;
    $("ev-rows").replaceChildren(...(d.evidence.length ? d.evidence.map(row) : [el("tr", {}, el("td", {colspan: "5", class: "note"}, "No evidence yet."))]));
  }

  function row(e) {
    const ctl = el("input", {class: "mono grow", value: e.controls.join(", "), "aria-label": "Controls"});
    const valid = el("input", {type: "date", value: e.valid_until || "", "aria-label": "Valid until"});
    const [cls, lbl] = STATE[e.state] || ["", e.state];
    const save = el("button", {class: "btn sm primary", type: "button", onclick: async () => {
      try { await api(`/api/evidence/${e.id}`, {controls: ctl.value.split(",").map(x => x.trim()).filter(Boolean), valid_until: valid.value}); load(); }
      catch (err) { alert(err.message); } }}, "Save");
    const del = me && me.role === "admin" ? el("button", {class: "btn sm danger", type: "button", onclick: async () => {
      if (!confirm(`Delete ${e.name}? It disappears from every control and later exports. The audit log keeps its fingerprint.`)) return;
      const r = await fetch(`/api/evidence/${e.id}`, {method: "DELETE", headers: {"X-Guardian": "1"}});
      if (!r.ok) alert((await r.json().catch(() => ({}))).detail || "Delete failed"); load(); }}, "Delete") : null;
    return el("tr", {}, el("td", {}, el("b", {}, e.name), el("div", {class: "micro"}, `${kb(e.size)} · ${e.uploaded_by} · ${new Date(e.uploaded_at * 1000).toLocaleDateString()}`),
        el("div", {class: "micro mono", title: "SHA-256"}, e.sha256.slice(0, 16) + "…")),
      el("td", {}, ctl), el("td", {}, valid), el("td", {}, el("span", {class: "tag " + cls}, lbl)),
      el("td", {}, el("div", {class: "row"}, save, el("a", {class: "btn sm", href: `/api/evidence/${e.id}/download`}, "Download"), del)));
  }
  return {load};
})();
