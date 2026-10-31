"use strict";
// Settings › Integrations: SIEM output (Sentinel, Splunk, syslog) and MCP access tokens. Uses $, el and api from settings.js.
const Integrations = (() => {
  let d = null, m = null;
  const del = async path => {
    const r = await fetch(path, {method: "DELETE", headers: {"X-Guardian": "1"}});
    const out = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(out.detail || `Request failed (${r.status})`);
    return out;
  };
  const F = {sentinel: [["tenant_id", "Tenant ID"], ["client_id", "Application (client) ID"], ["endpoint", "Data collection endpoint (https://…ingest.monitor.azure.com)"],
                        ["dcr_id", "Data collection rule immutable ID (dcr-…)"], ["stream", "Stream name"]],
             splunk: [["url", "HEC address (https://splunk.example.com:8088)"], ["index", "Index (optional)"]],
             syslog: [["host", "Host"], ["port", "Port"]]};
  const SEC = {sentinel: "Client secret", splunk: "HEC token"};
  const LABEL = {sentinel: "Microsoft Sentinel", splunk: "Splunk", syslog: "Syslog (RFC 5424)"};
  const field = (lab, input) => el("div", {}, el("label", {for: input.id}, lab), input);

  async function load() {
    try { d = await api("/api/siem"); m = await api("/api/mcp/tokens"); } catch (e) { return; }
    api("/api/github-token").then(g => { $("in-gh-state").textContent = g.set ? "saved" : "not set"; $("in-gh-state").className = "tag " + (g.set ? "ok" : ""); }).catch(() => {});
    $("in-siem").replaceChildren(...Object.keys(LABEL).map(k => {
      const c = d[k];
      const on = el("input", {type: "checkbox", id: `in-${k}-on`, checked: c.on});
      const inputs = F[k].map(([n, lab]) => field(lab, el("input", {id: `in-${k}-${n}`, class: "mono", value: c[n] ?? ""})));
      if (k === "syslog") inputs.push(field("Transport", (() => { const s = el("select", {id: "in-syslog-proto"}, ...["tls", "tcp", "udp"].map(p => el("option", {value: p}, p.toUpperCase()))); s.value = c.proto; return s; })()));
      if (SEC[k]) inputs.push(field(SEC[k] + (d.secret_set[k] ? " (saved)" : ""), el("input", {id: `in-${k}-secret`, type: "password", autocomplete: "new-password", placeholder: d.secret_set[k] ? "unchanged" : "not set"})));
      return el("div", {class: "card"}, el("label", {class: "check"}, on, " ", el("b", {}, LABEL[k])), el("div", {class: "f3 field"}, ...inputs));
    }));
    $("in-only-new").checked = d.only_new;
    $("in-last").textContent = d.last ? `Last sent after run ${d.last.run}: ` + Object.entries(d.last.result).map(([k, v]) => `${LABEL[k]} ${v}`).join(" · ") : "";
    $("in-mcp-url").textContent = m.url;
    $("in-tokens").replaceChildren(...(m.tokens.length ? m.tokens.map(t => el("tr", {}, el("td", {}, el("b", {}, t.name)),
      el("td", {}, t.sites == null ? "All sites" : `${t.sites.length} site(s)`), el("td", {class: "meta"}, t.last_used ? new Date(t.last_used * 1000).toLocaleString() : "never"),
      el("td", {}, el("button", {class: "btn sm danger", type: "button", onclick: async () => {
        if (!confirm(`Remove the token "${t.name}"? The tool using it loses access at once.`)) return;
        try { await del(`/api/mcp/tokens/${t.id}`); load(); } catch (e) { alert(e.message); } }}, "Remove"))))
      : [el("tr", {}, el("td", {colspan: "4", class: "note"}, "No tokens yet."))]));
    $("in-msites").replaceChildren(el("option", {value: ""}, "All sites"), ...m.sites.map(s => el("option", {value: s.id}, s.id === "local" ? "This network" : [s.customer, s.name].filter(Boolean).join(" · "))));
  }

  $("in-save").addEventListener("click", async () => {
    const body = {only_new: $("in-only-new").checked, secrets: {}};
    for (const k of Object.keys(LABEL)) {
      body[k] = {on: $(`in-${k}-on`).checked};
      for (const [n] of F[k]) body[k][n] = $(`in-${k}-${n}`).value;
      if (k === "syslog") { body.syslog.proto = $("in-syslog-proto").value; body.syslog.port = Number(body.syslog.port) || 0; }
      if (SEC[k] && $(`in-${k}-secret`).value) body.secrets[k] = $(`in-${k}-secret`).value;
    }
    try { await api("/api/siem", body); $("in-result").textContent = "Saved."; load(); } catch (e) { $("in-result").textContent = e.message; }
  });
  $("in-test").addEventListener("click", async () => {
    $("in-result").textContent = "Sending a test event…";
    try { const r = await api("/api/siem/test", {}); $("in-result").textContent = Object.entries(r).map(([k, v]) => `${LABEL[k]}: ${v}`).join(" · "); }
    catch (e) { $("in-result").textContent = e.message; }
  });
  $("in-mcp-add").addEventListener("click", async () => {
    const name = $("in-mname").value.trim();
    if (!name) { alert("Give the token a name, e.g. Claude Desktop"); return; }
    try {
      await Passkey.authenticate(true);
      const site = $("in-msites").value;
      const r = await api("/api/mcp/tokens", {name, sites: site ? [site] : null});
      $("in-mnew").replaceChildren(el("p", {class: "note"}, "Copy the token now: it's shown only once."), el("pre", {class: "code"}, r.token));
      $("in-mname").value = ""; load();
    } catch (e) { alert(e.name ? Passkey.explain(e) : e.message); }
  });
  const gh = async token => { try { await api("/api/github-token", {token}); $("in-gh").value = ""; load(); } catch (e) { alert(e.message); } };
  $("in-gh-save").addEventListener("click", () => { if ($("in-gh").value.trim()) gh($("in-gh").value.trim()); });
  $("in-gh-del").addEventListener("click", () => { if (confirm("Remove the GitHub token? Private repositories can't be scanned without it.")) gh(""); });
  return {load};
})();
