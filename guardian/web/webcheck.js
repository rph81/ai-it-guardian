"use strict";
// Code page › Web app check: a safe, read-only crawl of one web app. Uses $, el, api and when from code.js.
const WebCheck = (() => {
  let polling = null, open = null;
  const SEVC = {critical: "error", high: "error", medium: "warn", low: "", info: ""};

  async function load() {
    let d;
    try { d = await api("/api/webscan"); } catch (e) { return; }
    for (const id of ["wc-site", "ic-site"]) $(id).replaceChildren(...d.sites.map(s => el("option", {value: s.id}, s.id === "local" ? "This network" : [s.customer, s.name].filter(Boolean).join(" · "))));
    $("wc-go").disabled = $("ic-go").disabled = !!d.running; $("wc-stop").classList.toggle("hidden", !d.running);
    $("wc-history").replaceChildren(...(d.scans.length ? d.scans.map(s => el("tr", {class: "clickable", onclick: () => show(s.id)},
      el("td", {class: "mono"}, s.target), el("td", {}, when(s.started)), el("td", {}, s.by), el("td", {}, s.kind === "image" ? "image" : s.signed_in ? "web, signed in" : "web, anonymous"),
      el("td", {}, s.status === "running" ? (s.kind === "image" ? "running" : `running · ${s.pages} pages`) : s.status),
      el("td", {}, ...["critical", "high", "medium", "low"].filter(k => (s.counts || {})[k]).map(k => el("span", {class: `tag ${SEVC[k]}`}, `${s.counts[k]} ${k}`)))))
      : [el("tr", {}, el("td", {colspan: "6", class: "note"}, "No web checks yet."))]));
    clearTimeout(polling);
    if (d.running) { polling = setTimeout(load, 3000); if (open === d.running) show(open); }
  }

  async function show(id) {
    open = id;
    let d;
    try { d = await api(`/api/webscan/${id}`); } catch (e) { return; }
    $("wc-res").classList.remove("hidden");
    $("wc-rtitle").textContent = d.target;
    $("wc-rmeta").textContent = (d.kind === "image"
      ? `${d.status}${d.stage && d.status === "running" ? ` · ${d.stage}${d.layer ? ` ${d.layer}/${d.layers}` : ""}` : ""}` + (d.os ? ` · ${d.os} · ${d.packages} packages · ${d.layers} layers · ${d.mb} MB` : "")
      : `${d.status} · ${d.pages} pages · ${d.requests} requests · ${d.signed_in ? `signed in (${d.auth_header})` : "not signed in"}`) + (d.error ? ` · ${d.error}` : "");
    $("wc-findings").replaceChildren(...(d.findings.length ? d.findings.map((f, n) => el("details", {class: "finding"},
      el("summary", {}, el("span", {class: `sev ${f.severity}`}, f.severity), " ", el("b", {}, f.title), f.count > 1 ? el("span", {class: "micro"}, ` · ${f.count}×`) : null),
      el("p", {class: "pre"}, f.evidence), el("p", {class: "note"}, "Fix: ", f.recommendation),
      f.urls.length ? el("p", {class: "micro mono"}, f.urls.slice(0, 8).join("  ")) : null,
      f.finding ? el("span", {class: "tag ok"}, `In the Fix plan (${f.run} ${f.finding})`)
        : el("button", {class: "btn sm", type: "button", onclick: async () => {
            try { await api(`/api/webscan/${id}/findings/${n}/fix-plan`, {}); show(id); } catch (e) { alert(e.message); } }}, "Add to Fix plan")))
      : [el("p", {class: "note"}, d.status === "running" ? "Checking…" : "Nothing found.")]));
  }

  $("wc-form").addEventListener("submit", async e => {
    e.preventDefault();
    $("wc-err").textContent = "";
    if (!$("wc-ok").checked) { $("wc-err").textContent = "Confirm that you're allowed to test this app."; return; }
    try {
      await Passkey.authenticate(true);
      const r = await api("/api/webscan", {url: $("wc-url").value, site: $("wc-site").value, auth_name: $("wc-hname").value, auth_value: $("wc-hval").value,
        max_pages: Number($("wc-max").value) || 150, verify_tls: $("wc-tls").checked, authorized: true});
      $("wc-hval").value = ""; open = r.id; load(); show(r.id);
    } catch (err) { $("wc-err").textContent = err.name ? Passkey.explain(err) : err.message; }
  });
  $("ic-form").addEventListener("submit", async e => {
    e.preventDefault();
    $("ic-err").textContent = "";
    try {
      const r = await api("/api/imagescan", {image: $("ic-image").value, site: $("ic-site").value, token: $("ic-token").value});
      $("ic-token").value = ""; open = r.id; load(); show(r.id);
    } catch (err) { $("ic-err").textContent = err.message; }
  });
  $("wc-stop").addEventListener("click", async () => { try { await api("/api/webscan/stop", {}); } catch (e) { alert(e.message); } load(); });
  load();
  return {load};
})();
