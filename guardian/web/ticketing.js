"use strict";
// Settings › Ticketing: ServiceNow, ConnectWise PSA, Autotask, HaloPSA, Jira Service Management. Uses $, el and api from settings.js.
const Ticketing = (() => {
  let data = null;
  function fields() {
    const sys = $("tk-sys").value, spec = data.systems[sys], vals = (data.settings || {})[sys] || {};
    $("tk-fields").replaceChildren(...spec.fields.map(f => el("div", {},
      el("label", {for: "tkf-" + f.name}, f.label + (f.secret && data.secret_set[sys] ? " (saved)" : "")),
      el("input", {id: "tkf-" + f.name, class: "mono", type: f.secret ? "password" : "text", autocomplete: f.secret ? "new-password" : "off",
                   placeholder: f.secret ? (data.secret_set[sys] ? "unchanged" : "not set") : (f.placeholder || ""), value: f.secret ? "" : (vals[f.name] || "")}))));
  }
  async function load() {
    try { data = await api("/api/ticketing"); } catch (e) { return; }
    $("tk-sys").replaceChildren(...Object.entries(data.systems).map(([k, v]) => el("option", {value: k}, v.label)));
    $("tk-sys").value = data.system;
    $("tk-on").checked = data.on; $("tk-auto").checked = data.auto; $("tk-th").value = data.threshold; $("tk-resolve").checked = data.resolve_on_verify;
    $("tk-state").textContent = data.on ? `${data.systems[data.system].label}${data.auto ? " · automatic" : ""}` : "Off";
    $("tk-state").className = "tag " + (data.on ? "ok" : "");
    fields();
  }
  $("tk-sys").addEventListener("change", fields);
  $("tk-form").addEventListener("submit", async e => {
    e.preventDefault();
    const sys = $("tk-sys").value, spec = data.systems[sys], vals = {};
    let secret = null;
    for (const f of spec.fields) { const v = $("tkf-" + f.name).value; if (f.secret) secret = v || null; else vals[f.name] = v; }
    try {
      await api("/api/ticketing", {system: sys, on: $("tk-on").checked, auto: $("tk-auto").checked, threshold: $("tk-th").value,
        resolve_on_verify: $("tk-resolve").checked, fields: vals, secret});
      $("tk-result").textContent = "Saved."; await load();
    } catch (err) { alert(err.message); }
  });
  $("tk-test").addEventListener("click", async () => {
    $("tk-result").textContent = "Connecting…";
    try { const r = await api("/api/ticketing/test", {}); $("tk-result").textContent = `Connected to ${r.system || "the system"} as ${r.user}.`; }
    catch (err) { $("tk-result").textContent = err.message; }
  });
  return {load};
})();
