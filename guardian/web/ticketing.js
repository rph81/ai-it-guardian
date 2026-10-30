"use strict";
// Settings › Ticketing (ServiceNow). Uses $ and api from settings.js.
const Ticketing = (() => {
  async function load() {
    let c; try { c = await api("/api/ticketing"); } catch (e) { return; }
    $("tk-on").checked = c.on; $("tk-inst").value = c.instance; $("tk-user").value = c.username;
    $("tk-pass").value = ""; $("tk-pass").placeholder = c.secret_set ? "unchanged" : "not set";
    $("tk-group").value = c.assignment_group; $("tk-caller").value = c.caller_id; $("tk-cat").value = c.category;
    $("tk-auto").checked = c.auto; $("tk-th").value = c.threshold; $("tk-resolve").checked = c.resolve_on_verify;
    $("tk-state").textContent = c.on ? (c.auto ? "On · automatic" : "On") : "Off";
    $("tk-state").className = "tag " + (c.on ? "ok" : "");
  }
  $("tk-form").addEventListener("submit", async e => {
    e.preventDefault();
    try {
      await api("/api/ticketing", {on: $("tk-on").checked, instance: $("tk-inst").value, username: $("tk-user").value,
        password: $("tk-pass").value || null, assignment_group: $("tk-group").value, caller_id: $("tk-caller").value,
        category: $("tk-cat").value, auto: $("tk-auto").checked, threshold: $("tk-th").value, resolve_on_verify: $("tk-resolve").checked});
      $("tk-result").textContent = "Saved."; await load();
    } catch (err) { alert(err.message); }
  });
  $("tk-test").addEventListener("click", async () => {
    $("tk-result").textContent = "Connecting…";
    try { const r = await api("/api/ticketing/test", {}); $("tk-result").textContent = `Connected as ${r.user}; table ${r.table} is readable.`; }
    catch (err) { $("tk-result").textContent = err.message; }
  });
  return {load};
})();
