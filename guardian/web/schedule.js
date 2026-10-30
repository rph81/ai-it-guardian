"use strict";
// Settings › Schedules & alerts. Uses $, el and api from settings.js.
const Schedule = (() => {
  const DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const when = t => new Date(t * 1000).toLocaleString([], {weekday: "short", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit"});
  let data = null;

  function fill() {
    for (const id of ["q-day", "a-day"]) if (!$(id).childElementCount) $(id).append(...DAYS.map((d, i) => el("option", {value: String(i)}, d)));
    if (!$("a-mday").childElementCount) $("a-mday").append(...Array.from({length: 28}, (_, i) => el("option", {value: String(i + 1)}, `Day ${i + 1} of the month`)));
  }
  function days() {
    $("q-day").disabled = $("q-every").value !== "weekly";
    const monthly = $("a-every").value === "monthly";
    $("a-day").classList.toggle("hidden", monthly); $("a-mday").classList.toggle("hidden", !monthly);
    $("a-day").disabled = $("a-mday").disabled = $("a-every").value === "off";
  }

  async function load() {
    fill();
    try { data = await api("/api/schedule"); } catch (e) { return; }
    const q = data.schedule.quick, a = data.schedule.full;
    $("q-every").value = q.every; $("q-day").value = String(q.day); $("q-time").value = q.time;
    $("a-every").value = a.every; $("a-day").value = String(a.day); $("a-mday").value = String(a.mday); $("a-time").value = a.time;
    days();
    const nx = data.next;
    $("sched-next").textContent = [nx.quick && `Next scan: ${when(nx.quick)}`, nx.full && `Next AI assessment: ${when(nx.full)}`].filter(Boolean).join(" · ") || "Nothing scheduled.";
    $("un-state").textContent = data.unattended ? "Allowed" : "Off";
    $("un-state").className = "tag " + (data.unattended ? "warn" : "");
    $("un-on").disabled = data.unattended || !data.anthropic_key_set;
    $("un-off").disabled = !data.unattended;
    const n = data.notify;
    $("n-threshold").value = n.threshold; $("n-changes").checked = !!n.changes;
    $("e-on").checked = n.email.on; $("e-host").value = n.email.host; $("e-port").value = String(n.email.port || 587);
    $("e-user").value = n.email.username; $("e-from").value = n.email.sender; $("e-to").value = (n.email.to || []).join(", ");
    $("e-pass").placeholder = n.email.secret_set ? "unchanged" : "not set";
    for (const [k, p] of [["teams", "t"], ["slack", "s"], ["webhook", "w"]]) {
      $(p + "-on").checked = n[k].on; $(p + "-url").value = ""; $(p + "-url").placeholder = n[k].secret_set ? "unchanged (saved)" : "https://…";
    }
    const last = data.notify_last;
    $("n-last").textContent = last && last.t ? `Last alert ${when(last.t)}: ` + Object.entries(last.result).map(([k, v]) => `${k} ${v === "ok" ? "sent" : "failed (" + v + ")"}`).join(", ") : "";
  }

  $("q-every").addEventListener("change", days);
  $("a-every").addEventListener("change", days);
  $("sched-form").addEventListener("submit", async e => {
    e.preventDefault();
    try {
      const r = await api("/api/schedule", {quick: {every: $("q-every").value, time: $("q-time").value, day: +$("q-day").value, mday: 1},
                                             full: {every: $("a-every").value, time: $("a-time").value, day: +$("a-day").value, mday: +$("a-mday").value}});
      $("sched-saved").textContent = "Saved."; await load();
    } catch (err) { alert(err.message); }
  });
  $("un-on").addEventListener("click", async () => {
    if (!confirm("Keep a copy of the Anthropic key outside the vault so scheduled AI assessments can run at night?\n\nAnyone with root access to the container could read it.")) return;
    try { await Passkey.authenticate(true); await api("/api/schedule/unattended", {on: true}); await load(); }
    catch (err) { alert(err.name ? Passkey.explain(err) : err.message); }
  });
  $("un-off").addEventListener("click", async () => {
    try { await api("/api/schedule/unattended", {on: false}); await load(); } catch (err) { alert(err.message); }
  });
  $("notify-form").addEventListener("submit", async e => {
    e.preventDefault();
    const url = id => $(id).value.trim() || null;
    try {
      await api("/api/notify", {threshold: $("n-threshold").value, changes: $("n-changes").checked,
        email: {on: $("e-on").checked, host: $("e-host").value, port: +$("e-port").value, username: $("e-user").value,
                password: $("e-pass").value || null, sender: $("e-from").value, to: $("e-to").value.split(",")},
        teams: {on: $("t-on").checked, url: url("t-url")}, slack: {on: $("s-on").checked, url: url("s-url")},
        webhook: {on: $("w-on").checked, url: url("w-url")}});
      $("e-pass").value = ""; $("n-result").textContent = "Saved."; await load();
    } catch (err) { alert(err.message); }
  });
  $("n-test").addEventListener("click", async () => {
    $("n-result").textContent = "Sending…";
    try { const r = await api("/api/notify/test", {}); $("n-result").textContent = Object.entries(r.result).map(([k, v]) => `${k}: ${v === "ok" ? "sent" : v}`).join(" · "); }
    catch (err) { $("n-result").textContent = err.message; }
  });
  return {load};
})();
