"use strict";
// Light / dark / system mode and colour theme. Loaded in <head> without defer so the page never flashes the
// wrong colours; the choice is cached in this browser and saved to the account by the page (/api/me/prefs).
const Theme = (() => {
  const THEMES = {
    ember: ["Ember", "Orange and sage on olive charcoal. The default."],
    arctic: ["Arctic", "Ice blue and mint on blue graphite."],
    volt: ["Volt", "Signal lime on near-black. High contrast."],
    crimson: ["Crimson", "Red and sand on warm charcoal."],
    mono: ["Mono", "Pure black and white. Colour only where it means something."],
  };
  const MODES = ["light", "dark", "system"];
  const root = document.documentElement;
  const mq = matchMedia("(prefers-color-scheme: dark)");
  const read = k => { try { return localStorage.getItem(k); } catch (e) { return null; } };
  const write = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private mode: still works for this page */ } };
  let mode = MODES.includes(read("g-mode")) ? read("g-mode") : "dark";
  let theme = THEMES[read("g-theme")] ? read("g-theme") : "ember";
  const listeners = [];

  const scheme = () => mode === "system" ? (mq.matches ? "dark" : "light") : mode;
  function apply() {
    root.dataset.theme = theme;
    root.dataset.scheme = scheme();
    write("g-mode", mode); write("g-theme", theme);
    for (const f of listeners) f({mode, theme, scheme: scheme()});
  }
  mq.addEventListener("change", () => { if (mode === "system") apply(); });
  apply();

  // the quick light/dark button in the header, on any page that has one
  document.addEventListener("DOMContentLoaded", () => {
    const b = document.getElementById("mode-toggle");
    if (!b) return;
    const label = () => { b.textContent = scheme() === "dark" ? "Dark" : "Light"; b.setAttribute("aria-label", `Switch to ${scheme() === "dark" ? "light" : "dark"} mode`); };
    listeners.push(label); label();
    b.addEventListener("click", () => Theme.set({mode: scheme() === "dark" ? "light" : "dark"}, true));
  });

  return {
    THEMES, MODES,
    get: () => ({mode, theme, scheme: scheme()}),
    onChange: f => listeners.push(f),
    set(p, save) {
      if (p.mode && MODES.includes(p.mode)) mode = p.mode;
      if (p.theme && THEMES[p.theme]) theme = p.theme;
      apply();
      if (save) fetch("/api/me/prefs", {method: "POST", headers: {"Content-Type": "application/json", "X-Guardian": "1"},
                                        body: JSON.stringify({mode, theme})}).catch(() => {});
    },
  };
})();
