"use strict";

const panel = document.getElementById("panel");

let providers = [];
let fuse = null;
let rows = [];
let active = 0;

// Human-readable identity claims surfaced on top. The `mono` flag renders
// identifier-like values (numbers, issuers) in the monospace voice. Everything
// else lives under "Details".
const CLAIM_LABELS = [
  ["urn:telematik:claims:display_name", "Name", false],
  ["name", "Name", false],
  ["given_name", "Given name", false],
  ["family_name", "Family name", false],
  ["urn:telematik:claims:id", "Insurance no.", true],
  ["idNummer", "Insurance no.", true],
  ["birthdate", "Date of birth", false],
  ["urn:telematik:claims:geburtsdatum", "Date of birth", false],
  ["email", "Email", true],
  ["urn:telematik:claims:email", "Email", true],
  ["preferred_username", "Username", false],
  ["iss", "Provider", true],
];

function api(path, opts) {
  return fetch(path, { credentials: "same-origin", ...opts });
}
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function host(iss) {
  try { return new URL(iss).host; } catch { return iss; }
}
function monogram(name) {
  const p = (name || "?").trim().split(/\s+/);
  return ((p[0]?.[0] || "") + (p[1]?.[0] || "")).toUpperCase() || "?";
}

// Short, centered states scroll as a whole; the chooser keeps its own layout so
// the results list can fill the card and scroll inside it.
function setState(html, scroll) {
  panel.className = scroll ? "gw-panel is-scroll" : "gw-panel";
  panel.setAttribute("aria-busy", "false");
  panel.innerHTML = html;
}

async function boot() {
  const params = new URLSearchParams(location.search);
  if (params.get("error")) {
    renderError(params.get("error"), params.get("error_description"));
    return;
  }
  const resp = await api("/bff/auth/session");
  if (resp.status === 200) {
    renderIdentity((await resp.json()).session || {});
  } else if (params.get("login") === "success") {
    renderLoginSuccess();
  } else {
    renderChooser();
  }
}

async function renderChooser() {
  panel.className = "gw-panel";
  panel.setAttribute("aria-busy", "false");
  panel.innerHTML = `
    <div class="gw-head">
      <p class="gw-eyebrow">Identity federation</p>
      <h1 class="gw-title">Choose your identity provider</h1>
      <div class="gw-search">
        <span class="gw-prompt" aria-hidden="true">&rsaquo;</span>
        <input id="q" type="text" inputmode="search" enterkeyhint="search"
               placeholder="Search providers…" autocomplete="off" spellcheck="false"
               role="combobox" aria-expanded="true" aria-controls="results"
               aria-autocomplete="list" aria-label="Search identity providers" autofocus>
        <span class="gw-count" id="count" aria-live="polite">…</span>
      </div>
    </div>
    <div id="results" class="gw-results" role="listbox" aria-label="Identity providers"></div>`;

  const resp = await api("/bff/auth/providers");
  providers = resp.ok ? await resp.json() : [];
  fuse = new Fuse(providers, { keys: ["name", "iss"], threshold: 0.4, ignoreLocation: true });

  const q = document.getElementById("q");
  q.placeholder = `Search ${providers.length} providers…`;
  q.addEventListener("input", () => filter(q.value));
  q.addEventListener("keydown", onSearchKey);
  filter("");
  q.focus();
}

function filter(query) {
  rows = query.trim() ? fuse.search(query).map((r) => r.item) : providers;
  active = 0;
  document.getElementById("count").textContent = rows.length;

  const list = document.getElementById("results");
  if (!rows.length) {
    list.innerHTML = `<div class="gw-empty">No provider matches <code>${esc(query)}</code>.</div>`;
    return;
  }
  list.innerHTML = rows.map(rowHtml).join("");
  [...list.querySelectorAll("[data-i]")].forEach((el) => {
    const i = Number(el.dataset.i);
    el.addEventListener("click", () => startLogin(rows[i].iss));
    el.addEventListener("mousemove", () => setActive(i));
    const img = el.querySelector("img");
    if (img) img.addEventListener("error", () => img.replaceWith(monogramEl(rows[i].name)));
  });
  paintActive();
}

function monogramEl(name) {
  const s = document.createElement("span");
  s.className = "gw-logo";
  s.textContent = monogram(name);
  return s;
}

function rowHtml(p, i) {
  const logo = p.logo_uri
    ? `<img src="${esc(p.logo_uri)}" alt="" class="gw-logo" loading="lazy">`
    : `<span class="gw-logo">${esc(monogram(p.name))}</span>`;
  return `<button type="button" class="gw-row" data-i="${i}" role="option" aria-selected="false" id="opt-${i}">
    ${logo}
    <span class="gw-meta">
      <span class="gw-name">${esc(p.name || host(p.iss))}</span>
      <span class="gw-host">${esc(host(p.iss))}</span>
    </span>
    ${p.type ? `<span class="gw-type">${esc(p.type)}</span>` : ""}
    <span class="gw-go" aria-hidden="true"><i class="bi bi-arrow-return-left"></i></span>
  </button>`;
}

function onSearchKey(e) {
  if (e.key === "ArrowDown") { e.preventDefault(); setActive(active + 1); }
  else if (e.key === "ArrowUp") { e.preventDefault(); setActive(active - 1); }
  else if (e.key === "Enter") { e.preventDefault(); if (rows[active]) startLogin(rows[active].iss); }
}

function setActive(i) {
  if (!rows.length) return;
  active = Math.max(0, Math.min(rows.length - 1, i));
  paintActive();
}

function paintActive() {
  const els = [...document.querySelectorAll("#results [data-i]")];
  els.forEach((el, i) => {
    const on = i === active;
    el.classList.toggle("active", on);
    el.setAttribute("aria-selected", on ? "true" : "false");
  });
  const q = document.getElementById("q");
  if (q && els[active]) q.setAttribute("aria-activedescendant", els[active].id);
  els[active]?.scrollIntoView({ block: "nearest" });
}

async function startLogin(opIssuer) {
  const resp = await api("/bff/auth/login?op_issuer=" + encodeURIComponent(opIssuer));
  if (!resp.ok) { renderError("login_failed", "We couldn't start sign-in with that provider."); return; }
  const data = await resp.json();
  if (data.mode === "decoupled") {
    renderDecoupled(data);
  } else {
    location.href = data.auth_url;
  }
}

function renderDecoupled(data) {
  const name = data.op?.name || "your provider";
  setState(`
    <div class="gw-state gw-state-center">
      <button id="back" class="gw-back" type="button"><i class="bi bi-arrow-left"></i> All providers</button>
      <p class="gw-eyebrow">Scan to continue</p>
      <h2 class="gw-h">${esc(name)}</h2>
      <p class="gw-sub">Open the provider's app on your phone and scan this code.</p>
      <div class="gw-qr"><div id="qr"></div><span class="gw-scan" aria-hidden="true"></span></div>
      <p class="gw-wait"><span class="spinner-border spinner-border-sm"></span> Waiting for confirmation on your phone…</p>
      <div><a class="gw-link" href="${esc(data.auth_url)}">Open on this device instead</a></div>
    </div>`, true);

  const qr = qrcode(0, "M");
  qr.addData(data.auth_url);
  qr.make();
  document.getElementById("qr").innerHTML = qr.createImgTag(5, 0);
  document.getElementById("back").addEventListener("click", renderChooser);

  pollUntilDone();
}

async function pollUntilDone() {
  const resp = await api("/bff/auth/poll");
  if (resp.status === 200) { boot(); return; }
  setTimeout(pollUntilDone, 2000);
}

// renderIdentity shows the whole session (the access-token introspection): the human-readable identity
// claims on top, and everything else — the decoded id_token and the full session — under "Details".
function renderIdentity(session) {
  const id = (session && session.identity) || {}; // upstream identity claims
  const display =
    id["urn:telematik:claims:display_name"] ||
    id.name ||
    [id.given_name, id.family_name].filter(Boolean).join(" ") ||
    id.preferred_username ||
    id.sub ||
    "Verified session";

  const seen = new Set();
  const items = [];
  for (const [key, label, mono] of CLAIM_LABELS) {
    const v = id[key];
    if (v != null && v !== "" && typeof v !== "object" && !seen.has(label)) {
      seen.add(label);
      items.push(`<li>
        <span class="gw-claim-k">${esc(label)}</span>
        <span class="gw-claim-v${mono ? " mono" : ""}">${esc(v)}</span></li>`);
    }
  }

  // Technical details: the decoded token claims (the backend never sends the raw tokens), then the
  // whole session projection.
  let details = "";
  for (const [label, claims] of [["Access token", session.access_token], ["ID token", session.id_token]]) {
    if (claims && typeof claims === "object") {
      details += `<p class="gw-jwt-h">${label} · claims</p><pre>${esc(JSON.stringify(claims, null, 2))}</pre>`;
    }
  }
  details += `<p class="gw-jwt-h">Session</p><pre>${esc(JSON.stringify(session, null, 2))}</pre>`;

  setState(`
    <div class="gw-state gw-state-center">
      <div class="gw-avatar">${esc(monogram(display))}</div>
      <div class="gw-badge-ok">Verified session</div>
      <h1 class="gw-h">${esc(display)}</h1>
      <ul class="gw-claims">${items.join("") || '<li><span class="gw-claim-k">Identity</span><span class="gw-claim-v">No human-readable claims</span></li>'}</ul>
      <details class="gw-raw"><summary>Details</summary>${details}</details>
      <button id="logout" class="gw-btn gw-btn-ghost" type="button">Sign out</button>
    </div>`, true);

  document.getElementById("logout").addEventListener("click", async () => {
    await api("/bff/auth/logout", { method: "POST", headers: { "X-Requested-With": "fetch" } });
    location.href = "/";
  });
}

function renderLoginSuccess() {
  setState(`
    <div class="gw-state gw-state-center">
      <div class="gw-status-ico ok"><i class="bi bi-check-lg"></i></div>
      <h1 class="gw-h">You're signed in</h1>
      <p class="gw-sub">Return to your other device — it continues automatically.</p>
    </div>`, true);
}

function renderError(code, description) {
  setState(`
    <div class="gw-state">
      <div class="gw-state-center">
        <div class="gw-status-ico err"><i class="bi bi-x-lg"></i></div>
        <h1 class="gw-h">Sign-in failed</h1>
      </div>
      <div class="gw-errbox">
        <code>${esc(code)}</code>
        ${description ? `<p>${esc(description)}</p>` : ""}
      </div>
      <a href="/" class="gw-btn gw-btn-primary">Try again</a>
    </div>`, true);
}

boot();
