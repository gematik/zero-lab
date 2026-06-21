"use strict";

const panel = document.getElementById("panel");

let providers = [];
let fuse = null;
let rows = []; // currently shown providers
let active = 0;

const SEARCH_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>`;

// Friendly labels for the identity claims we surface first (the rest live under "Raw claims").
const CLAIM_LABELS = [
  ["urn:telematik:claims:display_name", "Name"],
  ["name", "Name"],
  ["given_name", "First name"],
  ["family_name", "Last name"],
  ["email", "Email"],
  ["urn:telematik:claims:email", "Email"],
  ["urn:telematik:claims:id", "Insurance number"],
  ["idNummer", "Insurance number"],
  ["urn:telematik:claims:organization", "Insurer"],
  ["organizationName", "Insurer"],
  ["birthdate", "Date of birth"],
  ["urn:telematik:claims:geburtsdatum", "Date of birth"],
  ["iss", "Issuer"],
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

async function boot() {
  const params = new URLSearchParams(location.search);
  if (params.get("error")) {
    renderError(params.get("error"), params.get("error_description"));
    return;
  }
  const resp = await api("/bff/auth/session");
  if (resp.status === 200) {
    const data = await resp.json();
    renderIdentity(data.userinfo || {});
  } else {
    renderChooser();
  }
}

async function renderChooser() {
  panel.innerHTML = `
    <header class="panel-head">
      <span class="brand">Zero Trust Lab</span>
      <h1>Sign in with your health insurer</h1>
      <p class="sub">Choose your Krankenkasse to continue.</p>
    </header>
    <div class="search">
      ${SEARCH_ICON}
      <input id="q" type="text" inputmode="search" enterkeyhint="search" placeholder="Search insurers…" autocomplete="off" spellcheck="false" autofocus>
      <kbd class="count">…</kbd>
    </div>
    <ul id="results" class="results" role="listbox" aria-label="Health insurers"></ul>
    <p class="hint"><kbd>↑</kbd> <kbd>↓</kbd> to move · <kbd>Enter</kbd> to choose</p>`;

  const resp = await api("/bff/auth/providers");
  providers = resp.ok ? await resp.json() : [];
  fuse = new Fuse(providers, { keys: ["name", "iss"], threshold: 0.4, ignoreLocation: true });

  document.querySelector(".count").textContent = providers.length;
  document.getElementById("q").placeholder = `Search ${providers.length} insurers…`;

  const q = document.getElementById("q");
  q.addEventListener("input", () => filter(q.value));
  q.addEventListener("keydown", onSearchKey);
  filter("");
  q.focus();
}

function filter(query) {
  rows = query.trim() ? fuse.search(query).map((r) => r.item) : providers;
  active = 0;
  const ul = document.getElementById("results");
  if (!rows.length) {
    ul.innerHTML = `<li class="empty">No insurer matches “${esc(query)}”.</li>`;
    return;
  }
  ul.innerHTML = rows.map(rowHtml).join("");
  [...ul.querySelectorAll(".row")].forEach((el) => {
    const i = Number(el.dataset.i);
    el.addEventListener("click", () => startLogin(rows[i].iss));
    const img = el.querySelector("img");
    if (img) img.addEventListener("error", () => img.remove());
  });
  paintActive();
}

function rowHtml(p, i) {
  const logo = p.logo_uri ? `<img src="${esc(p.logo_uri)}" alt="" loading="lazy">` : "";
  return `<li class="row" role="option" data-i="${i}">
    <span class="logo" data-mono="${esc(monogram(p.name))}">${logo}</span>
    <span class="meta">
      <span class="name">${esc(p.name || host(p.iss))}</span>
      <span class="host">${esc(host(p.iss))}</span>
    </span>
    <kbd class="tag">${esc(p.type || "")}</kbd>
  </li>`;
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
  const els = [...document.querySelectorAll(".row")];
  els.forEach((el, i) => el.classList.toggle("active", i === active));
  els[active]?.scrollIntoView({ block: "nearest" });
}

async function startLogin(opIssuer) {
  const resp = await api("/bff/auth/login?op_issuer=" + encodeURIComponent(opIssuer));
  if (!resp.ok) { renderError("login_failed", "Could not start the login."); return; }
  const data = await resp.json();
  if (data.mode === "decoupled") {
    renderDecoupled(data);
  } else {
    location.href = data.auth_url;
  }
}

function renderDecoupled(data) {
  const name = data.op?.name || "your insurer";
  panel.innerHTML = `
    <header class="panel-head">
      <button class="back" id="back">← Choose another</button>
      <span class="brand">Scan to sign in</span>
      <h1>${esc(name)}</h1>
    </header>
    <div class="qr-wrap"><div id="qr"></div></div>
    <p class="status"><span class="pulse"></span> Waiting for you to confirm on your phone…</p>
    <a class="muted-link" href="${esc(data.auth_url)}">Open the link on this device instead</a>`;

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

function renderIdentity(userinfo) {
  const display =
    userinfo["urn:telematik:claims:display_name"] ||
    userinfo.name ||
    [userinfo.given_name, userinfo.family_name].filter(Boolean).join(" ") ||
    userinfo.preferred_username ||
    userinfo.sub ||
    "Signed in";

  const seen = new Set();
  const claimRows = [];
  for (const [key, label] of CLAIM_LABELS) {
    if (userinfo[key] != null && userinfo[key] !== "" && !seen.has(label)) {
      seen.add(label);
      claimRows.push(`<div class="claim"><dt>${esc(label)}</dt><dd>${esc(userinfo[key])}</dd></div>`);
    }
  }

  panel.innerHTML = `
    <header class="panel-head id-head">
      <span class="brand">Signed in</span>
      <h1>${esc(display)}</h1>
      <p class="sub">${esc(userinfo.sub || "")}</p>
    </header>
    <dl class="claims">${claimRows.join("") || '<p class="sub">No profile claims were returned.</p>'}</dl>
    <details class="raw"><summary>Raw claims</summary><pre>${esc(JSON.stringify(userinfo, null, 2))}</pre></details>
    <button id="logout">Sign out</button>`;

  document.getElementById("logout").addEventListener("click", async () => {
    await api("/bff/auth/logout", { method: "POST", headers: { "X-Requested-With": "fetch" } });
    location.href = "/";
  });
}

function renderError(code, description) {
  panel.innerHTML = `
    <header class="panel-head">
      <span class="brand">Zero Trust Lab</span>
      <h1>Sign-in failed</h1>
    </header>
    <p class="error"><b>${esc(code)}</b><br>${esc(description || "")}</p>
    <a href="/" role="button">Try again</a>`;
}

boot();
