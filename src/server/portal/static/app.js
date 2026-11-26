// TailConnect web portal.
//
// Pages are built from DOM nodes and text only (never innerHTML), so names
// and other data that machines report can't inject markup or scripts.
"use strict";

// ---------- helpers ----------

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "value") e.value = v;
    else if (v === true) e.setAttribute(k, "");
    else e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === undefined || kid === null || kid === false) continue;
    e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return e;
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (method !== "GET") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body || {});
  }
  const r = await fetch("/api" + path, opts);
  let data = null;
  try { data = await r.json(); } catch (_) { /* empty */ }
  if (r.status === 401 && path !== "/login" && state.me) {
    state.me = null;
    render();
  }
  if (!r.ok) throw new Error((data && data.error) || r.statusText);
  return data;
}

let toastTimer;
function toast(msg, bad) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "show" + (bad ? " bad" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ""), bad ? 6000 : 2500);
}

// Run an action, report errors, then refresh the current tab.
async function act(fn, okMsg) {
  try {
    await fn();
    if (okMsg) toast(okMsg);
  } catch (e) {
    toast(e.message, true);
  }
  await refresh();
}

function ago(t) {
  if (!t) return "never";
  const s = Math.floor(Date.now() / 1000) - t;
  if (s < 0) return "in " + span(-s);
  if (s < 10) return "just now";
  return span(s) + " ago";
}
function span(s) {
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}

function copyButton(text) {
  return el("button", {
    type: "button",
    onclick: async () => {
      try { await navigator.clipboard.writeText(text); toast("Copied"); }
      catch (_) { toast("Copy failed: select the text instead", true); }
    },
  }, "Copy");
}

// A small modal form. fields: [{name, label, value, type, placeholder}]
function ask(title, fields, okLabel) {
  return new Promise((resolve) => {
    const inputs = {};
    const form = el("form", { method: "dialog" },
      fields.map((f) => {
        const i = el("input", { name: f.name, type: f.type || "text", value: f.value || "", placeholder: f.placeholder || "", autocomplete: "off" });
        inputs[f.name] = i;
        return el("label", {}, f.label, i);
      }),
      el("div", { class: "buttons" },
        el("button", { type: "button", onclick: () => { d.close(); resolve(null); } }, "Cancel"),
        el("button", { class: "primary", type: "submit" }, okLabel || "Save")));
    const d = el("dialog", {}, el("h3", {}, title), form);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const out = {};
      for (const [k, i] of Object.entries(inputs)) out[k] = i.value;
      d.close();
      resolve(out);
    });
    d.addEventListener("close", () => d.remove());
    document.body.append(d);
    d.showModal();
    const first = Object.values(inputs)[0];
    if (first) first.focus();
  });
}

function confirmDo(msg) {
  return new Promise((resolve) => {
    const d = el("dialog", {},
      el("h3", {}, msg),
      el("div", { class: "buttons" },
        el("button", { type: "button", onclick: () => { d.close(); resolve(false); } }, "Cancel"),
        el("button", { class: "primary danger", type: "button", onclick: () => { d.close(); resolve(true); } }, "Yes")));
    d.addEventListener("close", () => d.remove());
    document.body.append(d);
    d.showModal();
  });
}

function table(headers, rows, empty) {
  return el("div", { class: "panel" },
    el("table", {},
      el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
      el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { class: "empty", colspan: headers.length }, empty)))));
}

function fmtBytes(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)) + " " + u[i];
}
function fmtRate(n) { return fmtBytes(n) + "/s"; }

// Traffic cell: current speeds, and totals since the machine's tunnel started.
function trafficCell(m) {
  if (!m.traffic) return el("td", { class: "sub", title: "No report: idle, offline, or an older tcd" }, "–");
  const t = m.traffic;
  return el("td", {},
    el("button", { class: "link traffic", title: "Traffic per peer", onclick: () => showTraffic(m) },
      el("div", {}, "↓ " + fmtRate(t.rx_rate) + "  ↑ " + fmtRate(t.tx_rate)),
      el("div", { class: "sub" }, fmtBytes(t.rx) + " / " + fmtBytes(t.tx))));
}

async function showTraffic(m) {
  let r;
  try { r = await api("GET", "/machines/" + m.id + "/traffic"); } catch (e) { toast(e.message, true); return; }
  const rows = r.peers.map((x) => el("tr", {},
    el("td", {}, x.peer, x.ip ? el("div", { class: "sub mono" }, x.ip) : null),
    el("td", {}, fmtRate(x.rx_rate)), el("td", {}, fmtRate(x.tx_rate)),
    el("td", {}, fmtBytes(x.rx)), el("td", {}, fmtBytes(x.tx))));
  const d = el("dialog", { class: "wide" },
    el("h3", {}, "Traffic of " + r.machine),
    el("p", { class: "hint" }, r.reported
      ? "From " + m.name + "'s point of view: ↓ received, ↑ sent. Speeds are averages over its last report interval; totals count from when its tunnel started. Last report " + ago(Math.floor(Date.now() / 1000) - r.age) + "."
      : "This machine hasn't reported any traffic."),
    table(["Peer", "↓ speed", "↑ speed", "↓ total", "↑ total"], rows, "No traffic."),
    el("div", { class: "buttons" }, el("button", { class: "primary", onclick: () => d.close() }, "Close")));
  d.addEventListener("close", () => d.remove());
  document.body.append(d);
  d.showModal();
}

// A machine's key: waiting for approval, expired, expiring soon, never.
function keyBadge(m) {
  const now = Math.floor(Date.now() / 1000);
  if (!m.approved) return el("div", {}, badge("needs approval", "warn"));
  if (m.expired) return el("div", {}, badge("key expired", "bad"));
  if (m.expires === null || m.expires === undefined) return el("div", { class: "sub" }, "never expires");
  const soon = m.expires - now < 14 * 86400;
  return el("div", { class: "sub" }, soon ? badge("expires " + ago(m.expires), "warn") : "expires " + ago(m.expires));
}

function expiryDialog(m) {
  const choose = (expiry, msg) => { d.close(); act(() => api("POST", "/machines/" + m.id + "/expiry", { expiry }), msg); };
  const d = el("dialog", {},
    el("h3", {}, "Key expiry for " + m.name),
    el("p", { class: "hint" }, "An expired machine is cut off until it's renewed (here, or with sudo tcs up --authkey KEY on it). A later expiry brings it back at once."),
    el("div", { class: "buttons", style: "flex-wrap:wrap;justify-content:flex-start" },
      el("button", { onclick: () => choose("180d", "Expires in 6 months") }, "6 months"),
      el("button", { onclick: () => choose("365d", "Expires in 12 months") }, "12 months"),
      el("button", { onclick: () => choose("730d", "Expires in 24 months") }, "24 months"),
      el("button", { onclick: () => choose("default", "Expiry set to the server's default") }, "Server default"),
      el("button", { onclick: () => choose("never", "Never expires") }, "Never")),
    el("div", { class: "buttons" }, el("button", { onclick: () => d.close() }, "Cancel")));
  d.addEventListener("close", () => d.remove());
  document.body.append(d);
  d.showModal();
}

function badge(text, kind) {
  return el("span", { class: "badge " + (kind || "") }, text);
}

function fields(obj) {
  // FormData → plain object (checkboxes as booleans)
  const o = {};
  for (const e of obj.elements) {
    if (!e.name) continue;
    o[e.name] = e.type === "checkbox" ? e.checked : e.value;
  }
  return o;
}

// ---------- state ----------

const state = {
  info: null,
  me: null,
  tab: "machines",
  view: "login", // login | signup (when signed out)
  account: "", // operator's chosen account for keys and rules
  accounts: [],
  secret: null, // {title, value, extra} shown once
};

const app = document.getElementById("app");

async function boot() {
  try { state.info = await api("GET", "/info"); } catch (e) { state.info = { signup: "off", domain: "" }; }
  try { state.me = await api("GET", "/me"); } catch (_) { state.me = null; }
  render();
  setInterval(() => { if (state.me && state.tab === "machines" && !document.querySelector("dialog")) refresh(); }, 10000);
}

function render() {
  app.replaceChildren(state.me ? shell() : (state.view === "signup" ? signupView() : loginView()));
  if (state.me) refresh();
}

// ---------- sign in / sign up ----------

function loginView() {
  const err = el("div", { class: "err" });
  let useToken = false;
  const nameI = el("input", { name: "name", autocomplete: "username", required: true });
  const pwI = el("input", { name: "password", type: "password", autocomplete: "current-password", required: true });
  const tokenI = el("input", { name: "admin_token", type: "password", autocomplete: "off" });
  const nameField = el("label", {}, "Account name", nameI);
  const pwField = el("label", {}, "Password", pwI);
  const tokenField = el("label", { hidden: true }, "Admin token", tokenI);
  const toggle = el("button", {
    type: "button", class: "link",
    onclick: () => {
      useToken = !useToken;
      nameField.hidden = pwField.hidden = useToken;
      tokenField.hidden = !useToken;
      nameI.required = pwI.required = !useToken;
      toggle.textContent = useToken ? "Sign in with an account" : "Use the admin token";
    },
  }, "Use the admin token");
  const form = el("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      try {
        const body = useToken ? { admin_token: tokenI.value } : { name: nameI.value, password: pwI.value };
        await api("POST", "/login", body);
        state.me = await api("GET", "/me");
        state.tab = "machines";
        render();
      } catch (ex) { err.textContent = ex.message; }
    },
  }, nameField, pwField, tokenField, err, el("button", { class: "primary", type: "submit" }, "Sign in"));
  return el("div", { class: "auth" },
    el("h1", {}, "TailConnect"),
    el("p", { class: "hint" }, "Sign in to manage your network."),
    form,
    el("div", { class: "links" },
      state.info.signup !== "off"
        ? el("button", { type: "button", class: "link", onclick: () => { state.view = "signup"; render(); } }, "Create an account")
        : el("span"),
      toggle));
}

function signupView() {
  const err = el("div", { class: "err" });
  const preview = el("p", { class: "hint" });
  const nameI = el("input", { name: "name", required: true, autocomplete: "username", maxlength: 32 });
  const upd = () => {
    const n = nameI.value.trim().toLowerCase() || "you";
    preview.textContent = "Your machines will be called laptop." + n + "." + state.info.domain;
  };
  nameI.addEventListener("input", upd);
  upd();
  const pw1 = el("input", { type: "password", required: true, minlength: 10, autocomplete: "new-password" });
  const pw2 = el("input", { type: "password", required: true, minlength: 10, autocomplete: "new-password" });
  const inv = el("input", { autocomplete: "off", required: state.info.signup === "invite" });
  const form = el("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      if (pw1.value !== pw2.value) { err.textContent = "The passwords don't match"; return; }
      try {
        const r = await api("POST", "/signup", { name: nameI.value, password: pw1.value, invite: inv.value });
        if (r.status === "active") {
          state.me = await api("GET", "/me");
          render();
        } else {
          state.view = "login";
          render();
          toast("Account created: an operator has to approve it before you can sign in");
        }
      } catch (ex) { err.textContent = ex.message; }
    },
  },
  el("label", {}, "Account name (a-z, 0-9 and -)", nameI), preview,
  el("label", {}, "Password (at least 10 characters)", pw1),
  el("label", {}, "Password again", pw2),
  el("label", {}, state.info.signup === "invite" ? "Invite code" : "Invite code (optional: skips approval)", inv),
  err,
  el("button", { class: "primary", type: "submit" }, "Create account"));
  return el("div", { class: "auth" },
    el("h1", {}, "Create an account"),
    el("p", { class: "hint" }, state.info.signup === "approval" ? "An operator approves new accounts, unless you have an invite code." : "Your account is a private network of your own."),
    form,
    el("div", { class: "links" }, el("button", { type: "button", class: "link", onclick: () => { state.view = "login"; render(); } }, "Back to sign in"), el("span")));
}

// ---------- shell ----------

const TABS = [
  ["machines", "Machines"],
  ["keys", "Auth keys"],
  ["rules", "Access rules"],
  ["sharing", "Sharing"],
  ["accounts", "Accounts", true],
  ["me", "My account"],
];

let content;
function shell() {
  const me = state.me;
  content = el("main", {});
  return el("div", {},
    el("header", { class: "top" },
      el("div", { class: "brand" }, "TailConnect ", el("span", {}, me.domain)),
      el("div", { class: "who" },
        el("span", {}, me.admin_token ? "admin token" : me.name),
        me.operator ? badge("operator", "ok") : null,
        el("button", { onclick: async () => { try { await api("POST", "/logout"); } catch (_) {} state.me = null; render(); } }, "Sign out"))),
    el("nav", { class: "tabs" },
      TABS.filter(([, , op]) => !op || me.operator)
        .filter(([id]) => !(id === "me" && me.admin_token))
        .map(([id, label]) => el("button", {
          class: state.tab === id ? "on" : "", id: "tab-" + id,
          onclick: () => { state.tab = id; state.secret = null; render(); },
        }, label))),
    content);
}

async function refresh() {
  if (!state.me || !content) return;
  try {
    if (state.me.operator) state.accounts = await api("GET", "/accounts");
    const view = await ({
      machines: machinesTab, keys: keysTab, rules: rulesTab, sharing: sharingTab,
      accounts: accountsTab, me: meTab,
    }[state.tab] || machinesTab)();
    content.replaceChildren(...[].concat(view));
    const pending = state.accounts.filter((a) => a.status === "pending").length;
    const t = document.getElementById("tab-accounts");
    if (t) t.replaceChildren("Accounts", pending ? el("span", { class: "count" }, pending) : "");
  } catch (e) {
    content.replaceChildren(el("p", { class: "hint" }, e.message));
  }
}

function accountPicker(onchange) {
  if (!state.me.operator) return null;
  const names = state.accounts.map((a) => a.name);
  if (!state.account || !names.includes(state.account)) state.account = state.me.name && names.includes(state.me.name) ? state.me.name : (names[0] || "");
  return el("label", {}, "Account",
    el("select", { onchange: (e) => { state.account = e.target.value; onchange(); } },
      names.map((n) => el("option", { value: n, selected: n === state.account }, n))));
}

function secretBox() {
  if (!state.secret) return null;
  const s = state.secret;
  return el("div", { class: "secret" },
    el("div", {}, el("strong", {}, s.title), " — shown once: copy it now."),
    el("div", { class: "row" }, el("span", { class: "mono" }, s.value), copyButton(s.value)),
    s.extra ? el("div", { class: "row" }, el("span", { class: "mono" }, s.extra), copyButton(s.extra)) : null,
    s.qr ? el("div", { class: "qr" },
      el("img", { src: "data:image/svg+xml;charset=utf-8," + encodeURIComponent(s.qr), alt: "QR code of the join link", width: 220, height: 220 }),
      el("div", { class: "qr-text" },
        el("strong", {}, "Join with a phone or another device"),
        el("p", { class: "hint" }, "The code holds this join link (the hub, the key" + (state.me.tls_fingerprint ? ", the certificate's fingerprint" : "") + "). Scan it, or copy the link to a device that has TailConnect-SSH."),
        s.link ? el("div", { class: "row" }, el("span", { class: "mono" }, s.link), copyButton(s.link)) : null)) : null);
}

// ---------- machines ----------

async function machinesTab() {
  const ms = await api("GET", "/machines");
  const online = ms.filter((m) => m.online).length;
  const ops = state.me.operator;
  const cards = el("div", { class: "cards" },
    el("div", { class: "card" }, el("div", { class: "k" }, "Machines online"), el("div", { class: "v" }, online + " / " + ms.length)),
    ops ? el("div", { class: "card" }, el("div", { class: "k" }, "Accounts"), el("div", { class: "v" }, state.accounts.length)) : null,
    ops ? el("div", { class: "card" }, el("div", { class: "k" }, "Accounts waiting"), el("div", { class: "v" }, state.accounts.filter((a) => a.status === "pending").length)) : null,
    el("div", { class: "card" }, el("div", { class: "k" }, "Machines waiting for approval"), el("div", { class: "v" }, ms.filter((m) => !m.approved).length)),
    el("div", { class: "card" }, el("div", { class: "k" }, "MagicDNS domain"), el("div", { class: "v mono", style: "font-size:1rem;padding-top:.3rem" }, state.me.domain)));
  const rows = ms.map((m) => el("tr", {},
    el("td", {}, el("span", { class: "dot" + (m.online ? " on" : ""), title: m.online ? "online" : "offline" })),
    el("td", {},
      el("div", {}, el("strong", {}, m.name)),
      el("div", { class: "sub mono" }, m.fqdn),
      m.tags.map((t) => el("span", { class: "chip" }, "tag:" + t)),
      m.exit_node ? el("span", { class: "chip exit" }, "exit node") : null,
      m.ephemeral ? el("span", { class: "chip" }, "ephemeral") : null,
      keyBadge(m)),
    ops ? el("td", {}, m.account) : null,
    el("td", { class: "mono" }, m.ip),
    el("td", {}, m.hostname),
    el("td", {}, m.online ? "now" : ago(m.last_seen)),
    trafficCell(m),
    el("td", { class: "actions" },
      el("button", { onclick: async () => {
        const r = await ask("Tags for " + m.name, [{ name: "tags", label: "Tags, separated by commas (for example server, db)", value: m.tags.join(", ") }]);
        if (r) act(() => api("POST", "/machines/" + m.id + "/tags", { tags: r.tags }), "Tags saved");
      } }, "Tags"),
      m.approved ? null : el("button", { class: "primary", onclick: () => act(() => api("POST", "/machines/" + m.id + "/approve"), "Approved: " + m.name + " joins the network") }, "Approve"),
      el("button", { title: "When this machine's key expires", onclick: () => expiryDialog(m) }, "Expiry"),
      el("button", {
        title: m.exit_node
          ? "Stop routing internet traffic for this account's machines"
          : "Let this account's machines send their internet traffic through this machine (Linux)",
        onclick: () => act(() => api("POST", "/machines/" + m.id + "/exit-node", { enabled: !m.exit_node }),
          m.exit_node ? "Exit node off" : "Exit node on: machines of " + m.account + " can use it with tcs up --exit-node " + m.name),
      }, m.exit_node ? "Exit node: on" : "Exit node: off"),
      el("button", { onclick: async () => {
        const r = await ask("Rename " + m.name, [{ name: "name", label: "New name", value: m.name }]);
        if (r) act(() => api("POST", "/machines/" + m.id + "/rename", { name: r.name }), "Renamed");
      } }, "Rename"),
      el("button", { class: "danger", onclick: async () => {
        if (await confirmDo("Remove " + m.name + "? It needs a new auth key to join again.")) act(() => api("DELETE", "/machines/" + m.id), "Removed");
      } }, "Remove"))));
  return [cards, table(["", "Name", ops ? "Account" : null, "Address", "Hostname", "Last seen", "Traffic", ""].filter((h) => h !== null), rows, "No machines yet: create an auth key and join one.")];
}

// ---------- auth keys ----------

async function keysTab() {
  const keys = await api("GET", "/keys");
  const me = state.me;
  const form = el("form", {
    class: "inline",
    onsubmit: (e) => {
      e.preventDefault();
      const f = fields(e.target);
      act(async () => {
        const r = await api("POST", "/keys", { account: me.operator ? state.account : null, reusable: f.reusable, ephemeral: f.ephemeral, preapproved: f.preapproved, expires_hours: Number(f.expires) });
        const fp = me.tls_fingerprint ? " --tls-fingerprint " + me.tls_fingerprint : "";
        state.secret = { title: "Auth key for " + r.account, value: r.key, extra: "sudo tcs up --server " + me.server + fp + " --authkey " + r.key, qr: r.qr_svg, link: r.join_url };
      });
    },
  },
  accountPicker(refresh),
  el("label", {}, "Expires", el("select", { name: "expires" },
    [[1, "1 hour"], [24, "1 day"], [168, "7 days"], [720, "30 days"], [2160, "90 days"]].map(([v, t]) => el("option", { value: v, selected: v === 24 }, t)))),
  el("label", { class: "check" }, el("input", { type: "checkbox", name: "reusable" }), "Reusable"),
  el("label", { class: "check", title: "Machines that join with it are removed after being offline for a while" }, el("input", { type: "checkbox", name: "ephemeral" }), "Ephemeral"),
  el("label", { class: "check", title: "Machines that join with it skip the account's machine approval" }, el("input", { type: "checkbox", name: "preapproved" }), "Pre-approved"),
  el("button", { class: "primary", type: "submit" }, "Create key"));
  const rows = keys.map((k) => el("tr", {},
    el("td", { class: "mono" }, k.prefix + "…"),
    me.operator ? el("td", {}, k.account) : null,
    el("td", {}, [k.reusable ? "reusable" : "single use", k.ephemeral ? "ephemeral" : null, k.preapproved ? "pre-approved" : null].filter(Boolean).join(", ")),
    el("td", {}, k.used),
    el("td", {}, badge(k.state, k.state === "active" ? "ok" : "")),
    el("td", {}, k.expires ? ago(k.expires) : "never"),
    el("td", {}, ago(k.created)),
    el("td", { class: "actions" }, k.state === "active"
      ? el("button", { class: "danger", onclick: () => act(() => api("POST", "/keys/" + k.id + "/revoke"), "Revoked") }, "Revoke") : null)));
  return [
    el("h2", {}, "Create an auth key"),
    el("p", { class: "hint" }, "A machine joins with an auth key. Machines that joined stay when the key expires or is revoked."),
    el("div", { class: "panel" }, form, secretBox()),
    el("h2", {}, "Keys"),
    table(["Key", me.operator ? "Account" : null, "Kind", "Uses", "Status", "Expires", "Created", ""].filter((h) => h !== null), rows, "No keys yet."),
  ];
}

// ---------- access rules ----------

async function rulesTab() {
  const q = state.me.operator && state.account ? "?account=" + encodeURIComponent(state.account) : "";
  const r = await api("GET", "/rules" + q);
  const form = el("form", {
    class: "inline",
    onsubmit: (e) => {
      e.preventDefault();
      const f = fields(e.target);
      act(async () => {
        if (!r.rules.length && !(await confirmDo("This is " + r.account + "'s first rule: afterwards, only what rules allow is reachable between its machines. Continue?"))) return;
        await api("POST", "/rules", { account: r.account, from: f.from, to: f.to, ports: f.ports });
      }, "Rule added");
    },
  },
  accountPicker(refresh),
  el("label", {}, "From", el("input", { name: "from", placeholder: "tag:staff", required: true })),
  el("label", {}, "To", el("input", { name: "to", placeholder: "tag:server", required: true })),
  el("label", {}, "Ports", el("input", { name: "ports", placeholder: "tcp:22,tcp:443 or *" })),
  el("button", { class: "primary", type: "submit" }, "Add rule"));
  const rows = r.rules.map((x) => el("tr", {},
    el("td", { class: "mono" }, x.from), el("td", { class: "arrow" }, "→"), el("td", { class: "mono" }, x.to), el("td", { class: "mono" }, x.ports),
    el("td", { class: "actions" }, el("button", { class: "danger", onclick: async () => {
      if (r.rules.length === 1 && !(await confirmDo("Delete the last rule? Every machine of " + r.account + " can then reach every other again."))) return;
      act(() => api("DELETE", "/rules/" + x.id), "Rule deleted");
    } }, "Delete"))));
  return [
    el("h2", {}, "Access rules for " + r.account),
    el("p", { class: "hint" }, r.rules.length
      ? "Only what these rules allow can be opened between this account's machines. Replies always get back."
      : "No rules: every machine of this account can reach every other. The first rule changes that to only what the rules allow."),
    el("p", { class: "hint" }, "From and To: *, tag:NAME or a machine name. Ports: * or a list of 22, 8000-8100, tcp:443, udp:53, icmp."),
    el("div", { class: "panel" }, form),
    el("h2", {}, "Rules"),
    table(["From", "", "To", "Ports", ""], rows, "No rules."),
  ];
}

// ---------- sharing ----------

async function sharingTab() {
  const [sh, ms] = await Promise.all([api("GET", "/shares"), api("GET", "/machines")]);
  const me = state.me;
  const mine = me.operator ? ms : ms.filter((m) => m.account === me.name);
  const machineSelect = () => el("select", { name: "node_id", required: true },
    mine.map((m) => el("option", { value: m.id }, m.name + "." + m.account)));
  const shareForm = el("form", {
    class: "inline",
    onsubmit: (e) => {
      e.preventDefault();
      const f = fields(e.target);
      act(() => api("POST", "/shares", { node_id: Number(f.node_id), account: f.account, ports: f.ports }), "Shared: it takes effect once they accept");
    },
  },
  el("div", { class: "lead" }, "Share with an account"),
  el("label", {}, "Machine", machineSelect()),
  el("label", {}, "With account", el("input", { name: "account", required: true, placeholder: "account name" })),
  el("label", {}, "Ports", el("input", { name: "ports", placeholder: "* or tcp:80,tcp:443" })),
  el("button", { class: "primary", type: "submit" }, "Share"));
  const linkForm = el("form", {
    class: "inline",
    onsubmit: (e) => {
      e.preventDefault();
      const f = fields(e.target);
      act(async () => {
        const r = await api("POST", "/share-links", { node_id: Number(f.node_id), ports: f.ports, days: Number(f.days) });
        state.secret = { title: "Share link", value: r.code };
      });
    },
  },
  el("div", { class: "lead" }, "Or create a link: whoever redeems it first gets access"),
  el("label", {}, "Machine", machineSelect()),
  el("label", {}, "Ports", el("input", { name: "ports", placeholder: "* or tcp:445" })),
  el("label", {}, "Valid for", el("select", { name: "days" }, [[1, "1 day"], [7, "7 days"], [30, "30 days"]].map(([v, t]) => el("option", { value: v, selected: v === 7 }, t)))),
  el("button", { type: "submit" }, "Create link"));

  const byMe = sh.by_me.map((s) => el("tr", {},
    el("td", {}, s.machine), el("td", {}, s.account), el("td", { class: "mono" }, s.ports),
    el("td", {}, badge(s.status, s.status === "active" ? "ok" : "warn")),
    el("td", { class: "actions" },
      el("button", { onclick: async () => {
        const r = await ask("Ports for " + s.machine + " shared with " + s.account, [{ name: "ports", label: "* or a list such as tcp:80,tcp:443", value: s.ports }]);
        if (r) act(() => api("POST", "/shares/" + s.id + "/ports", { ports: r.ports }), "Ports saved");
      } }, "Ports"),
      el("button", { class: "danger", onclick: () => act(() => api("DELETE", "/shares/" + s.id), "Share ended") }, "Revoke"))));
  const links = sh.links.map((l) => el("tr", {},
    el("td", { class: "mono" }, l.prefix + "…"), el("td", {}, l.machine), el("td", { class: "mono" }, l.ports),
    el("td", {}, l.state === "used" ? "used by " + l.used_by : badge(l.state, l.state === "unused" ? "ok" : "")),
    el("td", {}, ago(l.expires)),
    el("td", { class: "actions" }, l.state === "unused"
      ? el("button", { class: "danger", onclick: () => act(() => api("DELETE", "/share-links/" + l.id), "Link revoked") }, "Revoke") : null)));
  const withMe = sh.with_me.map((s) => el("tr", {},
    el("td", {}, s.machine), el("td", {}, s.owner), el("td", { class: "mono" }, s.ports),
    el("td", {}, badge(s.status, s.status === "active" ? "ok" : "warn")),
    el("td", { class: "actions" },
      s.status === "pending" ? el("button", { class: "primary", onclick: () => act(() => api("POST", "/shares/" + s.id + "/accept"), "Accepted") }, "Accept") : null,
      el("button", { class: "danger", onclick: () => act(() => api("DELETE", "/shares/" + s.id), "Removed") }, s.status === "pending" ? "Decline" : "Remove"))));
  const redeem = el("form", {
    class: "inline",
    onsubmit: (e) => {
      e.preventDefault();
      const f = fields(e.target);
      act(() => api("POST", "/share-links/redeem", { code: f.code }), "Added");
    },
  }, el("label", {}, "Share link", el("input", { name: "code", required: true, placeholder: "tc-share-…", size: 40 })),
  el("button", { class: "primary", type: "submit" }, "Add"));

  return [
    el("h2", {}, "Shared by me"),
    el("p", { class: "hint" }, "Sharing lets another account's machines connect to one of yours. It's one-way: your machine can only reply."),
    el("div", { class: "panel" }, shareForm, linkForm, secretBox()),
    table(["Machine", "Shared with", "Ports", "Status", ""], byMe, "Nothing shared."),
    el("h2", {}, "Share links"),
    table(["Link", "Machine", "Ports", "Status", "Expires", ""], links, "No links."),
    me.admin_token ? null : el("h2", {}, "Shared with me"),
    me.admin_token ? null : el("div", { class: "panel" }, redeem),
    me.admin_token ? null : table(["Machine", "Owner", "Ports", "Status", ""], withMe, "Nothing shared with you."),
  ];
}

// ---------- accounts (operators) ----------

async function accountsTab() {
  const invites = await api("GET", "/invites");
  const me = state.me;
  const add = el("form", {
    class: "inline",
    onsubmit: (e) => {
      e.preventDefault();
      const f = fields(e.target);
      act(() => api("POST", "/accounts", { name: f.name, password: f.password, operator: f.operator }), "Account created");
    },
  },
  el("label", {}, "Name", el("input", { name: "name", required: true, maxlength: 32 })),
  el("label", {}, "Password (optional)", el("input", { name: "password", type: "password", autocomplete: "new-password" })),
  el("label", { class: "check" }, el("input", { type: "checkbox", name: "operator" }), "Operator"),
  el("button", { class: "primary", type: "submit" }, "Add account"));
  const sorted = [...state.accounts].sort((a, b) => (a.status === "pending" ? 0 : 1) - (b.status === "pending" ? 0 : 1) || a.name.localeCompare(b.name));
  const rows = sorted.map((a) => {
    const self = a.name === me.name;
    return el("tr", {},
      el("td", {}, el("strong", {}, a.name), self ? el("span", { class: "sub" }, " (you)") : null),
      el("td", {}, a.role),
      el("td", {}, badge(a.status, a.status === "active" ? "ok" : a.status === "pending" ? "warn" : "bad")),
      el("td", {}, a.has_password ? "yes" : "no"),
      el("td", { class: "mono" }, a.dns_domain || el("span", { class: "sub" }, a.name + "." + me.domain)),
      el("td", {}, a.machines),
      el("td", {}, ago(a.created)),
      el("td", { class: "actions" },
        a.status === "pending" ? el("button", { class: "primary", onclick: () => act(() => api("POST", "/accounts/" + a.id + "/status", { status: "active" }), "Approved") }, "Approve") : null,
        a.status === "active" && !self ? el("button", { onclick: () => act(() => api("POST", "/accounts/" + a.id + "/status", { status: "suspended" }), "Suspended") }, "Suspend") : null,
        a.status === "suspended" ? el("button", { onclick: () => act(() => api("POST", "/accounts/" + a.id + "/status", { status: "active" }), "Reactivated") }, "Reactivate") : null,
        self ? null : el("button", { onclick: () => act(() => api("POST", "/accounts/" + a.id + "/role", { role: a.role === "operator" ? "tenant" : "operator" }), "Role changed") }, a.role === "operator" ? "Make tenant" : "Make operator"),
        el("button", { onclick: async () => {
          const r = await ask((a.has_password ? "Reset password for " : "Set password for ") + a.name, [{ name: "password", label: "New password (at least 10 characters)", type: "password" }]);
          if (r) act(() => api("POST", "/accounts/" + a.id + "/password", { password: r.password }), "Password set");
        } }, a.has_password ? "Reset password" : "Set password"),
        el("button", { onclick: async () => {
          const r = await ask("MagicDNS domain for " + a.name, [{ name: "domain", label: "A domain such as acme.internal; empty for the default (" + a.name + "." + me.domain + ")", value: a.dns_domain || "" }]);
          if (r) act(() => api("POST", "/accounts/" + a.id + "/dns-domain", { domain: r.domain }), "Domain saved");
        } }, "DNS domain"),
        self ? null : el("button", { class: "danger", onclick: async () => {
          if (await confirmDo("Delete " + a.name + " with its machines, keys, rules and shares, for good?")) act(() => api("DELETE", "/accounts/" + a.id), "Deleted");
        } }, "Delete")));
  });
  const inviteForm = el("form", {
    class: "inline",
    onsubmit: (e) => {
      e.preventDefault();
      const f = fields(e.target);
      act(async () => { const r = await api("POST", "/invites", { days: Number(f.days) }); state.secret = { title: "Invite code", value: r.code }; });
    },
  }, el("label", {}, "Valid for", el("select", { name: "days" }, [[1, "1 day"], [7, "7 days"], [30, "30 days"]].map(([v, t]) => el("option", { value: v, selected: v === 7 }, t)))),
  el("button", { type: "submit" }, "Create invite"));
  const inviteRows = invites.map((i) => el("tr", {},
    el("td", { class: "mono" }, i.prefix + "…"),
    el("td", {}, i.state === "used" ? "used by " + i.used_by : badge(i.state, i.state === "unused" ? "ok" : "")),
    el("td", {}, ago(i.expires)), el("td", {}, ago(i.created)),
    el("td", { class: "actions" }, i.state === "unused" ? el("button", { class: "danger", onclick: () => act(() => api("DELETE", "/invites/" + i.id), "Invite revoked") }, "Revoke") : null)));
  return [
    el("h2", {}, "Accounts"),
    el("p", { class: "hint" }, "Sign-up: " + me.signup + ". Each account is a private network; suspending one cuts its machines off and stops its shares."),
    el("div", { class: "panel" }, add),
    table(["Name", "Role", "Status", "Password", "DNS domain", "Machines", "Created", ""], rows, "No accounts."),
    el("h2", {}, "Invites"),
    el("p", { class: "hint" }, "An invite lets someone create an account without waiting for approval. Each works once."),
    el("div", { class: "panel" }, inviteForm, secretBox()),
    table(["Code", "Status", "Expires", "Created", ""], inviteRows, "No invites."),
  ];
}

// ---------- my account ----------

async function meTab() {
  const form = el("form", {
    class: "inline",
    onsubmit: (e) => {
      e.preventDefault();
      const f = fields(e.target);
      if (f.new !== f.again) { toast("The new passwords don't match", true); return; }
      act(() => api("POST", "/me/password", { current: f.current, new: f.new }), "Password changed: you've been signed out everywhere else");
    },
  },
  el("label", {}, "Current password", el("input", { name: "current", type: "password", required: true, autocomplete: "current-password" })),
  el("label", {}, "New password", el("input", { name: "new", type: "password", required: true, minlength: 10, autocomplete: "new-password" })),
  el("label", {}, "Again", el("input", { name: "again", type: "password", required: true, minlength: 10, autocomplete: "new-password" })),
  el("button", { class: "primary", type: "submit" }, "Change password"));
  const st = await api("GET", "/me/settings");
  const approval = el("input", { type: "checkbox", checked: st.require_approval,
    onchange: (e) => act(() => api("POST", "/me/settings", { require_approval: e.target.checked }),
      e.target.checked ? "New machines now wait for your approval" : "New machines join at once") });
  return [
    el("h2", {}, "My account: " + state.me.name),
    el("p", { class: "hint" }, "Your machines are called NAME." + st.zone + "."),
    el("div", { class: "panel" }, el("form", { class: "inline" },
      el("label", { class: "check" }, approval, "Require approval for new machines"),
      el("span", { class: "sub", style: "padding-bottom:.45rem" }, "New machines stay cut off until approved on the Machines tab. Keys marked pre-approved skip this."))),
    el("h2", {}, "MagicDNS domain"),
    el("p", { class: "hint" },
      "By default your machines are NAME." + st.default_zone + ". You can give them a domain of your own" +
      (state.me.operator ? "" : ", ending in ." + st.allowed_suffixes.join(" or .")) + ", for example laptop.acme." + (st.allowed_suffixes[0] || "internal") + "."),
    el("div", { class: "panel" }, el("form", {
      class: "inline",
      onsubmit: (e) => {
        e.preventDefault();
        const d = fields(e.target).dns_domain;
        act(async () => {
          const r = await api("POST", "/me/settings", { dns_domain: d });
          toast("Your machines are now NAME." + r.zone);
        });
      },
    },
    el("label", {}, "Domain", el("input", { name: "dns_domain", value: st.dns_domain || "", placeholder: st.default_zone, size: 28 })),
    el("button", { class: "primary", type: "submit" }, "Save"),
    st.dns_domain ? el("button", { type: "button", onclick: () => act(() => api("POST", "/me/settings", { dns_domain: "" }), "Back to NAME." + st.default_zone) }, "Use the default") : null)),
    el("h2", {}, "Change password"),
    el("div", { class: "panel" }, form),
  ];
}

boot();
