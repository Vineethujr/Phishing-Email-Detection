"use strict";
/* Phishing Detection & Awareness Dashboard (vanilla JS).
   SECURITY: all API data is inserted with textContent / createTextNode - never innerHTML -
   so an email subject like "<script>..." is displayed as harmless text. */

const $ = (sel, root = document) => root.querySelector(sel);
const NS = "http://www.w3.org/2000/svg";

function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null) e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return e;
}
const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };
const svgEl = (tag, attrs = {}) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };

const CLASS_KEY = { "LOW RISK": "low", "MODERATE RISK": "moderate", "SUSPICIOUS": "suspicious", "HIGH RISK / LIKELY PHISHING": "high" };
const CLASS_COLOR = { low: "#1a7f4b", moderate: "#d49a12", suspicious: "#c8640f", high: "#b42323" };
const INDICATOR_LABEL = { urgency: "Urgent language", credential: "Credential request", fear: "Threat / fear language", financial: "Financial pressure",
  reward: "Prize / reward claim", personal_info: "Personal-info request", sender: "Suspicious sender", url: "Suspicious URL", link_mismatch: "Link text mismatch",
  attachment: "Risky attachment", generic_greeting: "Generic greeting", formatting: "Unusual formatting", combination: "Credential + risky link" };
const keyOf = (cls) => CLASS_KEY[cls] || "low";
const SHORT_CLASS = { "LOW RISK": "LOW", "MODERATE RISK": "MODERATE", "SUSPICIOUS": "SUSPICIOUS", "HIGH RISK / LIKELY PHISHING": "HIGH RISK" };

/* ------------------------------------------------------------------ API */
class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
let token = sessionStorage.getItem("token");

function detailText(d) {
  if (Array.isArray(d)) return d.map((x) => x.msg || "Invalid input").join("; ");
  return typeof d === "string" ? d : "Request failed";
}
async function api(path, { method = "GET", json, form } = {}) {
  const headers = {};
  if (token) headers.Authorization = "Bearer " + token;
  let body;
  if (json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
  if (form) body = form;
  const res = await fetch("/api" + path, { method, headers, body });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.startsWith("/login")) { openLogin(); throw new ApiError(401, "Please sign in to continue"); }
  if (!res.ok) throw new ApiError(res.status, detailText(data.detail));
  return data;
}
function notify(msg, kind = "error") {
  const n = $("#notice");
  n.textContent = msg; n.className = "notice" + (kind === "info" ? " info" : ""); n.hidden = false;
  clearTimeout(notify.t); notify.t = setTimeout(() => { n.hidden = true; }, 6000);
}
const fail = (e) => notify(e.message || "Something went wrong");

/* ------------------------------------------------------------------ routing */
const VIEWS = ["dashboard", "analyze", "history", "learn"];
function show(view) {
  if (!VIEWS.includes(view)) view = "dashboard";
  VIEWS.forEach((v) => { $("#view-" + v).hidden = v !== view; });
  document.querySelectorAll(".tab").forEach((t) => { if (t.dataset.view === view) t.setAttribute("aria-current", "page"); else t.removeAttribute("aria-current"); });
  if (view === "dashboard") loadDashboard(); if (view === "history") loadHistory();
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => { location.hash = t.dataset.view; }));
window.addEventListener("hashchange", () => show(location.hash.slice(1)));

/* ------------------------------------------------------------------ dashboard */
const charts = {};
function drawChart(id, config) {
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($("#" + id), config);
}
Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
Chart.defaults.color = "#5b667a";

async function loadDashboard() {
  try {
    const [s, ind] = await Promise.all([api("/dashboard/stats"), api("/dashboard/indicators?limit=10")]);
    $("#empty-note").hidden = s.total > 0;
    const cards = $("#cards"); clear(cards);
    [["Total Emails Analyzed", s.total, ""], ["Likely Phishing", s.likely_phishing, "k-high"], ["Suspicious", s.suspicious, "k-suspicious"],
     ["Low Risk", s.low_risk, "k-low"], ["Average Risk Score", s.average_risk_score, "k-avg"]]
      .forEach(([label, value, cls]) => cards.append(el("div", { class: "card " + cls }, el("div", { class: "label", text: label }), el("div", { class: "value", text: value }))));

    const bc = s.by_classification, order = ["LOW RISK", "MODERATE RISK", "SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"];
    drawChart("ch-class", { type: "doughnut", data: { labels: ["Low", "Moderate", "Suspicious", "High / likely phishing"],
      datasets: [{ data: order.map((k) => bc[k]), backgroundColor: order.map((k) => CLASS_COLOR[keyOf(k)]), borderWidth: 2, borderColor: "#fff" }] },
      options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { position: "right" } } } });

    const pv = s.phishing_vs_legitimate;
    drawChart("ch-flag", { type: "bar", data: { labels: ["Flagged (score ≥ 41)", "Not flagged"],
      datasets: [{ data: [pv.flagged_suspicious_or_high, pv.not_flagged], backgroundColor: ["#b4500f", "#1a7f4b"], borderRadius: 6 }] },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });

    const rows = ind.top_indicators.filter((x) => x.indicator_type !== "ml");   // ML estimate is shown separately from rule indicators
    drawChart("ch-ind", { type: "bar", data: { labels: rows.map((x) => INDICATOR_LABEL[x.indicator_type] || x.indicator_type),
      datasets: [{ data: rows.map((x) => x.count), backgroundColor: "#2b59c3", borderRadius: 4 }] },
      options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } } });

    const colorFor = (i) => (i < 2 ? CLASS_COLOR.low : i < 4 ? CLASS_COLOR.moderate : i < 7 ? CLASS_COLOR.suspicious : CLASS_COLOR.high);
    drawChart("ch-dist", { type: "bar", data: { labels: s.score_distribution.map((b) => b.bucket),
      datasets: [{ data: s.score_distribution.map((b) => b.count), backgroundColor: s.score_distribution.map((_, i) => colorFor(i)), borderRadius: 4 }] },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { title: { display: true, text: "Risk score range" } }, y: { beginAtZero: true, ticks: { precision: 0 } } } } });

    drawChart("ch-trend", { type: "line", data: { labels: s.trend.map((t) => t.date.slice(5)),
      datasets: [{ label: "Analyzed", data: s.trend.map((t) => t.total), borderColor: "#2b59c3", backgroundColor: "rgba(43,89,195,.12)", fill: true, tension: .3 },
                 { label: "Flagged", data: s.trend.map((t) => t.flagged), borderColor: "#b42323", tension: .3 }] },
      options: { maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });

    drawChart("ch-kw", { type: "bar", data: { labels: ind.top_keywords.map((k) => k.keyword),
      datasets: [{ data: ind.top_keywords.map((k) => k.count), backgroundColor: "#6b5bd6", borderRadius: 4 }] },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { ticks: { maxRotation: 35 } } } } });
  } catch (e) { if (e.status !== 401) fail(e); }
}
$("#refresh-btn").addEventListener("click", loadDashboard);

/* ------------------------------------------------------------------ analyze */
const SAMPLES = {
  phish: { sender: "security-alert@account-check.invalid.test", subject: "URGENT: Verify Your Account Immediately", attachment: "",
    body: "Dear Customer,\n\nWe detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your account immediately.\n\nLog in now to verify: http://198.51.100.10/verify-account\n\nEnter your password and confirm your login to restore access.\n\nSecurity Team" },
  legit: { sender: "training@example.org", subject: "Cybersecurity Workshop Reminder", attachment: "",
    body: "Hello team,\n\nThis is a reminder that the cybersecurity awareness workshop is on Friday at 3 PM in Room 204. The agenda is at https://example.org/workshops/cybersecurity.\n\nNo action is needed unless you cannot attend; in that case just reply to this email.\n\nThanks,\nTraining Team" },
  subtle: { sender: "docs-share@example-docs.example.net", subject: "Document shared with you", attachment: "",
    body: "Hi Sam,\n\nA colleague shared the meeting notes with you. You can view them here: https://docs-share.example.net/view/48213" },
};
document.querySelectorAll("[data-sample]").forEach((b) => b.addEventListener("click", () => {
  const s = SAMPLES[b.dataset.sample];
  $("#f-sender").value = s.sender; $("#f-subject").value = s.subject; $("#f-body").value = s.body; $("#f-att").value = s.attachment;
}));
$("#clear-btn").addEventListener("click", () => { ["#f-sender", "#f-subject", "#f-body", "#f-att"].forEach((i) => { $(i).value = ""; }); });

function gauge(score, key) {
  const C = 2 * Math.PI * 54;
  const svg = svgEl("svg", { class: "gauge k-" + key, viewBox: "0 0 120 120", role: "img", "aria-label": "Risk score " + score + " out of 100" });
  svg.append(svgEl("circle", { class: "track", cx: 60, cy: 60, r: 54 }));
  svg.append(svgEl("circle", { class: "arc", cx: 60, cy: 60, r: 54, "stroke-dasharray": (C * score / 100).toFixed(1) + " " + C.toFixed(1) }));
  const num = svgEl("text", { class: "num", x: 60, y: 66 }); num.textContent = String(score);
  const den = svgEl("text", { class: "den", x: 60, y: 82 }); den.textContent = "/ 100";
  svg.append(num, den);
  return svg;
}
const section = (title, ...kids) => el("div", { class: "section" }, el("h3", { text: title }), ...kids);
const bulletList = (items) => el("ul", { class: "plain" }, items.map((t) => el("li", { text: t })));

function urlBox(u) {
  const lvl = u.risk_level ? u.risk_level.toLowerCase() : "low";
  const shown = u.findings.filter((f) => f.points > 0 || f.severity === "info");
  return el("div", { class: "urlbox" },
    el("div", { class: "top" }, el("code", { text: u.url_safe }), el("span", { class: "mini k-" + lvl, text: u.risk_score + "/100 · " + lvl.toUpperCase() })),
    bulletList(shown.map((f) => f.description + (f.points ? " (+" + f.points + ")" : ""))));
}

function renderResult(r, note) {
  const key = keyOf(r.classification), panel = $("#result-panel");
  clear(panel);
  const meta = el("div", { class: "score-meta" },
    el("div", { class: "small-label", text: "Classification" }),
    el("span", { class: "badge k-" + key, text: r.classification }));
  const bd = r.mode === "hybrid"
    ? `Hybrid: rules ${r.rule_score}/100 · ML estimate ${(r.ml_probability * 100).toFixed(0)}% (0.4 rules + 0.6 ML)`
    : `Rule-based score ${r.rule_score}/100 (no ML model loaded)`;
  meta.append(el("div", { class: "breakdown", text: bd }));
  if (note) meta.append(el("div", { class: "breakdown", text: note }));
  panel.append(el("h2", { text: "Result" }), el("div", { class: "score-head" }, gauge(r.risk_score, key), meta));

  const why = r.indicators.length
    ? el("ul", { class: "why" }, r.indicators.map((i) => el("li", {}, el("span", { class: "tick", text: "✓" }), el("span", { class: "sev " + i.severity, text: i.severity }),
        el("span", { text: i.description }), el("span", { class: "pts", text: i.points ? "+" + i.points : "model" }))))
    : el("p", { class: "muted", text: "No warning signs matched the current rules. This does not guarantee the email is safe." });
  panel.append(section("Why?", why));

  const sa = r.sender_analysis;
  panel.append(section("Sender analysis", el("p", { text: "Sender risk: " + sa.sender_risk_score + "/100" + (sa.domain ? " · domain " + sa.domain : "") }),
    sa.sender_findings.length ? bulletList(sa.sender_findings.map((f) => f.description + " (+" + f.points + ")")) : el("p", { class: "muted", text: "No sender warning signs. An unfamiliar domain is not automatically malicious." })));

  if (r.url_analyses.length) panel.append(section("URL analysis (static, never visited)", r.url_analyses.map(urlBox), el("p", { class: "muted", text: "HTTPS only means the connection is encrypted; it does not make a site trustworthy." })));
  if (r.link_mismatches && r.link_mismatches.length) panel.append(section("Link text mismatch", bulletList(r.link_mismatches.map((m) => m.description))));

  const att = r.attachment_analysis;
  if (att.extension) panel.append(section("Attachment (filename check only)", el("p", { text: "Attachment risk: " + att.attachment_risk_score + "/100" }), el("p", { class: "muted", text: att.explanation })));

  const cats = r.content_analysis.categories, chips = [];
  Object.entries(cats).forEach(([k, v]) => v.matches.forEach((m) => chips.push(el("span", { class: "chip", text: (INDICATOR_LABEL[k] || k) + ": " + m }))));
  if (chips.length) panel.append(section("Matched phrases", el("div", { class: "chips" }, chips)));

  panel.append(section("Recommended actions", el("ul", { class: "recs" }, r.recommendations.map((t) => el("li", { text: t })))));
  panel.append(el("p", { class: "disclaimer", text: r.disclaimer + " Analysis #" + r.analysis_id + " saved (metadata only)." }));
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function busy(btn, label, fn) {
  const old = btn.textContent; btn.disabled = true; btn.textContent = label;
  try { await fn(); } catch (e) { if (e.status !== 401) fail(e); } finally { btn.disabled = false; btn.textContent = old; }
}
$("#analyze-btn").addEventListener("click", (ev) => busy(ev.currentTarget, "Analyzing…", async () => {
  const payload = { sender: $("#f-sender").value, subject: $("#f-subject").value, body: $("#f-body").value, attachment_name: $("#f-att").value, use_ml: $("#f-ml").checked };
  renderResult(await api("/analyze", { method: "POST", json: payload }));
}));
$("#upload-btn").addEventListener("click", (ev) => busy(ev.currentTarget, "Analyzing…", async () => {
  const f = $("#f-file").files[0];
  if (!f) throw new ApiError(0, "Choose a .eml or .txt file first");
  const form = new FormData(); form.append("file", f);
  renderResult(await api("/analyze/upload?use_ml=" + $("#f-ml").checked, { method: "POST", form }), "Analyzed file: " + f.name);
}));
$("#url-btn").addEventListener("click", (ev) => busy(ev.currentTarget, "Checking…", async () => {
  const box = $("#url-result"); clear(box);
  box.append(urlBox(await api("/analyze/url", { method: "POST", json: { url: $("#f-url").value } })));
}));

/* ------------------------------------------------------------------ history */
const hist = { offset: 0, limit: 10, total: 0 };
const fmtDate = (iso) => new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
function scoreCell(score, cls) {
  const k = keyOf(cls), fill = el("div", { class: "fill k-" + k });
  fill.style.width = score + "%";
  return el("div", { class: "scorebar" }, el("span", { text: score }), el("div", { class: "bar" }, fill));
}
async function loadHistory() {
  const p = new URLSearchParams({ sort: $("#h-sort").value, limit: hist.limit, offset: hist.offset });
  if ($("#h-q").value.trim()) p.set("q", $("#h-q").value.trim());
  if ($("#h-class").value) p.set("classification", $("#h-class").value);
  try {
    const d = await api("/analyses?" + p);
    hist.total = d.total;
    const body = $("#h-body"); clear(body);
    if (!d.items.length) body.append(el("tr", { class: "empty-row" }, el("td", { colspan: 7, text: "No matching analyses." })));
    d.items.forEach((a) => body.append(el("tr", {},
      el("td", { text: "#" + a.analysis_id }), el("td", { class: "nowrap", text: fmtDate(a.created_at) }), el("td", { text: a.sender_domain || "—" }),
      el("td", { class: "subj", title: a.subject, text: a.subject || "(no subject)" }),
      el("td", {}, scoreCell(a.risk_score, a.classification)),
      el("td", { class: "nowrap" }, el("span", { class: "badge k-" + keyOf(a.classification), title: a.classification, text: SHORT_CLASS[a.classification] || a.classification })),
      el("td", { class: "actions-cell" },
        el("button", { class: "btn btn-ghost small", text: "View", onclick: () => openDetail(a.analysis_id) }), " ",
        el("button", { class: "btn btn-ghost small danger", text: "Delete", onclick: () => removeAnalysis(a.analysis_id) })))));
    const pages = Math.max(1, Math.ceil(d.total / hist.limit));
    $("#h-page").textContent = `Page ${Math.floor(hist.offset / hist.limit) + 1} of ${pages} · ${d.total} total`;
    $("#h-prev").disabled = hist.offset === 0; $("#h-next").disabled = hist.offset + hist.limit >= d.total;
  } catch (e) { if (e.status !== 401) fail(e); }
}
let searchTimer;
$("#h-q").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { hist.offset = 0; loadHistory(); }, 250); });
["#h-class", "#h-sort"].forEach((s) => $(s).addEventListener("change", () => { hist.offset = 0; loadHistory(); }));
$("#h-prev").addEventListener("click", () => { hist.offset = Math.max(0, hist.offset - hist.limit); loadHistory(); });
$("#h-next").addEventListener("click", () => { hist.offset += hist.limit; loadHistory(); });

async function openDetail(id) {
  try {
    const a = await api("/analyses/" + id), box = $("#detail-body"); clear(box);
    const k = keyOf(a.classification);
    box.append(
      el("p", {}, el("strong", { text: "#" + a.analysis_id + " · " }), a.subject || "(no subject)"),
      el("p", { class: "muted", text: `${a.sender_domain || "no valid sender"} · ${fmtDate(a.created_at)} · ${a.mode === "hybrid" ? "hybrid" : "rules only"}` }),
      el("p", {}, el("span", { class: "badge k-" + k, text: a.classification }), "  Score " + a.risk_score + "/100" + (a.ml_probability != null ? " (ML " + Math.round(a.ml_probability * 100) + "%)" : "")),
      section("Indicators", a.indicators.length ? el("ul", { class: "why" }, a.indicators.map((i) => el("li", {}, el("span", { class: "tick", text: "✓" }), el("span", { class: "sev " + i.severity, text: i.severity }), el("span", { text: i.description })))) : el("p", { class: "muted", text: "None" })),
      section("URLs (defanged)", a.url_analyses.length ? a.url_analyses.map((u) => el("div", { class: "urlbox" }, el("div", { class: "top" }, el("code", { text: u.url_safe_representation }), el("span", { class: "mini", text: u.risk_score + "/100" })), bulletList(u.findings))) : el("p", { class: "muted", text: "No URLs" })));
    $("#detail-dialog").showModal();
  } catch (e) { if (e.status !== 401) fail(e); }
}
$("#detail-close").addEventListener("click", () => $("#detail-dialog").close());
async function removeAnalysis(id) {
  if (!confirm("Delete analysis #" + id + "?")) return;
  try { await api("/analyses/" + id, { method: "DELETE" }); notify("Analysis #" + id + " deleted", "info"); loadHistory(); }
  catch (e) { if (e.status !== 401) fail(e); }
}

/* ------------------------------------------------------------------ awareness */
const TIPS = [
  ["Check the sender address", "Look at the real address, not just the display name. A friendly name can hide an unrelated domain."],
  ["Read the domain spelling", "Watch for swapped characters (examp1e), extra words or hyphens, and long chains of subdomains."],
  ["Question unexpected urgency", "“Act now” and “within 24 hours” are designed to stop you thinking. Real problems can be checked calmly."],
  ["Inspect links before clicking", "Hover to preview the destination. Raw IP addresses, shorteners and odd hostnames deserve suspicion. HTTPS does not mean safe."],
  ["Never send credentials by email", "Organisations do not ask for passwords or one-time codes through email links. Go to the official site yourself."],
  ["Be careful with attachments", "Unexpected files are risky, especially .exe, .js, .zip or double extensions like invoice.pdf.exe."],
  ["Notice generic greetings", "“Dear Customer” from a company that knows your name is a mild warning sign, not proof by itself."],
  ["Verify unusual payment requests", "New bank details, gift cards or rush payments should be confirmed by phone using a number you already trust."],
  ["Recognise threatening language", "Threats of suspension, fines or legal action are pressure tactics. Slow down and verify."],
  ["Use context", "Were you expecting this? Does it match how this sender normally writes? Context often beats any single indicator."],
];
TIPS.forEach(([t, d], i) => $("#tips").append(el("div", { class: "tip" }, el("h3", {}, el("span", { class: "num", text: i + 1 }), t), el("p", { text: d }))));
const CHECKS = ["Do I recognise the sender, and does the real address match who they claim to be?", "Was I expecting this message?",
  "Is it pushing me to act urgently or scaring me?", "Does the link destination match what it says (hover to check)?", "Is it asking for a password, code or personal details?",
  "Is there an unexpected attachment or unusual file type?", "Is the greeting generic or the writing oddly off?", "Does it ask for money, gift cards or new bank details?",
  "Can I verify by opening the official site/app myself, not via this email?", "If still unsure, have I asked IT/security before clicking?"];
function updateChecks() {
  const n = document.querySelectorAll("#checklist input:checked").length, s = $("#check-status");
  s.textContent = n === CHECKS.length ? "All checks done. If anything still feels wrong, report it instead of clicking." : n + " of " + CHECKS.length + " checks done";
  s.className = "check-status" + (n === CHECKS.length ? " done" : "");
}
CHECKS.forEach((c, i) => $("#checklist").append(el("li", {}, el("label", {}, el("input", { type: "checkbox", id: "chk" + i, onchange: updateChecks }), el("span", { text: c })))));
updateChecks();

/* ------------------------------------------------------------------ auth */
function openLogin() { if (!$("#login-dialog").open) $("#login-dialog").showModal(); }
async function authAction(kind) {
  const err = $("#login-error"); err.hidden = true;
  const creds = { username: $("#l-user").value, password: $("#l-pass").value };
  try {
    if (kind === "register") { await api("/register", { method: "POST", json: creds }); }
    const d = await api("/login", { method: "POST", json: creds });
    token = d.access_token; sessionStorage.setItem("token", token);
    $("#login-dialog").close(); $("#l-pass").value = ""; setUser(creds.username, d.role); show(location.hash.slice(1));
  } catch (e) { err.textContent = e.message; err.hidden = false; }
}
$("#login-btn").addEventListener("click", () => authAction("login"));
$("#register-btn").addEventListener("click", () => authAction("register"));
function setUser(name, role) { $("#user-area").hidden = false; $("#user-label").textContent = name + " (" + role + ")"; $("#logout-btn").hidden = false; }
$("#logout-btn").addEventListener("click", async () => {
  try { await api("/logout", { method: "POST" }); } catch (e) { /* token may already be invalid */ }
  token = null; sessionStorage.removeItem("token"); $("#user-area").hidden = true; openLogin();
});

/* ------------------------------------------------------------------ start */
(async function init() {
  try {
    const h = await (await fetch("/api/health")).json();
    if (h.auth_required && !token) openLogin();
    if (h.auth_required && token) { $("#user-area").hidden = false; $("#user-label").textContent = "signed in"; $("#logout-btn").hidden = false; }
  } catch (e) { notify("Cannot reach the API. Is the server running?"); }
  show(location.hash.slice(1) || "dashboard");
})();
