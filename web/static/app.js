"use strict";
/* All dynamic text is inserted with textContent / createTextNode (never innerHTML),
   so resource names from uploaded configs cannot inject markup. */

const $ = (id) => document.getElementById(id);
const state = { runId: null, findings: [], sortKey: "fused_rank", sortDir: 1 };

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) node.append(c);
  return node;
}
const badge = (p) => el("span", { class: "badge " + p, text: p });
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

function setStatus(msg, isError = false) {
  const s = $("status");
  s.textContent = msg;
  s.className = isError ? "error" : "";
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  let body = null;
  try { body = await res.json(); } catch (_) { /* non-JSON error */ }
  if (!res.ok) throw new Error((body && body.error) || `Request failed (${res.status})`);
  return body;
}

/* ------------------------------------------------------------- runs */
async function loadRuns(selectId) {
  const runs = await api("/api/runs");
  const sel = clear($("runSelect"));
  if (!runs.length) {
    sel.append(el("option", { value: "", text: "No runs yet" }));
    state.runId = null;
    renderEmpty();
    return;
  }
  for (const r of runs) {
    const label = `${r.config_name} \u2013 ${r.run_id} (${r.created_at.slice(0, 19).replace("T", " ")})`;
    sel.append(el("option", { value: r.run_id, text: label }));
  }
  sel.value = selectId && runs.some((r) => r.run_id === selectId) ? selectId : runs[0].run_id;
  await selectRun(sel.value);
}

function renderEmpty() {
  clear($("metrics"));
  state.findings = [];
  clear($("findingsTable")).append(el("tbody", {}, el("tr", {}, el("td", { class: "empty", text: "No runs yet. Click \u201cRun demo scan\u201d." }))));
  clear($("compareTable")); clear($("bars")); clear($("ctiBars")); clear($("ctiTable"));
}

async function selectRun(runId) {
  state.runId = runId;
  const data = await api("/api/runs/" + encodeURIComponent(runId));
  state.findings = data.findings;
  renderMetrics(data.summary);
  fillCategories();
  renderFindings();
  renderCompare();
  closeDrawer();
  setStatus(`Showing run ${runId}: ${data.summary.total} finding(s).`);
}

function renderMetrics(s) {
  const items = [
    ["Findings", s.total], ["Critical priority", s.by_priority.Critical], ["High priority", s.by_priority.High],
    ["With CTI support", s.with_cti_support], ["CTI reports loaded", s.total_reports],
  ];
  const box = clear($("metrics"));
  for (const [label, num] of items)
    box.append(el("div", { class: "card" }, [el("div", { class: "num", text: String(num) }), el("div", { class: "label", text: label })]));
}

/* --------------------------------------------------------- findings */
function fillCategories() {
  const sel = $("categoryFilter");
  const keep = sel.value;
  clear(sel).append(el("option", { value: "", text: "All categories" }));
  for (const c of [...new Set(state.findings.map((f) => f.category))].sort()) sel.append(el("option", { value: c, text: c }));
  sel.value = [...sel.options].some((o) => o.value === keep) ? keep : "";
}

const COLS = [
  ["fused_rank", "Rank"], ["risk_score", "Score"], ["priority", "Priority"], ["check_id", "Check"],
  ["resource", "Resource"], ["severity", "Severity"], ["criticality", "Criticality"],
  ["cti_report_count", "CTI reports"], ["technique_ids", "Techniques"],
];
const PRI_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

function sortValue(f, key) {
  if (key === "priority") return PRI_ORDER[f.priority];
  if (key === "technique_ids") return f.technique_ids.join(",");
  return f[key];
}

function visibleFindings() {
  const q = $("search").value.trim().toLowerCase();
  const pri = $("priorityFilter").value, cat = $("categoryFilter").value;
  return state.findings
    .filter((f) => (!pri || f.priority === pri) && (!cat || f.category === cat))
    .filter((f) => !q || [f.resource, f.check_id, f.title, f.technique_ids.join(" ")].join(" ").toLowerCase().includes(q))
    .sort((a, b) => {
      const x = sortValue(a, state.sortKey), y = sortValue(b, state.sortKey);
      return (x < y ? -1 : x > y ? 1 : 0) * state.sortDir;
    });
}

function renderFindings() {
  const table = clear($("findingsTable"));
  const head = el("tr");
  for (const [key, label] of COLS) {
    const th = el("th", { text: label, tabindex: "0", scope: "col" });
    if (key === state.sortKey) th.setAttribute("aria-sort", state.sortDir === 1 ? "ascending" : "descending");
    const sort = () => {
      state.sortDir = state.sortKey === key ? -state.sortDir : 1;
      state.sortKey = key;
      renderFindings();
    };
    th.addEventListener("click", sort);
    th.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); } });
    head.append(th);
  }
  table.append(el("thead", {}, head));
  const body = el("tbody");
  const rows = visibleFindings();
  if (!rows.length) body.append(el("tr", {}, el("td", { class: "empty", colspan: String(COLS.length), text: "No findings match." })));
  for (const f of rows) {
    const tr = el("tr", { tabindex: "0" }, [
      el("td", { text: String(f.fused_rank) }), el("td", { text: f.risk_score.toFixed(1) }),
      el("td", {}, badge(f.priority)), el("td", { text: f.check_id }), el("td", { text: f.resource }),
      el("td", { text: f.severity }), el("td", { text: f.criticality }),
      el("td", { text: `${f.cti_report_count}/${f.total_reports}` }), el("td", { text: f.technique_ids.join(", ") }),
    ]);
    const open = () => openDrawer(f);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    body.append(tr);
  }
  table.append(body);
}

/* ----------------------------------------------------------- drawer */
function openDrawer(f) {
  const body = clear($("drawerBody"));
  body.append(el("h3", { text: `${f.check_id} \u2013 ${f.resource}` }), badge(f.priority));
  body.append(el("p", { class: "explain", text: f.explanation }));
  const rows = [
    ["Title", f.title], ["Detail", f.detail], ["Resource type", f.resource_type], ["Severity", f.severity],
    ["Asset criticality", f.criticality], ["ATT&CK techniques", f.technique_ids.join(", ") || "none"],
    ["CTI reports", f.cti_report_ids.join(", ") || "none"], ["Actors named", f.cti_actors.join(", ") || "none"],
    ["CTI weight", f.cti_weight.toFixed(2)], ["Raw risk", String(f.risk_raw)], ["Risk score (0\u2013100)", String(f.risk_score)],
    ["Rank (fused / baseline)", `${f.fused_rank} / ${f.baseline_rank}`], ["Explanation source", f.explanation_source],
  ];
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of rows) dl.append(el("dt", { text: k }), el("dd", { text: v }));
  body.append(dl);
  $("drawer").classList.remove("hidden");
  $("closeDrawer").focus();
}
function closeDrawer() { $("drawer").classList.add("hidden"); }

/* ---------------------------------------------------------- compare */
function barRow(name, value, max, valueText) {
  const fill = el("div", { class: "fill" });
  fill.style.width = `${max ? Math.max(2, (value / max) * 100) : 0}%`;
  return el("div", { class: "barrow" }, [el("div", { class: "name", text: name, title: name }),
    el("div", { class: "track" }, fill), el("div", { class: "val", text: valueText })]);
}

function renderCompare() {
  const sorted = [...state.findings].sort((a, b) => a.fused_rank - b.fused_rank);
  const bars = clear($("bars"));
  for (const f of sorted.slice(0, 10)) bars.append(barRow(`${f.check_id} ${f.resource}`, f.risk_score, 100, f.risk_score.toFixed(1)));
  const table = clear($("compareTable"));
  table.append(el("thead", {}, el("tr", {}, ["Resource", "Check", "Severity", "Baseline rank", "Fused rank", "Change", "Score"].map((h) => el("th", { text: h })))));
  const body = el("tbody");
  for (const f of sorted) {
    const d = f.baseline_rank - f.fused_rank;
    const change = d > 0 ? el("span", { class: "up", text: `\u25B2 ${d}` }) : d < 0 ? el("span", { class: "down", text: `\u25BC ${-d}` }) : el("span", { class: "same", text: "\u2013" });
    body.append(el("tr", {}, [el("td", { text: f.resource }), el("td", { text: f.check_id }), el("td", { text: f.severity }),
      el("td", { text: String(f.baseline_rank) }), el("td", { text: String(f.fused_rank) }), el("td", {}, change), el("td", { text: f.risk_score.toFixed(1) })]));
  }
  table.append(body);
}

/* -------------------------------------------------------------- CTI */
async function renderCti() {
  const rows = await api("/api/cti");
  const counts = {};
  for (const r of rows) (counts[r.technique_id] = counts[r.technique_id] || new Set()).add(r.report_id);
  const entries = Object.entries(counts).map(([t, s]) => [t, s.size]).sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 0;
  const bars = clear($("ctiBars"));
  if (!entries.length) bars.append(el("p", { class: "empty", text: "No CTI loaded yet. Run a scan first." }));
  for (const [t, n] of entries) bars.append(barRow(t, n, max, String(n)));
  const table = clear($("ctiTable"));
  table.append(el("thead", {}, el("tr", {}, ["Technique", "Report", "Evidence verified", "Method", "Evidence sentence"].map((h) => el("th", { text: h })))));
  const body = el("tbody");
  for (const r of rows)
    body.append(el("tr", { class: "static" }, [el("td", { text: r.technique_id }), el("td", { text: r.report_id }),
      el("td", { text: r.evidence_verified ? "yes" : "no" }), el("td", { text: r.method }), el("td", { class: "wrap", text: r.evidence })]));
  table.append(body);
}

/* ------------------------------------------------------- evaluation */
function evalCard(title, items) {
  return el("div", { class: "card" }, [el("strong", { text: title }), el("ul", {}, items.map((t) => el("li", { text: t })))]);
}
async function renderEval() {
  const body = clear($("evalBody"));
  body.append(el("p", { class: "note", text: "Computing\u2026" }));
  const r = await api("/api/evaluation");
  const d = r.detection, e = r.extraction, k = r.ranking, m = r.mapping_coverage;
  clear(body).append(el("div", { class: "evalgrid" }, [
    evalCard("Misconfiguration detection", [`Precision ${d.overall.precision}`, `Recall ${d.overall.recall}`, `F1 ${d.overall.f1}`,
      `False-positive resource rate ${d.false_positive_resource_rate}`, `Clean resources checked: ${d.clean_resources}`]),
    evalCard("CTI extraction (labelled subset)", [`Precision ${e.overall.precision}`, `Recall ${e.overall.recall}`,
      `Labelled reports ${e.labelled_reports} of ${e.total_reports}`, `Method: ${e.methods.join(", ")}`,
      `LLM outputs rejected: ${e.llm_outputs_rejected}`]),
    evalCard("Ranking: severity-only vs fused", [`Findings ${k.findings}`, `Mean rank change ${k.mean_abs_rank_change}`,
      `Top-5 overlap ${k.top5_overlap}`, `With CTI support ${k.findings_with_cti_support}`]),
    evalCard("Mapping coverage", [`Checks mapped ${m.checks_mapped}`, `With CTI support ${m.checks_with_cti_support}`,
      m.unsupported_checks.length ? `No CTI support: ${m.unsupported_checks.join(", ")}` : "Every check has CTI support"]),
  ]), el("p", { class: "note", text: r.note }));
}

/* ----------------------------------------------------------- wiring */
function showTab(name) {
  for (const t of document.querySelectorAll(".tab")) {
    const on = t.dataset.tab === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", String(on));
    $("tab-" + t.dataset.tab).classList.toggle("hidden", !on);
  }
  if (name === "cti") renderCti().catch((e) => setStatus(e.message, true));
  if (name === "eval") renderEval().catch((e) => setStatus(e.message, true));
}

async function guarded(fn) {
  try { await fn(); } catch (e) { setStatus(e.message, true); }
}

document.addEventListener("DOMContentLoaded", () => {
  for (const t of document.querySelectorAll(".tab")) t.addEventListener("click", () => showTab(t.dataset.tab));
  $("runSelect").addEventListener("change", (e) => guarded(() => selectRun(e.target.value)));
  for (const id of ["search", "priorityFilter", "categoryFilter"]) $(id).addEventListener("input", renderFindings);
  $("closeDrawer").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  $("demoBtn").addEventListener("click", () => guarded(async () => {
    setStatus("Running demo scan\u2026");
    const { runs } = await api("/api/scan/demo", { method: "POST" });
    await loadRuns(runs.vulnerable_env);
  }));

  $("fileInput").addEventListener("change", (e) => guarded(async () => {
    const file = e.target.files[0];
    if (!file) return;
    setStatus(`Scanning ${file.name}\u2026`);
    const fd = new FormData();
    fd.append("file", file);
    try {
      const { run_id } = await api("/api/scan", { method: "POST", body: fd });
      await loadRuns(run_id);
    } finally { e.target.value = ""; }
  }));

  guarded(() => loadRuns());
});
