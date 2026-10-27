"use strict";
/* All dynamic text is inserted with textContent / createTextNode (never innerHTML),
   ensuring resource names from uploaded configs cannot inject markup or XSS. */

const $ = (id) => document.getElementById(id);
const state = {
  runId: null,
  configName: "Demo Environment",
  isSample: true,
  findings: [],
  sortKey: "fused_rank",
  sortDir: 1
};

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c !== null && c !== undefined) node.append(c);
  }
  return node;
}

function svgIcon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");

  if (name === "shield") {
    const p1 = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p1.setAttribute("d", "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z");
    svg.appendChild(p1);
  } else if (name === "alert") {
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("cx", "12"); c.setAttribute("cy", "12"); c.setAttribute("r", "10");
    const l1 = document.createElementNS("http://www.w3.org/2000/svg", "line");
    l1.setAttribute("x1", "12"); l1.setAttribute("y1", "8"); l1.setAttribute("x2", "12"); l1.setAttribute("y2", "12");
    const l2 = document.createElementNS("http://www.w3.org/2000/svg", "line");
    l2.setAttribute("x1", "12"); l2.setAttribute("y1", "16"); l2.setAttribute("x2", "12.01"); l2.setAttribute("y2", "16");
    svg.append(c, l1, l2);
  } else if (name === "flame") {
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", "M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z");
    svg.appendChild(p);
  } else if (name === "cpu") {
    const r = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    r.setAttribute("x", "4"); r.setAttribute("y", "4"); r.setAttribute("width", "16"); r.setAttribute("height", "16"); r.setAttribute("rx", "2");
    svg.appendChild(r);
  } else {
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("cx", "12"); c.setAttribute("cy", "12"); c.setAttribute("r", "10");
    svg.appendChild(c);
  }
  return svg;
}

const badge = (p) => el("span", { class: "badge " + p, text: p });
const clear = (n) => { while (n && n.firstChild) n.removeChild(n.firstChild); return n; };

function setStatus(msg, isError = false) {
  const s = $("status");
  if (!s) return;
  s.textContent = msg;
  s.className = "hud-status-banner" + (isError ? " error" : " success");
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  let body = null;
  try { body = await res.json(); } catch (_) { /* non-JSON error */ }
  if (res.status === 401) {
    if (window.authState && window.authState.auth_required) {
      window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname + window.location.hash);
    }
    throw new Error((body && body.error) || "Authentication required. Please log in first.");
  }
  if (!res.ok) throw new Error((body && body.error) || `Request failed (${res.status})`);
  return body;
}

async function checkAuth() {
  try {
    const res = await fetch("/api/auth/me");
    const data = await res.json();
    window.authState = data;

    const navLoginBtn = $("navLoginBtn");
    const navUserBadge = $("navUserBadge");
    const navUsername = $("navUsername");
    const navLogoutBtn = $("navLogoutBtn");
    const mobileLoginLink = $("mobileLoginLink");
    const lockCard = $("dashboardAuthLock");
    const liveContent = $("dashboardLiveContent");

    if (data.authenticated) {
      if (navLoginBtn) navLoginBtn.style.display = "none";
      if (mobileLoginLink) {
        mobileLoginLink.textContent = `Sign Out (${data.user})`;
        mobileLoginLink.href = "/logout";
      }
      if (navUserBadge) {
        navUserBadge.style.display = "inline-flex";
        if (navUsername) navUsername.textContent = `${data.user} (${data.role || "analyst"})`;
      }
      if (navLogoutBtn) {
        navLogoutBtn.onclick = async (e) => {
          e.preventDefault();
          await fetch("/api/auth/logout", { method: "POST" });
          window.location.href = "/login?logged_out=1";
        };
      }
      if (lockCard) lockCard.style.display = "none";
      if (liveContent) liveContent.style.display = "block";
    } else {
      if (navLoginBtn) navLoginBtn.style.display = "inline-flex";
      if (navUserBadge) navUserBadge.style.display = "none";
      if (mobileLoginLink) {
        mobileLoginLink.textContent = "Sign In";
        mobileLoginLink.href = "/login";
      }

      if (data.auth_required) {
        if (lockCard) lockCard.style.display = "block";
        if (liveContent) liveContent.style.display = "none";
      } else {
        if (lockCard) lockCard.style.display = "none";
        if (liveContent) liveContent.style.display = "block";
      }
    }
    return data;
  } catch (e) {
    return { authenticated: false, auth_required: false };
  }
}


/* ------------------------------------------------------------- runs */
async function loadRuns(selectId) {
  const runs = await api("/api/runs");
  const sel = clear($("runSelect"));
  if (!runs || !runs.length) {
    sel.append(el("option", { value: "", text: "No scan runs yet" }));
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
  const tbody = el("tbody", {}, el("tr", {}, el("td", { class: "empty-state-cell", colspan: "9", text: "No runs yet. Click \u201cRun Demo Scan\u201d or upload a cloud config." })));
  clear($("findingsTable")).append(tbody);
  clear($("compareTable")); clear($("bars")); clear($("ctiBars")); clear($("ctiTable"));
}

async function selectRun(runId) {
  state.runId = runId;
  const data = await api("/api/runs/" + encodeURIComponent(runId));
  state.findings = data.findings;
  state.configName = data.run ? data.run.config_name : "Scan Run";
  state.isSample = (data.run && (data.run.config_name.includes("env") || data.run.config_name.includes("demo")));
  
  renderMetrics(data.summary);
  fillCategories();
  renderFindings();
  renderCompare();
  closeDrawer();
  setStatus(`Loaded run ${runId} (${state.configName}): ${data.summary.total} findings evaluated.`);
}

/* --------------------------------------------------------- metrics */
function renderMetrics(s) {
  const box = clear($("metrics"));
  if (!box) return;

  // Compute Posture Security Score (0 - 100)
  const crit = s.by_priority.Critical || 0;
  const high = s.by_priority.High || 0;
  const med = s.by_priority.Medium || 0;
  const low = s.by_priority.Low || 0;
  
  let score = 100;
  if (s.total > 0) {
    const deduction = (crit * 16) + (high * 9) + (med * 4) + (low * 1);
    score = Math.max(14, Math.round(100 - deduction));
  }

  // Count high-risk resources
  const highRiskResCount = new Set(
    state.findings.filter((f) => f.priority === "Critical" || f.priority === "High").map((f) => f.resource)
  ).size;

  const dataTag = state.isSample ? "Demo Data" : "Live Scan";

  const cards = [
    {
      id: "score",
      label: "Security Score",
      value: `${score}/100`,
      icon: "shield",
      type: "score",
      badge: score >= 85 ? "Optimal" : score >= 60 ? "Moderate" : "High Risk"
    },
    {
      id: "total",
      label: "Total Findings",
      value: String(s.total),
      icon: "alert",
      type: "findings",
      badge: dataTag
    },
    {
      id: "critical",
      label: "Critical Risks",
      value: String(crit),
      icon: "flame",
      type: "critical",
      badge: crit > 0 ? "Immediate Action" : "Clear"
    },
    {
      id: "high_risk",
      label: "High-Risk Resources",
      value: String(highRiskResCount),
      icon: "cpu",
      type: "high",
      badge: `${high} High Alerts`
    },
    {
      id: "cti_support",
      label: "With CTI Support",
      value: `${s.with_cti_support} / ${s.total}`,
      icon: "shield",
      type: "cti",
      badge: `${s.total_reports} Reports`
    }
  ];

  for (const c of cards) {
    const cardEl = el("div", { class: "metric-card" }, [
      el("div", { class: "metric-card-top" }, [
        el("div", { class: "metric-icon " + c.type }, [svgIcon(c.icon)]),
        el("span", { class: "metric-badge-sub", text: c.badge })
      ]),
      el("div", { class: "metric-val", text: c.value }),
      el("div", { class: "metric-label", text: c.label })
    ]);
    box.append(cardEl);
  }
}

/* --------------------------------------------------------- findings */
function fillCategories() {
  const sel = $("categoryFilter");
  if (!sel) return;
  const keep = sel.value;
  clear(sel).append(el("option", { value: "", text: "All Categories" }));
  for (const c of [...new Set(state.findings.map((f) => f.category))].sort()) {
    sel.append(el("option", { value: c, text: c }));
  }
  sel.value = [...sel.options].some((o) => o.value === keep) ? keep : "";
}

const COLS = [
  ["fused_rank", "Rank"],
  ["risk_score", "Score"],
  ["priority", "Priority"],
  ["check_id", "Check ID"],
  ["resource", "Resource"],
  ["severity", "Severity"],
  ["criticality", "Asset Criticality"],
  ["cti_report_count", "CTI Reports"],
  ["technique_ids", "ATT&CK Techniques"],
];
const PRI_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

function sortValue(f, key) {
  if (key === "priority") return PRI_ORDER[f.priority];
  if (key === "technique_ids") return f.technique_ids.join(",");
  return f[key];
}

function visibleFindings() {
  const searchInput = $("search");
  const q = searchInput ? searchInput.value.trim().toLowerCase() : "";
  const pri = $("priorityFilter") ? $("priorityFilter").value : "";
  const cat = $("categoryFilter") ? $("categoryFilter").value : "";

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
  if (!table) return;

  const head = el("tr");
  for (const [key, label] of COLS) {
    const th = el("th", { text: label, tabindex: "0", scope: "col" });
    if (key === state.sortKey) {
      th.setAttribute("aria-sort", state.sortDir === 1 ? "ascending" : "descending");
    }
    const sort = () => {
      state.sortDir = state.sortKey === key ? -state.sortDir : 1;
      state.sortKey = key;
      renderFindings();
    };
    th.addEventListener("click", sort);
    th.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); }
    });
    head.append(th);
  }
  table.append(el("thead", {}, head));

  const body = el("tbody");
  const rows = visibleFindings();
  if (!rows.length) {
    body.append(el("tr", {}, el("td", { class: "empty-state-cell", colspan: String(COLS.length), text: "No findings match your current search or filters." })));
  }

  for (const f of rows) {
    const rankClass = f.fused_rank === 1 ? "rank-badge top-1" : f.fused_rank <= 3 ? "rank-badge top-3" : "rank-badge";
    const rankEl = el("span", { class: rankClass, text: String(f.fused_rank) });

    const tr = el("tr", { tabindex: "0", "aria-label": `Finding ${f.check_id} on ${f.resource}` }, [
      el("td", {}, rankEl),
      el("td", { style: "font-weight: 700; font-family: var(--font-mono);", text: f.risk_score.toFixed(1) }),
      el("td", {}, badge(f.priority)),
      el("td", { style: "font-weight: 600;", text: f.check_id }),
      el("td", { text: f.resource }),
      el("td", { text: f.severity }),
      el("td", { text: f.criticality }),
      el("td", { text: `${f.cti_report_count}/${f.total_reports}` }),
      el("td", { text: f.technique_ids.join(", ") || "—" }),
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
  const headerContainer = clear($("drawerBadgeContainer"));
  if (headerContainer) {
    headerContainer.append(badge(f.priority));
  }

  const heading = $("drawerHeading");
  if (heading) {
    heading.textContent = `${f.check_id} \u2013 ${f.resource}`;
  }

  // Explanation box
  body.append(el("div", { class: "drawer-section-title", text: "Security Analysis & Context" }));
  body.append(el("div", { class: "explain-box", text: f.explanation }));

  // Remediation box with copy button
  if (f.remediation) {
    const copyBtn = el("button", { class: "copy-btn", type: "button", text: "Copy Fix" });
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(f.remediation).then(() => {
        copyBtn.textContent = "Copied!";
        setTimeout(() => { copyBtn.textContent = "Copy Fix"; }, 2000);
      });
    });

    const remBox = el("div", { class: "remediation-box" }, [
      el("div", { class: "remediation-header" }, [
        el("div", { class: "remediation-label" }, [
          svgIcon("shield"),
          el("span", { text: "Actionable Remediation" })
        ]),
        copyBtn
      ]),
      el("pre", { class: "remediation-code", text: f.remediation })
    ]);
    body.append(remBox);
  }

  // Attributes table
  body.append(el("div", { class: "drawer-section-title", text: "Technical Metadata" }));
  const rows = [
    ["Title", f.title],
    ["Detail", f.detail],
    ["Resource Type", f.resource_type],
    ["Rule Severity", f.severity],
    ["Asset Criticality", f.criticality],
    ["ATT&CK Techniques", f.technique_ids.join(", ") || "None"],
    ["CTI Threat Reports", f.cti_report_ids.join(", ") || "None"],
    ["Adversaries Named", f.cti_actors.join(", ") || "None"],
    ["CTI Relevance Weight", f.cti_weight.toFixed(2)],
    ["Raw Risk Score", String(f.risk_raw)],
    ["Normalized Risk (0-100)", String(f.risk_score)],
    ["Rank (Fused / Baseline)", `${f.fused_rank} / ${f.baseline_rank}`],
    ["Explanation Engine", f.explanation_source],
  ];

  const dl = el("dl", { class: "kv" });
  for (const [k, v] of rows) {
    dl.append(el("dt", { text: k }), el("dd", { text: String(v) }));
  }
  body.append(dl);

  const drawer = $("drawer");
  const backdrop = $("drawerBackdrop");
  if (drawer) drawer.classList.remove("hidden");
  if (backdrop) backdrop.classList.add("active");
  const closeBtn = $("closeDrawer");
  if (closeBtn) closeBtn.focus();
}

function closeDrawer() {
  const drawer = $("drawer");
  const backdrop = $("drawerBackdrop");
  if (drawer) drawer.classList.add("hidden");
  if (backdrop) backdrop.classList.remove("active");
}

/* ---------------------------------------------------------- compare */
function barRow(name, value, max, valueText, isCoral = false) {
  const fill = el("div", { class: "fill" + (isCoral ? " coral" : "") });
  fill.style.width = `${max ? Math.max(3, (value / max) * 100) : 0}%`;
  return el("div", { class: "barrow" }, [
    el("div", { class: "name", text: name, title: name }),
    el("div", { class: "track" }, fill),
    el("div", { class: "val", text: valueText })
  ]);
}

function renderCompare() {
  const sorted = [...state.findings].sort((a, b) => a.fused_rank - b.fused_rank);
  const bars = clear($("bars"));
  if (bars) {
    for (const f of sorted.slice(0, 10)) {
      bars.append(barRow(`${f.check_id} \u2013 ${f.resource}`, f.risk_score, 100, f.risk_score.toFixed(1), f.fused_rank <= 3));
    }
  }

  const table = clear($("compareTable"));
  if (!table) return;

  table.append(el("thead", {}, el("tr", {}, [
    "Resource", "Check ID", "Severity", "Baseline Rank", "Fused Rank", "Rank Delta", "Score"
  ].map((h) => el("th", { text: h })))));

  const body = el("tbody");
  for (const f of sorted) {
    const d = f.baseline_rank - f.fused_rank;
    const change = d > 0
      ? el("span", { class: "up", text: `\u25B2 +${d} (Elevated)` })
      : d < 0
      ? el("span", { class: "down", text: `\u25BC ${d}` })
      : el("span", { class: "same", text: "\u2013 Unchanged" });

    body.append(el("tr", {}, [
      el("td", { text: f.resource }),
      el("td", { text: f.check_id }),
      el("td", { text: f.severity }),
      el("td", { text: `#${f.baseline_rank}` }),
      el("td", { style: "font-weight: 700;", text: `#${f.fused_rank}` }),
      el("td", {}, change),
      el("td", { style: "font-weight: 700; font-family: var(--font-mono);", text: f.risk_score.toFixed(1) })
    ]));
  }
  table.append(body);
}

/* -------------------------------------------------------------- CTI */
async function renderCti() {
  const rows = await api("/api/cti");
  const counts = {};
  for (const r of rows) {
    (counts[r.technique_id] = counts[r.technique_id] || new Set()).add(r.report_id);
  }
  const entries = Object.entries(counts).map(([t, s]) => [t, s.size]).sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 0;
  
  const bars = clear($("ctiBars"));
  if (!entries.length) {
    bars.append(el("p", { class: "empty-state-cell", text: "No CTI reports loaded yet. Run a scan first." }));
  }
  for (const [t, n] of entries) {
    bars.append(barRow(t, n, max, `${n} reports`, true));
  }

  const table = clear($("ctiTable"));
  table.append(el("thead", {}, el("tr", {}, [
    "Technique ID", "Source Report", "Verified Evidence", "Method", "Evidence Sentence"
  ].map((h) => el("th", { text: h })))));

  const body = el("tbody");
  for (const r of rows) {
    body.append(el("tr", { class: "static" }, [
      el("td", { style: "font-weight: 700;", text: r.technique_id }),
      el("td", { text: r.report_id }),
      el("td", {}, el("span", { class: r.evidence_verified ? "up" : "same", text: r.evidence_verified ? "\u2713 Verified" : "Unverified" })),
      el("td", { text: r.method }),
      el("td", { class: "wrap", text: r.evidence })
    ]));
  }
  table.append(body);
}

/* ------------------------------------------------------- evaluation */
function evalCard(title, items) {
  return el("div", { class: "eval-card" }, [
    el("strong", { text: title }),
    el("ul", {}, items.map((t) => el("li", { text: t })))
  ]);
}

async function renderEval() {
  const body = clear($("evalBody"));
  body.append(el("p", { class: "eval-note", text: "Evaluating model accuracy against ground-truth benchmarks\u2026" }));
  const r = await api("/api/evaluation");
  const d = r.detection, e = r.extraction, k = r.ranking, m = r.mapping_coverage;
  clear(body).append(
    el("div", { class: "evalgrid" }, [
      evalCard("Misconfiguration Detection", [
        `Precision: ${d.overall.precision}`,
        `Recall: ${d.overall.recall}`,
        `F1 Score: ${d.overall.f1}`,
        `False-Positive Rate: ${d.false_positive_resource_rate}`,
        `Clean Resources Checked: ${d.clean_resources}`
      ]),
      evalCard("CTI Extraction (All Labelled Techniques)", [
        `Precision: ${e.overall.precision}`,
        `Recall: ${e.overall.recall}`,
        `In-Scope Precision: ${e.in_scope.precision}`,
        `In-Scope Recall: ${e.in_scope.recall}`,
        `Labelled Reports: ${e.labelled_reports} of ${e.total_reports}`,
        `Extraction Method: ${e.methods.join(", ")}`,
        `LLM Outputs Rejected: ${e.llm_outputs_rejected}`
      ]),
      evalCard("Ranking: Severity-Only vs Fused", [
        `Total Findings Evaluated: ${k.findings}`,
        `Mean Rank Delta: ${k.mean_abs_rank_change}`,
        `Top-5 Overlap: ${k.top5_overlap}`,
        `Findings With CTI Evidence: ${k.findings_with_cti_support}`
      ]),
      evalCard("Rule Mapping Coverage", [
        `Checks Mapped to TTPs: ${m.checks_mapped}`,
        `Checks with Active CTI Support: ${m.checks_with_cti_support}`,
        m.unsupported_checks.length
          ? `Pending CTI Support: ${m.unsupported_checks.join(", ")}`
          : "100% of Checks have Active CTI Support"
      ]),
    ]),
    el("p", { class: "eval-note", text: r.note })
  );
}

/* ----------------------------------------------------- attack paths */
async function renderAttackPaths() {
  const body = clear($("pathsBody"));
  if (!state.runId) {
    body.append(el("p", { class: "eval-note", text: "Select a scan run to analyze attack paths." }));
    return;
  }
  body.append(el("p", { class: "eval-note", text: "Analyzing graph topology and identifying lateral attack vectors\u2026" }));
  const res = await api(`/api/runs/${state.runId}/attack-paths`);
  const paths = res.attack_paths || [];
  clear(body);
  if (!paths.length) {
    body.append(el("div", { class: "empty-card", style: "background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 2.5rem; text-align: center; margin-top: 1rem;" }, [
      el("h4", { style: "font-size: 1.1rem; font-weight: 700; color: var(--text); margin-bottom: 0.5rem;", text: "No Exploitable Attack Paths Detected" }),
      el("p", { style: "color: var(--text-muted); font-size: 0.95rem; max-width: 500px; margin: 0 auto;", text: "Resource isolation, strict network controls, or identity boundaries prevent adversaries from chaining public exposure to sensitive assets in this environment." })
    ]));
    return;
  }

  const container = el("div", { class: "attack-paths-list", style: "display: flex; flex-direction: column; gap: 1.5rem; margin-top: 1rem;" });
  for (const ap of paths) {
    const card = el("div", { class: "ap-card", style: "background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 1.75rem; box-shadow: var(--shadow-sm);" });

    // Header
    const topRow = el("div", { style: "display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1rem;" });
    const titleBox = el("div", { style: "display: flex; align-items: center; gap: 0.75rem;" });
    titleBox.append(badge(ap.severity || "Critical"));
    titleBox.append(el("strong", { style: "font-size: 1.05rem; color: var(--text);", text: ap.title }));
    const scoreBox = el("div", { style: "font-size: 0.85rem; font-weight: 700; background: var(--bg-subtle); color: var(--accent); padding: 0.35rem 0.75rem; border-radius: var(--radius-pill);", text: `Risk Score: ${ap.risk_score}` });
    topRow.append(titleBox, scoreBox);

    // Flow / Steps
    const flowWrap = el("div", { class: "ap-flow", style: "background: var(--bg-subtle); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 1.25rem; margin-bottom: 1.25rem; overflow-x: auto;" });
    const flowTitle = el("div", { style: "font-size: 0.8rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.75rem; letter-spacing: 0.05em;", text: "Kill-Chain Sequence" });
    const stepsRow = el("div", { style: "display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem;" });

    (ap.steps || []).forEach((step, idx) => {
      const nodeBadge = el("span", { style: "background: var(--surface); border: 1px solid var(--border-strong); padding: 0.4rem 0.75rem; border-radius: var(--radius-xs); font-size: 0.85rem; font-weight: 600; color: var(--text);", text: step.from_node });
      stepsRow.append(nodeBadge);

      const arrow = el("span", { style: "color: var(--accent); font-weight: 700; font-size: 0.85rem; display: flex; align-items: center; gap: 0.25rem; padding: 0 0.25rem;" }, [
        el("span", { text: `\u2192 [${step.relationship || "chain"}]` })
      ]);
      stepsRow.append(arrow);

      if (idx === ap.steps.length - 1) {
        const destBadge = el("span", { style: "background: var(--surface); border: 2px solid var(--accent); padding: 0.4rem 0.75rem; border-radius: var(--radius-xs); font-size: 0.85rem; font-weight: 700; color: var(--accent);", text: step.to_node });
        stepsRow.append(destBadge);
      }
    });
    flowWrap.append(flowTitle, stepsRow);

    // Remediation & Factors
    const bottomGrid = el("div", { style: "display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; font-size: 0.88rem;" });
    const remBox = el("div", {}, [
      el("strong", { style: "color: var(--text); display: block; margin-bottom: 0.25rem;", text: "Remediation Strategy:" }),
      el("p", { style: "color: var(--text-muted); margin: 0;", text: ap.remediation || "Isolate resource and restrict network exposure." })
    ]);
    const whyBox = el("div", {}, [
      el("strong", { style: "color: var(--text); display: block; margin-bottom: 0.25rem;", text: "Path Impact & Threat Context:" }),
      el("p", { style: "color: var(--text-muted); margin: 0;", text: ap.risk_factors ? ap.risk_factors.join("; ") : "Public attack vector enables lateral privilege escalation." })
    ]);
    bottomGrid.append(remBox, whyBox);

    card.append(topRow, flowWrap, bottomGrid);
    container.append(card);
  }
  body.append(container);
}

/* ------------------------------------------------------- compliance */
async function renderCompliance() {
  const body = clear($("complianceBody"));
  if (!state.runId) {
    body.append(el("p", { class: "eval-note", text: "Select a scan run to view framework compliance." }));
    return;
  }
  body.append(el("p", { class: "eval-note", text: "Evaluating compliance against CIS AWS Foundations Benchmark & NIST SP 800-53\u2026" }));
  const res = await api(`/api/runs/${state.runId}/compliance`);
  const bms = (res.compliance && res.compliance.benchmarks) || {};
  clear(body);

  const grid = el("div", { class: "evalgrid", style: "display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 1.5rem; margin-top: 1rem;" });
  for (const [key, bm] of Object.entries(bms)) {
    const s = bm.summary || {};
    const card = el("div", { class: "eval-card", style: "background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 1.5rem; box-shadow: var(--shadow-sm);" });

    const title = el("h3", { style: "font-size: 1.1rem; font-weight: 700; margin-bottom: 0.25rem; color: var(--text);", text: `${bm.framework} ${bm.version}` });
    const scorePill = el("div", { style: "display: inline-block; background: var(--bg-subtle); color: var(--accent); padding: 0.25rem 0.65rem; border-radius: var(--radius-pill); font-size: 0.85rem; font-weight: 700; margin-bottom: 1rem;", text: `Score: ${s.compliance_score_percent}% | Coverage: ${s.coverage_rate_percent}%` });

    const statsRow = el("div", { style: "display: flex; gap: 0.75rem; margin-bottom: 1.25rem;" }, [
      el("span", { style: "background: #E8F8F0; color: #0E7844; font-size: 0.8rem; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: var(--radius-xs);", text: `Passed: ${s.passed}` }),
      el("span", { style: "background: #FEECEB; color: #E03E2D; font-size: 0.8rem; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: var(--radius-xs);", text: `Failed: ${s.failed}` }),
      el("span", { style: "background: var(--bg-subtle); color: var(--text-muted); font-size: 0.8rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: var(--radius-xs);", text: `Unassessed: ${s.unassessed}` })
    ]);

    const failedHeader = el("strong", { style: "font-size: 0.9rem; color: var(--text); display: block; margin-bottom: 0.5rem;", text: "Violations / Failed Controls:" });
    const failList = el("ul", { style: "list-style: none; padding: 0; margin: 0 0 1rem 0; font-size: 0.85rem; color: var(--text);" });
    if (!bm.failed_controls || !bm.failed_controls.length) {
      failList.append(el("li", { style: "color: #0E7844;", text: "No violations recorded for this benchmark." }));
    } else {
      bm.failed_controls.forEach((fc) => {
        failList.append(el("li", { style: "padding: 0.35rem 0; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;" }, [
          el("span", { text: `[${fc.control_id}] ${fc.title}` }),
          el("span", { style: "color: #E03E2D; font-weight: 700;", text: `${fc.failing_findings_count} finding(s)` })
        ]));
      });
    }

    const note = el("p", { style: "font-size: 0.78rem; color: var(--text-muted); margin-top: 0.75rem; border-top: 1px dashed var(--border); padding-top: 0.75rem;", text: bm.disclaimer || "Assessment covers deterministic static rules mapped to control criteria." });

    card.append(title, scorePill, statsRow, failedHeader, failList, note);
    grid.append(card);
  }
  body.append(grid);
}

/* ----------------------------------------------------------- wiring */
function showTab(name) {
  for (const t of document.querySelectorAll(".tab")) {
    const on = t.dataset.tab === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", String(on));
    const panel = $("tab-" + t.dataset.tab);
    if (panel) panel.classList.toggle("hidden", !on);
  }
  if (name === "paths") renderAttackPaths().catch((e) => setStatus(e.message, true));
  if (name === "compliance") renderCompliance().catch((e) => setStatus(e.message, true));
  if (name === "cti") renderCti().catch((e) => setStatus(e.message, true));
  if (name === "eval") renderEval().catch((e) => setStatus(e.message, true));
}

async function guarded(fn) {
  try {
    await fn();
  } catch (e) {
    setStatus(e.message, true);
  }
}

function triggerFileUpload() {
  if (window.authState && window.authState.auth_required && !window.authState.authenticated) {
    window.location.href = "/login?next=/#dashboard";
    return;
  }
  const fi = $("fileInput");
  if (fi) {
    const dash = $("dashboard");
    if (dash) dash.scrollIntoView({ behavior: "smooth" });
    fi.click();
  }
}

async function triggerDemoScan() {
  if (window.authState && window.authState.auth_required && !window.authState.authenticated) {
    window.location.href = "/login?next=/#dashboard";
    return;
  }
  const dash = $("dashboard");
  if (dash) dash.scrollIntoView({ behavior: "smooth" });
  setStatus("Running multi-cloud demo simulation\u2026");
  const { runs } = await api("/api/scan/demo", { method: "POST" });
  await loadRuns(runs.vulnerable_env);
}

document.addEventListener("DOMContentLoaded", () => {
  // Tabs
  for (const t of document.querySelectorAll(".tab")) {
    t.addEventListener("click", () => showTab(t.dataset.tab));
  }

  // Select Run
  const runSelect = $("runSelect");
  if (runSelect) {
    runSelect.addEventListener("change", (e) => guarded(() => selectRun(e.target.value)));
  }

  // Filters & Search
  for (const id of ["search", "priorityFilter", "categoryFilter"]) {
    const el = $(id);
    if (el) el.addEventListener("input", renderFindings);
  }

  // Drawer
  const closeDrawerBtn = $("closeDrawer");
  if (closeDrawerBtn) closeDrawerBtn.addEventListener("click", closeDrawer);
  const backdrop = $("drawerBackdrop");
  if (backdrop) backdrop.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  // Demo Scan Buttons
  const demoBtn = $("demoBtn");
  if (demoBtn) demoBtn.addEventListener("click", () => guarded(triggerDemoScan));
  const ctaDemoBtn = $("ctaDemoBtn");
  if (ctaDemoBtn) ctaDemoBtn.addEventListener("click", () => guarded(triggerDemoScan));

  // File Upload
  const fileInput = $("fileInput");
  if (fileInput) {
    fileInput.addEventListener("change", (e) => guarded(async () => {
      const file = e.target.files[0];
      if (!file) return;
      setStatus(`Scanning and prioritizing ${file.name}\u2026`);
      const fd = new FormData();
      fd.append("file", file);
      try {
        const { run_id } = await api("/api/scan", { method: "POST", body: fd });
        await loadRuns(run_id);
      } finally {
        e.target.value = "";
      }
    }));
  }

  // CTAs that trigger scan
  const navScanBtn = $("navScanBtn");
  if (navScanBtn) navScanBtn.addEventListener("click", triggerFileUpload);
  const heroStartScanBtn = $("heroStartScanBtn");
  if (heroStartScanBtn) {
    heroStartScanBtn.addEventListener("click", (e) => {
      e.preventDefault();
      triggerFileUpload();
    });
  }
  const ctaScanBtn = $("ctaScanBtn");
  if (ctaScanBtn) {
    ctaScanBtn.addEventListener("click", (e) => {
      e.preventDefault();
      triggerFileUpload();
    });
  }

  // Mobile menu toggle
  const mobileBtn = $("mobileMenuBtn");
  const navLinks = $("navLinks");
  if (mobileBtn && navLinks) {
    mobileBtn.addEventListener("click", () => {
      navLinks.classList.toggle("mobile-active");
    });
  }

  // Initial load: verify auth state before fetching dashboard data
  guarded(async () => {
    const auth = await checkAuth();
    if (!auth.auth_required || auth.authenticated) {
      await loadRuns();
    }
  });
});
