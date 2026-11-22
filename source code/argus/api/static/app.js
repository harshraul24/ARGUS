// ARGUS live triage workbench. Everything shown that came from telemetry (commands, paths,
// user names, host names) may have been written by an attacker: it is always passed
// through esc() and never inserted as HTML.
//
// One page, one run: the run the log receiver is writing. A case is one process tree, decided
// again whenever new events reach it (argus.live), so the queue, the host cards and the open
// case are refreshed together every few seconds.
"use strict";

const S = { live: null, cases: [], counts: {}, sel: null, view: null, viewRevs: 0, tab: "summary", show: "attention",
            host: null, known: null, fresh: new Set(), open: new Set(), verdicts: {}, tick: null,
            library: null, learnPoll: null };
const $ = (q) => document.querySelector(q);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (t) => (t ? String(t).replace("T", " ").replace(/\+00:00$|Z$/, "").slice(0, 19) : "");
const clock = (t) => (t ? String(t).slice(11, 19) : "");                 // hh:mm:ss of an ISO time (UTC)
const secs = (a, b) => (Date.parse(a) - Date.parse(b)) / 1000;
const ago = (s) => (s == null ? "–" : s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m`
                    : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`);
const pct = (x) => `${Math.round((x || 0) * 100)}%`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const FLAGGED = ["malicious", "suspicious"];
const QUIET_S = 60;            // a host silent this long is shown as quiet (an idle host often is)
const attention = (c) => FLAGGED.includes(c.disposition) || c.disposition === "undecidable" || c.blind_spots > 0;

async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}
// the server's reason ("detail") from a failed call, else the raw message
function errText(e) {
  const m = String(e.message).match(/^\d+ ([\s\S]*)$/);
  try { return JSON.parse(m[1]).detail || e.message; } catch (_) { return e.message; }
}
function toast(msg) {
  let t = $(".toast"); if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.append(t); }
  t.textContent = msg; t.classList.add("on"); setTimeout(() => t.classList.remove("on"), 2200);
}

// ------------------------------------------------------------------ boot and pages
async function boot() {
  document.querySelectorAll(".nav-btn").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
  document.querySelectorAll(".seg-btn").forEach((b) => b.addEventListener("click", () => {
    S.show = b.dataset.show;
    document.querySelectorAll(".seg-btn").forEach((x) => x.classList.toggle("active", x === b));
    renderQueue();
  }));
  $("#search").addEventListener("input", renderQueue);
  $("#hosts").addEventListener("click", (e) => {
    const b = e.target.closest(".host[data-host]"); if (!b) return;
    S.host = S.host === b.dataset.host ? null : b.dataset.host;
    renderHosts(); renderQueue();
  });
  $("#host-filter").addEventListener("click", () => { S.host = null; renderHosts(); renderQueue(); });
  $("#queue-list").addEventListener("click", (e) => { const li = e.target.closest(".qi[data-id]"); if (li) openCase(li.dataset.id); });
  $("#queue-list").addEventListener("keydown", queueKeys);
  $("#live-start").addEventListener("click", startLive);
  $("#live-stop").addEventListener("click", stopLive);
  $("#lib-filter").addEventListener("change", renderLibrary);
  $("#learn-form").addEventListener("submit", startLearning);
  $("#library-body").addEventListener("click", decideRule);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });
  await tick();
}
function showPage(p) {
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.page === p));
  ["queue", "gaps", "library"].forEach((x) => ($(`#page-${x}`).hidden = x !== p));
  if (p === "gaps") loadGaps();
  if (p === "library") { loadLibrary(); loadLearning(); }
}

// Every few seconds: the run's state and hosts, then its cases, then the open case if it was
// decided again. Paused while the tab is hidden.
async function tick() {
  clearTimeout(S.tick);
  if (!document.hidden) {
    try {
      await loadLive();
      await loadCases();
      if (!S.sel) renderEmpty(); else await refreshDetail();
    } catch (e) {
      $("#live-state").innerHTML = `<span class="bad" title="${esc(e.message)}">Cannot reach ARGUS</span>`;
    }
  }
  S.tick = setTimeout(tick, 3000);
}

// ------------------------------------------------------------------ the run and its hosts
async function loadLive() {
  const j = (S.live = await api("/workbench/live"));
  const sel = $("#live-run"), keep = sel.value || j.run || j.runs[j.runs.length - 1];
  sel.innerHTML = j.runs.map((r) => `<option>${esc(r)}</option>`).join("") || `<option value="">No runs</option>`;
  if (keep && j.runs.includes(keep)) sel.value = keep;
  sel.hidden = j.running;
  $("#live-start").hidden = j.running; $("#live-start").disabled = !j.runs.length;
  $("#live-stop").hidden = !j.running;
  $("#live-state").innerHTML = (j.running ? `<span class="pulse" aria-hidden="true"></span><b>Live</b> · ${esc(j.run)}`
    : j.run ? `Stopped · ${esc(j.run)}` : "Off")
    + (j.error ? ` · <span class="bad" title="${esc(j.error)}">error</span>` : "");
  renderHosts();
}
function renderHosts() {
  const hosts = Object.entries(S.live?.hosts || {});
  $("#hosts").hidden = !hosts.length;
  $("#hosts").innerHTML = hosts.map(([h, x]) => {
    const state = x.blind?.length ? "blind" : x.quiet_s == null ? "none" : x.quiet_s < QUIET_S ? "streaming" : "quiet";
    const what = { streaming: "Streaming", quiet: `Quiet ${ago(x.quiet_s)}`, none: "No data yet",
                   blind: `Blind to ${(x.blind || []).join(", ")}` }[state];
    const fa = x.first_alert;
    return `<button type="button" class="host ${state} ${S.host === h ? "sel" : ""}" data-host="${esc(h)}"
        aria-pressed="${S.host === h}" title="${S.host === h ? "Show every host" : `Show only ${esc(h)}`}">
      <span class="host-top"><span class="dot" aria-hidden="true"></span><span class="host-name">${esc(h)}</span>
        ${x.flagged ? `<span class="host-flag">${x.flagged} flagged</span>` : ""}</span>
      <span class="host-meta">${esc(what)}${x.last_record ? ` · last event ${esc(clock(x.last_record))}` : ""}</span>
      <span class="host-meta">${(x.events || 0).toLocaleString()} events · ${x.cases} cases</span>
      <span class="host-meta">${fa ? `First alert ${esc(clock(fa.at))}` : "No alert yet"}</span>
    </button>`;
  }).join("");
  $("#host-filter").hidden = !S.host;
  $("#host-filter").innerHTML = S.host ? `${esc(S.host)} <span aria-hidden="true">✕</span>` : "";
  $("#host-filter").title = "Show every host";
}
async function startLive() {
  const run = $("#live-run").value;
  if (!run) return;
  try {
    await api("/workbench/live", { method: "POST", body: JSON.stringify({ run }) });
    toast(`Live triage on ${run}`);
  } catch (e) { toast(errText(e).slice(0, 140)); }
  S.sel = null; S.view = null; S.known = null; S.fresh.clear(); S.host = null;
  showPage("queue");
  await tick();
}
async function stopLive() {
  if (!confirm("Stop live triage? The cases decided so far stay listed. Starting again reads the run from its beginning.")) return;
  try { await api("/workbench/live/stop", { method: "POST" }); toast("Live triage stopped"); }
  catch (e) { toast(errText(e).slice(0, 140)); }
  await tick();
}

// ------------------------------------------------------------------ queue
async function loadCases() {
  if (!S.live?.run) { S.cases = []; S.counts = {}; renderQueue(); return; }
  const d = await api("/workbench/cases?root=live");
  const first = S.known === null;
  S.known = S.known || {};
  for (const c of d.cases) {          // new or re-decided cases needing attention are marked until opened
    const n = c.revisions || 0, before = S.known[c.case_id];
    if (!first && c.case_id !== S.sel && attention(c) && (before === undefined || n > before)) S.fresh.add(c.case_id);
    S.known[c.case_id] = n;
  }
  S.cases = d.cases;
  S.counts = { total: d.total, attention: d.attention, flagged: d.flagged, per: d.listed_per_host };
  renderQueue();
}
function renderQueue() {
  const q = $("#search").value.toLowerCase();
  const mine = S.cases.filter((c) => !S.host || c.host === S.host);
  const rows = mine.filter((c) => !q || `${c.root_image} ${c.command} ${c.host} ${c.top || ""}`.toLowerCase().includes(q));
  const att = rows.filter(attention).sort((a, b) => (b.priority ?? -1) - (a.priority ?? -1) || b.last - a.last);
  const rest = rows.filter((c) => !attention(c)).sort((a, b) => b.last - a.last);
  const total = S.host ? S.live?.hosts?.[S.host]?.cases : S.counts.total;
  $("#n-attention").textContent = mine.filter(attention).length || "";
  $("#n-all").textContent = total || "";
  let html;
  if (!S.live?.run) html = empty("Start live triage to see cases.");
  else if (!S.cases.length) html = empty(`No cases yet. Waiting for events in captured/${S.live.run}/.`);
  else if (q && !rows.length) html = empty("No cases match.");
  else if (S.show === "attention") html = att.map(row).join("") || empty(`Nothing needs attention${S.host ? ` on ${S.host}` : ""}. Every case so far is benign.`);
  else html = (att.length ? section("Needs attention", att.length) + att.map(row).join("") : "")
    + section("Recent activity", rest.length) + rest.map(row).join("");
  $("#queue-list").innerHTML = html;
  $("#queue-stats").textContent = S.counts.total
    ? `${S.counts.total} cases · ${S.counts.flagged} flagged · each host's latest ${S.counts.per} quiet cases listed · times UTC` : "";
}
const empty = (msg) => `<li class="qi muted">${esc(msg)}</li>`;
const section = (name, n) => `<li class="q-section" role="presentation">${esc(name)} <span>${n}</span></li>`;
function row(c) {
  const disp = c.disposition || c.status, sel = c.case_id === S.sel;
  return `<li class="qi ${sel ? "sel" : ""}" data-id="${esc(c.case_id)}" role="option" aria-selected="${sel}">
    <div class="qi-top">
      <span class="chip ${esc(disp)}">${esc(disp)}</span>
      <span class="qi-name" title="${esc(c.root_image)}">${esc(c.root_image || "?")}</span>
      ${S.fresh.has(c.case_id) ? `<span class="fresh" title="New or decided again since you last looked">new</span>` : ""}
      <span class="qi-time" title="newest event (UTC)">${esc(clock(c.end))}</span>
    </div>
    ${c.command ? `<div class="qi-cmd" title="${esc(c.command)}">${esc(c.command)}</div>` : ""}
    <div class="qi-meta">
      <span>${esc(c.host)}</span><span>${c.events} event${c.events === 1 ? "" : "s"}</span>
      ${c.revisions > 1 ? `<span title="decided again as its events arrived">decided ${c.revisions}×</span>` : ""}
      ${c.top ? `<span title="top hypothesis">${esc(c.top)}</span>` : ""}
      ${c.blind_spots ? `<span class="badge blind" title="sensor blind spots">${c.blind_spots} blind</span>` : ""}
    </div>
  </li>`;
}
function queueKeys(e) {
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  const items = [...document.querySelectorAll(".qi[data-id]")];
  if (!items.length) return;
  e.preventDefault();
  const i = items.findIndex((li) => li.dataset.id === S.sel);
  const j = i < 0 ? 0 : Math.max(0, Math.min(items.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)));
  openCase(items[j].dataset.id);
}

// ------------------------------------------------------------------ a case
async function openCase(id) {
  S.sel = id; S.view = null; S.fresh.delete(id); renderQueue();
  document.querySelector(`.qi[data-id="${CSS.escape(id)}"]`)?.scrollIntoView({ block: "nearest" });
  $("#detail").innerHTML = `<div class="empty"><p>Loading…</p></div>`;
  for (let i = 0; i < 120 && S.sel === id; i++) {        // a case listed but not decided yet is, within seconds
    try { S.view = await api(`/workbench/case/${encodeURIComponent(id)}`); } catch (e) { S.view = null; }
    if (S.view && (S.view.verdict || S.view.status === "failed")) break;
    $("#detail").innerHTML = `<div class="empty"><p>Waiting for this case's first decision…</p></div>`;
    await sleep(1000);
  }
  if (S.sel !== id) return;
  S.viewRevs = S.view?.revisions?.length || 0;
  renderDetail();
}
// The open case was decided again: show the new decision, keeping the tab and scroll position.
// A half-written feedback form is never replaced; it gets a note instead.
async function refreshDetail() {
  const c = S.cases.find((x) => x.case_id === S.sel);
  if (!S.view || !c || (c.revisions || 0) <= S.viewRevs) return;
  if (S.tab === "feedback") {
    if (!$("#update-note")) {
      $("#detail").insertAdjacentHTML("afterbegin", `<div id="update-note" class="update-note">This case was decided again.
        <button type="button" class="btn small">Show</button></div>`);
      $("#update-note button").addEventListener("click", () => { S.tab = "summary"; openCase(S.sel); });
    }
    return;
  }
  const id = S.sel;
  let v;
  try { v = await api(`/workbench/case/${encodeURIComponent(id)}`); } catch (_) { return; }
  if (S.sel !== id || !v.verdict) return;
  S.view = v; S.viewRevs = v.revisions.length; S.fresh.delete(id);
  const y = $("#detail").scrollTop;
  renderDetail();
  $("#detail").scrollTop = y;
}
function renderEmpty() {
  const j = S.live;
  const [h, p] = !j?.run
    ? ["Live triage is off", "Pick the run the log receiver is writing, top right, and press Start. ARGUS then decides each case while its events arrive."]
    : !S.counts.total
      ? ["Waiting for events", `Nothing has arrived in captured/${j.run}/ yet. Check the log receiver and each victim's forwarding.`]
      : ["Select a case", "Cases that need attention come first. A case is one process tree, and it is decided again whenever new events reach it."];
  const html = `<div class="empty"><h2>${esc(h)}</h2><p>${esc(p)}</p></div>`;
  if ($("#detail").innerHTML !== html) $("#detail").innerHTML = html;
}

const TABS = [["summary", "Summary"], ["evidence", "Evidence"], ["tree", "Process tree"], ["timeline", "Timeline"],
              ["sensors", "Sensors"], ["shadow", "Shadow rules"], ["feedback", "Feedback"]];
function renderDetail() {
  const v = S.view;
  if (!v || !v.verdict) {
    $("#detail").innerHTML = `<div class="empty"><h2>Could not decide</h2><p>${esc(v?.error || "no decision yet")}</p></div>`;
    return;
  }
  const d = v.verdict, c = S.cases.find((x) => x.case_id === v.case_id) || {};
  const revs = v.revisions || [], last = revs[revs.length - 1];
  const lag = last?.event_time ? secs(last.at, last.event_time) : null;
  const top = d.top ? `Top hypothesis: <b>${esc(d.top.name)}</b> (${esc(d.top.rule_id)}), score ${d.top.score.toFixed(2)}`
                    : "No hypothesis is supported.";
  $("#detail").innerHTML = `
    <div class="verdict">
      <div>
        <div class="disp ${esc(d.disposition)}">${esc(d.disposition)}</div>
        <div class="case-line"><b>${esc(c.host)}</b> · process tree under <b>${esc(c.root_image || "?")}</b></div>
        ${c.command ? `<div class="case-cmd">${esc(c.command)}</div>` : ""}
      </div>
      <div class="nums">
        <div class="num"><b>${d.severity.toFixed(2)}</b><span>severity</span></div>
        <div class="num"><b>${d.priority.toFixed(2)}</b><span>priority</span></div>
        <div class="num"><b>${c.events ?? d.claims_total}</b><span>events</span></div>
        <div class="num"><b>${revs.length}</b><span>decisions</span></div>
      </div>
      <div class="why">${top}</div>
      <div class="facts">
        <span><i>First event</i>${esc(clock(c.start) || "–")}</span>
        <span><i>Newest event</i>${esc(clock(c.end) || "–")}</span>
        <span><i>Last decided</i>${esc(clock(last?.at) || "–")}</span>
        ${lag != null ? `<span title="from the newest event to the decision on it"><i>Decision lag</i>${lag.toFixed(1)} s</span>` : ""}
        <span class="mono muted">${esc(v.case_id)}</span>
      </div>
    </div>
    ${d.blind_spots.length ? `<div class="blind-box"><h3>What ARGUS could not see</h3>
      <ul>${d.blind_spots.map((b) => `<li>${esc(b)}</li>`).join("")}</ul>
      <div class="muted">Absence of evidence from a blind sensor is not evidence of absence; priority is lowered to reflect it.</div></div>` : ""}
    <div class="tabs" role="tablist">${TABS.map(([k, n]) => `<button class="tab ${S.tab === k ? "active" : ""}" data-tab="${k}" role="tab">${n}${tabCount(k)}</button>`).join("")}</div>
    <div id="tab-body"></div>`;
  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => { S.tab = b.dataset.tab; renderDetail(); }));
  ({ summary: tabSummary, evidence: tabEvidence, tree: tabTree, timeline: tabTimeline,
     sensors: tabSensors, shadow: tabShadow, feedback: tabFeedback }[S.tab] || tabSummary)();
}
function tabCount(k) {
  const v = S.view;
  const n = { evidence: v.hypotheses.length, timeline: v.timeline.length, shadow: v.shadow.length }[k];
  return n ? ` <span class="badge">${n}</span>` : "";
}

function tabSummary() {
  const v = S.view, d = v.verdict, revs = [...v.revisions].reverse();
  $("#tab-body").innerHTML = `
    ${revs.length ? `<div class="panel"><h3>Decisions, newest first</h3><div class="table-scroll"><table>
      <tr><th>decided</th><th>newest event</th><th>lag</th><th>disposition</th><th>severity</th><th>cause</th></tr>
      ${revs.map((r) => `<tr><td class="mono">${esc(clock(r.at))}</td><td class="mono">${esc(clock(r.event_time) || "–")}</td>
        <td>${r.event_time ? `${secs(r.at, r.event_time).toFixed(1)} s` : "–"}</td>
        <td><span class="chip ${esc(r.disposition)}">${esc(r.disposition)}</span></td>
        <td>${(+r.severity).toFixed(2)}</td><td>${esc(r.cause)}</td></tr>`).join("")}</table></div></div>` : ""}
    <div class="panel"><h3>Explanation</h3><div class="explain">${esc(v.explanation)}</div></div>
    ${d.next_actions.length ? `<div class="panel"><h3>Next actions</h3><ul>${d.next_actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul></div>` : ""}
    ${d.notes.length ? `<div class="panel"><h3>Notes</h3><ul>${d.notes.map((a) => `<li>${esc(a)}</li>`).join("")}</ul></div>` : ""}
    <div class="panel"><h3>Telemetry in this decision</h3><div class="kv">${Object.entries(v.claim_types)
      .map(([k, n]) => `<span>${esc(k)}</span><span>${n}</span>`).join("")}</div></div>`;
}

function claimTable(rows, showFor = true) {
  if (!rows.length) return `<p class="muted">No claims.</p>`;
  return `<div class="table-scroll"><table><tr><th>time</th><th>host</th><th>type</th><th>what</th>${showFor ? "<th>evidence for</th>" : ""}</tr>
    ${rows.map((r) => `<tr>
      <td class="mono">${esc(fmtTime(r.time))}</td><td>${esc(r.host)}</td><td>${esc(r.type)}</td>
      <td class="cmd" title="${esc(r.summary)}">${esc(r.summary)}</td>
      ${showFor ? `<td>${r.evidence_for.map((x) => `<span class="badge ev">${esc(x)}</span>`).join(" ")}</td>` : ""}</tr>`).join("")}</table></div>`;
}

function hypCard(h, shadow = false) {
  const mine = (S.verdicts[S.sel] || {})[h.rule_id];
  return `<div class="hyp ${S.open.has(h.rule_id) ? "open" : ""}" data-rule="${esc(h.rule_id)}">
    <div class="hyp-head">
      <div><div class="hyp-name">${esc(h.name)}</div>
        <div class="hyp-sub">${esc(h.rule_id)}${h.tactic ? " · " + esc(h.tactic) : ""} · ${h.support_total} supporting claim(s)${shadow ? " · shadow: cannot affect the verdict" : ""}</div></div>
      <div><div class="bar"><span style="width:${pct(h.score)}"></span></div><div class="hyp-sub">score ${h.score.toFixed(2)}</div></div>
      <div class="verdict-btns" title="Your verdict on this rule's evidence in this case (feeds the rule library)">
        <button data-v="malicious" class="${mine === "malicious" ? "on-mal" : ""}">Confirm</button>
        <button data-v="benign" class="${mine === "benign" ? "on-ben" : ""}">Reject</button>
      </div>
    </div>
    <div class="hyp-body">
      ${h.rationale.length ? `<h3>Why</h3><ul>${h.rationale.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      ${h.defeaters.length ? `<h3>Defeaters</h3>${h.defeaters.map((x) => `<div class="def"><span class="k ${esc(x.kind)}">${esc(x.kind)}</span><span>${esc(x.reason)}</span></div>`).join("")}` : ""}
      ${h.coverage_gaps.length ? `<h3>Coverage gaps</h3><ul>${h.coverage_gaps.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      <h3>Supporting claims</h3>${claimTable(h.support, false)}
      ${h.support_total > h.support.length ? `<p class="muted">Showing ${h.support.length} of ${h.support_total}.</p>` : ""}
    </div></div>`;
}
function wireHyps() {
  document.querySelectorAll(".hyp-head").forEach((el) => el.addEventListener("click", (e) => {
    if (e.target.closest(".verdict-btns")) return;
    const rule = el.parentElement.dataset.rule;
    if (el.parentElement.classList.toggle("open")) S.open.add(rule); else S.open.delete(rule);
  }));
  document.querySelectorAll(".verdict-btns button").forEach((b) => b.addEventListener("click", () => {
    const rule = b.closest(".hyp").dataset.rule;
    const m = (S.verdicts[S.sel] = S.verdicts[S.sel] || {});
    m[rule] = m[rule] === b.dataset.v ? undefined : b.dataset.v;
    if (!m[rule]) delete m[rule];
    renderDetail();
  }));
}
function tabEvidence() {
  const v = S.view;
  $("#tab-body").innerHTML = v.hypotheses.length ? v.hypotheses.map((h) => hypCard(h)).join("")
    : `<p class="muted">No hypothesis is supported in this case.</p>`;
  wireHyps();
}
function tabShadow() {
  const v = S.view;
  $("#tab-body").innerHTML = `<p class="muted">Shadow rules run on every case and are measured, but cannot move the verdict.
    Your verdicts here decide whether a rule is promoted or retired.</p>` +
    (v.shadow.length ? v.shadow.map((h) => hypCard(h, true)).join("") : `<p class="muted">No shadow rule fired.</p>`);
  wireHyps();
}

function treeNode(n) {
  return `<li class="node ${n.evidence ? "ev" : ""}"><div class="row">
      <span class="img">${esc(n.image)}</span>
      ${n.user_writable ? `<span class="badge uw" title="runs from a folder a user can write">user-writable</span>` : ""}
      ${n.evidence ? `<span class="badge ev">${n.evidence} evidence</span>` : ""}
      <span class="badge">${n.claims} claim(s)</span>
    </div>
    ${n.command ? `<div class="cmd">${esc(n.command)}</div>` : ""}
    ${n.children.length ? `<ul>${n.children.map(treeNode).join("")}</ul>` : ""}</li>`;
}
function tabTree() {
  const t = S.view.tree;
  $("#tab-body").innerHTML = `<div class="panel"><h3>Process tree — ${esc(t.scope)}</h3>
    ${t.roots.length ? `<ul class="tree">${t.roots.map(treeNode).join("")}</ul>` : `<p class="muted">No process lineage in this telemetry.</p>`}</div>`;
}
function tabTimeline() {
  $("#tab-body").innerHTML = `<div class="panel"><h3>Evidence timeline</h3>${claimTable(S.view.timeline)}</div>`;
}
function tabSensors() {
  const s = S.view.sensors;
  $("#tab-body").innerHTML = Object.entries(s).map(([id, h]) => `<div class="panel"><h3>${esc(id)}</h3><div class="sensor">
      <span class="muted">healthy</span><span>${esc(h.healthy)}</span>
      <span class="muted">records</span><span>${esc((h.covers || []).join(", ") || "—")}</span>
      <span class="muted">blind to</span><span>${(h.blind_to || []).map((b) => `<span class="badge blind">${esc(b)}</span>`).join(" ") || "—"}</span>
      ${h.notes && h.notes.length ? `<span class="muted">notes</span><span>${h.notes.map(esc).join("<br>")}</span>` : ""}
    </div></div>`).join("") || `<p class="muted">No sensor health reported.</p>`;
}

async function tabFeedback() {
  const mine = S.verdicts[S.sel] || {};
  let past = { outcomes: [], rule_verdicts: [] };
  try { past = await api(`/workbench/feedback/${encodeURIComponent(S.sel)}`); } catch (e) { /* none yet */ }
  $("#tab-body").innerHTML = `<div class="panel"><form class="fb">
      <h3>Case outcome</h3>
      <div class="outcomes">${[["true_positive", "True positive"], ["false_positive", "False positive"], ["benign", "Benign"], ["unknown", "Unknown"]]
        .map(([k, n]) => `<label><input type="radio" name="outcome" value="${k}" ${k === "unknown" ? "checked" : ""}> ${n}</label>`).join("")}</div>
      <label>Analyst <input type="text" name="analyst" placeholder="name or initials"></label>
      <label>Note <textarea name="note" rows="3"></textarea></label>
      <div class="muted">Rule verdicts from the Evidence and Shadow tabs: ${Object.keys(mine).length
        ? Object.entries(mine).map(([r, x]) => `<span class="badge">${esc(r)}: ${esc(x)}</span>`).join(" ") : "none"}</div>
      <div><button class="btn" type="submit">Record feedback</button></div>
    </form></div>
    <div class="panel"><h3>Recorded for this case</h3>
      ${past.outcomes.length ? `<table><tr><th>at</th><th>outcome</th><th>analyst</th><th>note</th></tr>${past.outcomes.map((o) =>
        `<tr><td>${esc(fmtTime(o.at))}</td><td>${esc(o.outcome)}</td><td>${esc(o.analyst)}</td><td>${esc(o.note)}</td></tr>`).join("")}</table>` : `<p class="muted">Nothing yet.</p>`}
      ${past.rule_verdicts.length ? `<p class="muted">${past.rule_verdicts.length} rule verdict(s) recorded.</p>` : ""}
    </div>`;
  $("form.fb").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    await api("/workbench/feedback", { method: "POST", body: JSON.stringify({
      case_id: S.sel, outcome: f.get("outcome"), analyst: f.get("analyst") || null,
      note: f.get("note") || null, rule_verdicts: mine }) });
    toast("Feedback recorded"); tabFeedback();
  });
}

// ------------------------------------------------------------------ coverage and library
async function loadGaps() {
  const g = await api("/workbench/gaps");
  $("#gaps-body").innerHTML = g.gaps.length ? `<div class="table-scroll"><table><tr><th>blind spot</th><th>sensor</th><th>cases</th><th>left undecidable</th><th>example</th></tr>
    ${g.gaps.map((x) => `<tr><td>${esc(x.gap)}</td><td>${esc(x.sensor)}</td><td>${x.cases}</td><td>${x.undecidable_cases}</td><td class="mono">${esc(x.example_case)}</td></tr>`).join("")}</table></div>`
    : `<p class="muted">No blind spots in the cases decided so far.</p>`;
}
async function loadLibrary(force = false) {
  if (!S.library || force) S.library = await api("/workbench/library");
  renderLibrary();
}

// ------------------------------------------------------------------ learning and review
async function loadLearning() {
  const j = await api("/workbench/learn");
  if (!$("#learn-model").value) $("#learn-model").value = j.default_model || "";
  const src = j.source || {};
  $("#learn-source").textContent = src.windows
    ? `Learns from the design operations ${src.operations.join(", ")} (${src.windows} windows on ${src.hosts.length} hosts). `
      + "Each rule is checked without labels; rules no independent source confirms wait for your review below."
    : "No design operations to learn from yet (lab_split.json and cases_lab).";
  renderLearning(j);
  clearTimeout(S.learnPoll);
  if (j.state === "running") S.learnPoll = setTimeout(loadLearning, 2000);
  else if (S.learnWasRunning) { S.learnWasRunning = false; loadLibrary(true); tick(); }
}
function renderLearning(j) {
  const busy = j.state === "running";
  $("#learn-start").disabled = busy;
  $("#learn-key").disabled = busy;
  const stage = { starting: "Starting", episodes: "Finding new activity", writing: "Writing rules",
                  checking: "Checking rules", done: "Finishing" }[j.stage] || j.stage;
  let html = "";
  if (busy) {
    const frac = j.total ? j.done / j.total : 0;
    html = `<div>${esc(stage)}${j.total ? ` · ${j.done}/${j.total}` : ""}</div>
      <div class="bar"><span style="width:${pct(frac)}"></span></div>`;
    S.learnWasRunning = true;
  } else if (j.state === "done") {
    const r = j.result || {};
    html = `<div class="ok">${esc(j.message)} ${r.new_rules ?? 0} new rule(s): ${r.new_active ?? 0} active,
      ${r.awaiting_review ?? 0} awaiting your review; ${r.duplicates_retired ?? 0} duplicate(s) retired.</div>`;
  } else if (j.state === "failed") {
    html = `<div class="bad">${esc(j.message)}</div>`;
  }
  $("#learn-status").innerHTML = html;
}
async function startLearning(ev) {
  ev.preventDefault();
  const key = $("#learn-key").value;
  try {
    const j = await api("/workbench/learn", { method: "POST",
      body: JSON.stringify({ model: $("#learn-model").value, api_key: key }) });
    $("#learn-key").value = "";                         // the page keeps no copy
    toast("Learning started");
    renderLearning(j);
    S.learnWasRunning = true;
    S.learnPoll = setTimeout(loadLearning, 2000);
  } catch (e) { toast(errText(e).slice(0, 140)); }
}
async function decideRule(ev) {
  const b = ev.target.closest("button[data-action]"); if (!b) return;
  const verb = b.dataset.action === "approve" ? "Approve" : "Retire";
  if (!confirm(`${verb} this rule? ${verb === "Approve" ? "It will start deciding cases." : "It will stop deciding cases."}`)) return;
  try {
    await api(`/workbench/library/${encodeURIComponent(b.dataset.uid)}`, { method: "POST",
      body: JSON.stringify({ action: b.dataset.action }) });
    toast(`Rule ${b.dataset.action === "approve" ? "approved" : "retired"}`);
    await loadLibrary(true);
    tick();
  } catch (e) { toast(errText(e).slice(0, 140)); }
}
// The five checks in order, as argus.rules.checks defines them: passed, failed or not reached.
// C5 also says who confirmed the rule; hovering gives the check's question and its finding.
const SOURCE_SHORT = { analyst: "analyst", "hand-written rule": "rule", "Sigma rule": "Sigma" };
function checkBadge(c) {
  const mark = { passed: "✓", failed: "✗", not_reached: "·" }[c.state];
  const tip = `${c.id} ${c.name}: ${c.question}` + (c.state === "not_reached" ? " (not reached)" : "")
    + (c.detail ? ` — ${c.detail}` : "") + (c.source ? ` — confirmed by ${c.source}` : "");
  const who = c.state === "passed" && c.source ? ` ${SOURCE_SHORT[c.source] || c.source}` : "";
  return `<span class="badge check ${esc(c.state)}" title="${esc(tip)}">${esc(c.id)} ${mark}${esc(who)}</span>`;
}
function renderLibrary() {
  const L = S.library; if (!L) return;
  const word = { shadow: "awaiting review" };
  $("#library-meta").textContent = L.library
    ? `${Object.entries(L.counts || {}).filter(([, v]) => v).map(([k, v]) => `${v} ${word[k] || k}`).join("  ·  ")}. Library file: ${L.library}.`
    : "No rule library yet. Learn rules from a design operation to start one.";
  const f = $("#lib-filter").value;
  const rows = L.entries.filter((e) => !f || e.status === f);
  const label = { shadow: "awaiting review" };
  const actions = (e) => e.status === "shadow"
    ? `<button class="approve" data-action="approve" data-uid="${esc(e.uid)}">Approve</button>
       <button class="retire" data-action="retire" data-uid="${esc(e.uid)}">Retire</button>`
    : e.status === "active" ? `<button class="retire" data-action="retire" data-uid="${esc(e.uid)}">Retire</button>` : "";
  $("#library-body").innerHTML = rows.length ? `<div class="table-scroll"><table><tr><th>rule</th><th>status</th><th>checks</th><th>reason</th><th>written from</th><th></th></tr>
    ${rows.map((e) => `<tr><td><b>${esc(e.name)}</b><div class="muted mono">${esc(e.uid)}</div></td>
      <td><span class="chip st-${esc(e.status)}">${esc(label[e.status] || e.status)}</span></td>
      <td><div class="checks">${e.checks.map(checkBadge).join("")}</div></td>
      <td>${esc(e.reason)}</td><td class="mono">${esc(e.origin)}</td><td><div class="rule-actions">${actions(e)}</div></td></tr>`).join("")}</table></div>`
    : `<p class="muted">No rules.</p>`;
}

boot().catch((e) => { $("#detail").innerHTML = `<div class="empty"><h2>Cannot reach ARGUS</h2><p>${esc(e.message)}</p></div>`; });
