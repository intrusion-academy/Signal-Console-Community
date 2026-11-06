// Collections, the host inventory (the Hosts page) and the fleet dashboard
// (Overview).
//
// One host row per host - its latest collection: what the host is
// (identity), how and when it was collected, which modules ran and how,
// its open signals and coverage gaps, its risk, the state of the telemetry
// its modules depend on, and its collection history. Telemetry is what the
// modules themselves report (each result's telemetry items), so nothing
// here knows a module's summary keys.
'use strict';

const { hostMeta, byHost } = require('./hosts');
const { runSignals, severityCounts, SEVERITY_RANK } = require('./signals');
const { applyTriage, isOpen } = require('./triage');
const { olderOutput } = require('../legacy');

// RISK_WEIGHT is what one open signal adds to its host's risk score, by
// severity; an escalated signal counts twice.
const RISK_WEIGHT = { critical: 40, high: 20, medium: 5, low: 1 };
const riskOf = (rows) => rows.filter(isOpen).reduce((n, s) => n + (RISK_WEIGHT[s.severity] || 0) * (s.triage === 'escalated' ? 2 : 1), 0);

// prevalenceKey is what makes two signals "the same" across hosts: the
// rule and the value it matched (an event's value in rule_matches); a
// signal with no value - a state of the host - is its rule.
const prevalenceKey = (s) => `${s.rule_id}\u0000${s.value || ''}`;

// derived keeps each run's signals as derived from its document: a run
// never changes after import (a re-import is a new object), so they are
// computed once per run and dropped with it. An older collection held as
// a shell (src/store.js) carries its own.
const derived = new WeakMap();
function derivedSignals(run) {
  if (run.shell) return run.signals;
  if (!derived.has(run)) derived.set(run, runSignals(run));
  return derived.get(run);
}

// fleetBase is what depends on the runs alone, computed once per change of
// the runs: each host's runs newest first, each run's previous run, and per
// signal is_new - its host's previous collection did not have it (false
// when there is no previous collection) - and fleet_n, the number of hosts
// whose current collection has the same signal (same rule, same value): 1
// is a match seen on this host alone, what stands out on a fleet of
// similar machines.
function fleetBase(runs) {
  const hosts = byHost(runs);
  const hostOfRun = new Map();
  for (const list of hosts.values()) for (const r of list) hostOfRun.set(r.run_id, list);
  const byRunId = new Map(runs.map((r) => [r.run_id, r]));
  const latest = [...hosts.values()].map((list) => list[0]);
  const prevalence = new Map();
  for (const run of latest) {
    for (const k of new Set(derivedSignals(run).map(prevalenceKey))) prevalence.set(k, (prevalence.get(k) || 0) + 1);
  }
  const previousOf = (runId) => {
    const list = hostOfRun.get(runId) || [];
    return list[list.indexOf(byRunId.get(runId)) + 1] || null;
  };
  const marked = new Map();
  const baseOf = (runId) => {
    if (!marked.has(runId)) {
      const run = byRunId.get(runId);
      const prev = previousOf(runId);
      const prevSids = prev ? new Set(derivedSignals(prev).map((s) => s.sid)) : null;
      marked.set(runId, run ? derivedSignals(run).map((s) => ({
        ...s, is_new: Boolean(prevSids) && !prevSids.has(s.sid), fleet_n: prevalence.get(prevalenceKey(s)) || 0,
      })) : []);
    }
    return marked.get(runId);
  };
  return { byHost: hosts, hostOfRun, baseOf, previousOf, latest };
}

// withTriage is the triage layer over a fleetBase: signalsOf(run_id) is a
// run's signals with the triage doc applied, computed per run on first use.
function withTriage(base, doc) {
  const triaged = new Map();
  const signalsOf = (runId) => {
    if (!triaged.has(runId)) triaged.set(runId, applyTriage(base.baseOf(runId), doc));
    return triaged.get(runId);
  };
  return { byHost: base.byHost, hostOfRun: base.hostOfRun, signalsOf, previousOf: base.previousOf, latest: base.latest };
}

// collections is the runs' fleetBase with the triage doc applied.
const collections = (runs, doc) => withTriage(fleetBase(runs), doc);

// telemetryOf lists a run's telemetry items, each with its module, in the
// panel's order (byTelemetryOrder).
// An item two modules state (Sysmon's log) is listed once.
function telemetryOf(run) {
  const seen = new Set();
  return Object.entries(run.modules || {}).flatMap(([module, r]) => (r.telemetry || []).map((t) => ({ ...t, module })))
    .filter((t) => !seen.has(t.id) && seen.add(t.id)).sort(byTelemetryOrder);
}

// warningsOf lists a run's KPI cards whose status is not good - a state of
// the host (its log, a policy, an account) its module says deserves a look,
// with the module's note on what it means.
function warningsOf(run) {
  return Object.entries(run.modules || {}).flatMap(([module, r]) => (r.kpis || [])
    .filter((k) => k.status === 'warn' || k.status === 'bad')
    .map((k) => ({ module, id: k.id, label: k.label, value: k.value, status: k.status, note: k.note || '' })));
}

// hostFacts is the part of a host row its run alone decides (facts,
// modules, warnings, gaps, telemetry, sources): computed once per run, like
// its derived signals, so a triage change rebuilds only the signal counts.
const facts = new WeakMap();
function hostFacts(run) {
  if (facts.has(run)) return facts.get(run);
  const hi = run.host || {};
  const u = run.user || {};
  const mods = run.modules || {};
  const gaps = Object.entries(mods).flatMap(([module, r]) => [
    ...(r.coverage_gaps || []).map((g) => ({ module, text: `${g.item}: ${g.reason}` })),
    ...(r.errors || []).map((e) => ({ module, text: e })),
  ]);
  const telemetry = telemetryOf(run);
  const warnings = warningsOf(run);
  const out = {
    run_id: run.run_id, ...hostMeta(run), machine_id: hi.machine_id || '',
    os_version: hi.os_version || '', arch: hi.arch || '', installation_type: hi.installation_type || '',
    domain: hi.user_domain || (run.host ? '(workgroup)' : ''), elevated: hi.elevated ?? null,
    timezone: hi.timezone || '', utc_to_local: hi.utc_to_local || '', boot_time: hi.boot_time || '',
    mode: run.mode || '', tool_version: run.tool_version || '', older_output: olderOutput(run), started: run.started || '', finished: run.finished || '', duration: run.duration || '',
    collected_by: u.name || '', collected_by_sid: u.sid || '', profile_created: u.profile_created || '',
    evidence: run.evidence || null, shadow_copies: run.shadow_copies || null, profile: run.profile || null,
    modules: Object.entries(mods).map(([name, r]) => ({ name, status: r.status || 'ok', errors: (r.errors || []).length })),
    warnings, warnings_n: warnings.length,
    gaps, gaps_n: gaps.length,
    telemetry,
    telemetry_off_n: telemetry.filter((t) => t.state === 'off').length,
    telemetry_unknown_n: telemetry.filter((t) => t.state === 'unknown').length,
    sources: sourcesOf(run),
  };
  facts.set(run, out);
  return out;
}

// hostInventory is one row per host (see above), from collections c.
function hostInventory(c) {
  const newCount = (runId) => (c.previousOf(runId) ? c.signalsOf(runId).filter((s) => s.is_new).length : '');
  return c.latest.map((run) => {
    const sigs = c.signalsOf(run.run_id);
    const open = sigs.filter(isOpen);
    const bySeverity = severityCounts(open);
    const history = c.hostOfRun.get(run.run_id).map((r) => {
      const cs = severityCounts(c.signalsOf(r.run_id).filter(isOpen));
      return {
        run_id: r.run_id, started: r.started || '', tool_version: r.tool_version || '', latest: r === run,
        signals_n: cs.critical + cs.high + cs.medium + cs.low, warnings_n: hostFacts(r).warnings_n, new_n: newCount(r.run_id),
      };
    });
    return {
      ...hostFacts(run),
      by_severity: bySeverity, signals_n: bySeverity.critical + bySeverity.high + bySeverity.medium + bySeverity.low,
      top_severity: Object.keys(SEVERITY_RANK).find((s) => bySeverity[s] > 0) || '',
      untriaged_n: open.filter((s) => s.triage === 'new').length,
      escalated_n: open.filter((s) => s.triage === 'escalated').length,
      new_n: newCount(run.run_id),
      risk: riskOf(sigs),
      history,
    };
  });
}

// sourceState is what the panel says of a source, never more than Signal
// read: Signal's status, except that evidence it read with no record while
// one of its prerequisites is off is "off" - Windows does not write it, so
// its emptiness says nothing (a read with records stays read: they were
// written before, or by a source the prerequisite does not govern). note
// says what the state means.
function sourceState(s) {
  const records = s.records ?? 0;
  const off = (s.prerequisites || []).filter((p) => p.state === 'off');
  if (s.status === 'read' && !records && off.length) {
    return { state: 'off', note: `not recorded: ${off.map((p) => `${p.label || p.fact} is off${p.basis ? ` (${p.basis})` : ''}`).join('; ')} - Windows writes none of it, so finding none says nothing` };
  }
  if (s.status === 'read') return { state: 'read', note: records ? (s.detail || '') : `read - no record in it${s.detail ? `; ${s.detail}` : ''}` };
  return { state: s.status, note: s.reason || '' };
}

// sourcesOf is the health of a run's evidence sources (schema 6), one plain
// row each: what the evidence is, its state (sourceState) and what that
// means, how much of it there was and when, and its prerequisites. Empty
// for an older run.
function sourcesOf(run) {
  return (run.sources || []).map((s) => ({
    evidence: s.evidence, label: s.label || s.evidence, kind: s.kind || '', provider: s.provider || '', channel: s.channel || '',
    status: s.status, ...sourceState(s), reason: s.reason || '', records: s.records ?? 0, oldest: s.oldest || '', newest: s.newest || '',
    prerequisites: (s.prerequisites || []).map((p) => `${p.label || p.fact}: ${p.state}`).join('; '),
    prereqs: (s.prerequisites || []).map((p) => ({ label: p.label || p.fact, state: p.state, basis: p.basis || '', reason: p.reason || '' })),
  }));
}

// FRESHNESS buckets hosts by how long ago they were last collected.
const DAY = 86400000;
const FRESHNESS = [['under 1 day', 1], ['1 to 2 days', 2], ['2 to 5 days', 5], ['5 to 7 days', 7], ['7 to 30 days', 30], ['over 30 days', Infinity]];

// TELEMETRY_ORDER is the order of the telemetry categories on the
// dashboard: what is recorded, what adds to it, whether its log can be
// trusted, the protection that produces detections (schema 13), the OS
// features evidence depends on, whether the sources were read (schema 49,
// Scope); anything else last.
const TELEMETRY_ORDER = ['Security Log Audit', 'Logging settings', 'Log health', 'Protection', 'Operating system features'];

// TELEMETRY_FIRST are the items a category lists first, in this order (the
// user, 2026-10-23); the rest follow by label.
const TELEMETRY_FIRST = ['audit_policy_enabled', 'audit_policy_change_audit', 'group_policy_logging_applied', 'process_creation_audit', 'process_termination_audit'];
const itemRank = (t) => (TELEMETRY_FIRST.includes(t.id) ? TELEMETRY_FIRST.indexOf(t.id) : TELEMETRY_FIRST.length);
const categoryRank = (c) => (TELEMETRY_ORDER.includes(c) ? TELEMETRY_ORDER.indexOf(c) : TELEMETRY_ORDER.length);

// byTelemetryOrder orders telemetry items: by category, its first items,
// then by label.
const byTelemetryOrder = (a, b) => categoryRank(a.category) - categoryRank(b.category) || itemRank(a) - itemRank(b) || String(a.label).localeCompare(String(b.label));

// fleetDashboard is Overview: over the host rows given by run ID (every
// host when empty) - the headline numbers, hosts ranked by risk, the rules
// whose signals are on the most hosts, telemetry coverage
// (per telemetry item the modules report, how many hosts have it on, off
// or unknown) and collection freshness. now is the reference time for
// freshness.
// freshness counts hosts by the age of their latest collection, in UTC
// (Signal records every time in UTC). A collection timed after this
// server's clock - the collecting host's clock was ahead - is counted
// apart, never dropped.
function freshness(hosts, now) {
  const ages = hosts.map((x) => (now - Date.parse(x.started)) / DAY);
  const out = FRESHNESS.map(([label, maxDays], i) => {
    const minDays = i ? FRESHNESS[i - 1][1] : 0;
    return { label, hosts: ages.filter((age) => age >= minDays && age < maxDays).length };
  });
  const ahead = ages.filter((age) => age < 0).length;
  if (ahead) out.unshift({ label: "ahead of this server's clock", hosts: ahead });
  return out;
}

function fleetDashboard(c, hostRows, hostIds, now = Date.now()) {
  const wanted = new Set(hostIds || []);
  const hosts = hostRows.filter((x) => !wanted.size || wanted.has(x.run_id));
  const open = hosts.flatMap((x) => c.signalsOf(x.run_id)).filter(isOpen);
  const rules = new Map();
  for (const s of open) {
    if (!rules.has(s.rule_id)) rules.set(s.rule_id, { rule_id: s.rule_id, title: s.rule_title || s.title, severity: s.severity, module: s.module, hosts: new Set(), signals_n: 0 });
    const r = rules.get(s.rule_id);
    r.hosts.add(s.run_id);
    r.signals_n++;
  }
  const telemetry = new Map();
  const newestFirst = hosts.slice().sort((a, b) => String(b.started).localeCompare(String(a.started)));
  for (const x of newestFirst) { // the newest collection's wording of an item wins
    for (const t of x.telemetry) {
      if (!telemetry.has(t.id)) telemetry.set(t.id, { id: t.id, label: t.label, detail: t.detail || '', category: t.category || 'Other', module: t.module, yes: 0, no: 0, absent: 0, unknown: 0 });
      const item = telemetry.get(t.id);
      item[{ on: 'yes', off: 'no', absent: 'absent' }[t.state] || 'unknown']++;
    }
  }
  // Evidence sources: per evidence type, how many hosts read it, partly,
  // not at all, have it off (sourceState) or do not have it, the records
  // across them and the time they span; for one host, that host's own.
  const sources = new Map();
  for (const x of newestFirst) {
    for (const src of x.sources) {
      if (!sources.has(src.evidence)) sources.set(src.evidence, { evidence: src.evidence, label: src.label, kind: src.kind, read: 0, partial: 0, not_read: 0, off: 0, unavailable: 0, records: 0, oldest: '', newest: '' });
      const a = sources.get(src.evidence);
      a[src.state in a ? src.state : 'not_read']++;
      a.records += src.records;
      if (src.oldest && (!a.oldest || src.oldest < a.oldest)) a.oldest = src.oldest;
      if (src.newest > a.newest) a.newest = src.newest;
    }
  }
  const started = hosts.map((x) => x.started).filter(Boolean).sort();
  // A host whose module did not run has no telemetry item for it: unknown.
  for (const item of telemetry.values()) item.unknown = hosts.length - item.yes - item.no - item.absent;
  return {
    summary: {
      hosts: hosts.length, by_severity: severityCounts(open),
      untriaged: open.filter((s) => s.triage === 'new').length,
      escalated: open.filter((s) => s.triage === 'escalated').length,
      hosts_urgent: hosts.filter((x) => x.by_severity.critical + x.by_severity.high > 0).length,
    },
    hosts: hosts.slice().sort((a, b) => b.risk - a.risk || a.host.localeCompare(b.host)),
    top_rules: [...rules.values()].map((r) => ({ ...r, hosts_n: r.hosts.size, hosts: undefined }))
      .sort((a, b) => b.hosts_n - a.hosts_n || (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || b.signals_n - a.signals_n),
    telemetry: [...telemetry.values()].sort(byTelemetryOrder),
    sources: hosts.length === 1 ? hosts[0].sources : [...sources.values()].sort((a, b) => a.label.localeCompare(b.label)),
    freshness: freshness(hosts, now),
    oldest_collection: started[0] || '', newest_collection: started[started.length - 1] || '',    modules: [...new Set(hosts.flatMap((x) => x.modules.map((m) => m.name)))].sort(),
  };
}

module.exports = { fleetBase, withTriage, collections, hostInventory, fleetDashboard, sourceState, riskOf };
