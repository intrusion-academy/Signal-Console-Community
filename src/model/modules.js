// Modules (the Modules page): every module any host ran, across the fleet
// (each host's latest collection) - what it is (as Signal describes it:
// result.about, schema 10), how it ran on each host, the evidence it read
// and that evidence's health, the rules it carries (built-in or from a rule
// file) and their outcomes, its open signals, its KPIs that call for a look
// and its telemetry. Nothing here knows a module by name: a module Signal
// adds tomorrow appears with no change.
'use strict';

const { hostMeta } = require('./hosts');
const { isOpen } = require('./triage');
const { severityCounts } = require('./signals');

const STATUSES = ['ok', 'partial', 'failed', 'skipped'];

// tally counts values into an object, every key given present.
function tally(keys, values) {
  const out = Object.fromEntries(keys.map((k) => [k, 0]));
  for (const v of values) out[v] = (out[v] || 0) + 1;
  return out;
}

// moduleHost is one module on one host: its version and status, how long
// it took, its gaps and errors, its warning cards and its open signals.
function moduleHost(run, r, signals) {
  const warnings = (r.kpis || []).filter((k) => k.status === 'warn' || k.status === 'bad');
  return {
    run_id: run.run_id, ...hostMeta(run), tool_version: run.tool_version || '',
    version: r.version || '', status: r.status || 'ok', duration_ms: r.duration_ms ?? null,
    gaps: (r.coverage_gaps || []).map((g) => `${g.item}: ${g.reason}`), errors: r.errors || [],
    gaps_n: (r.coverage_gaps || []).length + (r.errors || []).length,
    warnings: warnings.map((k) => k.label), warnings_n: warnings.length,
    signals_n: signals.length,
  };
}

// moduleInventory is one entry per module (by name, sorted). runs are the
// hosts' latest collections; signalsOf(run_id) a run's signals (triaged);
// catalog the rule catalog (model/rules.js), for the module's rules.
function moduleInventory(runs, signalsOf, catalog) {
  const byName = new Map();
  const newestFirst = runs.slice().sort((a, b) => String(b.started || '').localeCompare(String(a.started || '')));
  for (const run of newestFirst) {
    const open = signalsOf(run.run_id).filter(isOpen);
    const sources = new Map((run.sources || []).map((s) => [s.evidence, s]));
    for (const [name, r] of Object.entries(run.modules || {})) {
      if (!byName.has(name)) byName.set(name, { name, about: null, hosts: [], evidence: new Map(), telemetry: new Map(), kpis: new Map(), signals: [] });
      const m = byName.get(name);
      if (!m.about && r.about) m.about = r.about; // the newest run's description
      const mine = open.filter((s) => s.module === name);
      m.signals.push(...mine);
      m.hosts.push(moduleHost(run, r, mine));
      for (const e of (r.about && r.about.evidence) || []) {
        const s = sources.get(e);
        if (!m.evidence.has(e)) m.evidence.set(e, { evidence: e, label: (s && s.label) || e, kind: (s && s.kind) || '', provider: (s && s.provider) || '', statuses: [] });
        m.evidence.get(e).statuses.push(s ? s.status : 'not recorded');
      }
      for (const t of r.telemetry || []) {
        if (!m.telemetry.has(t.id)) m.telemetry.set(t.id, { id: t.id, label: t.label, states: [] });
        m.telemetry.get(t.id).states.push(t.state);
      }
      for (const k of r.kpis || []) {
        if (!m.kpis.has(k.id)) m.kpis.set(k.id, { id: k.id, label: k.label, statuses: [] });
        m.kpis.get(k.id).statuses.push(k.status || '');
      }
    }
  }
  const rulesOf = (name) => catalog.rules.filter((r) => r.module === name);
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name)).map((m) => {
    const rules = rulesOf(m.name);
    const imported = rules.filter((r) => r.origin && r.origin !== 'built-in');
    const durations = m.hosts.map((x) => x.duration_ms).filter((d) => typeof d === 'number');
    const statuses = tally(STATUSES, m.hosts.map((x) => x.status));
    const about = m.about || {};
    return {
      name: m.name, about: m.about, description: about.description || '', category: about.category || '',
      rule_prefix: about.rule_prefix || '', needs_admin: about.needs_admin ?? null, attack: about.attack || [], tags: about.tags || [],
      versions: [...new Set(m.hosts.map((x) => x.version).filter(Boolean))].sort().join(', '),
      hosts: m.hosts.sort((a, b) => a.host.localeCompare(b.host)),
      hosts_n: m.hosts.length, not_run_n: runs.length - m.hosts.length,
      statuses, ok_n: statuses.ok, problem_n: statuses.partial + statuses.failed + statuses.skipped,
      duration_avg_ms: durations.length ? Math.round(durations.reduce((n, d) => n + d, 0) / durations.length) : null,
      duration_max_ms: durations.length ? Math.max(...durations) : null,
      evidence: [...m.evidence.values()].map((e) => ({ ...e, statuses: tally(['read', 'partial', 'not_read', 'unavailable'], e.statuses) })),
      evidence_names: [...m.evidence.values()].map((e) => e.label).join('; '),
      telemetry: [...m.telemetry.values()].map((t) => ({ id: t.id, label: t.label, ...tally(['on', 'off', 'unknown'], t.states) })),
      kpis: [...m.kpis.values()].map((k) => ({ id: k.id, label: k.label, warn_n: k.statuses.filter((s) => s === 'warn' || s === 'bad').length, hosts_n: k.statuses.length })),
      warnings_n: m.hosts.reduce((n, x) => n + x.warnings_n, 0),
      rules_n: rules.length, builtin_n: rules.length - imported.length, imported_n: imported.length,
      rule_files: [...new Set(imported.map((r) => r.origin))].sort(),
      rules_flagged_n: rules.filter((r) => r.summary.flagged > 0).length,
      signals_n: m.signals.length, by_severity: severityCounts(m.signals),
    };
  });
}

module.exports = { moduleInventory };
