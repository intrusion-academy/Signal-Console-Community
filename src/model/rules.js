// The rule catalog (the Rules page): every rule any run's modules carry,
// with its outcome on every run.
'use strict';

const { hostMeta } = require('./hosts');
const { SEVERITY_RANK } = require('./signals');

// Per-host rule outcomes. The first three are Signal's own
// (core.RuleFlagged/RuleClear/RuleNotRun); the reason codes below them are
// Signal's (core.Reason*) plus the ones only visible across runs, which
// this file adds itself.
const RULE_STATUSES = ['flagged', 'clear', 'not_run'];
const REASON_LABELS = {
  dependency_off: 'dependency not met',
  dependency_unknown: 'dependency undetermined',
  facts_unavailable: 'data not collected',
  source_not_read: 'log not read',
  module_not_run: 'module not run',
  module_failed: 'module failed',
  rule_not_in_version: 'rule not in this version',
  rule_not_loaded: 'rule file not given to the run',
  rule_excluded: 'rule excluded from the run',
  partial: 'partially evaluated',
};

// REASON_GROUPS sorts every not-run reason into one of three causes, which
// the Rules page shows as one count column each: the rule's data or policy
// was not available (dependency), the module itself did not run (module),
// or the rule itself was left out (rule). Every reason belongs to exactly
// one group, so the three always add up to "not evaluated".
const REASON_GROUPS = {
  dependency_off: 'dependency', dependency_unknown: 'dependency', facts_unavailable: 'dependency', source_not_read: 'dependency',
  module_not_run: 'module', module_failed: 'module',
  rule_not_in_version: 'rule', rule_not_loaded: 'rule', rule_excluded: 'rule',
};

// BUILT_IN is the origin of a rule shipped inside Signal (a module's own);
// any other origin is the rule file it was imported from with -rules
// (Signal schema 8).
const BUILT_IN = 'built-in';
const originKind = (origin) => (!origin || origin === BUILT_IN ? 'built-in' : 'imported');

// hostStatus decides one rule's outcome on one run. A run from Signal
// schema 3 or later states it directly on its catalog entry; for an older
// run it is derived the same way Signal now decides it: a finding with the
// rule's ID means flagged; otherwise a dependency fact that is false or
// absent means not run; otherwise clear.
function hostStatus(entry, result, finding) {
  if (entry.status) return { status: entry.status, reason_code: entry.reason_code || '', reason: entry.reason || '' };
  if (finding) return { status: 'flagged', reason_code: '', reason: '' };
  const facts = result.dependency_facts || {};
  const off = (entry.depends_on || []).filter((d) => facts[d] === false);
  const unknown = (entry.depends_on || []).filter((d) => !(d in facts));
  if (off.length) return { status: 'not_run', reason_code: 'dependency_off', reason: `needs ${off.join(', ')}, which is off on this host` };
  if (unknown.length) return { status: 'not_run', reason_code: 'dependency_unknown', reason: `needs ${unknown.join(', ')}, which could not be determined on this host` };
  return { status: 'clear', reason_code: '', reason: '' };
}

// byRuleOrder is the catalog's order: by severity, then by ID.
const byRuleOrder = (a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || a.id.localeCompare(b.id);

// ruleCatalog builds the full reference of every rule any run's modules
// carry, as one severity-ordered list deduplicated by rule ID (a rule is
// identified by its ID alone; the definition shown is the newest run's),
// with the rule's outcome on every run - flagged (with the finding's own
// expanded text and match count), clear, or not_run with a reason_code and
// reason, including the reasons only visible across runs: the module was
// never run on that host (module_not_run), it was skipped or failed there
// (module_failed), that host's Signal version does not have the rule
// (rule_not_in_version), or - for a rule imported from a rule file - that
// host's run was not given the file (rule_not_loaded) - and the same
// counted in summary. Each rule says where it came from: origin_kind
// "built-in" (shipped with its module) or "imported" (a -rules file, named
// by origin and rule_files).
function ruleCatalog(runs) {
  const newestFirst = runs.slice().sort((a, b) => String(b.started || '').localeCompare(String(a.started || '')));
  const defs = new Map(); // rule_id -> definition (+ module)
  for (const run of newestFirst) {
    for (const [moduleName, result] of Object.entries(run.modules || {})) {
      for (const rule of result.rule_catalog || []) {
        if (defs.has(rule.id)) continue;
        defs.set(rule.id, {
          id: rule.id, module: moduleName, severity: rule.severity, title: rule.title, detail: rule.detail,
          impact: rule.impact || '', focus: rule.focus || '', condition: rule.condition, tags: rule.tags || [], attack: rule.attack || [],
          detection: rule.detection || null, depends_on: rule.depends_on || [], hash: rule.hash || '',
          evidence: rule.evidence || [], origin: rule.origin || '', // schema 8: what it reads, and built-in or which rule file
          origin_kind: originKind(rule.origin),
          // What each field means, and how Signal derives it: the names on
          // the entry, their text once per run (schema 63).
          fields: Object.fromEntries((rule.fields || []).map((f) => [f, (run.field_docs || {})[f] || {}])),
        });
      }
    }
  }

  const hostList = runs.map((run) => ({ run_id: run.run_id, ...hostMeta(run) }));
  const rules = [];
  for (const def of defs.values()) {
    const hosts = [];
    for (const run of runs) {
      const base = { run_id: run.run_id, ...hostMeta(run) };
      const result = (run.modules || {})[def.module];
      if (!result) {
        hosts.push({ ...base, status: 'not_run', reason_code: 'module_not_run', reason: `the ${def.module} module was not run on this host` });
        continue;
      }
      const entry = (result.rule_catalog || []).find((r) => r.id === def.id);
      if (!entry) {
        const failed = result.status === 'skipped' || result.status === 'failed' || !(result.rule_catalog || []).length;
        let row = { ...base, status: 'not_run', reason_code: 'rule_not_in_version', reason: `this host's Signal version (${run.tool_version || 'unknown'}) does not include this rule` };
        if (failed) row = { ...base, status: 'not_run', reason_code: 'module_failed', reason: `the ${def.module} module ${result.status || 'did not complete'} on this host${(result.errors || []).length ? ': ' + result.errors.join('; ') : ''}` };
        else if (def.origin_kind === 'imported') row = { ...base, status: 'not_run', reason_code: 'rule_not_loaded', reason: `this host's run was not given the rule file ${def.origin} (-rules)` };
        hosts.push(row);
        continue;
      }
      const finding = (result.findings || []).find((f) => f.rule_id === def.id);
      const row = { ...base, ...hostStatus(entry, result, finding), hash: entry.hash || '', origin: entry.origin || '' };
      if (finding) {
        row.title = finding.title;
        row.detail = finding.detail || '';
        row.impact = finding.impact || '';
        row.focus = finding.focus || '';
        if (finding.evidence && typeof finding.evidence.count === 'number') row.count = finding.evidence.count;
      }
      hosts.push(row);
    }

    const summary = { total: hosts.length, ran: 0, flagged: 0, clear: 0, not_run: 0, not_run_reasons: {} };
    for (const hs of hosts) {
      summary[hs.status]++;
      if (hs.status !== 'not_run') summary.ran++;
      else summary.not_run_reasons[hs.reason_code] = (summary.not_run_reasons[hs.reason_code] || 0) + 1;
    }
    // versions counts the distinct definitions of the rule across the runs
    // (Signal's catalog hash): more than one means hosts ran different rules.
    const versions = new Set(hosts.map((x) => x.hash).filter(Boolean)).size;
    // rule_files lists every rule file a host loaded this rule from (an
    // imported rule may come from differently named files on different hosts).
    const ruleFiles = [...new Set(hosts.map((x) => x.origin).filter((o) => o && o !== BUILT_IN))].sort();
    rules.push({ ...def, hosts, summary, versions, rule_files: ruleFiles });
  }
  rules.sort(byRuleOrder);
  return { hosts: hostList, rules, reason_labels: REASON_LABELS, reason_groups: REASON_GROUPS };
}

module.exports = { ruleCatalog, byRuleOrder, RULE_STATUSES, REASON_LABELS, REASON_GROUPS };
