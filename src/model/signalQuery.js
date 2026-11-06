// The Signals page's query, done on the server: which signals are in scope
// (every host's latest collection, or one run), the filter options that
// scope offers, the summary of what the filters keep, and the list -
// filtered, sorted and paged, or split into groups. The browser receives one page of rows at a time,
// however many signals the fleet has.
'use strict';

const { filterRequest } = require('../../public/js/columnFilter.js');

const { SEVERITY_RANK, severityCounts } = require('./signals');
const { sortRows, page } = require('./inventories');

const NO_TACTIC = 'No ATT&CK mapping';
const tacticKeys = (s) => (s.tactics.length ? s.tactics : [NO_TACTIC]);

// SHOW is the "Show" filter: which signals, by suppression and collection.
const SHOW = {
  '': (s) => !s.suppressed_by,
  new: (s) => !s.suppressed_by && s.is_new,
  rare: (s) => !s.suppressed_by && s.fleet_n === 1,
  suppressed: (s) => Boolean(s.suppressed_by),
  all: () => true,
};

// evidenceKey is the evidence a signal is built on, as the Evidence filter
// and grouping name it: its evidence type's label; a state of the host (a
// finding with no event behind it); or "source not recorded" for a run
// written before Signal recorded sources.
const HOST_STATE = 'state of the host (no event)';
const NOT_RECORDED = 'source not recorded';
const evidenceKey = (s) => s.evidence || (s.kind === 'state' ? HOST_STATE : NOT_RECORDED);

// GROUPS name the group(s) a signal is in, per "Group by" choice.
const GROUPS = {
  rule: (s) => [s.rule_id],
  host: (s) => [s.run_id],
  severity: (s) => [s.severity],
  triage: (s) => [s.triage],
  module: (s) => [s.module],
  tactic: tacticKeys,
  evidence: (s) => [evidenceKey(s)],
  entity: (s) => [`${s.entity_type}: ${s.entity_display}`], // what the signals are about
};

const list = (v) => (v === undefined || v === null || v === '' ? null : new Set(String(v).split(',')));

// mentionsAccount reports whether a signal is about an account: its line or
// one of its event's fields is one of its names (DOMAIN\name) or its SID -
// compared upper-cased (accounts is a Set of upper-cased names and SIDs).
function mentionsAccount(s, accounts) {
  return [s.entity, ...Object.values(s.fields || {})].some((v) => accounts.has(String(v ?? '').toUpperCase()));
}

// filtered keeps the signals the query's filters allow: modules, severity,
// rule, tactic, triage, evidence and type - what the signal is about -
// (comma-separated; absent = all), show,
// account (the account's names and SID, comma-separated: signals about it -
// see mentionsAccount), sids (signal IDs, comma-separated: an entity's
// signals), and q (text in the title, entity, context, host,
// rule or evidence).
function filtered(rows, q) {
  const f = { modules: list(q.modules), severity: list(q.severity), rule: list(q.rule), tactic: list(q.tactic), triage: list(q.triage), evidence: list(q.evidence), type: list(q.type) };
  const account = q.account ? new Set(String(q.account).split(',').map((a) => a.toUpperCase())) : null;
  const sids = list(q.sids);
  const show = SHOW[q.show || ''] || SHOW[''];
  const text = String(q.q || '').toLowerCase();
  return rows.filter((s) => (!f.modules || f.modules.has(s.module)) && (!f.severity || f.severity.has(s.severity))
    && (!f.rule || f.rule.has(s.rule_id)) && (!f.tactic || tacticKeys(s).some((t) => f.tactic.has(t))) && (!f.triage || f.triage.has(s.triage))
    && (!f.evidence || f.evidence.has(evidenceKey(s))) && (!f.type || f.type.has(s.entity_type)) && (!account || mentionsAccount(s, account)) && (!sids || sids.has(s.sid))
    && show(s) && (!text || [s.title, s.entity, s.context, s.host, s.rule_id, evidenceKey(s)].join('\n').toLowerCase().includes(text)));
}

// options are the filter choices a scope offers.
function options(rows) {
  return {
    modules: [...new Set(rows.map((s) => s.module))].sort(),
    rules: [...new Set(rows.map((s) => s.rule_id))].sort(),
    tactics: [...new Set(rows.flatMap(tacticKeys))],
    evidence: [...new Set(rows.map(evidenceKey))].sort(),
    types: [...new Set(rows.map((s) => s.entity_type))].sort(),
  };
}

// summary is the numbers the filters keep: by severity, untriaged signals,
// signals seen on one host only, hosts, rules and modules.
function summary(rows) {
  return {
    by_severity: severityCounts(rows),
    untriaged: rows.filter((s) => s.triage === 'new').length,
    rare: rows.filter((s) => s.fleet_n === 1).length,
    hosts: new Set(rows.map((s) => s.run_id)).size,
    rules: new Set(rows.map((s) => s.rule_id)).size,
    modules: [...new Set(rows.map((s) => s.module))].sort(),
    suppressed_by: [...new Set(rows.filter((s) => s.suppressed_by).map((s) => s.module))],
  };
}

// groups splits rows by the group key; each group has its key, size, most
// severe signal, host and rule counts, and what its header shows (a rule's
// title, a host's name and meta).
function groups(rows, by) {
  const keysOf = GROUPS[by];
  const out = new Map();
  for (const s of rows) {
    for (const k of keysOf(s)) {
      if (!out.has(k)) out.set(k, { key: k, rows: [] });
      out.get(k).rows.push(s);
    }
  }
  return [...out.values()].map(({ key, rows: rs }) => ({
    key, n: rs.length,
    top_severity: rs.reduce((a, b) => ((SEVERITY_RANK[b.severity] ?? 9) < (SEVERITY_RANK[a.severity] ?? 9) ? b : a)).severity,
    hosts_n: new Set(rs.map((r) => r.run_id)).size, rules_n: new Set(rs.map((r) => r.rule_id)).size,
    title: by === 'rule' ? rs[0].title : '', host: by === 'host' ? { run_id: rs[0].run_id, host: rs[0].host, os: rs[0].os, os_build: rs[0].os_build, role: rs[0].role } : null,
  })).sort((a, b) => b.n - a.n);
}

// query answers the Signals page's list: with q.group and no q.key, its
// groups; otherwise its rows (of group q.key when grouped), sorted by
// q.sort/q.dir (default: most severe, then newest) and paged by
// q.offset/q.limit.
function query(rows, q) {
  const asked = filterRequest(filtered(rows, q), q);
  if (asked.distinct) return asked;
  let out = asked.rows;
  if (q.group && GROUPS[q.group]) {
    if (q.key === undefined) return { groups: groups(out, q.group) };
    out = out.filter((s) => GROUPS[q.group](s).includes(q.key));
  }
  return page(q.sort ? sortRows(out, q.sort, q.dir) : out, q);
}

module.exports = { query, filtered, options, summary, mentionsAccount, GROUPS, SHOW, NO_TACTIC };
