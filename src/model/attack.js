// The ATT&CK coverage matrix (Overview): ATT&CK Enterprise's Windows
// matrix - src/data/attack.json, built from
// MITRE's published bundle, never fetched at run time - with, per technique,
// the rules mapped to it that were evaluated on the hosts in view. A
// sub-technique's rules count toward its parent too.
'use strict';

const MATRIX = require('../data/attack.json');
const { REASON_LABELS } = require('./rules');

const EVALUATED = new Set(['flagged', 'clear']);

// attackMatrix places the rule catalog (model/rules.js ruleCatalog) on the
// matrix over the hosts with the given run IDs (every host in the catalog
// when none is given). For each technique: count - its rules evaluated (on
// the one host; with several, on at least one of them); hosts_covered - the
// hosts on which at least one was evaluated; not_evaluated - each of its
// rules not evaluated on some host, with on how many and why.
function attackMatrix(catalog, runIds = []) {
  const wanted = new Set(runIds.length ? runIds : catalog.hosts.map((h) => h.run_id));
  const ruleHosts = catalog.rules.map((r) => ({ rule: r, hosts: r.hosts.filter((h) => wanted.has(h.run_id)), ids: (r.attack || []).map((a) => a.id) }));

  const cell = (t) => {
    const mapped = ruleHosts.filter((x) => x.ids.some((id) => id === t.id || id.startsWith(`${t.id}.`)));
    const covered = new Set();
    const rules = [];
    const notEvaluated = [];
    for (const { rule, hosts } of mapped) {
      const ran = hosts.filter((h) => EVALUATED.has(h.status));
      ran.forEach((h) => covered.add(h.run_id));
      if (ran.length) rules.push(rule.id);
      const missed = hosts.filter((h) => !EVALUATED.has(h.status));
      if (!missed.length) continue;
      const reasons = {};
      for (const h of missed) reasons[h.reason_code] = (reasons[h.reason_code] || 0) + 1;
      notEvaluated.push({
        rule: rule.id, title: rule.title, hosts: missed.length,
        reasons: Object.entries(reasons).map(([code, n]) => ({ label: REASON_LABELS[code] || code, hosts: n })),
        reason: missed.length === 1 ? missed[0].reason : '',
      });
    }
    return { id: t.id, name: t.name, out_of_scope: t.out_of_scope || '', count: rules.length, rules, hosts_covered: covered.size, not_evaluated: notEvaluated };
  };

  const subsOf = new Map();
  for (const t of MATRIX.techniques) {
    const [parent, sub] = t.id.split('.');
    if (sub) subsOf.set(parent, [...(subsOf.get(parent) || []), t]);
  }
  const byName = (a, b) => a.name.localeCompare(b.name);
  const tactics = MATRIX.tactics.map((tactic) => ({
    id: tactic.id, name: tactic.name, out_of_scope: tactic.out_of_scope || '',
    techniques: MATRIX.techniques.filter((t) => !t.id.includes('.') && t.tactics.includes(tactic.name)).sort(byName)
      .map((t) => ({ ...cell(t), subs: (subsOf.get(t.id) || []).filter((s) => s.tactics.includes(tactic.name)).sort(byName).map(cell) })),
  }));
  return { version: MATRIX.version, modified: MATRIX.modified, hosts: wanted.size, tactics };
}

module.exports = { attackMatrix };
