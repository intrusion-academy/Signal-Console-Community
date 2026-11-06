// The console's own rules (module "Console"): checks the console makes
// over the imported runs with data of its own - not Signal's rules. Each
// is in the rule catalog (the Rules page) and on the ATT&CK matrix like a
// Signal rule, with its outcome on every host: flagged, clear, or not run
// with the reason. Computed on each request, beside the cached catalog of
// Signal's rules, since what decides them (CISA's catalog, NVD's answers)
// changes without a run changing.
'use strict';

const MATRIX = require('./data/attack.json');
const { hostMeta } = require('./model/hosts');
const { byRuleOrder } = require('./model/rules');
const kev = require('./kev');
const applications = require('./applications');

const MODULE = 'Console';

// attackOf is an ATT&CK technique as a rule's attack entry (Signal's
// shape).
function attackOf(id) {
  const t = MATRIX.techniques.find((x) => x.id === id);
  return { id, tactic: t.tactics[0], technique: t.name, sub_technique: '', label: `${t.tactics[0]}:${t.name}` };
}

// RULES are the console's rules: Signal's definition fields, and
// outcomes(runs) - each run's outcome.
const RULES = [{
  id: kev.RULE, severity: 'medium', // a state of the host, not an act: medium at most (Signal's rules documentation, Severity)
  title: 'An installed version is affected by a known exploited vulnerability',
  detail: "An installed application's version is in the affected versions NIST's NVD gives for a CVE that CISA's Known Exploited Vulnerabilities catalog lists for its product (matched by name and publisher). The Applications page's Known exploited (CISA) column names each CVE and what it is.",
  impact: 'Attackers are known to exploit this vulnerability in the wild: the application is a way in, a way to run code or to gain privileges on this host. It flags the exposure, not an exploitation.',
  focus: "Check the version on the host and the CVE's advisory; update or remove the application. Look for its exploitation around the host's signals - a process it started, a download it opened, a crash or an unusual child process - and whether it is installed on other hosts (the Applications page stacks the fleet).",
  condition: "an installed version in NVD's affected versions of a CVE in CISA's KEV catalog for the product",
  tags: ['T1190', 'T1203', 'T1068', 'T1210'],
  outcomes(runs) {
    const ready = kev.status().loaded;
    const flagged = new Map();
    if (ready) {
      for (const f of applications.consoleFlags(runs)) for (const id of f.run_ids) flagged.set(id, [...(flagged.get(id) || []), f.label]);
    }
    return runs.map((run) => {
      if (!(run.modules || {}).Applications) return { status: 'not_run', reason_code: 'module_not_run', reason: 'the Applications module was not run on this host' };
      if (!ready) return { status: 'not_run', reason_code: 'facts_unavailable', reason: "CISA's Known Exploited Vulnerabilities catalog is not loaded in this console (Settings, Known exploited vulnerabilities)" };
      const apps = flagged.get(run.run_id);
      return apps ? { status: 'flagged', reason_code: '', reason: '', detail: `Affected: ${apps.join('; ')}.`, count: apps.length } : { status: 'clear', reason_code: '', reason: '' };
    });
  },
}];

// catalogOf is the console's rules as entries of model/rules.js's
// ruleCatalog over runs.
function catalogOf(runs) {
  return RULES.map(({ outcomes, ...def }) => {
    const hosts = outcomes(runs).map((o, i) => ({ run_id: runs[i].run_id, ...hostMeta(runs[i]), hash: '', origin: 'console', ...o }));
    const summary = { total: hosts.length, ran: 0, flagged: 0, clear: 0, not_run: 0, not_run_reasons: {} };
    for (const h of hosts) {
      summary[h.status]++;
      if (h.status !== 'not_run') summary.ran++;
      else summary.not_run_reasons[h.reason_code] = (summary.not_run_reasons[h.reason_code] || 0) + 1;
    }
    return {
      ...def, module: MODULE, attack: def.tags.map(attackOf), detection: null, depends_on: [], hash: '', evidence: [], origin: 'console', origin_kind: 'console', fields: {},
      hosts, summary, versions: 0, rule_files: [],
    };
  });
}

// withConsole is a cached rule catalog with the console's rules added, in
// the catalog's order like any other rule.
function withConsole(catalog, runs) {
  return { ...catalog, rules: [...catalog.rules, ...catalogOf(runs)].sort(byRuleOrder) };
}

module.exports = { withConsole, MODULE };
