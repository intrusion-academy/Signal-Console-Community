// Compromise assessment reports (the Reports page): what the hosts'
// findings and the analysts' triage notes say, as a document - built here
// as a list of blocks (title, heading, paragraph, key-values, table) that
// src/documents.js writes as Word or PDF. The report states only what the
// analysts decided and what is still open; it never concludes a host is
// clean on its own - an untriaged signal or an unreviewed inventory is
// listed as open work, and the report's readiness says so on its cover.
'use strict';

const cache = require('./cache');
const store = require('./store');
const triage = require('./triageStore');
const reviews = require('./reviews');
const db = require('./db');
const flags = require('./flags');
const license = require('./license');
const applications = require('./applications');
const { isOpen } = require('./model/triage');
const { hostMeta } = require('./model/hosts');

// PAGE_LABELS name the reviewed data pages as the navigation does.
const PAGE_LABELS = {
  autoruns: 'Autoruns', applications: 'Applications', extensions: 'Extensions', grouppolicy: 'Group Policy', remoteaccess: 'Remote Access',
  webservers: 'Web Servers', network: 'Network', topology: 'Topology', protection: 'Protection', recovery: 'Recovery', audit: 'Audit Policy',
};
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

// decisionKey is the triage record a signal's state comes from: its
// entity's, or its own.
const decisionKey = (s) => (s.triaged_via === 'entity' ? s.eid : s.sid);

// byDecision groups signals into one row per triage record (an untriaged
// signal by its entity): host, entity, rules, worst severity, how many
// signals, and the decision with its note.
function byDecision(signals, keyOf) {
  const groups = new Map();
  for (const s of signals) {
    const k = keyOf(s);
    let g = groups.get(k);
    if (!g) {
      g = { host: s.host, entity: s.entity_display || s.host, entity_type: s.entity_type || 'host', rules: new Set(), titles: new Set(), severity: s.severity, signals: 0, state: s.triage, note: s.note, by: s.triaged_by, at: s.triaged_at };
      groups.set(k, g);
    }
    g.rules.add(s.rule_id);
    g.titles.add(s.title);
    g.signals++;
    if (SEVERITIES.indexOf(s.severity) < SEVERITIES.indexOf(g.severity)) g.severity = s.severity;
  }
  return [...groups.values()]
    .map((g) => ({ ...g, rules: [...g.rules].filter(Boolean).join(', '), titles: [...g.titles].join('; ') }))
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.host.localeCompare(b.host) || a.entity.localeCompare(b.entity));
}

// readiness is what stands between the runs and a complete report: open
// signals no analyst has triaged, and data pages not reviewed on every host
// with something on them.
function readiness() {
  const runs = cache.latest();
  const signals = cache.scopeSignals('');
  const untriaged = signals.filter((s) => isOpen(s) && s.triage === 'new');
  const status = reviews.status(runs);
  const unreviewed = Object.entries(status).filter(([, s]) => s.state === 'not_reviewed')
    .map(([page, s]) => ({ page, label: PAGE_LABELS[page] || page, hosts: s.hosts, reviewed: s.reviewed }));
  return {
    hosts: runs.length,
    signals: signals.length,
    untriaged: untriaged.length,
    untriaged_entities: new Set(untriaged.map((s) => s.eid || s.sid)).size,
    escalated: signals.filter((s) => isOpen(s) && s.triage === 'escalated').length,
    unreviewed,
    ready: runs.length > 0 && untriaged.length === 0 && unreviewed.length === 0,
  };
}

// notes is every triage note any analyst wrote on these runs - each change of
// a decision, newest first - with what it is about (host, entity, rules) as
// the imported runs name it; and every analyst's flag with its reason
// (state "flagged").
function notes() {
  const flagNotes = flags.list().filter((f) => f.reason).map((f) => ({
    id: `flag:${f.kind}:${f.key}`, at: f.at, by: f.flagged_by, state: 'flagged', note: f.reason,
    host: '', run_id: '', entity_id: '', entity: `${f.label} (${f.where})`, rules: '', kind: 'flag', covers_n: 0,
  }));
  return [...triageNotes(), ...flagNotes].sort((a, b) => String(b.at).localeCompare(String(a.at)));
}

// triageNotes is the triage history's notes.
function triageNotes() {
  const about = new Map();
  const c = cache.collections();
  for (const run of store.all()) {
    for (const s of c.signalsOf(run.run_id)) {
      for (const [key, entity] of [[s.sid, s.entity_display || s.host], [s.eid, s.entity_display || s.host]]) {
        if (!key) continue;
        let a = about.get(key);
        if (!a) about.set(key, a = { host: s.host, run_id: run.run_id, entity_id: s.entity_id, entity, rules: new Set() });
        a.rules.add(s.rule_id);
      }
    }
  }
  return db.open().prepare('SELECT id, sid, state, note, at, decided_by, covers FROM triage_history ORDER BY at DESC, id DESC').all().map((r) => {
    const a = about.get(r.sid);
    return {
      id: r.id, at: r.at, by: r.decided_by || '', state: r.state, note: r.note,
      host: a ? a.host : '', run_id: a ? a.run_id : '', entity_id: a ? a.entity_id : '', entity: a ? a.entity : '(no longer in an imported run)', rules: a ? [...a.rules].filter(Boolean).join(', ') : '',
      kind: r.covers ? 'entity' : 'signal', covers_n: r.covers ? JSON.parse(r.covers).length : 1,
    };
  });
}

const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

// build is the report's blocks: who generated it and when, the analyst's
// summary, and the findings by decision.
function build({ user, summary }) {
  const runs = cache.latest();
  const signals = cache.scopeSignals('');
  const r = readiness();
  const ed = license.status();
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z').replace('T', ' ').replace('Z', ' UTC');
  const utc = (s) => (s ? String(s).replace(/\.\d+/, '').replace('T', ' ').replace(/Z$|\+00:00$/, ' UTC') : '');
  const starts = runs.map((x) => x.started).filter(Boolean).sort();
  const decided = signals.filter((s) => s.triage !== 'new' && !s.suppressed_by);
  const of = (state) => byDecision(decided.filter((s) => s.triage === state), decisionKey);
  const escalated = of('escalated');
  const reviewed = of('reviewed');
  const benign = of('benign');
  const open = byDecision(signals.filter((s) => isOpen(s) && s.triage === 'new'), (s) => s.eid || s.sid);
  const suppressed = signals.filter((s) => s.suppressed_by);
  const rules = triage.get().suppressions;
  const count = (rows) => rows.reduce((n, g) => n + g.signals, 0);

  const blocks = [
    { t: 'title', text: 'Compromise Assessment Report' },
    { t: 'kv', rows: [
      ['Generated', `${now} by ${user}`],
      ['Hosts assessed', String(runs.length)],
      ['Collections', starts.length ? `${utc(starts[0])} to ${utc(starts[starts.length - 1])} (each host's latest)` : '—'],
      ['Signal Console', ed.customer ? `${ed.label}, licensed to ${ed.customer}` : `${ed.label} - ${license.NAME}`],
    ] },
  ];
  if (!ed.customer) blocks.push({ t: 'p', text: "Made with the Community edition of Signal and Signal Console (Intrusion Academy), licensed only to defend the user's own organisation's computers and networks. A report prepared as a service to a third party requires a commercial license (Signal Pro or Signal Enterprise) from Intrusion Academy." });
  if (!r.ready) {
    const items = [];
    if (r.untriaged) items.push(`${plural(r.untriaged, 'open signal')} (${plural(r.untriaged_entities, 'entity', 'entities')}) not triaged`);
    if (r.unreviewed.length) items.push(`${plural(r.unreviewed.length, 'data page')} not reviewed on every host (${r.unreviewed.map((u) => u.label).join(', ')})`);
    blocks.push({ t: 'warn', text: `Incomplete assessment: ${items.join('; ')}. The conclusions below cover only what analysts triaged and reviewed; the open items are listed in sections 4 and 6.` });
  }
  blocks.push(
    { t: 'h', text: '1. Analyst summary' },
    { t: 'p', text: String(summary || '').trim() || 'No summary was written for this report.' },
    { t: 'h', text: '2. Findings at a glance' },
    { t: 'p', text: 'Every signal is a rule that matched on a host. Analysts triage what a signal is about (its entity) as escalated (needs action) or benign (explained), with a note saying why; a suppression rule hides signals judged not worth attention across the hosts.' },
    { t: 'table', head: ['Decision', 'Entities', 'Signals'], widths: [3, 1, 1], rows: [
      ['Escalated', escalated.length, count(escalated)],
      ['Benign', benign.length, count(benign)],
      ...(reviewed.length ? [['Reviewed (before console 0.16.0)', reviewed.length, count(reviewed)]] : []),
      ['Open - not triaged', open.length, count(open)],
      ['Suppressed by a rule', '—', suppressed.length],
    ] },
    { t: 'table', head: ['Severity', 'Open signals', 'Escalated signals'], widths: [3, 1, 1], rows: SEVERITIES.map((sev) => [
      sev, signals.filter((s) => isOpen(s) && s.severity === sev).length, signals.filter((s) => isOpen(s) && s.triage === 'escalated' && s.severity === sev).length,
    ]) },
    { t: 'h', text: '3. Escalated findings' },
  );
  const decisionTable = (rows) => ({ t: 'table', head: ['Severity', 'Host', 'Entity', 'Finding', 'Analyst note', 'Decided'], widths: [1.1, 1.4, 2, 2.6, 3.4, 1.6],
    rows: rows.map((g) => [g.severity, g.host, `${g.entity} (${g.entity_type})`, `${g.titles}${g.rules ? ` [${g.rules}]` : ''} - ${plural(g.signals, 'signal')}`, g.note, `${g.by || '—'}, ${utc(g.at)}`]) });
  blocks.push(escalated.length ? decisionTable(escalated) : { t: 'p', text: 'No finding was escalated.' });
  const flagged = [...flags.list(), ...applications.consoleFlags(runs)];
  blocks.push({ t: 'h', text: '3a. Flagged items' },
    { t: 'p', text: "Inventory rows and entities an analyst flagged, with the analyst's reason, and applications the console flagged by a console rule - an installed version is in the affected versions NIST's NVD gives for a CVE CISA's Known Exploited Vulnerabilities catalog lists for their product." });
  blocks.push(flagged.length ? { t: 'table', head: ['Item', 'Where', 'Flagged by', 'Reason'], widths: [2.4, 1.6, 1.6, 4.4],
    rows: flagged.map((f) => [f.label, f.where, f.source === 'console' ? `Console (${f.rule})` : `${f.flagged_by || '—'}, ${utc(f.at)}`, f.reason || '—']) } : { t: 'p', text: 'Nothing is flagged.' });
  blocks.push({ t: 'h', text: '4. Open findings - not triaged' });
  blocks.push(open.length ? { t: 'table', head: ['Severity', 'Host', 'Entity', 'Finding', 'Signals'], widths: [1.1, 1.6, 2.4, 4.5, 0.9],
    rows: open.map((g) => [g.severity, g.host, `${g.entity} (${g.entity_type})`, `${g.titles}${g.rules ? ` [${g.rules}]` : ''}`, g.signals]) } : { t: 'p', text: 'Every open signal is triaged.' });
  blocks.push({ t: 'h', text: '5. Findings judged benign' });
  blocks.push(benign.length ? decisionTable(benign) : { t: 'p', text: 'No finding was triaged benign.' });
  if (reviewed.length) blocks.push({ t: 'h', text: '5a. Findings marked reviewed' }, decisionTable(reviewed));
  blocks.push({ t: 'h', text: '6. Inventory reviews' },
    { t: 'p', text: 'The data pages analysts mark reviewed per host once they have gone through what the host recorded there. A page is listed for the hosts with something on it.' });
  const status = reviews.status(runs);
  const pages = Object.entries(status).filter(([, s]) => s.hosts > 0);
  blocks.push(pages.length ? { t: 'table', head: ['Page', 'Hosts with data', 'Reviewed on', 'State', 'Last reviewed'], widths: [2, 1, 1, 1.2, 2.4],
    rows: pages.map(([page, s]) => [PAGE_LABELS[page] || page, s.hosts, s.reviewed, s.state === 'reviewed' ? 'reviewed' : 'not reviewed', s.at ? `${s.reviewed_by}, ${utc(s.at)}` : '—']) } : { t: 'p', text: 'No host has data on a reviewed page.' });
  blocks.push({ t: 'h', text: '7. Suppression rules' });
  blocks.push(rules.length ? { t: 'table', head: ['Conditions', 'Why (note)', 'Hides', 'Created'], widths: [3, 3.5, 0.8, 1.8],
    rows: rules.map((x) => [x.conditions.map((c) => `${c.field} ${c.op} ${c.value}`).join(' AND '), x.note, suppressed.filter((s) => s.suppressed_by === x.id).length, `${x.created_by || '—'}, ${utc(x.created)}`]) } : { t: 'p', text: 'No suppression rule.' });
  blocks.push({ t: 'h', text: '8. Hosts in scope' },
    { t: 'table', head: ['Host', 'OS', 'Role', 'Collected', 'Open signals'], widths: [1.8, 2.6, 1.2, 2, 1], rows: runs.map((x) => {
      const m = hostMeta(x);
      return [m.host, `${m.os} ${m.os_build}`.trim(), m.role, utc(x.started), signals.filter((s) => s.run_id === x.run_id && isOpen(s)).length];
    }) });
  blocks.push({ t: 'h', text: '9. Limitations' },
    { t: 'p', text: 'This report covers what Signal read on each host at its latest collection and what analysts decided about it in this console. A host can have changed since it was collected. Signals depend on what Windows was set to record (audit policy, logs and their size); evidence Windows did not record cannot appear here, and the absence of a finding is not proof the host was not compromised.' });
  return blocks;
}

module.exports = { readiness, notes, build };
