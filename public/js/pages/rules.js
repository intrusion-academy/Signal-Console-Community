// The Rules page: first the ATT&CK coverage matrix (matrix.js) of the hosts
// the Hosts filter chose; then the tool's full detection scope in one flat list - every
// rule any imported module carries, not only those that fired - with its
// outcome on every imported host (see src/model/rules.js) in count
// columns. A summary strip totals the rules on screen; "group by ATT&CK
// tactic" splits them into one card per tactic with its evaluation
// coverage. Expanding a row shows what the rule detects, why it matters and
// what to do next, with its values filled in; a paged per-host table; and
// the detection logic. The filter bar (module, severity, origin, outcome,
// hosts, grouping) is kept in the URL.
//
// A rule is built-in (shipped with its module) or imported - written for
// this fleet and given to Signal as a rule file (-rules) when it ran. The
// Origin column and filter say which, and the "Rule files" card lists the
// files the hosts loaded, with their rules - or how to write one.

import { h, fetchJSON } from '../dom.js';
import { pageLink, urlParams, setParams, queryString } from '../router.js';
import {
  SEVERITY_RANK, ATTACK_TACTICS, NO_TACTIC, RULE_OUTCOME, outcomeTag, detailBlock, codeBlock, fillTemplate, narrative, attackTags,
  groupedView, hostLabels, filterBar, stickyPage, summaryStrip, checkboxDropdown, selectionFromUrl, section, CORE,
} from '../components.js';
import { dataTable, col, forHosts } from '../table.js';
import { suppressionRules } from './signals.js';
import { attackMatrix } from '../matrix.js';

// ruleLogic lays out a rule's detection logic as a code block: its per-event
// selections (Tier 2) and field matchers, the condition combining them (or
// a Tier-1 rule's aggregate condition), and the policies it depends on.
function ruleLogic(rule) {
  const lines = [];
  if (rule.origin) {
    const where = { 'built-in': '# shipped with Signal', console: "# a console rule - checked by Signal Console over the imported runs, not by Signal" };
    lines.push([[where[rule.origin] || '# loaded from a rule file given with -rules', 'comment']]);
    lines.push([['origin', 'kw'], [': '], [rule.origin, 'val']]);
  }
  if ((rule.evidence || []).length) {
    lines.push([['# the evidence it reads - each signal says which one it came from', 'comment']]);
    lines.push([['evidence', 'kw'], [': '], [rule.evidence.join(', '), 'field']]);
  }
  if (lines.length) lines.push([['']]);
  const selections = Object.entries(rule.detection || {});
  if (selections.length) {
    lines.push([['# detection, evaluated per event', 'comment']]);
    for (const [name, fields] of selections) {
      lines.push([[name, 'sel'], [':']]);
      for (const [field, fm] of Object.entries(fields)) {
        lines.push([['    '], [field, 'field'], [' '], [fm.modifier || 'equals', 'mod'], [' '], ['[' + (fm.values || []).join(', ') + ']', 'val']]);
      }
    }
    lines.push([['']]);
    // What each field is - and, for one Signal computes rather than reads
    // from the record, how - so no rule looks like it waits for Windows to
    // write something it never writes.
    const docs = Object.entries(rule.fields || {});
    if (docs.length) {
      lines.push([['# the fields it reads', 'comment']]);
      for (const [field, d] of docs) {
        lines.push([['#   '], [field, 'field'], [`: ${d.doc || ''}`, 'comment']]);
        if (d.derived) lines.push([['#     '], [`computed, not read: ${d.derived}`, 'comment']]);
      }
      lines.push([['']]);
    }
  }
  lines.push([[selections.length ? '# condition, combining the selections above' : '# condition, evaluated once per run over aggregate facts', 'comment']]);
  lines.push([['condition', 'kw'], [': '], [rule.condition, 'expr']]);
  if ((rule.depends_on || []).length) {
    lines.push([['']]);
    lines.push([['# cannot be evaluated on a host where this is off or undetermined', 'comment']]);
    lines.push([['depends on', 'kw'], [': '], [rule.depends_on.join(', '), 'field']]);
  }
  return codeBlock(lines);
}

// tacticsOf lists the tactics a rule's techniques belong to.
function tacticsOf(rule) {
  return [...new Set((rule.attack || []).flatMap((a) => String(a.tactic || '').split(', ').filter(Boolean)))];
}

// RULE_COLUMNS is the Rules table. Every count column holds a plain number
// (see ruleCounts), so the CSV export classifies directly; the three reason
// columns always add up to "Not evaluated on".
const RULE_COLUMNS = [
  col('severity', 'severity', { desc: 'How urgent a finding from this rule is: critical, high, medium or low.' }),
  col('module', 'module', { desc: 'The Signal module that runs the rule.' }),
  col('origin_kind', 'origin'),
  col('id', 'rule_id', { desc: 'The rule\'s unique ID; its first part names the module.', render: undefined }),
  col('title', 'title', { desc: 'What the rule detects.', render: (v, row) => fillTemplate(v, row.scope, 'title') }),
  col('hosts_n'), col('evaluated_n'), col('not_evaluated_n'), col('dependency_n'), col('module_n'), col('rule_n'), col('flagged_n'),
];

export async function renderRules(container) {
  const catalog = await fetchJSON('/api/rules');
  if (catalog.rules.length === 0) {
    container.replaceChildren(h('div', { class: 'card mut' }, 'No rules to show yet - import at least one run first.'));
    return;
  }
  const reasonLabel = (code) => catalog.reason_labels[code] || code;
  const reasonGroup = (code) => catalog.reason_groups[code] || 'dependency';

  const labelByRun = hostLabels(catalog.hosts);
  const hostLabel = (hst) => labelByRun.get(hst.run_id);

  // Outcome filter options, each with a stable key for the URL: the two
  // "evaluated" outcomes, then one per reason for not being evaluated that
  // actually occurs in this catalog.
  const reasonCodes = [...new Set(catalog.rules.flatMap((r) => r.hosts.filter((x) => x.status === 'not_run').map((x) => x.reason_code)))].sort();
  const OUTCOMES = [
    { key: 'flagged', label: 'Flagged', test: (x) => x.status === 'flagged' },
    { key: 'clear', label: 'Evaluated, not flagged', test: (x) => x.status === 'clear' },
    ...reasonCodes.map((code) => ({ key: `not_run:${code}`, label: `Not evaluated: ${reasonLabel(code)}`, test: (x) => x.status === 'not_run' && x.reason_code === code })),
  ];
  const outcomeLabels = OUTCOMES.map((o) => o.label);
  const outcomeByLabel = new Map(OUTCOMES.map((o) => [o.label, o]));

  const modules = [...new Set(catalog.rules.map((r) => r.module))].sort();
  const severities = Object.keys(SEVERITY_RANK).filter((s) => catalog.rules.some((r) => r.severity === s)).sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b]);
  const origins = ['built-in', 'imported', 'console'];
  const hostOptions = catalog.hosts.map(hostLabel);

  const q = urlParams();
  const focusRule = q.get('rule'); // /rules?rule=<id> - opened and highlighted
  const sel = {
    modules: selectionFromUrl('module', modules),
    severities: selectionFromUrl('severity', severities),
    origins: selectionFromUrl('origin', origins),
    outcomes: selectionFromUrl('outcome', outcomeLabels, (key) => (OUTCOMES.find((o) => o.key === key) || {}).label),
    hosts: selectionFromUrl('hosts', hostOptions, (runId) => labelByRun.get(runId)),
    hostMode: ['flagged', 'not_flagged'].includes(q.get('mode')) ? q.get('mode') : 'any',
    group: q.get('group') === 'tactic' ? 'tactic' : 'none',
  };

  function syncUrl() {
    const unless = (set, options, value) => (set.size === options.length ? null : value);
    setParams({
      module: unless(sel.modules, modules, [...sel.modules]),
      severity: unless(sel.severities, severities, [...sel.severities]),
      origin: unless(sel.origins, origins, [...sel.origins]),
      outcome: unless(sel.outcomes, outcomeLabels, [...sel.outcomes].map((l) => outcomeByLabel.get(l).key)),
      hosts: unless(sel.hosts, hostOptions, catalog.hosts.filter((hst) => sel.hosts.has(hostLabel(hst))).map((hst) => hst.run_id)),
      mode: sel.hostMode === 'any' ? null : sel.hostMode,
      group: sel.group === 'none' ? null : sel.group,
    });
  }

  const pick = (key, options) => (s) => { sel[key] = s.size ? s : new Set(options); syncUrl(); draw(); };
  const choose = (key) => (e) => { sel[key] = e.target.value; syncUrl(); draw(); };
  const select = (key, options) => h('select', { onchange: choose(key) },
    options.map(([value, text]) => h('option', { value, selected: sel[key] === value ? 'selected' : null }, text)));
  const bar = filterBar([
    ['Module', checkboxDropdown(modules, pick('modules', modules), [...sel.modules]).el],
    ['Severity', checkboxDropdown(severities, pick('severities', severities), [...sel.severities]).el],
    ['Origin', checkboxDropdown(origins, pick('origins', origins), [...sel.origins]).el],
    ['Outcome', checkboxDropdown(outcomeLabels, pick('outcomes', outcomeLabels), [...sel.outcomes]).el],
    ['Hosts', checkboxDropdown(hostOptions, pick('hosts', hostOptions), [...sel.hosts]).el,
      select('hostMode', [['any', 'any outcome'], ['flagged', 'flagged on them'], ['not_flagged', 'not flagged on them']])],
    ['Group by', select('group', [['none', 'none'], ['tactic', 'ATT&CK tactic']])],
  ]);

  // ruleCounts turns one rule's in-scope host outcomes into the plain
  // numbers the count columns (and the CSV export) carry.
  function ruleCounts(hosts) {
    const c = { hosts_n: hosts.length, evaluated_n: 0, not_evaluated_n: 0, dependency_n: 0, module_n: 0, rule_n: 0, flagged_n: 0 };
    for (const x of hosts) {
      if (x.status === 'not_run') {
        c.not_evaluated_n++;
        c[reasonGroup(x.reason_code) + '_n']++;
      } else {
        c.evaluated_n++;
        if (x.status === 'flagged') c.flagged_n++;
      }
    }
    return c;
  }

  function visibleRows() {
    const rows = [];
    const tests = [...sel.outcomes].map((l) => outcomeByLabel.get(l).test);
    for (const r of catalog.rules) {
      if (!sel.modules.has(r.module) || !sel.severities.has(r.severity) || !sel.origins.has(r.origin_kind)) continue;
      const scope = r.hosts.filter((x) => sel.hosts.has(labelByRun.get(x.run_id)));
      if (scope.length === 0) continue;
      const anyFlagged = scope.some((x) => x.status === 'flagged');
      if (sel.hostMode === 'flagged' && !anyFlagged) continue;
      if (sel.hostMode === 'not_flagged' && anyFlagged) continue;
      if (!scope.some((x) => tests.some((test) => test(x)))) continue;
      rows.push({ ...r, scope, ...ruleCounts(scope) });
    }
    return rows;
  }

  // coverage is the share of a set of rules' host checks (one rule on one
  // host) that were actually evaluated.
  function coverage(rows) {
    const checks = rows.reduce((n, r) => n + r.hosts_n, 0);
    return checks ? Math.round((rows.reduce((n, r) => n + r.evaluated_n, 0) * 100) / checks) : 0;
  }

  function rulesSummary(rows) {
    const count = (pred) => rows.filter(pred).length;
    return summaryStrip([
      { icon: 'id', value: rows.length, label: 'rules shown' },
      { icon: 'module', value: count((r) => r.origin_kind === 'built-in'), label: 'built-in', link: ['rules', { origin: 'built-in' }] },
      { icon: 'server', value: count((r) => r.origin_kind === 'console'), label: 'console rules', link: ['rules', { origin: 'console' }] },
      { icon: 'file', value: count((r) => r.origin_kind === 'imported'), label: 'imported from rule files', cls: count((r) => r.origin_kind === 'imported') ? 'origin-imported' : null, link: ['rules', { origin: 'imported' }] },
      { icon: 'flagged', value: count((r) => r.flagged_n > 0), label: 'flagged on at least one host', cls: RULE_OUTCOME.flagged.cls },
      { icon: 'evaluated', value: count((r) => r.flagged_n === 0 && r.not_evaluated_n === 0), label: 'evaluated on every host, nothing flagged', cls: RULE_OUTCOME.clear.cls },
      { icon: 'notEvaluated', value: count((r) => r.not_evaluated_n > 0), label: 'not evaluated on at least one host', cls: RULE_OUTCOME.not_run.cls },
      { icon: 'coverage', value: `${coverage(rows)}%`, label: 'of host checks evaluated' },
    ], rows.map((r) => r.module));
  }

  // hostTable is the rule's outcome on every in-scope host (10 per page).
  // Each host links to its page; a "flagged" outcome opens the rule's
  // signals on that host.
  function hostTable(rule) {
    const order = { flagged: 0, not_run: 1, clear: 2 };
    const rows = rule.scope
      .slice()
      .sort((a, b) => order[a.status] - order[b.status] || labelByRun.get(a.run_id).localeCompare(labelByRun.get(b.run_id)))
      .map((x) => ({
        ...x, // the host's run_id, os, os_build and role, for its link
        x,
        host: labelByRun.get(x.run_id),
        outcome: RULE_OUTCOME[x.status].label,
        matches: x.count ?? '',
        reason: x.status === 'not_run' || x.reason_code === 'partial' ? reasonLabel(x.reason_code) : '',
        details: x.status === 'flagged' ? (x.detail || x.title || '') : (x.reason || ''),
      }));
    const details = (row) => {
      const x = row.x;
      if (x.status === 'flagged') return rule.origin_kind === 'console' ? x.detail : fillTemplate(rule.detail, [x], 'detail') || x.title;
      if (x.status === 'clear' && !x.reason) return h('span', { class: 'mut' }, 'evaluated over this host\'s data; nothing matched');
      return x.reason;
    };
    return dataTable(rows, [
      col('host'),
      col('outcome', 'outcome', {
        desc: 'Flagged, evaluated with no match, or not evaluated. "flagged" opens the rule\'s signals on the host - for a console rule, which makes no signals, the page it flags rows on.',
        render: (_v, row) => (row.x.status !== 'flagged' ? outcomeTag(row.x.status)
          : rule.origin_kind === 'console' ? pageLink('applications', { hosts: row.x.run_id }, outcomeTag('flagged'))
            : pageLink('signals', { host: row.x.run_id, rule: rule.id }, outcomeTag('flagged'))),
      }),
      col('matches'), col('reason'),
      col('details', 'details', { render: (_v, row) => details(row) }),
    ], { pageSize: 10, filename: `${rule.id}-hosts` });
  }

  function detail(row) {
    return h('div', { class: 'detail' },
      detailBlock(null, narrative(row, (text, key) => fillTemplate(text, row.scope, key)), attackTags(row.attack, row.tags)),
      row.versions > 1 ? detailBlock(null, h('div', { class: 'tagtext ev-absent' }, `${row.versions} different definitions of this rule are in use across the hosts (different Signal versions); the newest is shown.`)) : null,
      detailBlock('Outcome per host', hostTable(row)),
      detailBlock('Detection logic', ruleLogic(row)));
  }

  // One host chosen: each rule's outcome on it, not counts of hosts.
  const rulesTable = (rows, filename) => dataTable(rows, forHosts(RULE_COLUMNS, sel.hosts.size), { detail, filename, height: 'auto', focus: focusRule ? (row) => row.id === focusRule : null }); // every rule, the table as tall as they need

  // tacticGroups is the "group by ATT&CK tactic" view: one card per tactic
  // - every tactic, since a tactic no rule covers is the point of the view.
  function tacticGroups(rows) {
    const hasUnmapped = rows.some((r) => tacticsOf(r).length === 0);
    return groupedView(rows, {
      keysOf: (r) => (tacticsOf(r).length ? tacticsOf(r) : [NO_TACTIC]),
      order: hasUnmapped ? [...ATTACK_TACTICS, NO_TACTIC] : ATTACK_TACTICS,
      empty: 'No rule covers this tactic yet.',
      head: (tactic, group) => {
        const pct = coverage(group);
        const flagged = group.filter((r) => r.flagged_n > 0).length;
        return h('span', { class: 'tactic-head' },
          h('span', { class: 'tactic-name' }, tactic),
          h('span', { class: 'mut' }, group.length ? `${group.length} rule${group.length === 1 ? '' : 's'}` : 'no rules'),
          group.length > 0 && h('span', { class: 'tactic-cov' }, h('span', { class: 'bar' }, h('i', { style: `width:${pct}%` })), h('span', { class: 'mut' }, `${pct}% evaluated`)),
          flagged > 0 && h('span', { class: 'tagtext ' + RULE_OUTCOME.flagged.cls }, `${flagged} flagged`));
      },
      build: (group, tactic) => rulesTable(group, `rules-${tactic.toLowerCase().replace(/[^a-z]+/g, '-')}`),
    });
  }

  // The ATT&CK coverage matrix of the hosts the Hosts filter chose, fetched
  // again only when that choice changes.
  const matrixBox = h('div');
  let matrixHosts = null;
  async function drawMatrix() {
    const chosen = catalog.hosts.filter((hst) => sel.hosts.has(hostLabel(hst)));
    const ids = chosen.length === catalog.hosts.length ? '' : chosen.map((hst) => hst.run_id).join(',');
    if (ids === matrixHosts) return;
    matrixHosts = ids;
    const matrix = await fetchJSON(`/api/dashboards/attack?${queryString({ hosts: ids })}`);
    if (ids !== matrixHosts) return; // the choice changed while it loaded
    matrixBox.replaceChildren(section(chosen.length === 1 ? 'ATT&CK coverage — what Signal evaluated on this host' : 'ATT&CK coverage — what Signal evaluated on the hosts in view',
      () => attackMatrix(matrix), { collapsed: false, modules: [CORE] }));
  }

  const summaryBox = h('div');
  const tableBox = h('div');
  function draw() {
    drawMatrix().catch((err) => matrixBox.replaceChildren(h('div', { class: 'card result-err' }, `ATT&CK coverage: ${err.message}`)));
    const rows = visibleRows();
    summaryBox.replaceChildren(rulesSummary(rows));
    tableBox.replaceChildren(...(sel.group === 'tactic' ? tacticGroups(rows) : [rulesTable(rows, 'rules')]));
  }

  // The suppression rules: what hides signals across the fleet - with the
  // rule files, the analysts' own tuning of the rules. Starts collapsed.
  const suppressBox = h('div');
  async function drawSuppressions() {
    const rules = await fetchJSON('/api/signals/suppressions');
    suppressBox.replaceChildren(section(`Suppression rules (${rules.length})`, () => suppressionRules(rules, drawSuppressions), { collapsed: true, modules: [] })); // analysts' rules, from no module
  }
  stickyPage(container, bar);
  container.replaceChildren(bar, matrixBox, summaryBox, ruleFilesCard(catalog, labelByRun), suppressBox, tableBox);
  draw();
  await drawSuppressions();
}

// ruleFilesCard lists the rule files the hosts' runs loaded (-rules): each
// file with its rules, their modules and the hosts that ran them - rules
// written for this fleet, beside the modules' own. With none imported, it
// says how to add some. Starts collapsed.
// RULE_TEMPLATE is a rule file to fill in (Signal's rules documentation): every
// required key with a placeholder, one selection, and the fidelity
// contract's two tests - a record it must match and a look-alike it must not.
const RULE_TEMPLATE = [{
  id: 'EXEC-YOUR-RULE-NAME', module: 'Executions', severity: 'medium', title: 'One line: what happened',
  evidence: ['process_creation'],
  detail: 'What happened - about one matching event.', impact: 'Why it matters.', focus: 'What to do next.',
  tags: [], notes: 'Why this rule exists in this fleet.',
  condition: 'program',
  detection: { program: { 'process.name': { modifier: 'endswith', values: ['\\your-program.exe'] } } },
  tests: [
    { evidence: 'process_creation', fields: { 'process.name': 'C:\\Tools\\your-program.exe' }, expect: 'match' },
    { evidence: 'process_creation', fields: { 'process.name': 'C:\\Tools\\not-your-program.exe' }, expect: 'no_match', note: 'a look-alike name' },
  ],
}];

function downloadRuleTemplate() {
  const a = h('a', { href: URL.createObjectURL(new Blob([JSON.stringify(RULE_TEMPLATE, null, 2) + '\n'], { type: 'application/json' })), download: 'rule-template.json' });
  a.click();
  URL.revokeObjectURL(a.href);
}

function ruleFilesCard(catalog, labelByRun) {
  const files = new Map();
  for (const r of catalog.rules.filter((x) => x.origin_kind === 'imported')) {
    for (const x of r.hosts.filter((hst) => hst.origin && hst.origin !== 'built-in')) {
      if (!files.has(x.origin)) files.set(x.origin, { file: x.origin, rules: new Set(), modules: new Set(), hosts: new Map() });
      const f = files.get(x.origin);
      f.rules.add(r.id);
      f.modules.add(r.module);
      f.hosts.set(x.run_id, x);
    }
  }
  const rows = [...files.values()].map((f) => ({
    file: f.file, rule_ids: [...f.rules].sort(), modules: [...f.modules].sort(),
    hosts: [...f.hosts.values()].map((x) => ({ ...x, host: labelByRun.get(x.run_id) })), seen_n: f.hosts.size,
    host_names: [...f.hosts.values()].map((x) => labelByRun.get(x.run_id)).join('; '),
  })).sort((a, b) => a.file.localeCompare(b.file));
  const howTo = h('div', { class: 'mut' },
    'Rules written for this fleet are JSON files - the same format as the modules\' own rules, each with the tests it must pass - given to Signal when it runs: ',
    h('span', { class: 'mono' }, 'signal live -all -rules C:\\signal-rules'), '. ',
    'Signal checks them before the survey (', h('span', { class: 'mono' }, 'signal rules -check -rules C:\\signal-rules'), ') and runs them beside the built-in rules; ',
    'they appear here and in the table below marked "imported", with the file each came from. See RULES.md in Signal\'s documentation.');
  const template = h('div', { style: 'margin-top:8px' }, h('button', { type: 'button', class: 'ghost', onclick: downloadRuleTemplate }, 'Download a rule template'),
    h('span', { class: 'mut' }, ' - a rule file to fill in: every required key, a selection, and the two tests every rule must pass.'));
  return section(`Rule files — rules imported when Signal ran (${rows.length})`, () => h('div', {}, howTo, template, rows.length ? h('div', { style: 'margin-top:12px' }, dataTable(rows, [
    col('file', 'rule_file'), col('rule_ids'), col('modules', 'modules', { desc: 'The modules its rules run in.' }),
    col('seen_n', 'seen_n', { label: 'Loaded on', desc: 'Hosts whose run loaded the file.' }), col('host_names'),
  ], { filename: 'rule-files' })) : null), { collapsed: rows.length === 0, modules: [...new Set(rows.flatMap((r) => r.modules))] });
}
