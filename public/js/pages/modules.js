// The Modules page: every module the fleet's hosts ran (each host's latest
// collection), as Signal describes it - what it answers, the evidence it
// reads and that evidence's health on the hosts, how it ran on each host
// (version, status, time, gaps), the telemetry and cards it reports, and
// its rules, built-in or imported from rule files (see
// src/model/modules.js). /modules?module=<name> opens one module. Every
// module badge in the app opens its module here.

import { h, fetchJSON, mono, keyValues } from '../dom.js';
import { pageLink, urlParams, setParams } from '../router.js';
import {
  section, filterBar, stickyPage, summaryStrip, checkboxDropdown, selectionFromUrl, detailBlock, attackTags, countCell,
} from '../components.js';
import { dataTable, col, forHosts } from '../table.js';

// SHOW is the "Show" filter: a key (kept in the URL), its wording, and
// which modules it keeps.
const SHOW = [
  ['', 'every module', () => true],
  ['problems', 'partial, failed or skipped somewhere', (m) => m.problem_n > 0],
  ['not_everywhere', 'not run on every host', (m) => m.not_run_n > 0],
  ['imported', 'with imported rules', (m) => m.imported_n > 0],
  ['signals', 'with open signals', (m) => m.signals_n > 0],
];

const MODULE_COLUMNS = [
  col('name', 'module_name'), col('description'), col('versions'), col('hosts_n', 'ran_n'), col('problem_n'), col('not_run_n'),
  col('duration_avg_ms'), col('evidence_names'), col('rules_n'), col('signals_n', 'module_signals_n'), col('warnings_n', 'module_warnings_n'),
];

// moduleDetail is one module's expanded row: what it is; the evidence it
// reads and how readable it was on the hosts; the telemetry and cards it
// reports; how it ran on each host; and its rules.
function moduleDetail(m) {
  const facts = [
    ['Category', m.category || '—'], ['Rule prefix', m.rule_prefix ? mono(m.rule_prefix + '-') : '—'],
    ['Needs administrator rights', m.needs_admin == null ? '—' : (m.needs_admin ? 'yes' : 'no')],
    ['Average time', m.duration_avg_ms == null ? '—' : `${m.duration_avg_ms.toLocaleString()} ms (slowest ${m.duration_max_ms.toLocaleString()} ms)`],
  ];
  // hostCount is a column counting the module's hosts in one state.
  const hostCount = (key, label, icon, cls, desc) => col(key, 'count', { label, icon, desc, render: (v) => countCell(v, cls) });
  const evidenceRows = m.evidence.map((e) => ({ ...e, ...e.statuses }));
  return h('div', { class: 'detail' },
    detailBlock('What it answers', h('div', {}, m.description || h('span', { class: 'mut' }, 'Not recorded - these hosts ran a Signal older than 0.9.0, which did not describe its modules.')),
      keyValues(facts), attackTags(m.attack, m.tags)),
    detailBlock('Evidence it reads - read once for every module by Signal\'s providers',
      evidenceRows.length ? dataTable(evidenceRows, [col('label', 'source'),
        hostCount('read', 'Read on', 'evaluated', 'st-ran', 'Hosts where the evidence was read completely.'),
        hostCount('partial', 'Partly read on', 'coverage', 'ev-absent', 'Hosts where the read ended early; what was read is kept.'),
        hostCount('not_read', 'Not read on', 'notEvaluated', 'st-notrun', 'Hosts where it could not be read - its rules were not evaluated there.'),
        hostCount('unavailable', 'No source on', 'moduleOff', 'st-notrun', 'Hosts where nothing provides it (another mode, an older Signal).')],
      { filename: `${m.name}-evidence`, pageSize: 10 }) : h('div', { class: 'mut' }, 'Not recorded.')),
    m.telemetry.length ? detailBlock('Telemetry its detection depends on', dataTable(m.telemetry, [col('label', 'title', { label: 'Telemetry', desc: 'What the module\'s detection depends on.' }),
      hostCount('on', 'On', 'success', 'st-ran', 'Hosts where it is on.'), hostCount('off', 'Off', 'failure', 'sev-high', 'Hosts where it is off: what depends on it cannot be seen there.'),
      hostCount('unknown', 'Unknown', 'reason', '', 'Hosts where it could not be determined.')],
    { filename: `${m.name}-telemetry`, pageSize: 10 })) : null,
    m.kpis.length ? detailBlock('Cards it states on each host\'s page', dataTable(m.kpis, [col('label', 'title', { label: 'Card', desc: 'A headline number the module states.' }),
      col('warn_n', 'count', { label: 'Warning on', desc: 'Hosts where the card\'s state is not good (see the host\'s page for what it means).', render: (v) => countCell(v, 'sev-medium') }),
      col('hosts_n', 'count', { label: 'Stated on', desc: 'Hosts where the module stated it.' })], { filename: `${m.name}-cards`, pageSize: 10 })) : null,
    detailBlock('On each host', dataTable(m.hosts, [col('host'), col('version'), col('status'), col('duration_ms'), col('signals_n', 'module_signals_n', { render: (v, row) => (v ? pageLink('signals', { host: row.run_id, modules: m.name }, countCell(v, 'sev-high')) : countCell(0)) }),
      col('warnings', 'warning_list'), col('gaps', 'gap_list')], { filename: `${m.name}-hosts`, pageSize: 10 })),
    detailBlock('Rules', h('div', {}, `${m.rules_n} rule${m.rules_n === 1 ? '' : 's'}: ${m.builtin_n} built-in, ${m.imported_n} imported from rule files · ${m.rules_flagged_n} flagged somewhere · `,
      pageLink('rules', { module: m.name }, 'open them on the Rules page')),
    m.rule_files.length ? h('div', {}, h('span', { class: 'mut' }, 'Rule files: '), m.rule_files.map((f, i) => [i ? ', ' : '', mono(f)])) : null));
}

export async function renderModulesPage(container) {
  const { hosts_n: hostsN, modules } = await fetchJSON('/api/modules');
  if (modules.length === 0) {
    container.replaceChildren(h('div', { class: 'card mut' }, 'No modules yet - ', pageLink('import', {}, 'import'), ' a Signal run first.'));
    return;
  }
  const focus = urlParams().get('module');
  const categories = [...new Set(modules.map((m) => m.category || 'not recorded'))].sort();
  const show = urlParams().get('show');
  const sel = { categories: selectionFromUrl('category', categories), show: SHOW.some(([k]) => k === show) ? show : '' };
  const syncUrl = () => setParams({ category: sel.categories.size === categories.length ? null : [...sel.categories], show: sel.show || null });
  const bar = filterBar([
    ['Category', checkboxDropdown(categories, (s) => { sel.categories = s.size ? s : new Set(categories); syncUrl(); draw(); }, [...sel.categories]).el],
    ['Show', h('select', { onchange: (e) => { sel.show = e.target.value; syncUrl(); draw(); } },
      SHOW.map(([k, label]) => h('option', { value: k, selected: sel.show === k ? 'selected' : null }, label)))],
  ]);
  const summaryBox = h('div');
  const tableBox = h('div');
  function draw() {
    const keep = SHOW.find(([k]) => k === sel.show)[2];
    const rows = modules.filter((m) => sel.categories.has(m.category || 'not recorded') && keep(m));
    const sum = (k) => rows.reduce((n, m) => n + m[k], 0);
    summaryBox.replaceChildren(summaryStrip([
      { icon: 'module', value: rows.length, label: 'modules' },
      { icon: 'hosts', value: hostsN, label: 'hosts' },
      { icon: 'notEvaluated', value: rows.filter((m) => m.problem_n > 0).length, label: 'partial, failed or skipped somewhere', cls: rows.some((m) => m.problem_n > 0) ? 'ev-absent' : null, link: ['modules', { show: 'problems' }] },
      { icon: 'scroll', value: sum('builtin_n'), label: 'built-in rules', link: ['rules', { origin: 'built-in' }] },
      { icon: 'file', value: sum('imported_n'), label: 'imported rules', cls: sum('imported_n') ? 'origin-imported' : null, link: ['rules', { origin: 'imported' }] },
      { icon: 'signals', value: sum('signals_n'), label: 'open signals', cls: sum('signals_n') ? 'sev-high' : null, link: ['signals', {}] },
    ], rows.map((m) => m.name)));
    tableBox.replaceChildren(section('Modules', () => (rows.length
      ? dataTable(rows, forHosts(MODULE_COLUMNS, hostsN), { detail: moduleDetail, rowKey: (r) => r.name, focus: focus ? (r) => r.name === focus : null, filename: 'modules' })
      : h('div', { class: 'mut' }, 'No module matches the filters.')), { collapsed: false, modules: rows.map((m) => m.name) }));
  }
  stickyPage(container, bar);
  container.replaceChildren(bar, summaryBox, tableBox);
  draw();
}
