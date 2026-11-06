// The Hosts page: the host inventory - one row per host, from its latest
// collection: what it is, when it was collected, its open signals and risk,
// coverage gaps and the telemetry its modules depend on (see
// src/model/fleet.js) - and, at /hosts?host=<run id>, one host's own page:
// everything about that host in one place, its collection history
// included. Every host name in the app links there; a link to an earlier
// collection opens its host's page. KPIs and telemetry are what each
// module reports, so a new module's appear here with no change.

import { h, fetchJSON, ts, mono, svgIcon } from '../dom.js';
import { pageLink, urlParams, setParams, go, queryString } from '../router.js';
import {
  CORE, section, filterBar, stickyPage, summaryStrip, severityItems, checkboxDropdown, selectionFromUrl, moduleBadge, hostLabels,
  kpiGrid, factCard,
} from '../components.js';
import { dataTable, col, sourcesView, telemetryCoverage } from '../table.js';
import { entityList } from './signals.js';
import { hostExclusionsView, exclusionProduct, persistenceView, applicationsView, extensionsView } from './inventories.js';

// HOST_COLUMNS is the host inventory table; a host's modules, KPIs and
// telemetry items are on its own page.
const HOST_COLUMNS = [
  col('host'), col('os'), col('os_build'), col('role'), col('domain'),
  col('started', 'started', { wrap: true }),
  col('risk'), col('signals_n'), col('warnings_n'), col('gaps_n'), col('telemetry_off_n'),
];

// HOST_STATUS is the host list's "Show" filter: a key (kept in the URL),
// its wording, and which hosts it keeps.
const HOST_STATUS = [
  ['', 'every host', () => true],
  ['signals', 'with signals', (x) => x.signals_n > 0],
  ['urgent', 'with critical or high signals', (x) => x.by_severity.critical + x.by_severity.high > 0],
  ['warnings', 'with warnings', (x) => x.warnings_n > 0],
  ['gaps', 'with coverage gaps', (x) => x.gaps_n > 0],
  ['telemetry_off', 'with telemetry off', (x) => x.telemetry_off_n > 0],
  ['clean', 'with no signals and no gaps', (x) => !x.signals_n && !x.gaps_n],
];

// modulesOf lists the modules of host rows, with Signal core.
const modulesOf = (hosts) => [CORE, ...new Set(hosts.flatMap((x) => x.modules.map((m) => m.name)))];

export async function renderHostsPage(container) {
  const hosts = await fetchJSON('/api/hosts');
  const id = urlParams().get('host');
  const host = hosts.find((x) => x.history.some((r) => r.run_id === id));
  return host ? renderHostProfile(container, host, hosts) : renderHostList(container, hosts);
}

// renderHostList is the host inventory: a sticky filter bar (OS build,
// role, domain, and a Show filter - see HOST_STATUS - kept in the URL), a
// summary strip, and the table, 20 hosts per page.
function renderHostList(container, hosts) {
  if (hosts.length === 0) {
    container.replaceChildren(h('div', { class: 'card mut' }, 'No hosts yet - ', pageLink('import', {}, 'import'), ' a Signal run first.'));
    return;
  }
  const osOf = (x) => [x.os, x.os_build].filter(Boolean).join(' ') || 'not recorded';
  const unique = (f) => [...new Set(hosts.map(f))].sort();
  const options = { os: unique(osOf), roles: unique((x) => x.role), domains: unique((x) => x.domain || '(none)') };
  const status = urlParams().get('status');
  const sel = {
    os: selectionFromUrl('os', options.os),
    roles: selectionFromUrl('role', options.roles),
    domains: selectionFromUrl('domain', options.domains),
    status: HOST_STATUS.some(([k]) => k === status) ? status : '',
  };
  function syncUrl() {
    const unless = (key) => (sel[key].size === options[key].length ? null : [...sel[key]]);
    setParams({ os: unless('os'), role: unless('roles'), domain: unless('domains'), status: sel.status || null });
  }
  const pick = (key) => (s) => { sel[key] = s.size ? s : new Set(options[key]); syncUrl(); draw(); };
  const bar = filterBar([
    ['OS build', checkboxDropdown(options.os, pick('os'), [...sel.os]).el],
    ['Role', checkboxDropdown(options.roles, pick('roles'), [...sel.roles]).el],
    ['Domain', checkboxDropdown(options.domains, pick('domains'), [...sel.domains]).el],
    ['Show', h('select', { onchange: (e) => { sel.status = e.target.value; syncUrl(); draw(); } },
      HOST_STATUS.map(([k, label]) => h('option', { value: k, selected: sel.status === k ? 'selected' : null }, label)))],
  ]);

  const summaryBox = h('div');
  const tableBox = h('div');
  function draw() {
    const keep = HOST_STATUS.find(([k]) => k === sel.status)[2];
    const rows = hosts.filter((x) => sel.os.has(osOf(x)) && sel.roles.has(x.role) && sel.domains.has(x.domain || '(none)') && keep(x));
    const n = (key) => rows.filter(HOST_STATUS.find(([k]) => k === key)[2]).length;
    const item = (key, icon, label, cls) => ({ icon, value: n(key), label, cls: n(key) ? cls : null, link: ['hosts', { status: key }] });
    summaryBox.replaceChildren(summaryStrip([
      { icon: 'hosts', value: rows.length, label: 'hosts' },
      { icon: 'server', value: rows.filter((x) => x.role === 'Server' || x.role === 'Domain Controller').length, label: 'servers and domain controllers' },
      item('signals', 'signals', 'with signals', 'sev-high'),
      item('urgent', 'severity', 'critical or high', 'sev-critical'),
      item('warnings', 'warning', 'with warnings', 'sev-medium'),
      item('gaps', 'notEvaluated', 'with coverage gaps', 'ev-absent'),
      item('telemetry_off', 'shield', 'with telemetry off', 'sev-high'),
    ], modulesOf(rows)));
    tableBox.replaceChildren(section('Hosts', () => (rows.length ? dataTable(rows, HOST_COLUMNS, { pageSize: 20, filename: 'hosts' }) : h('div', { class: 'mut' }, 'No host matches the filters.')),
      { collapsed: false, modules: modulesOf(rows) }));
  }

  stickyPage(container, bar);
  container.replaceChildren(bar, summaryBox, tableBox);
  draw();
}

// coverageWarnings is a host's coverage gaps and module errors - what could
// not be checked, which matters as much as what was found - or null.
// shadowCopiesView is what a collection with -shadow read from the host's
// existing shadow copies: Signal's note on what that means for every
// signal, then each copy - read or why not, what it added (records only it
// holds) and set aside (the live system holds them too) - and what could
// not be listed.
function shadowCopiesView(sc, host) {
  const rows = sc.copies.map((c) => ({ ...c, state: c.read ? 'read' : 'not read' }));
  return h('div', {},
    h('div', { class: 'mut hidden-note' }, sc.note),
    dataTable(rows, [
      col('volume', 'details', { label: 'Copy of', desc: 'The drive the shadow copy is a copy of.' }),
      col('created', 'time', { label: 'Made', desc: `When Windows made the copy (UTC).` }),
      col('state', 'details', { label: 'Read', desc: 'Whether Signal read this copy, and why not.', render: (v, row) => (row.read ? h('span', { class: 'tagtext st-ran' }, 'read') : h('span', { class: 'mut' }, row.reason || 'not read')) }),
      col('added', 'count', { label: 'Only in the copy', desc: 'Records only this copy holds - the host no longer does - given to the modules\' rules; every signal from one says so.' }),
      col('also_live', 'count', { label: 'Also on the host', desc: 'Records of the copy the live system (or a newer copy) holds too: set aside, never repeated.' }),
      col('id', 'details', { label: 'ID', desc: 'Windows\' ID for the copy (signal live -shadow <ID> reads it alone).', render: (v) => mono(v) }),
    ], { height: 'scroll', filename: `${host}-shadow-copies`, rowKey: (r) => r.id }),
    sc.problems && sc.problems.length ? h('div', { class: 'mut hidden-note' }, 'Not listed: ' + sc.problems.join('; ')) : null);
}

function coverageWarnings(gaps) {
  if (gaps.length === 0) return null;
  return h('div', {},
    h('h2', { class: 'card-head' }, `Coverage gaps and errors (${gaps.length})`, moduleBadge(gaps.map((g) => g.module))),
    gaps.map((g) => h('div', { style: 'margin-bottom:4px' }, h('b', {}, `[${g.module}] `), g.text)));
}


// renderHostProfile is one host's page, from its latest collection: a
// header naming the host (with links to its signals, rule outcomes and
// inventories), a summary strip, its identity, collection and modules, its
// coverage gaps, each module's KPIs and the telemetry its detection depends
// on, its signals, the identities seen on it - each with how many hosts in
// the fleet share it - its antivirus exclusions (or why they are unknown),
// and its collection history.
async function renderHostProfile(container, x, hosts) {
  const id = x.run_id;
  const [modules, inv, open, suppressed, accts, ents] = await Promise.all([
    fetchJSON(`/api/hosts/${encodeURIComponent(id)}/modules`),
    fetchJSON(`/api/inventories?on_host=${encodeURIComponent(id)}`),
    fetchJSON(`/api/signals?${queryString({ host: id })}`),
    fetchJSON(`/api/signals?${queryString({ host: id, show: 'suppressed' })}`),
    fetchJSON(`/api/users?${queryString({ on_host: id })}`),
    fetchJSON(`/api/entities?${queryString({ host: id })}`),
  ]);
  const labels = hostLabels(hosts);
  const bar = filterBar([
    ['Host', h('select', { onchange: (e) => go('hosts', { host: e.target.value }) },
      hosts.map((o) => h('option', { value: o.run_id, selected: o.run_id === id ? 'selected' : null }, labels.get(o.run_id))))],
    ['', pageLink('hosts', {}, '← All hosts')],
  ]);

  const modNames = x.modules.map((m) => m.name);
  const head = h('div', { class: 'card host-head' },
    h('div', { class: 'host-title' }, svgIcon(x.role === 'Client' ? 'hosts' : 'server'), h('span', {}, x.host), h('span', { class: 'mut host-role' }, x.role)),
    h('div', { class: 'mut' }, [x.os, x.os_version, x.os_build && `build ${x.os_build}`, x.arch, x.domain].filter(Boolean).join(' · ')),
    h('div', { class: 'row host-links' },
      pageLink('signals', { host: id }, 'Signals'),
      pageLink('rules', { hosts: id }, 'Rule outcomes'), pageLink('audit', { hosts: id }, 'Audit policy'),
      moduleBadge([CORE])));

  const facts = h('div', { class: 'grid facts-grid' },
    factCard('Identity', [CORE], [
      ['Hostname', x.host], ['Machine ID', x.machine_id && mono(x.machine_id)], ['Domain', x.domain], ['Role', x.role], ['Installation type', x.installation_type],
      ['Operating system', x.os], ['Version', x.os_version], ['Build', x.os_build], ['Architecture', x.arch],
      ['Time zone', x.timezone ? `${x.timezone}${x.utc_to_local ? ` (${x.utc_to_local})` : ''}` : ''],
    ]),
    factCard('Collection', [CORE], [
      ['Run ID', mono(id)], ['Mode', x.mode], ['Signal version', h('span', {}, x.tool_version,
        x.older_output ? [' ', h('span', { class: 'tagtext ev-absent' }, 'older output'), h('div', { class: 'mut' }, x.older_output)] : '',
        x.withdrawn_signal ? [' ', h('span', { class: 'tagtext withdrawn-tag' }, 'withdrawn version'), h('div', { class: 'mut' }, `${x.withdrawn_signal}. Re-run the host with the current Signal (signal update).`)] : '')], ['Collected', ts(x.started)], ['Finished', ts(x.finished)],
      ['Duration', x.duration], ['Host started', x.boot_time && ts(x.boot_time)], ['Collected by', x.collected_by], ['Collector SID', x.collected_by_sid && mono(x.collected_by_sid)],
      ['Profile created', x.profile_created && ts(x.profile_created)], ['Elevated', x.elevated == null ? '' : (x.elevated ? 'Yes' : 'No')],
      ['Scoping profile', x.profile
        ? h('span', {}, pageLink('settings', { profile: x.profile.sha256 }, x.profile.name), x.profile.window ? h('span', { class: 'mut' }, ` · window ${x.profile.window}${x.profile.since ? ` (from ${ts(x.profile.since)})` : ''}`) : '')
        : h('span', { class: 'mut' }, 'none given (or Signal before 0.54.0)')],
      ...(x.profile?.problems?.length ? [['Profile problems', h('span', { class: 'tagtext ev-absent' },
        `${x.profile.problems.length} part(s) left out of the run: ${x.profile.problems.join('; ')}`)]] : []),
      ...(x.evidence ? [['Evidence source', x.evidence.source], ['Layout', x.evidence.layout]] : []),
    ]),
    factCard('Modules', modNames, x.modules.map((m) => [m.name, h('span', {},
      h('span', { class: 'tagtext ' + (m.status === 'ok' ? 'st-ran' : 'ev-absent') }, m.status),
      m.errors ? h('span', { class: 'mut' }, ` · ${m.errors} error${m.errors === 1 ? '' : 's'}`) : null)])));

  const telemetryModules = modules.filter((m) => m.telemetry.length).map((m) => m.name);
  const hidden = suppressed.total;
  const sections = [
    section(null, () => coverageWarnings(x.gaps), { cls: 'warn' }),
    kpiGrid(modules),
    section('Telemetry its detection depends on', () => telemetryCoverage(x.telemetry, 1), { collapsed: false, modules: telemetryModules }),
    section('Evidence sources — what was read, and what it depends on', () => sourcesView(x.sources, x.host), { collapsed: false, modules: [CORE] }),
    ...(x.shadow_copies ? [section(`Shadow copies — read besides the live system (${x.shadow_copies.copies.filter((c) => c.read).length} of ${x.shadow_copies.copies.length})`,
      () => shadowCopiesView(x.shadow_copies, x.host), { collapsed: false, modules: [CORE] })] : []),
    // What to look at on this host: each entity with its signals, opening
    // its page - everything about it, as on the Signals page.
    section(`Signals on this host — by what they are about (${ents.rows.length})`, () => h('div', {},
      ents.rows.length ? entityList(ents.rows, { filename: `signals-${x.host}` }) : h('div', { class: 'mut' }, 'No signal on this host.'),
      hidden ? h('div', { class: 'mut hidden-note' }, `${hidden} more hidden by suppression rules - `, pageLink('signals', { host: id, show: 'suppressed' }, 'show them')) : null),
    { collapsed: false, modules: open.summary.modules }),
    section(`Accounts that used this host (${accts.users.length})`, () => (accts.users.length ? h('div', {},
      dataTable(accts.users, [col('account', 'user'), col('scope'), col('sources', 'account_sources'), col('enabled'), col('admin'), col('logged_on_now'),
        col('logons'), col('failures'), col('first_seen'), col('last_seen'), col('seen_n', 'seen_n', { label: 'On hosts', desc: 'How many hosts of the fleet the account used.' }), col('notes', 'account_notes')],
      { filename: `${x.host}-accounts`, rowKey: (r) => r.key }),
      accts.excluded.length ? h('div', { class: 'mut hidden-note' }, `${accts.excluded.length} more left out - Windows' own identities, groups, unused default accounts: `,
        pageLink('users', {}, 'see why on the Users page')) : null)
      : h('div', { class: 'mut' }, 'No account recorded - run Signal with the Users and Logons modules.')), { collapsed: false, modules: ['Users', 'Logons'] }),
    ...(inv.persistence.hosts ? [section('Persistent entries on this host — with how many hosts have each', () => persistenceView(inv.persistence, { on_host: id }),
      { collapsed: false, modules: ['Persistence'] })] : []),
    ...(inv.applications.hosts ? [section('Applications on this host — with how many hosts have each', () => applicationsView(inv.applications, { on_host: id }),
      { collapsed: false, modules: ['Applications'] })] : []),
    ...(inv.extensions.hosts ? [section('Browser extensions on this host — with how many hosts have each', () => extensionsView(inv.extensions, { on_host: id }),
      { collapsed: false, modules: ['Browsers'] })] : []),
    // Only when the host's exclusions were collected (read or not).
    ...(!inv.av_exclusions.hosts[0] ? [] : [
      section(`${exclusionProduct(inv.av_exclusions)} exclusions on this host${inv.av_exclusions.hosts[0].state === 'read' ? ` (${inv.av_exclusions.hosts[0].n})` : ''} — what it does not scan`,
        () => hostExclusionsView(inv.av_exclusions), { collapsed: false, modules: ['Protection'] })]),
    section(`Collection history (${x.history.length})`, () => dataTable(x.history, [
      col('started', 'started', { desc: `When Signal ran on the host (UTC); opens that collection's signals.`, render: (v, row) => pageLink('signals', { host: row.run_id }, ts(v)) }),
      col('run_id', 'run', { desc: 'The collection\'s run ID; "current" is the one every page shows.', render: (v, row) => h('span', { class: 'run-cell' }, mono(v), row.latest ? h('span', { class: 'tagtext st-ran' }, 'current') : null) }),
      col('tool_version'), col('signals_n', 'count', { label: 'Signals', desc: 'Open signals (critical to low) in that collection.' }),
      col('warnings_n', 'count', { label: 'Warnings', desc: 'Cards of that collection whose state is not good (a small log, a policy off...).' }),
      col('new_n', 'new_n'),
    ], { filename: `${x.host}-collections` }), { collapsed: false, modules: [CORE] }),
  ];

  // Once the host's header scrolls away, the filter bar names the host -
  // its name, role and risk - so a long page never loses whose it is.
  const mini = h('span', { class: 'bar-host', 'aria-hidden': 'true' }, svgIcon(x.role === 'Client' ? 'hosts' : 'server'),
    h('b', {}, x.host), h('span', { class: 'mut' }, x.role), h('span', { class: x.risk ? 'tagtext sev-high' : 'mut' }, `risk ${x.risk}`));
  bar.append(mini);
  if (window.IntersectionObserver) new window.IntersectionObserver(([e]) => mini.classList.toggle('on', !e.isIntersecting && e.boundingClientRect.top < 0)).observe(head);

  stickyPage(container, bar);
  container.replaceChildren(bar, head,
    summaryStrip([
      ...severityItems(x.by_severity, { host: id }),
      { icon: 'firstSeen', value: x.new_n === '' ? '—' : x.new_n, label: 'new since previous collection', cls: x.new_n ? 'tr-new' : null, link: x.new_n ? ['signals', { host: id, show: 'new' }] : null },
      { icon: 'eye', value: x.untriaged_n, label: 'untriaged', cls: x.untriaged_n ? 'tr-new' : null, link: x.untriaged_n ? ['signals', { host: id, triage: 'new' }] : null },
      { icon: 'gauge', value: x.risk, label: 'risk', cls: x.risk ? 'sev-high' : null },
      { icon: 'warning', value: x.warnings_n, label: 'warnings', cls: x.warnings_n ? 'sev-medium' : null },
      { icon: 'notEvaluated', value: x.gaps_n, label: 'coverage gaps', cls: x.gaps_n ? 'ev-absent' : null },
      { icon: 'shield', value: x.telemetry_off_n, label: 'telemetry off', cls: x.telemetry_off_n ? 'sev-high' : null },
    ], [...open.summary.modules, ...telemetryModules]),
    facts, ...sections.filter(Boolean));
}
