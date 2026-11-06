// Overview: the fleet dashboard, over every host's latest collection
// (narrowed by the Hosts / OS build / Role filters): a summary strip of open
// signals by severity, untriaged and escalated ones and hosts with critical
// or high signals; hosts ranked by risk; rules ranked by how many hosts their signals are on; telemetry coverage, per item the modules report;
// the evidence sources (a host's own, or how many hosts read each); how
// recently the hosts were collected; and every row an analyst flagged on an
// inventory page (src/flags.js - fleet-wide). A single host's details are
// on its Hosts page.

import { h, fetchJSON, ts } from '../dom.js';
import { pageLink, queryString } from '../router.js';
import { CORE, section, filterBar, stickyPage, summaryStrip, severityItems, hostScopeFilters, stackBar } from '../components.js';
import { dataTable, col, forHosts, sourcesView, telemetryCoverage } from '../table.js';

// freshness is how long ago the hosts were last collected, with the oldest
// and newest collection - how current the picture on every page is.
function freshness(d, hosts) {
  return h('div', {},
    h('p', { class: 'mut card-intro' }, 'Every page shows each host as it was at its latest collection. A host collected days ago may have changed since - its signals, accounts and settings are as they were then. Collect again the hosts whose picture is old.'),
    h('div', { class: 'kv freshness-range' }, h('div', {}, h('span', {}, 'Oldest collection: '), ts(d.oldest_collection)), h('div', {}, h('span', {}, 'Newest collection: '), ts(d.newest_collection))),
    h('div', { class: 'dash-bars' }, d.freshness.map((f) => h('div', { class: 'dash-bar-row' },
      h('span', {}, `collected ${f.label} ago`), stackBar([[f.hosts, 'fresh', 'hosts'], [hosts - f.hosts, 'rest', 'other hosts']]), h('span', { class: 'mut' }, `${f.hosts} host${f.hosts === 1 ? '' : 's'}`)))));
}

// flagsView is the flagged items: every row an analyst flagged (newest
// first) and every row the console flagged by its own rules - when, what,
// on which page, by whom, the console rule and the reason. A Signal rule's
// flags are its signals (the Signals page).
function flagsView(flags) {
  return h('div', {},
    h('p', { class: 'mut card-intro' }, "Rows an analyst flagged on the data pages and entities flagged in the graph, each with the analyst's reason, and applications the console flagged: an installed version is in the affected versions NIST's NVD gives for a CVE CISA's Known Exploited Vulnerabilities catalog lists for the product (Settings). Fleet-wide, whatever the host filter. A row a Signal rule flags is a signal: see Signals."),
    flags.length ? dataTable(flags, [col('at', 'flag_at'), col('label', 'flag_item'), col('where', 'flag_where'), col('flagged_by', 'flag_by'), col('rule', 'flag_rule'), col('reason', 'flag_reason')], { pageSize: 10, filename: 'flagged-items' })
      : h('div', { class: 'mut' }, 'Nothing is flagged.'));
}

export async function renderOverviewPage(container) {
  const runs = (await fetchJSON('/api/runs')).filter((r) => r.latest);
  const body = h('div');
  const scope = hostScopeFilters(runs, load);
  const bar = filterBar(scope.fields);
  stickyPage(container, bar);
  container.replaceChildren(bar, body);

  let generation = 0;
  async function load() {
    const mine = ++generation;
    const chosen = scope.selected();
    if (chosen.length === 0) {
      body.replaceChildren(h('div', { class: 'card mut' }, runs.length ? 'No host matches the filters.' : 'No hosts yet - import a Signal run first.'));
      return;
    }
    const ids = chosen.length === runs.length ? '' : chosen.map((r) => r.run_id).join(',');
    const [d, flags] = await Promise.all([fetchJSON(`/api/dashboards/fleet?${queryString({ hosts: ids })}`), fetchJSON('/api/flags')]);
    if (mine !== generation) return;
    const s = d.summary;
    const link = ids ? { hosts: ids } : {};
    // One host in view (chosen, or the only one imported): every number is
    // that host's - its name, not "1 hosts"; no ranking among hosts.
    const one = s.hosts === 1 ? d.hosts[0] : null;
    body.replaceChildren(
      summaryStrip([
        one ? { icon: 'hosts', value: one.host, label: 'host', link: ['hosts', { host: one.run_id }] } : { icon: 'hosts', value: s.hosts, label: 'hosts', link: ['hosts', {}] },
        ...severityItems(s.by_severity, {}),
        { icon: 'eye', value: s.untriaged, label: 'untriaged', cls: s.untriaged ? 'tr-new' : null, link: s.untriaged ? ['signals', { triage: 'new' }] : null },
        { icon: 'flagged', value: s.escalated, label: 'escalated', cls: s.escalated ? 'tr-escalated' : null, link: s.escalated ? ['signals', { triage: 'escalated' }] : null },
        one ? null : { icon: 'server', value: s.hosts_urgent, label: 'hosts with critical or high', cls: s.hosts_urgent ? 'sev-high' : null, link: s.hosts_urgent ? ['hosts', { status: 'urgent' }] : null },
      ].filter(Boolean), d.modules),
      h('div', { class: 'dash-grid' },
        section(one ? 'Host risk' : 'Hosts ranked by risk', () => dataTable(d.hosts, [
          col('host'), col('risk'), col('signals_n'), col('untriaged_n'), col('warnings_n'), col('gaps_n'), col('started', 'started', { label: 'Last collected' }),
        ], { pageSize: 10, filename: 'hosts-by-risk' }), { collapsed: false, modules: [CORE, ...d.modules] }),
        section(one ? 'Rules flagged' : 'Rules ranked by hosts flagged', () => (d.top_rules.length ? dataTable(d.top_rules, forHosts([
          col('severity'), col('rule_id', 'rule_id', { render: (v) => pageLink('signals', { ...link, rule: v }, v), desc: 'The rule; opens its open signals.' }), col('title'),
          col('hosts_n', 'hosts_n', { label: 'Hosts flagged', desc: 'Hosts where the rule has open signals (not suppressed, not triaged benign).' }),
          col('signals_n', 'count', { label: 'Signals', desc: one ? 'Its open signals on the host.' : 'Its open signals across those hosts.' }),
        ], s.hosts), { pageSize: 10, filename: 'rules-by-hosts' }) : h('div', { class: 'mut' }, 'No open signals.')), { collapsed: false, modules: d.top_rules.map((r) => r.module) })
      ),
      section(`Flagged items (${flags.length}) — fleet-wide`, () => flagsView(flags), { collapsed: false, modules: [CORE] }),
      section('Telemetry coverage', () => telemetryCoverage(d.telemetry, s.hosts), { collapsed: false, modules: d.telemetry.map((t) => t.module) }),
      section(one ? 'Evidence sources — what was read, and what it depends on' : 'Evidence sources — how many hosts read each',
        () => sourcesView(d.sources, one ? one.host : 'fleet'), { collapsed: false, modules: [CORE] }),
      section('Collection freshness', () => freshness(d, s.hosts), { collapsed: false, modules: [CORE] }));
  }
  await load();
}
