// The fleet inventory pages - what was observed across the selected hosts,
// one question each:
//   Autoruns - what is configured to run again (the Persistence module),
//     stacked, rarest first.
//   Applications - the software installed (the Applications module),
//     stacked, rarest first.
//   Extensions - the browser extensions installed (the Browsers module),
//     stacked, rarest first.
//   Group Policy - the GPOs in the domain controllers' SYSVOL and applied
//     to the members (the Directory module), stacked, rarest first, each
//     with its domain status.
//   Remote Access - the remote access tools found (the RemoteAccess module),
//     stacked, rarest first, and the peers their logs record, most hosts
//     first.
//   Network - what the hosts listen on and which Internet addresses they
//     talked to (the Network module).
//   Protection - what the antivirus does not scan: every exclusion, and
//     each host's count or why it is unknown (the Protection module).
//   Recovery - can each host be recovered, and did someone take that away:
//     every way back on each host, the ones a rule flagged first (the
//     Backup module).
//   Audit Policy - the effective audit policy, the event IDs it makes
//     expected and those present, and the policy's changes (LogIntegrity).
// The sticky filter bar narrows each to the chosen hosts (by name,
// operating system build and role), kept in the URL (?hosts=&os=&role=).
// Every host's latest collection is used.

import { h, fetchJSON, ts } from '../dom.js';
import { queryString, currentPage } from '../router.js';
import { canEdit } from '../session.js';
import { section, filterBar, stickyPage, summaryStrip, hostScopeFilters } from '../components.js';
import { topologyMap, subnetsView, linksView, othersView, unreadView } from './topology.js';
import { persistenceView, applicationsView, extensionsView, groupPolicyView, remoteToolsView, remotePeersView, remotePathsView, webSitesView, webScriptsView, networkView, exclusionsView, exclusionProduct, auditPolicyTabs, recoveryView } from './inventories.js';

// hostsItem is a summary strip's first item: the host in view, or how many.
const hostsItem = (chosen) => (chosen.length === 1 ? { icon: 'hosts', value: chosen[0].host, label: 'host' } : { icon: 'hosts', value: chosen.length, label: 'hosts' });

// stacked is a stacked-inventory page: cfg names the inventory's part of
// /api/inventories, its module, its noun, its card's title and its view.
const stacked = (cfg) => (container) => scopedPage(container, (inv, scope, chosen) => {
  const p = inv[cfg.part];
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'layers', value: p.total.toLocaleString(), label: cfg.noun },
      { icon: 'value', value: p.distinct.toLocaleString(), label: 'distinct' },
      chosen.length === 1 ? null : { icon: 'firstSeen', value: p.single_host.toLocaleString(), label: 'on one host only', cls: p.single_host ? 'tr-new' : null },
    ].filter(Boolean), [cfg.module]),
    section(cfg.title, () => cfg.view(p, scope, chosen.length, 'auto'), { collapsed: false, modules: [cfg.module] }), // the page's only panel: auto-height
  ];
});

export const renderAutorunsPage = stacked({
  part: 'persistence', module: 'Persistence', noun: 'persistent entries', title: 'Autoruns — what will run again, rarest first', view: persistenceView,
});

export const renderApplicationsPage = stacked({
  part: 'applications', module: 'Applications', noun: 'applications', title: 'Applications — what is installed, rarest first', view: applicationsView,
});

export const renderExtensionsPage = stacked({
  part: 'extensions', module: 'Browsers', noun: 'extensions', title: 'Browser extensions — what is installed in the browsers, rarest first', view: extensionsView,
});

export const renderGroupPolicyPage = (container) => scopedPage(container, (inv, scope, chosen) => {
  const p = inv.group_policy;
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'policy', value: p.distinct.toLocaleString(), label: 'GPOs' },
      chosen.length === 1 ? null : { icon: 'firstSeen', value: p.single_host.toLocaleString(), label: 'on one host only', cls: p.single_host ? 'tr-new' : null },
      { icon: 'notEvaluated', value: p.not_in_sysvol.toLocaleString(), label: "applied, but not in their domain controller's SYSVOL", cls: p.not_in_sysvol ? 'sev-medium' : null },
    ].filter(Boolean), ['Directory']),
    section('Group Policy — every GPO in SYSVOL or applied to a host, rarest first', () => groupPolicyView(p, scope, chosen.length, 'auto'), { collapsed: false, modules: ['Directory'] }),
  ];
});

export const renderRemoteAccessPage = (container) => scopedPage(container, (inv, scope, chosen) => {
  const r = inv.remote_access;
  const tools = { ...r.tools, modules: r.modules };
  const peers = { ...r.peers, modules: r.modules };
  const paths = { ...r.paths, modules: r.modules };
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'remote', value: r.tools.distinct.toLocaleString(), label: r.tools.distinct === 1 ? 'remote access product' : 'remote access products' },
      chosen.length === 1 ? null : { icon: 'firstSeen', value: r.tools.single_host.toLocaleString(), label: 'on one host only', cls: r.tools.single_host ? 'tr-new' : null },
      { icon: 'peer', value: r.peers.distinct.toLocaleString(), label: 'peers in their logs' },
      chosen.length === 1 ? null : { icon: 'hosts', value: r.peers.many_hosts.toLocaleString(), label: 'peers on more than one host', cls: r.peers.many_hosts ? 'sev-high' : null },
      { icon: 'key', value: r.paths.distinct.toLocaleString(), label: "of Windows' own ways in configured" },
    ].filter(Boolean), ['RemoteAccess']),
    section('Remote access tools — every product installed or run, rarest first', () => remoteToolsView(tools, scope, chosen.length), { collapsed: false, modules: ['RemoteAccess'] }),
    section('Peers — the other sides of their sessions, most hosts first', () => remotePeersView(peers, scope, chosen.length), { collapsed: false, modules: ['RemoteAccess'] }),
    section("Windows' own ways in — port forwards, SSH keys, WinRM, Remote Assistance, shadowing", () => remotePathsView(paths, scope, chosen.length), { collapsed: false, modules: ['RemoteAccess'] }),
  ];
});

export const renderWebServersPage = (container) => scopedPage(container, (inv, scope, chosen) => {
  const w = inv.web;
  const sites = { ...w.sites, modules: w.modules };
  const scripts = { ...w.scripts, modules: w.modules };
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'webapp', value: w.sites.distinct.toLocaleString(), label: w.sites.distinct === 1 ? 'web site' : 'web sites' },
      { icon: 'file', value: w.scripts.distinct.toLocaleString(), label: 'scripts with webshell indicators', cls: w.scripts.distinct ? 'sev-medium' : null },
      { icon: 'severity', value: w.scripts.high.toLocaleString(), label: 'of high confidence', cls: w.scripts.high ? 'sev-high' : null },
    ], w.modules),
    section('Scripts with webshell indicators — rarest first, the strongest first', () => webScriptsView(scripts, scope, chosen.length), { collapsed: false, modules: w.modules }),
    section('Web sites — what each serves, listens on and runs as', () => webSitesView(sites, scope, chosen.length), { collapsed: false, modules: w.modules }),
  ];
});

export const renderNetworkPage = (container) => scopedPage(container, (inv, scope, chosen) => {
  const n = inv.network;
  const total = (id) => (n.tables[id] ? n.tables[id].total : 0);
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'server', value: total('listeners').toLocaleString(), label: 'listening ports (port and program)' },
      { icon: 'globe', value: total('remote_addresses').toLocaleString(), label: 'Internet addresses (address, port and program)' },
    ], n.modules),
    section('Network — what the hosts listen on and which Internet addresses they talked to', () => networkView(n, scope, chosen.length, 'auto'), { collapsed: false, modules: n.modules }),
  ];
});

export const renderTopologyPage = (container) => scopedPage(container, (inv, scope, chosen) => {
  const t = inv.topology;
  const placed = new Set(t.subnets.flatMap((s) => s.hosts.map((x) => x.run_id)));
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'topology', value: t.subnets.length.toLocaleString(), label: t.subnets.length === 1 ? 'subnet' : 'subnets' },
      { icon: 'link', value: t.links.length.toLocaleString(), label: 'connections recorded between hosts in view' },
      { icon: 'peer', value: t.others.length.toLocaleString(), label: 'private addresses no host in view has' },
      { icon: 'hosts', value: (chosen.length - placed.size).toLocaleString(), label: 'hosts not placed', cls: chosen.length - placed.size ? 'sev-medium' : null },
    ], t.modules),
    section('Map — each subnet with its hosts, a line for each connection recorded between two of them', () => topologyMap(t) || h('div', { class: 'mut' }, 'No host in view has an adapter that is up with an IPv4 address.'), { collapsed: false, modules: t.modules }),
    section('Subnets — as the hosts configured them now', () => subnetsView(t), { collapsed: false, modules: t.modules }),
    t.links.length ? section('Connections between hosts in view', () => linksView(t), { collapsed: false, modules: t.modules }) : null,
    t.others.length ? section('Private addresses no host in view has', () => othersView(t), { collapsed: false, modules: t.modules }) : null,
    t.unread.length ? section('Hosts not placed', () => unreadView(t), { collapsed: false, modules: t.modules }) : null,
  ].filter(Boolean);
}, h('div', { class: 'topo-dev-note' }, h('b', {}, 'Under development. '), 'The Topology page is still being built and may not work in the best way yet - read the map with the tables below it, which state what each host recorded.'));

export const renderRecoveryPage = (container) => scopedPage(container, (inv, scope, chosen) => {
  const rec = inv.recovery;
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'severity', value: rec.summary.taken_away.toLocaleString(), label: rec.summary.taken_away === 1 ? 'host with recovery taken away' : 'hosts with recovery taken away', cls: rec.summary.taken_away ? 'sev-high' : null },
      { icon: 'snapshot', value: rec.summary.with_copies.toLocaleString(), label: `of ${rec.summary.hosts.toLocaleString()} with a shadow copy` },
    ], rec.modules),
    section('Ways back — every host\'s recovery as Signal read it, what a rule flagged first', () => recoveryView(rec, chosen.length), { collapsed: false, modules: rec.modules }),
  ];
});

export const renderProtectionPage = (container) => scopedPage(container, (inv, scope, chosen) => {
  const av = inv.av_exclusions;
  const product = exclusionProduct(av);
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'shield', value: av.summary.total, label: `${product} exclusions`, cls: av.summary.flagged ? 'sev-high' : null },
      { icon: 'flagged', value: av.summary.flagged, label: 'flagged by a rule', cls: av.summary.flagged ? 'sev-high' : null },
      { icon: 'notEvaluated', value: av.summary.hosts_unknown, label: chosen.length === 1 ? 'exclusions unknown' : 'hosts whose exclusions are unknown', cls: av.summary.hosts_unknown ? 'ev-absent' : null },
    ], av.modules),
    section(`${product} exclusions — what ${product} does not scan`, () => exclusionsView(av, chosen.length), { collapsed: false, modules: av.modules }),
  ];
});

export const renderAuditPage = (container) => scopedPage(container, (inv, scope, chosen) => {
  const s = inv.summary;
  const modules = [...new Set([...inv.audit_policy.modules, ...inv.event_ids.modules, ...inv.audit_policy_changes.modules, ...inv.logging_policy.modules, ...inv.event_logs.modules])];
  const one = chosen.length === 1;
  return [
    summaryStrip([
      hostsItem(chosen),
      { icon: 'id', value: s.event_ids_present, label: 'event IDs present' },
      { icon: 'notEvaluated', value: s.event_ids_absent_somewhere, label: one ? 'event IDs expected but absent' : 'event IDs expected but absent on some host', cls: s.event_ids_absent_somewhere ? 'ev-absent' : null },
      { icon: 'policy', value: s.gp_not_in_force, label: one ? 'subcategories Group Policy audits that are off' : 'subcategories Group Policy audits that are off on some host', cls: s.gp_not_in_force ? 'sev-medium' : null },
      { icon: 'status', value: inv.audit_policy_changes.rows.length, label: 'policy changes' },
      { icon: 'notEvaluated', value: s.logs_turned_off, label: one ? 'logs turned off' : 'logs turned off (host and log)', cls: s.logs_turned_off ? 'sev-medium' : null },
    ], modules),
    section('Audit policy and event IDs', () => auditPolicyTabs(inv.audit_policy, inv.event_ids, inv.audit_policy_changes, inv.logging_policy, inv.event_logs, chosen.length), { collapsed: false, modules }),
  ];
});

// reviewBar is the page's review over the chosen hosts: "Not reviewed"
// until an analyst marks it reviewed - on the hosts the filters chose (one
// host, or the fleet); the page is reviewed for the fleet only when every
// host is. A host whose inventory changed since its mark is not reviewed.
function reviewBar(r, scope, chosen, reload) {
  if (!r || r.hosts === 0) return null;
  const done = r.state === 'reviewed';
  const where = chosen.length === 1 ? 'on this host' : `on ${r.reviewed} of ${r.hosts} hosts with entries here`;
  const put = (on) => async () => {
    await fetchJSON('/api/reviews', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ page: currentPage(), hosts: scope.hosts, on }) });
    window.dispatchEvent(new window.Event('reviews-changed'));
    reload();
  };
  return h('div', { class: `card review-bar${done ? ' done' : ''}` },
    h('span', { class: 'review-state' }, done ? 'Reviewed' : 'Not reviewed'),
    h('span', { class: 'mut' }, done ? `${where}${r.reviewed_by ? ` - last marked by ${r.reviewed_by}, ${ts(r.at)}` : ''}` : `${where} reviewed. Review the table, then mark it: a host's mark holds until its inventory changes.`),
    canEdit() ? h('button', { class: done ? 'ghost' : 'btn', onclick: put(!done), title: chosen.length === 1 ? 'For this host only' : 'For every host the filters chose' }, done ? 'Mark not reviewed' : 'Mark reviewed') : null);
}

// scopedPage is one such page under the host filters: draw(inv, scope,
// chosen) builds its content from /api/inventories for the chosen hosts.
// note, when given, stands first on the page, above the filter bar.
async function scopedPage(container, draw, note) {
  const runs = (await fetchJSON('/api/runs')).filter((r) => r.latest);
  const scopeFilters = hostScopeFilters(runs, () => load());
  const body = h('div');
  const bar = filterBar(scopeFilters.fields);

  let generation = 0;
  async function load() {
    const mine = ++generation;
    const chosen = scopeFilters.selected();
    if (chosen.length === 0) {
      body.replaceChildren(h('div', { class: 'card mut' }, runs.length ? 'No imported host matches the filters.' : 'No hosts yet - import a Signal run first.'));
      return;
    }
    const scope = { hosts: chosen.length === runs.length ? '' : chosen.map((r) => r.run_id).join(','), modules: '' };
    const [inv, reviews] = await Promise.all([fetchJSON(`/api/inventories?${queryString(scope)}`), fetchJSON(`/api/reviews?${queryString({ hosts: scope.hosts })}`)]);
    if (mine !== generation) return; // a newer filter choice is already loading
    body.replaceChildren(...[reviewBar(reviews[currentPage()], scope, chosen, load), ...draw(inv, scope, chosen)].filter(Boolean)); // no review bar on a page not reviewed (Topology)
  }

  stickyPage(container, bar);
  container.replaceChildren(...(note ? [note] : []), bar, body);
  await load();
}
