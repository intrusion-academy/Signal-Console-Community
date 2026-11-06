// The inventory views: what was observed across the selected hosts,
// grouped by value - the audit policy (a tab per category), the event IDs
// and the policy's changes, the logons, the network, the antivirus
// exclusions, the persistent entries and the applications - each naming the
// module(s) its data came from. The pages that show them are
// inventoryPages.js (Audit Policy, Network, Protection, Autoruns,
// Applications), users.js (the logons) and hosts.js (one host's). Raw
// process and command-line inventories are not collected: Signal reports
// what its rules matched (the Signals page), not data that would need
// analysing in its own right.

import { h, fetchJSON } from '../dom.js';
import { queryString } from '../router.js';
import { EVENT_STATUS, sourceLine, tabbedPanel, detailBlock, hostLink, trendChart } from '../components.js';
import { dataTable, col, forHosts } from '../table.js';

// withHosts adds the host columns' plain values to an inventory row: the
// host count (seen_n) and their names (host_names, for search and CSV).
function withHosts(row, hosts) {
  return { ...row, hosts, seen_n: hosts.length, host_names: hosts.map((x) => x.host).join('; ') };
}

// hostGroups is an expanded row's per-state host lists: [[title, hosts,
// cls]], each shown only when it has hosts.
function hostGroups(groups) {
  return h('div', { class: 'detail' }, groups.filter(([, hosts]) => hosts.length).map(([title, hosts, cls]) =>
    detailBlock(null, h('div', { class: 'detail-title' + (cls ? ' ' + cls : '') }, title, ` (${hosts.length})`), h('div', {}, hosts.flatMap((x, i) => [i ? ', ' : '', hostLink(x)])))));
}

// inventoryView is one inventory's content: its source modules, then its
// table (20 rows per page, unless opts says otherwise) - or a note when no
// selected run has the data.
function inventoryView(modules, rows, columns, opts) {
  return h('div', {}, sourceLine(modules),
    rows.length ? dataTable(rows, columns, { pageSize: 20, ...opts }) : h('div', { class: 'mut' }, 'No selected run has this data.'));
}

// AUDIT_CATEGORIES is the advanced audit policy's categories in Windows'
// own order (auditpol /get /category:*); a category not listed follows.
const AUDIT_CATEGORIES = ['System', 'Logon/Logoff', 'Object Access', 'Privilege Use', 'Detailed Tracking', 'Policy Change', 'Account Management', 'DS Access', 'Account Logon'];
const categoryRank = (c) => (AUDIT_CATEGORIES.includes(c) ? AUDIT_CATEGORIES.indexOf(c) : AUDIT_CATEGORIES.length);

// policyByCategory is the effective audit policy, one tab per category,
// each listing only its own subcategories - for several hosts, how many
// audit each; for one, whether it does (a row's hosts need no expanding).
function policyByCategory(ap, hostCount) {
  const rows = ap.rows.map((r) => ({ ...r, success_n: r.success.length, failure_n: r.failure.length, off_n: r.off.length, gp_off_n: r.gp_off.length }));
  const categories = [...new Set(rows.map((r) => r.category))].sort((a, b) => categoryRank(a) - categoryRank(b) || a.localeCompare(b));
  if (!categories.length) return inventoryView(ap.modules, [], []);
  const layered = ap.rows.some((r) => r.group_policy || r.local_gpo);
  const columns = forHosts([col('subcategory'), col('success_n'), col('failure_n'), col('off_n'),
    ...(layered ? [col('local_gpo'), col('group_policy', 'gp_audit'), col('gp_off_n')] : []), col('event_ids')], hostCount);
  return h('div', {}, sourceLine(ap.modules), tabbedPanel(categories.map((c) => {
    const mine = rows.filter((r) => r.category === c);
    return {
      id: c, title: c, count: mine.length,
      build: () => dataTable(mine, columns, {
        height: 'auto', filename: `audit_policy_${c.toLowerCase().replace(/[^a-z]+/g, '_')}`,
        detail: hostCount === 1 ? null : (r) => hostGroups([['Success audited on', r.success, 'st-ran'], ['Failure audited on', r.failure, 'st-ran'], ['Not audited on', r.off, 'st-notrun'],
          ["Group Policy's setting off on", r.gp_off, 'sev-medium']]),
      }),
    };
  }), 'sub'));
}

// EVENT_VIEWS are the event IDs tab's "Show" choices: every event ID the
// policy expects or the logs hold, or one kind of them.
const EVENT_VIEWS = [
  ['', 'every event ID', () => true],
  ['present', 'present in the logs', (r) => r.present_n > 0],
  ['absent', 'expected but absent somewhere', (r) => r.absent_n > 0],
  ['policy_off', 'present with the policy off somewhere', (r) => r.policy_off_n > 0],
  ['flagged', 'flagged by a rule', (r) => r.flagged_by.length > 0],
];
const oneHostView = (label) => label.replace(' somewhere', '').replace('the logs', 'the log');

// eventIdView is every event ID - expected by the policy, present in the
// logs, or both - in one table, 10 per page, with a Show filter; for
// several hosts each row expands to its hosts per status.
function eventIdView(ev, hostCount) {
  const rows = ev.rows.map((r) => {
    const st = (s) => r.statuses[s] || [];
    return {
      ...withHosts(r, r.present), expected_n: r.expected.length, present_n: r.present.length,
      absent_n: st('absent').length + st('absent_common').length, policy_off_n: st('present_policy_off').length,
    };
  });
  const one = hostCount === 1;
  const columns = forHosts([col('event_id'), col('subcategories'), col('flagged_rules', 'flagged_by'), col('expected_n'), col('present_n'), col('absent_n'), col('policy_off_n'),
    col('count', 'count', { desc: one ? 'How many times the event is in the host\'s log.' : 'How many times the event is in the logs, across every host where it is present.' }), col('first_seen'), col('last_seen')], hostCount);
  const slot = h('div');
  const draw = (view) => {
    const keep = EVENT_VIEWS.find(([k]) => k === view)[2];
    slot.replaceChildren(dataTable(rows.filter(keep), columns, {
      height: 'auto', filename: 'event_ids',
      detail: one ? null : (r) => hostGroups(Object.keys(EVENT_STATUS).map((s) => [EVENT_STATUS[s], r.statuses[s] || [], 'ev-' + s])),
    }));
  };
  draw('');
  return h('div', {}, sourceLine(ev.modules),
    h('div', { class: 'row view-filters' }, h('label', {}, h('span', { class: 'mut' }, 'Show'),
      h('select', { onchange: (e) => draw(e.target.value) }, EVENT_VIEWS.map(([k, label]) => h('option', { value: k }, one ? oneHostView(label) : label))))),
    slot);
}

// changesView is the audit policy changes, newest first: when, (on which
// host,) what changed and how - "Changed by" left out when every change was
// the computer's own (Group Policy), which the How column already says.
function changesView(changes, hostCount) {
  const byAccount = changes.rows.some((r) => !String(r.changed_by || '').endsWith('$'));
  const columns = forHosts([col('time', 'change_time'), col('host'), col('subcategory'), col('changes', 'audit_changes'),
    byAccount ? col('changed_by', 'subject', { label: 'Changed by', desc: 'The account that changed the policy; the computer\'s own account (ending in $) is Group Policy being applied.' }) : null,
    col('via', 'audit_via')].filter(Boolean), hostCount);
  return inventoryView(changes.modules, changes.rows, columns, { height: 'auto', filename: 'audit_policy_changes' });
}

// loggingView is each host's logging settings by layer of policy: the
// setting's own value, Group Policy's, the one in force and what decides it.
function loggingView(lp, hostCount) {
  const columns = forHosts([col('setting', 'log_setting'), col('host'), col('local', 'layer_local'), col('group_policy', 'layer_gp'),
    col('in_force', 'layer_in_force'), col('decided_by', 'layer_decided_by')], hostCount);
  return inventoryView(lp.modules, lp.rows, columns, { height: 'auto', filename: 'logging_policy' });
}

// eventLogsView is each host's other event logs: whether each records,
// its size and limit, and how far back its oldest record reaches.
function eventLogsView(el, hostCount) {
  const columns = forHosts([col('log', 'log_name'), col('host'), col('recording', 'log_recording'), col('read_by', 'log_read_by'), col('size_mb', 'log_size_mb'),
    col('max_size_mb', 'log_max_mb'), col('when_full', 'log_when_full'), col('records', 'log_records'), col('oldest_record', 'log_oldest'), col('window_days', 'log_window')], hostCount);
  return inventoryView(el.modules, el.rows, columns, { height: 'auto', filename: 'event_logs' });
}

// auditPolicyTabs is the audit policy, event ID, policy change, logging
// policy and event log inventories - small enough to be sent whole - as
// one panel: the policy (a tab per category inside), every event ID
// expected or present, the changes made to the policy (event 4719), the
// logging settings by layer of policy, and the other event logs.
export function auditPolicyTabs(ap, ev, changes, logging, logs, hostCount) {
  return tabbedPanel([
    { id: 'policy', title: 'Audit policy', count: ap.rows.length, build: () => policyByCategory(ap, hostCount) },
    { id: 'events', title: 'Event IDs — expected by policy and present in the logs', count: ev.rows.length, build: () => eventIdView(ev, hostCount) },
    { id: 'changes', title: 'Policy changes', count: changes.rows.length, build: () => changesView(changes, hostCount) },
    { id: 'layers', title: 'Logging policy by layer', count: logging.rows.length, build: () => loggingView(logging, hostCount) },
    { id: 'logs', title: 'Other event logs', count: logs.rows.length, build: () => eventLogsView(logs, hostCount) },
  ]);
}

// Filters of the identity inventories, applied on the server (see
// src/model/inventories.js's queryRows). "Seen on" finds the rare values -
// on a fleet of similar hosts, what appears on just one stands out; "First
// seen" finds the new ones, counted back from the latest collection among
// the selected hosts.
const RARITY = [['', 'any number of hosts'], ['seen_hosts=1', 'only 1 host'], ['seen_hosts=2', '2 hosts'], ['max_pct=5', 'under 5% of hosts'], ['max_pct=10', 'under 10% of hosts'], ['max_pct=20', 'under 20% of hosts']];
const NEWNESS = [['', 'any time'], ['1', 'within 1 day'], ['7', 'within 7 days'], ['30', 'within 30 days']];

// pagedInventory is one server-paged inventory table (GET url, within the
// page's scope) under its source modules and a filter row: how many hosts
// a row was seen on (rarity) and, for an inventory with times (timed), how
// recently it was first seen. height: the table's dataTable height ('auto',
// 'scroll'), or none - 20 rows a page.
function pagedInventory(url, filename, modules, columns, scope, hostCount, timed = true, height = undefined) {
  const f = { rarity: '', new_days: '' };
  const params = () => {
    const [rk, rv] = f.rarity ? f.rarity.split('=') : [];
    return { ...scope, ...(rk ? { [rk]: rv } : {}), new_days: f.new_days };
  };
  const slot = h('div');
  const cols = forHosts(columns, hostCount);
  const redraw = () => slot.replaceChildren(dataTable([], cols, {
    pageSize: 20, height, filename, remote: (req) => fetchJSON(`${url}?${queryString({ ...params(), ...req })}`),
  }));
  const choose = (key, options) => h('select', { onchange: (e) => { f[key] = e.target.value; redraw(); } },
    options.map(([v, t]) => h('option', { value: v, selected: f[key] === v ? 'selected' : null }, t)));
  redraw();
  return h('div', {}, sourceLine(modules),
    h('div', { class: 'row view-filters' },
      hostCount === 1 ? null : h('label', {}, h('span', { class: 'mut' }, 'Seen on'), choose('rarity', RARITY)), // how many hosts means nothing for one
      timed ? h('label', {}, h('span', { class: 'mut' }, 'First seen'), choose('new_days', NEWNESS), h('span', { class: 'mut' }, 'of the latest collection')) : null),
    slot);
}

// persistenceView is the persistent entries (Signal's
// inventory.persistence), stacked across the hosts by the server, rarest
// first: each entry configured the same way once, with how many hosts have
// it. Windows' own entries are left out by Signal. hostCount: hosts in view
// (the host page leaves it out - each entry keeps its fleet-wide count).
// height: the table's (pagedInventory).
export function persistenceView(p, scope, hostCount, height) {
  if (!p.hosts) return h('div', { class: 'mut' }, 'No selected host ran the Persistence module.');
  const columns = [col('flagged'), col('location'), col('entry'), col('command'), col('signer'), col('signature'), col('sha256'),
    col('user', 'user', { label: 'Whose / runs as', desc: 'Whose entry it is (a user\'s registry or folder), or the account a service or task runs as.', render: (v) => v || '—' }),
    col('seen_n', 'seen_n', { desc: 'How many of the selected hosts have this entry, configured the same way - the fewer, the more it stands out.' }), col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${p.total.toLocaleString()} entries on ${p.hosts} host${p.hosts === 1 ? '' : 's'}, ${p.distinct.toLocaleString()} distinct${p.hosts === 1 ? '' : ` (${p.single_host.toLocaleString()} on only one host)`}, rarest first.`),
    h('p', { class: 'mut card-intro' }, 'Windows\' own entries - signed by Microsoft, in Windows\' or Program Files\' folders, not a script host - are left out by Signal (Persistence.all=true lists them).'),
    pagedInventory('/api/inventories/persistence', 'persistence', p.modules, columns, scope, hostCount, false, height));
}

// applicationsView is the installed applications (Signal's
// inventory.applications), stacked across the hosts by the server, rarest
// first: each application (name and publisher) once, with how many hosts
// have it. Windows' own Store packages are left out by Signal. height: the
// table's (pagedInventory).
export function applicationsView(a, scope, hostCount, height) {
  if (!a.hosts) return h('div', { class: 'mut' }, 'No selected host ran the Applications module.');
  const columns = [col('flagged'), col('name', 'app_name'), col('publisher'), col('versions', 'app_versions'), col('location', 'app_location'), col('installed'), col('in_period'), col('kev', 'app_kev'), col('user', 'app_user'),
    col('seen_n', 'seen_n', { desc: 'How many of the selected hosts have this application - the fewer, the more it stands out.' }), col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${a.total.toLocaleString()} applications on ${a.hosts} host${a.hosts === 1 ? '' : 's'}, ${a.distinct.toLocaleString()} distinct${a.hosts === 1 ? '' : ` (${a.single_host.toLocaleString()} on only one host)`}, rarest first.`),
    h('p', { class: 'mut card-intro' }, 'Read from the uninstall keys of the machine and every user, Windows Installer and the users\' Store packages; Windows\' own Store packages are left out by Signal.'),
    a.kev && a.kev.old ? h('p', { class: 'card-intro sev-medium' }, `Known exploited (CISA): the catalog is ${a.kev.age_days} days old (released ${a.kev.released.slice(0, 10)}) - vulnerabilities CISA added since are not checked. Update it on Settings, Known exploited vulnerabilities.`) : null,
    pagedInventory('/api/inventories/applications', 'applications', a.modules, columns, scope, hostCount, false, height));
}

// extensionsView is the browser extensions stacked across the hosts (or on
// one, with its fleet counts), rarest first. height: the table's.
export function extensionsView(e, scope, hostCount, height) {
  if (!e.hosts) return h('div', { class: 'mut' }, 'No selected host ran the Browsers module.');
  const columns = [col('flagged'), col('names', 'ext_names'), col('id', 'ext_id'), col('browsers', 'ext_browsers'), col('installed_by', 'ext_installed_by'),
    col('versions', 'app_versions'), col('installed', 'ext_installed'), col('in_period'), col('capabilities', 'ext_capabilities'), col('update_url', 'ext_update_url'), col('forced_by', 'ext_forced_by'),
    col('user', 'ext_user'), col('seen_n', 'seen_n', { desc: 'How many of the selected hosts have this extension - the fewer, the more it stands out.' }), col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${e.total.toLocaleString()} extensions on ${e.hosts} host${e.hosts === 1 ? '' : 's'}, ${e.distinct.toLocaleString()} distinct${e.hosts === 1 ? '' : ` (${e.single_host.toLocaleString()} on only one host)`}, rarest first.`),
    h('p', { class: 'mut card-intro' }, 'Read from every profile of every Chromium- and Gecko-based browser of every user - the browser\'s own records and each extension\'s manifest; the browsers\' own extensions are left out by Signal. What an extension may do is what its permissions allow, not what it did.'),
    pagedInventory('/api/inventories/extensions', 'extensions', e.modules, columns, scope, hostCount, false, height));
}

// groupPolicyView is the Group Policy objects across the hosts: one row
// per GPO, its domain status, what it deploys and where it is linked.
export function groupPolicyView(g, scope, hostCount, height) {
  if (!g.hosts) return h('div', { class: 'mut' }, 'No selected host ran the Directory module.');
  const columns = [col('flagged'), col('names', 'gpo_names'), col('guid', 'gpo_guid'), col('domain_status', 'gpo_status'), col('deploys', 'gpo_deploys'),
    col('links', 'gpo_links'), col('extensions', 'gpo_extensions'), col('versions', 'gpo_versions'), col('changed_by', 'gpo_changed_by'),
    col('created', 'gpo_created'), col('changed', 'gpo_changed'), col('applied', 'gpo_applied'), col('in_period'),
    col('seen_n', 'seen_n', { desc: 'How many of the selected hosts have this GPO - in their SYSVOL (a domain controller) or applied (a member).' }), col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${g.distinct.toLocaleString()} GPOs on ${g.hosts} host${g.hosts === 1 ? '' : 's'}${g.hosts === 1 ? '' : ` (${g.single_host.toLocaleString()} on only one host)`}, rarest first.`),
    h('p', { class: 'mut card-intro' }, "A domain controller lists every GPO in its SYSVOL; a member, every GPO Group Policy applied to it - from Group Policy's own records and copies, which keep a GPO deleted since. Signal never queries the directory: a GPO a member applied that is missing from the SYSVOL of its domain controller, collected after it applied, was deleted or has not replicated there - the Domain status says so."),
    pagedInventory('/api/inventories/grouppolicy', 'group_policy', g.modules, columns, scope, hostCount, false, height));
}

// remoteToolsView is the remote access products across the hosts: one row
// per product, how it is on each host, who it is enrolled to, its sessions.
export function remoteToolsView(r, scope, hostCount, height) {
  if (!r.hosts) return h('div', { class: 'mut' }, 'No selected host ran the RemoteAccess module.');
  const columns = [col('flagged'), col('product', 'ra_product'), col('kind', 'ra_kind'), col('modes', 'ra_modes'), col('portable', 'ra_portable'),
    col('installed', 'ra_installed'), col('first_seen', 'ra_first_seen'), col('last_seen', 'ra_last_seen'), col('accounts', 'ra_accounts'),
    col('tenants', 'ra_tenants'), col('servers', 'ra_servers'), col('unattended_n', 'ra_unattended'), col('sessions', 'ra_sessions'), col('allowed', 'ra_allowed'),
    col('seen_n', 'seen_n', { desc: 'How many of the selected hosts have this product - the fewer, the more it stands out.' }), col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${r.distinct.toLocaleString()} product${r.distinct === 1 ? '' : 's'} on ${r.hosts} host${r.hosts === 1 ? '' : 's'}${r.hosts === 1 ? '' : ` (${r.single_host.toLocaleString()} on only one host)`}, rarest first.`),
    h('p', { class: 'mut card-intro' }, "Each product is found installed or run portable - by its program's version resource, so a renamed copy is still found - from installations, services, program runs, the process table and its own folders, configuration and logs. Its configuration's passwords and keys are never read: only that one is set. Sessions are what the product's own log kept, and only for the products whose logs Signal reads."),
    pagedInventory('/api/inventories/remotetools', 'remote_tools', r.modules, columns, scope, hostCount, false, height));
}

// webSitesView is the web sites across the hosts: one row per site (its
// server, name and folders), with what it listens on, runs as and holds.
export function webSitesView(w, scope, hostCount, height) {
  if (!w.hosts) return h('div', { class: 'mut' }, 'No selected host ran the Webshells module.');
  const columns = [col('flagged'), col('server', 'web_server'), col('versions', 'web_versions'), col('site', 'web_site'), col('roots', 'web_roots'),
    col('bindings', 'web_bindings'), col('identities', 'web_identities'), col('holds', 'web_holds'), col('last_deployment', 'web_last_deployment'),
    col('flagged_scripts', 'web_flagged'), col('detections', 'web_detections'), col('running', 'web_running'), col('files', 'web_files'),
    col('seen_n', 'seen_n', { desc: 'How many of the selected hosts serve this site from the same folders - a web farm is one row.' }), col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${w.distinct.toLocaleString()} site${w.distinct === 1 ? '' : 's'} on ${w.hosts} host${w.hosts === 1 ? '' : 's'}${w.hosts === 1 ? '' : ` (${w.single_host.toLocaleString()} on only one host)`}, rarest first.`),
    h('p', { class: 'mut card-intro' }, "Each site as its server's configuration declares it - IIS's applicationHost.config, Apache httpd's, nginx's and Tomcat's files - with the walk of its folders. A host that ran the module with no row has no web server Signal recognises."),
    pagedInventory('/api/inventories/websites', 'web_sites', w.modules, columns, scope, hostCount, false, height));
}

// webScriptsView is the scripts with webshell indicators across the hosts:
// one row per path, rarest first, the strongest first among equals.
export function webScriptsView(w, scope, hostCount, height) {
  if (!w.hosts) return h('div', { class: 'mut' }, 'No selected host ran the Webshells module.');
  const columns = [col('flagged'), col('confidence', 'web_confidence'), col('file', 'web_file'), col('sites', 'web_sites'), col('urls', 'web_urls'),
    col('indicators', 'web_indicators'), col('requests', 'web_requests'), col('created', 'web_created'), col('modified', 'web_modified'),
    col('seen_n', 'seen_n', { desc: 'How many of the selected hosts have a script at this path - the same script on several servers was put there more than once.' }), col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${w.distinct.toLocaleString()} script${w.distinct === 1 ? '' : 's'} with indicators on ${w.hosts} host${w.hosts === 1 ? '' : 's'}, ${w.high.toLocaleString()} of high confidence.`),
    h('p', { class: 'mut card-intro' }, "Judged by each script's place, times, attributes, the requests IIS's log records for it and the antivirus - its content is not read. A webshell written with a site's deployment, in an ordinary folder, carries none of these; scripts with no indicator are counted on their site, not listed."),
    pagedInventory('/api/inventories/webscripts', 'web_scripts', w.modules, columns, scope, hostCount, false, height));
}

// remotePathsView is Windows' own ways in across the hosts: one row per
// kind and value, rarest first.
export function remotePathsView(p, scope, hostCount, height) {
  if (!p.hosts) return h('div', { class: 'mut' }, 'No selected host ran the RemoteAccess module.');
  const columns = [col('flagged'), col('kind', 'ra_path_kind'), col('path_value', 'ra_path_value'), col('details', 'ra_path_detail'), col('users', 'ra_path_user'),
    col('last_changed', 'ra_path_changed'), col('places', 'ra_path_where'),
    col('seen_n', 'seen_n', { desc: 'How many of the selected hosts have it configured - the fewer, the more it stands out.' }), col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${p.distinct.toLocaleString()} configured on ${p.hosts} host${p.hosts === 1 ? '' : 's'}${p.hosts === 1 ? '' : ` (${p.single_host.toLocaleString()} on only one host)`}, rarest first.`),
    h('p', { class: 'mut card-intro' }, "Windows' own ways into a host, as configured now: port forwards, SSH keys the OpenSSH server accepts (named by fingerprint - the key is never read), WinRM's listeners and relaxations, Remote Assistance, Remote Desktop shadowing. Windows' defaults are not listed. What each allows, not that anyone used it."),
    pagedInventory('/api/inventories/remotepaths', 'remote_paths', p.modules, columns, scope, hostCount, false, height));
}

// remotePeersView is the other sides of remote access sessions across the
// hosts: one row per product ID, most hosts first.
export function remotePeersView(p, scope, hostCount, height) {
  if (!p.hosts) return h('div', { class: 'mut' }, 'No selected host ran the RemoteAccess module.');
  const columns = [col('flagged'), col('product', 'ra_product'), col('peer_id', 'ra_peer_id'), col('peer_names', 'ra_peer_names'), col('addresses', 'ra_addresses'),
    col('sessions_n', 'ra_sessions_n'), col('incoming_n', 'ra_incoming_n'), col('with_transfers_n', 'ra_with_transfers'), col('auths', 'ra_auths'),
    col('first_start', 'ra_first_start'), col('last_start', 'ra_last_start'),
    col('seen_n', 'seen_n', { desc: 'How many of the selected hosts it had sessions with - more than one: one party reaching several hosts, which no single host shows.', render: (v) => (v > 1 ? h('b', { class: 'tagtext sev-high' }, String(v)) : String(v)) }),
    col('host_names')];
  return h('div', {},
    h('p', { class: 'card-intro' }, `${p.distinct.toLocaleString()} peer${p.distinct === 1 ? '' : 's'} in ${p.total.toLocaleString()} session${p.total === 1 ? '' : 's'}, most hosts first.`),
    h('p', { class: 'mut card-intro' }, "A peer is the product's own ID for the other side of a session - the same whichever host it connects to. The address is the one the product recorded: the other side's, or the vendor's relay it came through. Only what the products' logs kept, on the hosts whose logs were read."),
    pagedInventory('/api/inventories/remotepeers', 'remote_peers', p.modules, columns, scope, hostCount, false, height));
}

// LOGON_COLUMNS are the logon inventories' columns, per table.
const hostCols = () => [col('seen_n'), col('host_names')];
const timeCols = () => [col('first_seen'), col('last_seen')];
const LOGON_COLUMNS = {
  logons: () => [col('account', 'user'), col('scope'), col('type_name'), col('source', 'logon_source'), col('source_scope'), col('auth_package'),
    col('count', 'count', { desc: 'Successful logons, across every selected host.' }), col('elevated'), ...hostCols(), ...timeCols()],
  failures: () => [col('account', 'user'), col('type_name'), col('source', 'logon_source'), col('source_scope'), col('reason', 'failure_reason'),
    col('count', 'count', { desc: 'Failed logons, across every selected host.' }), ...hostCols(), ...timeCols()],
  explicit: () => [col('subject'), col('account', 'user'), col('target_server'), col('process'), col('count'), ...hostCols(), ...timeCols()],
  privileged: () => [col('account', 'user'), col('scope'), col('count', 'count', { desc: 'Logons given administrative privileges (4672).' }), ...hostCols(), ...timeCols()],
  rdp_sessions: () => [col('account', 'user'), col('how', 'session_how'), col('source', 'logon_source'), col('source_scope'), col('event', 'rdp_event'),
    col('count', 'count', { desc: 'Records of this step, across every selected host.' }), ...hostCols(), ...timeCols()],
  rdp_outbound: () => [col('account', 'user'), col('sid'), col('server', 'rdp_server'), col('event', 'rdp_event'),
    col('count', 'count', { desc: 'Records of this step, across every selected host.' }), ...hostCols(), ...timeCols()],
};

// logonsView is the logon inventories: the fleet's daily trend, then each
// Logons table across the hosts - one tab each.
export function logonsView(logons, scope, hostCount) {
  const where = hostCount === 1 ? 'on the host' : 'across the selected hosts';
  return tabbedPanel([
    { id: 'trend', title: 'Trend', count: logons.trend.length, build: () => h('div', {}, sourceLine(logons.modules), trendChart(logons.trend, { title: `Logons and failed logons per day ${where}` })) },
    ...Object.entries(logons.tables).map(([id, t]) => ({
      id, title: t.title, count: t.total,
      build: () => pagedInventory(`/api/inventories/logons/${id}`, `logons_${id}`, logons.modules, LOGON_COLUMNS[id](), scope, hostCount),
    })),
  ]);
}

// NETWORK_COLUMNS are the network inventories' columns, per table.
const NETWORK_COLUMNS = {
  listeners: () => [col('flagged'), col('protocol', 'net_protocol'), col('address', 'net_address'), col('port', 'net_port'), col('program', 'net_program'), col('signer'), col('signature'), ...hostCols()],
  remote_addresses: () => [col('flagged'), col('address', 'net_address'), col('port', 'net_port'), col('program', 'net_program'),
    col('records', 'net_records'), col('seen_in', 'net_seen_in'), ...hostCols(), ...timeCols()],
  internal_addresses: () => [col('address', 'net_address', { desc: "A private address the hosts were connected with: another host of the organisation's networks (10/8, 172.16/12, 192.168/16, fc00::/7). The Topology page names the ones a host in view has." }),
    col('port', 'net_port'), col('program', 'net_program'), col('records', 'net_records'), col('seen_in', 'net_seen_in'), ...hostCols(), ...timeCols()],
};

// networkView is the network inventories: each Network table across the
// hosts - one tab each. height: the tables' (pagedInventory).
export function networkView(network, scope, hostCount, height) {
  return tabbedPanel(Object.entries(network.tables).map(([id, t]) => ({
    id, title: t.title, count: t.total,
    build: () => pagedInventory(`/api/inventories/network/${id}`, `network_${id}`, network.modules, NETWORK_COLUMNS[id](), scope, hostCount, id !== 'listeners', height),
  })));
}

// recoveryView is every way back on the chosen hosts, one row per host and
// mechanism - its state exactly as Signal worded it, what decides it, its
// storage and newest point in time, and the Backup rules that flagged it -
// the flagged ones first.
export function recoveryView(rec, hostCount) {
  if (!rec.rows.length) return h('div', { class: 'mut' }, 'No recovery state - run Signal with the Backup module (0.47.0 and later).');
  const columns = forHosts([
    col('host'),
    col('mechanism', 'details', { label: 'Way back', icon: 'lifebuoy', desc: 'The recovery mechanism: a volume\'s shadow copies, System Restore, the Windows Recovery Environment, boot recovery, File History, Windows Backup or a service they run on.', wrap: false }),
    col('recovery_state', 'details', { label: 'State', desc: 'Its state exactly as Signal read it - "none on this volume" is not "taken away", and "not read" is unknown, never off.' }),
    col('flagged_by', 'flagged_by', { label: 'Flagged by', desc: 'The Backup rules that flagged it on this host; each opens the rule.' }),
    col('decided_by', 'details', { label: 'Decided by', desc: 'What sets the state: a policy key, the boot configuration, ReAgent.xml, WMI, the service table, Windows Backup\'s log.' }),
    col('storage', 'details', { label: 'Storage', desc: 'A volume\'s shadow copy storage: used, and the most it may grow to.' }),
    col('point_in_time', 'time', { label: 'Newest point', desc: `The newest shadow copy, or the last successful backup (UTC).` }),
  ], hostCount);
  return h('div', {}, sourceLine(rec.modules), dataTable(rec.rows, columns, { height: 'auto', filename: 'recovery', rowKey: (r) => r.run_id + '|' + r.mechanism }));
}

// exclusionProduct names the antivirus product(s) the exclusions are
// configured in, by their official name as the data records it (Microsoft
// Defender Antivirus - today Signal's only exclusions reader); "Antivirus"
// when no exclusion was read to name one.
export const exclusionProduct = (av) => [...new Set(av.rows.map((r) => r.product).filter(Boolean))].sort().join(', ') || 'Antivirus';

// exclusionRow is a host's exclusion state as a table row: its count, or -
// for CSV and sorting - why it is not known.
const exclusionRow =(x) => ({ ...x, exclusions_n: x.state === 'read' ? x.n : x.state.replace('_', ' '), exclusion_reason: x.reason });

// exclusionsView is the antivirus exclusions: every exclusion configured
// on the selected hosts (flagged ones first; for several hosts, on which),
// and each host's count - or why its exclusions are unknown.
export function exclusionsView(av, hostCount) {
  const columns = forHosts([col('flagged'), col('exclusion'), col('kind', 'exclusion_kind'), col('product'), col('flagged_rules', 'flagged_by', { desc: 'The rules that flagged the exclusion as risky on at least one host; each opens the rule.' }),
    col('seen_n'), col('host_names')], hostCount);
  const hostColumns = [col('host'), col('exclusions_n'), col('exclusion_reason')];
  const unknown = av.hosts.filter((x) => x.state !== 'read').length;
  return tabbedPanel([
    { id: 'exclusions', title: 'Exclusions', count: av.rows.length,
      build: () => h('div', {}, sourceLine(av.modules),
        av.rows.length ? dataTable(av.rows, columns, { pageSize: 20, filename: 'av_exclusions' })
          : h('div', { class: 'mut' }, unknown ? 'No exclusion on the hosts whose exclusions were read; the others are unknown (see Per host).' : 'No exclusion is configured on the selected hosts.')) },
    { id: 'hosts', title: 'Per host', count: av.hosts.length,
      build: () => h('div', {}, sourceLine(av.modules), dataTable(av.hosts.map(exclusionRow), hostColumns, { pageSize: 20, filename: 'av_exclusions_per_host' })) },
  ]);
}

// hostExclusionsView is one host's antivirus exclusions (the Hosts page):
// each exclusion with how many hosts of the fleet share it and the rules
// that flagged it - or, when the host's exclusions could not be read, why
// (unknown, never "none"). av is the inventory narrowed to the host
// (/api/inventories?on_host=).
export function hostExclusionsView(av) {
  const x = av.hosts[0];
  if (!x || x.state !== 'read') {
    return h('div', { class: 'mut' }, h('span', { class: 'tagtext ev-absent' }, 'Unknown'), ` - ${x ? x.reason : 'not collected'}`);
  }
  if (!av.rows.length) return h('div', {}, sourceLine(av.modules), h('div', { class: 'mut' }, 'No exclusion is configured in the host\'s antivirus.'));
  return h('div', {}, sourceLine(av.modules), dataTable(av.rows, [col('flagged'), col('exclusion'), col('kind', 'exclusion_kind'), col('product'),
    col('flagged_rules', 'flagged_by', { desc: 'The rules that flagged the exclusion as risky; each opens the rule.' }),
    col('seen_n', 'seen_n', { label: 'On hosts', desc: 'How many hosts of the fleet have the same exclusion - one is this host alone.' }), col('host_names')],
  { pageSize: 20, filename: 'av_exclusions_host' }));
}
