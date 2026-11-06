// The Users page: every account that used the fleet's hosts - one row per
// account, however many hosts it used (a domain account is one user) - and,
// at /users?user=<key>, one account's own page: how each host knows it, its
// logon trend, how and from where it logged on, what failed, and the
// signals about it. Built from the Users and Logons modules' tables (see
// src/model/users.js); every host's latest collection.
//
// Accounts that are not people's - Windows' own identities, groups,
// computers, default accounts never enabled or used - are left out, and
// listed below the table with the reason, so nothing is hidden without
// saying why.

import { h, fetchJSON, ts, mono, svgIcon } from '../dom.js';
import { logonsView } from './inventories.js';
import { pageLink, urlParams, setParams, go } from '../router.js';
import {
  section, filterBar, stickyPage, summaryStrip, checkboxDropdown, selectionFromUrl, factCard, trendChart, moduleBadge,
} from '../components.js';
import { dataTable, col, forHosts } from '../table.js';
import { signalTable } from './signals.js';

const MODULES = ['Users', 'Logons'];

// SHOW is the list's "Show" filter: a key (kept in the URL), its wording,
// and which users it keeps.
const SHOW = [
  ['', 'every user', () => true],
  ['admins', 'administrators somewhere', (u) => u.admin_n > 0],
  ['logged_on', 'signed in now', (u) => u.logged_on_n > 0],
  ['signals', 'with signals', (u) => u.signals_n > 0],
  ['failures', 'with failed logons', (u) => u.failures > 0],
  ['notes', 'with notes', (u) => u.notes_n > 0],
  ['rare', 'on one host only', (u) => u.seen_n === 1],
];

const LIST_COLUMNS = [
  col('account', 'user'), col('scope'), col('kind', 'account_kind'), col('seen_n', 'seen_n', { label: 'On hosts', desc: 'How many hosts the account used.' }),
  col('host_names'), col('admin_n'), col('logged_on_n'), col('logons'), col('failures'), col('signals_n', 'account_signals_n'),
  col('first_seen', 'first_seen', { desc: 'The earliest use any host records: a profile\'s creation, a logon.' }),
  col('last_seen', 'last_seen', { desc: 'The latest use any host records: a profile\'s last load, a logon, an open session.' }),
  col('sources', 'account_sources'), col('notes', 'account_notes'),
];

export async function renderUsersPage(container) {
  const data = await fetchJSON('/api/users');
  const key = urlParams().get('user');
  if (key) return renderUserProfile(container, key, data);
  return renderUserList(container, data);
}

// renderUserList is every user, filtered by scope, kind and Show (kept in
// the URL), under a summary strip, with the excluded accounts below.
async function renderUserList(container, { users, excluded, hosts_n: hostsN }) {
  if (users.length === 0 && excluded.length === 0) {
    container.replaceChildren(h('div', { class: 'card mut' }, 'No accounts yet - import runs of Signal with the Users and Logons modules (-m Users,Logons, or -all).'));
    return;
  }
  const unique = (f) => [...new Set(users.map(f))].sort();
  const options = { scopes: unique((u) => u.scope), kinds: unique((u) => u.kind) };
  const show = urlParams().get('show');
  const sel = {
    scopes: selectionFromUrl('scope', options.scopes),
    kinds: selectionFromUrl('kind', options.kinds),
    show: SHOW.some(([k]) => k === show) ? show : '',
  };
  function syncUrl() {
    const unless = (k) => (sel[k].size === options[k].length ? null : [...sel[k]]);
    setParams({ scope: unless('scopes'), kind: unless('kinds'), show: sel.show || null });
  }
  const pick = (k) => (s) => { sel[k] = s.size ? s : new Set(options[k]); syncUrl(); draw(); };
  const bar = filterBar([
    ['Defined in', checkboxDropdown(options.scopes, pick('scopes'), [...sel.scopes]).el],
    ['Kind', checkboxDropdown(options.kinds, pick('kinds'), [...sel.kinds]).el],
    ['Show', h('select', { onchange: (e) => { sel.show = e.target.value; syncUrl(); draw(); } },
      SHOW.map(([k, label]) => h('option', { value: k, selected: sel.show === k ? 'selected' : null }, label)))],
  ]);
  const summaryBox = h('div');
  const tableBox = h('div');
  function draw() {
    const keep = SHOW.find(([k]) => k === sel.show)[2];
    const rows = users.filter((u) => sel.scopes.has(u.scope) && sel.kinds.has(u.kind) && keep(u));
    const n = (f) => rows.filter(f).length;
    const item = (k, icon, label, cls) => {
      const v = n(SHOW.find(([s]) => s === k)[2]);
      return { icon, value: v, label, cls: v ? cls : null, link: ['users', { show: k }] };
    };
    summaryBox.replaceChildren(summaryStrip([
      { icon: 'user', value: rows.length, label: 'users' },
      item('admins', 'shield', 'administrators somewhere', 'sev-medium'),
      item('logged_on', 'eye', 'signed in now'),
      item('signals', 'signals', 'with signals', 'sev-high'),
      item('failures', 'failure', 'with failed logons', 'sev-medium'),
      item('notes', 'warning', 'with notes', 'sev-medium'),
      { icon: 'notEvaluated', value: excluded.length, label: 'accounts left out (below)' },
    ], MODULES));
    tableBox.replaceChildren(section('Users', () => (rows.length ? dataTable(rows, forHosts(LIST_COLUMNS, hostsN), { pageSize: 20, filename: 'users', rowKey: (r) => r.key })
      : h('div', { class: 'mut' }, 'No user matches the filters.')), { collapsed: false, modules: MODULES }));
  }
  const excludedBox = section(`Accounts left out of this page (${excluded.length}) — and why`, () => h('div', {},
    h('div', { class: 'mut', style: 'margin-bottom:8px' }, 'Found on the hosts, but not a person\'s account: Windows\' own identities, per-session and service accounts, groups, computer accounts, and default accounts (Administrator, Guest, DefaultAccount, WDAGUtilityAccount) that are disabled and were never used. A default account that is enabled, or was used, is a user above. Accounts are recognised by their SID, never by their name alone.'),
    dataTable(excluded, forHosts([col('account', 'user'), col('kind', 'account_kind'), col('reason', 'excluded_reason'), col('seen_n', 'seen_n', { label: 'Hosts' }), col('host_names'), col('sources', 'account_sources')], hostsN),
      { pageSize: 20, filename: 'excluded_accounts' })), { collapsed: true, modules: MODULES });

  // The logons of every host's latest collection: who logged on, how, from
  // where, and the trend - above the accounts they belong to.
  const logonsBox = h('div');
  stickyPage(container, bar);
  container.replaceChildren(bar, summaryBox, logonsBox, tableBox, excludedBox);
  draw();
  const inv = await fetchJSON('/api/inventories');
  logonsBox.replaceChildren(section('Logons — who logged on, how, from where, and the trend', () => logonsView(inv.logons, { hosts: '', modules: '' }, hostsN),
    { collapsed: false, modules: inv.logons.modules }));
}

// renderUserProfile is one account's page: who it is, how each host knows
// it, its trend, its logons and failures, and the signals about it.
async function renderUserProfile(container, key, { users }) {
  const u = await fetchJSON(`/api/users/${encodeURIComponent(key)}`);
  const bar = filterBar([
    ['User', h('select', { onchange: (e) => go('users', { user: e.target.value }) },
      users.map((o) => h('option', { value: o.key, selected: o.key === u.key ? 'selected' : null }, o.account)))],
    ['', pageLink('users', {}, '← All users')],
  ]);
  const head = h('div', { class: 'card host-head' },
    h('div', { class: 'host-title' }, svgIcon('user'), h('span', {}, u.account), h('span', { class: 'mut host-role' }, `${u.scope} · ${u.kind}`)),
    h('div', { class: 'mut' }, [u.sid && `SID ${u.sid}`, u.other_names.length && `also recorded as ${u.other_names.join(', ')}`].filter(Boolean).join(' · ')));
  const detailCols = [
    col('host'), col('sources', 'account_sources'), col('enabled'), col('admin'), col('groups'), col('profile_path'),
    col('first_seen'), col('last_seen'), col('logged_on_now'), col('logons'), col('failures'), col('privileged'), col('changes', 'account_changes'), col('notes', 'account_notes'),
  ];
  const logonCols = [col('host'), col('type_name'), col('source', 'logon_source'), col('source_scope'), col('auth_package'), col('count'), col('elevated'), col('first_seen'), col('last_seen')];
  const failureCols = [col('host'), col('type_name'), col('source', 'logon_source'), col('source_scope'), col('reason', 'failure_reason'), col('count'), col('first_seen'), col('last_seen')];
  const explicitCols = [col('host'), col('subject'), col('account', 'user'), col('target_server'), col('process'), col('count'), col('first_seen'), col('last_seen')];
  const microsoft = u.host_detail.map((x) => x.microsoft_account).find(Boolean);

  // A panel with nothing to show is left out (section() returns null for
  // it); filter(Boolean) keeps such gaps from being written as "null".
  stickyPage(container, bar);
  container.replaceChildren(...[bar, head,
    u.notes.length ? h('div', { class: 'card warn' }, h('h2', { class: 'card-head' }, 'Notes', moduleBadge(['Users'])), u.notes.map((n) => h('div', { class: 'user-note' }, n))) : null,
    summaryStrip([
      { icon: 'hosts', value: u.seen_n, label: u.seen_n === 1 ? 'host' : 'hosts' },
      { icon: 'shield', value: u.admin_n, label: 'administrator on', cls: u.admin_n ? 'sev-medium' : null },
      { icon: 'eye', value: u.logged_on_n, label: 'signed in now' },
      { icon: 'logon', value: u.logons.toLocaleString(), label: 'logons' },
      { icon: 'failure', value: u.failures.toLocaleString(), label: 'failed logons', cls: u.failures ? 'sev-medium' : null },
      { icon: 'key', value: u.privileged.toLocaleString(), label: 'administrative logons' },
      { icon: 'signals', value: u.signals_n, label: 'signals', cls: u.signals_n ? 'sev-high' : null },
    ], MODULES),
    h('div', { class: 'grid facts-grid' }, factCard('Identity', MODULES, [
      ['Account', mono(u.account)], ['SID', u.sid && mono(u.sid)], ['Defined in', u.scope], ['Kind', u.kind],
      ['Microsoft account', microsoft], ['First seen', ts(u.first_seen)], ['Last seen', ts(u.last_seen)],
      ['Known from', u.sources],
    ])),
    section('On hosts — how each host knows it', () => dataTable(u.host_detail, detailCols, { filename: `user-hosts`, rowKey: (r) => r.run_id }), { collapsed: false, modules: MODULES }),
    section('Logon trend', () => trendChart(u.trend, { title: `${u.account}: logons and failed logons per day` }), { collapsed: false, modules: ['Logons'] }),
    section(`How it logged on (${u.logon_rows.length})`, () => (u.logon_rows.length ? dataTable(u.logon_rows, logonCols, { filename: 'user-logons' })
      : h('div', { class: 'mut' }, 'No logon of this account is in the hosts\' Security logs.')), { collapsed: false, modules: ['Logons'] }),
    u.failure_rows.length ? section(`Failed logons (${u.failure_rows.length})`, () => dataTable(u.failure_rows, failureCols, { filename: 'user-failed-logons' }), { collapsed: false, modules: ['Logons'] }) : null,
    u.explicit_rows.length ? section(`Explicit credentials (${u.explicit_rows.length})`, () => dataTable(u.explicit_rows, explicitCols, { filename: 'user-explicit-credentials' }), { collapsed: false, modules: ['Logons'] }) : null,
    section('Signals about this account', () => (u.signals_n ? signalTable({ account: u.ids.join(',') }, `user-signals`) : h('div', { class: 'mut' }, 'No open signal names this account.')),
      { collapsed: false, modules: MODULES })].filter(Boolean));
}
