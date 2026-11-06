// The Settings page: how this console is set up, one group at a time
// (its bar) - the scoping profiles that scope Signal's runs
// (pages/profiles.js), VirusTotal lookups (GET|PUT
// /api/virustotal/settings), HTTPS (GET
// /api/settings/https), CISA's Known Exploited Vulnerabilities catalog
// (GET /api/settings/kev), how links open (this browser), this server's
// load (GET /api/settings/server), and - for an admin - the console's
// accounts (/api/settings/accounts), its audit log and its updates
// (/api/settings/updates - src/updates.js).
// More settings join it as groups.

import { h, fetchJSON, ts, mono } from '../dom.js';
import { isAdmin, sessionUser } from '../session.js';
import { section, detailBlock, codeBlock, CORE } from '../components.js';
import { urlParams, go, LINK_MODES, linkMode, setLinkMode } from '../router.js';
import { dataTable, col } from '../table.js';
import { renderProfilesPage } from './profiles.js';

// GROUPS are the page's setting groups, one shown at a time - chosen in
// its bar (the URL's group), the profiles first.
const GROUPS = [
  { id: 'profiles', title: 'Scoping profiles' },
  { id: 'virustotal', title: 'VirusTotal' },
  { id: 'kev', title: 'Known exploited vulnerabilities' },
  { id: 'links', title: 'Links' },
  { id: 'https', title: 'HTTPS' },
  { id: 'server', title: 'Signal Console' },
  { id: 'license', title: 'License' },
  { id: 'accounts', title: 'Users', admin: true },
  { id: 'audit', title: 'Audit log', admin: true },
  { id: 'updates', title: 'Updates', admin: true },
];

export async function renderSettingsPage(container) {
  const q = urlParams();
  if (q.get('profile') || q.has('new')) return renderProfilesPage(container); // the profile builder, alone
  const groups = GROUPS.filter((g) => !g.admin || (sessionUser() || {}).role === 'admin');
  const group = groups.some((g) => g.id === q.get('group')) ? q.get('group') : groups[0].id;
  const bar = h('nav', { class: 'settings-nav', 'aria-label': 'Setting groups' }, ...groups.map((g) => h('button', {
    class: 'chip' + (g.id === group ? ' on' : ''), 'aria-current': g.id === group ? 'page' : null, onclick: () => go('settings', g.id === GROUPS[0].id ? {} : { group: g.id }),
  }, g.title)));
  const body = h('div');
  container.replaceChildren(h('div', { class: 'settings-layout' }, bar, body));
  if (group === 'profiles') return renderProfilesPage(body);
  if (group === 'virustotal') {
    const vt = await fetchJSON('/api/virustotal/settings');
    return body.replaceChildren(section('VirusTotal lookups', () => virusTotalView(vt), { collapsed: false, modules: [CORE] }));
  }
  if (group === 'kev') {
    const k = await fetchJSON('/api/settings/kev');
    return body.replaceChildren(section("Known exploited vulnerabilities - CISA's catalog", () => kevView(k), { collapsed: false, modules: [CORE] }));
  }
  if (group === 'accounts') {
    const list = await fetchJSON('/api/settings/accounts');
    return body.replaceChildren(section("Users - the console's accounts", () => accountsView(list), { collapsed: false, modules: [CORE] }));
  }
  if (group === 'audit') {
    const a = await fetchJSON('/api/settings/audit');
    return body.replaceChildren(section('Audit log - sign-ins, accounts and run removals', () => auditView(a), { collapsed: false, modules: [CORE] }));
  }
  if (group === 'updates') {
    const u = await fetchJSON('/api/settings/updates');
    return body.replaceChildren(section('Updates - Signal Console and Signal', () => updatesView(u), { collapsed: false, modules: [CORE] }));
  }
  if (group === 'license') {
    const l = await fetchJSON('/api/settings/license');
    return body.replaceChildren(section('License - the edition in force', () => licenseView(l), { collapsed: false, modules: [CORE] }));
  }
  if (group === 'links') return body.replaceChildren(section('Links - how a page opens from another', linksView, { collapsed: false, modules: [CORE] }));
  if (group === 'server') {
    const s = await fetchJSON('/api/settings/server');
    return body.replaceChildren(section('This Signal Console - its memory and data files', () => serverView(s), { collapsed: false, modules: [CORE] }));
  }
  const https = await fetchJSON('/api/settings/https');
  return body.replaceChildren(section('HTTPS - how browsers reach this console', () => httpsView(https), { collapsed: false, modules: [CORE] }));
}

// virusTotalView turns the VirusTotal lookups on or off and keeps the key.
function virusTotalView(v) {
  const msg = h('p', { class: 'mut' });
  const key = h('input', { class: 'cond-value', type: 'password', placeholder: v.key_set ? `stored (${v.key_hint}) - type to replace` : 'API key (64 characters)', autocomplete: 'off', size: 48 });
  const wait = h('input', { class: 'cond-value num', type: 'number', min: 15, max: 86400, value: v.wait_seconds });
  const refresh = h('input', { class: 'cond-value num', type: 'number', min: 0, max: 365, value: v.refresh_days });
  const save = (body) => async () => {
    try {
      await fetchJSON('/api/virustotal/settings', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body()) });
      window.location.reload();
    } catch (err) { msg.textContent = err.message; }
  };
  const c = v.counts || {};
  const edit = isAdmin(); // shared settings: admins only
  return h('div', {},
    edit ? null : h('p', { class: 'mut' }, 'Only an admin changes these settings - they apply to the whole console.'),
    h('p', {}, h('strong', { class: v.enabled ? 'result-ok' : '' }, v.enabled ? 'On. ' : 'Off. '),
      "When on, the console looks up every file hash (SHA-256), public IP address and domain in the hosts' latest collections at VirusTotal - a lookup only: no file is uploaded. What VirusTotal says is shown beside Signal's facts as “VirusTotal says”, with the date it was looked up, and never changes a signal. Signal itself never connects to VirusTotal."),
    h('p', { class: 'mut' }, "Every answer is kept, so an item is not looked up twice - but VirusTotal's verdicts change as engines learn a file: an answer older than the age below is looked up again (only for what the latest collections still name), its old verdict shown, with its date, until the new one arrives. New items go first."),
    h('p', { class: 'mut' }, "The lookups are queued and taken in turn. When VirusTotal answers that the key's quota is used up (the free key allows 4 lookups a minute), that item stays queued - shown as “waiting for VirusTotal” - and the queue waits before going on."),
    h('div', { class: 'facts' }, h('table', {},
      fact('API key', v.key_set ? `stored (ends ${v.key_hint})` : 'none'),
      fact('Wait after a quota answer', `${v.wait_seconds} seconds`),
      fact('Looked up again after', v.refresh_days ? `${v.refresh_days} days - ${v.stale} answer${v.stale === 1 ? '' : 's'} of the latest collections older than that` : 'never - an answer is kept as it was'),
      fact('Queue', `${c.done || 0} looked up, ${c.not_found || 0} not known to VirusTotal, ${c.queued || 0} waiting`),
      v.paused_until ? fact('Paused until', ts(v.paused_until)) : null,
      v.last_error ? fact('Last error', h('span', { class: 'sev-high' }, v.last_error)) : null)),
    edit ? h('div', { class: 'vt-form' },
      h('div', {}, key, ' ', h('button', { class: 'btn', onclick: save(() => ({ key: key.value })) }, 'Save key')),
      h('div', {}, h('label', {}, 'Wait after a quota answer (seconds) ', wait), ' ', h('button', { class: 'ghost', onclick: save(() => ({ wait_seconds: Number(wait.value) })) }, 'Save wait')),
      h('div', {}, h('label', {}, 'Look an answer up again after (days, 0 = never) ', refresh), ' ', h('button', { class: 'ghost', onclick: save(() => ({ refresh_days: Number(refresh.value) })) }, 'Save')),
      h('div', {}, h('button', { class: v.enabled ? 'ghost danger' : 'btn', onclick: save(() => ({ enabled: !v.enabled })), disabled: !v.key_set && !v.enabled ? 'disabled' : null }, v.enabled ? 'Turn off' : 'Turn on'))) : null,
    msg);
}

// ROLE_TEXT says what each role may do.
const ROLE_TEXT = { admin: 'everything, the accounts included', analyst: 'everything but the accounts', viewer: 'read-only' };

// accountsView lists the console's accounts with what an admin may change
// on each - role, name, password, enabled, removed - and adds one. Every
// change signs that account out; the console always keeps an enabled admin.
function accountsView(list) {
  const msg = h('div', { class: 'result-err', role: 'alert' });
  const me = (sessionUser() || {}).username;
  const send = async (path, method, body) => {
    msg.textContent = '';
    try {
      await fetchJSON(`/api/settings/accounts${path}`, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
      go('settings', { group: 'accounts' });
    } catch (err) { msg.textContent = err.message; }
  };
  const at = (u) => `/${encodeURIComponent(u.username)}`;
  const roleSelect = (u) => h('select', { 'aria-label': `Role of ${u.username}`, onchange: (e) => send(at(u), 'PUT', { role: e.target.value }) },
    Object.keys(ROLE_TEXT).map((r) => h('option', { value: r, selected: r === u.role ? 'selected' : null }, r)));
  const actions = (u) => {
    const pw = h('input', { class: 'cond-value', type: 'password', autocomplete: 'new-password', placeholder: 'New password (12+ characters)', hidden: true });
    const setPw = h('button', { class: 'ghost', onclick: () => {
      if (pw.hidden) { pw.hidden = false; pw.focus(); return; }
      send(at(u), 'PUT', { password: pw.value });
    } }, 'Set password');
    const self = u.username === me;
    return h('div', { class: 'account-actions' },
      h('button', { class: 'ghost', disabled: self ? 'disabled' : null, title: self ? 'Another admin renames your account (or npm run users)' : null, onclick: () => {
        const to = String(window.prompt(`Rename ${u.username} to:`, u.username) || '').trim();
        if (to && to !== u.username) send(at(u), 'PUT', { username: to });
      } }, 'Rename'),
      pw, setPw,
      h('button', { class: 'ghost', disabled: self ? 'disabled' : null, onclick: () => send(at(u), 'PUT', { disabled: !u.disabled }) }, u.disabled ? 'Enable' : 'Disable'),
      h('button', { class: 'ghost danger', disabled: self ? 'disabled' : null, onclick: () => {
        if (window.confirm(`Remove the account ${u.username}? What it did stays recorded under its name.`)) send(at(u), 'DELETE');
      } }, 'Remove'));
  };
  const rows = list.map((u) => ({ ...u, state: u.disabled ? 'disabled' : 'active' }));
  const name = h('input', { class: 'cond-value', type: 'text', placeholder: 'Account name', autocomplete: 'off' });
  const role = h('select', { 'aria-label': 'Role' }, Object.keys(ROLE_TEXT).map((r) => h('option', { value: r, selected: r === 'analyst' ? 'selected' : null }, r)));
  const password = h('input', { class: 'cond-value', type: 'password', placeholder: 'Password (12+ characters)', autocomplete: 'new-password' });
  return h('div', {},
    h('p', { class: 'mut' }, `Roles: admin - ${ROLE_TEXT.admin}; analyst - ${ROLE_TEXT.analyst}; viewer - ${ROLE_TEXT.viewer}. Every change signs that account out everywhere. The console always keeps one enabled admin, and you change your own account from another admin's (or with npm run users on the server). What an account did - triage, flags, imports - stays recorded under the name it had.`),
    dataTable(rows, [
      col('username', 'text', { label: 'Account', icon: 'user', desc: 'The name the account signs in with.', render: (v) => (v === me ? h('span', {}, mono(v), h('span', { class: 'mut' }, ' (you)')) : mono(v)) }),
      col('role', 'text', { label: 'Role', icon: 'shield', desc: 'What it may do: admin, analyst or viewer. Changing it signs the account out.', render: (v, u) => (u.username === me ? v : roleSelect(u)) }),
      col('state', 'text', { label: 'State', icon: 'status', desc: 'Active, or disabled (cannot sign in).' }),
      col('created', 'text', { label: 'Created', icon: 'clock', desc: 'When the account was made (UTC).', render: (v) => ts(v) }),
      col('actions', 'text', { label: 'Change', icon: 'edit', desc: 'Rename, set a new password, disable or remove. Your own account is changed by another admin.', render: (v, u) => actions(u) }),
    ], { rowKey: (r) => r.username, height: 'auto', filename: 'accounts' }),
    h('div', { class: 'vt-form' }, h('div', {}, h('b', {}, 'Add an account '), name, ' ', role, ' ', password, ' ',
      h('button', { class: 'btn', onclick: () => send('', 'POST', { username: name.value, role: role.value, password: password.value }) }, 'Add'))),
    msg);
}

// auditView lists the audit log, newest first.
function auditView(a) {
  return h('div', {},
    h('p', { class: 'mut' }, `Every sign-in and refused sign-in, every sign-out, every change to an account and every run removed, with who did it and from which address. Never a password or a session. Only admins read it. The newest ${a.kept.toLocaleString('en-US')} events are kept; what an analyst decides (triage, flags) has its own history where it is made. Times are UTC.`),
    dataTable(a.events, [
      col('at', 'text', { label: 'When', icon: 'clock', desc: 'When it happened (UTC).', render: (v) => ts(v) }),
      col('what', 'text', { label: 'What', icon: 'status', desc: 'The event.' }),
      col('actor', 'text', { label: 'By', icon: 'user', desc: "The account that acted - for a refused sign-in, the name typed; 'command line' or 'first start' for the server's shell.", render: (v) => mono(v) }),
      col('target', 'text', { label: 'To', icon: 'target', desc: 'The account it was done to.', render: (v) => mono(v) }),
      col('address', 'text', { label: 'From', icon: 'globe', desc: "The address the request came from (empty for the server's shell).", render: (v) => mono(v) }),
      col('detail', 'text', { label: 'Detail', icon: 'details', desc: "Why a sign-in was refused, what a role changed from and to, a renamed account's old name, the runs removed." }),
    ], { rowKey: (r) => String(r.id), filename: 'audit-log' }));
}

// LINK_TEXT is each link mode's choice and what it means.
const LINK_TEXT = {
  same: ['In this tab', 'The default. The page opens in place of the one you are on; Back returns to it.'],
  tab: ['In a new tab', 'The page opens in a new tab of this window, so the page you are on stays as it is.'],
  window: ['In a new window', 'The page opens in a small window of its own, with no tabs or toolbar - beside the page you are on, to compare or keep in sight.'],
};

// linksView chooses how an in-app link or a row that opens a page opens it.
function linksView() {
  const now = linkMode();
  return h('div', {},
    h('p', {}, "How a page opens when you click a link or a row on another page - an entity, a host, a rule. The side navigation and a page's own filters and tabs always change the page in place. A Ctrl or Shift click keeps the browser's own meaning (a new tab, a new window). Kept in this browser only, for you."),
    h('div', { class: 'link-modes' }, ...LINK_MODES.map((m) => h('label', { class: 'link-mode' },
      h('input', { type: 'radio', name: 'link-mode', value: m, checked: m === now ? '' : null, onchange: () => setLinkMode(m) }),
      h('b', {}, LINK_TEXT[m][0]), ' ', h('span', { class: 'mut' }, LINK_TEXT[m][1])))));
}

// kevView shows CISA's catalog and NVD's lookups as the console holds
// them, how the matching works, the NVD API key, and the steps for a
// console without Internet access.
function kevView(k) {
  const n = k.nvd;
  const msg = h('p', { class: 'mut' });
  const send = (url, method, body) => async () => {
    msg.textContent = 'Working...';
    try {
      await fetchJSON(url, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ? body() : {}) });
      window.location.reload();
    } catch (err) { msg.textContent = err.message; }
  };
  const key = h('input', { class: 'cond-value', type: 'password', placeholder: n.key_set ? `stored (${n.key_hint}) - type to replace` : 'NVD API key (a UUID)', autocomplete: 'off', size: 40 });
  const refresh = h('input', { class: 'cond-value num', type: 'number', min: 0, max: 365, value: n.refresh_days });
  const warn = h('input', { class: 'cond-value num', type: 'number', min: 0, max: 365, value: k.warn_days });
  const edit = isAdmin(); // shared settings: admins only
  return h('div', {},
    edit ? null : h('p', { class: 'mut' }, 'Only an admin changes these settings - they apply to the whole console.'),
    h('p', {}, "The console flags an installed application when one of its installed versions is affected by a vulnerability CISA lists as exploited in the wild. Not a vulnerability scanner: only CVEs in CISA's Known Exploited Vulnerabilities catalog, only products matched by name, only versions NVD states as affected. Console rule: ", mono('CONSOLE-KEV-PRODUCT'), '.'),
    k.old ? h('div', { class: 'card report-warn' }, h('b', {}, `CISA's catalog is ${k.age_days} days old`), ` (released ${k.released.slice(0, 10)}). CISA adds exploited vulnerabilities most weeks: the ones added since are not checked. Update from CISA, or copy a newer file and Read the file.`) : null,
    h('div', { class: 'facts' }, h('table', {},
      fact('CISA catalog', k.loaded ? `version ${k.version}, released ${k.released} - ${k.count.toLocaleString()} vulnerabilities (read ${ts(k.file_time)})` : 'none yet - no application is flagged'),
      fact('Catalog file', mono(k.file)),
      fact('NVD lookups', `${n.done} CVEs read, ${n.not_found} not in NVD, ${n.failed} failed (tried again after 6 hours), ${n.queued} waiting - one every ${n.seconds} seconds`),
      fact('Catalog age warning', k.warn_days ? `after ${k.warn_days} days` : 'never'),
      fact('NVD records read again after', n.refresh_days ? `${n.refresh_days} days (NVD corrects affected versions; a record is used until read again)` : 'never'),
      fact('NVD API key', n.key_set ? `stored (ends ${n.key_hint})` : 'none - 5 lookups in 30 seconds'),
      fact('Saved NVD answers', mono(n.dir)),
      k.error ? fact('Error', h('span', { class: 'sev-high' }, k.error)) : null)),
    edit ? h('div', { class: 'vt-form' },
      h('div', {}, h('button', { class: 'btn', onclick: send('/api/settings/kev/update', 'POST') }, 'Update from CISA'), ' ',
        h('button', { class: 'ghost', onclick: send('/api/settings/kev/reload', 'POST') }, 'Read the file')),
      h('div', {}, key, ' ', h('button', { class: 'btn', onclick: send('/api/settings/kev/nvd', 'PUT', () => ({ key: key.value })) }, 'Save key'),
        n.key_set ? h('button', { class: 'ghost danger', onclick: send('/api/settings/kev/nvd', 'PUT', () => ({ key: '' })) }, 'Remove key') : null),
      h('div', {}, h('label', {}, 'Read an NVD record again after (days, 0 = never) ', refresh), ' ', h('button', { class: 'ghost', onclick: send('/api/settings/kev/nvd', 'PUT', () => ({ refresh_days: Number(refresh.value) })) }, 'Save')),
      h('div', {}, h('label', {}, 'Warn when the catalog is older than (days, 0 = never) ', warn), ' ', h('button', { class: 'ghost', onclick: send('/api/settings/kev/nvd', 'PUT', () => ({ warn_days: Number(warn.value) })) }, 'Save'))) : null,
    msg,
    detailBlock('How the lookup and the matching work',
      h('ol', {},
        h('li', {}, h('b', {}, 'The catalog. '), "CISA's Known Exploited Vulnerabilities catalog lists the CVEs attackers are known to have exploited, each with its vendor and product (for example 7-Zip / 7-Zip) - but not which versions are affected. Update from CISA downloads it; the console keeps it in the catalog file above."),
        h('li', {}, h('b', {}, 'Product match. '), "An installed application (Applications page) matches a catalog product when its name, with version numbers, architectures (x64, x86) and brackets removed, is the product or vendor + product - alone or followed by more words - and the vendor is in its publisher or name. \u201c7-Zip 24.08 (x64)\u201d by Igor Pavlov matches 7-Zip."),
        h('li', {}, h('b', {}, 'Affected versions. '), "For each CVE of a matched product, the console asks NIST's National Vulnerability Database (NVD) for that CVE's record - sending the CVE ID only, never anything about the hosts - and keeps its answer. The record states the affected products as CPEs with version ranges, such as 7-Zip before 24.09."),
        h('li', {}, h('b', {}, 'Version match. '), "Only a range whose product is in the application's name counts (a record often names other vendors' products too). Each installed version is compared number by number with the range's bounds: 24.08 is before 24.09, so it is affected; 24.09 is not."),
        h('li', {}, h('b', {}, 'The flag. '), "An affected version flags the application: the Known exploited (CISA) column lists the CVEs and what each is, and the console's flag with its reason is in Overview's Flagged items and the report. A CVE whose versions cannot be compared - not looked up yet, no range for the product, or a version that is not plain numbers - flags nothing; the column counts it as not compared."))),
    detailBlock('NVD API key - free',
      h('p', {}, 'Without a key NVD answers 5 requests in 30 seconds, so the console looks up one CVE every 6.5 seconds; with a key, 50 in 30 seconds (one every 0.7 seconds). The key is free: request it at ', mono('https://nvd.nist.gov/developers/request-an-api-key'), " with an e-mail address, open the link NVD e-mails you to activate it, and paste the key (a UUID like 12345678-abcd-...) above. It is kept in this console's main database and sent only to NVD.")),
    detailBlock('Without Internet access',
      h('ol', {},
        h('li', {}, 'On a machine with Internet access, download CISA\'s catalog: ', mono(k.source)),
        h('li', {}, 'Copy the file to this console as ', mono(k.file), ' and press Read the file. The applications whose products match are then known, and their CVEs are listed below as waiting for an NVD answer.'),
        h('li', {}, 'For each CVE listed below, open its NVD address on the machine with Internet access and save the answer, unchanged, as ', mono('<CVE>.json'), ' (for example ', mono('CVE-2025-0411.json'), ').'),
        h('li', {}, 'Copy those files to ', mono(n.dir), ' and open the Applications page: each saved answer is read once and kept. Repeat when the hosts or the catalog change.')),
      n.missing.length
        ? h('div', {}, h('p', { class: 'mut' }, `${n.missing.length} CVE${n.missing.length === 1 ? '' : 's'} with no NVD answer yet:`),
          codeBlock(n.missing.map((c) => [[`${n.api}${c}`]])))
        : h('p', { class: 'mut' }, 'No CVE is waiting for an NVD answer.')));
}

// serverView shows what this server holds: its memory, its data files, and
// the runs in memory with the model's last rebuild.
function serverView(s) {
  const mb = (n) => `${(n / 1048576).toFixed(1)} MB`;
  const pct = Math.round((100 * s.heap.used) / s.heap.limit);
  const rebuilt = (r) => (r ? `${r.ms} ms over ${r.runs} runs${r.triage_only ? ' (triage only)' : ''}, ${ts(r.at)}` : 'not yet rebuilt');
  const runs = s.runs;
  return h('div', {},
    h('p', {}, "The runs are read into memory when a page first needs them after the server starts - each host's latest collection whole, its earlier ones as their signals - and stay there; a page needs the model rebuilt after any import, removal or triage change."),
    h('div', { class: 'facts' }, h('table', {},
      fact('Memory (JavaScript heap)', `${mb(s.heap.used)} of at most ${mb(s.heap.limit)} (${pct}%)`),
      fact('Memory (whole process)', mb(s.heap.rss)),
      fact('Database file', `${mb(s.data.db_bytes)} in ${s.data.dir}`),
      fact('Latest collections in memory', runs ? String(runs.runs_in_memory) : 'none read yet'),
      fact('Older collections (signals only)', runs ? String(runs.older_runs) : 'none read yet'),
      fact('Last model rebuild', runs ? rebuilt(runs.rebuild) : 'not yet rebuilt'),
      fact('Node.js', s.node),
      fact('Running for', `${Math.floor(s.uptime_seconds / 3600)} h ${Math.floor((s.uptime_seconds % 3600) / 60)} min`))));
}

// updatesView is the update state (src/updates.js) and the admin's
// choices: automatic updates, other places for the update file, checking
// and updating now, and an update file (and package) given by hand.
function updatesView(u) {
  const msg = h('p', { class: 'mut' });
  const call = (url, opts) => async () => {
    msg.textContent = 'Working...';
    try {
      await fetchJSON(url, { method: 'POST', ...opts });
      window.location.reload();
    } catch (err) { msg.textContent = err.message; }
  };
  const put = (body) => call('/api/settings/updates', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const sources = h('textarea', { class: 'cond-value', rows: 3, cols: 70, placeholder: 'https://... one address a line' }, (u.custom_sources || []).join('\n'));
  const file = h('input', { type: 'file', accept: '.json' });
  const pkg = h('input', { type: 'file', accept: '.zip' });
  const upload = async () => {
    if (!file.files[0]) { msg.textContent = 'Choose the update file (updates.json).'; return; }
    const form = new FormData();
    form.append('file', file.files[0]);
    if (pkg.files[0]) form.append('package', pkg.files[0]);
    await call('/api/settings/updates/upload', { body: form })();
  };
  const signal = u.signal;
  const state = u.withdrawn ? h('span', { class: 'withdrawn-tag' }, `withdrawn: ${u.withdrawn.reason}`)
    : u.available ? `${u.latest} is available` : u.latest ? 'the newest version' : 'not known yet';
  const places = [...(u.custom_sources || []), ...(u.mirrors || []), ...(u.sources || [])].filter((s, i, a) => a.indexOf(s) === i);
  return h('div', {},
    h('p', {}, 'Signal Console and Signal learn of new versions from one update file, signed with the release key: it is trusted for its signature, never for the place it came from, so it can be read from any of the places below, a mirror, or a copy given by hand. A version found to have a bug that misleads, or a vulnerability, is withdrawn in it. Signal is updated on each host with ', mono('signal update'), ' (or from a share it wrote with ', mono('signal update -o'), ').'),
    h('div', { class: 'facts' }, h('table', {},
      fact('This Signal Console', h('span', {}, `${u.version} - `, state)),
      fact('How it updates', u.mode === 'managed'
        ? 'Started by launch.js (a release package): a new version is downloaded, checked against the signed file, unpacked beside this one and, after the data is backed up, started in its place - or rolled back if it does not start.'
        : 'Not started by launch.js (a git checkout, or node server.js): a new version is announced here and in the banner, never applied - update it by hand (git pull, or the new release package).'),
      fact('Automatic updates', u.auto
        ? 'On - a new version is applied when the console is idle; one that withdraws this version at once, after a two-minute notice.'
        : 'Off - nothing changes by itself; a withdrawn version is shown in red to every user until an admin updates.'),
      fact('Update file', u.issued ? `signed ${ts(u.issued)}, expires ${ts(u.expires)}${u.stale ? ' - expired: a newer version may not be known' : ''}${u.source ? `, read from ${u.source}` : ''}` : 'none read yet'),
      fact('Last check', u.checked_at ? `${ts(u.checked_at)}${u.error ? ` - ${u.error}` : ''}` : (u.checking ? 'checking now' : 'not since this console started')),
      u.downloading ? fact('Downloading', `${u.downloading.version}, since ${ts(u.downloading.started)}`) : null,
      u.pending ? fact('Restart', `into ${u.pending.version} at ${ts(u.pending.at)}, or when idle after it`) : null,
      u.rolled_back ? fact('Rolled back', h('span', { class: 'withdrawn-tag' }, `${u.rolled_back.version} did not start (${ts(u.rolled_back.at)}); the data was restored from ${u.rolled_back.backup || 'the backup'}. It is not tried again automatically.`)) : null,
      fact('Signal (the exe)', signal
        ? h('span', {}, `newest ${signal.latest}`, signal.notes ? [' - ', h('a', { href: signal.notes, target: '_blank', rel: 'noopener' }, 'what changed')] : '',
          signal.withdrawn.length ? h('div', { class: 'mut' }, 'Withdrawn: ', signal.withdrawn.map((w) => `${w.version || `every version before ${w.below}`} (${w.reason})`).join('; '), '. Their runs are accepted and marked as from a withdrawn version.') : '')
        : 'not known yet'),
      fact('Places read, in order', h('div', {}, ...places.map((s) => h('div', {}, mono(s))))))),
    (u.problems || []).length ? detailBlock('Why the places failed', h('div', {}, ...u.problems.map((p) => h('div', { class: 'mut' }, p)))) : null,
    detailBlock('Choices', h('div', {},
      h('p', {}, h('button', { class: 'btn', onclick: call('/api/settings/updates/check') }, 'Check now'), ' ',
        u.available && u.mode === 'managed' ? h('button', { class: 'btn', onclick: call('/api/settings/updates/apply') }, `Update to ${u.latest} now`) : null, ' ',
        h('button', { class: 'btn', onclick: put({ auto: !u.auto }) }, u.auto ? 'Turn automatic updates off' : 'Turn automatic updates on')),
      h('p', {}, 'Other places for the update file, read first - one address a line (a mirror of your own, a share served over HTTP):'), sources,
      h('p', {}, h('button', { class: 'btn', onclick: () => put({ sources: sources.value.split('\n') })() }, 'Save the places')))),
    detailBlock('Without Internet access', h('div', {},
      h('p', {}, 'Download the update file (updates.json) and, for this console, its package (signal-console-X.Y.Z.zip) on a machine with access, and give them here: the file is checked against the release key, the package against the file.'),
      h('p', {}, 'Update file: ', file, ' Package: ', pkg, ' ', h('button', { class: 'btn', onclick: upload }, 'Give them')))),
    msg);
}

// licenseView is the edition in force and the terms it is used under.
function licenseView(l) {
  return h('div', {},
    h('p', {}, 'This console is the Community edition of Signal Console, licensed under the Signal Community License 1.0.0. It may be used, free of charge, solely to defend the computers, networks and systems that the licensee's organisation owns or operates, and for personal, educational and non-commercial research use.'),
    h('div', { class: 'facts' }, h('table', {},
      fact('Edition', h('span', { class: 'edition-community' }, l.label)),
      fact('License', l.license),
      fact('Licensor', 'Intrusion Academy'))),
    h('p', { class: 'mut' }, 'Providing services to any third party, resale, redistribution outside the organisation, and incorporation into another product or service require a commercial license (the Pro or Enterprise edition) from Intrusion Academy. The License page states the terms in full.'));
}

// fact is one labelled value of the certificate.
const fact = (label, value) => h('tr', {}, h('th', {}, label), h('td', {}, value));

// code is lines of plain text as a code block.
const code = (lines) => codeBlock(lines.map((l) => [[l]]));

// httpsView is whether this console answers over HTTPS, its certificate,
// why HTTPS matters and how to turn it on.
function httpsView(s) {
  const c = s.certificate;
  const now = new Date();
  const state = s.https
    ? h('p', {}, h('strong', {}, 'This console answers over HTTPS. '), 'Browsers check its certificate when they connect.')
    : s.behind_proxy
      ? h('p', {}, h('strong', {}, 'This console runs behind a proxy that answers over HTTPS '), '(SIGNAL_CONSOLE_SECURE_COOKIE=1): the proxy holds the certificate, not this console.')
      : h('p', {}, h('strong', { class: 'sev-medium' }, 'This console answers over plain HTTP. '), 'Passwords, sessions and the runs cross the network unencrypted.');
  const cert = c && h('div', { class: 'facts' }, h('table', {},
    fact('Subject', mono(c.subject)), fact('Names (subject alternative names)', mono(c.names || 'none')), fact('Issuer', mono(c.issuer)),
    fact('Valid', h('span', { class: new Date(c.valid_to) < now ? 'sev-high' : null }, `${ts(c.valid_from)} to ${ts(c.valid_to)}${new Date(c.valid_to) < now ? ' - expired' : ''}`)),
    fact('SHA-256 fingerprint', mono(c.sha256)), fact('File', mono(c.file)),
    c.self_signed ? fact('Note', 'Self-signed: every machine that connects must trust this certificate itself (Trusted Root Certification Authorities).') : null));
  return h('div', {},
    state,
    cert ? detailBlock('Certificate', cert) : null,
    s.certificate_error ? h('p', { class: 'sev-high' }, s.certificate_error) : null,
    detailBlock('Why HTTPS',
      h('p', {}, 'Over plain HTTP, anyone on the network between a browser and this console can read what crosses it and change it:'),
      h('ul', {},
        h('li', {}, 'the analysts\' passwords and session cookies - whoever reads them signs in as that analyst;'),
        h('li', {}, 'the runs - account names, command lines, file paths, addresses: what an attacker on the network would want to read, or to alter before an analyst sees it.')),
      h('p', {}, 'Plain HTTP is accepted so that a lab or a first deployment needs no certificate. Use HTTPS wherever the network is not your own.')),
    detailBlock('Turn on HTTPS',
      h('ol', {},
        h('li', {}, 'Get a certificate for the name used for this console (for example signal-console.corp.example) from your organisation\'s own certificate authority. Domain-joined machines already trust it through Group Policy: nothing to install on them.'),
        h('li', {}, 'Save the certificate, with its chain, and its private key as PEM files on this machine - readable by the account the console runs as, and no one else.'),
        h('li', {}, 'Set these two variables to the files\' paths and restart the console:'),
      ),
      code(['SIGNAL_CONSOLE_TLS_CERT=C:\\signal-console\\tls\\console.pem', 'SIGNAL_CONSOLE_TLS_KEY=C:\\signal-console\\tls\\console.key']),
      h('p', { class: 'mut' }, 'Or let a reverse proxy (IIS, nginx) answer over HTTPS in front of the console, and set SIGNAL_CONSOLE_SECURE_COOKIE=1 here.')),
  );
}
