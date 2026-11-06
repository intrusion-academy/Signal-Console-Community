// The Profiles page: Signal's scoping profiles (Signal's profile documentation) -
// what a run looks for: its window, the incident's pivot points, each
// module's parameters, the rules withheld and the approved baseline. The
// list shows every profile saved here and every one the hosts were given
// (a profile not saved here is known only by its name and hash), each with
// its hosts; the hosts given none are named. The builder (?profile=<hash>,
// ?new=1) writes a profile, checks it as Signal will, and gives it as a
// file or as the encoded one-line argument. A saved profile is kept exactly
// as written, so its SHA-256 is the one the runs report.

import { h, fetchJSON, mono, withTip } from '../dom.js';
import { pageLink, urlParams, go, openPage } from '../router.js';
import { section, summaryStrip, codeBlock, detailBlock, narrative, sevTag, hostLinks, CORE } from '../components.js';
import { dataTable, col } from '../table.js';
import { canEdit, sessionUser } from '../session.js';

// isFullPath: a drive, a share, a %VARIABLE% or a wildcard folder first.
const isFullPath = (v) => /^([a-zA-Z]:\\|\\\\|%[^%\\]+%\\|\*\\)/.test(v);

// HASH_LENGTH is each hash type's length in hexadecimal characters - how a
// pasted hash's type is recognised.
const HASH_LENGTH = { sha256: 64, sha1: 40, md5: 32 };
const hashCheck = (t, name) => (v) => (new RegExp(`^[0-9a-fA-F]{${HASH_LENGTH[t]}}$`).test(v) ? '' : `not a ${name} (${HASH_LENGTH[t]} hexadecimal characters)`);

// TYPES are Signal's pivot and baseline types (core.PivotTypes,
// core.BaselineTypes): each one's label, what its value is, and check -
// the same check `signal profile -check` makes, so a value Signal would
// leave out is refused here first.
const TYPES = {
  file: ['File', 'a file name (any folder) or a full path: C:\\..., \\\\server\\..., %VARIABLE%\\... - * matches any characters',
    (v) => (!v.replace(/[*\\.]/g, '') ? 'matches every file: give a part of its name'
      : v.includes('\\') && !isFullPath(v) ? 'a folder makes it a full path (C:\\..., \\\\server\\..., %VARIABLE%\\... or *\\...); a name alone has none' : '')],
  file_present: ['File present now', 'a file\'s full path on the host\'s disk (C:\\...\\name.ext or %SystemRoot%\\...): Signal looks for it there when it runs - an IoC sweep of the current state, no record searched',
    (v) => (v.includes('*') || !/^([a-zA-Z]:|%[^%\\]+%)\\.*[^\\]$/.test(v) || !v.slice(2).includes('\\') ? 'a full path on the host\'s disk with the file\'s name, no wildcard and no share (C:\\...\\name.ext)' : '')],
  sha256: ['Hash · SHA-256', 'a SHA-256 (64 hexadecimal characters)', hashCheck('sha256', 'SHA-256')],
  sha1: ['Hash · SHA-1', 'a SHA-1 (40 hexadecimal characters)', hashCheck('sha1', 'SHA-1')],
  md5: ['Hash · MD5', 'an MD5 (32 hexadecimal characters)', hashCheck('md5', 'MD5')],
  account: ['Account', 'a SID, DOMAIN\\name, or a name in any domain', () => ''],
  address: ['Address', 'an IPv4 or IPv6 address', (v) => (isAddress(v) ? '' : 'not an IP address')],
  domain: ['Domain', 'a host name, matched with its subdomains', (v) => (/[/\\:@ ]/.test(v) ? 'a host name only; a URL is a url' : '')],
  url: ['URL', 'a URL, or a part of one (8 characters at least)', (v) => (v.length >= 8 ? '' : 'too short to match only that URL')],
  service: ['Service', 'a service\'s key name', () => ''],
  task: ['Task', 'a scheduled task\'s path, or its name', () => ''],
  command: ['Command', 'a fragment of a command line or a script (4 characters at least)', (v) => (v.length >= 4 ? '' : 'too short to match only that command')],
  registry_key: ['Registry key', 'HKLM\\..., HKU\\<SID>\\... or HKCU\\... (every user)', (v) => (/^(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKU\\S-1-|HKEY_USERS\\S-1-)[^\\]*\\./i.test(v) ? '' : 'not a key under HKLM\\, HKU\\<SID>\\ or HKCU\\')],
  remote_id: ['Remote ID', 'a remote access tool\'s ID, this host\'s or a peer\'s', () => ''],
  extension: ['Extension', 'a browser extension\'s ID', () => ''],
};
const PIVOT_TYPES = Object.keys(TYPES);

// HASHED is where Signal itself hashes files (SHA-256, SHA-1 and MD5 in
// one read), as they are when it runs.
const HASHED = [['now', 'running processes\' executables'], ['now', 'auto-start entries\', services\' and scheduled tasks\' programs'],
  ['now', 'programs with network connections or listening'], ['now', 'downloaded files still on disk'],
  ['historical', 'process creations Sysmon recorded (event 1), with the hashes its configuration records']];

// WHERE is what Signal searches for each type, each source tagged now (what
// the host holds when Signal runs) or historical (a record of the past).
// Signal's Scope module states the same per run, in its pivots table.
const WHERE = {
  file: [['now', 'running processes'], ['now', 'auto-start entries, services and scheduled tasks (their programs)'], ['now', 'programs with network connections or listening'],
    ['now', 'remote access tools\' files, web sites\' server-side scripts, SYSVOL\'s files'], ['now', 'antivirus detection history'], ['now', 'the disk at a full path without a wildcard (checked directly)'],
    ['historical', 'process creations (Security 4688, Sysmon 1)'], ['historical', 'program runs (Prefetch, BAM, PCA)'], ['historical', 'service installations (System 7045, Security 4697) and scheduled-task changes'],
    ['historical', 'downloads (browser history, Mark of the Web)'], ['historical', 'antivirus detections and blocks'], ['historical', 'network connections (Security 5156, Sysmon 3, the firewall\'s log)'],
    ['historical', 'shadow copies, with signal live -shadow']],
  file_present: [['now', 'the disk, at this path only - one file\'s metadata when Signal runs; no record is searched, so a file that was there and is gone is not found']],
  sha256: HASHED, sha1: HASHED, md5: HASHED,
  account: [['now', 'local accounts, the Administrators group, user profiles, who is signed in'], ['now', 'running processes\' users'],
    ['historical', 'logons, failed logons, explicit credentials, administrative logons'], ['historical', 'account changes, process creations\' users, Remote Desktop and domain authentications']],
  address: [['now', 'network connections and listeners, network settings (hosts file, proxies)'],
    ['historical', 'logons\' source addresses, network connections (5156, Sysmon 3, the firewall\'s log)'], ['historical', 'Remote Desktop and WinRM sessions, remote access tools\' logs']],
  domain: [['now', 'network settings (hosts file, proxies)'], ['historical', 'sites visited, downloads\' sources, BITS jobs - with their subdomains']],
  url: [['now', 'browser extensions\' update URLs'], ['historical', 'downloads, sites visited, BITS jobs, web server requests']],
  service: [['now', 'configured services'], ['historical', 'service installations (System 7045, Security 4697)']],
  task: [['now', 'scheduled tasks'], ['historical', 'scheduled-task changes (Task Scheduler log, Security 4698-4702)']],
  command: [['now', 'running processes\' command lines, auto-start commands'], ['now', 'PowerShell history files and transcripts'],
    ['historical', 'process creations\' command lines (4688 with command lines, Sysmon 1)'], ['historical', 'PowerShell script blocks and module logging (4104, 4103)']],
  registry_key: [['now', 'auto-start entries\' keys, and below'], ['now', 'the registry at this key (checked directly; HKCU by the entries only)']],
  remote_id: [['now', 'remote access tools\' configuration'], ['historical', 'their logs\' sessions and transfers']],
  extension: [['now', 'installed browser extensions of every browser and user']],
};

// whereTip is a type's tooltip: what it is, then every source searched,
// tagged now or historical.
const whereTip = (t) => h('span', {}, h('div', {}, TYPES[t][1]), h('div', { class: 'mut' }, 'Searched in:'),
  h('ul', { class: 'where-list' }, (WHERE[t] || []).map(([when, what]) => h('li', {}, h('span', { class: `tagtext ${when === 'now' ? 'st-ran' : 'sev-low'}` }, when), ' ', what))));
const BASELINE_TYPES = ['file', 'sha256', 'sha1', 'md5', 'service', 'task', 'extension', 'domain', 'account'];

// ARG_LIMIT is where an encoded profile nears Windows' command line limit
// (32,767 characters), leaving room for the rest of the command.
const ARG_LIMIT = 30000;

// isAddress accepts what Signal's parser (Go's netip.ParseAddr) accepts:
// an IPv4 octet with a leading zero (10.20.09.12) is refused, as it is
// there - it could be read as octal.
function isAddress(v) {
  if (/^\d+(\.\d+){3}$/.test(v)) return v.split('.').every((n) => /^(0|[1-9]\d{0,2})$/.test(n) && Number(n) <= 255);
  if (!v.includes(':') || !/^[0-9a-fA-F:.]+$/.test(v)) return false;
  try { new URL(`http://[${v}]/`); return true; } catch { return false; }
}

// refang undoes the usual ways threat reports defang an indicator
// (evil[.]example, hxxp://, 203.0.113[.]9) and trims quotes, so a value
// copied from a report is the value Signal will meet.
function refang(v) {
  return v.trim().replace(/^["'`]+|["'`]+$/g, '').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\]/g, ':')
    .replace(/^hxxp(s?):\/\//i, 'http$1://').replace(/^fxp:\/\//i, 'ftp://');
}

// detect is a value's type when its form says it, '' when it does not: a
// hash by its length, a file by its path or extension, and so on. A
// service, a task, an account name, a command or a remote ID looks like
// any word - the analyst chooses those, nothing is guessed.
function detect(v) {
  for (const [t, n] of Object.entries(HASH_LENGTH)) if (new RegExp(`^[0-9a-fA-F]{${n}}$`).test(v)) return t;
  if (isAddress(v)) return 'address';
  if (/^S-1-\d+(-\d+)+$/i.test(v)) return 'account';
  if (/^(HKLM|HKCU|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS)\\/i.test(v)) return 'registry_key';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return 'url';
  if (isFullPath(v) || v.includes('*')) return 'file';
  if (/^[a-p]{32}$/.test(v)) return 'extension'; // a Chromium extension's ID: 32 letters a to p
  if (/^[^\\/\s]+\.(exe|dll|sys|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|msi|lnk|iso|img|zip|rar|7z|docm|xlsm|pptm|jar)$/i.test(v)) return 'file';
  if (/^(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,63}$/i.test(v)) return 'domain';
  return '';
}

// typeOf reads a type as written in a bulk list or an older profile:
// "hash" is recognised by the value's length, "path" and "file_name"
// (before Signal 0.78.0) are "file", a label ("Hash · MD5") its type.
function typeOf(t, value) {
  const s = (t || '').trim().toLowerCase();
  if (!s) return '';
  if (s === 'hash') return detect(value) in HASH_LENGTH ? detect(value) : '';
  if (s === 'path' || s === 'file_name') return 'file';
  if (TYPES[s]) return s;
  return Object.keys(TYPES).find((k) => TYPES[k][0].toLowerCase() === s) || '';
}

// csvLine splits one line of a bulk list at its commas; a field in double
// quotes may hold commas ("a, b") and doubled quotes.
function csvLine(line) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') quoted = false; else cur += c;
    } else if (c === '"' && !cur.trim()) quoted = true;
    else if (c === ',') { out.push(cur); cur = ''; } else cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

// bulkEntries reads a bulk list - one entry a line: value, type, context;
// the type and the context may be left out (the type is then recognised
// from the value). A header line and empty lines are skipped; a context
// may hold commas.
function bulkEntries(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const [value = '', type = '', ...rest] = csvLine(line);
    const v = refang(value);
    if (!v || (/^value$/i.test(v) && /^type$/i.test(type))) continue;
    out.push({ type: typeOf(type, v) || (type ? '' : detect(v)), value: v, context: rest.join(', ').trim(), chosen: !!type });
  }
  return out;
}

// entryProblem is what Signal would leave out in entry x of list, ''
// when nothing.
function entryProblem(x, list, types) {
  const value = refang(x.value.trim());
  if (!value) return 'a value is required - or remove the row';
  if (!x.type) return 'choose its type';
  if (!types.includes(x.type)) return `${TYPES[x.type][0]} is not a type here`;
  const why = TYPES[x.type][2](value);
  if (why) return why;
  const same = (y) => y.type === x.type && refang(y.value.trim()).toLowerCase() === value.toLowerCase();
  if (list.slice(0, list.indexOf(x)).some(same)) return 'repeated above';
  return '';
}

// WILDCARD is the cost of a file pattern, said here and by Signal.
const WILDCARD = 'a wildcard is compared with every file every record names - slower than a name or a full path';

// today is the date in UTC, as a profile's created is written.
const today = () => new Date().toISOString().slice(0, 10);

// nextVersion is the version an edited profile takes: its last number one
// up ("1" -> "2", "1.4" -> "1.5"), ".1" added when it has none.
function nextVersion(v) {
  if (!v) return '1';
  return /\d+$/.test(v) ? v.replace(/\d+$/, (n) => String(Number(n) + 1)) : `${v}.1`;
}

// windowPicker edits p.window in one of the forms Signal reads - none, the
// last N days or hours, or from a moment in UTC - so it cannot be
// mistyped; a window written otherwise (an imported "90m") is kept as it
// is until another form is chosen. What is not complete is p.windowIssue.
function windowPicker(p, changed) {
  const w = p.window.trim();
  const last = /^(\d+)([dh])$/.exec(w);
  const instant = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/.test(w) ? new Date(w).toISOString().slice(0, 16) : '';
  const now = new Date().toISOString().slice(0, 16);
  const modes = [['none', 'No window - read whole logs'], ['last', 'The last'], ['since', 'From a date and time']];
  if (w && !last && !instant) modes.push(['kept', `As written: ${w}`]);
  const mode = h('select', {}, modes.map(([v, l]) => h('option', { value: v, selected: v === (!w ? 'none' : last ? 'last' : instant ? 'since' : 'kept') ? 'selected' : null }, l)));
  const count = h('input', { class: 'cond-value num', type: 'number', min: 1, step: 1, value: last ? last[1] : '7' });
  const unit = h('select', {}, [['d', 'days'], ['h', 'hours']].map(([v, l]) => h('option', { value: v, selected: v === (last ? last[2] : 'd') ? 'selected' : null }, l)));
  const at = h('input', { type: 'datetime-local', step: 60, max: now, value: instant });
  const parts = h('span', { class: 'row' });
  const draw = () => parts.replaceChildren(...(mode.value === 'last' ? [count, unit, h('span', { class: 'mut' }, 'back from each run')]
    : mode.value === 'since' ? [at, h('span', { class: 'mut' }, 'UTC - the estimated infection time')] : []));
  const set = () => {
    p.windowIssue = '';
    if (mode.value === 'none') p.window = '';
    if (mode.value === 'kept') p.window = w;
    if (mode.value === 'last') {
      p.window = `${count.value}${unit.value}`;
      if (!/^[1-9]\d*$/.test(count.value)) p.windowIssue = 'Window: give a whole number of days or hours, 1 or more.';
    }
    if (mode.value === 'since') {
      p.window = at.value ? `${at.value}:00Z` : '';
      if (!at.value) p.windowIssue = 'Window: choose the date and time it starts.';
      else if (at.value > new Date().toISOString().slice(0, 16)) p.windowIssue = 'Window: it starts in the future.';
    }
    draw();
    changed();
  };
  for (const el of [mode, unit]) el.onchange = set;
  for (const el of [count, at]) el.oninput = set;
  draw();
  return h('div', { class: 'row' }, mode, parts);
}

export async function renderProfilesPage(container) {
  const q = urlParams();
  if (q.get('profile') || q.has('new')) return renderBuilder(container, q.get('profile'));
  return renderList(container);
}

// renderList is every profile saved here or given to a host, and the hosts
// given none.
async function renderList(container) {
  const { profiles, unprofiled } = await fetchJSON('/api/profiles');
  const given = profiles.reduce((n, p) => n + p.hosts.length, 0);
  const columns = [col('name', 'profile_name'), col('version', 'version', { desc: 'The profile\'s own version, as written in it.' }), col('author', 'profile_author', { label: 'Author', icon: 'user', desc: 'Who wrote it, as written in it.' }),
    col('window', 'profile_window'), col('pivots_n'), col('host_n', 'profile_hosts'), col('saved', 'profile_saved'), col('saved_by'), col('sha256', 'profile_sha256')];
  const rows = profiles.map((p) => ({ ...p, host_n: p.hosts.length }));
  // A section with nothing to show is null: left out, never printed.
  container.replaceChildren(...[
    summaryStrip([
      { icon: 'sliders', value: profiles.filter((p) => p.saved).length, label: 'profiles saved here' },
      { icon: 'hosts', value: given, label: 'hosts given a profile' },
      { icon: 'hosts', value: unprofiled.length, label: 'hosts given none', cls: unprofiled.length ? 'sev-medium' : null },
    ], [CORE]),
    h('div', { class: 'card' }, h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => go('settings', { new: 1 }) }, 'New profile'),
      h('span', { class: 'mut' }, 'Write a profile, or import one to edit it; check it here as Signal will, then give it to signal live -profile as a file or as one encoded argument.'))),
    section('Profiles', () => (rows.length
      ? dataTable(rows, columns, { height: 'auto', filename: 'profiles', open: (row) => openPage('settings', { profile: row.sha256 }) })
      : h('div', { class: 'mut' }, 'No profile yet: none is saved here, and no host was given one.')), { collapsed: false, modules: [CORE] }),
    section('Hosts given no profile', () => (unprofiled.length
      ? h('div', {}, h('div', { class: 'mut' }, 'Their latest collection was given no profile - or was made by Signal before 0.54.0, which had none: no window, no pivot points.'), hostLinks(unprofiled))
      : null), { collapsed: false, modules: [CORE] }),
  ].filter(Boolean));
}

// emptyProfile is a new profile, every part present so the builder can
// edit it in place.
const emptyProfile = () => ({ profile: 1, name: '', version: '', author: '', created: '', window: '', modules: {}, suppress: [], baseline: [], pivots: [] });

// isEmpty: a parameter left at Signal's default.
const isEmpty = (v) => v === '' || (Array.isArray(v) && !v.length);

// entriesOut writes pivot points or baseline entries as Signal reads them.
const entriesOut = (list) => list.map((x) => ({ type: x.type, value: refang(x.value.trim()), ...(x.context.trim() ? { context: x.context.trim() } : {}) }));

// serialize writes a profile as JSON, leaving out what is empty - the text
// that is saved, downloaded and encoded, so all three hash alike.
function serialize(p) {
  const out = { profile: 1, name: p.name.trim() };
  for (const k of ['version', 'author', 'created', 'window']) if (p[k].trim()) out[k] = p[k].trim();
  if (p.pivots.length) out.pivots = entriesOut(p.pivots);
  const mods = Object.fromEntries(Object.entries(p.modules).map(([m, ps]) => [m, Object.fromEntries(Object.entries(ps).filter(([, v]) => !isEmpty(v)))]).filter(([, ps]) => Object.keys(ps).length));
  if (Object.keys(mods).length) out.modules = mods;
  if (p.suppress.length) out.suppress = p.suppress;
  if (p.baseline.length) out.baseline = entriesOut(p.baseline);
  return JSON.stringify(out, null, 2) + '\n';
}

// entriesIn reads pivot points or baseline entries as written; "note" is
// what a pivot's context was called before Signal 0.57.0.
const entriesIn = (list) => (Array.isArray(list) ? list : []).map((x) => {
  const value = String(x.value || '');
  return { type: typeOf(String(x.type || ''), value), value, context: String(x.context ?? x.note ?? ''), chosen: true };
});

// parse reads a profile's JSON into the builder's shape; it throws on what
// is not a profile. A profile written before Signal 0.78.0 is read as one
// of today's: its baseline.remote_tools are RemoteAccess's approved_tools.
function parse(text) {
  const doc = JSON.parse(text);
  if (!doc || doc.profile !== 1) throw new Error('not a Signal profile (format version 1)');
  const p = emptyProfile();
  for (const k of ['name', 'version', 'author', 'created', 'window']) p[k] = String(doc[k] || '');
  for (const [m, ps] of Object.entries(doc.modules || {})) p.modules[m] = Object.fromEntries(Object.entries(ps).map(([k, v]) => [k, Array.isArray(v) ? v.map(String) : String(v)]));
  p.suppress = (doc.suppress || []).map((s) => ({ rule: String(s.rule || ''), reason: String(s.reason || '') }));
  const tools = doc.baseline && !Array.isArray(doc.baseline) ? (doc.baseline.remote_tools || []).map(String) : [];
  if (tools.length) p.modules.RemoteAccess = { ...(p.modules.RemoteAccess || {}), approved_tools: tools };
  p.baseline = entriesIn(doc.baseline);
  p.pivots = entriesIn(doc.pivots);
  const known = new Set(['profile', 'name', 'version', 'author', 'created', 'window', 'modules', 'suppress', 'baseline', 'pivots']);
  const unknown = Object.keys(doc).filter((k) => !known.has(k));
  if (unknown.length) throw new Error(`unknown key(s) ${unknown.join(', ')} - Signal refuses them`);
  return p;
}

// problems is everything Signal would leave out of p, in words.
function problems(p, params) {
  const out = [];
  if (!p.name.trim()) out.push('A name is required: every finding says which profile produced it.');
  const w = p.window.trim();
  const duration = /^\d+d$/.test(w) || /^(\d+(\.\d+)?(h|m|s|ms))+$/.test(w);
  const instant = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(w);
  if (w && !duration && !instant) out.push(`Window "${w}": not a time (RFC 3339, e.g. 2026-10-01T08:00:00Z) or a duration back from the run (e.g. 7d, 72h).`);
  else if (instant && Date.parse(w) > Date.now()) out.push(`Window "${w}" starts in the future.`);
  if (p.windowIssue) out.push(p.windowIssue);
  p.pivots.forEach((x, i) => {
    const why = entryProblem(x, p.pivots, PIVOT_TYPES);
    if (why) out.push(`Pivot point ${i + 1} (${x.value.trim() || 'empty'}): ${why}.`);
  });
  for (const [m, ps] of Object.entries(p.modules)) {
    for (const [k, v] of Object.entries(ps)) {
      if (isEmpty(v)) continue;
      const kind = (params[m] || {})[k];
      if (kind === 'int' && !(Number.isInteger(Number(v)) && Number(v) > 0)) out.push(`${m}.${k}: not a whole number above zero.`);
    }
  }
  for (const s of p.suppress) if (!s.reason.trim()) out.push(`Suppressing ${s.rule}: a reason is required.`);
  p.baseline.forEach((x, i) => {
    const why = entryProblem(x, p.baseline, BASELINE_TYPES);
    if (why) out.push(`Baseline entry ${i + 1} (${x.value.trim() || 'empty'}): ${why}.`);
  });
  return out;
}

// notes is what Signal uses but warns about: the wildcards.
const notes = (p) => [...p.pivots.map((x) => ['Pivot point', x]), ...p.baseline.map((x) => ['Baseline entry', x])]
  .filter(([, x]) => x.type === 'file' && x.value.includes('*')).map(([what, x]) => `${what} ${x.value.trim()}: ${WILDCARD}.`);

// encode gives a profile's JSON as Signal's one-line argument: gzip, then
// unpadded base64url (profile.Encode). It needs the browser's
// CompressionStream.
async function encode(text) {
  const stream = new Blob([text]).stream().pipeThrough(new window.CompressionStream('gzip'));
  const bytes = new Uint8Array(await new window.Response(stream).arrayBuffer());
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return window.btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// download hands the browser a file to save.
function download(name, text) {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'application/json' })), download: name });
  document.body.append(a);
  a.click();
  a.remove();
}

// entriesEditor edits p[key] - the pivot points or the baseline - in
// place: one row each, an empty row last to start the next. A value is
// refanged when it is left, its type recognised from its form until the
// analyst chooses one; several lines pasted into a value, or added from a
// file or the bulk box, make one row each (value, type, context). Every
// row says what Signal would leave out of it; the Save waits until none
// does.
function entriesEditor(p, key, types, edited, opts) {
  const box = h('div');
  const draw = () => {
    const body = h('tbody');
    const rowOf = (x) => {
      const status = h('td');
      const type = h('select', { onchange: (e) => { x.type = e.target.value; x.chosen = true; check(); } },
        h('option', { value: '' }, 'choose…'), types.map((t) => h('option', { value: t, title: TYPES[t][1] }, TYPES[t][0])));
      const info = h('span', { class: 'where-info' });
      const value = h('input', { class: 'cond-value', value: x.value, placeholder: x.blank ? opts.placeholder : '' });
      const context = h('input', { class: 'cond-note', value: x.context || '', placeholder: opts.contextHint, oninput: (e) => { x.context = e.target.value; check(); } });
      const remove = h('button', { class: 'ghost danger', title: 'Remove this row', onclick: () => { p[key].splice(p[key].indexOf(x), 1); edited(); draw(); } }, 'Remove');
      const tr = h('tr', {}, h('td', {}, value), h('td', {}, h('span', { class: 'row' }, type, info)), h('td', {}, context), status, h('td', {}, x.blank ? '' : remove));
      // check shows the row's type and what Signal would leave out of it.
      function check(quiet) {
        if (x.blank) return;
        if (!x.chosen) x.type = detect(refang(x.value.trim()));
        type.value = x.type;
        info.replaceChildren(TYPES[x.type] ? withTip(h('span', { class: 'where-mark', 'aria-label': 'where Signal searches' }, 'ⓘ'), whereTip(x.type), 'tip-wide') : '');
        const why = entryProblem(x, p[key], types);
        const wild = !why && x.type === 'file' && x.value.includes('*');
        status.replaceChildren(why ? h('span', { class: 'tagtext sev-high' }, why)
          : wild ? h('span', { class: 'tagtext sev-medium', title: WILDCARD }, 'ready - a wildcard is slower')
            : h('span', { class: 'tagtext st-ran' }, x.context.trim() ? 'ready' : 'ready - add its context'));
        if (!quiet) edited();
      }
      value.oninput = (e) => {
        x.value = e.target.value;
        if (x.blank) { // the empty row becomes an entry, and a new empty row follows
          delete x.blank;
          p[key].push(x);
          value.placeholder = '';
          tr.lastChild.replaceChildren(remove);
          body.append(rowOf({ type: '', value: '', context: '', blank: true }));
        }
        check();
      };
      value.onchange = () => { x.value = refang(x.value); value.value = x.value; check(); };
      value.onpaste = (e) => {
        const text = (e.clipboardData || window.clipboardData).getData('text');
        if (!text.includes('\n')) return;
        e.preventDefault();
        if (!x.blank) p[key].splice(p[key].indexOf(x), 1);
        add(text);
      };
      if (!x.blank) check(true);
      return tr;
    };
    for (const x of p[key]) body.append(rowOf(x));
    body.append(rowOf({ type: '', value: '', context: '', blank: true }));
    const head = (label, tip) => h('th', {}, withTip(label, tip));
    const bulk = h('textarea', { class: 'note', rows: 4, placeholder: 'One a line: value, type, context - e.g.\n203.0.113.9, address, the staging server\nevil.exe\nd41d8cd98f00b204e9800998ecf8427e, hash, the dropper' });
    const file = h('input', { type: 'file', accept: '.txt,.csv,text/plain,text/csv', onchange: async (e) => { const f = e.target.files[0]; if (f) add(await f.text()); } });
    box.replaceChildren(
      h('div', { class: 'tw' }, h('table', { class: 'pivot-table' },
        h('thead', {}, h('tr', {}, head('Value', opts.valueTip),
          head('Type', 'Recognised from the value\'s form - a hash by its length (64: SHA-256, 40: SHA-1, 32: MD5); change it if it is wrong. A service, a task, an account name, a command or a remote ID looks like any word - choose its type.'),
          head('Context', opts.contextTip),
          head('Check', 'What Signal would leave out; "ready" when nothing.'), h('th'))),
        body)),
      opts.note ? h('div', { class: 'mut' }, opts.note) : '',
      detailBlock('Add many', h('div', { class: 'mut' }, 'Paste or upload a text or CSV file: one a line, value, type, context, separated by commas. The type and the context may be left out - the type is then recognised from the value; a context may hold commas, or put the field in double quotes.'),
        bulk, h('div', { class: 'row' }, h('button', { class: 'ghost', onclick: () => { add(bulk.value); bulk.value = ''; } }, 'Add'), h('label', { class: 'ghost' }, 'Upload a file ', file))));
  };
  // add makes one row of each line of a bulk list.
  const add = (text) => {
    p[key].push(...bulkEntries(text));
    edited();
    draw();
  };
  draw();
  return box;
}

// renderBuilder is one profile in the builder: a saved one (hash), or a
// new one. Until it is edited, an opened profile keeps its text as written
// - and so its hash.
async function renderBuilder(container, hash) {
  const [{ modules }, { rules }, list, catalog] = await Promise.all([fetchJSON('/api/modules'), fetchJSON('/api/rules'), fetchJSON('/api/profiles'), fetchJSON('/api/profiles/params')]);
  const listed = hash ? list.profiles.find((x) => x.sha256 === hash) : null;
  let p = emptyProfile();
  let text = null; // the text as written, while unedited
  let saved = null; // the saved profile's text, when one was opened
  if (hash) {
    if (!listed || !listed.saved) {
      container.replaceChildren(h('div', { class: 'card' },
        h('h2', { class: 'card-head' }, listed ? `Profile "${listed.name}"` : 'Profile not found'),
        h('div', { class: 'mut' }, listed
          ? 'This profile is not saved here: only its name and hash are known, from the runs of the hosts that were given it. Import its file in a new profile to see and edit it.'
          : 'No saved profile and no host\'s run has this hash.'),
        listed ? detailBlock('Hosts given it', hostLinks(listed.hosts)) : '',
        detailBlock('SHA-256', mono(hash)),
        h('div', { class: 'row' }, pageLink('settings', {}, 'Every profile'))));
      return;
    }
    text = saved = (await fetchJSON(`/api/profiles/${encodeURIComponent(hash)}`)).text;
    p = parse(text);
  }
  // The stamps are the console's, not typed: a new profile is version 1,
  // created today by the signed-in account; an opened one keeps its author
  // and date, and an edit of it takes the next version.
  let base = null;
  const stamp = () => {
    if (text !== null) base = { version: p.version };
    else Object.assign(p, { version: '1', author: (sessionUser() || {}).username || '', created: today() });
  };
  stamp();
  // Every module's parameters: this console's catalog (Signal's `signal
  // list -json`), then what the imported runs state - a newer Signal's.
  const declared = new Map(catalog.modules.map((m) => [m.name, m.params || []]));
  for (const m of modules) if (m.about && m.about.params) declared.set(m.name, m.about.params);
  const paramModules = [...declared].filter(([, ps]) => ps.length).sort(([a], [b]) => a.localeCompare(b));
  const params = Object.fromEntries(paramModules.map(([m, ps]) => [m, Object.fromEntries(ps.map((x) => [x.name, x.kind]))]));
  const output = h('div');
  const stampLine = h('div', { class: 'profile-text mut' });
  const drawStamp = () => stampLine.replaceChildren(
    `Version ${p.version || '—'} · created ${p.created || '—'} · by ${p.author || '—'} - set by the console${base ? ' (an edit takes the next version)' : ''}.`);
  const edited = () => {
    text = null;
    if (base) p.version = nextVersion(base.version);
    drawStamp();
    drawOutput();
  };

  // Suppressed rules: rule IDs written or pasted, each with the reason.
  const suppressBox = h('div');
  const drawSuppress = () => {
    const ruleOf = (id) => rules.find((r) => r.id === id);
    const ids = h('textarea', { class: 'note', rows: 3, placeholder: 'Rule IDs - one a line, or separated by commas or spaces: EXEC-SUSPICIOUS-LOCATION, PERSIST-TASK-HIDDEN' });
    const reason = h('input', { class: 'cond-note', placeholder: 'Why they are withheld on these hosts (required)' });
    const add = h('button', { class: 'ghost', onclick: () => {
      const given = [...new Set(ids.value.split(/[\s,;]+/).map((s) => s.trim().toUpperCase()).filter(Boolean))];
      if (!given.length || !reason.value.trim()) return window.alert('Give the rule IDs and the reason.');
      const bad = given.filter((id) => !/^[A-Z0-9]+(-[A-Z0-9]+)+$/.test(id));
      if (bad.length) return window.alert(`Not a rule ID (PREFIX-NAME): ${bad.join(', ')}`);
      p.suppress = [...p.suppress.filter((s) => !given.includes(s.rule)), ...given.map((rule) => ({ rule, reason: reason.value.trim() }))];
      edited();
      drawSuppress();
    } }, 'Suppress');
    suppressBox.replaceChildren(
      p.suppress.length ? dataTable(p.suppress.map((s) => ({ ...s, r: ruleOf(s.rule) })), [
        col('rule', 'rule_id'), col('severity', 'severity', { render: (_v, row) => (row.r ? sevTag(row.r.severity) : h('span', { class: 'mut', title: 'Signal suppresses it if a module that runs has it, and warns when none has' }, 'not in these runs')) }),
        col('title', 'title', { render: (_v, row) => (row.r ? row.r.title : '—') }), col('reason', 'suppress_reason', { label: 'Reason', icon: 'reason', desc: 'Why it is withheld: the run\'s rule catalog says it was not run, with this reason.' }),
        col('remove', 'remove_rule', { label: '', render: (_v, row) => h('button', { class: 'ghost danger', onclick: () => { p.suppress = p.suppress.filter((s) => s.rule !== row.rule); edited(); drawSuppress(); } }, 'Remove') }),
      ], { height: 'auto', filename: 'suppressed-rules', detail: (row) => (row.r ? narrative(row.r) : null) }) : h('div', { class: 'mut' }, 'No rule is withheld.'),
      detailBlock('Withhold rules', h('div', { class: 'mut' }, 'A rule of a module that does not run is ignored by Signal - never an error.'), ids, h('div', { class: 'row' }, reason, add)));
  };

  // The output: what Signal would leave out, the JSON, and how to give it.
  const importer = h('input', { type: 'file', accept: '.json', onchange: async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const raw = await file.text();
    try { p = parse(raw); } catch (err) { return window.alert(`${file.name}: ${err.message}`); }
    text = raw;
    stamp();
    renderLoaded();
  } });
  function drawOutput() {
    const bad = problems(p, params);
    const warn = notes(p);
    const json = text ?? serialize(p);
    const cmd = h('div');
    const showCmd = h('button', { class: 'ghost', disabled: bad.length ? 'disabled' : null, onclick: async () => {
      if (!window.CompressionStream) return cmd.replaceChildren(h('div', { class: 'mut' }, 'This browser cannot compress: download the file and run signal profile -encode <file>.'));
      const arg = await encode(json);
      cmd.replaceChildren(codeBlock([[['signal', 'kw'], [' live -all '], ['-profile ', 'field'], [arg, 'val']]]),
        h('div', { class: arg.length > ARG_LIMIT ? 'tagtext sev-high' : 'mut' }, `${arg.length.toLocaleString()} characters${arg.length > ARG_LIMIT ? ' - near Windows\' command line limit (32,767): give the file instead' : ''}.`),
        h('div', { class: 'profile-alarm' }, 'The command line is recorded on the host (Security 4688, Sysmon 1, the EDR): anyone with its logs can read this scope, an intruder still there included. For a sensitive scope, give the file from a share and remove it after the run.'));
    } }, 'Show the command line');
    const save = canEdit() && h('button', { class: 'btn', disabled: bad.length ? 'disabled' : null, onclick: async () => {
      const res = await fetchJSON('/api/profiles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: json }) });
      go('settings', { profile: res.sha256 });
    } }, 'Save here');
    const remove = canEdit() && hash && h('button', { class: 'ghost danger', onclick: async () => {
      if (!confirm('Remove this profile from the console? The runs given it keep its name and hash.')) return;
      await fetchJSON(`/api/profiles/${encodeURIComponent(hash)}`, { method: 'DELETE' });
      go('settings', {});
    } }, 'Remove');
    output.replaceChildren(
      bad.length ? detailBlock('Signal would leave these out', h('ul', { class: 'profile-problems' }, bad.map((b) => h('li', {}, b))))
        : h('div', { class: 'mut' }, 'Checked as Signal checks it; signal profile -check <file> is the final word.'),
      warn.length ? detailBlock('Signal will warn', h('ul', { class: 'profile-notes' }, warn.map((b) => h('li', {}, b)))) : '',
      h('div', { class: 'row' }, save, h('button', { class: 'ghost', disabled: bad.length ? 'disabled' : null, onclick: () => download(`${(p.name || 'profile').replace(/[^\w.-]+/g, '-')}.json`, json) }, 'Download the file'), showCmd, remove),
      cmd,
      detailBlock(json === saved ? 'The profile, as saved' : 'The profile', h('pre', { class: 'code-block' }, json)));
  }

  // renderLoaded draws the builder for p - again after an import.
  function renderLoaded() {
    // field is one labelled input bound to p[key].
    const field = (label, key, placeholder, hint) => [
      h('label', {}, label),
      h('div', {}, h('input', { class: 'cond-value', value: p[key], placeholder, oninput: (e) => { p[key] = e.target.value; edited(); } }), hint ? h('div', { class: 'mut' }, hint) : ''),
    ];
    drawStamp();
    const identity = h('div', { class: 'profile-form' },
      ...field('Name', 'name', 'Finance share - week 42', 'Required. Every run given the profile carries its name and hash.'),
      h('label', {}, 'Window'), h('div', {}, windowPicker(p, edited),
        h('div', { class: 'mut' }, 'Where the focus starts. The event logs are read from this moment on (LogIntegrity alone reads whole logs): an event recorded before it is not read, so what only an older event shows is missed - choose a window that reaches back before the earliest activity you suspect. What the host holds now - services, tasks, auto-starts, installed applications, files - is read whatever the window, and what falls in it is marked as in the period. With no window, whole logs are read and the period rules are not run.')),
      h('label', {}, 'Stamped'), stampLine);

    // A parameter's input by its kind; a list is one entry a line.
    const paramRows = paramModules.flatMap(([m, ps]) => ps.map((x) => {
      const value = (p.modules[m] || {})[x.name] ?? '';
      const set = (v) => { p.modules[m] = { ...(p.modules[m] || {}), [x.name]: v }; edited(); };
      const input = x.kind === 'bool'
        ? h('select', { onchange: (e) => set(e.target.value) }, ['', 'true', 'false'].map((v) => h('option', { value: v, selected: v === value ? 'selected' : null }, v || '(Signal\'s default)')))
        : x.kind === 'list'
          ? h('textarea', { class: 'note', rows: 3, placeholder: 'One a line (empty: not given)', oninput: (e) => set(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean)) }, (Array.isArray(value) ? value : value ? [value] : []).join('\n'))
          : h('input', { class: 'cond-value', type: 'number', min: 1, value, placeholder: '(Signal\'s default)', oninput: (e) => set(e.target.value) });
      return [h('label', {}, mono(`${m}.${x.name}`)), h('div', {}, input, h('div', { class: 'mut' }, x.doc))];
    }));
    const paramsCard = h('div', {}, h('div', { class: 'mut' }, 'Every module that takes parameters. A parameter of a module that does not run is ignored by Signal - never an error.'),
      h('div', { class: 'profile-form' }, ...paramRows.flat()));

    const pivotBox = entriesEditor(p, 'pivots', PIVOT_TYPES, edited, {
      placeholder: 'a new pivot point: a value, or paste several lines',
      valueTip: 'The trace, as Signal will match it - a defanged value (evil[.]example, hxxp://) is refanged. Every type is searched in what the host recorded and what it holds now. A file is a name or a full path; * matches any characters (slower). "File present now" only checks the disk at that path when Signal runs.',
      contextHint: 'where it came from (recommended)',
      contextTip: 'Where it came from - a host, a report, a sample. Optional, but every hit carries it: add it.',
      note: 'Signal searches every record its modules read for them (run it with the Scope module: -all, or -m ...,Scope), and checks full paths and registry keys directly.',
    });
    const baselineBox = entriesEditor(p, 'baseline', BASELINE_TYPES, edited, {
      placeholder: 'an approved element: a value, or paste several lines',
      valueTip: 'What the organisation runs on purpose: a service, a task, a file (a name or a full path; * matches any characters), a hash, an extension, a domain, an account.',
      contextHint: 'why it is approved (recommended)',
      contextTip: 'Why it is approved - the product, the team. Optional; every approved signal carries it.',
      note: 'A signal about an approved element stays in the output, marked approved with its entry - approval is the organisation\'s statement, not proof it is benign. Build it once and give it to every run.',
    });

    drawSuppress();
    container.replaceChildren(
      h('div', { class: 'card' },
        h('h2', { class: 'card-head' }, hash ? `Profile "${p.name}"` : 'New profile'),
        h('div', { class: 'row' }, pageLink('settings', {}, 'Every profile'), h('label', { class: 'ghost' }, 'Import a profile file ', importer)),
        listed ? h('div', { class: 'mut' }, `SHA-256 ${hash} · given to ${listed.hosts.length} host(s)`, listed.hosts.length ? [': ', hostLinks(listed.hosts)] : '') : ''),
      section('Identification and window', () => identity, { collapsed: false, modules: [CORE] }),
      section('Pivot points', () => pivotBox, { collapsed: false, modules: ['Scope'] }),
      section('Module parameters', () => paramsCard, { collapsed: false, modules: paramModules.map(([m]) => m) }),
      section('Rules withheld', () => suppressBox, { collapsed: false, modules: [CORE] }),
      section('Approved baseline', () => baselineBox, { collapsed: false, modules: [CORE] }),
      section('Check and give it to Signal', () => output, { collapsed: false, modules: [CORE] }));
    drawOutput();
  }
  renderLoaded();
}
