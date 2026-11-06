// Flags: an analyst's red flag on a row of a fleet inventory - an autorun,
// an application, a listening port, an Internet address, an antivirus
// exclusion - kept fleet-wide by the row's identity (its kind and key),
// with who flagged it and when (src/db.js, flags). A row is also flagged
// when a rule's signal names it (its rules); an analyst's flag is set and
// removed by hand, a rule's stays while its signal does. One feature for
// every inventory: a new one names its kind here and calls apply.
'use strict';

const db = require('./db');

// KINDS is what can be flagged: its name, the page it is on, and a row's
// identity - its key parts and how the flags list names it.
const KINDS = {
  // An autorun is one variant of its entry (persistence.js: the command, file hash and signature too -
  // the user, 2026-11-04); a flag set before keyed the entry alone (its first 3 parts, LEGACY_PARTS).
  autoruns: { label: 'Autoruns', page: 'autoruns', identity: (r) => [[r.location, r.entry, r.program, r.command, r.sha256, r.signature], `${r.location}: ${r.entry} -> ${r.command || r.program}`] },
  applications: { label: 'Applications', page: 'applications', identity: (r) => [[r.name, r.publisher], r.publisher ? `${r.name} (${r.publisher})` : r.name] },
  extensions: { label: 'Browser extensions', page: 'extensions', identity: (r) => [[r.id], r.names ? `${r.names} (${r.id})` : r.id] },
  group_policy: { label: 'Group Policy', page: 'grouppolicy', identity: (r) => [[r.guid], r.names ? `${r.names} ${r.guid}` : r.guid] },
  remote_tools: { label: 'Remote access - tools', page: 'remoteaccess', identity: (r) => [[r.product], r.product] },
  remote_peers: { label: 'Remote access - peers', page: 'remoteaccess', identity: (r) => [[r.product, r.peer_id], `${r.product} ID ${r.peer_id}`] },
  remote_paths: { label: "Remote access - Windows' own ways in", page: 'remoteaccess', identity: (r) => [[r.kind, r.path_value], `${r.kind}: ${r.path_value}`] },
  web_sites: { label: 'Web servers - sites', page: 'webservers', identity: (r) => [[r.server, r.site, r.roots], `${r.server} ${r.site}`] },
  web_scripts: { label: 'Web servers - scripts', page: 'webservers', identity: (r) => [[r.file], r.file] },
  listeners: {
    label: 'Network - listening ports', page: 'network',
    identity: (r) => [[r.protocol, r.address, r.port, r.program], `${r.protocol} ${r.address}:${r.port} ${r.program || '(program unknown)'}`],
  },
  remote_addresses: { label: 'Network - Internet addresses', page: 'network', identity: (r) => [[r.address, r.port, r.program], `${r.address}:${r.port} ${r.program || '(program unknown)'}`] },
  av_exclusions: { label: 'Protection - antivirus exclusions', page: 'protection', identity: (r) => [[r.product, r.kind, r.exclusion], `${r.product} ${r.kind}: ${r.exclusion}`] },
  // An entity of the graph by its graph key (model/entities.js nodeId; an
  // analyst's entity is analyst:<id>).
  entities: { label: 'Entities (the graph)', page: 'overview', identity: (r) => [[r.node || r.id], `${r.type}: ${r.display}`] },
};

// FLAGGED is the flagged column's value: text, so a column filter picks it.
const FLAGGED = { yes: 'flagged', no: 'not flagged' };

// keyOf is a row's identity from its parts: case folded, as Windows
// compares names and paths.
const keyOf = (...parts) => parts.map((p) => String(p ?? '').toLowerCase()).join('\u0000');

// LEGACY_PARTS: a kind whose identity grew, and how many parts its older
// flags' keys have - such a flag still covers every row that starts with
// it, until it is removed (removing it from any of them removes it).
const LEGACY_PARTS = { autoruns: 3 };
const legacyKey = (kind, key) => (LEGACY_PARTS[kind] ? key.split('\u0000').slice(0, LEGACY_PARTS[kind]).join('\u0000') : null);

// keyOfRow is a row's identity key as its kind names it.
const keyOfRow = (kind, row) => keyOf(...KINDS[kind].identity(row)[0]);

// apply sets each row's flag: its identity (flag_kind, flag_key, and
// flag_label - how the flags list names it), the rules whose signals name
// it (flag_rules), the console's flags (flag_console: each console rule
// with its reason), the analyst's flag (flagged_by_analyst: who and when;
// flag_reason) and flagged. rulesOf(row) is the rules ("ID: title"), consoleOf(row)
// the console's flags ({rule, reason}). The rows are copied, never
// changed (they may be cached).
function apply(kind, rows, rulesOf = () => [], consoleOf = () => []) {
  const identity = KINDS[kind].identity;
  const analyst = new Map(db.open().prepare('SELECT key, flagged_by, at, reason FROM flags WHERE kind = ?').all(kind).map((f) => [f.key, f]));
  return rows.map((row) => {
    const [parts, label] = identity(row);
    const key = keyOf(...parts);
    const mark = analyst.get(key) || analyst.get(legacyKey(kind, key));
    const rules = rulesOf(row);
    const byConsole = consoleOf(row);
    return {
      ...row, flag_kind: kind, flag_key: key, flag_label: label, flag_rules: rules.join('\n'),
      flag_console: byConsole.map((f) => `${f.rule}: ${f.reason}`).join('\n'),
      flagged_by_analyst: mark ? `${mark.flagged_by} (${mark.at})` : '', flag_reason: mark ? mark.reason : '',
      flagged: rules.length || byConsole.length || mark ? FLAGGED.yes : FLAGGED.no,
    };
  });
}

// set flags a row, fleet-wide, by the analyst `by` with their reason -
// or removes the flag (on false). It returns an error message, or '' when
// done: a kind that cannot be flagged, or a flag without a reason.
function set(kind, key, label, on, by, reason) {
  if (!KINDS[kind] || !key) return 'not a row that can be flagged';
  const conn = db.open();
  if (on) {
    if (!String(reason || '').trim()) return 'a flag needs the reason why';
    conn.prepare('INSERT OR REPLACE INTO flags (kind, key, label, flagged_by, at, reason) VALUES (?, ?, ?, ?, ?, ?)')
      .run(kind, String(key), String(label || ''), String(by || ''), new Date().toISOString(), String(reason).trim());
  } else {
    conn.prepare('DELETE FROM flags WHERE kind = ? AND key IN (?, ?)').run(kind, String(key), legacyKey(kind, String(key)) || String(key));
  }
  return '';
}

// prune removes the analyst flags whose row no longer exists in the data
// (rowsByKind: each kind's current rows) - a removed run takes the flags
// of what only it had with it.
function prune(rowsByKind) {
  const conn = db.open();
  for (const kind of Object.keys(KINDS)) {
    const present = new Set((rowsByKind[kind] || []).flatMap((r) => [keyOfRow(kind, r), legacyKey(kind, keyOfRow(kind, r))]));
    for (const f of conn.prepare('SELECT key FROM flags WHERE kind = ?').all(kind)) {
      if (!present.has(f.key)) conn.prepare('DELETE FROM flags WHERE kind = ? AND key = ?').run(kind, f.key);
    }
  }
}

// list is every analyst's flag, newest first, with where it is - source
// "analyst", by the account, with its reason.
function list() {
  return db.open().prepare('SELECT kind, key, label, flagged_by, at, reason FROM flags ORDER BY at DESC, kind, key').all()
    .map((f) => ({ ...f, source: 'analyst', rule: '', where: (KINDS[f.kind] || {}).label || f.kind, page: (KINDS[f.kind] || {}).page || '' }));
}

module.exports = { apply, set, list, prune, keyOf, KINDS, FLAGGED };
