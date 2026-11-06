// Storage for imported Signal runs.
//
// A "run" is one JSON document produced by one `signal live` invocation on
// one host. Each is stored verbatim in its data file (src/db.js) and
// kept parsed in memory, upgraded to the current output contract
// (src/legacy.js), for the model to compute from - a data file's runs are
// read on its first use. version() counts changes to its stored set, so
// a cache of anything computed from all() can tell when it is stale (see
// src/cache.js). Every function works on the current data file.
//
// Runs imported by earlier versions of this app, as files in data/runs/,
// are moved into the database once, on first start.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const db = require('./db');
const legacy = require('./legacy');
const { validRunId } = require('./contract');
const { hostOf, byHost } = require('./model/hosts');
const { runSignals } = require('./model/signals');


// migrateFiles imports the run files of an earlier version of this app
// (data/runs/*.json), once; the files are left in place.
function migrateFiles() {
  if (db.meta('migrated_run_files')) return;
  const dir = path.join(db.DATA_DIR, 'runs');
  const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')) : [];
  let n = 0;
  for (const file of files) {
    try {
      const doc = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
      if (validRunId(doc.run_id)) { write(doc); n++; }
    } catch (err) {
      console.error(`store: skipping unreadable file ${file}: ${err.message}`);
    }
  }
  db.meta('migrated_run_files', new Date().toISOString());
  if (n) console.log(`store: moved ${n} run file(s) from ${dir} into the database`);
}

// write stores a document verbatim - text, the bytes as received, when
// given - replacing any run with the same ID (and, with it, its indexed
// rows), and indexes its inventories; answers when it was imported.
function write(doc, importedBy = '', text = JSON.stringify(doc)) {
  const imported = new Date().toISOString();
  db.transaction(() => {
    db.open().prepare(`INSERT OR REPLACE INTO runs (run_id, host, machine_id, started, tool_version, schema_version, imported, imported_by, doc)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(doc.run_id, hostOf(doc), (doc.host && doc.host.machine_id) || '', doc.started || '',
      doc.tool_version || '', Number(doc.schema_version) || 0, imported, importedBy, text);
    indexRun(doc);
  });
  return imported;
}

// INDEXED are Signal's inventories stacked across the fleet by SQL: each
// role's rows are stored in its table (src/db.js), by these columns.
const INDEXED = {
  'inventory.persistence': { table: 'persistence', columns: ['location', 'entry', 'command', 'program', 'user', 'signer', 'signature', 'sources', 'sha256'] }, // schema 14
  'inventory.applications': { table: 'applications', columns: ['name', 'publisher', 'version', 'location', 'installed', 'user', 'sources', 'in_period'] }, // schema 25; in_period 53
  'inventory.browser_extensions': {
    table: 'extensions',
    columns: ['browser', 'user', 'profile', 'id', 'name', 'version', 'installed_by', 'from_store', 'state', 'installed', 'capabilities', 'update_url', 'forced_by', 'in_period'],
  }, // schema 29; in_period 53
  'inventory.group_policy': {
    table: 'group_policy',
    columns: ['guid', 'name', 'version', 'created', 'changed', 'links', 'applied_to', 'applied', 'extensions', 'deploys', 'changed_by', 'in_period', 'read_from'],
  }, // schema 32
  'inventory.remote_tools': {
    table: 'remote_tools',
    columns: ['product', 'kind', 'mode', 'installed', 'portable', 'first_seen', 'last_seen', 'tool_id', 'account', 'tenant', 'server', 'unattended', 'sessions', 'allowed', 'sources'],
  }, // schema 33
  'activity.remote_sessions': {
    table: 'remote_sessions',
    columns: ['product', 'direction', 'start', 'end', 'duration', 'peer_id', 'peer_name', 'address', 'address_scope', 'account', 'auth', 'type', 'transfers', 'log'],
  }, // schema 33
  'inventory.remote_paths': {
    table: 'remote_paths',
    columns: ['kind', 'value', 'detail', 'user', 'changed', 'where'],
  }, // schema 34
  'inventory.web_apps': {
    table: 'web_apps',
    columns: ['server', 'version', 'site', 'bindings', 'roots', 'pools', 'identity', 'holds', 'files', 'last_deployment', 'newest_script', 'logs', 'running',
      'flagged', 'detections', 'sources'],
  }, // schema 35
  'inventory.web_files': {
    table: 'web_files',
    columns: ['server', 'site', 'file', 'url', 'size', 'created', 'modified', 'confidence', 'indicators', 'requests'],
  }, // schema 35
};

// INDEX_KEY marks, in meta, that every stored run was indexed into the
// tables INDEXED names - a new table re-indexes them once.
const INDEX_KEY = 'indexed_' + Object.values(INDEXED).map((x) => x.table).join('_');

// indexRun stores a run's indexed inventories as rows of their tables
// (replacing any it had).
function indexRun(doc) {
  for (const { table } of Object.values(INDEXED)) db.open().prepare(`DELETE FROM ${table} WHERE run_id = ?`).run(doc.run_id);
  for (const r of Object.values(doc.modules || {})) {
    for (const d of r.datasets || []) {
      const ix = INDEXED[d.role];
      if (!ix) continue;
      const ins = db.open().prepare(`INSERT INTO ${ix.table} (run_id, ${ix.columns.map((c) => `"${c}"`).join(', ')}) VALUES (?${', ?'.repeat(ix.columns.length)})`);
      const at = ix.columns.map((c) => d.columns.indexOf(c));
      for (const row of d.rows) ins.run(doc.run_id, ...at.map((i) => (i >= 0 && row[i] != null ? String(row[i]) : '')));
    }
  }
}

// A rule's definition (its text, condition, tags, evidence...) is the
// same in every run of one Signal version, so its values are held once and
// shared by every run's catalog entry; only an entry's outcome on its host
// (PER_RUN) is its own. The values are never changed after import.
const PER_RUN = new Set(['status', 'reason_code', 'reason']);
const definitions = new Map();
function share(entry) {
  for (const [k, v] of Object.entries(entry)) {
    if (PER_RUN.has(k) || v === null || (typeof v !== 'string' && typeof v !== 'object')) continue;
    const key = `${k}\u0000${typeof v === 'string' ? v : JSON.stringify(v)}`;
    if (!definitions.has(key)) definitions.set(key, v);
    entry[k] = definitions.get(key);
  }
}

// lighten drops the indexed rows from a run's in-memory copy - they are
// read from their tables - keeping how many there were, notes each
// dataset's digest, and shares its rules' definitions (above).
function lighten(run) {
  for (const r of Object.values(run.modules || {})) {
    for (const e of r.rule_catalog || []) share(e);
    for (const d of r.datasets || []) {
      // What the dataset held, for a review's fingerprint (src/reviews.js).
      d.digest = crypto.createHash('sha256').update(JSON.stringify(d.rows || [])).digest('hex');
      if (INDEXED[d.role]) {
        d.indexed = d.rows.length;
        d.rows = [];
      }
    }
  }
  return run;
}

// Only each host's latest collection is held whole in memory. An older
// one is a shell: its envelope (host, times, versions), its modules'
// status and KPI cards (the host's collection history), and its signals as
// derived once (runSignals) - what the pages read of a past collection;
// get() reads its whole document from the database when a page asks.
const SHELL_KEYS = ['run_id', 'host', 'user', 'mode', 'tool_version', 'schema_version', 'upgraded_from', 'started', 'finished', 'duration', 'evidence', 'profile'];
function shell(run) {
  const out = { shell: true, signals: runSignals(run), modules: {} };
  for (const k of SHELL_KEYS) if (run[k] !== undefined) out[k] = run[k];
  for (const [name, r] of Object.entries(run.modules || {})) out.modules[name] = { status: r.status, kpis: r.kpis || [] };
  return out;
}

// readRun is a stored run, parsed, upgraded and lightened.
function readRun(runId) {
  const row = db.open().prepare('SELECT doc FROM runs WHERE run_id = ?').get(runId);
  return row ? lighten(legacy.upgrade(JSON.parse(row.doc))) : null;
}

// settle keeps each host's latest run whole and every other a shell, after
// any change to the set - of every host, or only of the host of changed (a
// run just saved or removed): regrouping every host on every save made a
// save cost grow with the number of runs.
function settle(st, changed) {
  let runs = [...st.runs.values()];
  if (changed) {
    const name = hostOf(changed);
    const id = changed.host && changed.host.machine_id;
    // A run without a machine ID joins its name's (hostKeys), so the host's
    // runs are those sharing its name or its machine ID.
    runs = runs.filter((r) => hostOf(r) === name || (id && r.host && r.host.machine_id === id));
  }
  for (const list of byHost(runs).values()) {
    list.forEach((run, i) => {
      if (i === 0 && run.shell) st.runs.set(run.run_id, readRun(run.run_id));
      if (i > 0 && !run.shell) st.runs.set(run.run_id, shell(run));
    });
  }
  st.whole.clear();
}

// load reads the data file's stored runs into memory - each host's latest whole,
// the rest as shells (see above); which is latest is decided from the
// table's columns first, so the older documents are never all held at once.
// arrivals maps run_id -> {imported, imported_by}, when and how each run
// arrived ("upload by <account>", or the address Signal sent it from).
function load() {
  const st = { runs: new Map(), arrivals: new Map(), whole: new Map(), version: 1 };
  const { runs, arrivals } = st;
  migrateFiles();
  const heads = db.open().prepare('SELECT run_id, host, machine_id, started FROM runs').all()
    .map((r) => ({ run_id: r.run_id, started: r.started, host: { hostname: r.host, machine_id: r.machine_id } }));
  const latest = new Set([...byHost(heads).values()].map((list) => list[0].run_id));
  // Runs stored before an indexed table existed are indexed once.
  const reindex = !db.meta(INDEX_KEY);
  for (const { run_id: id } of heads) {
    const row = db.open().prepare('SELECT imported, imported_by, doc FROM runs WHERE run_id = ?').get(id);
    try {
      const doc = JSON.parse(row.doc);
      if (reindex) db.transaction(() => indexRun(doc));
      const run = lighten(legacy.upgrade(doc));
      runs.set(id, latest.has(id) ? run : shell(run));
      arrivals.set(id, { imported: row.imported, imported_by: row.imported_by });
    } catch (err) {
      // One corrupt document must not prevent every other run from loading.
      console.error(`store: skipping unreadable run ${id}: ${err.message}`);
    }
  }
  if (reindex) db.meta(INDEX_KEY, new Date().toISOString());
  settle(st); // a corrupt latest leaves its host's next run latest
  return st;
}

// state is the current data file's runs, read on first use.
const state = () => db.local('store', load);

// save stores an already validated run, with how it arrived; text is the
// document as received (stored as it is - never serialised again on the
// main thread). doc becomes the in-memory copy (upgraded in place), so a
// caller reads only its run_id and host after. Re-importing the same
// run_id replaces the previous copy, so repeating an import is safe.
function save(doc, importedBy, text) {
  if (!validRunId(doc.run_id)) throw new Error(`invalid run_id ${JSON.stringify(doc.run_id)}`);
  const st = state();
  st.arrivals.set(doc.run_id, { imported: write(doc, importedBy, text), imported_by: importedBy });
  st.runs.set(doc.run_id, lighten(legacy.upgrade(doc)));
  settle(st, doc);
  st.version++;
}

function remove(runId) {
  const st = state();
  const gone = st.runs.get(runId);
  if (!gone) return false;
  db.open().prepare('DELETE FROM runs WHERE run_id = ?').run(runId);
  st.runs.delete(runId);
  st.arrivals.delete(runId);
  settle(st, gone);
  st.version++;
  return true;
}

// WHOLE is how many older runs' whole documents get() keeps after reading
// them (a page about a past collection asks several times).
const WHOLE = 8;

// get is a run's whole document: a host's latest from memory, an older one
// read from the database.
function get(runId) {
  const st = state();
  const run = st.runs.get(runId);
  if (!run || !run.shell) return run;
  if (!st.whole.has(runId)) {
    if (st.whole.size >= WHOLE) st.whole.delete(st.whole.keys().next().value);
    st.whole.set(runId, readRun(runId));
  }
  return st.whole.get(runId);
}

// all is every run in memory: each host's latest whole, the rest shells.
const all = () => [...state().runs.values()];
const arrival = (runId) => state().arrivals.get(runId) || { imported: '', imported_by: '' };

const has = (runId) => state().runs.has(runId);

module.exports = { save, remove, get, has, all, arrival, version: () => state().version };
