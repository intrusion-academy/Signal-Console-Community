// The databases: SQLite files (Node's built-in node:sqlite - no extra
// dependency). The main file (signal-console.db) holds what the whole
// console shares: accounts and sessions, Signal's profiles, VirusTotal's
// lookups and settings. The runs and the analysts' work on them (triage,
// suppressions, flags, reviews) are held in a data file: open() is the
// current request's, set by within(), and everything a request calls -
// however deep, across awaits - reads and writes that file. Every file has
// the same schema, versioned (PRAGMA user_version) and upgraded in order
// on open, so a later change adds one step to MIGRATIONS rather than a new
// file format; each uses only its own tables.
//
// The Community edition has one data file: the main file itself
// (server.js runs every request about the data within() it).
//
// The directory is data/ by default; SIGNAL_CONSOLE_DATA (or the name it had
// as Signal Web, SIGNAL_WEB_DATA) points it elsewhere
// (the end-to-end test runs against a fresh one).
'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { AsyncLocalStorage } = require('async_hooks');

// In a release package (launch.js in the install folder, this app in
// app/<version>/ under it) the data is the install folder's, whichever
// version runs - so the account scripts find it too.
const INSTALL = path.join(__dirname, '..', '..', '..');
const PACKAGED = path.basename(path.join(__dirname, '..', '..')) === 'app' && fs.existsSync(path.join(INSTALL, 'launch.js'));
const DATA_DIR = process.env.SIGNAL_CONSOLE_DATA || process.env.SIGNAL_WEB_DATA || (PACKAGED ? path.join(INSTALL, 'data') : path.join(__dirname, '..', 'data'));

// MIGRATIONS are the schema's versions, in order; index i brings the
// database from version i to i+1.
const MIGRATIONS = [
  `
  -- runs: each imported document verbatim (doc), with the columns every
  -- listing needs, so a listing never parses a document.
  CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    machine_id TEXT NOT NULL DEFAULT '',
    started TEXT NOT NULL DEFAULT '',
    tool_version TEXT NOT NULL DEFAULT '',
    schema_version INTEGER NOT NULL DEFAULT 0,
    imported TEXT NOT NULL,
    doc TEXT NOT NULL
  );
  CREATE INDEX runs_host ON runs (host);

  -- triage: the current state of each triaged signal, by stable ID;
  -- triage_history: every change, in order - who decided what, when.
  CREATE TABLE triage (sid TEXT PRIMARY KEY, state TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', updated TEXT NOT NULL);
  CREATE TABLE triage_history (id INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT NOT NULL, state TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', at TEXT NOT NULL);
  CREATE INDEX triage_history_sid ON triage_history (sid);

  CREATE TABLE suppressions (id TEXT PRIMARY KEY, conditions TEXT NOT NULL, note TEXT NOT NULL, created TEXT NOT NULL);

  -- meta: one-time facts, such as which old files were migrated.
  CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  `,
  `
  -- users: local accounts (see src/auth.js). role is analyst (every
  -- action) or viewer (read-only); password is an scrypt hash.
  CREATE TABLE users (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('analyst', 'viewer')),
    password TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL
  );
  -- sessions: one row per signed-in browser, by the SHA-256 of its token
  -- (the token itself is only ever in the browser's cookie).
  CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users (username) ON DELETE CASCADE,
    created TEXT NOT NULL,
    last_seen TEXT NOT NULL
  );
  -- Who made each triage decision and suppression rule (empty for those
  -- made before accounts existed).
  ALTER TABLE triage ADD COLUMN decided_by TEXT NOT NULL DEFAULT '';
  ALTER TABLE triage_history ADD COLUMN decided_by TEXT NOT NULL DEFAULT '';
  ALTER TABLE suppressions ADD COLUMN created_by TEXT NOT NULL DEFAULT '';
  `,
  `
  -- How each run arrived: "upload by <account>", or the address Signal sent it from
  -- (empty for runs imported before this was recorded).
  ALTER TABLE runs ADD COLUMN imported_by TEXT NOT NULL DEFAULT '';
  `,
  `
  -- persistence: every run's persistent entries (Signal's
  -- inventory.persistence table), one row each, so the fleet is stacked by
  -- SQL rather than in memory; a run's rows go with it.
  CREATE TABLE persistence (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    location TEXT NOT NULL, entry TEXT NOT NULL, command TEXT NOT NULL, program TEXT NOT NULL,
    user TEXT NOT NULL, signer TEXT NOT NULL, signature TEXT NOT NULL, sources TEXT NOT NULL
  );
  CREATE INDEX persistence_run ON persistence (run_id);
  CREATE INDEX persistence_group ON persistence (location, entry, program);
  `,
  `
  -- each persistent entry's program hash (Signal schema 24); the entries an
  -- analyst flagged, fleet-wide, by the entry's identity (location, entry
  -- and program, lower case) - with who and when.
  ALTER TABLE persistence ADD COLUMN sha256 TEXT NOT NULL DEFAULT '';
  CREATE TABLE autorun_flags (
    location TEXT NOT NULL, entry TEXT NOT NULL, program TEXT NOT NULL,
    flagged_by TEXT NOT NULL, at TEXT NOT NULL,
    PRIMARY KEY (location, entry, program)
  );
  `,
  `
  -- applications: every run's installed applications (Signal's
  -- inventory.applications, schema 25), one row each, stacked by SQL.
  CREATE TABLE applications (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    name TEXT NOT NULL, publisher TEXT NOT NULL, version TEXT NOT NULL, location TEXT NOT NULL,
    installed TEXT NOT NULL, user TEXT NOT NULL, sources TEXT NOT NULL
  );
  CREATE INDEX applications_run ON applications (run_id);
  CREATE INDEX applications_group ON applications (name, publisher);
  `,
  `
  -- flags: an analyst's red flag on a row of any fleet inventory (an
  -- autorun, an application, a listening port, an Internet address, an
  -- antivirus exclusion), by its kind and identity - with how it is named,
  -- who flagged it and when (src/flags.js). The autoruns' flags move in.
  CREATE TABLE flags (
    kind TEXT NOT NULL, key TEXT NOT NULL, label TEXT NOT NULL,
    flagged_by TEXT NOT NULL, at TEXT NOT NULL,
    PRIMARY KEY (kind, key)
  );
  INSERT INTO flags (kind, key, label, flagged_by, at)
    SELECT 'autoruns', lower(location) || char(0) || entry || char(0) || program, location || ': ' || entry || ' -> ' || program, flagged_by, at FROM autorun_flags;
  DROP TABLE autorun_flags;
  `,
  `
  -- covers: an entity's triage (Signal schema 28 - an entity on a host,
  -- triaged as a whole) records the signals it was decided over, as a JSON
  -- list of their sids; a signal that appears later is not covered. Empty
  -- for a signal's own triage.
  ALTER TABLE triage ADD COLUMN covers TEXT NOT NULL DEFAULT '';
  ALTER TABLE triage_history ADD COLUMN covers TEXT NOT NULL DEFAULT '';
  `,
  `
  -- extensions: every run's browser extensions (Signal's
  -- inventory.browser_extensions, schema 29), one row per extension per
  -- browser profile, stacked by SQL.
  CREATE TABLE extensions (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    browser TEXT NOT NULL, user TEXT NOT NULL, profile TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
    installed_by TEXT NOT NULL, from_store TEXT NOT NULL, state TEXT NOT NULL, installed TEXT NOT NULL, capabilities TEXT NOT NULL,
    update_url TEXT NOT NULL, forced_by TEXT NOT NULL
  );
  CREATE INDEX extensions_run ON extensions (run_id);
  CREATE INDEX extensions_group ON extensions (id);
  `,
  `
  -- group_policy: every run's Group Policy objects (Signal's
  -- inventory.group_policy, schema 32) - a domain controller's SYSVOL, a
  -- member's applied GPOs - one row per GPO per run, stacked by SQL.
  CREATE TABLE group_policy (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    guid TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, created TEXT NOT NULL, changed TEXT NOT NULL, links TEXT NOT NULL,
    applied_to TEXT NOT NULL, applied TEXT NOT NULL, extensions TEXT NOT NULL, deploys TEXT NOT NULL, changed_by TEXT NOT NULL,
    in_period TEXT NOT NULL, read_from TEXT NOT NULL
  );
  CREATE INDEX group_policy_run ON group_policy (run_id);
  CREATE INDEX group_policy_group ON group_policy (guid);
  `,
  `
  -- remote_tools and remote_sessions: every run's remote access products
  -- and the sessions their logs record (Signal's inventory.remote_tools and
  -- activity.remote_sessions, schema 33), stacked by SQL - a product by its
  -- name, a peer by its product and ID.
  CREATE TABLE remote_tools (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    product TEXT NOT NULL, kind TEXT NOT NULL, mode TEXT NOT NULL, installed TEXT NOT NULL, portable TEXT NOT NULL, first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, tool_id TEXT NOT NULL, account TEXT NOT NULL, tenant TEXT NOT NULL, server TEXT NOT NULL, unattended TEXT NOT NULL,
    sessions TEXT NOT NULL, allowed TEXT NOT NULL, sources TEXT NOT NULL
  );
  CREATE INDEX remote_tools_run ON remote_tools (run_id);
  CREATE INDEX remote_tools_group ON remote_tools (product);
  CREATE TABLE remote_sessions (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    product TEXT NOT NULL, direction TEXT NOT NULL, start TEXT NOT NULL, "end" TEXT NOT NULL, duration TEXT NOT NULL, peer_id TEXT NOT NULL,
    peer_name TEXT NOT NULL, address TEXT NOT NULL, address_scope TEXT NOT NULL, account TEXT NOT NULL, auth TEXT NOT NULL, type TEXT NOT NULL,
    transfers TEXT NOT NULL, log TEXT NOT NULL
  );
  CREATE INDEX remote_sessions_run ON remote_sessions (run_id);
  CREATE INDEX remote_sessions_group ON remote_sessions (product, peer_id);
  `,
  `
  -- remote_paths: every run's own Windows ways in (Signal's
  -- inventory.remote_paths, schema 34) - port forwards, SSH keys, WinRM,
  -- Remote Assistance, shadowing - stacked by kind and value.
  CREATE TABLE remote_paths (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    kind TEXT NOT NULL, value TEXT NOT NULL, detail TEXT NOT NULL, user TEXT NOT NULL, changed TEXT NOT NULL, "where" TEXT NOT NULL
  );
  CREATE INDEX remote_paths_run ON remote_paths (run_id);
  CREATE INDEX remote_paths_group ON remote_paths (kind, value);
  `,
  `
  -- web_apps and web_files: every run's web sites and the scripts with a
  -- webshell indicator (Signal's inventory.web_apps and inventory.web_files,
  -- schema 35) - a site stacked by its server, name and folders, a script
  -- by its path.
  CREATE TABLE web_apps (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    server TEXT NOT NULL, version TEXT NOT NULL, site TEXT NOT NULL, bindings TEXT NOT NULL, roots TEXT NOT NULL, pools TEXT NOT NULL,
    identity TEXT NOT NULL, holds TEXT NOT NULL, files TEXT NOT NULL, last_deployment TEXT NOT NULL, newest_script TEXT NOT NULL, logs TEXT NOT NULL,
    running TEXT NOT NULL, flagged TEXT NOT NULL, detections TEXT NOT NULL, sources TEXT NOT NULL
  );
  CREATE INDEX web_apps_run ON web_apps (run_id);
  CREATE TABLE web_files (
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    server TEXT NOT NULL, site TEXT NOT NULL, file TEXT NOT NULL, url TEXT NOT NULL, size TEXT NOT NULL, created TEXT NOT NULL, modified TEXT NOT NULL,
    confidence TEXT NOT NULL, indicators TEXT NOT NULL, requests TEXT NOT NULL
  );
  CREATE INDEX web_files_run ON web_files (run_id);
  CREATE INDEX web_files_group ON web_files (file);
  `,
  `
  -- profiles: Signal's scoping profiles saved here (the Profiles page), by
  -- the SHA-256 of their JSON as written - the hash a run reports, so a
  -- run links to the profile it was given; who saved each, and when.
  CREATE TABLE profiles (
    sha256 TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    doc TEXT NOT NULL,
    saved_by TEXT NOT NULL DEFAULT '',
    saved_at TEXT NOT NULL
  );
  `,
  `
  -- in_period: Signal 0.60.0 (schema 53) states for each application and
  -- extension whether it was installed in the period the profile gave
  -- (Signal's in-period rules became this column); empty for older runs.
  ALTER TABLE applications ADD COLUMN in_period TEXT NOT NULL DEFAULT '';
  ALTER TABLE extensions ADD COLUMN in_period TEXT NOT NULL DEFAULT '';
  `,
  `
  -- reviews: an analyst marked a data page (an inventory) reviewed on a
  -- host, for that host's inventory as it was (fingerprint: the page's
  -- datasets in the host's latest collection) - a changed inventory is
  -- not reviewed again until marked.
  CREATE TABLE reviews (
    page TEXT NOT NULL, host TEXT NOT NULL, fingerprint TEXT NOT NULL,
    reviewed_by TEXT NOT NULL, at TEXT NOT NULL,
    PRIMARY KEY (page, host)
  );
  -- virustotal: the VirusTotal lookups of hashes, IP addresses and
  -- domains (src/virustotal.js) - queued, then looked up in turn; state
  -- queued / done / not_found / failed; result is VirusTotal's answer, kept
  -- apart from Signal's findings.
  CREATE TABLE virustotal (
    kind TEXT NOT NULL, value TEXT NOT NULL, state TEXT NOT NULL,
    malicious INTEGER, suspicious INTEGER, harmless INTEGER, undetected INTEGER,
    detail TEXT NOT NULL DEFAULT '', looked_up TEXT NOT NULL DEFAULT '', queued TEXT NOT NULL,
    PRIMARY KEY (kind, value)
  );
  CREATE INDEX virustotal_state ON virustotal (state, queued);
  `,
  `
  -- This step adds a table of another edition; it adds nothing here, so
  -- the steps that follow keep their numbers in every edition.
  SELECT 1;
  `,
  `
  -- the admin role (every action). SQLite cannot change a CHECK, so the
  -- table is made again; every session ends.
  CREATE TABLE users_new (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    password TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL
  );
  INSERT INTO users_new SELECT username, role, password, disabled, created FROM users;
  DELETE FROM sessions;
  DROP TABLE users;
  ALTER TABLE users_new RENAME TO users;
  `,
  `
  -- analyst_entities, analyst_links: what an analyst added to the entity
  -- graph by hand (src/analystGraph.js) - an entity Signal did not report,
  -- and a link between any two of the graph's entities (an entity's graph
  -- key, or analyst:<id>), with the words that say what it is. Marked as
  -- the analyst's everywhere they show, never mixed with Signal's.
  CREATE TABLE analyst_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    added_by TEXT NOT NULL,
    at TEXT NOT NULL
  );
  CREATE TABLE analyst_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    a TEXT NOT NULL,
    b TEXT NOT NULL,
    words TEXT NOT NULL DEFAULT '',
    added_by TEXT NOT NULL,
    at TEXT NOT NULL
  );
  `,
  `
  -- timeline_tags: an analyst's tags on a Timeline item - a signal by its
  -- sid, an analyst's event by manual:<id> (src/timeline.js).
  -- timeline_events: what an analyst added to the timeline by hand, at the
  -- time they give - never Signal's, marked as theirs wherever it shows.
  CREATE TABLE timeline_tags (
    item TEXT NOT NULL,
    tag TEXT NOT NULL,
    added_by TEXT NOT NULL,
    at TEXT NOT NULL,
    PRIMARY KEY (item, tag)
  );
  CREATE TABLE timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    entity_type TEXT NOT NULL DEFAULT '',
    entity_name TEXT NOT NULL DEFAULT '',
    added_by TEXT NOT NULL,
    at TEXT NOT NULL
  );
  `,
  `
  -- flags.reason: why the analyst flagged the row (required since console
  -- 0.102.0; empty for older flags) - shown in Flagged items, the triage
  -- notes and the report.
  ALTER TABLE flags ADD COLUMN reason TEXT NOT NULL DEFAULT '';
  `,
  `
  -- nvd: NVD's affected versions of the CVEs CISA's KEV catalog lists for
  -- an installed application (src/nvd.js) - state done / not_found /
  -- failed, ranges the vulnerable application CPEs as JSON. Main file only.
  CREATE TABLE nvd (
    cve TEXT PRIMARY KEY, state TEXT NOT NULL, ranges TEXT NOT NULL DEFAULT '[]', looked_up TEXT NOT NULL
  );
  `,
  `
  -- audit: sign-ins and refused sign-ins, sign-outs, account changes and
  -- every run removed (src/audit.js) - never a secret. Main file only.
  CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT ''
  );
  `,
];

// files maps a database file to its connection and the state the modules
// keep computed from it (local).
const files = new Map();
const scope = new AsyncLocalStorage();

// connect returns a file's connection, creating and upgrading the database
// on first use.
function connect(file) {
  let f = files.get(file);
  if (f) return f.conn;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const conn = new DatabaseSync(file);
  conn.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  const version = conn.prepare('PRAGMA user_version').get().user_version;
  for (let v = version; v < MIGRATIONS.length; v++) {
    transaction(() => {
      conn.exec(MIGRATIONS[v]);
      conn.exec(`PRAGMA user_version = ${v + 1}`);
    }, conn);
  }
  f = { conn, local: new Map() };
  files.set(file, f);
  return conn;
}

const MAIN = path.join(DATA_DIR, 'signal-console.db');

// main returns the main database.
function main() {
  // The app was Signal Web until 0.55.0: its database file moves to the new
  // name once (with its WAL and shared-memory files).
  const old = path.join(DATA_DIR, 'signal-web.db');
  if (!files.has(MAIN) && !fs.existsSync(MAIN) && fs.existsSync(old)) {
    for (const ext of ['', '-wal', '-shm']) if (fs.existsSync(old + ext)) fs.renameSync(old + ext, MAIN + ext);
  }
  return connect(MAIN);
}

// openAll opens - and so migrates - every database file (launch.js's trial
// of a new version: src/updates.js).
function openAll() {
  main();
}

// within runs fn with file as the current data file (open()).
const within = (file, fn) => scope.run(file, fn);

function currentFile() {
  const file = scope.getStore();
  if (!file) throw new Error('no data file selected');
  return file;
}

// open returns the current data file's database.
const open = () => connect(currentFile());

// local returns the state named name that a module keeps for the current
// data file, made by init on first use.
function local(name, init) {
  const file = currentFile();
  connect(file);
  const l = files.get(file).local;
  if (!l.has(name)) l.set(name, init());
  return l.get(name);
}

// loaded lists the files whose module state named name was made.
const loaded = (name) => [...files].filter(([, f]) => f.local.has(name)).map(([file]) => file);

// close closes one file's database, or every one (tests
// that remove their data directory).
function close(file) {
  for (const [f, { conn }] of files) {
    if (file && f !== file) continue;
    conn.close();
    files.delete(f);
  }
}

// transaction runs fn atomically on conn (the current data file's database by
// default): everything it writes, or nothing.
function transaction(fn, conn = open()) {
  conn.exec('BEGIN');
  try {
    const out = fn();
    conn.exec('COMMIT');
    return out;
  } catch (err) {
    conn.exec('ROLLBACK');
    throw err;
  }
}

// meta reads or (with a value) writes a one-time fact, in conn (the
// current data file's database by default).
function meta(key, value, conn = open()) {
  if (value === undefined) return (conn.prepare('SELECT value FROM meta WHERE key = ?').get(key) || {}).value;
  conn.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').run(key, String(value));
  return value;
}

module.exports = { main, open, openAll, within, local, loaded, close, transaction, meta, DATA_DIR, MAIN };
