// Updates (Signal's updates documentation): how Signal Console learns of a new
// version of itself and of Signal, and - installed from a release package
// and started by launch.js - updates itself.
//
// The update file, updates.json, is the one Signal reads: an envelope
// holding the manifest's exact bytes, an Ed25519 signature over them and
// the signing key's ID. It is trusted for its signature, never for where it
// was found: the places below, the mirrors a verified file names (kept
// here), and an admin's own (Settings > Updates) are tried in turn, and an
// offline copy can be uploaded. KEYS and SOURCES are the same as Signal's
// internal/update; the format only grows (a newer one says to update by
// hand).
//
// Modes: "managed" when launch.js started this console (it sets
// SIGNAL_CONSOLE_ROOT) - a new version is downloaded, checked, unpacked
// beside the running one, the data backed up, and the console restarted
// into it; launch.js rolls back if it does not start. "notify" otherwise (a
// git checkout, `node server.js`) - the update is announced, never applied.
//
// Automatic updates are on by default (an admin turns them off). With them
// on, a new version is applied when the console is idle; one that withdraws
// the running version is applied at once (after a two-minute notice). With
// them off nothing changes by itself: a withdrawn version shows a red
// banner to every user until an admin updates.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const db = require('./db');
const tasks = require('./tasks');
const { unzip } = require('./zip');

const VERSION = require('../package.json').version;
const PRODUCT = 'signal-console';
const FORMAT = 1;

// KEYS are the release public keys by key ID (internal/update.Keys).
const KEYS = {
  '0d7b64c9': '8TWuysi3mfdDAnwKL/u+5id41VjIX83DAbBIJn+Gxww=', // in use (generated 2026-10-26)
  '85cd7db0': 'a5Bj22Wh8qKRMBqD9JxogDKUKSRY+XiN3sPYpxeHGSk=', // backup, kept offline
};

// SOURCES are where the update file is looked for (internal/update.Sources).
const SOURCES = [
  'https://signal-update.intrusion.academy/updates.json',
];

const CHECK_EVERY = 6 * 3600 * 1000;
const NOTICE = 2 * 60 * 1000; // the warning before a restart
const RESTART = 75; // launch.js: restart into current.json's version
const BACKUPS_KEPT = 2;

// The install folder (launch.js's) when managed, else ''.
const ROOT = process.env.SIGNAL_CONSOLE_ROOT || '';
const managed = () => Boolean(ROOT) && fs.existsSync(path.join(ROOT, 'app'));

// ---- the file -------------------------------------------------------------

// parse reads X.Y.Z, or null.
function parse(v) {
  const m = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(String(v));
  return m ? m.slice(1).map(Number) : null;
}

// compare orders two X.Y.Z versions; one that is not sorts first.
function compare(a, b) {
  const x = parse(a);
  const y = parse(b);
  if (!x || !y) return (x ? 1 : 0) - (y ? 1 : 0);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

// check throws on the first thing wrong with a manifest (as Signal's).
function check(m) {
  if (!m || m.format < 1 || m.format > FORMAT) throw new Error(`manifest: format ${m && m.format}`);
  if (!Date.parse(m.issued) || !(Date.parse(m.expires) > Date.parse(m.issued))) throw new Error('manifest: issued and expires must be set, expires after issued');
  if (!m.products || !Object.keys(m.products).length) throw new Error('manifest: no products');
  const http = (u) => /^https?:\/\//.test(String(u));
  for (const [name, p] of Object.entries(m.products)) {
    if (!parse(p.latest)) throw new Error(`manifest: ${name}: latest is not X.Y.Z`);
    if (!Array.isArray(p.urls) || !p.urls.length || !(p.size > 0)) throw new Error(`manifest: ${name}: urls and size are required`);
    if (![...p.urls, ...(m.mirrors || [])].every(http)) throw new Error('manifest: an address is not http(s)');
    if (!/^[0-9a-fA-F]{64}$/.test(p.sha256 || '')) throw new Error(`manifest: ${name}: sha256 must be 64 hex digits`);
    for (const w of p.withdrawn || []) {
      if (!w.version === !w.below || !parse(w.version || w.below) || !w.reason) throw new Error(`manifest: ${name}: a withdrawal needs version or below, and a reason`);
    }
  }
}

// verify returns the manifest of an update file signed by one of keys;
// it throws on anything else.
function verify(text, keys = KEYS) {
  let env;
  try {
    env = JSON.parse(String(text));
  } catch {
    throw new Error('not an update file');
  }
  const pub = keys[env && env.key];
  if (!pub) throw new Error(`signed by key "${env && env.key}", which this console does not know`);
  const key = crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pub, 'base64')]), format: 'der', type: 'spki' });
  const manifest = Buffer.from(String(env.manifest || ''), 'base64');
  if (!crypto.verify(null, manifest, key, Buffer.from(String(env.signature || ''), 'base64'))) {
    throw new Error('the signature does not match: the file was changed or not made by the release key');
  }
  const m = JSON.parse(manifest.toString('utf8'));
  if (m.format > FORMAT) throw new Error(`the update file is format ${m.format}; this console reads format ${FORMAT} - download the new version by hand`);
  check(m);
  return m;
}

// withdrawalOf is the withdrawal naming version in a product, or null.
function withdrawalOf(product, version) {
  if (!product || !parse(version)) return null;
  return (product.withdrawn || []).find((w) => (w.version && compare(version, w.version) === 0) || (w.below && compare(version, w.below) < 0)) || null;
}

// ---- state ----------------------------------------------------------------

const meta = (key, value) => db.meta(key, value, db.main());
const state = { checking: false, downloading: null, pending: null, error: '', problems: [], source: '', checked_at: '' };
let busy = 0; // runs being received

// manifest is the newest verified file kept, or null.
function manifest() {
  const text = meta('updates_file');
  if (!text) return null;
  try {
    return verify(text);
  } catch {
    return null;
  }
}

const auto = () => meta('updates_auto') !== '0';
const customSources = () => JSON.parse(meta('updates_sources') || '[]');

// keep stores a verified file unless an older one than already kept: a
// replayed old file never takes back what a newer one said.
function keep(text, m, source) {
  const kept = manifest();
  if (kept && Date.parse(m.issued) < Date.parse(kept.issued)) throw new Error(`older (signed ${m.issued}) than the one already read (${kept.issued})`);
  meta('updates_file', text);
  meta('updates_mirrors', JSON.stringify(m.mirrors || []));
  state.source = source;
}

// ---- checking -------------------------------------------------------------

async function get(url, max, ms) {
  const res = await fetch(url, { signal: AbortSignal.timeout(ms), headers: { 'user-agent': `SignalConsole/${VERSION}` } });
  if (!res.ok) throw new Error(`answered ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > max) throw new Error(`more than ${max} bytes`);
  return buf;
}

// checkNow reads the update file from the first place that serves a valid
// one, then decides (decide).
async function checkNow() {
  if (state.checking) return status(true);
  state.checking = true;
  const problems = [];
  try {
    const mirrors = JSON.parse(meta('updates_mirrors') || '[]');
    for (const src of [...new Set([...customSources(), ...mirrors, ...SOURCES])]) {
      try {
        const text = (await get(src, 1 << 20, 30000)).toString('utf8');
        keep(text, verify(text), src);
        problems.length = 0;
        break;
      } catch (err) {
        problems.push(`${src}: ${err.message}`);
      }
    }
    state.problems = problems;
    state.error = problems.length ? 'no place served a valid update file' : '';
    state.checked_at = new Date().toISOString();
    decide();
  } finally {
    state.checking = false;
  }
  return status(true);
}

// upload takes an update file (and, for this console, its package) given
// by hand - a console without Internet access.
async function upload(fileText, pkg) {
  const m = verify(fileText);
  keep(fileText, m, 'uploaded by an admin');
  state.checked_at = new Date().toISOString();
  state.error = '';
  if (pkg && pkg.length) await install(m.products[PRODUCT], pkg);
  decide();
  return status(true);
}

// ---- deciding and applying ------------------------------------------------

// decide starts what the newest file asks for, by the rules in this file's
// header.
function decide() {
  const m = manifest();
  const p = m && m.products[PRODUCT];
  if (!p || !managed() || compare(p.latest, VERSION) <= 0 || state.downloading || state.pending || failed().includes(p.latest)) return;
  const withdrawn = withdrawalOf(p, VERSION);
  if (!auto()) return;
  apply(Boolean(withdrawn)).catch((err) => { state.error = err.message; });
}

// apply downloads, checks and unpacks the newest version (if not done) and
// schedules the restart into it: at once after the notice when the running
// version is withdrawn (or an admin asked), else once the console is idle.
async function apply(now) {
  if (!managed()) throw new Error('this console was not started by launch.js (a release package): update it by hand - git pull, or the new package');
  const m = manifest();
  const p = m && m.products[PRODUCT];
  if (!p || compare(p.latest, VERSION) <= 0) throw new Error('no newer version is known');
  if (!fs.existsSync(path.join(ROOT, 'app', p.latest, 'server.js'))) {
    state.downloading = { version: p.latest, started: new Date().toISOString() };
    try {
      let pkg = null;
      const problems = [];
      for (const url of p.urls) {
        try {
          pkg = checkPackage(p, await get(url, p.size, 10 * 60000));
          break;
        } catch (err) {
          problems.push(`${url}: ${err.message}`);
        }
      }
      if (!pkg) throw new Error(`Signal Console ${p.latest} could not be downloaded: ${problems.join('; ')}`);
      await install(p, pkg);
    } finally {
      state.downloading = null;
    }
  }
  schedule(p.latest, now);
}

// checkPackage returns pkg when it is exactly the signed package.
function checkPackage(p, pkg) {
  if (pkg.length !== p.size) throw new Error(`the download is ${pkg.length} bytes; the update file says ${p.size}`);
  if (crypto.createHash('sha256').update(pkg).digest('hex') !== p.sha256.toLowerCase()) throw new Error("the download's SHA-256 is not the one the update file signs");
  return pkg;
}

// install unpacks a checked package's app/<version>/ beside the running
// version (a .partial folder renamed when complete). launch.js and the data
// are never touched by an update.
async function install(p, pkg) {
  checkPackage(p, pkg);
  const prefix = `app/${p.latest}/`;
  const files = unzip(pkg).filter((f) => f.name.startsWith(prefix));
  const pj = files.find((f) => f.name === `${prefix}package.json`);
  if (!pj || JSON.parse(pj.data).version !== p.latest || !files.some((f) => f.name === `${prefix}server.js`)) {
    throw new Error(`the package does not hold Signal Console ${p.latest} (${prefix}package.json, server.js)`);
  }
  const final = path.join(ROOT, 'app', p.latest);
  const partial = `${final}.partial`;
  fs.rmSync(partial, { recursive: true, force: true });
  for (const f of files) {
    const to = path.join(partial, f.name.slice(prefix.length));
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.writeFileSync(to, f.data);
  }
  fs.rmSync(final, { recursive: true, force: true });
  fs.renameSync(partial, final);
}

// schedule announces the restart (the banner) and makes it when due and
// the console is idle - no run being received and, unless now,
// no background task running.
function schedule(version, now) {
  if (state.pending) return;
  state.pending = { version, at: new Date(Date.now() + NOTICE).toISOString(), now };
  const tick = () => {
    const running = tasks.list().some((t) => t.state === 'running');
    if (Date.now() < Date.parse(state.pending.at) || busy > 0 || (!now && running)) return setTimeout(tick, 5000).unref();
    try {
      restart(version);
    } catch (err) {
      state.error = `the update to ${version} was not applied: ${err.message}`;
      state.pending = null;
    }
  };
  setTimeout(tick, 5000).unref();
}

// restart backs up the data, points launch.js at version and exits for it
// to start that version (RESTART). launch.js restores the backup and starts
// this version again if the new one does not start.
function restart(version) {
  const backup = backupData();
  const current = readCurrent();
  writeCurrent({ version, previous: VERSION, backup, failed: current.failed || [] });
  console.log(`Signal Console ${VERSION}: restarting into ${version} (data backed up to ${backup})`);
  setTimeout(() => process.exit(RESTART), 200);
}

// backupData copies every database file (the main one and every data file) to
// data/backups/<version>-<time>/ with VACUUM INTO - a consistent copy while
// the console runs - keeping the newest BACKUPS_KEPT, and returns its folder.
function backupData() {
  const root = path.join(db.DATA_DIR, 'backups');
  const dir = path.join(root, `${VERSION}-${new Date().toISOString().replace(/[:.]/g, '-')}`);
  fs.mkdirSync(dir, { recursive: true });
  const files = [['signal-console.db', path.join(db.DATA_DIR, 'signal-console.db')]];
  for (const [rel, file] of files) {
    if (!fs.existsSync(file)) continue;
    const conn = new DatabaseSync(file);
    try {
      conn.exec(`VACUUM INTO '${path.join(dir, rel).replace(/'/g, "''")}'`);
    } finally {
      conn.close();
    }
  }
  const all = fs.readdirSync(root).filter((d) => fs.statSync(path.join(root, d)).isDirectory()).sort((a, b) => fs.statSync(path.join(root, b)).mtimeMs - fs.statSync(path.join(root, a)).mtimeMs);
  for (const old of all.slice(BACKUPS_KEPT)) fs.rmSync(path.join(root, old), { recursive: true, force: true });
  return dir;
}

const currentFile = () => path.join(ROOT, 'current.json');
// failed are the versions launch.js rolled back from: never tried again
// automatically (an admin's Update now still may, after a fix is known).
function failed() {
  try {
    return readCurrent().failed || [];
  } catch {
    return [];
  }
}
const readCurrent = () => JSON.parse(fs.readFileSync(currentFile(), 'utf8'));
function writeCurrent(c) {
  fs.writeFileSync(`${currentFile()}.tmp`, JSON.stringify(c, null, 2));
  fs.renameSync(`${currentFile()}.tmp`, currentFile());
}

// ---- what the pages read ------------------------------------------------

// status is the update state: for every user what the banner needs, for an
// admin (full) also the places and problems.
function status(full) {
  const m = manifest();
  const p = m && m.products[PRODUCT];
  const s = m && m.products.signal;
  const w = p && withdrawalOf(p, VERSION);
  let rolledBack = null;
  if (managed()) {
    try {
      const c = readCurrent();
      if (c.rolled_back) rolledBack = c.rolled_back;
    } catch { /* no current.json yet: a first start */ }
  }
  const out = {
    version: VERSION, mode: managed() ? 'managed' : 'notify', auto: auto(),
    latest: p ? p.latest : '', available: Boolean(p && compare(p.latest, VERSION) > 0), notes: (p && p.notes) || '',
    withdrawn: w ? { reason: w.reason, severity: w.severity || '' } : null,
    issued: m ? m.issued : '', expires: m ? m.expires : '', stale: Boolean(m && Date.now() > Date.parse(m.expires)),
    checked_at: state.checked_at, checking: state.checking, error: state.error,
    downloading: state.downloading, pending: state.pending, rolled_back: rolledBack,
    signal: s ? { latest: s.latest, notes: s.notes || '', withdrawn: s.withdrawn || [] } : null,
  };
  if (full) Object.assign(out, { source: state.source, problems: state.problems, sources: SOURCES, custom_sources: customSources(), mirrors: JSON.parse(meta('updates_mirrors') || '[]') });
  return out;
}

// signalWithdrawal is the reason a Signal version is withdrawn, or '' -
// for the runs it made (marked on Import and the host page).
function signalWithdrawal(version) {
  const m = manifest();
  const w = m && withdrawalOf(m.products.signal, version);
  return w ? `Signal ${version} is withdrawn: ${w.reason}` : '';
}

// markWithdrawn adds each row's Signal withdrawal (withdrawn_signal) to
// rows carrying a tool_version.
function markWithdrawn(rows) {
  return rows.map((r) => ({ ...r, withdrawn_signal: signalWithdrawal(r.tool_version) }));
}

// settings changes the admin's choices.
function settings({ auto: on, sources }) {
  if (on !== undefined) meta('updates_auto', on ? '1' : '0');
  if (sources !== undefined) {
    const list = (Array.isArray(sources) ? sources : []).map((s) => String(s).trim()).filter(Boolean);
    const bad = list.find((s) => !/^https?:\/\/\S+$/.test(s));
    if (bad) throw new Error(`"${bad}" is not an http(s) address`);
    meta('updates_sources', JSON.stringify(list));
  }
  decide();
  return status(true);
}

// track counts the runs being received (middleware), so a
// restart never cuts one off.
function track(req, res, next) {
  busy++;
  let done = false;
  const end = () => { if (!done) { done = true; busy--; } };
  res.on('finish', end);
  res.on('close', end);
  next();
}

// start checks at start-up and every CHECK_EVERY, and registers the work
// in the tasks menu.
function start() {
  tasks.register(() => {
    if (state.downloading) return { id: 'update', title: 'Signal Console update', state: 'running', detail: `downloading ${state.downloading.version}`, page: 'settings', params: { group: 'updates' } };
    if (state.pending) return { id: 'update', title: 'Signal Console update', state: 'waiting', detail: `restarting into ${state.pending.version} at ${state.pending.at.slice(11, 16)} UTC, when idle`, page: 'settings', params: { group: 'updates' } };
    return null;
  });
  const run = () => checkNow().catch((err) => { state.error = err.message; });
  setTimeout(run, 10000).unref();
  setInterval(run, CHECK_EVERY).unref();
}

module.exports = {
  KEYS, SOURCES, FORMAT, compare, verify, withdrawalOf, checkPackage,
  start, checkNow, upload, apply, status, settings, signalWithdrawal, markWithdrawn, track,
};
