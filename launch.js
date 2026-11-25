// Signal Console's launcher (Signal's updates documentation) - how a release
// package is started: `node launch.js` in the install folder; in a git
// checkout, `npm start` runs it too.
//
//   <install folder>/
//     launch.js        this file; never replaced by an update
//     current.json     the version to start: {version, previous, backup, failed, rolled_back}
//     app/<version>/   each version's files, side by side
//     data/            the accounts, settings and runs (SIGNAL_CONSOLE_DATA, unless set)
//
// A git checkout is one more version: its own server.js, at its
// package.json's version. It runs until an update unpacks a newer version in
// app/, and runs again once a git pull makes it the newest.
//
// It starts app/<version>/server.js and waits for it to say it is ready.
// When the console exits to apply an update (status 75, src/updates.js has
// pointed current.json at the new version and backed up the data), it
// starts the new version on trial: if that one exits or is not ready within
// TRIAL, before it served anything, the backup is put back, the version is
// marked failed (never tried again) and the previous version started - the
// console says so on Settings > Updates. A console that stops after it was
// ready is started again (it crashed); one that exits with status 0 was
// stopped, and so is the launcher.
//
// Kept small and dependency-free on purpose: it is the one part an update
// cannot fix.
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const CURRENT = path.join(ROOT, 'current.json');
const RESTART = 75;
const TRIAL = Number(process.env.SIGNAL_CONSOLE_TRIAL_MS) || 120000;
const DATA = process.env.SIGNAL_CONSOLE_DATA || path.join(ROOT, 'data');

const log = (msg) => console.log(`[launch] ${msg}`);

function compare(a, b) {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
}

// checkoutVersion is the git checkout's version, or '' in a release
// package (no server.js beside this file).
function checkoutVersion() {
  if (!fs.existsSync(path.join(ROOT, 'server.js'))) return '';
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
}

// dirOf is where a version's server.js is: app/<version>/, else the
// checkout itself when it is that version.
function dirOf(version) {
  const app = path.join(ROOT, 'app', version);
  return !fs.existsSync(path.join(app, 'server.js')) && version === checkoutVersion() ? ROOT : app;
}

function readCurrent() {
  const checkout = checkoutVersion();
  if (fs.existsSync(CURRENT)) {
    const c = JSON.parse(fs.readFileSync(CURRENT, 'utf8'));
    if (!checkout || compare(checkout, c.version) <= 0) return c;
    // A git pull past the version that ran: the checkout is the newest.
    const pulled = { version: checkout, failed: c.failed || [] };
    writeCurrent(pulled);
    return pulled;
  }
  // A first start: the newest version unpacked, or the checkout.
  const apps = path.join(ROOT, 'app');
  const versions = (fs.existsSync(apps) ? fs.readdirSync(apps) : []).filter((v) => /^\d+\.\d+\.\d+$/.test(v) && fs.existsSync(path.join(apps, v, 'server.js')));
  if (checkout) versions.push(checkout);
  versions.sort(compare);
  if (!versions.length) throw new Error(`no version to start in ${apps}`);
  const c = { version: versions[versions.length - 1] };
  writeCurrent(c);
  return c;
}

function writeCurrent(c) {
  fs.writeFileSync(`${CURRENT}.tmp`, JSON.stringify(c, null, 2));
  fs.renameSync(`${CURRENT}.tmp`, CURRENT);
}

// restore puts a backup's database files back over the data (their WAL
// and shared-memory files removed first: they belong to the failed
// version's writes).
function restore(backup) {
  if (!backup || !fs.existsSync(backup)) return;
  const copy = (from, to) => {
    for (const ext of ['-wal', '-shm']) fs.rmSync(to + ext, { force: true });
    fs.copyFileSync(from, to);
  };
  copy(path.join(backup, 'signal-console.db'), path.join(DATA, 'signal-console.db'));
}

let child = null;

function start(trial) {
  const c = readCurrent();
  const dir = dirOf(c.version);
  log(`starting Signal Console ${c.version}${trial ? ' (new version, on trial)' : ''}`);
  child = spawn(process.execPath, [path.join(dir, 'server.js')], {
    cwd: dir,
    stdio: ['inherit', 'inherit', 'inherit', 'ipc'],
    env: { ...process.env, SIGNAL_CONSOLE_ROOT: ROOT, SIGNAL_CONSOLE_DATA: DATA },
  });
  let ready = false;
  const started = Date.now();
  const timer = trial ? setTimeout(() => { if (!ready) { log(`${c.version} was not ready within ${TRIAL / 1000} s`); child.kill(); } }, TRIAL) : null;
  child.on('message', (m) => {
    if (m === 'ready') {
      ready = true;
      if (timer) clearTimeout(timer);
    }
  });
  child.on('exit', (code, signal) => {
    if (timer) clearTimeout(timer);
    if (code === RESTART) return start(true);
    if (trial && !ready) {
      const failed = c.version;
      log(`${failed} did not start; restoring the data backed up before it and going back to ${c.previous}`);
      restore(c.backup);
      writeCurrent({ version: c.previous, failed: [...new Set([...(c.failed || []), failed])], rolled_back: { version: failed, at: new Date().toISOString(), backup: c.backup || '' } });
      return start(false);
    }
    if (code === 0 || signal === 'SIGINT' || signal === 'SIGTERM') process.exit(0);
    const wait = Date.now() - started < 60000 ? 10000 : 1000;
    log(`Signal Console ${c.version} stopped (${signal || `status ${code}`}); starting it again in ${wait / 1000} s`);
    setTimeout(() => start(false), wait);
  });
}

// node launch.js users ... runs the current version's account script (npm
// run users) on this data.
const SCRIPTS = { users: 'users.js' };
if (SCRIPTS[process.argv[2]]) {
  const dir = dirOf(readCurrent().version);
  const r = require('child_process').spawnSync(process.execPath, [path.join(dir, 'scripts', SCRIPTS[process.argv[2]]), ...process.argv.slice(3)], { stdio: 'inherit', env: { ...process.env, SIGNAL_CONSOLE_DATA: DATA } });
  process.exit(r.status ?? 1);
}

// Ctrl+C reaches the console itself (the same console window); the
// launcher waits for it to exit, then exits too. A service manager's stop
// (SIGTERM, to the launcher alone) is passed on.
process.on('SIGINT', () => {});
process.on('SIGTERM', () => { if (child) child.kill('SIGTERM'); });

start(false);
