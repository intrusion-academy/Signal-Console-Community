// Reviews: an analyst's mark that a data page (an inventory - Autoruns,
// Applications, Network...) was reviewed on a host, as Signals are triaged.
// A page is "Not reviewed" on a host until marked; the mark holds for the
// host's inventory as it was (a fingerprint of the page's datasets in its
// latest collection), so a new collection re-opens it only when that
// inventory changed. A page is reviewed for the fleet only when every host
// with something on it is (src/db.js, reviews).
'use strict';

const crypto = require('crypto');
const db = require('./db');
const { hostOf } = require('./model/hosts');
const { PAGE_DATA } = require('./model/inventories');

// PAGES are the data pages reviewed: every inventory page but Users, whose
// accounts are triaged through their signals, and Topology, a map of the
// networks rather than entries to review (the user, 2026-11-04).
const PAGES = Object.keys(PAGE_DATA).filter((p) => p !== 'users' && p !== 'topology');

// hostKey is a run's host identity: its machine ID, else its name.
const hostKey = (run) => (run.host && run.host.machine_id) || hostOf(run);

// fingerprint is what a page shows of a run - the digests of its datasets
// with rows (store.js lighten) - or '' when it shows nothing there.
function fingerprint(run, page) {
  const wanted = new Set(PAGE_DATA[page]);
  const parts = [];
  for (const [name, result] of Object.entries(run.modules || {})) {
    for (const d of result.datasets || []) {
      if ((wanted.has(d.role) || wanted.has(d.name)) && (d.rows.length || d.indexed)) parts.push(`${name}/${d.role || d.name}/${d.digest}`);
    }
  }
  return parts.length ? crypto.createHash('sha256').update(parts.sort().join('\n')).digest('hex') : '';
}

// status is each page's review over runs (hosts' latest collections): how
// many hosts have something on it, how many of them are reviewed, and the
// latest mark's who and when.
function status(runs) {
  const marks = db.open().prepare('SELECT page, host, fingerprint, reviewed_by, at FROM reviews').all();
  const byKey = new Map(marks.map((m) => [`${m.page}\u0000${m.host}`, m]));
  const out = {};
  for (const page of PAGES) {
    const s = { hosts: 0, reviewed: 0, reviewed_by: '', at: '' };
    for (const run of runs) {
      const fp = fingerprint(run, page);
      if (!fp) continue;
      s.hosts++;
      const m = byKey.get(`${page}\u0000${hostKey(run)}`);
      if (m && m.fingerprint === fp) {
        s.reviewed++;
        if (m.at > s.at) Object.assign(s, { reviewed_by: m.reviewed_by, at: m.at });
      }
    }
    s.state = s.reviewed === s.hosts ? 'reviewed' : 'not_reviewed';
    out[page] = s;
  }
  return out;
}

// mark marks page reviewed on each run's host as its inventory is now - or,
// with on false, takes the mark away. It returns false for a page not
// reviewed.
function mark(page, runs, on, user) {
  if (!PAGES.includes(page)) return false;
  const conn = db.open();
  const at = new Date().toISOString();
  db.transaction(() => {
    for (const run of runs) {
      const fp = fingerprint(run, page);
      if (!on) conn.prepare('DELETE FROM reviews WHERE page = ? AND host = ?').run(page, hostKey(run));
      else if (fp) conn.prepare('INSERT OR REPLACE INTO reviews (page, host, fingerprint, reviewed_by, at) VALUES (?, ?, ?, ?, ?)').run(page, hostKey(run), fp, user, at);
    }
  });
  return true;
}

module.exports = { PAGES, status, mark, fingerprint };
