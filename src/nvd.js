// NVD's affected versions of the CVEs CISA's catalog lists (src/kev.js):
// the catalog names products, not versions, so for each CVE an installed
// application matched by name, the console reads NIST's National
// Vulnerability Database record of that CVE - its configurations' CPE
// ranges - and an application is flagged only when an installed version
// falls in one. Only CVE IDs are sent to NVD, never host data.
//
// A record is read from the data folder's nvd/<CVE>.json (NVD's answer as
// saved - for a console without Internet access), else looked up at NVD,
// one at a time (NVD allows 5 requests in 30 seconds without an API key,
// 50 with one - a free key the analyst may give on Settings), and
// kept in the main database (src/db.js, nvd): state done / not_found /
// failed, the ranges as JSON.
'use strict';

const fs = require('fs');
const path = require('path');
const { setInterval, clearInterval } = require('timers');
const db = require('./db');
const tasks = require('./tasks');

const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';
const DIR = path.join(db.DATA_DIR, 'nvd');
const TICK = 6500; // between two lookups without a key
const TICK_KEY = 700; // with a key

// meta is the NVD API key and the refresh age, kept in the main database.
const meta = (key, value) => db.meta(key, value, db.main());

// refreshDays is how old a record may be before it is read again - read
// once and kept (configure forgets it): stale() runs for every CVE of every
// application row, and two database reads each made the Applications page slow.
let refreshKept = null;
const refreshDays = () => {
  if (refreshKept === null) refreshKept = meta('nvd_refresh_days') === undefined ? DEFAULT_REFRESH : Number(meta('nvd_refresh_days'));
  return refreshKept;
};

// stale is whether a kept answer is past the refresh age.
const stale = (k) => k.state !== 'failed' && refreshDays() > 0 && Date.now() - Date.parse(k.looked_up) > refreshDays() * DAY;
const RETRY = 6 * 3600 * 1000; // a failed lookup is tried again after
const DAY = 86400000;
const DEFAULT_REFRESH = 30; // days before a record is read again (0: never) - NVD corrects affected versions

let known = null; // cve -> { state, ranges, looked_up }
const queue = new Set();
let timer = null;

// words is a CPE vendor or product as compared with an application's name.
const words = (s) => String(s || '').toLowerCase().replace(/\\/g, '').replace(/[^a-z0-9+#]+/g, ' ').trim();

// rangesOf is a CVE record's vulnerable application CPEs: product words
// and the versions they cover.
function rangesOf(cve) {
  const out = [];
  for (const conf of cve.configurations || []) {
    for (const node of conf.nodes || []) {
      if (node.negate) continue;
      for (const m of node.cpeMatch || []) {
        const part = String(m.criteria || '').split(':');
        if (!m.vulnerable || part[2] !== 'a') continue;
        out.push({
          product: words(part[4]), version: part[5] || '*',
          start: m.versionStartIncluding || m.versionStartExcluding || '', start_incl: Boolean(m.versionStartIncluding),
          end: m.versionEndExcluding || m.versionEndIncluding || '', end_incl: Boolean(m.versionEndIncluding),
        });
      }
    }
  }
  return out;
}

function load() {
  if (known) return known;
  known = new Map(db.main().prepare('SELECT cve, state, ranges, looked_up FROM nvd').all()
    .map((r) => [r.cve, { state: r.state, ranges: JSON.parse(r.ranges || '[]'), looked_up: r.looked_up }]));
  return known;
}

function keep(cve, state, ranges) {
  const at = new Date().toISOString();
  db.main().prepare('INSERT OR REPLACE INTO nvd (cve, state, ranges, looked_up) VALUES (?, ?, ?, ?)').run(cve, state, JSON.stringify(ranges), at);
  load().set(cve, { state, ranges, looked_up: at });
}

// keepDoc keeps an NVD answer for a CVE.
function keepDoc(cve, doc) {
  const v = (doc.vulnerabilities || [])[0];
  if (v) keep(cve, 'done', rangesOf(v.cve));
  else keep(cve, 'not_found', []);
}

// readSaved reads a CVE's saved NVD answer from the data folder, when
// there is one; false otherwise.
function readSaved(cve) {
  const file = path.join(DIR, `${cve}.json`);
  if (!fs.existsSync(file)) return false;
  try {
    keepDoc(cve, JSON.parse(fs.readFileSync(file, 'utf8')));
  } catch {
    keep(cve, 'failed', []);
  }
  return true;
}

// step looks up the next queued CVE at NVD.
async function step() {
  const cve = queue.values().next().value;
  if (!cve) { clearInterval(timer); timer = null; return; }
  queue.delete(cve);
  try {
    const key = meta('nvd_key');
    const res = await fetch(API + encodeURIComponent(cve), { headers: key ? { apiKey: key } : {}, signal: AbortSignal.timeout(30000) });
    if (!res.ok) throw new Error(`NVD answered ${res.status}`);
    keepDoc(cve, await res.json());
  } catch {
    keep(cve, 'failed', []);
  }
}

// want queues a CVE not yet read (or failed long enough ago).
function want(cve) {
  const k = load().get(cve);
  if (k && !stale(k) && (k.state !== 'failed' || Date.now() - Date.parse(k.looked_up) < RETRY)) return;
  if (queue.has(cve) || readSaved(cve)) return;
  queue.add(cve);
  if (!timer) start();
}

// start takes the queue in turn, at the pace the key allows.
function start() {
  clearInterval(timer);
  timer = setInterval(() => { step(); }, meta('nvd_key') ? TICK_KEY : TICK);
  timer.unref();
  step();
}

// configure saves the NVD API key ('' removes it) and goes on at its pace.
function configure({ key, refresh_days: refresh }) {
  if (refresh !== undefined) {
    const n = Number(refresh);
    if (!Number.isInteger(n) || n < 0 || n > 365) throw new Error('the refresh age is whole days, 0 (never) to 365');
    meta('nvd_refresh_days', n);
    refreshKept = null;
  }
  if (key === undefined) return status();
  const k = String(key || '').trim();
  if (k && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(k)) throw new Error('an NVD API key is a UUID: 8-4-4-4-12 hexadecimal characters');
  meta('nvd_key', k);
  if (timer) start();
  return status();
}

// cmp compares two versions by their numeric parts; null when either has
// a part that is not a number (not compared).
function cmp(a, b) {
  const pa = String(a).split(/[.\-_ ]+/).filter(Boolean);
  const pb = String(b).split(/[.\-_ ]+/).filter(Boolean);
  if (!pa.length || !pb.length || [...pa, ...pb].some((x) => !/^\d+$/.test(x))) return null;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = Number(pa[i] || 0) - Number(pb[i] || 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

// inRange is whether a version is covered by a range: true, false, or
// null when it cannot be compared.
function inRange(version, r) {
  if (r.version === '-') return null;
  if (r.version !== '*') return cmp(version, r.version) === null ? null : cmp(version, r.version) === 0;
  const lo = r.start ? cmp(version, r.start) : 1;
  const hi = r.end ? cmp(version, r.end) : -1;
  if (lo === null || hi === null) return null;
  return (r.start_incl ? lo >= 0 : lo > 0 || !r.start) && (r.end_incl ? hi <= 0 : hi < 0);
}

// affected is whether an application (its name and installed versions)
// is affected by a CVE: 'yes' when an installed version is in one of the
// CVE's ranges for a product the name holds, 'no' when every version was
// compared and none is, 'unknown' otherwise (not read yet - it is queued -,
// no range for the product, a version not comparable).
function affected(cve, name, versions) {
  let k = load().get(cve);
  if (!k || k.state === 'failed' || stale(k)) { want(cve); k = load().get(cve); } // a stale record is used until read again
  if (!k || k.state === 'failed') return 'unknown';
  const n = ` ${words(name)} `;
  const ranges = k.ranges.filter((r) => r.product && n.includes(` ${r.product} `));
  const list = String(versions || '').split(',').map((v) => v.trim()).filter(Boolean);
  if (!ranges.length || !list.length) return 'unknown';
  const results = list.map((v) => ranges.map((r) => inRange(v, r)));
  if (results.some((rs) => rs.includes(true))) return 'yes';
  return results.every((rs) => rs.every((x) => x === false)) ? 'no' : 'unknown';
}

// status is what the Settings page shows.
function status() {
  const counts = { done: 0, not_found: 0, failed: 0 };
  for (const k of load().values()) counts[k.state] = (counts[k.state] || 0) + 1;
  const key = meta('nvd_key') || '';
  // missing: the CVEs with no answer yet - queued, or failed (on a console
  // without Internet access, every one) - to save by hand.
  const missing = [...new Set([...queue, ...[...load()].filter(([, k]) => k.state === 'failed').map(([cve]) => cve)])].sort();
  return { ...counts, queued: queue.size, dir: DIR, api: API, refresh_days: refreshDays(), key_set: Boolean(key), key_hint: key ? `…${key.slice(-4)}` : '', seconds: (key ? TICK_KEY : TICK) / 1000, missing };
}

// The lookups as a background task (src/tasks.js): while CVEs wait.
tasks.register(() => {
  if (!queue.size) return null;
  const s = status();
  const done = s.done + s.not_found + s.failed;
  return {
    id: 'nvd', title: "NVD's affected versions (CISA's known exploited vulnerabilities)", state: 'running', done, total: done + queue.size,
    detail: `${queue.size} CVE${queue.size === 1 ? '' : 's'} waiting - one every ${s.seconds} seconds${s.key_set ? '' : ' (no NVD API key)'}`,
    page: 'settings', params: { group: 'kev' },
  };
});

module.exports = { affected, status, configure, cmp, inRange, rangesOf };
