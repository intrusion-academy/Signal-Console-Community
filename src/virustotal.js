// VirusTotal enrichment (Settings): when an analyst turns it on and gives
// an API key, the console looks up every file hash, public IP address and
// domain the hosts' latest collections name (Signal's entity facts) - a
// lookup only, nothing is uploaded. Off by default; Signal itself never
// connects anywhere for it.
//
// The lookups are a queue in the database (src/db.js, virustotal), taken
// in turn. When VirusTotal answers that the key's quota is used up (429),
// that item stays queued - never "not found" - and the queue waits the
// configured time (a minute by default; the free key allows 4 lookups a
// minute) before going on. What VirusTotal says is kept apart from
// Signal's findings and shown as "VirusTotal says ..." with its date.
'use strict';

const db = require('./db');
const tasks = require('./tasks');

// meta is a setting of the lookups, kept in the main database: one key
// and one queue for the whole console.
const meta = (key, value) => db.meta(key, value, db.main());

const API = 'https://www.virustotal.com/api/v3';
const PATHS = { file: 'files', ip: 'ip_addresses', domain: 'domains' };
const DEFAULT_WAIT = 60; // seconds after a quota answer
const DEFAULT_REFRESH = 7; // days before an answer is looked up again (0: never)
const DAY = 86400000;
const TICK = 2000; // between two lookups, and the idle check

let pausedUntil = 0; // the queue waits until then (a quota answer, a failure)
let lastVersion = ''; // the runs' version last queued from
let current = new Set(); // the items the latest collections name (kind NUL value), to refresh only those

// refreshDays is how old an answer may be before it is looked up again.
const refreshDays = () => {
  const n = Number(meta('vt_refresh_days'));
  return Number.isInteger(n) && meta('vt_refresh_days') !== undefined ? n : DEFAULT_REFRESH;
};

// staleItems is the answers older than the refresh age that the latest
// collections still name, oldest first - VirusTotal's verdicts change.
function staleItems(limit = 500) {
  const days = refreshDays();
  if (!days) return [];
  const cutoff = new Date(Date.now() - days * DAY).toISOString();
  return db.main().prepare("SELECT kind, value, looked_up FROM virustotal WHERE state IN ('done', 'not_found') AND looked_up < ? ORDER BY looked_up LIMIT ?").all(cutoff, limit)
    .filter((x) => current.has(`${x.kind}\u0000${x.value}`));
}

// settings is what the Settings page shows - never the key itself.
function settings() {
  const key = meta('vt_key') || '';
  const counts = Object.fromEntries(db.main().prepare('SELECT state, COUNT(*) AS n FROM virustotal GROUP BY state').all().map((r) => [r.state, r.n]));
  return {
    enabled: meta('vt_enabled') === '1', key_set: Boolean(key), key_hint: key ? `…${key.slice(-4)}` : '',
    wait_seconds: Number(meta('vt_wait')) || DEFAULT_WAIT, paused_until: pausedUntil ? new Date(pausedUntil).toISOString() : '',
    last_error: meta('vt_error') || '', counts, refresh_days: refreshDays(), stale: staleItems().length,
  };
}

// configure saves the analyst's choices; a key given replaces the stored one.
function configure({ enabled, key, wait_seconds: wait, refresh_days: refresh }) {
  if (refresh !== undefined) {
    const n = Number(refresh);
    if (!Number.isInteger(n) || n < 0 || n > 365) throw new Error('the refresh age is whole days, 0 (never) to 365');
    meta('vt_refresh_days', n);
  }
  if (key !== undefined && key !== '') {
    if (!/^[0-9a-f]{64}$/i.test(String(key).trim())) throw new Error('a VirusTotal API key is 64 hexadecimal characters');
    meta('vt_key', String(key).trim());
    meta('vt_error', '');
    pausedUntil = 0;
  }
  if (wait !== undefined) {
    const n = Number(wait);
    if (!Number.isInteger(n) || n < 15 || n > 86400) throw new Error('the wait is whole seconds, 15 to 86400');
    meta('vt_wait', n);
  }
  if (enabled !== undefined) {
    if (enabled && !meta('vt_key')) throw new Error('add an API key first');
    meta('vt_enabled', enabled ? '1' : '0');
  }
  return settings();
}

// itemsOf lists what the runs' entity facts name: SHA-256 hashes, public
// addresses (Signal's scope), domains.
function itemsOf(runs) {
  const out = new Set();
  for (const run of runs) for (const e of run.entity_facts || []) for (const [kind, value] of entityItems(e)) out.add(`${kind}\u0000${value}`);
  return [...out].map((x) => x.split('\u0000'));
}

// entityItems is what one entity's facts name for VirusTotal.
function entityItems(e) {
  const out = (e.facts || []).filter((f) => /^[0-9a-f]{64}$/i.test(f.value) && /sha-256/i.test(f.label)).map((f) => ['file', f.value.toLowerCase()]);
  if (e.type === 'address' && (e.facts || []).some((f) => f.label === 'Scope' && f.value === 'public')) out.push(['ip', e.key]);
  if (e.type === 'domain') out.push(['domain', String(e.key).toLowerCase()]);
  return out;
}

// flaggedEntities is the runs' entities VirusTotal's stored answers call
// malicious or suspicious, by entity ID (type:key): the most engines' answer
// of each - from lookups already made, never a new one.
function flaggedEntities(runs) {
  const out = {};
  for (const run of runs) {
    for (const e of run.entity_facts || []) {
      for (const a of results(entityItems(e))) {
        const bad = (a.malicious || 0) + (a.suspicious || 0);
        const id = `${e.type}:${e.key}`;
        if (a.state === 'done' && bad && (!out[id] || bad > out[id].malicious + out[id].suspicious)) {
          out[id] = { kind: a.kind, value: a.value, malicious: a.malicious, suspicious: a.suspicious, engines: a.malicious + a.suspicious + a.harmless + a.undetected, looked_up: a.looked_up };
        }
      }
    }
  }
  return out;
}

// enqueue queues what is not looked up yet.
function enqueue(runs) {
  const ins = db.main().prepare("INSERT OR IGNORE INTO virustotal (kind, value, state, queued) VALUES (?, ?, 'queued', ?)");
  const at = new Date().toISOString();
  const items = itemsOf(runs);
  current = new Set(items.map(([kind, value]) => `${kind}\u0000${value}`));
  db.transaction(() => { for (const [kind, value] of items) ins.run(kind, value, at); }, db.main());
}

// results answers the pages: each asked item's lookup, or its waiting state.
function results(items) {
  const get = db.main().prepare('SELECT * FROM virustotal WHERE kind = ? AND value = ?');
  const enabled = meta('vt_enabled') === '1';
  return items.map(([kind, value]) => {
    const r = PATHS[kind] && get.get(kind, kind === 'ip' ? String(value) : String(value).toLowerCase());
    if (!r) return { kind, value, state: enabled ? 'queued' : 'off' };
    return { kind, value, state: r.state, malicious: r.malicious, suspicious: r.suspicious, harmless: r.harmless, undetected: r.undetected, detail: r.detail, looked_up: r.looked_up };
  });
}

// lookup asks VirusTotal for one item and records the answer. A quota
// answer (429) leaves it queued and pauses the queue; any other failure
// (a refused key, the network) pauses too and is shown on Settings.
async function lookup(item) {
  const key = meta('vt_key');
  const set = db.main().prepare('UPDATE virustotal SET state = ?, malicious = ?, suspicious = ?, harmless = ?, undetected = ?, detail = ?, looked_up = ? WHERE kind = ? AND value = ?');
  const now = () => new Date().toISOString();
  let res;
  try {
    res = await fetch(`${API}/${PATHS[item.kind]}/${encodeURIComponent(item.value)}`, { headers: { 'x-apikey': key }, signal: AbortSignal.timeout(30000) });
  } catch (err) {
    return pause(`VirusTotal could not be reached: ${err.message}`);
  }
  if (res.status === 429) return pause('', true); // the key's quota: try again after the wait
  if (res.status === 401 || res.status === 403) return pause(`VirusTotal refused the API key (${res.status})`);
  if (res.status === 404) {
    set.run('not_found', null, null, null, null, '', now(), item.kind, item.value);
    return;
  }
  if (!res.ok) return pause(`VirusTotal answered ${res.status}`);
  const a = ((await res.json()).data || {}).attributes || {};
  const s = a.last_analysis_stats || {};
  const detail = [a.meaningful_name, a.as_owner, a.country, a.registrar].filter(Boolean).join(' · ');
  set.run('done', s.malicious ?? 0, s.suspicious ?? 0, s.harmless ?? 0, s.undetected ?? 0, detail, now(), item.kind, item.value);
  meta('vt_error', '');
}

function pause(error, quota = false) {
  pausedUntil = Date.now() + (Number(meta('vt_wait')) || DEFAULT_WAIT) * 1000;
  meta('vt_error', quota ? '' : error);
}

// step is one turn of the queue: while on and not paused, new items of the
// latest collections are queued (when the runs changed) and the oldest
// queued one is looked up. latest() and version() come from the cache and
// the store.
async function step(latest, version) {
  if (meta('vt_enabled') !== '1' || !meta('vt_key') || Date.now() < pausedUntil) return;
  if (version() !== lastVersion) {
    lastVersion = version();
    enqueue(latest());
  }
  // A new item first; else the oldest answer past the refresh age - its
  // verdict stays shown until the new one replaces it.
  const next = db.main().prepare("SELECT kind, value FROM virustotal WHERE state = 'queued' ORDER BY queued, kind, value LIMIT 1").get() || staleItems(1)[0];
  if (next) await lookup(next);
}

// start runs the queue, a step every TICK, one at a time.
function start(latest, version) {
  let busy = false;
  const timer = setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
      await step(latest, version);
    } catch (err) {
      console.error(`virustotal: ${err.message}`);
    } finally {
      busy = false;
    }
  }, TICK);
  timer.unref();
}

// The lookups as a background task (src/tasks.js): while items wait, how
// many are left and whether the queue waits on VirusTotal's quota.
tasks.register(() => {
  const s = settings();
  const c = s.counts || {};
  if (!c.queued && !(s.enabled && s.stale)) return null;
  if (!c.queued) {
    return { id: 'virustotal', title: 'VirusTotal lookups', state: 'running', page: 'settings', params: { group: 'virustotal' },
      detail: `${s.stale} answer${s.stale === 1 ? '' : 's'} older than ${s.refresh_days} days being looked up again - the old verdict stays shown until then` };
  }
  const done = (c.done || 0) + (c.not_found || 0) + (c.failed || 0);
  const base = { id: 'virustotal', title: 'VirusTotal lookups', done, total: done + c.queued, page: 'settings', params: { group: 'virustotal' } };
  if (!s.enabled) return { ...base, state: 'paused', detail: `${c.queued} waiting - the lookups are turned off (Settings, VirusTotal)` };
  if (s.paused_until && Date.parse(s.paused_until) > Date.now()) return { ...base, state: 'waiting', detail: `${c.queued} waiting - VirusTotal's quota is used up; going on after ${s.paused_until.replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}` };
  return { ...base, state: 'running', detail: `${c.queued} waiting - one lookup at a time${s.last_error ? `; last error: ${s.last_error}` : ''}` };
});

module.exports = { settings, configure, results, start, step, itemsOf, flaggedEntities };
