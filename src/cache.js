// The computed model for the current runs and triage, built once per change
// and shared by every route - so a page load, or paging through a table,
// never re-derives signals from every run. Parts are computed on first use:
// the model for triage-independent views (rules, inventories) survives a
// triage change.
'use strict';

const db = require('./db');
const store = require('./store');
const triage = require('./triageStore');
const model = require('./model');
const { performance } = require('perf_hooks');
const { olderOutput } = require('./legacy');

// part returns a named part of the model, computing it on first use after
// a change: triage-dependent parts are keyed by both versions, the rest by
// the runs' only.
// Each data file keeps its own (db.local).
function part(name, compute, triageDependent = true) {
  const c = db.local('cache', () => ({ current: { key: '', parts: {} }, byRuns: { version: -1, parts: {} } }));
  if (triageDependent) {
    const key = `${store.version()}/${triage.version()}`;
    if (c.current.key !== key) c.current = { key, parts: {} };
    if (!(name in c.current.parts)) c.current.parts[name] = compute();
    return c.current.parts[name];
  }
  if (c.byRuns.version !== store.version()) c.byRuns = { version: store.version(), parts: {} };
  if (!(name in c.byRuns.parts)) c.byRuns.parts[name] = compute();
  return c.byRuns.parts[name];
}

// fleetBase is the part of the model the runs alone decide (each run's
// derived signals are kept per run, src/model/fleet.js); collections lays
// the triage over it - so a triage change rebuilds only that layer. How
// long the last rebuild took is kept (lastRebuild) for the Settings page's
// Server group and the benchmark: the runs' part and the triage layer
// when the runs changed, the triage layer alone otherwise.
const timed = (fn) => {
  const start = performance.now();
  const out = fn();
  return [out, performance.now() - start];
};
const fleetBase = () => part('fleetBase', () => {
  const [out, ms] = timed(() => model.fleetBase(store.all()));
  db.local('cache', () => ({})).baseMs = ms;
  return out;
}, false);
const collections = () => part('collections', () => {
  const c = db.local('cache', () => ({}));
  c.baseMs = null;
  const [base, baseMs] = timed(fleetBase);
  const [out, ms] = timed(() => {
    const t = model.withTriage(base, triage.get());
    for (const r of t.latest) t.signalsOf(r.run_id); // the triage of every host's latest collection, which every page reads
    return t;
  });
  const runsChanged = c.baseMs !== null;
  c.rebuild = { ms: Math.round(ms + (runsChanged ? baseMs : 0)), at: new Date().toISOString(), runs: store.all().length, triage_only: !runsChanged };
  return out;
});
const lastRebuild = () => db.local('cache', () => ({})).rebuild || null;
const hosts = () => part('hosts', () => model.hostInventory(collections()));
const latest = () => collections().latest;
const rules = () => part('rules', () => model.ruleCatalog(latest()), false);
const users = () => part('users', () => model.userInventory(latest(), collections().signalsOf));
const modules = () => part('modules', () => model.moduleInventory(latest(), collections().signalsOf, rules()));

// runSummaries is one lightweight row per run (the Import list and the
// host filters): enough to identify and manage a run, with its open
// signals counted (signal_count).
const runSummaries = () => part('runs', () => {
  const c = collections();
  const isLatest = new Set(c.latest);
  return store.all().map((r) => {
    const counts = model.severityCounts(c.signalsOf(r.run_id).filter(model.isOpen));
    return {
      run_id: r.run_id, tool_version: r.tool_version, older_output: olderOutput(r), schema_version: r.upgraded_from ?? r.schema_version, mode: r.mode,
      started: r.started, finished: r.finished, duration: r.duration, ...model.hostMeta(r), machine_id: (r.host && r.host.machine_id) || '',
      modules: Object.keys(r.modules || {}), latest: isLatest.has(r), ...store.arrival(r.run_id),
      signal_count: counts.critical + counts.high + counts.medium + counts.low, risk: model.riskOf(c.signalsOf(r.run_id)),
    };
  });
});

// scopeSignals is the signals of one run (any collection), or of every
// host's latest collection when runId is empty.
function scopeSignals(runId) {
  const c = collections();
  if (runId) return part(`signals:${runId}`, () => (store.has(runId) ? c.signalsOf(runId).slice().sort(model.compareSignals) : []));
  return part('signals:', () => c.latest.flatMap((r) => c.signalsOf(r.run_id)).sort(model.compareSignals));
}

// inventories is the inventories of a host and module selection (every
// host's latest collection / all modules when empty), the last few kept.
const INVENTORY_ENTRIES = 20;
function inventories(hostIds, modules) {
  const entries = part('inventories', () => new Map(), false);
  const key = JSON.stringify([hostIds, modules]);
  if (!entries.has(key)) {
    const wanted = new Set(hostIds);
    const runs = hostIds.length ? [...wanted].filter(store.has).map(store.get) : latest();
    if (entries.size >= INVENTORY_ENTRIES) entries.delete(entries.keys().next().value);
    entries.set(key, model.inventories(runs, modules));
  }
  return entries.get(key);
}

// entityFleet maps each entity to how many hosts' latest collections have
// signals about it.
const entityFleet = () => part('entityFleet', () => model.fleetCounts(scopeSignals('')));

// triageKeys is every sid and entity triage ID of every imported run (any
// collection) - the triage that is still about something.
const triageKeys = () => new Set(store.all().flatMap((r) => collections().signalsOf(r.run_id).flatMap((s) => [s.sid, s.eid])).filter(Boolean));

module.exports = { triageKeys, lastRebuild, collections, hosts, latest, rules, users, entityFleet, modules, runSummaries, scopeSignals, inventories };
