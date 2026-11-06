// Routes for listing and removing imported runs: the Import page's list and
// every page's host filter.
'use strict';

const express = require('express');
const store = require('../store');
const audit = require('../audit');
const target = () => '';
const { who } = require('../auth');
const cache = require('../cache');
const flags = require('../flags');
const triage = require('../triageStore');
const persistence = require('../persistence');
const applications = require('../applications');
const extensions = require('../extensions');
const analystGraph = require('../analystGraph');
const { entityList } = require('../model/entities');

const router = express.Router();

// GET /api/runs - one lightweight row per imported run (see
// cache.runSummaries).
router.get('/', (req, res) => {
  res.json(require('../updates').markWithdrawn(cache.runSummaries()));
});

// GET /api/runs/:id - the run document, upgraded to the current output
// contract.
router.get('/:id', (req, res) => {
  const run = store.get(req.params.id);
  if (!run) return res.status(404).json({ error: 'no such run' });
  res.json(run);
});

// graphEntities is every entity the graph can show, by its graph key: the
// entities with signals, those their signals name, and the analyst's.
function graphEntities() {
  const rows = entityList(cache.scopeSignals(''), cache.collections().signalsOf, (id) => store.get(id), triage.get(), cache.entityFleet());
  return [...rows, ...rows.flatMap((r) => r.related || []), ...analystGraph.list().entities.map((e) => ({ node: e.key }))];
}

// pruneRemoved drops what only removed runs had - the analyst flags (every
// host's latest collection is what is left) and the triage (no run has the
// signal or entity) - once, after any removal.
function pruneRemoved() {
  triage.prune(cache.triageKeys());
  const runs = cache.latest();
  const inv = cache.inventories([], []);
  flags.prune({
    autoruns: persistence.query(runs, {}).rows,
    applications: applications.query(runs, {}).rows,
    extensions: extensions.query(runs, {}).rows,
    listeners: inv.network.tables.listeners ? inv.network.tables.listeners.rows : [],
    remote_addresses: inv.network.tables.remote_addresses ? inv.network.tables.remote_addresses.rows : [],
    av_exclusions: inv.av_exclusions.rows,
    entities: graphEntities(),
  });
}

// POST /api/runs/remove {ids: [run ID]} - remove several imported runs at
// once (the Import page's "Remove selected"); answers how many were removed
// and the IDs it did not hold.
router.post('/remove', (req, res) => {
  const ids = req.body && req.body.ids;
  if (!Array.isArray(ids) || !ids.length || !ids.every((id) => typeof id === 'string')) return res.status(400).json({ error: 'ids: a list of run IDs' });
  const missing = ids.filter((id) => !store.remove(id));
  if (missing.length < ids.length) {
    pruneRemoved();
    audit.record('runs_removed', { ...who(req), target: target(req), detail: ids.filter((id) => !missing.includes(id)).join(', ') });
  }
  res.json({ removed: ids.length - missing.length, missing });
});

// DELETE /api/runs/:id - remove one imported run.
router.delete('/:id', (req, res) => {
  if (!store.remove(req.params.id)) return res.status(404).json({ error: 'no such run' });
  pruneRemoved();
  audit.record('runs_removed', { ...who(req), target: target(req), detail: req.params.id });
  res.json({ ok: true });
});

module.exports = router;
