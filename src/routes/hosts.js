// The hosts API (the Hosts page - see model/fleet.js's hostInventory):
//
//   GET /api/hosts
//     one row per host - its latest collection: identity, collection,
//     modules, open signals, risk, coverage gaps, telemetry, and its
//     collection history.
//   GET /api/hosts/:run_id/modules
//     that run's modules as its page presents them: each module's status,
//     KPIs and telemetry.
'use strict';

const express = require('express');
const store = require('../store');
const cache = require('../cache');

const router = express.Router();

router.get('/', (req, res) => {
  res.json(require('../updates').markWithdrawn(cache.hosts()));
});

router.get('/:id/modules', (req, res) => {
  const run = store.get(req.params.id);
  if (!run) return res.status(404).json({ error: 'no such run' });
  res.json(Object.entries(run.modules || {}).map(([name, r]) => ({
    name, version: r.version || '', status: r.status || 'ok', kpis: r.kpis || [], telemetry: r.telemetry || [],
  })));
});

module.exports = router;
