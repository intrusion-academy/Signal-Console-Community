// The signals and triage API (the Signals, Overview and Hosts pages - see
// model/signals.js, model/triage.js and model/signalQuery.js):
//
//   GET /api/signals?host=<run id>&...filters
//     the Signals page's frame for a scope (every host's latest collection,
//     or one run, any collection): the filter options it offers and the
//     summary of what the filters keep. Filters: modules, severity, rule,
//     tactic, triage (comma-separated; absent = all), show, q.
//   GET /api/signals/list?host=&...filters&group=&key=&sort=&dir=&offset=&limit=
//     the signals, filtered, sorted and paged - or, with group and no key,
//     their groups (each then fetched with key).
//   PUT    /api/signals/:sid/triage   {state, note}
//   GET    /api/signals/:sid/history  every triage change of a signal
//   GET    /api/signals/suppressions
//   POST   /api/signals/suppressions  {conditions: [{field, op, value}], note}
//   DELETE /api/signals/suppressions/:id
'use strict';

const express = require('express');
const triage = require('../triageStore');
const cache = require('../cache');
const { signalQuery } = require('../model');

const router = express.Router();

router.get('/', (req, res) => {
  const rows = cache.scopeSignals(String(req.query.host || ''));
  const kept = signalQuery.filtered(rows, req.query);
  res.json({ options: signalQuery.options(rows), summary: signalQuery.summary(kept), total: kept.length });
});

router.get('/list', (req, res) => {
  res.json(signalQuery.query(cache.scopeSignals(String(req.query.host || '')), req.query));
});

router.put('/:sid/triage', (req, res) => {
  try {
    res.json(triage.setState(req.params.sid, req.body.state, req.body.note, req.user.username));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/:sid/history', (req, res) => {
  res.json(triage.history(req.params.sid));
});

// Every suppression rule, with how many of the fleet's current signals
// (every host's latest collection) it hides.
router.get('/suppressions', (req, res) => {
  const rows = cache.scopeSignals('');
  res.json(triage.get().suppressions.map((r) => ({ ...r, hides_n: rows.filter((s) => s.suppressed_by === r.id).length })));
});

router.post('/suppressions', (req, res) => {
  try {
    res.json(triage.addSuppression(req.body || {}, req.user.username));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/suppressions/:id', (req, res) => {
  if (!triage.removeSuppression(req.params.id)) return res.status(404).json({ error: 'no such suppression rule' });
  res.json({ ok: true });
});

module.exports = router;
