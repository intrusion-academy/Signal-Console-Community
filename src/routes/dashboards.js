// The dashboard API: Overview, the fleet dashboard (see model/fleet.js's
// fleetDashboard).
//
//   GET /api/dashboards/fleet?hosts=<run ids>
//     over the given hosts' latest collections (every host when absent):
//     headline numbers, hosts ranked by risk, rules ranked by how many hosts
//     they flagged, telemetry coverage and collection freshness.
//   GET /api/dashboards/attack?hosts=<run ids>
//     the ATT&CK coverage matrix over the same hosts (model/attack.js).
//   GET /api/dashboards/timeline?hosts=<run ids>
//     every signal of those hosts' latest collections, slim, for
//     Overview's timeline: when it began and last matched (or the range its
//     own time is within), what it is about, its rule, severity and triage;
//     what its time is (`time_is`), `as_of` when it is a state observed as
//     Signal read the host - its time the collection's - with its `anchor`
//     when Windows recorded one (Signal schema 59), and `collected`.
'use strict';

const express = require('express');
const cache = require('../cache');
const { fleetDashboard, attackMatrix } = require('../model');
const { withConsole } = require('../consoleRules');

const router = express.Router();

router.get('/fleet', (req, res) => {
  res.json(fleetDashboard(cache.collections(), cache.hosts(), String(req.query.hosts || '').split(',').filter(Boolean)));
});

router.get('/attack', (req, res) => {
  res.json(attackMatrix(withConsole(cache.rules(), cache.latest()), String(req.query.hosts || '').split(',').filter(Boolean)));
});

router.get('/timeline', (req, res) => {
  const hosts = new Set(String(req.query.hosts || '').split(',').filter(Boolean));
  res.json(cache.scopeSignals('').filter((s) => !hosts.size || hosts.has(s.run_id)).map((s) => ({
    sid: s.sid, run_id: s.run_id, host: s.host, entity_id: s.entity_id, entity_type: s.entity_type, entity_display: s.entity_display,
    rule_id: s.rule_id, title: s.title, module: s.module, severity: s.severity, triage: s.triage, suppressed: Boolean(s.suppressed_by),
    count: s.count || 1, first: s.first_seen || s.time, last: s.last_seen || s.time, time_from: s.count > 1 ? '' : s.time_from || '',
    time_is: s.time_is || '', as_of: Boolean(s.as_of), anchor: s.anchor || null, collected: s.started || '',
  })));
});

module.exports = router;
