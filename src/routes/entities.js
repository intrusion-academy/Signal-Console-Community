// The entities API (the Signals page: its list of entities, and each
// entity's page - see model/entities.js):
//
//   GET /api/entities?host=<run id>&...filters
//     the scope's signals (every host's latest collection, or one run, any
//     collection), filtered as the Signals page's filters say (model/
//     signalQuery.js, plus type; show=rare: entities on one host only),
//     grouped by host and entity: the rows,
//     their summary, and the filter options the scope offers.
//     runs=<run id,run id> keeps those hosts' signals only (the Graph page:
//     only the hosts it draws cross the wire).
//   GET /api/entities/item?id=<type:key>&host=<run id>
//     one entity on one host (host optional: the latest collection where
//     it has the most open signals) - its page.
//   GET /api/entities/find?q=<text>
//     the finder: entities of every host's latest collection whose name,
//     key or facts contain the text, with the hosts where they match.
//   GET /api/entities/facts?host=<run id>&ids=<id,id>
//     the facts of those entities in that collection, by ID.
//   GET /api/entities/virustotal?host=<run id>
//     the entities of that collection (else of every host's latest) whose
//     files, address or domain VirusTotal's stored answers call malicious
//     or suspicious, by ID - the graph's marks.
//   PUT /api/entities/triage   {id, host, state, note}
//     triage the entity on that collection's host, as a whole: the
//     decision covers its signals of that collection.
//   GET /api/entities/history?id=<type:key>&host=<run id>
//     every triage change of the entity on that host.
'use strict';

const express = require('express');
const cache = require('../cache');
const store = require('../store');
const triage = require('../triageStore');
const vt = require('../virustotal');
const { signalQuery } = require('../model');
const { entityList, listSummary, entityPage, entityFacts, findEntities } = require('../model/entities');

const router = express.Router();

router.get('/', (req, res) => {
  const only = new Set(String(req.query.runs || '').split(',').filter(Boolean));
  const scoped = cache.scopeSignals(String(req.query.host || ''));
  const rows = only.size ? scoped.filter((s) => only.has(s.run_id)) : scoped;
  // Show "rare" is of the entity: what one host alone has signals about.
  const rare = req.query.show === 'rare';
  const list = entityList(signalQuery.filtered(rows, rare ? { ...req.query, show: '' } : req.query), cache.collections().signalsOf, (id) => store.get(id), triage.get(), cache.entityFleet())
    .filter((r) => !rare || r.fleet_n === 1);
  res.json({ options: signalQuery.options(rows), summary: listSummary(list), rows: list, hosts_n: cache.latest().length });
});

// page is the entity of the request (id, host) on its page, or null.
function page(req) {
  const runId = String(req.query.host || (req.body && req.body.host) || '');
  if (runId && !store.has(runId)) return null;
  return entityPage(cache.latest(), (id) => store.get(id), cache.collections().signalsOf, triage.get(), String(req.query.id || (req.body && req.body.id) || ''), runId);
}

router.get('/item', (req, res) => {
  const e = page(req);
  if (!e) return res.status(404).json({ error: 'no collection knows this entity' });
  res.json(e);
});

router.get('/find', (req, res) => res.json(findEntities(cache.latest(), req.query.q)));

router.get('/facts', (req, res) => {
  const run = store.get(String(req.query.host || ''));
  if (!run) return res.status(404).json({ error: 'no such collection' });
  res.json(entityFacts(run, String(req.query.ids || '').split(',').filter(Boolean)));
});

router.get('/virustotal', (req, res) => {
  const run = req.query.host ? store.get(String(req.query.host)) : null;
  res.json(vt.flaggedEntities(run ? [run] : cache.latest()));
});

router.put('/triage', (req, res) => {
  const e = page(req);
  if (!e || !req.body.host) return res.status(404).json({ error: 'no such entity in this collection' });
  try {
    res.json(triage.setState(e.triage.eid, req.body.state, req.body.note, req.user.username, e.sids));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// An entity's history holds its decisions as a whole and those of each of
// its signals apart (each naming its rule), in time order.
router.get('/history', (req, res) => {
  const e = page(req);
  if (!e) return res.status(404).json({ error: 'no such entity' });
  const rules = new Map(cache.collections().signalsOf(e.run_id).map((s) => [s.sid, s.rule_id]));
  res.json([...triage.history(e.triage.eid), ...e.sids.flatMap((sid) => triage.history(sid).map((c) => ({ ...c, signal: rules.get(sid) || sid })))]
    .sort((a, b) => String(a.at).localeCompare(String(b.at))));
});

module.exports = router;
