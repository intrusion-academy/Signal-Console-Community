// The reviews API (src/reviews.js):
//
//   GET /api/reviews[?hosts=<run ids>]
//     each data page's review over the chosen hosts' latest collections
//     (every host when none is given): hosts with something on it, how
//     many are reviewed, state reviewed / not_reviewed.
//   PUT /api/reviews {page, hosts, on}
//     an analyst marks the page reviewed (or not) on the chosen hosts
//     (run ids; every host when empty).
'use strict';

const express = require('express');
const reviews = require('../reviews');
const cache = require('../cache');

const router = express.Router();

// chosen is the latest collections of the hosts named by run ID, or every
// host's.
function chosen(ids) {
  const latest = cache.latest();
  const wanted = new Set(String(ids || '').split(',').filter(Boolean));
  return wanted.size ? latest.filter((r) => wanted.has(r.run_id)) : latest;
}

router.get('/', (req, res) => res.json(reviews.status(chosen(req.query.hosts))));

router.put('/', (req, res) => {
  const { page, hosts, on } = req.body || {};
  if (!reviews.mark(String(page || ''), chosen(Array.isArray(hosts) ? hosts.join(',') : hosts), Boolean(on), req.user.username)) {
    return res.status(400).json({ error: 'not a page that is reviewed' });
  }
  res.json({ ok: true });
});

module.exports = router;
