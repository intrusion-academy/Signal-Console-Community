// The VirusTotal API (src/virustotal.js):
//
//   GET /api/virustotal/settings
//     on or off, whether a key is stored (its last four characters), the
//     wait after a quota answer, the queue's counts, the last error.
//   PUT /api/virustotal/settings {enabled?, key?, wait_seconds?}
//     an admin turns the lookups on or off, stores a key, sets the wait.
//   GET /api/virustotal?items=<kind>:<value>,...
//     what VirusTotal said of each (kind file, ip or domain), or its state.
'use strict';

const express = require('express');
const vt = require('../virustotal');

const router = express.Router();

router.get('/settings', (req, res) => res.json(vt.settings()));

router.put('/settings', (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'only an admin changes the VirusTotal settings' });
  try {
    res.json(vt.configure(req.body || {}));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/', (req, res) => {
  const items = String(req.query.items || '').split(',').filter(Boolean).slice(0, 200).map((x) => {
    const i = x.indexOf(':');
    return [x.slice(0, i), x.slice(i + 1)];
  });
  res.json(vt.results(items));
});

module.exports = router;
