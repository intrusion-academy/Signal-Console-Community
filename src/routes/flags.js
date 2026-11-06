// The flags API (src/flags.js):
//
//   GET /api/flags
//     the flagged items: every analyst's flag, newest first, then the
//     console's (an application in CISA's KEV catalog, over the hosts'
//     latest collections) - when, what, where, by whom, the console rule
//     and the reason.
//   PUT /api/flags {kind, key, label, on, reason}
//     an analyst flags a row of an inventory, fleet-wide, with the reason
//     (required) - or removes the flag; kind, key and label are the row's
//     flag_kind, flag_key and flag_label.
'use strict';

const express = require('express');
const flags = require('../flags');
const cache = require('../cache');
const applications = require('../applications');

const router = express.Router();

router.get('/', (req, res) => res.json([...flags.list(), ...applications.consoleFlags(cache.latest())]));

router.put('/', (req, res) => {
  const { kind, key, label, on, reason } = req.body || {};
  const error = flags.set(String(kind || ''), key, label, Boolean(on), req.user.username, reason);
  if (error) return res.status(400).json({ error });
  res.json({ ok: true });
});

module.exports = router;
