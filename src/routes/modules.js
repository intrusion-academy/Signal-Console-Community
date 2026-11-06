// The modules API (the Modules page - see model/modules.js):
//
//   GET /api/modules
//     every module the fleet's hosts ran (each host's latest collection):
//     what it is, how it ran on each host, the evidence it read and its
//     health, its rules (built-in and imported), signals, warning cards and
//     telemetry.
'use strict';

const express = require('express');
const cache = require('../cache');

const router = express.Router();

router.get('/', (req, res) => {
  res.json({ hosts_n: cache.latest().length, modules: cache.modules() });
});

module.exports = router;
