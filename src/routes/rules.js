// The rules API: the full catalog of every rule any imported module
// carries, with each rule's outcome on every host's latest collection -
// backs the Rules page (see model/rules.js).
'use strict';

const express = require('express');
const cache = require('../cache');
const { withConsole } = require('../consoleRules');

const router = express.Router();

router.get('/', (req, res) => {
  res.json(withConsole(cache.rules(), cache.latest()));
});

module.exports = router;
