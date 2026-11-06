// The model: pure transforms from the imported run documents to what every
// page presents. Nothing here reads or writes storage; src/cache.js keeps
// the computed model for the current runs and triage.
'use strict';

module.exports = {
  ...require('./hosts'),
  ...require('./signals'),
  ...require('./triage'),
  ...require('./rules'),
  ...require('./inventories'),
  ...require('./fleet'),
  ...require('./users'),
  ...require('./entities'),
  ...require('./modules'),
  ...require('./attack'),
  signalQuery: require('./signalQuery'),
};
