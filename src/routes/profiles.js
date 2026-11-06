// The profiles API (the Profiles page - src/profiles.js):
//
//   GET /api/profiles
//     every saved profile, and every profile the hosts' latest collections
//     were given that is not saved here (known only by its name and hash),
//     each with the hosts that ran it; and the hosts given none.
//   GET /api/profiles/params
//     every module's parameters (src/data/modules.json: signal list -json).
//   GET /api/profiles/:sha256
//     a saved profile: {sha256, text} - its JSON exactly as written.
//   POST /api/profiles {text}
//     an analyst saves a profile, exactly as written; returns its hash.
//   DELETE /api/profiles/:sha256
//     an analyst removes a saved profile.
'use strict';

const express = require('express');
const cache = require('../cache');
const profiles = require('../profiles');
const { hostMeta } = require('../model/hosts');

const router = express.Router();

router.get('/', (req, res) => {
  const byHash = new Map(profiles.list().map((p) => [p.sha256, { ...p, saved: true, hosts: [] }]));
  const none = [];
  for (const run of cache.latest()) {
    const host = { run_id: run.run_id, ...hostMeta(run) };
    const p = run.profile;
    if (!p || !p.sha256) { none.push(host); continue; }
    if (!byHash.has(p.sha256)) {
      byHash.set(p.sha256, { sha256: p.sha256, name: p.name || '', version: p.version || '', author: p.author || '', created: p.created || '', window: p.window || '', pivots_n: null, saved: false, saved_by: '', saved_at: '', hosts: [] });
    }
    byHash.get(p.sha256).hosts.push(host);
  }
  res.json({ profiles: [...byHash.values()], unprofiled: none });
});

// Every module's parameters as this console's Signal states them
// (src/data/modules.json, written by `signal list -json`), so a profile
// can give them before any run is imported.
router.get('/params', (req, res) => res.json({ modules: require('../data/modules.json') }));

router.get('/:hash', (req, res) => {
  const doc = profiles.get(req.params.hash);
  if (doc === undefined) return res.status(404).json({ error: 'no profile with this hash is saved here' });
  res.json({ sha256: req.params.hash, text: doc });
});

router.post('/', (req, res) => {
  try {
    res.json({ sha256: profiles.save((req.body || {}).text, req.user.username) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/:hash', (req, res) => {
  if (!profiles.remove(req.params.hash)) return res.status(404).json({ error: 'no profile with this hash is saved here' });
  res.json({ ok: true });
});

module.exports = router;
