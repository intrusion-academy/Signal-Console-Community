// The users API (the Users page - see model/users.js):
//
//   GET /api/users
//     every account that used the fleet's hosts, one row each (without its
//     per-host detail), and the accounts left out, with why.
//   GET /api/users?on_host=<run id>
//     that host's accounts, each with the host's own detail (how it knows
//     the account, its logons there) and its fleet-wide host count; and the
//     accounts left out on it.
//   GET /api/users/:key
//     one user's profile: its row with its per-host detail, logon tables
//     and daily trend. key is its SID, or DOMAIN\name (URL-encoded).
'use strict';

const express = require('express');
const cache = require('../cache');
const { userSummary } = require('../model/users');

const router = express.Router();

router.get('/', (req, res) => {
  const inv = cache.users();
  const host = String(req.query.on_host || '');
  if (host) {
    // One host's accounts: each user seen on it, with that host's detail.
    res.json({
      users: inv.users.flatMap((u) => u.host_detail.filter((h) => h.run_id === host).map((h) => ({ ...h, key: u.key, account: u.account, scope: u.scope, kind: u.kind, seen_n: u.seen_n }))),
      excluded: inv.excluded.filter((e) => e.hosts.some((h) => h.run_id === host)),
    });
    return;
  }
  res.json({ hosts_n: cache.latest().length, users: inv.users.map(userSummary), excluded: inv.excluded });
});

router.get('/:key', (req, res) => {
  const u = cache.users().users.find((x) => x.key === String(req.params.key).toUpperCase());
  if (!u) return res.status(404).json({ error: 'no such user' });
  res.json(u);
});

module.exports = router;
