// The console's accounts, managed by an admin on the Settings page (the
// user, 2026-10-26) - the same changes as scripts/users.js:
//
//   GET    /api/settings/accounts                 every account (never a password)
//   POST   /api/settings/accounts                 {username, role, password} adds one
//   PUT    /api/settings/accounts/:name           {role} | {username} (rename) | {password} | {disabled}
//   DELETE /api/settings/accounts/:name
//
// Every change signs the account out everywhere (src/auth.js update); none
// may leave the console without an enabled admin; an admin cannot remove
// or disable their own account here (another admin, or the command line).
'use strict';

const express = require('express');
const auth = require('../auth');

const router = express.Router();

router.use((req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'only an admin manages accounts' })));

const answer = (res, fn) => Promise.resolve().then(fn).then(() => res.json(auth.listUsers()), (err) => res.status(400).json({ error: err.message }));

router.get('/', (req, res) => res.json(auth.listUsers()));

router.post('/', (req, res) => {
  const { username, role, password } = req.body || {};
  answer(res, () => auth.addUser(String(username || '').trim(), role, password, auth.who(req)));
});

router.put('/:name', (req, res) => {
  const name = req.params.name;
  const b = req.body || {};
  answer(res, async () => {
    if (b.username !== undefined) {
      if (name === req.user.username) throw new Error('rename your own account from another admin, or with npm run users');
      auth.renameUser(name, String(b.username).trim(), auth.who(req));
    } else if (b.role !== undefined) auth.setRole(name, b.role, auth.who(req));
    else if (b.password !== undefined) await auth.setPassword(name, b.password, auth.who(req));
    else if (b.disabled !== undefined) {
      if (name === req.user.username && b.disabled) throw new Error('you cannot disable your own account');
      auth.setDisabled(name, Boolean(b.disabled), auth.who(req));
    } else throw new Error('nothing to change');
  });
});

router.delete('/:name', (req, res) => {
  if (req.params.name === req.user.username) return res.status(400).json({ error: 'you cannot remove your own account' });
  return answer(res, () => auth.removeUser(req.params.name, auth.who(req)));
});

module.exports = router;
