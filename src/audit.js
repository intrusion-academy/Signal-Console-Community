// The audit log: who signed in or failed to, every change to the
// console's accounts, and every run removed -
// what an organisation's auditor asks for first.
// One row per event in the main file: when, the account that acted
// (or "command line" / "first start" for the server's shell), what was
// done, to what, from which address, and a detail. Never a password or a
// session token. The newest MAX_ROWS rows are kept.
//
// What an analyst decides (triage, flags, suppressions) is recorded with
// its own history where it is made; this log is about access.
'use strict';

const db = require('./db');

const MAX_ROWS = 100000;

// ACTIONS are the events, each with the words the Settings page shows.
const ACTIONS = {
  sign_in: 'signed in',
  sign_in_failed: 'sign-in refused',
  sign_out: 'signed out',
  account_added: 'account added',
  account_renamed: 'account renamed',
  role_changed: 'role changed',
  password_changed: 'password changed',
  account_disabled: 'account disabled',
  account_enabled: 'account enabled',
  account_removed: 'account removed',
  runs_removed: 'runs removed',
};

// record adds one event; an unknown action is a programming error.
function record(action, { actor = '', target = '', address = '', detail = '' } = {}) {
  if (!ACTIONS[action]) throw new Error(`unknown audit action ${action}`);
  const conn = db.main();
  const { lastInsertRowid } = conn.prepare('INSERT INTO audit (at, actor, action, target, address, detail) VALUES (?, ?, ?, ?, ?, ?)')
    .run(new Date().toISOString(), String(actor), action, String(target), String(address || ''), String(detail));
  if (lastInsertRowid > MAX_ROWS) conn.prepare('DELETE FROM audit WHERE id <= ?').run(Number(lastInsertRowid) - MAX_ROWS);
}


// list returns the newest events first, each with its action's words.
function list(limit = 5000) {
  return db.main().prepare('SELECT id, at, actor, action, target, address, detail FROM audit ORDER BY id DESC LIMIT ?').all(limit)
    .map((r) => ({ ...r, what: ACTIONS[r.action] || r.action }));
}

module.exports = { record, list, ACTIONS, MAX_ROWS };
