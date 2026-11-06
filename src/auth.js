// Authentication and authorization: local accounts, browser sessions, and
// who may do what.
//
// Accounts live in the database (users table), each an admin - every
// action, the accounts' management included - an analyst - every action
// on the runs and the analysts' work - or a viewer - read-only: a
// viewer's request that would change anything (any method but GET/HEAD) is
// refused on the server, whatever the page shows. Accounts are managed by
// admins on the Settings page (routes/accounts.js) and on the server's
// command line (scripts/users.js); the first is made in the shell that
// starts the console (server.js). There is deliberately no sign-up page,
// since one reachable before the first account exists would let anyone on
// the network claim it.
//
// Passwords are stored as scrypt hashes (Node's crypto - no dependency),
// each with its own random salt. A session is a random token in an
// HttpOnly, SameSite=Strict cookie; the database keeps only its SHA-256, so
// a copy of the database opens no session. A session ends after 8 hours
// without use, after 7 days at the latest, at sign-out, and when its
// account's password, role or status changes. Sign-in is refused for 15
// minutes after 5 failures for one account name or from one address.
// Sign-ins, failures, sign-outs and every account change are in the audit
// log (src/audit.js); who made a change is `who` - {actor, address} - the
// server's command line when not given.
'use strict';

const crypto = require('crypto');
const { promisify } = require('util');
const db = require('./db');
const audit = require('./audit');

const scrypt = promisify(crypto.scrypt);

const ROLES = ['admin', 'analyst', 'viewer'];
const USERNAME_RE = /^[A-Za-z0-9._-]{1,64}$/;
const MIN_PASSWORD = 12;
const COOKIE = 'sc_session';
const IDLE_MS = 8 * 3600 * 1000;
const MAX_AGE_MS = 7 * 24 * 3600 * 1000;
const TOUCH_MS = 60 * 1000; // last_seen is written at most once a minute per session
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

const now = () => new Date();
const iso = (d) => d.toISOString();
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const SHELL = { actor: 'command line' };

// ---- Passwords ------------------------------------------------------------

// hashPassword returns "scrypt$N$r$p$salt$hash" (base64 salt and hash).
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$');
}

// verifyPassword compares in constant time.
async function verifyPassword(password, stored) {
  const [kind, N, r, p, salt, hash] = String(stored).split('$');
  if (kind !== 'scrypt') return false;
  const expected = Buffer.from(hash, 'base64');
  const key = await scrypt(password, Buffer.from(salt, 'base64'), expected.length, { N: Number(N), r: Number(r), p: Number(p) });
  return crypto.timingSafeEqual(key, expected);
}

// A hash of no one's password, checked when the account does not exist, so
// an unknown name takes as long to refuse as a wrong password.
let decoyHash = null;
const decoy = async () => (decoyHash = decoyHash || await hashPassword(crypto.randomBytes(16).toString('hex')));

function checkPassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD) throw new Error(`a password needs at least ${MIN_PASSWORD} characters`);
}

// ---- Accounts ---------------------------------------------------------------

function checkUsername(username) {
  if (!USERNAME_RE.test(String(username || ''))) throw new Error('a username is 1-64 letters, digits, dots, dashes or underscores');
}
function checkRole(role) {
  if (!ROLES.includes(role)) throw new Error(`a role is one of: ${ROLES.join(', ')}`);
}

const getUser = (username) => db.main().prepare('SELECT username, role, password, disabled, created FROM users WHERE username = ?').get(String(username || ''));

function listUsers() {
  return db.main().prepare('SELECT username, role, disabled, created FROM users ORDER BY username').all().map((u) => ({ ...u, disabled: Boolean(u.disabled) }));
}

async function addUser(username, role, password, who = SHELL) {
  checkUsername(username);
  checkRole(role);
  checkPassword(password);
  if (getUser(username)) throw new Error(`account ${username} already exists`);
  db.main().prepare('INSERT INTO users (username, role, password, created) VALUES (?, ?, ?, ?)').run(username, role, await hashPassword(password), iso(now()));
  audit.record('account_added', { ...who, target: username, detail: `role ${role}` });
}

// update changes one account, signs it out everywhere and records the
// change in the audit log.
function update(username, sql, values, who, action, detail = '') {
  if (!getUser(username)) throw new Error(`no account ${username}`);
  db.transaction(() => {
    db.main().prepare(`UPDATE users SET ${sql} WHERE username = ?`).run(...values, username);
    db.main().prepare('DELETE FROM sessions WHERE username = ?').run(username);
  }, db.main());
  audit.record(action, { ...who, target: username, detail });
}

async function setPassword(username, password, who = SHELL) {
  checkPassword(password);
  update(username, 'password = ?', [await hashPassword(password)], who, 'password_changed');
}
function setRole(username, role, who = SHELL) {
  checkRole(role);
  if (role !== 'admin') keepAnAdmin(username, 'change the role of');
  const was = getUser(username);
  update(username, 'role = ?', [role], who, 'role_changed', was ? `${was.role} to ${role}` : `to ${role}`);
}
function setDisabled(username, disabled, who = SHELL) {
  if (disabled) keepAnAdmin(username, 'disable');
  update(username, 'disabled = ?', [disabled ? 1 : 0], who, disabled ? 'account_disabled' : 'account_enabled');
}
function removeUser(username, who = SHELL) {
  if (!getUser(username)) throw new Error(`no account ${username}`);
  keepAnAdmin(username, 'remove');
  db.main().prepare('DELETE FROM users WHERE username = ?').run(username);
  audit.record('account_removed', { ...who, target: username });
}

// keepAnAdmin refuses a change that would leave no enabled admin.
function keepAnAdmin(username, change) {
  const u = getUser(username);
  if (!u || u.role !== 'admin' || u.disabled) return;
  const others = db.main().prepare("SELECT count(*) AS n FROM users WHERE role = 'admin' AND disabled = 0 AND username <> ?").get(username).n;
  if (!others) throw new Error(`${username} is the only admin: make another account an admin before you ${change} it`);
}

// renameUser renames an account; it is signed out. What it did before keeps
// the name it had (triage, flags, imports record who acted at the time).
function renameUser(username, to, who = SHELL) {
  checkUsername(to);
  if (!getUser(username)) throw new Error(`no account ${username}`);
  if (getUser(to)) throw new Error(`account ${to} already exists`);
  db.transaction(() => {
    db.main().prepare('DELETE FROM sessions WHERE username = ?').run(username);
    db.main().prepare('UPDATE users SET username = ? WHERE username = ?').run(to, username);
  }, db.main());
  audit.record('account_renamed', { ...who, target: to, detail: `was ${username}` });
}

// ---- Sign-in limits ---------------------------------------------------------

// failures maps an account name or an address to its recent failures.
const failures = new Map();

function lockedFor(keys, at = Date.now()) {
  let wait = 0;
  for (const k of keys) {
    const f = failures.get(k);
    if (!f) continue;
    if (at - f.first > LOCK_MS) { failures.delete(k); continue; }
    if (f.n >= MAX_FAILURES) wait = Math.max(wait, f.first + LOCK_MS - at);
  }
  return wait;
}
function fail(keys, at = Date.now()) {
  for (const k of keys) {
    const f = failures.get(k);
    if (!f || at - f.first > LOCK_MS) failures.set(k, { n: 1, first: at });
    else f.n++;
  }
}

// ---- Sessions ---------------------------------------------------------------

// signIn checks a name and password; it returns {token, user} or throws
// with a message fit to show (never saying which of the two was wrong).
async function signIn(username, password, address) {
  const keys = [`user:${String(username || '').toLowerCase()}`, `addr:${address || ''}`];
  const name = String(username || '').slice(0, 64);
  const wait = lockedFor(keys);
  if (wait) {
    audit.record('sign_in_failed', { actor: name, address, detail: 'not checked: too many failed attempts for this name or address' });
    throw new Error(`too many failed attempts; try again in ${Math.ceil(wait / 60000)} minute(s)`);
  }
  const user = getUser(username);
  const ok = user ? await verifyPassword(String(password || ''), user.password) : (await verifyPassword(String(password || ''), await decoy()), false);
  if (!ok || user.disabled) {
    fail(keys);
    audit.record('sign_in_failed', { actor: name, address, detail: !user ? 'no such account' : ok ? 'the account is disabled' : 'wrong password' });
    throw new Error('wrong username or password');
  }
  for (const k of keys) failures.delete(k);
  const token = crypto.randomBytes(32).toString('base64url');
  const at = iso(now());
  db.main().prepare('INSERT INTO sessions (token_hash, username, created, last_seen) VALUES (?, ?, ?, ?)').run(sha256(token), user.username, at, at);
  audit.record('sign_in', { actor: user.username, address });
  return { token, user: { username: user.username, role: user.role } };
}

// sessionUser returns the account a session token belongs to, or null when
// the session does not exist, has expired, or its account is disabled.
function sessionUser(token, at = Date.now()) {
  if (!token) return null;
  const s = db.main().prepare('SELECT s.token_hash, s.created, s.last_seen, u.username, u.role, u.disabled FROM sessions s JOIN users u ON u.username = s.username WHERE s.token_hash = ?').get(sha256(token));
  if (!s) return null;
  if (s.disabled || at - Date.parse(s.last_seen) > IDLE_MS || at - Date.parse(s.created) > MAX_AGE_MS) {
    db.main().prepare('DELETE FROM sessions WHERE token_hash = ?').run(s.token_hash);
    return null;
  }
  if (at - Date.parse(s.last_seen) > TOUCH_MS) db.main().prepare('UPDATE sessions SET last_seen = ? WHERE token_hash = ?').run(iso(new Date(at)), s.token_hash);
  return { username: s.username, role: s.role };
}

function signOut(token, address) {
  if (!token) return;
  const s = db.main().prepare('SELECT username FROM sessions WHERE token_hash = ?').get(sha256(token));
  db.main().prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
  if (s) audit.record('sign_out', { actor: s.username, address });
}


// ---- HTTP -------------------------------------------------------------------

function cookieOf(req) {
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}

function setCookie(req, res, token, maxAgeMs) {
  const secure = req.secure || (process.env.SIGNAL_CONSOLE_SECURE_COOKIE || process.env.SIGNAL_WEB_SECURE_COOKIE) === '1'; // the old name still counts
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(maxAgeMs / 1000)}${secure ? '; Secure' : ''}`);
}

// sameOrigin: a request that changes something must come from this app's
// own pages - a browser sends Origin on such requests, and SameSite=Strict
// already keeps the cookie off other sites' requests; this is the second
// check.
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

// requireAuth guards every /api route but the sign-in ones: no session is
// 401; a viewer's (or a cross-origin) request that would change anything
// is 403. req.user is the signed-in account.
// who is the account behind a request and its address, for the audit log.
const who = (req) => ({ actor: req.user.username, address: req.socket.remoteAddress });

function requireAuth(req, res, next) {
  const user = sessionUser(cookieOf(req));
  if (!user) return res.status(401).json({ error: 'sign in first' });
  req.user = user;
  const reading = req.method === 'GET' || req.method === 'HEAD';
  if (!reading && !sameOrigin(req)) return res.status(403).json({ error: 'cross-origin request refused' });
  if (!reading && user.role === 'viewer') return res.status(403).json({ error: 'this account is read-only' });
  next();
}

// routes: POST /api/auth/login {username, password}, POST /api/auth/logout,
// GET /api/auth/me (the signed-in account, or null).
function routes() {
  const router = require('express').Router();
  router.post('/login', async (req, res) => {
    if (!sameOrigin(req)) return res.status(403).json({ error: 'cross-origin request refused' });
    try {
      const { token, user } = await signIn((req.body || {}).username, (req.body || {}).password, req.socket.remoteAddress);
      setCookie(req, res, token, MAX_AGE_MS);
      res.json(user);
    } catch (err) {
      res.status(401).json({ error: err.message });
    }
  });
  router.post('/logout', (req, res) => {
    signOut(cookieOf(req), req.socket.remoteAddress);
    setCookie(req, res, '', 0);
    res.json({ ok: true });
  });
  router.get('/me', (req, res) => {
    res.json(sessionUser(cookieOf(req))); // null when no one is signed in - an answer, not an error
  });
  return router;
}

module.exports = {
  ROLES, MIN_PASSWORD, hashPassword, verifyPassword, addUser, setPassword, setRole, setDisabled, removeUser, renameUser, listUsers,
  signIn, sessionUser, signOut, requireAuth, routes, who,
  _test: { lockedFor, fail, failures },
};
