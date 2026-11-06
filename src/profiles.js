// Profiles: Signal's scoping profiles (Signal's profile documentation) saved
// here by the Profiles page, each by the SHA-256 of its JSON as written -
// the same bytes `signal live -profile` is given, so the hash a run
// reports (run.profile.sha256) finds it. Signal checks a profile fully
// (`signal profile -check`); this store only refuses what is not one.
'use strict';

const crypto = require('crypto');
const db = require('./db');

// MAX is a profile's largest size here - the API's request limit (server.js);
// a profile is a few kilobytes.
const MAX = 1 << 20;

// sha256 is the hash Signal reports for a profile's JSON.
const sha256 = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');

// list is every saved profile, newest first, without its document.
function list() {
  return db.main().prepare('SELECT sha256, name, doc, saved_by, saved_at FROM profiles ORDER BY saved_at DESC').all()
    .map(({ doc, ...p }) => ({ ...p, ...summary(doc) }));
}

// summary is what a profile's list row states of its document.
function summary(doc) {
  const p = JSON.parse(doc);
  return { version: p.version || '', author: p.author || '', created: p.created || '', window: p.window || '', pivots_n: (p.pivots || []).length };
}

// get is one saved profile's JSON as written, or undefined.
function get(hash) {
  const row = db.main().prepare('SELECT doc FROM profiles WHERE sha256 = ?').get(String(hash));
  return row && row.doc;
}

// save stores a profile's JSON exactly as given and returns its hash; it
// throws when the text is not a profile (format version 1, a name).
function save(text, user) {
  if (typeof text !== 'string' || text.length > MAX) throw new Error('not a profile: JSON text of 1 MB at most');
  let p;
  try { p = JSON.parse(text); } catch (err) { throw new Error(`not JSON: ${err.message}`); }
  if (!p || p.profile !== 1 || typeof p.name !== 'string' || !p.name.trim()) throw new Error('not a profile: it needs "profile": 1 and a name');
  const hash = sha256(text);
  db.main().prepare('INSERT OR REPLACE INTO profiles (sha256, name, doc, saved_by, saved_at) VALUES (?, ?, ?, ?, ?)')
    .run(hash, p.name.trim(), text, user || '', new Date().toISOString());
  return hash;
}

// remove deletes a saved profile; runs keep naming it.
function remove(hash) {
  return db.main().prepare('DELETE FROM profiles WHERE sha256 = ?').run(String(hash)).changes > 0;
}

module.exports = { list, get, save, remove, sha256 };
