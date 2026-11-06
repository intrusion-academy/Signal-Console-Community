// Storage for the analyst's decisions about signals: a triage state and
// note per signal (keyed by its stable ID - see model/signals.js) or per
// entity on a host (keyed by its own stable ID, with the signals the
// decision covers - see model/entities.js), with the history of every
// change, and suppression rules (see model/triage.js for what they mean). Kept apart from the runs: a run is evidence and is
// stored verbatim; triage is the analyst's work about it, and must survive
// a run being re-imported or replaced by a newer collection.
//
// The triage file of an earlier version of this app (data/triage.json) is
// moved into the database once, on first start.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');
const { TRIAGE_STATES, SUPPRESSION_OPS } = require('./model/triage');


// migrateFile moves data/triage.json into the database, once.
function migrateFile() {
  if (db.meta('migrated_triage_file')) return;
  const file = path.join(db.DATA_DIR, 'triage.json');
  if (fs.existsSync(file)) {
    try {
      const old = JSON.parse(fs.readFileSync(file, 'utf8'));
      db.transaction(() => {
        for (const [sid, t] of Object.entries(old.states || {})) {
          db.open().prepare('INSERT OR REPLACE INTO triage (sid, state, note, updated) VALUES (?, ?, ?, ?)').run(sid, t.state, t.note || '', t.updated || '');
          db.open().prepare('INSERT INTO triage_history (sid, state, note, at) VALUES (?, ?, ?, ?)').run(sid, t.state, t.note || '', t.updated || '');
        }
        for (const r of old.suppressions || []) {
          // Earlier versions called a signal's context line "executable".
          const conditions = (r.conditions || []).map((c) => (c.field === 'executable' ? { ...c, field: 'context' } : c));
          db.open().prepare('INSERT OR REPLACE INTO suppressions (id, conditions, note, created) VALUES (?, ?, ?, ?)').run(r.id, JSON.stringify(conditions), r.note || '', r.created || '');
        }
      });
      console.log(`triage: moved ${file} into the database`);
    } catch (err) {
      console.error(`triage: could not read ${file}: ${err.message}`);
    }
  }
  db.meta('migrated_triage_file', new Date().toISOString());
}

// load reads the data file's triage into memory: doc is the states and the
// suppression rules; version counts changes, so a cache of anything
// computed with the triage can tell when it is stale.
function load() {
  migrateFile();
  const states = {};
  for (const r of db.open().prepare('SELECT sid, state, note, updated, decided_by, covers FROM triage').iterate()) {
    states[r.sid] = { state: r.state, note: r.note, updated: r.updated, by: r.decided_by, covers: r.covers ? JSON.parse(r.covers) : null };
  }
  const suppressions = db.open().prepare('SELECT id, conditions, note, created, created_by FROM suppressions ORDER BY created').all()
    .map((r) => ({ id: r.id, conditions: JSON.parse(r.conditions), note: r.note, created: r.created, created_by: r.created_by }));
  return { doc: { states, suppressions }, version: 1 };
}

// current is the data file's triage, read on first use.
const current = () => db.local('triage', load);

const get = () => current().doc;

// setState records a signal's or an entity's triage state and note,
// decided by the account `by`, and the change in its history - for an
// entity, with the sids of the signals it covers. Every decision needs a
// note (the analyst's reason) - reopening one ("new", shown as open) too.
function setState(sid, state, note, by, covers = null) {
  if (!TRIAGE_STATES.includes(state)) throw new Error(`unknown triage state "${state}"`);
  const at = new Date().toISOString();
  const text = String(note || '').trim();
  if (!text) throw new Error('a triage decision needs a note saying why');
  const who = String(by || '');
  const covered = covers ? JSON.stringify(covers) : '';
  db.transaction(() => {
    db.open().prepare('INSERT OR REPLACE INTO triage (sid, state, note, updated, decided_by, covers) VALUES (?, ?, ?, ?, ?, ?)').run(sid, state, text, at, who, covered);
    db.open().prepare('INSERT INTO triage_history (sid, state, note, at, decided_by, covers) VALUES (?, ?, ?, ?, ?, ?)').run(sid, state, text, at, who, covered);
  });
  const st = current();
  st.doc.states[sid] = { state, note: text, updated: at, by: who, covers };
  st.version++;
  return st.doc.states[sid];
}

// prune forgets the triage of every signal and entity no imported run has
// (keep: their sids and entity triage IDs) - decision and history alike:
// once its runs are removed, a decision is over and never comes back on a
// later import. Answers how many it forgot.
function prune(keep) {
  const st = current();
  const gone = Object.keys(st.doc.states).filter((sid) => !keep.has(sid));
  const orphans = db.open().prepare('SELECT DISTINCT sid FROM triage_history').all().map((r) => r.sid).filter((sid) => !keep.has(sid) && !gone.includes(sid));
  if (!gone.length && !orphans.length) return 0;
  db.transaction(() => {
    for (const sid of [...gone, ...orphans]) {
      db.open().prepare('DELETE FROM triage WHERE sid = ?').run(sid);
      db.open().prepare('DELETE FROM triage_history WHERE sid = ?').run(sid);
    }
  });
  for (const sid of gone) delete st.doc.states[sid];
  st.version++;
  return gone.length;
}

// history lists a signal's or an entity's triage changes, oldest first:
// state, note, when, by whom, and how many signals an entity's covered.
function history(sid) {
  return db.open().prepare('SELECT state, note, at, decided_by AS by, covers FROM triage_history WHERE sid = ? ORDER BY id').all(sid)
    .map((r) => ({ state: r.state, note: r.note, at: r.at, by: r.by, covers_n: r.covers ? JSON.parse(r.covers).length : null }));
}

// FIELD_RE is what a condition's field may name: one of a signal's columns
// or an event field such as process.parent_name.
const FIELD_RE = /^[a-z_][a-z0-9_.]*$/;

// addSuppression validates and stores a suppression rule: conditions
// [{field, op, value}] (at least one; every one must hold) and a note
// saying why the matching signals are not worth an analyst's attention,
// made by the account `by`.
function addSuppression({ conditions, note }, by) {
  const conds = (conditions || []).map((c) => ({ field: String(c.field || ''), op: String(c.op || ''), value: String(c.value ?? '') }));
  if (conds.length === 0) throw new Error('a suppression rule needs at least one condition');
  for (const c of conds) {
    if (!FIELD_RE.test(c.field) || !SUPPRESSION_OPS[c.op] || c.value === '') throw new Error(`invalid condition ${JSON.stringify(c)}`);
  }
  if (!String(note || '').trim()) throw new Error('a suppression rule needs a note saying why');
  const rule = { id: crypto.randomBytes(6).toString('hex'), conditions: conds, note: String(note).trim(), created: new Date().toISOString(), created_by: String(by || '') };
  db.open().prepare('INSERT INTO suppressions (id, conditions, note, created, created_by) VALUES (?, ?, ?, ?, ?)').run(rule.id, JSON.stringify(rule.conditions), rule.note, rule.created, rule.created_by);
  const st = current();
  st.doc.suppressions.push(rule);
  st.version++;
  return rule;
}

function removeSuppression(id) {
  const { changes } = db.open().prepare('DELETE FROM suppressions WHERE id = ?').run(id);
  if (!changes) return false;
  const st = current();
  st.doc.suppressions = st.doc.suppressions.filter((r) => r.id !== id);
  st.version++;
  return true;
}

module.exports = { get, setState, history, prune, addSuppression, removeSuppression, version: () => current().version };
