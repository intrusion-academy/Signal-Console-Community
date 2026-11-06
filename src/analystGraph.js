// The analyst's additions to the entity graph: entities Signal did not
// report and links between any two of the graph's entities, each with who
// added it and when (src/db.js, analyst_entities and analyst_links). They
// are the analyst's statements, never Signal's findings - the graph marks
// them apart.
'use strict';

const db = require('./db');

// KEY is how an analyst's entity is named in a link and a flag.
const KEY = 'analyst:';

// list is every analyst entity and link of the data file.
function list() {
  const conn = db.open();
  return {
    entities: conn.prepare('SELECT id, type, name, note, added_by, at FROM analyst_entities ORDER BY id').all().map((e) => ({ ...e, key: KEY + e.id })),
    links: conn.prepare('SELECT id, a, b, words, added_by, at FROM analyst_links ORDER BY id').all(),
  };
}

// addEntity adds an entity (type and name required) and returns it.
function addEntity({ type, name, note }, by) {
  type = String(type || '').trim();
  name = String(name || '').trim();
  if (!type || !name || type.length > 40 || name.length > 500) throw new Error('an entity needs a type (up to 40 characters) and a name (up to 500)');
  const r = db.open().prepare('INSERT INTO analyst_entities (type, name, note, added_by, at) VALUES (?, ?, ?, ?, ?)')
    .run(type, name, String(note || '').slice(0, 2000), by, new Date().toISOString());
  return list().entities.find((e) => e.id === Number(r.lastInsertRowid));
}

// addLink links two of the graph's entities (their keys), saying what it is.
function addLink({ a, b, words }, by) {
  a = String(a || '');
  b = String(b || '');
  if (!a || !b || a === b) throw new Error('a link needs two different entities');
  db.open().prepare('INSERT INTO analyst_links (a, b, words, added_by, at) VALUES (?, ?, ?, ?, ?)')
    .run(a, b, String(words || '').trim().slice(0, 200), by, new Date().toISOString());
}

// removeEntity removes an analyst entity and every analyst link to it.
function removeEntity(id) {
  const conn = db.open();
  conn.prepare('DELETE FROM analyst_links WHERE a = ? OR b = ?').run(KEY + id, KEY + id);
  return conn.prepare('DELETE FROM analyst_entities WHERE id = ?').run(Number(id)).changes > 0;
}

const removeLink = (id) => db.open().prepare('DELETE FROM analyst_links WHERE id = ?').run(Number(id)).changes > 0;

module.exports = { list, addEntity, addLink, removeEntity, removeLink, KEY };
