// The analyst's part of the Timeline page: tags on its items (a signal by
// its sid, an analyst's event by manual:<id>) and events added by hand,
// each with who added it and when (src/db.js, timeline_tags and
// timeline_events). An event added by hand is the analyst's statement,
// never Signal's finding - the page marks it apart.
'use strict';

const db = require('./db');

const MANUAL = 'manual:';
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

// list is every tag (item -> tags) and every manual event of the data file.
function list() {
  const conn = db.open();
  const tags = {};
  for (const t of conn.prepare('SELECT item, tag FROM timeline_tags ORDER BY tag').all()) (tags[t.item] ||= []).push(t.tag);
  const events = conn.prepare('SELECT id, time, severity, title, description, host, entity_type, entity_name, added_by, at FROM timeline_events ORDER BY time').all()
    .map((e) => ({ ...e, key: MANUAL + e.id }));
  return { tags, events };
}

// setTags replaces an item's tags (trimmed, at most 20 of 40 characters).
function setTags(item, tags, by) {
  item = String(item || '');
  if (!item || item.length > 200) throw new Error('no item to tag');
  const clean = [...new Set((Array.isArray(tags) ? tags : []).map((t) => String(t).trim()).filter(Boolean))];
  if (clean.length > 20 || clean.some((t) => t.length > 40)) throw new Error('at most 20 tags of up to 40 characters');
  const conn = db.open();
  db.transaction(() => {
    conn.prepare('DELETE FROM timeline_tags WHERE item = ?').run(item);
    const add = conn.prepare('INSERT INTO timeline_tags (item, tag, added_by, at) VALUES (?, ?, ?, ?)');
    const at = new Date().toISOString();
    for (const t of clean) add.run(item, t, by, at);
  }, conn);
}

// checked is an event's fields, refused when the time, severity or title is missing.
function checked(e) {
  const time = new Date(String(e.time || ''));
  const severity = String(e.severity || '');
  const title = String(e.title || '').trim();
  if (Number.isNaN(time.getTime())) throw new Error('an event needs its time');
  if (!SEVERITIES.includes(severity)) throw new Error(`a severity: ${SEVERITIES.join(', ')}`);
  if (!title || title.length > 300) throw new Error('an event needs a title (up to 300 characters)');
  const cut = (v, n) => String(v || '').trim().slice(0, n);
  return [time.toISOString(), severity, title, cut(e.description, 4000), cut(e.host, 200), cut(e.entity_type, 40), cut(e.entity_name, 500)];
}

function addEvent(e, by) {
  db.open().prepare('INSERT INTO timeline_events (time, severity, title, description, host, entity_type, entity_name, added_by, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(...checked(e), by, new Date().toISOString());
}

const updateEvent = (id, e) => db.open().prepare('UPDATE timeline_events SET time = ?, severity = ?, title = ?, description = ?, host = ?, entity_type = ?, entity_name = ? WHERE id = ?')
  .run(...checked(e), Number(id)).changes > 0;

// removeEvent removes a manual event and its tags.
function removeEvent(id) {
  const conn = db.open();
  conn.prepare('DELETE FROM timeline_tags WHERE item = ?').run(MANUAL + Number(id));
  return conn.prepare('DELETE FROM timeline_events WHERE id = ?').run(Number(id)).changes > 0;
}

module.exports = { list, setTags, addEvent, updateEvent, removeEvent };
