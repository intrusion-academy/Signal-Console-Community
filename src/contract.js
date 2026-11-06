// Validation of a run document against Signal's output contract
// (Signal's output contract documentation). Import refuses a document with any
// problem; the contract test runs it over the fixture runs Signal itself
// generates. A run of an older schema is
// checked only for what every version has - an identifier and a modules
// object - and then upgraded (src/legacy.js); a run of a newer schema than
// this app knows is refused rather than half-understood.
'use strict';

const { CURRENT } = require('./legacy');
const CONSOLE_VERSION = require('../package.json').version;

// RUN_ID_RE is what a run ID may be: Signal writes 16 hex digits; letters,
// digits and dashes are accepted (the fixture runs use names). Anything else
// - a path separator, "..", a drive letter - is refused.
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const validRunId = (id) => typeof id === 'string' && RUN_ID_RE.test(id);

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const MODULE_STATUSES = new Set(['ok', 'partial', 'failed', 'skipped']);
const KPI_STATUSES = new Set(['good', 'warn', 'bad']);
const TELEMETRY_STATES = new Set(['on', 'off', 'absent', 'unknown']);
const RULE_STATUSES = new Set(['flagged', 'clear', 'not_run']);
const SOURCE_STATUSES = new Set(['read', 'partial', 'not_read', 'unavailable']);

// MIN_SIGNAL_MAJOR is the oldest Signal major version whose runs are
// accepted: every run before Signal 1.0.0 (the first release) is refused.
// signalMajor reads the major number from a version such as "1.2.3" or
// "1.0.0-rc1"; anything without one is 0, so it is refused too.
const MIN_SIGNAL_MAJOR = 1;
const signalMajor = (v) => { const m = /^(\d+)\./.exec(typeof v === 'string' ? v : ''); return m ? Number(m[1]) : 0; };

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isString = (v) => typeof v === 'string';

// problems lists every way doc departs from the contract (empty: valid).
function problems(doc) {
  if (!isObject(doc)) return ['not a JSON object'];
  const out = [];
  if (!validRunId(doc.run_id)) out.push('run_id missing or invalid (letters, digits and dashes only)');
  if (!isObject(doc.modules)) out.push('modules must be an object');
  if (signalMajor(doc.tool_version) < MIN_SIGNAL_MAJOR) {
    out.push(`this run is from Signal ${doc.tool_version || '(version not stated)'}, older than Signal ${MIN_SIGNAL_MAJOR}.0.0 - Signal Console ${CONSOLE_VERSION} accepts runs from Signal ${MIN_SIGNAL_MAJOR}.0.0 or later only, so it was not stored; `
      + `update Signal on the host (signal update) and run it again`);
    return out;
  }
  const version = Number(doc.schema_version) || 0;
  if (version > CURRENT) {
    out.push(`this run is from a newer Signal (${doc.tool_version ? `version ${doc.tool_version}, ` : ''}output schema ${version}) than this Signal Console ${CONSOLE_VERSION} reads (schema ${CURRENT} at most), so it was not stored - `
      + 'update Signal Console to the version released with that Signal or later, then import the run again'
    );
  }
  if (out.length || version < CURRENT) return out;

  if (!isObject(doc.host) || !isString(doc.host.hostname)) out.push('host.hostname missing');
  if (!Array.isArray(doc.sources)) out.push('sources must be a list');
  for (const s of Array.isArray(doc.sources) ? doc.sources : []) {
    if (!isObject(s) || !isString(s.evidence) || !isString(s.label) || !SOURCE_STATUSES.has(s.status)) { out.push(`source ${JSON.stringify(s)}: needs evidence, label and a known status`); continue; }
    for (const p of s.prerequisites || []) {
      if (!isString(p.fact) || !TELEMETRY_STATES.has(p.state)) out.push(`source ${s.evidence}: prerequisite ${JSON.stringify(p)}`);
    }
  }
  // Entities (schema 17): each a type, key and display, its severity and
  // its signals - a list, possibly empty when no signal named a subject.
  if (doc.entities !== undefined && !Array.isArray(doc.entities)) out.push('entities must be a list');
  for (const e of Array.isArray(doc.entities) ? doc.entities : []) {
    if (!isObject(e) || !isString(e.type) || !isString(e.key) || !isString(e.display) || !SEVERITIES.has(e.severity) || !Array.isArray(e.signals)
      || e.signals.some((s) => !isObject(s) || !isString(s.rule_id) || !isString(s.value) || typeof s.count !== 'number')) {
      out.push(`entity ${JSON.stringify(e && e.key)}: needs type, key, display, a severity and its signals (rule_id, value, count)`);
      break;
    }
  }
  // Entity facts (schema 28): each a type, key and display, and its facts
  // - a list, possibly empty; absent in a run upgraded from before 28 (not
  // read - never "none").
  if (doc.entity_facts !== undefined && !Array.isArray(doc.entity_facts)) out.push('entity_facts must be a list');
  for (const f of Array.isArray(doc.entity_facts) ? doc.entity_facts : []) {
    if (!isObject(f) || !isString(f.type) || !isString(f.key) || !isString(f.display) || !Array.isArray(f.facts)
      || f.facts.some((x) => !isObject(x) || !isString(x.label) || !isString(x.value) || !isString(x.source))) {
      out.push(`entity facts ${JSON.stringify(f && f.key)}: need type, key, display and facts (label, value, source)`);
      break;
    }
  }
  // Shadow copies (schema 39, signal live -shadow only): what was asked
  // for, the note on what it means, and each copy found.
  if (doc.shadow_copies !== undefined) {
    const sc = doc.shadow_copies;
    // Signal 0.45.0-0.53.0 wrote "copies": null when the host had no copy: none (legacy.upgrade makes it a list).
    const copies = sc && sc.copies === null ? [] : sc && sc.copies;
    if (!isObject(sc) || !isString(sc.requested) || !isString(sc.note) || !Array.isArray(copies)
      || copies.some((c) => !isObject(c) || !isString(c.id) || !isString(c.volume) || !isString(c.created) || typeof c.read !== 'boolean')) {
      out.push('shadow_copies needs requested, a note and its copies (id, volume, created, read)');
    }
  }
  for (const [name, r] of Object.entries(doc.modules)) {
    const at = (what) => `${name}: ${what}`;
    if (!isObject(r)) { out.push(at('result must be an object')); continue; }
    if (!MODULE_STATUSES.has(r.status)) out.push(at(`status "${r.status}"`));
    if (r.about !== undefined && (!isObject(r.about) || !isString(r.about.description) || (r.about.evidence !== undefined && !Array.isArray(r.about.evidence)))) out.push(at('about needs a description, and evidence as a list'));
    for (const k of r.kpis || []) {
      if (!isString(k.id) || !isString(k.label) || !isString(k.value) || (k.status !== undefined && !KPI_STATUSES.has(k.status)) || (k.note !== undefined && !isString(k.note))) out.push(at(`KPI ${JSON.stringify(k)}`));
    }
    for (const t of r.telemetry || []) {
      if (!isString(t.id) || !isString(t.label) || !TELEMETRY_STATES.has(t.state) || !isString(t.category)) out.push(at(`telemetry ${JSON.stringify(t)}`));
    }
    for (const d of r.datasets || []) {
      if (!isString(d.name) || !Array.isArray(d.columns) || !Array.isArray(d.rows)) { out.push(at(`dataset ${d.name}: needs name, columns and rows`)); continue; }
      const bad = d.rows.findIndex((row) => !Array.isArray(row) || row.length !== d.columns.length);
      if (bad >= 0) out.push(at(`dataset ${d.name}: row ${bad} does not have ${d.columns.length} values`));
      if (String(d.role || '').startsWith('identity.') && d.columns.slice(1).join() !== 'count,first_seen,last_seen') out.push(at(`identity dataset ${d.name}: columns ${d.columns.join(', ')}`));
      if (d.role === 'inventory.av_exclusions' && d.columns.join() !== 'product,kind,exclusion') out.push(at(`exclusions dataset ${d.name}: columns ${d.columns.join(', ')}`));
    }
    for (const e of r.rule_catalog || []) {
      if (!isString(e.id) || !SEVERITIES.has(e.severity) || !RULE_STATUSES.has(e.status)) out.push(at(`rule ${e.id}: severity "${e.severity}", status "${e.status}"`));
    }
    for (const f of r.findings || []) {
      if (!SEVERITIES.has(f.severity) || !isString(f.title)) out.push(at(`finding ${f.rule_id}: severity "${f.severity}"`));
      // An observation must carry its fields; its entity and value, when
      // present, must be text. Signal always states both, but a run where
      // one event lacks them is still worth importing - the event shows
      // without them - rather than refused whole over one event.
      for (const o of f.observations || []) {
        const text = (v) => v === undefined || isString(v);
        if (!isObject(o.fields) || !text(o.entity) || !text(o.value)) { out.push(at(`finding ${f.rule_id}: observation needs fields, and text entity and value`)); break; }
        if (o.source !== undefined && (!isObject(o.source) || !isString(o.source.evidence) || !isString(o.source.label))) { out.push(at(`finding ${f.rule_id}: observation source needs its evidence type and label`)); break; }
        if (o.corroborated_by !== undefined && (!Array.isArray(o.corroborated_by) || o.corroborated_by.some((p) => !isObject(p) || !isString(p.evidence) || !isString(p.description)))) { out.push(at(`finding ${f.rule_id}: corroborated_by needs a list of evidence, each with its type and description`)); break; }
      }
    }
  }
  return out;
}

module.exports = { problems, validRunId, CURRENT };
