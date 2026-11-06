// Triage and suppression: an analyst's decisions about signals (see
// src/triageStore.js for where they are kept). A triage state per entity
// on a host, covering its signals (Signal schema 28: the analyst triages
// what the signals are about, as a whole), or per signal for one with no
// entity - new (the default), reviewed, benign or escalated, with a note - and
// suppression rules, each a set of conditions that hides every signal
// matching all of them (the same signal on every host and in every future
// collection), with a note saying why. A signal is open unless it is
// suppressed or triaged benign; the counts, risk and "untriaged" numbers
// across the app are of open signals.
'use strict';

const TRIAGE_STATES = ['new', 'reviewed', 'benign', 'escalated'];

// SUPPRESSION_OPS compare a signal's field with a condition's value,
// case-insensitively.
const SUPPRESSION_OPS = {
  equals: (a, b) => a === b,
  contains: (a, b) => a.includes(b),
  startswith: (a, b) => a.startsWith(b),
  endswith: (a, b) => a.endsWith(b),
};

// SIGNAL_FIELDS are the signal's own columns a condition may name; any
// other field is one of its event's fields (process.parent_name,
// log.subject, ...), or signer.
const SIGNAL_FIELDS = ['rule_id', 'host', 'module', 'entity', 'context', 'evidence'];

// suppressionField is the value of a condition's field on a signal: one of
// its own columns, its program's signer (only when its signature is valid -
// its entity's facts, model/signals.js), or any of its event's fields.
function suppressionField(s, field) {
  if (SIGNAL_FIELDS.includes(field)) return s[field];
  if (field === 'signer') return s.signer || '';
  return (s.fields || {})[field];
}

// suppressionMatches: every condition holds (a rule without conditions
// matches nothing), and a field the signal does not have never matches.
function suppressionMatches(rule, s) {
  const conds = rule.conditions || [];
  return conds.length > 0 && conds.every((c) => {
    const v = suppressionField(s, c.field);
    const op = SUPPRESSION_OPS[c.op];
    return op && v !== undefined && v !== null && v !== '' && op(String(v).toLowerCase(), String(c.value ?? '').toLowerCase());
  });
}

// decisionOf is the decision a signal stands under, {t, via}: its
// entity's, when that decision covers it, or its own - the newer of the
// two when both were made (an analyst decides one signal of an entity
// apart, or the entity again as a whole). Null when none was made; a
// signal that appeared after its entity's decision has only its own.
function decisionOf(doc, eid, sid) {
  const states = (doc && doc.states) || {};
  const e = eid ? states[eid] : null;
  const ent = e && e.covers && e.covers.includes(sid) ? e : null;
  const own = states[sid] || null;
  if (ent && own) return String(own.updated) > String(ent.updated) ? { t: own, via: 'signal' } : { t: ent, via: 'entity' };
  return ent ? { t: ent, via: 'entity' } : own ? { t: own, via: 'signal' } : null;
}

// applyTriage adds each signal's triage (state, note, when, by whom, and
// whether it is its entity's - triaged_via) and the suppression rule
// hiding it, if any (decisionOf).
function applyTriage(rows, doc) {
  const rules = (doc && doc.suppressions) || [];
  return rows.map((s) => {
    const d = decisionOf(doc, s.eid, s.sid);
    const t = d && d.t;
    const rule = rules.find((r) => suppressionMatches(r, s));
    return {
      ...s, triage: t ? t.state : 'new', note: t ? t.note || '' : '', triaged_at: t ? t.updated || '' : '', triaged_by: t ? t.by || '' : '',
      triaged_via: d ? d.via : '', suppressed_by: rule ? rule.id : '',
    };
  });
}

const isOpen = (s) => !s.suppressed_by && s.triage !== 'benign';

module.exports = { TRIAGE_STATES, SUPPRESSION_OPS, SIGNAL_FIELDS, applyTriage, decisionOf, isOpen };
