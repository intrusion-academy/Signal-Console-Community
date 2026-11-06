// Signals (the Signals, Overview and Hosts pages).
//
// A signal is one rule match: every event a rule matched is a signal of its
// own, rather than one finding per rule holding its events as "instances" -
// so signals can be filtered, grouped, counted and triaged like any other
// row. Every finding is a signal (critical to low): a host's context is in
// its modules' KPIs and telemetry, not here (Signal schema 10).
//
// A finding carries its matched events as Observations, capped per rule.
// Where a rule matched more, the module's rule_matches dataset lists every
// distinct value it matched with a count; each value not fully covered by
// the captured events becomes one more signal carrying that value, its
// remaining count and its time range, so nothing a rule matched is left
// out. A finding with no events at all - a state of the host, such as a
// small log - is one signal.
//
// Everything here reads the output contract's generic fields - an
// observation's time, entity, context and value - never a module's own
// field names.
//
// Every signal has a stable ID (sid) computed from what it is - host name,
// rule, and the signal's name (its value: what its matches have in common)
// - never from the run it was imported with, so a signal keeps its triage
// when the host is collected again, however many matches it has gained.
'use strict';

const crypto = require('crypto');
const { hostMeta } = require('./hosts');
const { OBSERVED } = require('../legacy');

// SEVERITY_RANK gives severities a sort order (most urgent first).
const SEVERITY_RANK = { critical: -1, high: 0, medium: 1, low: 2 };

// signalId is a signal's stable ID: a short hash of what identifies it.
const signalId = (...parts) => crypto.createHash('sha1').update(parts.join('\u0000')).digest('hex').slice(0, 16);

// tacticsOf lists the ATT&CK tactics of a finding's techniques (a technique
// under several tactics names them joined by ", ").
function tacticsOf(attack) {
  return [...new Set((attack || []).flatMap((a) => String(a.tactic || '').split(', ').filter(Boolean)))];
}

// datasetObjects returns a result's dataset `name` as objects keyed by
// column name (an empty list when the result has no such dataset).
function datasetObjects(result, name) {
  const ds = (result.datasets || []).find((d) => d.name === name);
  return ds ? ds.rows.map((r) => Object.fromEntries(ds.columns.map((c, i) => [c, r[i]]))) : [];
}

// sharedEvidence is the evidence label its events share, or '' when they
// differ or carry none - what a signal built from several events (a rule's
// uncaptured matches) says about its evidence.
function sharedEvidence(events) {
  const labels = [...new Set(events.map((e) => e.evidence))];
  return labels.length === 1 ? labels[0] : '';
}

// eventsOf lists a finding's captured events. Each carries its source
// (schema 5): its evidence type - the label, e.g. "process creation
// (historical)", in `evidence` - and where it was read (`source`); and any
// other evidence of the same instance (`corroborated_by`, schema 7).
// An observation is one signal (schema 16): every match of its rule with
// the same coalesce key - its earliest match described in full, how many
// matches it stands for, their time span, and what differed among them. A
// run before schema 16 had one observation per match: count 1, its time.
// time_from (schema 21) makes the time the end of a range the event
// happened in - its own time is not recorded (a typed PowerShell command).
function eventsOf(f) {
  return (f.observations || []).map((o) => ({
    kind: 'event', time: o.last || o.time || '', time_from: o.time_from || '', time_is: o.time_is || '', as_of: Boolean(o.as_of), anchor: o.anchor || null, entity: String(o.entity || ''), context: o.context || '', value: o.value || '',
    count: o.count || 1, first_seen: o.first || o.time || '', last_seen: o.last || o.time || '',
    distinct: o.distinct || 0, distinct_more: Boolean(o.distinct_more), variants: o.variants || [],
    subject: o.subject || null, related: o.related || [], occurrences: o.occurrences || [],
    fields: o.fields || {}, enrichment: o.enrichment || null,
    evidence: o.source ? o.source.label : '', source: o.source || null, corroborated_by: o.corroborated_by || [],
    shadow_copy_matches: o.shadow_copy_matches || 0, from_shadow_copy: o.from_shadow_copy || '', approved: o.approved || '',
    // A signal's own title, naming what it matched, and the profile's context for it (schema 60).
    ...(o.title ? { title: o.title } : {}), profile_context: o.profile_context || '',
  }));
}

// uncapturedValues lists, for a rule, the matched values (from the
// complete rule_matches dataset) that its findings' captured events do not
// already show, with how many matches each stands for. A rule over several
// evidence types has one finding per type (schema 6), so the captured
// events are those of all its findings. A value's evidence is the type
// rule_matches names (schema 22, labelled from the run's sources), else
// the type its rule's captured events share.
function uncapturedValues(ruleId, findings, ruleMatches, sources = new Map()) {
  const events = findings.filter((f) => f.rule_id === ruleId).flatMap(eventsOf);
  const captured = new Map();
  for (const e of events) if (e.value) captured.set(e.value, (captured.get(e.value) || 0) + e.count);
  const evidence = sharedEvidence(events);
  const values = [];
  for (const m of ruleMatches.filter((r) => r.rule_id === ruleId)) {
    const rest = (m.count || 0) - (captured.get(m.value) || 0);
    if (rest > 0) values.push({ kind: 'value', time: m.last_seen || '', entity: String(m.value), context: '', value: String(m.value), count: rest, first_seen: m.first_seen || '', last_seen: m.last_seen || '', fields: {}, enrichment: null, evidence: (sources.get(m.evidence) || {}).label || m.evidence || evidence, source: null,
      time_is: "first and last match (the rule's list of matches)", as_of: (sources.get(m.evidence) || {}).kind === 'state', anchor: null, shadow_copy_matches: Math.min(m.shadow_copy_matches || 0, rest) });
  }
  return values;
}

// entityTriageId is the stable ID of an entity on a host - its triage key,
// beside the signals' own (signalId): the host's name, its type and key.
const entityTriageId = (host, type, key) => signalId(host, 'entity', type, key);

// entityOfSignals maps a run's signals - by rule and name - to the entity
// Signal grouped them under (schema 17): its type, key and display, and
// the other entities the signal names, an account by its SID (schema 28).
function entityOfSignals(run) {
  const out = new Map();
  for (const e of run.entities || []) {
    for (const x of e.signals || []) out.set(`${x.rule_id}\u0000${x.value}`, { type: e.type, key: e.key, display: e.display, related: x.related || [] });
  }
  return out;
}

// validSigner is a program's signer when its facts say its signature is
// valid (schema 28) - what a suppression rule's "signer" condition tests.
function validSigner(facts) {
  const sig = facts && facts.facts.find((f) => f.label === 'Signature');
  const signer = facts && facts.facts.find((f) => f.label === 'Signer');
  return sig && sig.tone === 'ok' && signer ? signer.value : '';
}

// runSignals lists every signal of one run (unordered). Each row carries its
// stable ID (sid), its host's run_id/host/os/os_build/role (what a host link
// shows), its finding's rule, severity and text (title, detail, impact,
// focus), ATT&CK techniques and tactics, the finding's evidence, and the
// event itself - or, for a finding with no event (a state of the host), none.
function runSignals(run) {
  const out = [];
  const host = { run_id: run.run_id, ...hostMeta(run) };
  const entityOf = entityOfSignals(run);
  const factsOf = new Map((run.entity_facts || []).map((f) => [`${f.type}:${f.key}`, f]));
  // about is a signal's entity, as the run's entities name it: its ID
  // (type:key), triage ID, display, the entities it names, and its
  // program's valid signer. A signal Signal grouped under no entity - a
  // state of the host (its log too small), an older run - is about the host
  // itself, so every signal has one entity to be investigated under.
  const about = (ruleId, value) => {
    const e = entityOf.get(`${ruleId}\u0000${value}`);
    if (!e) {
      const key = host.host.toLowerCase();
      return { entity_id: `host:${key}`, eid: entityTriageId(host.host, 'host', key), entity_type: 'host', entity_display: host.host, entity_related: [], signer: '' };
    }
    const id = `${e.type}:${e.key}`;
    return { entity_id: id, eid: entityTriageId(host.host, e.type, e.key), entity_type: e.type, entity_display: e.display, entity_related: e.related, signer: validSigner(factsOf.get(id)) };
  };
  for (const [module, result] of Object.entries(run.modules || {})) {
    const ruleMatches = datasetObjects(result, 'rule_matches');
    const valuesShown = new Set(); // rules whose uncaptured values are already listed (once per rule, with its first finding)
    // What each rule's matches share to be one signal: its coalesce fields
    // (none: the subject entity, or the match's value) - schema 16.
    const coalesceOf = new Map((result.rule_catalog || []).map((r) => [r.id, r.coalesce || []]));
    for (const f of result.findings || []) {
      const tactics = tacticsOf(f.attack);
      const base = {
        ...host, module, rule_id: f.rule_id || '', severity: f.severity, title: f.title,
        // rule_title: the finding's title, for its rule - a signal's own title
        // (schema 60) names what it matched, so a list per rule never uses it.
        rule_title: f.title,
        detail: f.detail || '', impact: f.impact || '', focus: f.focus || '',
        tags: f.tags || [], attack: f.attack || [], tactics, tactic: tactics.join('; '), evidence: f.evidence || {},
        rule_count: f.evidence && typeof f.evidence.count === 'number' ? f.evidence.count : null,
        coalesce: coalesceOf.get(f.rule_id) || [],
      };
      const matches = eventsOf(f);
      if (!valuesShown.has(base.rule_id)) {
        valuesShown.add(base.rule_id);
        matches.push(...uncapturedValues(base.rule_id, result.findings, ruleMatches, new Map((run.sources || []).map((x) => [x.evidence, x]))));
      }
      if (matches.length === 0) {
        const row = { kind: 'state', time: f.time || '', time_is: OBSERVED, as_of: true, anchor: null, entity: '', context: '', count: 1, fields: {}, enrichment: null, evidence: '', source: null };
        out.push({ ...base, ...row, ...about(base.rule_id, null), sid: signalId(host.host, base.rule_id), id: `${run.run_id}/${base.rule_id}` });
        continue;
      }
      const seen = new Map(); // two signals of one rule with one name (one per evidence type) are told apart by their order
      matches.forEach((s, i) => {
        // A signal is its rule's matches with one coalesce key, named by its
        // value: the same signal in every collection of the host, however
        // many matches it gains (schema 16).
        const key = [host.host, base.rule_id, s.value || s.entity].join('\u0000');
        const n = (seen.get(key) || 0) + 1;
        seen.set(key, n);
        out.push({ ...base, ...s, ...about(base.rule_id, s.value), sid: signalId(key, n), id: `${run.run_id}/${base.rule_id}/${i}` });
      });
    }
  }
  return out;
}

// signals lists every signal of the given runs, most severe first, then
// newest first.
function signals(runs) {
  return runs.flatMap(runSignals).sort(compareSignals);
}

// compareSignals orders signals most severe first, then newest first.
function compareSignals(a, b) {
  return (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || String(b.time).localeCompare(String(a.time));
}

// severityCounts counts signals by severity, every severity present.
function severityCounts(rows) {
  const counts = Object.fromEntries(Object.keys(SEVERITY_RANK).map((s) => [s, 0]));
  for (const r of rows) if (r.severity in counts) counts[r.severity]++;
  return counts;
}

module.exports = { SEVERITY_RANK, signals, runSignals, compareSignals, severityCounts, tacticsOf, datasetObjects, entityTriageId };
