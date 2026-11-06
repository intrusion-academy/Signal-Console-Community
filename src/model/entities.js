// Entities: what the signals are about - a program, an account, a log, a
// task... or the host itself - the one list the Signals page shows, and
// each entity's page, which holds everything about it: what Signal read of
// it (its facts, schema 28), every signal about it in full, the signals it
// is named in, its related entities, and its triage as a whole
// (Signal's entities documentation).
//
// Signal groups each host's signals by their subject entity (the run's
// `entities`: type, normalised key, display, related, caveats) and reads
// every entity's facts once (`entity_facts`). Here every signal knows its
// entity (model/signals.js - a signal grouped under none is about the
// host), so the list is the signals grouped by host and entity: one row
// per entity on a host, with its rules, counts and triage. Related
// entities are linked, never merged: grouping through them would chain
// everything on a host through SYSTEM or explorer.exe.
//
// An entity is triaged per host, as a whole: the decision covers the
// signals it had then (model/triage.js applies it to them); a signal that
// appears later is open, and the entity counts it as new since triage.
'use strict';

const { isOpen, decisionOf } = require('./triage');
const { SEVERITY_RANK, entityTriageId } = require('./signals');

// entityId is an entity's URL-safe identity: its type and normalised key.
const entityId = (type, key) => `${type}:${key}`;

// splitId is an entity ID's type and key (a key may hold colons).
function splitId(id) {
  const i = String(id).indexOf(':');
  return i < 0 ? { type: '', key: '' } : { type: id.slice(0, i), key: id.slice(i + 1) };
}

// nodeId is an entity's identity across hosts: its ID, except an account
// known by name alone, which is one host's (a local account's SID already
// differs by host; a name alone never proves the same account elsewhere -
// Signal's entity model).
const nodeId = (id, runId) => (String(id).startsWith('account:name:') ? `${id}@${runId}` : id);

const hostOf = (run) => ({ run_id: run.run_id, host: (run.host && run.host.hostname) || '' });

// worst is the most severe severity of signals, '' for none.
const worst = (list) => list.reduce((best, s) => ((SEVERITY_RANK[s.severity] ?? 9) < (SEVERITY_RANK[best] ?? 9) ? s.severity : best), '');

// entityTriage is the analysts' decisions about an entity on a host, from
// those its signals stand under (decisionOf - the entity's as a whole, or
// a signal's own): its state - the one state when all agree, escalated
// when any is, else open -, the latest decision's note, time and author,
// whether its signals were decided differently (mixed), how many were
// decided (covers_n) and how many not (new_n: none decided is plain open).
function entityTriage(doc, eid, sids) {
  const decided = sids.map((sid) => decisionOf(doc, eid, sid)).filter(Boolean).map((d) => d.t);
  if (!decided.length) return { state: 'new', note: '', at: '', by: '', covers_n: 0, new_n: 0, mixed: false };
  const states = new Set(decided.map((t) => t.state));
  const latest = decided.reduce((a, b) => (String(b.updated) > String(a.updated) ? b : a));
  const new_n = sids.length - decided.length;
  const state = states.size === 1 && !new_n ? latest.state : states.has('escalated') ? 'escalated' : states.size === 1 ? latest.state : 'new';
  return { state, note: latest.note || '', at: latest.updated || '', by: latest.by || '', covers_n: decided.length, new_n, mixed: states.size > 1 };
}

// fleetCounts maps each entity to how many hosts' latest collections have
// signals about it - 1 is one host alone, what stands out in a fleet.
function fleetCounts(latestSignals) {
  const hosts = new Map();
  for (const s of latestSignals) {
    const id = nodeId(s.entity_id, s.run_id);
    if (!hosts.has(id)) hosts.set(id, new Set());
    hosts.get(id).add(s.run_id);
  }
  return new Map([...hosts].map(([id, set]) => [id, set.size]));
}

// relatedOf is the entities a group's signals name, each once, with what
// they are to the group's entity (roles, schema 52) and the rules whose
// signals name them - the graph's lines and their labels.
function relatedOf(list) {
  const out = new Map();
  for (const s of list) {
    for (const r of s.entity_related || []) {
      const id = entityId(r.type, r.key);
      if (!out.has(id)) out.set(id, { id, node: nodeId(id, s.run_id), type: r.type, display: r.display, roles: [], rules: [] });
      const x = out.get(id);
      // a signal's related entity has its one role (schema 52)
      if (r.role && !x.roles.includes(r.role)) x.roles.push(r.role);
      if (!x.rules.includes(s.rule_id)) x.rules.push(s.rule_id);
    }
  }
  return [...out.values()];
}

// entityList is the Signals page's list: the given (filtered) signals
// grouped by host and entity - one row each, with its severity (of its open
// signals, else of all), its rules with their matches, its triage as a
// whole, how many hosts share it (fleet), its caveats and the entities its
// signals name (related - the Signals page's graph). allOf(run_id) is
// a run's every signal (the triage covers them, not only those shown),
// runOf(run_id) the run.
function entityList(signals, allOf, runOf, doc, fleet) {
  const groups = new Map();
  for (const s of signals) {
    const k = `${s.run_id}\u0000${s.entity_id}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(s);
  }
  const rows = [...groups.values()].map((list) => {
    const s0 = list[0];
    const run = runOf(s0.run_id) || {};
    const { type, key } = splitId(s0.entity_id);
    const subject = (run.entities || []).find((e) => e.type === type && e.key === key);
    const open = list.filter(isOpen);
    const rules = new Map();
    for (const s of list) {
      const r = rules.get(s.rule_id) || { rule_id: s.rule_id, title: s.rule_title || s.title, severity: s.severity, count: 0, open: false };
      r.count += s.count || 1;
      r.open = r.open || isOpen(s);
      rules.set(s.rule_id, r);
    }
    const times = list.flatMap((s) => [s.first_seen || s.time, s.last_seen || s.time]).filter(Boolean).sort();
    const triage = entityTriage(doc, s0.eid, allOf(s0.run_id).filter((s) => s.entity_id === s0.entity_id).map((s) => s.sid));
    return {
      key: `${s0.run_id}/${s0.entity_id}`, id: s0.entity_id, node: nodeId(s0.entity_id, s0.run_id), type: s0.entity_type, display: s0.entity_display,
      run_id: s0.run_id, host: s0.host, os: s0.os, os_build: s0.os_build, role: s0.role,
      severity: worst(open) || worst(list), open_n: open.length, signals_n: list.length,
      matches: list.reduce((n, s) => n + (s.count || 1), 0),
      rules: [...rules.values()].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || b.count - a.count),
      rules_text: [...rules.keys()].sort().join('; '), modules: [...new Set(list.map((s) => s.module))].sort(),
      first_seen: times[0] || '', last_seen: times[times.length - 1] || '', is_new: list.some((s) => s.is_new),
      fleet_n: fleet.get(nodeId(s0.entity_id, s0.run_id)) || 0, caveats_n: subject && subject.caveats ? subject.caveats.length : 0,
      triage: triage.state === 'new' || triage.new_n ? 'new' : triage.state, new_n: triage.new_n,
      related: relatedOf(list),
    };
  });
  return rows.sort((a, b) => (b.open_n > 0) - (a.open_n > 0) || (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
    || a.fleet_n - b.fleet_n || String(b.last_seen).localeCompare(String(a.last_seen)));
}

// listSummary is the numbers of the list: entities by severity (of those
// with open signals), untriaged, on one host only, hosts.
function listSummary(rows) {
  const bySeverity = Object.fromEntries(Object.keys(SEVERITY_RANK).map((s) => [s, rows.filter((r) => r.open_n > 0 && r.severity === s).length]));
  return { by_severity: bySeverity, untriaged: rows.filter((r) => r.triage === 'new').length, rare: rows.filter((r) => r.fleet_n === 1).length,
    hosts: new Set(rows.map((r) => r.run_id)).size, modules: [...new Set(rows.flatMap((r) => r.modules))].sort() };
}

// names reports whether a signal names the entity {type, key} without
// being about it: one of the entities its earliest match names.
const names = (s, type, key) => s.entity_id !== entityId(type, key) && (s.entity_related || []).some((r) => r.type === type && r.key === key);

// hostFacts are the host's own facts, from the run: what it is and how it
// was collected - the facts of the host entity.
function hostFacts(run) {
  const h = run.host || {};
  const src = 'Signal (the host, at collection)';
  const facts = [['Name', h.hostname], ['Machine ID', h.machine_id], ['Operating system', [h.os, h.os_build && `build ${h.os_build}`].filter(Boolean).join(', ')],
    ['Installation', h.installation_type], ['Domain', h.user_domain], ['Time zone', h.timezone], ['Collected', run.started, 'time'], ['Signal version', run.tool_version]]
    .filter(([, v]) => v).map(([label, value, kind]) => ({ label, value: String(value), kind: kind || '', tone: '', source: src }));
  return { facts, gaps: [] };
}

// entityPage is one entity on one host, for its page: the host is runId
// when given (any collection), else the latest collection where it has the
// most open signals; with its facts, its signals and the signals it is
// only named in (their sids, and as timeline lanes), its related entities,
// caveats, triage, and the other hosts whose latest collections know it.
// Null when no collection knows it.
function entityPage(latest, runOf, signalsOf, doc, id, runId) {
  const { type, key } = splitId(id);
  const knows = (r) => signalsOf(r.run_id).some((s) => s.entity_id === id || names(s, type, key)) || (r.entity_facts || []).some((f) => f.type === type && f.key === key);
  const knowing = latest.filter(knows);
  const openOf = (r) => signalsOf(r.run_id).filter((s) => s.entity_id === id && isOpen(s)).length;
  const run = runId ? runOf(runId) : knowing.slice().sort((a, b) => openOf(b) - openOf(a))[0];
  if (!run) return null;
  const signals = signalsOf(run.run_id);
  const subject = (run.entities || []).find((e) => e.type === type && e.key === key) || null;
  const facts = type === 'host' ? hostFacts(run) : (run.entity_facts || []).find((f) => f.type === type && f.key === key) || null;
  const own = signals.filter((s) => s.entity_id === id);
  const named = signals.filter((s) => names(s, type, key));
  const pages = new Set([...(run.entities || []).map((e) => entityId(e.type, e.key)), ...(run.entity_facts || []).map((f) => entityId(f.type, f.key))]);
  const display = (own[0] && own[0].entity_display) || (facts && facts.display) || ((named[0] && named[0].entity_related.find((r) => r.type === type && r.key === key)) || {}).display || key;
  const host = hostOf(run);
  const eid = entityTriageId(host.host, type, key);
  const times = own.flatMap((s) => [s.first_seen || s.time, s.last_seen || s.time]).filter(Boolean).sort();
  return {
    id, type, key, display, ...host, latest: latest.includes(run),
    severity: worst(own.filter(isOpen)), first_seen: times[0] || '', last_seen: times[times.length - 1] || '',
    matches: own.reduce((n, s) => n + (s.count || 1), 0),
    facts: facts ? { facts: facts.facts || [], gaps: facts.gaps || [] } : null,
    sids: own.map((s) => s.sid), named_sids: named.map((s) => s.sid), open_n: own.filter(isOpen).length,
    related: ((subject && subject.related) || []).map((r) => ({ ...r, id: entityId(r.type, r.key), has_page: pages.has(entityId(r.type, r.key)) })),
    related_more: Boolean(subject && subject.related_more),
    caveats: (subject && subject.caveats) || [],
    triage: { eid, ...entityTriage(doc, eid, own.map((s) => s.sid)) },
    other_hosts: knowing.filter((r) => r !== run && nodeId(id, r.run_id) === id).map(hostOf),
  };
}

// entityFacts is the facts of the given entities in one run, by ID - what
// the entity page shows of its related entities.
function entityFacts(run, ids) {
  const wanted = new Set(ids);
  const out = {};
  for (const f of run.entity_facts || []) {
    const id = entityId(f.type, f.key);
    if (wanted.has(id)) out[id] = { id, type: f.type, display: f.display, facts: f.facts || [], gaps: f.gaps || [] };
  }
  return out;
}

// findEntities is the finder's answer (GET /api/entities/find): every
// entity the hosts' latest collections know - the subjects of signals, the
// entities their signals name, and those Signal read facts about - whose
// name, key or one of whose facts (a SHA-256, a path, a signer...) contains
// text, case-insensitively: "where else is this hash, this account, this
// address?". One row per entity: the hosts where it matches, how many of
// them have signals about it (subject_n), and what matched. Those with
// signals first, then on the most hosts; at most limit rows (more: there
// were others). Text under 3 characters finds nothing.
function findEntities(latest, text, limit = 50) {
  const q = String(text || '').trim().toLowerCase();
  if (q.length < 3) return { rows: [], more: false };
  const has = (v) => String(v || '').toLowerCase().includes(q);
  const found = new Map();
  for (const run of latest) {
    const subjects = new Set((run.entities || []).map((e) => entityId(e.type, e.key)));
    const add = (type, key, display, matched) => {
      const id = entityId(type, key);
      const row = found.get(id) || { id, type, display, matched: [], hosts: [], subject_n: 0 };
      found.set(id, row);
      if (!row.matched.includes(matched)) row.matched.push(matched);
      if (row.hosts.some((x) => x.run_id === run.run_id)) return;
      row.hosts.push({ ...hostOf(run), subject: subjects.has(id) });
      if (subjects.has(id)) row.subject_n++;
    };
    for (const e of run.entities || []) {
      if (has(e.display) || has(e.key)) add(e.type, e.key, e.display, 'name');
      for (const r of e.related || []) if (has(r.display) || has(r.key)) add(r.type, r.key, r.display, 'name');
    }
    for (const f of run.entity_facts || []) {
      if (has(f.display) || has(f.key)) add(f.type, f.key, f.display, 'name');
      for (const x of f.facts || []) if (has(x.value)) add(f.type, f.key, f.display, x.label);
    }
  }
  const rows = [...found.values()].sort((a, b) => (b.subject_n > 0) - (a.subject_n > 0) || b.hosts.length - a.hosts.length || a.display.localeCompare(b.display));
  for (const r of rows) r.hosts.sort((a, b) => b.subject - a.subject || a.host.localeCompare(b.host));
  return { rows: rows.slice(0, limit), more: rows.length > limit };
}

module.exports = { entityList, listSummary, fleetCounts, entityPage, entityFacts, findEntities, entityId, splitId };
