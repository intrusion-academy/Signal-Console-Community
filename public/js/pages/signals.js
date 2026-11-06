// The Signals page: one list of what to look at - each entity (a program,
// an account, a log, a task... or the host itself) with the signals about
// it - and each entity's page, which holds everything about it on one page
// (Signal's entities documentation): its signals at a glance, the graph of it and
// what it is linked to, a timeline of every occurrence, every signal about
// it folded to one row and unfolding in place in full - its sources,
// process graph, command line, fields, occurrences - the signals it is
// only named in, what Signal read about it and its linked entities with
// their facts, and its triage as a whole. No signal opens anywhere else: a link to a
// signal (the host and user pages' tables, an old bookmark) opens its
// entity's page at that signal.
//
// The list's filters are the signals' (model/signalQuery.js): an entity is
// listed when any of its signals passes them. Filtering and grouping
// happen on the server (GET /api/entities).

import { h, fetchJSON, apiFetch, ts, mono, breakable, svgIcon, virusTotalLink, withTip } from '../dom.js';
import { pageLink, pageUrl, urlParams, setParams, queryString, render, openPage, rememberedHosts, rememberHosts, rememberState, rememberedState, linkClick } from '../router.js';
import {
  SEVERITY_RANK, ATTACK_TACTICS, NO_TACTIC, TRIAGE, TRIAGE_CHOICES, sevTag, triageTag, detailBlock, hostLink, hostLabels,
  section, filterBar, stickyPage, summaryStrip, severityItems, checkboxDropdown, selectionFromUrl,
  triageBlock, entityTriage, entityLink, entityIcon, factsCard, occurrenceTimeline, CORE, roleWords, quotedTitle,
  copyButton,
} from '../components.js';
import { dataTable, col } from '../table.js';
import { entityGraph } from '../graph.js';
import { canEdit } from '../session.js';

// SIGNAL_COLUMNS is the signal table (the host and user pages); a row opens
// its entity's page at that signal. A signal not in its host's previous
// collection is marked "new" by its title.
const SIGNAL_COLUMNS = [col('severity'), col('time'), col('host'), col('rule_id'),
  col('title', 'title', { render: (v, row) => h('span', {}, v, row.is_new ? h('span', { class: 'new-tag', title: 'Not in the host\'s previous collection' }, 'new') : null, shadowTag(row), approvedTag(row)) }),
  col('entity'), col('count', 'count', { label: 'Matches', desc: 'How many matches of the rule this signal stands for: every match with the same subject (or what the rule coalesces on) is one signal.' }),
  col('evidence'), col('fleet_n'), col('triage'), col('module')];

// SIGNAL_FIELD_LABELS name a signal's own columns a suppression condition
// can test; any other condition tests one of its event's fields, by name.
const SIGNAL_FIELD_LABELS = { rule_id: 'Rule', host: 'Host', entity: 'Entity', context: 'Context', evidence: 'Evidence', signer: 'Signer (valid signature)' };
const fieldLabel = (f) => SIGNAL_FIELD_LABELS[f] || f;
const SUPPRESSION_OPS = ['equals', 'contains', 'startswith', 'endswith'];

// suppressForm builds a suppression rule from a signal: candidate
// conditions prefilled from the signal - its rule, its context line's file
// name and its valid signer ticked; its entity, host and every field of its
// event offered - each editable, and a required note. The rule hides every
// signal matching all ticked conditions, on every host, now and in later
// collections.
function suppressForm(s, done) {
  const file = s.context && s.context.includes('\\') ? '\\' + s.context.split('\\').pop() : '';
  const candidates = [
    ['rule_id', 'equals', s.rule_id, true],
    ['context', 'endswith', file, Boolean(file)],
    ['signer', 'equals', s.signer || '', Boolean(s.signer)],
    ['entity', 'equals', s.entity || '', false],
    ...Object.entries(s.fields || {}).filter(([, v]) => typeof v === 'string').map(([k, v]) => [k, 'equals', v, false]),
    ['host', 'equals', s.host, false],
  ].filter(([, , value]) => value);
  const rows = candidates.map(([field, op, value, on]) => {
    const tick = h('input', { type: 'checkbox', checked: on ? 'checked' : null });
    const opSel = h('select', {}, SUPPRESSION_OPS.map((o) => h('option', { value: o, selected: o === op ? 'selected' : null }, o)));
    const val = h('input', { type: 'text', class: 'cond-value', value });
    return { field, tick, opSel, val, el: h('div', { class: 'cond-row' }, tick, h('span', { class: 'cond-field' }, fieldLabel(field)), opSel, val) };
  });
  const note = h('input', { type: 'text', class: 'cond-note', placeholder: 'Why these signals are not worth attention (required)' });
  const status = h('span', { class: 'mut' });
  const create = async () => {
    const conditions = rows.filter((r) => r.tick.checked).map((r) => ({ field: r.field, op: r.opSel.value, value: r.val.value }));
    try {
      await fetchJSON('/api/signals/suppressions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ conditions, note: note.value }) });
      done();
    } catch (err) {
      status.textContent = /needs a note/.test(err.message) ? 'Write a note saying why.' : /condition/.test(err.message) ? 'Tick at least one condition with a value.' : err.message;
    }
  };
  return h('div', { class: 'suppress-form', onclick: (e) => e.stopPropagation() },
    h('div', { class: 'mut' }, 'Hide every signal matching all ticked conditions - on every host, now and in later collections:'),
    rows.map((r) => r.el), note, h('div', { class: 'row' }, h('button', { class: 'btn', onclick: create }, 'Create suppression rule'), status));
}

// CODE_FIELDS are shown whole, each in its own card: what ran, as text.
const CODE_FIELDS = [
  ['process.command_line', 'Command line'], ['powershell.script_text', 'Script / command'],
  ['powershell.host_application', 'Started by'], ['persist.command', 'Command'],
];

// FIELD_ROWS name and order the fields of a signal's details table: label,
// how its value reads (mono for machine text), and when it calls for a look
// (orange; red for 'bad'). A field not listed is a row under its own name,
// after these.
const FIELD_ROWS = [
  ['process.name', 'Program', 'mono'], ['process.parent_name', 'Parent', 'mono'],
  ['process.user', 'Account'], ['process.run_as', 'Runs as'], ['process.user_sid', 'Account SID', 'mono'],
  ['account.name', 'Account'], ['account.sid', 'Account SID', 'mono'], ['account.kind', 'Account kind'], ['account.scope', 'Account scope'],
  ['log.subject', 'Acted'], ['log.subject_sid', 'Acted (SID)', 'mono'], ['log.target', 'Target'], ['log.target_sid', 'Target (SID)', 'mono'],
  ['process.pid', 'PID', 'mono'], ['process.parent_pid', 'Parent PID', 'mono'], ['process.logon_id', 'Logon session', 'mono'],
  ['process.integrity_level', 'Integrity', '', (v) => /high|system/.test(v)],
  ['process.token_elevation', 'Token', '', (v) => /full/.test(v)],
  ['process.start_time', 'Started', 'time'],
  ['source.ip', 'Source address', 'mono', (v, f) => f['source.ip_scope'] === 'public'], ['source.ip_scope', 'Address scope'], ['source.workstation', 'Source computer'],
  ['logon.type_name', 'Logon type'], ['service.name', 'Service'], ['service.image_path', 'Image path', 'mono'], ['task.path', 'Task', 'mono'],
  ['av.threat', 'Threat', '', () => true, 'bad'], ['av.path', 'Detected file', 'mono'],
  ['run.source', 'Recorded by'], ['run.count', 'Runs counted'], ['run.time', 'Ran', 'time'],
  ['powershell.flagged', 'Flagged by PowerShell', '', (v) => v === 'true'], ['powershell.script_path', 'Script file', 'mono'], ['powershell.script_block_id', 'Script block ID', 'mono'],
  ['powershell.history_file', 'History file', 'mono'], ['powershell.history_created', 'History file created', 'time'], ['powershell.history_written', 'History file last written', 'time'],
  ['powershell.engine_version', 'Engine version', '', (v) => /^2\./.test(v)], ['powershell.host_name', 'PowerShell host'],
];

const base = (p) => String(p || '').split('\\').pop();

// FIELD_ICONS give a field's title the icon of what it is about, the first
// that fits: an account, a time, a program or script, the web, a file, the
// network, persistence, protection, a log, the directory, remote access.
const FIELD_ICONS = [
  [/(^|\.)(user|account|subject|target|owner|actor|member|run_as|sid)|_sid$|\.user_|account\./, 'user'],
  [/time|_at$|created|modified|installed|started|first|last|written|registered|\.when$|\.ended$/, 'clock'],
  [/^(process|powershell|run|wmi)\./, 'terminal'],
  [/^(browser|visit|download|extension|domain|site)\./, 'globe'],
  [/^(file|sysvol)\.|path$|\.folder$/, 'file'],
  [/^(source|net|winrm|rdp|session|logon)\.|address|\.ip/, 'topology'],
  [/^(service|task|persist|bits)\./, 'plug'],
  [/^(av|protection|amsi)\./, 'shield'],
  [/^(log|clock)\./, 'dataset'],
  [/^(gpo|setting|directory|auth)\./, 'policy'],
  [/^(remote|transfer)\./, 'remote'],
  [/^web\./, 'webserver'],
];
const fieldIcon = (k) => (FIELD_ICONS.find(([re]) => re.test(k)) || [null, 'details'])[1];

// detailsTable is every field of the signal's event, one row each like the
// host's Identity card - each hash its own row, linked to VirusTotal; each
// title with its kind's icon, on one line (the values wrap). For a signal
// of several matches (s) it says which fields every match shares - the
// rule's coalesce fields, else its subject - and that the rest are its
// first match's; a time that is its first match's own is left out (each
// match's time and record are under Every occurrence).
function detailsTable(f, skip, s) {
  const known = new Map(FIELD_ROWS.map((r) => [r[0], r]));
  const order = [...FIELD_ROWS.map((r) => r[0]).filter((k) => k in f), ...Object.keys(f).filter((k) => !known.has(k)).sort()];
  const many = s && s.count > 1;
  const firstAt = many ? ts(s.first_seen || s.time) : '';
  const rows = [];
  for (const k of order) {
    const v = f[k];
    if (skip.has(k) || v === '' || v == null) continue;
    if (many && /^\d{4}-\d\d-\d\dT/.test(String(v)) && ts(String(v)) === firstAt) continue; // the first match's own time: per occurrence
    if (k === 'process.hashes') {
      for (const part of String(v).split(',')) {
        const [type, hash] = part.trim().split('=');
        if (hash) rows.push({ k, label: type, v: virusTotalLink(type, hash) });
      }
      continue;
    }
    const [, label = k, how = '', alarm, level] = known.get(k) || [];
    const text = String(v);
    const hot = alarm && alarm(text.toLowerCase(), f) ? (level === 'bad' ? 'sig-bad' : 'sig-attn') : '';
    const shown = how === 'time' ? ts(text) : how === 'mono' ? breakable(text) : text;
    rows.push({ k, label, v: h('span', { class: [how === 'mono' ? 'mono' : '', hot].filter(Boolean).join(' ') || null }, shown) });
  }
  if (!rows.length) return null;
  const tr = (r) => h('tr', {}, h('td', { class: 'mut sig-field-k' }, svgIcon(fieldIcon(r.k)), r.label), h('td', {}, r.v));
  const sub = (text, hint) => h('tr', { class: 'sig-table-sub' }, h('td', { colspan: '2' }, h('div', {}, text), hint ? h('div', { class: 'mut sig-small' }, hint) : null));
  if (!many) return h('div', { class: 'card facts sig-table' }, h('table', {}, rows.map(tr)));
  const keys = new Set(s.coalesce || []);
  const shared = rows.filter((r) => keys.has(r.k));
  const rest = rows.filter((r) => !keys.has(r.k));
  const n = s.count.toLocaleString();
  return h('div', { class: 'card facts sig-table' }, h('table', {},
    shared.length
      ? [sub(`Shared by all ${n} matches - what makes them one signal`, 'The rule joins its matches that have the same values in these fields.'), ...shared.map(tr)]
      : [sub(`Shared by all ${n} matches - what makes them one signal: they are about the same ${s.entity_type}`, s.entity_display)],
    rest.length ? [sub('Of its first match', `Recorded when the first of the ${n} matches happened; a later match may differ here. Each match's own time and record are under Every occurrence below.`), ...rest.map(tr)] : []));
}

// chain is the process and its parent, as a graph: each node its program,
// its folder, its PID and - where the evidence names it - its account.
// 4688's subject is the account that created the process (the parent's);
// the process runs as it unless run_as says otherwise.
function chain(s, f) {
  if (!f['process.name'] || !f['process.parent_name']) return null;
  const fromSecurity = s.source && s.source.channel === 'Security';
  const node = (path, role, pid, account, hot) => h('div', { class: 'sig-node' + (hot ? ' hot' : '') },
    h('div', { class: 'sig-node-role' }, svgIcon(hot ? 'terminal' : 'layers'), role),
    h('div', { class: 'sig-node-name mono' }, base(path)),
    h('div', { class: 'sig-node-path mono' }, breakable(String(path).slice(0, String(path).length - base(path).length))),
    h('div', { class: 'sig-node-meta' },
      h('span', {}, h('span', { class: 'mut' }, hot ? 'PID ' : 'Parent PID '), pid ?? '—'),
      h('span', {}, svgIcon('user'), account || h('span', { class: 'mut' }, 'not recorded'))));
  return h('div', { class: 'sig-graph' },
    node(f['process.parent_name'], 'Parent', f['process.parent_pid'], fromSecurity ? f['process.user'] : '', false),
    h('div', { class: 'sig-edge' }, h('span', {}, 'started')),
    node(f['process.name'], 'Process', f['process.pid'], f['process.run_as'] || f['process.user'], true));
}

// shadowTag marks a signal read, in all or part, from a shadow copy only
// (signal live -shadow): the host no longer holds those records.
const shadowTag = (s) => (s.shadow_copy_matches ? h('span', { class: 'shadow-tag', title: s.from_shadow_copy || 'Read from a shadow copy only: the host itself no longer holds these records.' },
  s.shadow_copy_matches === s.count ? 'shadow copy' : `${s.shadow_copy_matches} from a shadow copy`) : null);

// approvedTag marks a signal about an element of the run profile's
// baseline: the organisation approves it - Signal's sentence on hover. The
// signal stays open: approval is not proof it is benign.
const approvedTag = (s) => (s.approved ? h('span', { class: 'approved-tag', title: s.approved }, 'approved') : null);

// shadowNote says, at the top of a signal, that its records come from a
// shadow copy - what the host no longer holds - in Signal's own words.
const shadowNote = (s) => (s.from_shadow_copy ? h('div', { class: 'sig-shadow' }, h('div', { class: 'sig-source-k' }, svgIcon('snapshot'), 'From a shadow copy'), h('div', {}, s.from_shadow_copy)) : null);

// timeLines say, on a signal's main source card, what its time is and -
// for a state observed as Signal read the host - the time Windows recorded
// about it that places it, with what that time is (Signal schema 59).
const timeLines = (s) => [
  s.time_is ? h('div', { class: 'sig-small' }, h('span', { class: 'mut' }, 'Its time: '), `${ts(s.time)} - ${s.time_is}`) : null,
  s.as_of && s.anchor ? h('div', { class: 'sig-small' }, h('span', { class: 'mut' }, 'Placed by: '), `${ts(s.anchor.time)} - ${s.anchor.what}`,
    h('span', { class: 'mut' }, ' (what Windows recorded; it does not prove when it came to be, and can be altered)')) : null,
];

// sourceCards is one card per source that recorded the signal - its own
// and every other of the same thing - each saying what it is and exactly
// where it was read, to go back to it - after the profile's context for
// what it matched, when the profile gave one (schema 60).
function sourceCards(s) {
  const given = s.profile_context ? h('div', { class: 'sig-source main' },
    h('div', { class: 'sig-source-k' }, svgIcon('sliders'), 'Context from the profile'),
    h('div', { class: 'sig-source-v' }, s.profile_context),
    h('div', { class: 'mut sig-small' }, "What the analyst who wrote the run's profile said about this pivot point - their words, not Signal's.")) : null;
  const cards = recordedBy(s);
  if (given) cards.prepend(given);
  return cards;
}

// recordedBy is the source cards themselves.
function recordedBy(s) {
  const card = (p, main) => h('div', { class: 'sig-source' + (main ? ' main' : '') },
    h('div', { class: 'sig-source-k' }, svgIcon('dataset'), 'Recorded by'),
    h('div', { class: 'sig-source-v' }, p.label, ' ', p.shadow_copy ? pill(`shadow copy of ${p.shadow_copy.volume} made ${ts(p.shadow_copy.created)}`, 'attn')
      : pill(p.kind === 'state' ? 'now' : 'historical', p.kind === 'state' ? 'attn' : 'neutral')),
    h('div', { class: 'mono sig-small' }, breakable(p.description.startsWith(p.label + ' - ') ? p.description.slice(p.label.length + 3) : p.description)),
    main ? timeLines(s) : null);
  if (s.kind === 'state') return h('div', { class: 'sig-sources' }, h('div', { class: 'sig-source main' }, h('div', { class: 'sig-source-k' }, svgIcon('dataset'), 'Recorded by'), h('div', {}, 'the state of the host at collection'), timeLines(s)));
  if (!s.source) {
    return h('div', { class: 'sig-sources' }, h('div', { class: 'sig-source main' }, h('div', { class: 'sig-source-k' }, svgIcon('dataset'), 'Recorded by'),
      h('div', {}, s.evidence || 'not recorded'), timeLines(s), s.kind === 'value' ? h('div', { class: 'mut sig-small' }, 'Beyond the signals the run kept in full: its name, count and times come from the rule\'s complete list of matches.') : null));
  }
  return h('div', { class: 'sig-sources' }, card(s.source, true), ...(s.corroborated_by || []).map((p) => card(p, false)));
}

// OCCURRENCE_COLUMNS list a signal's occurrences: when, what it was (when
// the signal's matches differ - Signal schema 42), and the record.
const OCCURRENCE_COLUMNS = [
  col('time', 'time', {
    label: 'When', desc: 'When it happened (UTC) - "between" when its own time is not recorded - and what that time is.',
    render: (v, row) => h('span', {}, row.time_from ? `between ${ts(row.time_from)} and ${ts(v)}` : ts(v), row.time_is ? h('div', { class: 'mut sig-small' }, row.time_is) : null),
  }),
  col('entity', 'details', { label: 'What', desc: 'What this occurrence was - its own name and context, where the signal\'s matches differ (the threat and the file of each detection).',
    render: (v, row) => (v ? h('span', {}, mono(v), row.context ? h('span', { class: 'mut' }, ' · ', breakable(row.context)) : null) : '—') }),
  col('source', 'details', { label: 'Recorded in', desc: 'The record it was read from - the log, its event ID and record number - to go back to it.', render: (v) => (v ? mono(v) : '—') }),
];

// occurrences is a signal's matches over time: a mark per occurrence on a
// timeline and every one of them listed (Signal schema 28) - or, for a
// signal whose run kept no list, its first and last and how many; for a
// match whose own time is not recorded, its range.
function occurrences(s) {
  if (s.time_from && !(s.count > 1)) {
    return h('div', { class: 'sig-timeline' }, h('div', { class: 'sig-tl-bar range' }),
      h('div', { class: 'sig-tl-ends' }, h('span', {}, ts(s.time_from)), h('b', { class: 'sig-attn' }, 'its own time is not recorded'), h('span', {}, ts(s.time))));
  }
  if (!(s.count > 1)) return null;
  const list = s.occurrences || [];
  if (!list.length) {
    return h('div', { class: 'sig-timeline' }, h('div', { class: 'sig-tl-bar' }, h('i'), h('i')),
      h('div', { class: 'sig-tl-ends' }, h('span', {}, 'first ', ts(s.first_seen)), h('b', {}, `${s.count.toLocaleString()} matches`), h('span', {}, 'last ', ts(s.last_seen))));
  }
  return h('div', { class: 'sig-fact wide' },
    h('div', { class: 'sig-fact-k' }, svgIcon('clock'), `Every occurrence (${list.length.toLocaleString()})`),
    h('div', { class: 'mut sig-small' }, `This signal is ${list.length.toLocaleString()} matches of its rule that share what the table above says. Each is listed here with what differs between them: its own time and the record it was read from${list.some((o) => o.entity) ? ', and what it was where the matches name different things' : ''}.`),
    occurrenceTimeline([{ label: h('span', { class: 'mut' }, `${list.length.toLocaleString()} matches`), severity: s.severity, times: list }]),
    dataTable(list, list.some((o) => o.entity) ? OCCURRENCE_COLUMNS : OCCURRENCE_COLUMNS.filter((c) => c.key !== 'entity'), { height: 'scroll', filename: `occurrences-${s.rule_id.toLowerCase()}` }));
}

const sideCard = (title, icon, ...rows) => h('div', { class: 'sig-side-card' }, h('div', { class: 'sig-side-title' }, svgIcon(icon), title), ...rows.filter(Boolean));
const sideRow = (k, v) => h('div', { class: 'sig-side-row' }, h('span', { class: 'mut' }, k), v && v.nodeType ? v : h('span', {}, String(v ?? '—')));
const pill = (text, cls) => h('span', { class: 'sig-pill ' + cls }, text);

// processCard is what Signal checked of this process instance at
// collection - whether it is still running, and for one that is not, its
// exit as the Security log recorded it (4689) - or why it could not. What
// is known of its program is the program entity's facts.
function processCard(en) {
  const p = en && en.process;
  if (!p && !(en && en.gaps && en.gaps.length)) return null;
  return sideCard('This process', 'terminal',
    // This instance (its PID, at its start time) - the program may run again under another PID.
    p ? sideRow('Process', p.still_running ? pill('still running', 'bad') : h('span', { title: p.note || '' }, pill('exited', 'neutral'))) : null,
    p && p.exited ? sideRow('Exited', ts(p.exited)) : null,
    p && p.exited ? sideRow('Exit status', h('span', { class: 'mono' }, p.exit_status || '—')) : null,
    p && p.exit_record ? sideRow('Exit record', h('span', { class: 'mono sig-small' }, p.exit_record)) : null,
    // svchost.exe: the services this very process hosts (Signal names them only while it runs).
    p && p.services && p.services.length ? sideRow('Services hosted', h('div', {}, ...p.services.map((s) => h('div', { class: 'mono sig-small' }, s)))) : null,
    p && !p.still_running && p.note ? h('div', { class: 'mut sig-small' }, p.note) : null,
    en.gaps && en.gaps.length ? h('div', { class: 'mut sig-small' }, 'Not determined: ' + en.gaps.map((g) => `${g.item} (${g.reason})`).join('; ')) : null);
}

// signalBody is everything about one signal, in the order an analyst reads
// it (the rule's playbook - what happened, why it matters, what next - is
// on the Rules page, one click from "Rule" under Where): the sources that
// recorded it; the process graph; its command line or script
// whole; every field of its event; every occurrence and what varied; its
// process, and where it sits; then a way to suppress signals like it.
function signalBody(s, onSuppressed) {
  const f = s.fields || {};
  const code = CODE_FIELDS.filter(([k]) => f[k]).map(([k, label]) => h('div', { class: 'sig-fact wide' },
    h('div', { class: 'sig-fact-k' }, svgIcon('terminal'), label), h('pre', { class: 'sig-code' }, String(f[k]))));
  const stateFacts = s.kind === 'state' && s.evidence && typeof s.evidence === 'object' ? s.evidence : {};
  const table = detailsTable({ ...(s.kind === 'value' ? { Value: s.entity } : {}), ...stateFacts, ...f }, new Set(CODE_FIELDS.map(([k]) => k)), s);
  const variants = s.distinct > 1 ? h('div', { class: 'sig-variants' }, h('div', { class: 'sig-side-title' }, svgIcon('layers'),
    `${s.distinct_more ? 'More than ' + s.distinct : s.distinct} different forms`), s.variants.map((v) => h('div', { class: 'mono sig-small' }, breakable(v.entity), v.context ? h('span', { class: 'mut' }, ' · ', v.context) : null))) : null;
  const where = [['Module', s.module], ['Rule', pageLink('rules', { rule: s.rule_id }, s.rule_id)], ['Evidence', s.evidence || '—'], ['Hosts with this signal', s.fleet_n === 1 ? 'this host only' : s.fleet_n ? `${s.fleet_n} hosts (their latest collections)` : '—']];
  if (s.rule_count != null) where.push(['Matches of this rule on this host', String(s.rule_count)]);
  const suppressSlot = h('div');
  const suppression = s.suppressed_by
    ? h('div', { class: 'mut' }, 'Hidden by a suppression rule - see Suppression rules on the Rules page.')
    : canEdit() ? h('div', {}, h('button', { class: 'ghost', onclick: (e) => { e.stopPropagation(); suppressSlot.replaceChildren(suppressForm(s, onSuppressed)); } }, 'Suppress signals like this…'), suppressSlot) : null;
  return h('div', { class: 'ent-sig-body' },
    shadowNote(s), sourceCards(s), chain(s, f), ...code, table, occurrences(s), variants,
    h('div', { class: 'ent-sig-cards' }, processCard(s.enrichment), sideCard('Where', 'server', ...where.map(([k, v]) => sideRow(k, v)))),
    suppression);
}

// foldable is one row of an entity's page that unfolds in place: its head
// (clicked to open or close) and a body built the first time it opens.
// The element's open(bool) opens or closes it.
function foldable(cls, id, headParts, build, open) {
  let body = null;
  const box = h('div', { class: 'ent-sig-box' });
  const chevron = h('span', { class: 'chevron' }, '▸');
  const set = (on) => {
    if (on && !body) body = build();
    box.replaceChildren(...(on ? [body] : []));
    chevron.style.transform = `rotate(${on ? 90 : 0}deg)`;
    el.classList.toggle('open', on);
    head.setAttribute('aria-expanded', String(on));
  };
  const head = h('div', { class: 'ent-sig-head', role: 'button', tabindex: '0', onclick: () => set(!el.classList.contains('open')),
    onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); set(!el.classList.contains('open')); } } }, chevron, ...headParts);
  const el = h('div', { class: cls, id }, head, box);
  el.open = set;
  set(Boolean(open));
  return el;
}

// whenText is a signal's time as its row reads it: its match, the span of
// its matches, or the range its own time is not recorded within.
const whenText = (s) => (s.time_from && !(s.count > 1) ? `between ${ts(s.time_from)} and ${ts(s.time)}` : s.count > 1 ? `${ts(s.first_seen)} → ${ts(s.last_seen)}` : ts(s.time));

// signalSection is one signal on its entity's page, folded: a row with its
// severity, title, what it matched (its name, on one line - whole on
// hover), rule, matches, when and triage - and, for a signal it is only
// named in, the entity it is about - unfolding its body in place.
function signalSection(s, opts) {
  const what = String(s.entity || '');
  const head = [
    sevTag(s.severity),
    h('div', { class: 'ent-sig-main' },
      h('div', {}, h('span', { class: 'ent-sig-title' }, quotedTitle(s.title)),
        s.is_new ? h('span', { class: 'new-tag', title: 'Not in the host\'s previous collection' }, 'new') : null, shadowTag(s), approvedTag(s)),
      what ? h('div', { class: 'ent-sig-what mono', title: what }, what) : null,
      opts.named ? h('div', { class: 'mut sig-small' }, 'about ', entityLink({ id: s.entity_id, type: s.entity_type, display: s.entity_display }, s.run_id)) : null),
    h('div', { class: 'ent-sig-meta' }, h('span', { class: 'mut mono ent-sig-rule' }, s.rule_id),
      h('span', { class: 'mut ent-sig-n' }, `${(s.count || 1).toLocaleString()} match${s.count > 1 ? 'es' : ''}`),
      h('span', { class: 'mut ent-sig-when' }, whenText(s))),
    h('span', { class: 'ent-sig-tri' }, s.suppressed_by ? h('span', { class: 'mut' }, 'suppressed') : triageTag(s.triage)),
  ];
  return foldable(`ent-sig sev-edge-${s.severity}`, `signal-${s.sid}`, head, () => signalBody(s, opts.refresh), opts.open);
}

// signalTable is a server-paged table of signals - the host and user
// pages: params are the /api/signals/list query; height the table's
// dataTable height ('auto', 'scroll'), or none - pages. A row opens its
// entity's page at that signal.
export function signalTable(params, filename, height) {
  return dataTable([], SIGNAL_COLUMNS, {
    height,
    remote: (req) => fetchJSON(`/api/signals/list?${queryString({ ...params, ...req })}`),
    rowKey: (row) => row.sid,
    open: (row) => openPage('signals', { entity: row.entity_id, host: row.run_id, signal: row.sid }),
    filename,
  });
}

// ENTITY_COLUMNS are the list of entities: each row what to look at, with
// the signals about it by rule.
const ENTITY_COLUMNS = [
  col('severity'), col('last_seen'), col('triage', 'triage', { label: 'Triage', desc: 'The analyst\'s decision about the entity, as a whole - open until decided, and again when a signal appears after the decision.' }),
  col('type', 'entity_type'), col('display', 'entity_name'), col('host'),
  col('rules_text', 'entity_rules', {
    label: 'Signals', desc: 'Its signals by rule, the most severe first, with how many matches each stands for. Open the entity to read each in full.',
    render: (_v, row) => h('div', { class: 'ent-rules' }, row.rules.map((r) => h('span', { class: 'ent-rule' + (r.open ? '' : ' closed'), title: r.title }, sevTag(r.severity, r.rule_id), h('span', { class: 'mut' }, ` ×${r.count.toLocaleString()}`)))),
  }),
  col('open_n'), col('matches', 'entity_matches'), col('fleet_n', 'fleet_n', { desc: 'How many hosts\' latest collections have signals about the same entity. 1: this host alone - on a fleet of similar machines, what stands out.' }),
  col('caveats_n'),
];

// entityList is a table of entities, each row opening its page - the
// Signals page's list, and a host's on its page (opts.height: the table's
// dataTable height, or none - 20 a page).
export function entityList(rows, opts = {}) {
  return dataTable(rows, ENTITY_COLUMNS, {
    pageSize: 20, height: opts.height, filename: opts.filename || 'signals-by-entity', rowKey: (r) => r.key,
    // An entity with no open signal (all benign or suppressed) reads faded,
    // a space above the first of them where the open ones end.
    rowClass: (r, prev) => (r.open_n ? '' : `row-closed${prev && prev.open_n ? ' group-start' : ''}`),
    open: (r) => openPage('signals', { entity: r.id, host: r.run_id }),
  });
}

// entityHeader is the entity's header: severity, type, name, host, time
// span, its signals, its triage - and the other hosts that know it.
function entityHeader(e) {
  const others = e.other_hosts.length ? h('span', {}, 'also on ', ...e.other_hosts.flatMap((x, i) => [i ? ', ' : '', pageLink('signals', { entity: e.id, host: x.run_id }, x.host)])) : null;
  return h('div', { class: 'sig-head sev-' + (e.severity || 'low') },
    e.severity ? sevTag(e.severity) : h('span', { class: 'mut' }, 'no open signal'),
    h('div', { class: 'sig-head-title' }, h('div', { class: 'ent-head-type' }, svgIcon(entityIcon(e.type)), ' ', e.type), mono(e.display)),
    h('div', { class: 'sig-head-meta' }, hostLink(e),
      e.first_seen ? h('span', {}, e.first_seen === e.last_seen ? ts(e.first_seen) : `${ts(e.first_seen)} → ${ts(e.last_seen)}`) : null,
      h('span', {}, `${e.open_n} open of ${e.sids.length} signal${e.sids.length === 1 ? '' : 's'}`),
      e.sids.length ? triageTag(e.triage.state) : null,
      e.triage.new_n ? h('span', { class: 'sig-attn' }, `${e.triage.new_n} not triaged yet`) : null,
      e.latest ? null : h('span', { class: 'sig-attn' }, 'an earlier collection'), others));
}

// entityTriageBlock is the entity's triage as a whole: it covers its
// signals of this collection; a signal that appears later is open until the
// entity is triaged again. An entity only named in other signals has none
// of its own to triage. With several signals, the analyst may decide all of
// them or tick which (own: its signals).
function entityTriageBlock(e, own) {
  if (!e.sids.length) return detailBlock('Triage', h('div', { class: 'mut' }, 'No signal is about it - it is named in other entities\' signals: triage those entities.'));
  const scope = h('div', { class: 'mut' }, `Decides its ${e.sids.length} signal${e.sids.length === 1 ? '' : 's'} on this host as a whole - or tick the ones a decision is for, each then decided apart; a signal that appears later is open until it is triaged again.`);
  return triageBlock(e.triage, { ...entityTriage(e.id, e.run_id), scope, signals: own }, () => render());
}

// byRole orders related entities by what they are to the entity, so the
// same kind of link reads together (those with no role last).
const firstRole = (r) => (r.roles && r.roles[0]) || '￿';
const byRole = (list) => list.slice().sort((a, b) => firstRole(a).localeCompare(firstRole(b)));

// relatedCard is an entity its signals name - what it is to this entity
// (its roles, as the signals' records state them; schema 52), linked to its
// page, with what Signal read about it unfolding in place.
function relatedCard(r, facts, host) {
  const roles = (r.roles || []).map((x) => roleWords(x)).join(', ');
  const head = h('span', {}, roles ? h('span', { class: 'mut' }, `${roles}: `) : null,
    r.has_page ? entityLink(r, host) : h('span', {}, svgIcon(entityIcon(r.type)), ' ', mono(r.display)));
  if (!facts) return h('div', { class: 'ent-related' }, head);
  return h('details', { class: 'ent-related' }, h('summary', {}, head), factsCard(`What Signal read about the ${r.type}`, entityIcon(r.type), facts));
}

// roughly is a long duration rounded for a glance - "about 3 weeks",
// "almost 5 months", "over 2 years" (almost: rounded up, over: down); ''
// under a week, where the exact gap reads well enough.
function roughly(ms) {
  const days = ms / 86400000;
  if (days < 7) return '';
  const [n, unit] = days < 45 ? [days / 7, 'week'] : days < 365 ? [days / 30.44, 'month'] : [days / 365.25, 'year'];
  const r = Math.max(1, Math.round(n));
  const word = Math.abs(r - n) < 0.1 ? 'about' : r > n ? 'almost' : 'over';
  return `${word} ${r} ${unit}${r === 1 ? '' : 's'}`;
}

// gapOf is the time between two signals' starts: its exact words, a
// rounded tag for a long one, and its size on the rail - none (at the same
// time), hours (under a day), days, or months (30 days or more).
function gapOf(from, to) {
  const back = Date.parse(to) < Date.parse(from); // the rail runs newest first
  const ms = Math.abs(Date.parse(to) - Date.parse(from));
  if (Number.isNaN(ms)) return { text: '', size: 'hours' };
  if (ms <= 0) return { text: 'at the same time', size: 'same' };
  const parts = [[86400000, 'd'], [3600000, 'h'], [60000, 'min'], [1000, 's']].reduce((out, [unit, name]) => {
    const n = Math.floor((ms - out.used) / unit);
    if (n && out.list.length < 2) { out.list.push(`${n} ${name}`); out.used += n * unit; }
    return out;
  }, { list: [], used: 0 }).list;
  return { text: `${parts.join(' ') || 'under 1 s'} ${back ? 'earlier' : 'later'}`, rough: roughly(ms), size: ms >= 30 * 86400000 ? 'months' : ms >= 86400000 ? 'days' : 'hours' };
}

// signalsBlock is a list of signal sections, folded, with Expand all /
// Collapse all. The signals stand on a time rail in the order they
// began, the oldest first: each with its start's date and time beside it,
// and between two the time that passed.
function signalsBlock(title, list, sections) {
  if (!list.length) return null;
  const all = (open) => (e) => {
    e.preventDefault();
    for (const s of list) sections.get(s.sid).open(open);
  };
  return h('div', { class: 'ent-sigs' },
    h('div', { class: 'ent-sigs-head' }, h('div', { class: 'detail-title' }, title),
      h('span', { class: 'mut sig-small ent-sigs-order' }, 'oldest first ↓'),
      h('button', { class: 'ghost', onclick: all(true) }, 'Expand all'), h('button', { class: 'ghost', onclick: all(false) }, 'Collapse all')),
    timeRail(list, (s) => sections.get(s.sid)));
}

// timeRail stands signals (in time order, the oldest first - or the
// newest, the gaps then "earlier") on a rail: each its start's date and time, a dot of
// its severity, its row (rowOf), and between two the time that passed -
// exact, rounded when long, its space by its length. A signal whose own
// time is not recorded stands at the start of its range, marked "from"; no
// time is said to pass to or from it. opts.days heads each day with its
// date and how many signals began on it (a header's data-day: YYYY-MM-DD).
// The Timeline page and an entity's page share it.
export function timeRail(list, rowOf, opts = {}) {
  const ranged = (s) => Boolean(s.time_from) && !(s.count > 1);
  const stamp = (s) => {
    const t = ts(startOf(s));
    const anchored = s.as_of && s.anchor;
    return h('div', {
      class: 'ent-step-when' + (ranged(s) || anchored ? ' ranged' : ''),
      title: ranged(s) ? `Its own time is not recorded: between ${ts(s.time_from)} and ${ts(s.time)}`
        : anchored ? `Its own time is not recorded: placed by ${s.anchor.what}, ${ts(s.anchor.time)} - observed when Signal read the host, ${ts(s.time)}` : 'When it began: its first match',
    }, h('div', { class: 'ent-step-date' }, (ranged(s) ? 'from ' : '') + t.slice(0, 10)), h('div', { class: 'ent-step-time' }, t.slice(11)),
    timeIsOf(s) ? h('div', { class: 'ent-step-is' }, timeIsOf(s)) : null);
  };
  const gap = (a, b) => (ranged(a) || ranged(b) ? { text: 'own time not recorded', size: 'hours' } : gapOf(startOf(a), startOf(b)));
  const dayOf = (s) => ts(startOf(s)).slice(0, 10);
  const perDay = new Map();
  if (opts.days) for (const s of list) perDay.set(dayOf(s), (perDay.get(dayOf(s)) || 0) + 1);
  const dayHead = (d) => h('div', { class: 'rail-day', 'data-day': d }, h('span', { class: 'rail-day-date' }, new Date(`${d}T00:00:00Z`).toLocaleDateString('en-GB', { weekday: 'long', timeZone: 'UTC' }), ' ', h('b', {}, d)),
    h('span', { class: 'mut' }, `${perDay.get(d)} signal${perDay.get(d) === 1 ? '' : 's'}`));
  return h('div', { class: 'ent-rail' }, list.flatMap((s, i) => [
    opts.days && (!i || dayOf(list[i - 1]) !== dayOf(s)) ? dayHead(dayOf(s)) : null,
    i ? (({ text, rough, size }) => h('div', { class: `ent-step-gap gap-${size}` }, h('span', {}, text), rough ? h('span', { class: 'gap-rough' }, rough) : null))(gap(list[i - 1], s)) : null,
    h('div', { class: 'ent-step' }, stamp(s), h('div', { class: `ent-step-dot sev-${s.severity}` }), rowOf(s)),
  ]));
}

// graphOf is the entity graph of one entity: the entity, the entities its
// signals name, and those whose signals name it - each other entity with
// its line to this one only - and the analysts' links to it. Opened with
// the entity selected.
function graphOf(e, rows, analyst, vt, flags) {
  const own = rows.find((r) => r.id === e.id);
  const naming = rows.filter((r) => r !== own && (r.related || []).some((x) => x.id === e.id));
  const linked = new Set(((own && own.related) || []).map((x) => x.id));
  const others = rows.filter((r) => r !== own && linked.has(r.id) && !naming.includes(r));
  const focus = own ? own.node : ((naming[0] && naming[0].related.find((x) => x.id === e.id)) || {}).node;
  const scoped = [...(own ? [own] : []), ...naming.map((r) => ({ ...r, related: r.related.filter((x) => x.id === e.id) })), ...others.map((r) => ({ ...r, related: [] }))];
  if (!scoped.length || !focus) return null;
  const pick = (a) => {
    const links = a.links.filter((l) => l.a === focus || l.b === focus);
    const keys = new Set(links.flatMap((l) => [l.a, l.b]));
    return { entities: a.entities.filter((x) => keys.has(x.key)), links };
  };
  return entityGraph(scoped, { flags, analyst: pick(analyst), pickAnalyst: pick, vt, focus, bare: true, editable: canEdit() });
}

// glance is the entity's signals at a glance, under its header: how many of
// each severity are open, their matches, the modules that found them, the
// entities it is linked to, its caveats, and VirusTotal's answer when it
// called its file, address or domain malicious or suspicious.
function glance(e, own, vtHit) {
  const open = own.filter((s) => s.triage !== 'benign' && !s.suppressed_by);
  const bySev = Object.keys(SEVERITY_RANK).map((sev) => [sev, open.filter((s) => s.severity === sev).length]).filter(([, n]) => n);
  const modules = [...new Set(own.map((s) => s.module))].sort();
  const item = (label, value, cls) => h('div', { class: 'ent-glance-item' + (cls ? ' ' + cls : '') }, h('div', { class: 'ent-glance-v' }, value), h('div', { class: 'ent-glance-k' }, label));
  return h('div', { class: 'ent-glance' },
    item('open signals', bySev.length ? h('span', {}, ...bySev.flatMap(([sev, n], i) => [i ? ' · ' : '', sevTag(sev, `${n} ${sev}`)])) : '0'),
    item('matches', e.matches.toLocaleString()),
    modules.length ? item(modules.length === 1 ? 'module' : 'modules', modules.join(', ')) : null,
    item('linked entities', String(e.related.length) + (e.related_more ? '+' : '')),
    e.caveats.length ? item('caveats', String(e.caveats.length), 'attn') : null,
    vtHit ? withTip(item('VirusTotal says', `${vtHit.malicious} malicious, ${vtHit.suspicious} suspicious of ${vtHit.engines}`, 'bad'),
      `VirusTotal's answer for ${vtHit.value}, looked up ${ts(vtHit.looked_up)} - not Signal's finding`) : null);
}

// entitySummary is the entity's page as plain text, for a ticket, a
// hand-over or the investigation notes: what it is, where, its signals (each with
// its rule, matches, time span and triage), what Signal read about it, its
// related entities, its caveats and the page's link. Times are UTC, as
// every page shows them.
function entitySummary(e, own, named) {
  const span = (a, b) => (!a ? '' : a === b || !b ? ts(a) : `${ts(a)} → ${ts(b)}`);
  const signal = (s) => `- [${s.severity}] ${s.rule_id} ${s.title} - ${(s.count || 1).toLocaleString()} match${(s.count || 1) === 1 ? '' : 'es'}`
    + `${span(s.first_seen || s.time, s.last_seen || s.time) ? `, ${span(s.first_seen || s.time, s.last_seen || s.time)}` : ''}`
    + ` (${s.suppressed_by ? 'suppressed' : (TRIAGE[s.triage] || { label: s.triage }).label})`;
  const lines = [`${e.type}: ${e.display}`, `Host: ${e.host} (collection ${e.run_id}${e.latest ? ', its latest' : ', an earlier one'})`];
  if (e.other_hosts.length) lines.push(`Also on: ${e.other_hosts.map((x) => x.host).join(', ')}`);
  lines.push(`Signals: ${e.open_n} open of ${e.sids.length}${e.severity ? `, most severe open: ${e.severity}` : ''}${span(e.first_seen, e.last_seen) ? `; ${span(e.first_seen, e.last_seen)}` : ''}`);
  if (e.sids.length) lines.push(`Triage: ${(TRIAGE[e.triage.state] || { label: e.triage.state }).label}${e.triage.by ? ` by ${e.triage.by}` : ''}${e.triage.at ? ` (${ts(e.triage.at)})` : ''}${e.triage.note ? ` - ${e.triage.note}` : ''}${e.triage.new_n ? `; ${e.triage.new_n} signal(s) new since` : ''}`);
  if (own.length) lines.push('', 'Signals about it:', ...own.map(signal));
  if (named.length) lines.push('', 'Signals it is named in (about other entities):', ...named.map((s) => `${signal(s)} - about ${s.entity}`));
  if (e.facts && e.facts.facts.length) lines.push('', 'What Signal read about it:', ...e.facts.facts.map((f) => `- ${f.label}: ${f.kind === 'time' ? ts(f.value) : f.value}`));
  if (e.facts && e.facts.gaps.length) lines.push(`Not determined: ${e.facts.gaps.map((g) => `${g.item} (${g.reason})`).join('; ')}`);
  if (e.related.length) lines.push('', 'Linked to this entity:', ...byRole(e.related).map((r) => `- ${(r.roles || []).map((x) => roleWords(x)).join(', ') || 'linked'}: ${r.type} ${r.display}`), ...(e.related_more ? ['- and more'] : []));
  if (e.caveats.length) lines.push('', 'Caveats - there may be more:', ...e.caveats.map((c) => `- ${c}`));
  lines.push('', `Signal Console: ${location.origin}${pageUrl('signals', { entity: e.id, host: e.run_id })}`);
  return lines.join('\n');
}

// startOf is when a signal began: the earliest of its matches - or, for a
// match whose own time is not recorded, the start of its range; a state
// observed as Signal read the host stands at its anchor, the best time
// Windows recorded about it (Signal schema 59), when there is one.
export const startOf = (s) => (s.as_of && s.anchor ? s.anchor.time : s.time_from || s.first_seen || s.time || '');

// timeIsOf says what a signal's time on the rail is - "event logged",
// "registry key last written..." - in Signal's words.
export const timeIsOf = (s) => (s.as_of && s.anchor ? s.anchor.what : s.time_is || '');
// byTime orders signals as they happened, the oldest first; the most
// severe first among those that began at once.
const byTime = (a, b) => String(startOf(a)).localeCompare(String(startOf(b))) || (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);

// renderEntityPage is one entity on one host, everything about it on one
// page: its header and its signals at a glance; the graph of it and what
// it is linked to, the page's width; its signals - first their timeline, then each signal
// folded to one row, unfolding in place (only the one a link asked for
// opens); the signals it is only named in; beside them what Signal read
// about it (with VirusTotal's answer), the entities it is linked to with
// their facts, and its caveats; below everything, page-wide, its triage.
async function renderEntityPage(container, id, host, focusSid) {
  // The ways back: to the Signals list with its filters as last set; and,
  // only when the signal was opened from the Timeline, to the Timeline
  // where they were - stuck at the top left of the window, since the page
  // opens scrolled to the signal, not at its start.
  const fromTimeline = urlParams().get('from') === 'timeline' && rememberedState('timeline');
  const backLink = () => pageLink('signals', Object.fromEntries(new URLSearchParams(rememberedState('signals') || '')), '← All signals');
  let back = h('div', { class: 'row' }, backLink());
  let e;
  try {
    e = await fetchJSON(`/api/entities/item?${queryString({ id, host })}`);
  } catch {
    container.replaceChildren(back, h('div', { class: 'card mut' }, 'No collection knows this entity - its host may have been collected again without it.'));
    return;
  }
  const ids = e.related.map((r) => r.id);
  const list = (sids) => fetchJSON(`/api/signals/list?${queryString({ host: e.run_id, sids: sids.join(','), show: 'all', limit: sids.length })}`).then((r) => r.rows.sort(byTime));
  const [own, named, relatedFacts, scope, analyst, flags, vt] = await Promise.all([
    e.sids.length ? list(e.sids) : [],
    e.named_sids.length ? list(e.named_sids) : [],
    ids.length ? fetchJSON(`/api/entities/facts?${queryString({ host: e.run_id, ids: ids.join(',') })}`) : {},
    fetchJSON(`/api/entities?${queryString({ host: e.run_id, show: 'all' })}`),
    fetchJSON('/api/graph/analyst'),
    fetchJSON('/api/flags'),
    fetchJSON(`/api/entities/virustotal?${queryString({ host: e.run_id })}`),
  ]);
  back = h('div', { class: 'row' }, backLink(), copyButton('Copy summary', () => entitySummary(e, own, named), 'Copy what the page states about it as plain text - for a ticket, a hand-over or the investigation notes'));
  // Every signal starts folded, to be read as a list first; only the one a
  // link asked for opens (main.js scrolls to it).
  const sections = new Map([...own.map((s) => [s.sid, signalSection(s, { open: s.sid === focusSid, refresh: () => render() })]),
    ...named.map((s) => [s.sid, signalSection(s, { open: s.sid === focusSid, named: true, refresh: () => render() })])]);
  const graph = section('Graph — this entity and the entities linked to it', () => graphOf(e, scope.rows, analyst, vt, flags.filter((f) => f.kind === 'entities').map((f) => f.key)),
    { collapsed: false, modules: [...new Set([...own, ...named].map((s) => s.module))].sort() });
  const main = h('div', { class: 'sig-main' },
    signalsBlock(`Signals about it (${own.length})`, own, sections),
    signalsBlock(`Signals it is named in (${named.length}) - about other entities`, named, sections));
  const side = h('div', { class: 'sig-side ent-side' },
    factsCard(`What Signal read about the ${e.type}`, entityIcon(e.type), e.facts),
    e.related.length ? h('div', { class: 'sig-side-card' }, h('div', { class: 'sig-side-title', title: 'Not subjects of a signal themselves: entities this one is linked to by the evidence of its signals and by enrichment' }, svgIcon('layers'), `Linked to this entity (${e.related.length}${e.related_more ? '+' : ''})`),
      ...byRole(e.related).map((r) => relatedCard(r, relatedFacts[r.id], e.run_id)), e.related_more ? h('div', { class: 'mut' }, 'and more') : null) : null,
    e.caveats.length ? h('div', { class: 'sig-side-card' }, h('div', { class: 'sig-side-title' }, svgIcon('warning'), 'Caveats - there may be more'), ...e.caveats.map((c) => h('div', { class: 'mut sig-small' }, c))) : null,
    e.type === 'account' && /^S-1-/.test(e.key) ? h('div', {}, pageLink('users', { user: e.key }, 'The account across the fleet, on Users')) : null,
    e.type === 'host' ? h('div', {}, pageLink('hosts', { host: e.run_id }, 'The host\'s cards, telemetry and inventories, on Hosts')) : null);
  const toTimeline = fromTimeline ? h('div', { class: 'tl-back' }, h('a', { href: fromTimeline.url, onclick: (x) => linkClick(x, fromTimeline.url) }, '← Back to the timeline')) : null;
  container.replaceChildren(...[toTimeline, back].filter(Boolean), h('div', { class: 'card sig-page' }, h('div', { class: 'detail sig-detail' },
    entityHeader(e), glance(e, own, vt[e.id]), graph ? h('div', { class: 'ent-graph-wide' }, graph) : null, h('div', { class: 'sig-body' }, main, side), h('div', { class: 'ent-triage-wide' }, entityTriageBlock(e, own)))));
  if (focusSid && sections.has(focusSid)) sections.get(focusSid).classList.add('focus-row'); // main.js scrolls to it once the page is on screen
}

// SHOW is the "Show" filter: which signals, by suppression and collection.
const SHOW = [
  ['', 'open and triaged (not suppressed)'],
  ['new', 'new since the previous collection'],
  ['rare', 'on one host only'],
  ['suppressed', 'suppressed only'],
  ['all', 'everything, suppressed included'],
];

// suppressionRules is the list of suppression rules: each rule's
// conditions, note, when it was made, how many of the scope's signals it
// hides, and a Remove button (the Rules page).
export function suppressionRules(rules, onChange) {
  if (rules.length === 0) return h('div', { class: 'mut' }, canEdit() ? 'No suppression rules yet. Unfold a signal on its entity\'s page and choose "Suppress signals like this…" to hide it and every signal like it.' : 'No suppression rules yet.');
  const rows = rules.map((r) => ({ ...r, conditions_text: r.conditions.map((c) => `${fieldLabel(c.field)} ${c.op} "${c.value}"`).join(' and ') }));
  return dataTable(rows, [
    col('conditions_text', 'details', { label: 'Conditions', desc: 'A signal is hidden when all of these hold (case-insensitive).' }),
    col('note', 'details', { label: 'Why', desc: 'The note given when the rule was made.' }),
    col('created', 'started', { label: 'Created', desc: `When the rule was made (UTC).` }),
    col('created_by', 'domain', { label: 'Created by', icon: 'eye', desc: 'The analyst who made the rule.', render: (v) => v || '—' }),
    col('hides_n', 'count', { label: 'Hides', desc: 'How many of the current signals it hides.' }),
    canEdit() && col('id', 'run', {
      label: 'Remove', desc: 'Delete the rule; the signals it hid come back.',
      render: (v) => h('button', {
        class: 'ghost danger', onclick: async (e) => {
          e.stopPropagation();
          if (!confirm('Remove this suppression rule? The signals it hides will show again.')) return;
          await apiFetch(`/api/signals/suppressions/${v}`, { method: 'DELETE' });
          onChange();
        },
      }, 'Remove'),
    }),
  ].filter(Boolean), { filename: 'suppression-rules', pageSize: 20 });
}

// renderSignalsPage lists what to look at - every entity with signals of
// every host's latest collection by default, or of one host (any
// collection, via ?host=<run id>) - under a summary strip; the sticky
// filter bar (Host, Type, Modules, Severity, Rule, ATT&CK tactic, Triage,
// Evidence, Show) is kept in the URL. ?entity=<type:key>&host=<run id>
// opens an entity's page (&signal=<sid> unfolds that signal); an old
// ?signal=<sid> link opens its entity's page at it.
export async function renderSignalsPage(container) {
  let q = urlParams();
  // The list opened without filters (the sidebar, a bare link): its filters as last set.
  const FILTERS = ['host', 'type', 'modules', 'severity', 'rule', 'tactic', 'triage', 'evidence', 'show'];
  if (!q.get('entity') && !q.get('signal') && !FILTERS.some((k) => q.has(k)) && rememberedState('signals')) {
    setParams(Object.fromEntries(new URLSearchParams(rememberedState('signals'))));
    q = urlParams();
  }
  if (q.get('entity')) return renderEntityPage(container, q.get('entity'), q.get('host') || '', q.get('signal') || '');
  if (q.get('signal')) {
    const s = (await fetchJSON(`/api/signals/list?${queryString({ host: q.get('host') || '', sids: q.get('signal'), show: 'all', limit: 1 })}`)).rows[0];
    if (s) {
      history.replaceState(null, '', pageUrl('signals', { entity: s.entity_id, host: s.run_id, signal: s.sid }));
      return renderEntityPage(container, s.entity_id, s.run_id, s.sid);
    }
  }
  const runs = await fetchJSON('/api/runs');
  const current = runs.filter((r) => r.latest);
  const byId = new Map(runs.map((r) => [r.run_id, r]));
  // No host in the URL: the host filter chosen on another page, when it is one host.
  const kept = rememberedHosts();
  const hostId = byId.has(q.get('host')) ? q.get('host') : !q.get('host') && kept.length === 1 && byId.has(kept[0]) ? kept[0] : '';
  const earlier = hostId && !byId.get(hostId).latest ? byId.get(hostId) : null; // an earlier collection, from a host's history
  const scope = await fetchJSON(`/api/entities?${queryString({ host: hostId, show: 'all' })}`);

  const options = {
    types: scope.options.types,
    modules: scope.options.modules,
    severities: Object.keys(SEVERITY_RANK),
    rules: scope.options.rules,
    tactics: [...ATTACK_TACTICS, NO_TACTIC].filter((t) => scope.options.tactics.includes(t)),
    triage: TRIAGE_CHOICES,
    evidence: scope.options.evidence,
  };
  const sel = {
    types: selectionFromUrl('type', options.types),
    modules: selectionFromUrl('modules', options.modules),
    severities: selectionFromUrl('severity', options.severities),
    rules: selectionFromUrl('rule', options.rules),
    tactics: selectionFromUrl('tactic', options.tactics),
    triage: selectionFromUrl('triage', options.triage),
    evidence: selectionFromUrl('evidence', options.evidence),
    show: SHOW.some(([k]) => k === q.get('show')) ? q.get('show') : '',
  };
  const unless = (key) => (sel[key].size === options[key].length ? null : [...sel[key]]);
  const filters = () => ({ host: hostId, type: unless('types'), modules: unless('modules'), severity: unless('severities'), rule: unless('rules'), tactic: unless('tactics'), triage: unless('triage'), evidence: unless('evidence'), show: sel.show });
  const syncUrl = () => {
    setParams({ ...filters(), host: hostId || null, show: sel.show || null });
    const kept = urlParams();
    rememberState('signals', kept.toString());
  };
  const pick = (key) => (s) => { sel[key] = s.size ? s : new Set(options[key]); syncUrl(); draw(); };
  const labels = hostLabels(current);
  const hostOptions = [['', `Fleet-wide (${current.length} host${current.length === 1 ? '' : 's'})`], ...current.map((r) => [r.run_id, labels.get(r.run_id)]),
    ...(earlier ? [[earlier.run_id, `${earlier.host} (earlier collection, ${ts(earlier.started)})`]] : [])];
  const bar = filterBar([
    ['Host', h('select', { onchange: (e) => { rememberHosts(e.target.value ? [e.target.value] : []); setParams({ host: e.target.value || null }); render(); } },
      hostOptions.map(([v, t]) => h('option', { value: v, selected: v === hostId ? 'selected' : null }, t)))],
    ['Type', checkboxDropdown(options.types, pick('types'), [...sel.types]).el],
    ['Modules', checkboxDropdown(options.modules, pick('modules'), [...sel.modules]).el],
    ['Severity', checkboxDropdown(options.severities, pick('severities'), [...sel.severities]).el],
    ['Rule', checkboxDropdown(options.rules, pick('rules'), [...sel.rules]).el],
    ['ATT&CK tactic', checkboxDropdown(options.tactics, pick('tactics'), [...sel.tactics]).el],
    ['Triage', checkboxDropdown(options.triage, pick('triage'), [...sel.triage], (t) => TRIAGE[t].label).el],
    ['Evidence', checkboxDropdown(options.evidence, pick('evidence'), [...sel.evidence]).el],
    ['Show', h('select', { onchange: (e) => { sel.show = e.target.value; syncUrl(); draw(); } }, SHOW.map(([v, t]) => h('option', { value: v, selected: sel.show === v ? 'selected' : null }, t)))],
  ]);

  const summaryBox = h('div');
  const listBox = h('div');
  let generation = 0;
  async function draw() {
    const mine = ++generation;
    const { rows, summary: s } = await fetchJSON(`/api/entities?${queryString(filters())}`);
    if (mine !== generation) return;
    const linkScope = { host: hostId || null, rule: unless('rules') };
    summaryBox.replaceChildren(summaryStrip([
      { icon: 'target', value: rows.length, label: 'entities' },
      ...severityItems(s.by_severity, linkScope),
      { icon: 'eye', value: s.untriaged, label: 'untriaged', cls: s.untriaged ? 'tr-new' : null },
      { icon: 'firstSeen', value: s.rare, label: 'on one host only', cls: s.rare ? 'tr-new' : null, link: s.rare && sel.show !== 'rare' ? ['signals', { ...linkScope, show: 'rare' }] : null },
      { icon: 'hosts', value: s.hosts, label: 'hosts' },
    ], s.modules.length ? s.modules : [CORE]));
    listBox.replaceChildren(section('Signals — what to look at, by what it is about; open one to read and triage everything about it', () => (rows.length
      ? entityList(rows, { height: 'auto' }) : h('div', { class: 'mut' }, 'No signal matches the filters.')), { collapsed: false, modules: s.modules.length ? s.modules : [CORE] }));
  }

  stickyPage(container, bar);
  container.replaceChildren(bar, summaryBox, listBox);
  syncUrl();
  await draw();
}
