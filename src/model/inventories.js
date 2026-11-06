// Fleet-wide inventories (the fleet inventory pages and the Users page's logons).
//
// An inventory is everything observed of one kind, across the selected
// hosts, grouped by value: one row per audit subcategory, event ID or logon
// pattern, saying on which hosts (and how often) it was seen. Grouping
// across hosts - rather than one row per host - is what makes a fleet
// inventory useful: a value seen on 1 of 200 hosts stands out.
//
// The audit policy and event-ID inventories read LogIntegrity's two tables
// by name; the audit policy changes, the logon tables and the antivirus
// exclusions, by role. The small inventories are sent whole; the logon
// tables are searched, filtered, sorted and paged here, on the server (see
// queryRows), so the page stays fast at hundreds of hosts.
'use strict';

const { filterRequest } = require('../../public/js/columnFilter.js');

const { HostSet, hostMeta } = require('./hosts');
const { topology } = require('./topology');

// withModules keeps only the given modules of each run (all of them when
// modules is empty), so every inventory - and its source-module list -
// reflects the module filter.
function withModules(runs, modules) {
  if (!modules || modules.length === 0) return runs;
  const wanted = new Set(modules);
  return runs.map((run) => ({ ...run, modules: Object.fromEntries(Object.entries(run.modules || {}).filter(([m]) => wanted.has(m))) }));
}

// datasetRows lists every row of every dataset matching `match` (a name,
// or a predicate on the dataset), across every run and module, as an
// object keyed by column name, with the run, module and dataset it came
// from. modules collects the names of the modules that contributed.
function datasetRows(runs, match) {
  const test = typeof match === 'function' ? match : (ds) => ds.name === match;
  const rows = [];
  const modules = new Set();
  for (const run of runs) {
    for (const [moduleName, result] of Object.entries(run.modules || {})) {
      for (const ds of result.datasets || []) {
        if (!test(ds)) continue;
        modules.add(moduleName);
        for (const r of ds.rows) {
          rows.push({ row: Object.fromEntries(ds.columns.map((c, i) => [c, r[i]])), key: r[0], run, module: moduleName, dataset: ds.name });
        }
      }
    }
  }
  return { rows, modules: [...modules].sort() };
}

// groupBy folds items into a Map by key, creating each group with init()
// and updating it with add(group, item).
function groupBy(items, keyOf, init, add) {
  const groups = new Map();
  for (const item of items) {
    const k = keyOf(item);
    if (!groups.has(k)) groups.set(k, init(item));
    add(groups.get(k), item);
  }
  return [...groups.values()];
}

// widenTime keeps a group's earliest first_seen and latest last_seen.
function widenTime(g, first, last) {
  if (first && (!g.first_seen || first < g.first_seen)) g.first_seen = first;
  if (last && (!g.last_seen || last > g.last_seen)) g.last_seen = last;
}

// hostFields are the plain values of a row's host columns - how many hosts
// (seen_n) and their names (host_names) - for sorting, search and CSV; the
// host list itself stays in hosts, for links.
function hostFields(hosts) {
  return { hosts, seen_n: hosts.length, host_names: hosts.map((x) => x.host).join('; ') };
}

// eventIdFlags maps each event ID to the rules that flagged it: a rule that
// fired on a run and whose detection matches log.event_id with that value
// (the rule's own definition, so always complete).
function eventIdFlags(runs) {
  const byValue = new Map();
  for (const run of runs) {
    for (const result of Object.values(run.modules || {})) {
      const fired = new Set((result.findings || []).map((f) => f.rule_id).filter(Boolean));
      for (const entry of result.rule_catalog || []) {
        if (!fired.has(entry.id)) continue;
        for (const sel of Object.values(entry.detection || {})) {
          for (const v of (sel['log.event_id'] || {}).values || []) {
            if (!byValue.has(String(v))) byValue.set(String(v), new Map());
            byValue.get(String(v)).set(entry.id, { rule_id: entry.id, severity: entry.severity });
          }
        }
      }
    }
  }
  return (value) => [...(byValue.get(String(value)) || new Map()).values()].sort((a, b) => a.rule_id.localeCompare(b.rule_id));
}

// auditPolicyInventory: per audit subcategory, the hosts that audit its
// Success events, its Failure events, and neither; what the local GPO and
// Group Policy set on them (schema 37), and the hosts where a direction
// Group Policy turns on is off in force (Signal decides it: not_in_force).
function auditPolicyInventory(runs) {
  const { rows, modules } = datasetRows(runs, 'audit_policy');
  const set = (v) => v && v !== 'not set' && v !== 'unknown';
  const groups = groupBy(rows, ({ row }) => row.subcategory,
    ({ row }) => ({ category: row.category, subcategory: row.subcategory, event_ids: row.event_ids, success: new HostSet(), failure: new HostSet(), off: new HostSet(),
      gp_off: new HostSet(), group_policy: new Set(), local_gpo: new Set() }),
    (g, { row, run }) => {
      if (row.success) g.success.add(run);
      if (row.failure) g.failure.add(run);
      if (!row.success && !row.failure) g.off.add(run);
      if (row.not_in_force) g.gp_off.add(run);
      if (set(row.group_policy)) g.group_policy.add(row.group_policy);
      if (set(row.local_gpo)) g.local_gpo.add(row.local_gpo);
    });
  return {
    modules,
    rows: groups.map((g) => ({ ...g, success: g.success.list(), failure: g.failure.list(), off: g.off.list(), gp_off: g.gp_off.list(),
      group_policy: [...g.group_policy].sort().join('; '), local_gpo: [...g.local_gpo].sort().join('; ') }))
      .sort((a, b) => a.category.localeCompare(b.category) || a.subcategory.localeCompare(b.subcategory)),
  };
}

// loggingPolicyInventory: each host's logging settings by layer of policy
// (Signal's logging_policy, schema 37) - one row per host and setting.
function loggingPolicyInventory(runs) {
  const { rows, modules } = datasetRows(runs, 'logging_policy');
  return {
    modules,
    rows: rows.map(({ row, run }) => ({ ...row, run_id: run.run_id, ...hostMeta(run) }))
      .sort((a, b) => a.setting.localeCompare(b.setting) || a.host.localeCompare(b.host)),
  };
}

// eventIdInventory: per event ID, the hosts in each expected-vs-present
// status (see Signal's event_ids dataset), its total count and first/last
// occurrence across the hosts where it is present, and the rules that
// flagged it.
function eventIdInventory(runs) {
  const flags = eventIdFlags(runs);
  const { rows, modules } = datasetRows(runs, 'event_ids');
  const groups = groupBy(rows, ({ row }) => row.event_id,
    ({ row }) => ({ event_id: row.event_id, subcategories: new Set(), statuses: {}, expected: new HostSet(), present: new HostSet(), count: 0, first_seen: null, last_seen: null }),
    (g, { row, run }) => {
      if (row.subcategories) g.subcategories.add(row.subcategories);
      (g.statuses[row.status] = g.statuses[row.status] || new HostSet()).add(run);
      if (row.expected) g.expected.add(run);
      if (row.present) {
        g.present.add(run);
        g.count += row.count || 0;
        widenTime(g, row.first_seen, row.last_seen);
      }
    });
  return {
    modules,
    rows: groups.map((g) => {
      const rules = flags(g.event_id);
      return {
        ...g,
        subcategories: [...g.subcategories].join('; '),
        statuses: Object.fromEntries(Object.entries(g.statuses).map(([s, set]) => [s, set.list()])),
        expected: g.expected.list(),
        present: g.present.list(),
        flagged_by: rules, flagged_rules: rules.map((r) => r.rule_id).join('; '),
      };
    }).sort((a, b) => a.event_id - b.event_id),
  };
}

// eventLogInventory: each host's other event logs (Signal's event_logs,
// schema 38) - whether each records, its size and how far back it reaches;
// one row per host and log, the logs turned off first.
function eventLogInventory(runs) {
  const { rows, modules } = datasetRows(runs, 'event_logs');
  const off = (r) => (String(r.recording).startsWith('no - ') ? 0 : 1);
  return {
    modules,
    rows: rows.map(({ row, run }) => ({ ...row, run_id: run.run_id, ...hostMeta(run) }))
      .sort((a, b) => off(a) - off(b) || a.log.localeCompare(b.log) || a.host.localeCompare(b.host)),
  };
}

// auditPolicyChangeInventory: every audit policy change (Signal's
// activity.audit_policy_changes: one row per change, schema 11) on the
// selected hosts - a change happens on one host at one moment, so each is
// its own row, with its host - newest first.
function auditPolicyChangeInventory(runs) {
  const { rows, modules } = datasetRows(runs, (ds) => ds.role === 'activity.audit_policy_changes');
  return {
    modules,
    rows: rows.map(({ row, run }) => ({ ...row, run_id: run.run_id, ...hostMeta(run) }))
      .sort((a, b) => String(b.time).localeCompare(String(a.time)) || a.host.localeCompare(b.host)),
  };
}

// LOGON_TABLES are the logon inventories, each gathering one Logons table
// (by dataset role) across hosts, grouped by the columns that identify a row
// (key) - the counts summed, the times widened, the hosts listed.
const LOGON_TABLES = [
  { id: 'logons', title: 'Logons', role: 'activity.logons', key: ['account', 'logon_type', 'source'],
    keep: ['account', 'sid', 'kind', 'scope', 'logon_type', 'type_name', 'source', 'source_scope', 'auth_package'], sum: ['count', 'elevated'] },
  { id: 'failures', title: 'Failed logons', role: 'activity.logon_failures', key: ['account', 'logon_type', 'source', 'reason'],
    keep: ['account', 'scope', 'logon_type', 'type_name', 'source', 'source_scope', 'reason'], sum: ['count'] },
  { id: 'explicit', title: 'Explicit credentials', role: 'activity.explicit_credentials', key: ['subject', 'account', 'target_server', 'process'],
    keep: ['subject', 'account', 'target_server', 'process'], sum: ['count'] },
  { id: 'privileged', title: 'Administrative logons', role: 'activity.privileged_logons', key: ['account'],
    keep: ['account', 'sid', 'scope'], sum: ['count'] },
  // Remote Desktop's own logs (schema 19): the sessions and connections of
  // the host connected to, and the connections its client made.
  { id: 'rdp_sessions', title: 'Remote Desktop', role: 'activity.rdp_sessions', key: ['account', 'how', 'source', 'event'],
    keep: ['account', 'how', 'source', 'source_scope', 'event'], sum: ['count'] },
  { id: 'rdp_outbound', title: 'Remote Desktop client connections', role: 'activity.rdp_outbound', key: ['sid', 'server', 'event'],
    keep: ['account', 'sid', 'server', 'event'], sum: ['count'] },
];

// NETWORK_TABLES are the network inventories (schema 27), gathered the
// same way: the ports listened on - rarest first, the program on a port
// few hosts have is the one to look at - and the Internet addresses talked
// to, by address, port and program.
const NETWORK_TABLES = [
  { id: 'listeners', title: 'Listening ports', role: 'activity.listeners', key: ['protocol', 'address', 'port', 'program'],
    keep: ['protocol', 'address', 'port', 'program', 'signer', 'signature'], sum: [], rarest: true },
  { id: 'remote_addresses', title: 'Internet addresses', role: 'activity.remote_addresses', key: ['address', 'port', 'program'],
    keep: ['address', 'port', 'program', 'seen_in'], sum: ['records'], rarest: true },
  { id: 'internal_addresses', title: 'Private addresses', role: 'activity.internal_addresses', key: ['address', 'port', 'program'],
    keep: ['address', 'port', 'program', 'seen_in'], sum: ['records'], rarest: true }, // schema 55
];

// roleTables gathers each table of specs (LOGON_TABLES, NETWORK_TABLES)
// across the hosts: one row per key, the sums added, the times widened, the
// hosts listed - every row searchable by its text (search) - most counted
// first, or rarest first for a spec that says so.
function roleTables(runs, specs) {
  const tables = {};
  const modules = new Set();
  for (const t of specs) {
    const found = datasetRows(runs, (ds) => ds.role === t.role);
    found.modules.forEach((m) => modules.add(m));
    const groups = groupBy(found.rows, ({ row }) => t.key.map((k) => String(row[k] ?? '').toUpperCase()).join('\u0000'),
      ({ row }) => ({ ...Object.fromEntries(t.keep.map((k) => [k, row[k] ?? ''])), ...Object.fromEntries(t.sum.map((k) => [k, 0])), hosts: new HostSet(), first_seen: null, last_seen: null }),
      (g, { row, run }) => {
        g.hosts.add(run);
        for (const k of t.sum) g[k] += row[k] || 0;
        widenTime(g, row.first_seen, row.last_seen);
      });
    const total = (r) => (t.sum.length ? r[t.sum[0]] : 0);
    tables[t.id] = {
      title: t.title,
      // key opens the account's page on the Users tab - when the row names
      // its SID, the identity the Users page keys an account by.
      rows: groups.map((g) => ({ ...g, ...hostFields(g.hosts.list()), key: g.sid ? String(g.sid).toUpperCase() : '', value: g.account, search: t.keep.map((k) => g[k]).join(' ') }))
        .sort((a, b) => (t.rarest ? a.seen_n - b.seen_n : 0) || total(b) - total(a) || t.key.map((k) => a[k]).join(' ').localeCompare(t.key.map((k) => b[k]).join(' '))),
    };
  }
  return { modules: [...modules].sort(), tables };
}

// logonInventory: each Logons table across the hosts (see LOGON_TABLES)
// and the fleet's daily trend: logons and failed logons per day, summed
// over the hosts.
function logonInventory(runs) {
  const { modules, tables } = roleTables(runs, LOGON_TABLES);
  const days = new Map();
  for (const { row } of datasetRows(runs, (ds) => ds.role === 'activity.daily').rows) {
    const d = days.get(row.day) || { day: row.day, logons: 0, failures: 0 };
    d[row.outcome === 'failure' ? 'failures' : 'logons'] += row.count || 0;
    days.set(row.day, d);
  }
  return { modules, tables, trend: [...days.values()].sort((a, b) => a.day.localeCompare(b.day)) };
}

// The antivirus exclusions (Signal's inventory.av_exclusions role, schema
// 13): every exclusion configured on a host - each one something its
// antivirus does not scan, so all of them are listed, not only the ones a
// rule flags. Whether a host's exclusions were read at all comes from the
// run's evidence sources (av_exclusion): a host whose list could not be
// read is unknown, never "no exclusions"; a host that did not collect them
// (the module did not run) is left out, as on every other panel.
const AV_EXCLUSIONS_ROLE = 'inventory.av_exclusions';
const AV_EXCLUSION_EVIDENCE = 'av_exclusion';

// exclusionStateOf is whether a run's antivirus exclusions were read
// (state read, n of them) or could not be (unknown, with Signal's reason);
// null when they were not collected at all (the module did not run, or an
// older Signal).
function exclusionStateOf(run) {
  const src = (run.sources || []).find((s) => s.evidence === AV_EXCLUSION_EVIDENCE);
  if (!src) return null;
  if (src.status !== 'read') return { state: 'unknown', n: null, reason: src.reason || 'not read' };
  let n = 0;
  for (const r of Object.values(run.modules || {})) for (const d of r.datasets || []) if (d.role === AV_EXCLUSIONS_ROLE) n += d.rows.length;
  return { state: 'read', n, reason: '' };
}

// exclusionFlags is the rules that flagged an exclusion on a run: its
// findings whose observation came from av_exclusion evidence about the
// exclusion (its entity; schema 16 names the signal by kind and exclusion).
function exclusionFlags(run, value) {
  const out = [];
  for (const r of Object.values(run.modules || {})) {
    for (const f of r.findings || []) {
      if ((f.observations || []).some((o) => o.source && o.source.evidence === AV_EXCLUSION_EVIDENCE && (o.entity || o.value) === value)) out.push({ rule_id: f.rule_id, severity: f.severity });
    }
  }
  return out;
}

// avExclusionInventory: each exclusion (product, kind, exclusion - letter case
// folded, as Windows compares paths) with the hosts it is configured on
// and the rules that flagged it, flagged ones first; and the state of every
// selected host that collected them - how many, or why they are unknown.
function avExclusionInventory(runs) {
  const { rows, modules } = datasetRows(runs, (ds) => ds.role === AV_EXCLUSIONS_ROLE);
  const groups = groupBy(rows, ({ row }) => [row.product, row.kind, String(row.exclusion).toLowerCase()].join('\u0000'),
    ({ row }) => ({ product: row.product, kind: row.kind, exclusion: row.exclusion, hosts: new HostSet(), flagged: new Map() }),
    (g, { row, run }) => {
      g.hosts.add(run);
      for (const f of exclusionFlags(run, row.exclusion)) g.flagged.set(f.rule_id, f);
    });
  const STATE_RANK = { read: 0, unknown: 1 };
  return {
    modules,
    rows: groups.map((g) => {
      const flagged = [...g.flagged.values()].sort((a, b) => a.rule_id.localeCompare(b.rule_id));
      return { product: g.product, kind: g.kind, exclusion: g.exclusion, ...hostFields(g.hosts.list()), flagged_by: flagged, flagged_rules: flagged.map((f) => f.rule_id).join('; ') };
    }).sort((a, b) => (b.flagged_by.length > 0) - (a.flagged_by.length > 0) || b.seen_n - a.seen_n || String(a.exclusion).localeCompare(String(b.exclusion))),
    hosts: runs.flatMap((run) => { const st = exclusionStateOf(run); return st ? [{ run_id: run.run_id, ...hostMeta(run), ...st }] : []; })
      .sort((a, b) => STATE_RANK[a.state] - STATE_RANK[b.state] || (b.n || 0) - (a.n || 0) || a.host.localeCompare(b.host)),
  };
}

// exclusionSummary is the fleet's exclusions in numbers, over an
// avExclusionInventory: hosts read, with exclusions, unknown; exclusions in all and distinct ones.
function exclusionSummary(inv) {
  const read = inv.hosts.filter((x) => x.state === 'read');
  return {
    hosts_read: read.length, hosts_with: read.filter((x) => x.n > 0).length,
    hosts_unknown: inv.hosts.filter((x) => x.state === 'unknown').length,
    total: read.reduce((n, x) => n + x.n, 0), distinct: inv.rows.length,
    flagged: inv.rows.filter((r) => r.flagged_by.length).length,
  };
}

// recoveryInventory is every host's ways back (Backup's inventory.recovery,
// schema 41): one row per host and mechanism, as Signal words its state,
// with the Backup rules that flagged it on that host (a signal about the
// mechanism, by its name); per host, whether its collection has a shadow
// copy of any volume and whether a rule says recovery was taken away.
function recoveryInventory(runs) {
  const found = datasetRows(runs, (ds) => ds.role === 'inventory.recovery');
  const flags = new Map(); // run -> mechanism -> rule IDs
  for (const run of runs) {
    const byMechanism = new Map();
    for (const f of ((run.modules || {}).Backup || {}).findings || []) {
      for (const o of f.observations || []) {
        // A recovery mechanism by its name; a service recovery runs on by its
        // key, as the table names it in parentheses: "... (VSS)".
        const svc = (o.fields || {})['service.key'];
        const m = svc ? `(${String(svc).toLowerCase()})` : o.subject && o.subject.type === 'recovery' ? o.subject.display : '';
        if (m) byMechanism.set(m, [...new Set([...(byMechanism.get(m) || []), f.rule_id])]);
      }
    }
    flags.set(run, byMechanism);
  }
  const rows = found.rows.map(({ row, run }) => {
    const key = String(row.mechanism || '').match(/\([^)]+\)$/);
    const rules = flags.get(run).get(row.mechanism) || (key && flags.get(run).get(key[0].toLowerCase())) || [];
    return { ...hostMeta(run), run_id: run.run_id, mechanism: row.mechanism || '', recovery_state: row.state || '', decided_by: row.decided_by || '',
      storage: row.storage || '', point_in_time: row.point_in_time || '', flagged_by: rules.map((rule_id) => ({ rule_id })), flagged_n: rules.length };
  }).sort((a, b) => b.flagged_n - a.flagged_n || a.host.localeCompare(b.host) || a.mechanism.localeCompare(b.mechanism));
  const hosts = new Set(found.rows.map(({ run }) => run.run_id));
  const withCopies = new Set(rows.filter((r) => r.mechanism.startsWith('Shadow copies on ') && /^\d/.test(r.recovery_state)).map((r) => r.run_id));
  const takenAway = new Set(rows.filter((r) => r.flagged_n).map((r) => r.run_id));
  return { modules: [...found.modules].sort(), rows, summary: { hosts: hosts.size, with_copies: withCopies.size, taken_away: takenAway.size } };
}

// inventories builds every inventory for a set of runs (the host filter's
// selection) and modules (the module filter's; all when empty), plus the
// page's summary numbers and the latest collection time (the reference
// point of the "first seen within" filter).
function inventories(runs, modules) {
  const scoped = withModules(runs, modules);
  const inv = {
    host_count: runs.length,
    collected_at: runs.reduce((t, r) => (r.started && r.started > t ? r.started : t), ''),
    audit_policy: auditPolicyInventory(scoped),
    event_ids: eventIdInventory(scoped),
    audit_policy_changes: auditPolicyChangeInventory(scoped),
    logging_policy: loggingPolicyInventory(scoped),
    event_logs: eventLogInventory(scoped),
    logons: logonInventory(scoped),
    network: roleTables(scoped, NETWORK_TABLES),
    av_exclusions: avExclusionInventory(scoped),
    recovery: recoveryInventory(scoped),
    topology: { modules: ['Network'], ...topology(scoped) },
  };
  inv.av_exclusions.summary = exclusionSummary(inv.av_exclusions);
  const absent = (r) => (r.statuses.absent || []).length + (r.statuses.absent_common || []).length > 0;
  inv.summary = {
    hosts: runs.length,
    event_ids_present: inv.event_ids.rows.filter((r) => r.present.length).length,
    event_ids_absent_somewhere: inv.event_ids.rows.filter(absent).length,
    gp_not_in_force: inv.audit_policy.rows.filter((r) => r.gp_off.length).length,
    logs_turned_off: inv.event_logs.rows.filter((r) => String(r.recording).startsWith('no - ')).length,
  };
  return inv;
}

// onHost keeps an inventory's rows seen on one host (a run ID), while each
// row keeps its fleet-wide host list - so a host's page shows its values
// with how common each is across the fleet.
const onHost = (rows, runId) => (runId ? rows.filter((r) => (r.hosts || []).some((x) => x.run_id === runId)) : rows);

// sortRows orders rows by one of their fields, numbers numerically.
function sortRows(rows, key, dir) {
  if (!key) return rows;
  const sign = dir === 'desc' ? -1 : 1;
  return rows.slice().sort((a, b) => {
    const x = a[key], y = b[key];
    return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x ?? '').localeCompare(String(y ?? ''))) * sign;
  });
}

// page is one page of rows: offset/limit (limit 0: every row - the CSV
// export), with the number of matching rows.
function page(rows, params) {
  const offset = Number(params.offset) || 0;
  const limit = Number(params.limit) || 0;
  return { total: rows.length, rows: limit ? rows.slice(offset, offset + limit) : rows };
}

// queryRows is one page of an inventory (a logon table), with every
// filter applied on the server: on_host (only rows seen on that run - see
// onHost), q (text in any shown field - a row's search text, when it has
// one), seen_hosts / max_pct (rarity: seen on exactly N hosts, or on less
// than P% of the selected hosts), new_days (first seen within N days before
// the latest collection), then sort/dir and offset/limit. total is the
// number of matching rows, total_all the inventory's size before filtering.
function queryRows(allRows, params, ctx) {
  const rows = onHost(allRows, params.on_host);
  const q = String(params.q || '').toLowerCase();
  const seenHosts = Number(params.seen_hosts) || 0;
  const maxPct = Number(params.max_pct) || 0;
  const newDays = Number(params.new_days) || 0;
  const since = newDays && ctx.collected_at ? new Date(Date.parse(ctx.collected_at) - newDays * 86400000).toISOString() : '';
  const text = (r) => [r.search || r.value, ...(r.hosts || []).map((x) => x.host), ...(r.modules || []), ...(r.datasets || [])].join('\n').toLowerCase();
  const out = rows.filter((r) => {
    if (seenHosts && r.hosts.length !== seenHosts) return false;
    if (maxPct && (r.hosts.length * 100) / Math.max(1, ctx.host_count) >= maxPct) return false;
    if (since && !(r.first_seen && r.first_seen >= since)) return false;
    return !q || text(r).includes(q);
  });
  const asked = filterRequest(out, params);
  if (asked.distinct) return asked;
  return { ...page(sortRows(asked.rows, params.sort, params.dir), params), total_all: rows.length };
}

// PAGE_DATA is what each data page shows: the roles (or names) of the
// datasets it reads. Pages not named here (Overview, Signals, Hosts, Rules,
// Modules) always have something to show.
const PAGE_DATA = {
  autoruns: ['inventory.persistence'],
  applications: ['inventory.applications'],
  extensions: ['inventory.browser_extensions'],
  grouppolicy: ['inventory.group_policy'],
  remoteaccess: ['inventory.remote_tools', 'activity.remote_sessions', 'inventory.remote_paths'],
  webservers: ['inventory.web_apps', 'inventory.web_files'],
  network: ['activity.listeners', 'activity.remote_addresses', 'activity.internal_addresses'],
  topology: ['inventory.network_adapters'],
  protection: [AV_EXCLUSIONS_ROLE],
  recovery: ['inventory.recovery'],
  audit: ['audit_policy', 'logging_policy', 'event_logs', 'activity.audit_policy_changes'],
  users: ['entity.account', 'activity.logons', 'activity.logon_failures', 'activity.privileged_logons', 'activity.explicit_credentials',
    'activity.account_daily', 'activity.rdp_sessions', 'activity.rdp_outbound'],
};

// emptyPages lists the data pages none of the runs has a row for - their
// module did not run, or found nothing - for the navigation to leave out.
// A stacked inventory's rows are in its table: `indexed` counts them.
function emptyPages(runs) {
  const filled = new Set();
  for (const run of runs) {
    for (const result of Object.values(run.modules || {})) {
      for (const ds of result.datasets || []) if (ds.rows.length || ds.indexed) filled.add(ds.role).add(ds.name);
    }
  }
  // Protection states each host's exclusions - none, or unknown and why -
  // which is worth showing with no exclusion listed (unknown is never no).
  if (runs.some(exclusionStateOf)) filled.add(AV_EXCLUSIONS_ROLE);
  return Object.keys(PAGE_DATA).filter((page) => !PAGE_DATA[page].some((x) => filled.has(x)));
}

module.exports = { PAGE_DATA, emptyPages, inventories, onHost, queryRows, sortRows, page, avExclusionInventory, exclusionSummary };
