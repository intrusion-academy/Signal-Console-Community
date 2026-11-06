// The inventories API (the Inventories page - see model/inventories.js):
//
//   GET /api/inventories?hosts=<run ids>&modules=<names>&on_host=<run id>
//     the page's summary numbers and small inventories (audit policy,
//     event IDs, audit policy changes, antivirus exclusions) whole.
//   GET /api/inventories/pages
//     the data pages no host's latest collection has data for.
//   GET /api/inventories/persistence?...the same parameters
//     one page of the persistent entries stacked across the hosts, rarest
//     first (src/persistence.js - SQL over the persistence table).
//   GET /api/inventories/applications?...the same parameters
//     one page of the installed applications stacked across the hosts,
//     rarest first (src/applications.js - SQL over the applications table).
//   GET /api/inventories/extensions?...the same parameters
//     one page of the browser extensions stacked across the hosts, rarest
//     first (src/extensions.js - SQL over the extensions table).
//   GET /api/inventories/grouppolicy?...the same parameters
//     one page of the Group Policy objects stacked across the hosts, rarest
//     first, each with its domain status (src/grouppolicy.js).
//   GET /api/inventories/remotetools?...the same parameters
//     one page of the remote access products stacked across the hosts,
//     rarest first (src/remoteaccess.js).
//   GET /api/inventories/remotepeers?...the same parameters
//     one page of the remote parties (a product's ID for the other side of
//     a session) stacked across the hosts, most hosts first.
//   GET /api/inventories/remotepaths?...the same parameters
//     one page of Windows' own ways in stacked across the hosts, rarest
//     first.
//   GET /api/inventories/websites?...the same parameters
//     one page of the web sites stacked across the hosts, rarest first
//     (src/web.js).
//   GET /api/inventories/webscripts?...the same parameters
//     one page of the scripts with webshell indicators stacked by path,
//     rarest first, the strongest confidence first among equals.
//   GET /api/inventories/logons/<table>?...the same parameters
//     one page of a logon inventory (table: logons, failures, explicit,
//     privileged, rdp_sessions, rdp_outbound); the fleet's daily logon
//     trend comes whole with GET /api/inventories.
//   GET /api/inventories/network/<table>?...the same parameters
//     one page of a network inventory (table: listeners, remote_addresses).
//
// hosts/modules narrow everything to the page's host and module filters
// (every host's latest collection / all modules when absent). on_host (a
// run ID) keeps only the values seen on that host while their host counts
// stay fleet-wide - the Hosts page's per-host inventories. Computed
// inventories are cached per selection (src/cache.js).
'use strict';

const express = require('express');
const cache = require('../cache');
const store = require('../store');
const persistence = require('../persistence');
const applications = require('../applications');
const extensions = require('../extensions');
const grouppolicy = require('../grouppolicy');
const remoteaccess = require('../remoteaccess');
const web = require('../web');
const flags = require('../flags');
const { onHost, queryRows, emptyPages } = require('../model');

const router = express.Router();

const list = (v) => (v ? String(v).split(',').filter(Boolean) : []);
const inventoriesFor = (query) => cache.inventories(list(query.hosts), list(query.modules));

router.get('/', (req, res) => {
  const inv = inventoriesFor(req.query);
  res.json({
    summary: inv.summary,
    host_count: inv.host_count,
    collected_at: inv.collected_at,
    audit_policy: inv.audit_policy,
    event_ids: inv.event_ids,
    audit_policy_changes: inv.audit_policy_changes,
    logging_policy: inv.logging_policy,
    event_logs: inv.event_logs,
    logons: { modules: inv.logons.modules, trend: inv.logons.trend, tables: tableTotals(inv.logons.tables, req.query.on_host) },
    network: { modules: inv.network.modules, tables: tableTotals(inv.network.tables, req.query.on_host) },
    persistence: {
      ...persistence.summary(moduleRuns(req.query, 'Persistence').filter((r) => !req.query.on_host || r.run_id === req.query.on_host)),
      modules: ['Persistence'],
    },
    applications: {
      ...applications.summary(moduleRuns(req.query, 'Applications').filter((r) => !req.query.on_host || r.run_id === req.query.on_host)),
      modules: ['Applications'],
      kev: (({ loaded, old, age_days: age, released }) => ({ loaded, old, age_days: age, released }))(require('../kev').status()), // the Known exploited column's catalog
    },
    extensions: {
      ...extensions.summary(moduleRuns(req.query, 'Browsers').filter((r) => !req.query.on_host || r.run_id === req.query.on_host)),
      modules: ['Browsers'],
    },
    recovery: { ...inv.recovery, rows: onHost(inv.recovery.rows, req.query.on_host) },
    topology: inv.topology,
    group_policy: groupPolicySummary(req.query),
    remote_access: remoteAccessSummary(req.query),
    web: webSummary(req.query),
    av_exclusions: {
      ...inv.av_exclusions,
      rows: flags.apply('av_exclusions', onHost(inv.av_exclusions.rows, req.query.on_host), (r) => r.flagged_by.map((f) => (f.title ? `${f.rule_id}: ${f.title}` : f.rule_id))),
      hosts: req.query.on_host ? inv.av_exclusions.hosts.filter((x) => x.run_id === req.query.on_host) : inv.av_exclusions.hosts,
    },
  });
});

// groupPolicySummary is the Group Policy inventory's size, with how many of
// its GPOs are not in their domain controller's SYSVOL any more.
function groupPolicySummary(query) {
  const runs = moduleRuns(query, 'Directory');
  const mine = runs.filter((r) => !query.on_host || r.run_id === query.on_host);
  const rows = grouppolicy.query(runs, { on_host: query.on_host }).rows;
  return { ...grouppolicy.summary(mine), not_in_sysvol: rows.filter((r) => r.not_in_sysvol).length, modules: ['Directory'] };
}

// remoteAccessSummary is the remote access inventories' size, with how
// many remote parties connected to more than one host.
function remoteAccessSummary(query) {
  const runs = moduleRuns(query, 'RemoteAccess');
  const mine = runs.filter((r) => !query.on_host || r.run_id === query.on_host);
  const peers = remoteaccess.peers.query(runs, { on_host: query.on_host }).rows;
  return {
    tools: remoteaccess.tools.summary(mine), paths: remoteaccess.paths.summary(mine),
    peers: { ...remoteaccess.peers.summary(mine), many_hosts: peers.filter((r) => r.seen_n > 1).length }, modules: ['RemoteAccess'],
  };
}

// webSummary is the web server inventories' size, with how many of the
// scripts are of high confidence.
function webSummary(query) {
  const runs = moduleRuns(query, 'Webshells');
  const mine = runs.filter((r) => !query.on_host || r.run_id === query.on_host);
  const scripts = web.scripts.query(runs, { on_host: query.on_host }).rows;
  return {
    sites: web.sites.summary(mine), scripts: { ...web.scripts.summary(mine), high: scripts.filter((r) => r.confidence === 'high').length },
    modules: ['Webshells'],
  };
}

// tableTotals is each table's title and row count, for its tab.
const tableTotals = (tables, host) => Object.fromEntries(Object.entries(tables).map(([id, t]) => [id, { title: t.title, total: onHost(t.rows, host).length }]));

// moduleRuns is the runs a query covers: the chosen ones, or every host's
// latest collection; none when the module filter leaves the module out.
function moduleRuns(query, module) {
  const mods = list(query.modules);
  if (mods.length && !mods.includes(module)) return [];
  const wanted = new Set(list(query.hosts));
  return wanted.size ? [...wanted].filter(store.has).map(store.get) : cache.latest();
}

// ruleFlags maps each value a module's rule signal names on runs in one of
// fields (lower case) to those rules - a row with it is flagged by them.
// Each rule is named with its title - "PERSIST-X: what it found" - so a
// flagged row says why.
// keyOf(signal, value) may narrow the key (default: the value alone).
function ruleFlags(runs, module, fields, keyOf = (s, v) => v) {
  const out = new Map();
  const titled = (s) => `${s.rule_id}: ${s.rule_title || s.title}`;
  const { signalsOf } = cache.collections();
  for (const run of runs) {
    for (const s of signalsOf(run.run_id)) {
      if (s.module !== module || s.suppressed_by) continue;
      for (const k of fields) {
        const p = s.fields && s.fields[k];
        if (!p) continue;
        const key = keyOf(s, String(p).toLowerCase());
        if (!out.has(key)) out.set(key, []);
        if (!out.get(key).some((x) => x.startsWith(`${s.rule_id}:`))) out.get(key).push(titled(s));
      }
    }
  }
  return out;
}

// GET /api/inventories/pages - the data pages with nothing to show in any
// host's latest collection (the navigation hides them).
router.get('/pages', (req, res) => {
  res.json({ empty: emptyPages(cache.latest()) });
});

router.get('/persistence', (req, res) => {
  const runs = moduleRuns(req.query, 'Persistence');
  // A signal that names its entry flags that entry only - by program alone,
  // a rule about one logon script flagged every entry running cmd.exe.
  const byEntry = (s, v) => (s.fields['persist.entry'] ? persistence.ruleKey(v, s.fields['persist.entry']) : v);
  res.json(persistence.query(runs, req.query, ruleFlags(runs, 'Persistence', ['persist.program', 'service.program', 'service.dll'], byEntry)));
});

router.get('/applications', (req, res) => {
  const runs = moduleRuns(req.query, 'Applications');
  res.json(applications.query(runs, req.query, ruleFlags(runs, 'Applications', ['app.name'])));
});

router.get('/grouppolicy', (req, res) => {
  const runs = moduleRuns(req.query, 'Directory');
  res.json(grouppolicy.query(runs, req.query, ruleFlags(runs, 'Directory', ['gpo.guid', 'directory.gpo'])));
});

router.get('/remotetools', (req, res) => {
  const runs = moduleRuns(req.query, 'RemoteAccess');
  res.json(remoteaccess.tools.query(runs, req.query, ruleFlags(runs, 'RemoteAccess', ['remote.product'])));
});

router.get('/remotepaths', (req, res) => {
  const runs = moduleRuns(req.query, 'RemoteAccess');
  res.json(remoteaccess.paths.query(runs, req.query, ruleFlags(runs, 'RemoteAccess', ['remote.path_value'])));
});

router.get('/remotepeers', (req, res) => {
  const runs = moduleRuns(req.query, 'RemoteAccess');
  res.json(remoteaccess.peers.query(runs, req.query, ruleFlags(runs, 'RemoteAccess', ['session.peer_id'])));
});

router.get('/websites', (req, res) => {
  const runs = moduleRuns(req.query, 'Webshells');
  res.json(web.sites.query(runs, req.query, ruleFlags(runs, 'Webshells', ['web.site'])));
});

router.get('/webscripts', (req, res) => {
  const runs = moduleRuns(req.query, 'Webshells');
  res.json(web.scripts.query(runs, req.query, ruleFlags(runs, 'Webshells', ['web.file'])));
});

router.get('/extensions', (req, res) => {
  const runs = moduleRuns(req.query, 'Browsers');
  res.json(extensions.query(runs, req.query, ruleFlags(runs, 'Browsers', ['extension.id'])));
});

// NETWORK_FLAGS is the signal field that flags a network table's row (its
// kind in src/flags.js): the listener's program, the other end's address.
const NETWORK_FLAGS = {
  listeners: { field: 'process.name', value: (r) => r.program },
  remote_addresses: { field: 'net.remote_address', value: (r) => r.address },
};

// One page of a logon or network table; a network table's rows carry their
// flags.
for (const group of ['logons', 'network']) {
  router.get(`/${group}/:table`, (req, res) => {
    const inv = inventoriesFor(req.query);
    const source = inv[group].tables[req.params.table];
    if (!source) return res.status(404).json({ error: `no such ${group} table` });
    const nf = group === 'network' && NETWORK_FLAGS[req.params.table];
    let rows = source.rows;
    if (nf) {
      const rules = ruleFlags(moduleRuns(req.query, 'Network'), 'Network', [nf.field]);
      rows = flags.apply(req.params.table, rows, (r) => rules.get(String(nf.value(r) || '').toLowerCase()) || []);
    }
    res.json(queryRows(rows, req.query, inv));
  });
}

module.exports = router;
