// The applications inventory (Signal's inventory.applications, schema 25),
// stacked across the fleet (src/stacked.js) over the applications table:
// one row per application (name and publisher) - its versions, folders and
// users listed - with how many hosts have it, rarest first.
//
// An application is flagged when an Applications rule's signal names it on
// one of its hosts (by its name), when the console finds its product in
// CISA's Known Exploited Vulnerabilities catalog (src/kev.js), or when an
// analyst flagged it - by its name and publisher.
'use strict';

const db = require('./db');
const kev = require('./kev');

const stacked = require('./stacked').of({
  table: 'applications',
  role: 'inventory.applications',
  group: 'lower(name), lower(publisher)',
  select: `name, publisher, group_concat(DISTINCT nullif(version, '')) AS versions, group_concat(DISTINCT nullif(location, '')) AS location,
    min(nullif(installed, '')) AS installed, group_concat(DISTINCT nullif(user, '')) AS user, max(in_period = 'true') AS in_period`,
  search: `name || ' ' || publisher || ' ' || version || ' ' || location || ' ' || user || ' ' || sources`,
  order: 'lower(name)',
  flagKind: 'applications',
  ruleKey: (r) => String(r.name).toLowerCase(),
  consoleOf: (r) => r.kev_flags,
  // Each row's CVEs are checked once here (assess); consoleOf reads the result.
  shape: (r) => {
    const k = kev.assess(r);
    return {
      ...r, versions: r.versions || '', location: r.location || '', installed: r.installed || '', user: r.user || '', in_period: r.in_period ? 'yes' : 'no', value: r.name,
      kev: k.cves, kev_unchecked: k.unchecked, kev_flags: k.flags,
    };
  },
});

// consoleFlags is the console's flags of the applications on runs, as
// GET /api/flags lists them beside the analysts' - each with the runs
// (run_ids) that have the application.
function consoleFlags(runs) {
  const rows = db.open().prepare(`SELECT name, publisher, group_concat(DISTINCT nullif(version, '')) AS versions, group_concat(DISTINCT run_id) AS run_ids FROM applications
    WHERE run_id IN (SELECT value FROM json_each(?)) GROUP BY lower(name), lower(publisher)`).all(JSON.stringify(runs.map((r) => r.run_id)));
  const status = kev.status();
  return rows.flatMap((r) => kev.flagsOf(r).map((f) => ({
    kind: 'applications', key: '', label: r.publisher ? `${r.name} (${r.publisher})` : r.name, flagged_by: 'Console', at: status.file_time,
    reason: f.reason, source: 'console', rule: f.rule, where: 'Applications', page: 'applications', run_ids: r.run_ids.split(','),
  })));
}

module.exports = { ...stacked, consoleFlags };
