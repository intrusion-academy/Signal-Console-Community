// The Group Policy inventory (Signal's inventory.group_policy, schema 32),
// stacked across the fleet (src/stacked.js) over the group_policy table:
// one row per GPO (its GUID - the same on every host of a domain) - its
// names, versions, links, what it deploys and who changed it - with how
// many hosts have it, rarest first.
//
// A domain controller's run lists every GPO in its SYSVOL; a member's,
// every GPO Group Policy applied to it. Their comparison is the row's
// domain status: a GPO a member applied that is not in the SYSVOL of a
// controller of its domain collected after it last applied there was
// deleted since, or has not replicated to that controller - Signal cannot
// see this on one host (it never queries the directory).
//
// A GPO is flagged when a Directory rule's signal names it (by its GUID),
// or when an analyst flagged it.
'use strict';

const db = require('./db');

// parse is a json_group_array's values, without the nulls.
const parse = (v) => (v ? JSON.parse(v).filter((x) => x !== null && x !== '') : []);

// domainOf is the DNS domain a distinguished name is in ("OU=x,DC=corp,
// DC=local" -> corp.local), or "".
const domainOf = (dn) => (String(dn).match(/DC=([^,;()\s]+)/gi) || []).map((p) => p.slice(3)).join('.').toLowerCase();

// SYSVOL_DOMAIN finds the domain in a controller's read_from
// ("SYSVOL (C:\Windows\SYSVOL\sysvol\corp.local\Policies\{...})").
const SYSVOL_DOMAIN = /sysvol\\([^\\]+)\\Policies\\/i;

// controllers are the domain controllers among runs, each with its domain
// (from its SYSVOL path) and when it was collected.
function controllers(runs) {
  const dcs = runs.filter((r) => r.host && r.host.is_domain_controller);
  if (!dcs.length) return [];
  const stmt = db.open().prepare("SELECT read_from FROM group_policy WHERE run_id = ? AND read_from LIKE 'SYSVOL (%' LIMIT 1");
  return dcs.map((r) => {
    const row = stmt.get(r.run_id);
    const m = row && SYSVOL_DOMAIN.exec(row.read_from);
    return { run_id: r.run_id, host: r.host.hostname, started: r.started || '', domain: m ? m[1].toLowerCase() : '' };
  }).filter((d) => d.domain);
}

// statusOf words a GPO's domain status from its SYSVOL presence, the
// domains its links name, and when a member last applied it.
function statusOf(r, dcs) {
  const inSysvol = parse(r.sysvol_runs);
  if (inSysvol.length) {
    const names = dcs.filter((d) => inSysvol.includes(d.run_id)).map((d) => d.host);
    return { status: `in SYSVOL${names.length ? ' (' + names.join(', ') + ')' : ''}`, missing: false };
  }
  const domains = new Set(parse(r.links).flatMap((l) => l.split(';')).map(domainOf).filter(Boolean));
  const mine = dcs.filter((d) => domains.has(d.domain));
  if (!mine.length) return { status: '', missing: false };
  const later = mine.filter((d) => r.member_applied && d.started > r.member_applied);
  if (!later.length) {
    return { status: `applied after ${mine.map((d) => d.host).join(', ')} was collected - not compared`, missing: false };
  }
  const when = later.map((d) => `${d.host}, collected ${d.started.slice(0, 16).replace('T', ' ')} UTC`).join('; ');
  return { status: `not in its domain controller's SYSVOL (${when}) - deleted after it applied here, or not replicated to that controller`, missing: true };
}

module.exports = {
  ...require('./stacked').of({
    table: 'group_policy',
    role: 'inventory.group_policy',
    group: 'upper(guid)',
    select: `upper(guid) AS guid, json_group_array(DISTINCT nullif(name, '')) AS names, json_group_array(DISTINCT nullif(version, '')) AS versions,
      json_group_array(DISTINCT nullif(links, '')) AS links, json_group_array(DISTINCT nullif(deploys, '')) AS deploys,
      json_group_array(DISTINCT nullif(extensions, '')) AS extensions, json_group_array(DISTINCT nullif(changed_by, '')) AS changed_by,
      min(nullif(created, '')) AS created, max(nullif(changed, '')) AS changed, max(nullif(applied, '')) AS applied, max(in_period = 'true') AS in_period,
      json_group_array(DISTINCT CASE WHEN read_from LIKE 'SYSVOL (%' THEN run_id END) AS sysvol_runs,
      max(CASE WHEN read_from NOT LIKE 'SYSVOL (%' THEN nullif(applied, '') END) AS member_applied`,
    search: `guid || ' ' || name || ' ' || links || ' ' || deploys || ' ' || changed_by || ' ' || extensions`,
    order: 'upper(guid)',
    flagKind: 'group_policy',
    ruleKey: (r) => String(r.guid).toLowerCase(),
    context: controllers,
    shape: (r, dcs) => {
      const { status, missing } = statusOf(r, dcs || []);
      return {
        guid: r.guid, names: parse(r.names).join('; '), versions: parse(r.versions).join('; '), links: parse(r.links).join('; '),
        deploys: parse(r.deploys).join('; '), extensions: parse(r.extensions).join('; '), changed_by: parse(r.changed_by).join('; '),
        created: r.created || '', changed: r.changed || '', applied: r.applied || '', in_period: r.in_period ? 'yes' : 'no',
        domain_status: status, not_in_sysvol: missing, seen_n: r.seen_n, run_ids: r.run_ids, value: r.guid,
      };
    },
  }),
  domainOf,
};
