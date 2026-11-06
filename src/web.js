// The web server inventories (Signal's inventory.web_apps and
// inventory.web_files, schema 35), stacked across the fleet
// (src/stacked.js):
//
//   sites - one row per site: its server, name and folders (a web farm's
//     hosts serving the same site are one row) - what it listens on, what
//     it holds and runs as, when it was last deployed, its scripts with
//     indicators and the antivirus's detections in it; rarest first.
//   scripts - one row per server-side script with a webshell indicator, by
//     its path: its confidence, indicators and the requests IIS's log
//     records for it - rarest first, the strongest first among equals.
//
// A site is flagged when a Webshells rule's signal names it, a script when
// one names its path, or either when an analyst flagged it.
'use strict';

const stacked = require('./stacked');

// parse is a json_group_array's values, without the empty ones.
const parse = (v) => (v ? JSON.parse(v).filter((x) => x !== null && x !== '') : []);
const join = (v) => parse(v).join('; ');

const sites = stacked.of({
  table: 'web_apps',
  role: 'inventory.web_apps',
  group: "lower(server) || char(0) || lower(site) || char(0) || lower(roots)",
  select: `server, site, roots, json_group_array(DISTINCT nullif(version, '')) AS versions, json_group_array(DISTINCT nullif(bindings, '')) AS bindings,
    json_group_array(DISTINCT nullif(pools, '')) AS pools, json_group_array(DISTINCT nullif(identity, '')) AS identities,
    json_group_array(DISTINCT nullif(holds, '')) AS holds, json_group_array(DISTINCT nullif(files, '')) AS files,
    max(nullif(last_deployment, '')) AS last_deployment, json_group_array(DISTINCT nullif(newest_script, '')) AS newest,
    json_group_array(DISTINCT nullif(running, '')) AS running, json_group_array(DISTINCT nullif(flagged, '')) AS flagged_scripts,
    json_group_array(DISTINCT nullif(detections, '')) AS detections`,
  search: `server || ' ' || site || ' ' || roots || ' ' || bindings || ' ' || identity || ' ' || holds`,
  order: 'lower(server), lower(site)',
  flagKind: 'web_sites',
  ruleKey: (r) => String(r.site).toLowerCase(),
  shape: (r) => ({
    server: r.server, versions: join(r.versions), site: r.site, roots: r.roots, bindings: join(r.bindings), pools: join(r.pools), identities: join(r.identities),
    holds: join(r.holds), files: join(r.files), last_deployment: r.last_deployment || '', newest: join(r.newest), running: join(r.running),
    flagged_scripts: join(r.flagged_scripts), detections: join(r.detections), seen_n: r.seen_n, run_ids: r.run_ids, value: `${r.server} ${r.site}`,
  }),
});

// RANK orders confidences, strongest first.
const RANK = "CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END";

const scripts = stacked.of({
  table: 'web_files',
  role: 'inventory.web_files',
  group: 'lower(file)',
  select: `file, json_group_array(DISTINCT nullif(server || ' ' || site, ' ')) AS sites, json_group_array(DISTINCT nullif(url, '')) AS urls,
    min(${RANK}) AS rank, json_group_array(DISTINCT nullif(confidence, '')) AS confidences, json_group_array(DISTINCT nullif(indicators, '')) AS indicators,
    json_group_array(DISTINCT nullif(requests, '')) AS requests, min(nullif(created, '')) AS created, max(nullif(modified, '')) AS modified,
    json_group_array(DISTINCT nullif(size, '')) AS sizes`,
  search: `file || ' ' || url || ' ' || site || ' ' || indicators || ' ' || confidence`,
  order: `min(${RANK}), lower(file)`,
  flagKind: 'web_scripts',
  ruleKey: (r) => String(r.file).toLowerCase(),
  shape: (r) => ({
    file: r.file, sites: join(r.sites), urls: join(r.urls), confidence: ['high', 'medium', 'low'][r.rank] || '', indicators: join(r.indicators),
    requests: join(r.requests), created: r.created || '', modified: r.modified || '', sizes: join(r.sizes), seen_n: r.seen_n, run_ids: r.run_ids, value: r.file,
  }),
});

module.exports = { sites, scripts };
