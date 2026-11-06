// A stacked inventory: one of Signal's inventories stacked across the fleet
// by SQL over its table (src/db.js) - one row per thing (its group), its
// values across the hosts listed, with how many hosts have it, rarest
// first by default: on a fleet of similar hosts, what only one host has
// stands out. src/applications.js and src/extensions.js are its specs.
//
// A row is flagged (src/flags.js) when a rule's signal names it on one of
// its hosts (ruleFlags, by spec.ruleKey), or when an analyst flagged it.
'use strict';

const db = require('./db');
const flags = require('./flags');
const { hostMeta } = require('./model/hosts');
const { sortRows, page } = require('./model/inventories');
const { filterRequest } = require('../public/js/columnFilter.js');

// A spec names: table (its SQL table), role (the dataset role it holds),
// group (the GROUP BY expression - one row per thing), select (the
// aggregates of a row, beside seen_n and its hosts), search (the text a
// free-text query looks in), order (the tie-break after rarity), flagKind
// (its kind in src/flags.js), ruleKey(row) (the lowercased value a rule's
// signal names it by) and shape(row, context) (the row as the page shows
// it). An optional context(runs) is computed once per query and handed to
// shape - what a row is compared with beyond its own values; an optional
// where (SQL) keeps only some rows of the table; mostFirst orders the
// most widespread first instead of the rarest; an optional consoleOf(row)
// is the console's own flags of a row ({rule, reason} - src/kev.js).

// query is one page of a stacked inventory over runs - the parameters of
// src/persistence.js's query. ruleFlags maps a row's ruleKey to the rules
// whose signals name it on these hosts.
function query(spec, runs, params, ruleFlags = new Map()) {
  const byId = new Map(runs.map((r) => [r.run_id, r]));
  const ofRuns = `FROM ${spec.table} WHERE run_id IN (SELECT value FROM json_each(?))${spec.where ? ' AND ' + spec.where : ''}`;
  const args = [JSON.stringify(runs.map((r) => r.run_id))];
  const q = String(params.q || '').toLowerCase();
  const where = q ? ` AND instr(lower(${spec.search}), ?) > 0` : '';
  if (q) args.push(q);
  const having = [];
  const seenHosts = Number(params.seen_hosts) || 0;
  const maxPct = Number(params.max_pct) || 0;
  if (seenHosts) having.push(`seen_n = ${seenHosts}`);
  if (maxPct) having.push(`seen_n * 100.0 / ${Math.max(1, runs.length)} < ${maxPct}`);
  if (params.on_host) having.push('sum(run_id = ?) > 0');
  const hargs = params.on_host ? [params.on_host] : [];
  const group = `GROUP BY ${spec.group}`;
  const conn = db.open();
  const totalAll = conn.prepare(`SELECT count(*) AS n FROM (SELECT 1 ${ofRuns}${where} ${group} ${params.on_host ? 'HAVING sum(run_id = ?) > 0' : ''})`).get(...args, ...hargs).n;
  const context = spec.context ? spec.context(runs) : undefined;
  const grouped = conn.prepare(`SELECT ${spec.select}, count(DISTINCT run_id) AS seen_n,
    CASE WHEN count(DISTINCT run_id) <= 50 THEN group_concat(DISTINCT run_id) END AS run_ids ${ofRuns}${where} ${group}
    ${having.length ? 'HAVING ' + having.join(' AND ') : ''} ORDER BY seen_n${spec.mostFirst ? ' DESC' : ''}, ${spec.order}`).all(...args, ...hargs)
    .map((r) => {
      const hosts = r.run_ids ? r.run_ids.split(',').map((id) => byId.get(id)).filter(Boolean).map((run) => ({ run_id: run.run_id, ...hostMeta(run) })) : [];
      return { ...spec.shape(r, context), run_ids: undefined, hosts, host_names: hosts.map((x) => x.host).join('; ') };
    });
  const flagged = flags.apply(spec.flagKind, grouped, (r) => ruleFlags.get(spec.ruleKey(r)) || [], spec.consoleOf);
  const asked = filterRequest(flagged, params);
  if (asked.distinct) return asked;
  return { ...page(sortRows(asked.rows, params.sort, params.dir), params), total_all: totalAll };
}

// summary is a stacked inventory's size over runs: its rows, distinct
// things, those on one host only, and how many runs have the table.
function summary(spec, runs) {
  const ids = JSON.stringify(runs.map((r) => r.run_id));
  const ofRuns = `FROM ${spec.table} WHERE run_id IN (SELECT value FROM json_each(?))${spec.where ? ' AND ' + spec.where : ''}`;
  const group = `GROUP BY ${spec.group}`;
  const conn = db.open();
  const total = conn.prepare(`SELECT count(*) AS n ${ofRuns}`).get(ids).n;
  const distinct = conn.prepare(`SELECT count(*) AS n FROM (SELECT 1 ${ofRuns} ${group})`).get(ids).n;
  const single = conn.prepare(`SELECT count(*) AS n FROM (SELECT 1 ${ofRuns} ${group} HAVING count(DISTINCT run_id) = 1)`).get(ids).n;
  const hosts = runs.filter((r) => Object.values(r.modules || {}).some((m) => (m.datasets || []).some((d) => d.role === spec.role))).length;
  return { total, distinct, single_host: single, hosts };
}

// of binds a spec: its query and summary.
const of = (spec) => ({
  query: (runs, params, ruleFlags) => query(spec, runs, params, ruleFlags),
  summary: (runs) => summary(spec, runs),
});

module.exports = { of };
