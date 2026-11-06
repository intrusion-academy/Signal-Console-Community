// The persistence inventory (Signal's inventory.persistence, schema 14),
// stacked across the fleet by SQL over the persistence table (src/db.js):
// one row per (location, entry, program) - an entry configured the same way
// on several hosts is one row, with how many hosts have it - rarest first
// by default, as Kansa and Autoruns users read it: on a fleet of similar
// hosts, what only one host has stands out.
//
// An entry is flagged (src/flags.js) when a rule's signal names its program
// on one of its hosts, or when an analyst flagged it - by the entry's
// identity: location, entry and program.
'use strict';

const db = require('./db');
const flags = require('./flags');
const { hostMeta } = require('./model/hosts');
const { sortRows, page } = require('./model/inventories');
const { filterRequest } = require('../public/js/columnFilter.js');

// query is one page of the stacked inventory over runs (the latest
// collection of each selected host): params q (text in any column),
// seen_hosts / max_pct (rarity: exactly N hosts, or under P%), on_host (only entries that run has - each
// still counted across every selected host), filters / distinct (column
// filters - public/js/columnFilter.js), sort / dir, offset / limit (limit
// 0: every row). ruleFlags maps a program (lower case) to the rules whose
// signals name it on these hosts. Each row lists its hosts when there are
// at most 50.
// One row per entry configured the same way: its place, name and program,
// and what it runs (the command), the file's SHA-256 and its signature's
// state - so a host whose entry runs a different command, or a different
// file under the same name, is a row of its own, rare, not hidden under the
// others' (the user, 2026-11-04).
// ruleKey is the key of a rule's flag on one entry: its program and entry.
const ruleKey = (program, entry) => `${String(program).toLowerCase()}\u0000${String(entry || '').toLowerCase()}`;

function query(runs, params, ruleFlags = new Map()) {
  const ids = JSON.stringify(runs.map((r) => r.run_id));
  const byId = new Map(runs.map((r) => [r.run_id, r]));
  const where = [];
  const args = [ids];
  const q = String(params.q || '').toLowerCase();
  if (q) {
    where.push(`instr(lower(location || ' ' || entry || ' ' || command || ' ' || program || ' ' || signer || ' ' || user || ' ' || sha256), ?) > 0`);
    args.push(q);
  }
  const having = [];
  const seenHosts = Number(params.seen_hosts) || 0;
  const maxPct = Number(params.max_pct) || 0;
  if (seenHosts) having.push(`seen_n = ${seenHosts}`);
  if (maxPct) having.push(`seen_n * 100.0 / ${Math.max(1, runs.length)} < ${maxPct}`);
  if (params.on_host) having.push('sum(run_id = ?) > 0');
  const hargs = params.on_host ? [params.on_host] : [];
  const base = `FROM persistence WHERE run_id IN (SELECT value FROM json_each(?)) ${where.length ? 'AND ' + where.join(' AND ') : ''}
    GROUP BY location, lower(entry), lower(program), command, lower(sha256), signature`;
  const conn = db.open();
  const totalAll = conn.prepare(`SELECT count(*) AS n FROM (SELECT 1 ${base} ${params.on_host ? 'HAVING sum(run_id = ?) > 0' : ''})`).get(...args, ...hargs).n;
  const grouped = conn.prepare(`SELECT location, entry, command, program, min(signer) AS signer, signature, min(user) AS user,
    min(sources) AS sources, sha256, count(DISTINCT run_id) AS seen_n,
    CASE WHEN count(DISTINCT run_id) <= 50 THEN group_concat(DISTINCT run_id) END AS run_ids ${base}
    ${having.length ? 'HAVING ' + having.join(' AND ') : ''} ORDER BY seen_n, location, entry`).all(...args, ...hargs)
    .map((r) => {
      const hosts = r.run_ids ? r.run_ids.split(',').map((id) => byId.get(id)).filter(Boolean).map((run) => ({ run_id: run.run_id, ...hostMeta(run) })) : [];
      return { ...r, run_ids: undefined, value: r.entry, hosts, host_names: hosts.map((x) => x.host).join('; ') };
    });
  const rulesOf = (r) => {
    const program = String(r.program).toLowerCase();
    return [...new Set([...(ruleFlags.get(program) || []), ...(ruleFlags.get(ruleKey(program, r.entry)) || [])])];
  };
  const flagged = flags.apply('autoruns', grouped, rulesOf);
  const asked = filterRequest(flagged, params);
  if (asked.distinct) return asked;
  return { ...page(sortRows(asked.rows, params.sort, params.dir), params), total_all: totalAll };
}

// summary is the inventory's size over runs: entries, distinct entries,
// and how many runs have the table at all (ran Persistence).
function summary(runs) {
  const ids = JSON.stringify(runs.map((r) => r.run_id));
  const conn = db.open();
  const total = conn.prepare('SELECT count(*) AS n FROM persistence WHERE run_id IN (SELECT value FROM json_each(?))').get(ids).n;
  const distinct = conn.prepare('SELECT count(*) AS n FROM (SELECT 1 FROM persistence WHERE run_id IN (SELECT value FROM json_each(?)) GROUP BY location, lower(entry), lower(program), command, lower(sha256), signature)').get(ids).n;
  const single = conn.prepare(`SELECT count(*) AS n FROM (SELECT 1 FROM persistence WHERE run_id IN (SELECT value FROM json_each(?))
    GROUP BY location, lower(entry), lower(program), command, lower(sha256), signature HAVING count(DISTINCT run_id) = 1)`).get(ids).n;
  const hosts = runs.filter((r) => Object.values(r.modules || {}).some((m) => (m.datasets || []).some((d) => d.role === 'inventory.persistence'))).length;
  return { total, distinct, single_host: single, hosts };
}

module.exports = { query, summary, ruleKey };
