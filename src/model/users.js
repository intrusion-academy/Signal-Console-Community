// Users: every account that used the fleet's hosts, one profile each - like
// a host - from what each host's latest collection states about it.
//
// An account is known by its SID when any source gives one (the same domain
// account on many hosts is one user), otherwise by DOMAIN\name. It is built
// from the Users module's accounts (dataset role entity.account: how the
// host knows it - its account database, the Administrators group, a profile,
// an open session) and the Logons module's logon tables (activity.*: how it
// logged on, failed, and its daily trend), matched by SID or, for an event
// that carries none, by name on the same host. A failed logon never creates
// a user: the account may not exist (a spray tries made-up names).
//
// The accounts both modules left out (accounts.excluded: Windows' own
// identities, groups, computers, unused default accounts) are listed apart,
// with the reason, so nothing is hidden without saying why. What a host
// notes about an account that is not a signal (entity.account's notes: the
// built-in Administrator enabled, a profile folder no account owns) is
// carried per host and on the user.
'use strict';

const { HostSet, hostMeta } = require('./hosts');
const { isOpen } = require('./triage');
const { mentionsAccount } = require('./signalQuery');

// rowsOf lists a run's rows of the datasets with a role, as objects.
function rowsOf(run, role) {
  const out = [];
  for (const [module, result] of Object.entries(run.modules || {})) {
    for (const ds of result.datasets || []) {
      if (ds.role !== role) continue;
      for (const r of ds.rows) out.push({ module, ...Object.fromEntries(ds.columns.map((c, i) => [c, r[i]])) });
    }
  }
  return out;
}

const upper = (s) => String(s || '').toUpperCase();
const keyOf = (sid, account) => (sid ? upper(sid) : upper(account));
const later = (a, b) => (!a || (b && b > a) ? b || a : a);
const earlier = (a, b) => (!a || (b && b < a) ? b || a : a);

// userInventory builds every user of the given runs (each host's latest),
// with its per-host detail, and the excluded accounts. signalsOf(run_id)
// gives a run's signals (for each user's open-signal count).
function userInventory(runs, signalsOf) {
  const users = new Map();
  const userOf = (key, run) => {
    if (!users.has(key)) users.set(key, { key, sid: '', names: new Set(), kind: '', scope: '', hosts: new Map(), trend: new Map(), logonRows: [], failureRows: [], explicitRows: [] });
    const u = users.get(key);
    if (!u.hosts.has(run.run_id)) {
      u.hosts.set(run.run_id, { run_id: run.run_id, ...hostMeta(run), sources: new Set(), enabled: '', admin: false, groups: '', profile_path: '',
        first_seen: '', last_seen: '', logged_on_now: false, session: '', logons: 0, failures: 0, privileged: 0, microsoft_account: '', notes: '', changes: '' });
    }
    return { u, h: u.hosts.get(run.run_id) };
  };
  const excluded = new Map();

  for (const run of runs) {
    const byName = new Map(); // DOMAIN\name (upper) -> user key, on this host
    for (const a of rowsOf(run, 'entity.account')) {
      const key = keyOf(a.sid, a.account);
      const { u, h } = userOf(key, run);
      u.sid = u.sid || upper(a.sid);
      if (a.account && !a.account.startsWith('S-1-')) u.names.add(a.account);
      u.kind = u.kind || a.kind;
      u.scope = a.scope || u.scope;
      String(a.sources || '').split('; ').filter(Boolean).forEach((s) => h.sources.add(s));
      Object.assign(h, {
        enabled: a.enabled, admin: a.admin === true, groups: a.groups || '', profile_path: a.profile_path || '',
        first_seen: earlier(h.first_seen, a.first_seen), last_seen: later(h.last_seen, a.last_seen),
        logged_on_now: a.logged_on_now === true, session: a.session || '', microsoft_account: a.microsoft_account || '',
        notes: a.notes || '', // schema 10: what to know that is not a signal
        changes: a.changes || '', // schema 19: the Security log's account changes, with who made each
      });
      byName.set(upper(a.account), key);
    }
    for (const l of rowsOf(run, 'activity.logons')) {
      const key = l.sid ? upper(l.sid) : byName.get(upper(l.account)) || upper(l.account);
      const { u, h } = userOf(key, run);
      u.sid = u.sid || upper(l.sid);
      u.names.add(l.account);
      u.kind = u.kind || l.kind;
      u.scope = u.scope || l.scope;
      byName.set(upper(l.account), key);
      h.sources.add('logon events');
      h.logons += l.count;
      h.first_seen = earlier(h.first_seen, l.first_seen);
      h.last_seen = later(h.last_seen, l.last_seen);
      u.logonRows.push({ ...l, ...hostMeta(run), run_id: run.run_id });
    }
    for (const f of rowsOf(run, 'activity.logon_failures')) {
      const key = f.sid ? upper(f.sid) : byName.get(upper(f.account));
      if (!key || !users.has(key)) continue; // an account this host does not know: the Logons inventory lists it
      const { u, h } = userOf(key, run);
      h.failures += f.count;
      u.failureRows.push({ ...f, ...hostMeta(run), run_id: run.run_id });
    }
    for (const p of rowsOf(run, 'activity.privileged_logons')) {
      const key = p.sid ? upper(p.sid) : byName.get(upper(p.account));
      if (key && users.has(key)) userOf(key, run).h.privileged += p.count;
    }
    for (const x of rowsOf(run, 'activity.explicit_credentials')) {
      const keys = new Set([x.account, x.subject].map((who) => byName.get(upper(who))).filter(Boolean));
      for (const key of keys) users.get(key).explicitRows.push({ ...x, ...hostMeta(run), run_id: run.run_id });
    }
    for (const d of rowsOf(run, 'activity.account_daily')) {
      const key = byName.get(upper(d.account));
      if (!key) continue;
      const t = users.get(key).trend;
      const day = t.get(d.day) || { day: d.day, logons: 0, failures: 0 };
      day.logons += d.logons;
      day.failures += d.failures;
      t.set(d.day, day);
    }
    for (const e of rowsOf(run, 'accounts.excluded')) {
      const k = `${upper(e.account)}\u0000${e.reason}`;
      if (!excluded.has(k)) excluded.set(k, { account: e.account, sid: e.sid || '', kind: e.kind, reason: e.reason, hosts: new HostSet(), sources: new Set() });
      excluded.get(k).hosts.add(run);
      excluded.get(k).sources.add(`${e.module}: ${e.sources}`);
    }
  }

  const signalsByRun = new Map(runs.map((r) => [r.run_id, signalsOf(r.run_id).filter(isOpen)]));
  const rows = [...users.values()].map((u) => {
    const hosts = [...u.hosts.values()].sort((a, b) => a.host.localeCompare(b.host));
    const names = [...u.names];
    const account = names.sort((a, b) => a.length - b.length || a.localeCompare(b))[0] || u.sid;
    const ids = new Set([...names.map(upper), u.sid].filter(Boolean));
    const signals = hosts.reduce((n, h) => n + (signalsByRun.get(h.run_id) || []).filter((s) => mentionsAccount(s, ids)).length, 0);
    const sum = (k) => hosts.reduce((n, h) => n + (h[k] || 0), 0);
    return {
      key: u.key, account, sid: u.sid, kind: u.kind, scope: u.scope || 'unknown', other_names: names.filter((n) => n !== account),
      ids: [...ids], // its names and SID: the Signals query's account filter
      hosts: hosts.map((h) => ({ run_id: h.run_id, host: h.host, os: h.os, os_build: h.os_build, role: h.role })),
      host_detail: hosts.map((h) => ({ ...h, sources: [...h.sources].sort().join('; ') })),
      seen_n: hosts.length, host_names: hosts.map((h) => h.host).join('; '),
      admin_n: hosts.filter((h) => h.admin).length, logged_on_n: hosts.filter((h) => h.logged_on_now).length,
      sources: [...new Set(hosts.flatMap((h) => [...h.sources]))].sort().join('; '),
      logons: sum('logons'), failures: sum('failures'), privileged: sum('privileged'), signals_n: signals,
      notes: [...new Set(hosts.flatMap((h) => h.notes.split('; ').filter(Boolean)))], notes_n: hosts.filter((h) => h.notes).length,
      first_seen: hosts.reduce((t, h) => earlier(t, h.first_seen), ''), last_seen: hosts.reduce((t, h) => later(t, h.last_seen), ''),
      trend: [...u.trend.values()].sort((a, b) => a.day.localeCompare(b.day)),
      logon_rows: u.logonRows, failure_rows: u.failureRows, explicit_rows: u.explicitRows,
    };
  }).sort((a, b) => b.logons - a.logons || a.account.localeCompare(b.account));
  return {
    users: rows,
    excluded: [...excluded.values()].map((e) => ({ ...e, hosts: e.hosts.list(), seen_n: e.hosts.list().length, sources: [...e.sources].join('; ') }))
      .sort((a, b) => a.account.localeCompare(b.account)),
  };
}

// userSummary is a user row without its per-host detail and tables - what
// the list sends.
const DETAIL = new Set(['host_detail', 'trend', 'logon_rows', 'failure_rows', 'explicit_rows']);
function userSummary(u) {
  return Object.fromEntries(Object.entries(u).filter(([k]) => !DETAIL.has(k)));
}

module.exports = { userInventory, userSummary };
