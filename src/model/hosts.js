// Hosts: how a run names and identifies its machine, and each host's latest
// collection.
//
// A host is identified by its machine ID (Signal's host.machine_id, the
// installation's MachineGuid) when the run has one, so a renamed host stays
// one host and two hosts sharing a name stay two. A run from an older
// Signal has no machine ID; it belongs to the machine ID other runs of the
// same host name carry, when exactly one does, and is otherwise identified
// by its host name.
'use strict';

// hostOf returns the name the app shows for a run's machine: the live
// host's name, or the forensic evidence's source path.
function hostOf(run) {
  if (run.host && run.host.hostname) return run.host.hostname;
  if (run.evidence && run.evidence.source) return run.evidence.source;
  return run.run_id;
}

// roleOf names a run's machine role.
function roleOf(run) {
  const hi = run.host;
  if (!hi) return 'Evidence';
  return hi.is_domain_controller ? 'Domain Controller' : hi.is_server ? 'Server' : 'Client';
}

// hostMeta is what the app shows about a host wherever it names one: its
// name, operating system, build and role (the host filters and the host
// hover cards use it).
function hostMeta(run) {
  const hi = run.host || {};
  return { host: hostOf(run), os: hi.os || '', os_build: hi.os_build || '', role: roleOf(run) };
}

// hostKeys returns a function giving each of runs its host's identity (see
// above).
function hostKeys(runs) {
  const idsByName = new Map();
  for (const run of runs) {
    const id = run.host && run.host.machine_id;
    if (!id) continue;
    if (!idsByName.has(hostOf(run))) idsByName.set(hostOf(run), new Set());
    idsByName.get(hostOf(run)).add(id);
  }
  return (run) => {
    const id = run.host && run.host.machine_id;
    if (id) return `id:${id}`;
    const ids = idsByName.get(hostOf(run));
    return ids && ids.size === 1 ? `id:${[...ids][0]}` : `name:${hostOf(run)}`;
  };
}

// byHost groups runs by host, each host's runs newest first.
function byHost(runs) {
  const keyOf = hostKeys(runs);
  const groups = new Map();
  for (const run of runs) {
    const k = keyOf(run);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(run);
  }
  for (const list of groups.values()) list.sort((a, b) => String(b.started || '').localeCompare(String(a.started || '')));
  return groups;
}

// latestRuns keeps each host's most recent run - the fleet as it is now.
// Every page but a host's collection history works on these.
function latestRuns(runs) {
  const latest = new Set([...byHost(runs).values()].map((list) => list[0]));
  return runs.filter((r) => latest.has(r));
}

// HostSet collects the hosts a value was seen on, once each, as
// {run_id, host, os, os_build, role} - what the front end links to and
// shows on hover.
class HostSet {
  constructor() { this.byRun = new Map(); }
  add(run) { this.byRun.set(run.run_id, { run_id: run.run_id, ...hostMeta(run) }); }
  list() { return [...this.byRun.values()].sort((a, b) => a.host.localeCompare(b.host)); }
}

module.exports = { hostOf, hostMeta, hostKeys, byHost, latestRuns, HostSet };
