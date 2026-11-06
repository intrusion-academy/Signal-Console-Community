// Upgrades a run written by an older Signal (schema version 13 or earlier)
// to the current output contract (schema 14 - see
// Signal's output contract documentation), in place, so nothing else in this app
// needs to know which version a run came from. It fills in what later
// schemas state themselves - KPIs, telemetry, dataset roles and each
// observation's time, entity, context and value (schema 4) - from what the
// older modules wrote, with the same IDs and wording as the current modules,
// and drops what the tool no longer produces (the command-line inventory and
// the activity samples: raw data, not signals). An observation's source
// (schema 5: which evidence it came from) cannot be recovered and stays
// absent - the pages say the source was not recorded; so does the health of
// the run's evidence sources (schema 6), which stays an empty list. Insight
// findings and rules (schema 9 and earlier) are dropped: since schema 10
// every finding is a signal, and what an insight said is part of the
// module's KPIs and telemetry, which older runs already carry.
'use strict';

// Schemas 13 to 17 only add (Antivirus; Persistence, which replaces
// Services, and its inventory.persistence role; an observation's subject
// and related entities; one observation per coalesced signal, with its
// count - an older observation is one match; the run's entities - an
// older run has none, and says so): nothing to upgrade. Schema 18 renames
// Processes to Executions (EXEC-) and Antivirus to Protection (PROT-); an
// older run keeps the names it was collected with - every host is re-run.
// Schema 19 only adds (Remote Desktop: rdp_session and rdp_outbound, the
// activity.rdp_sessions and activity.rdp_outbound tables; the accounts'
// changes column): an older run has none of them. Schema 20 only adds
// (Sysmon's process creations, PowerShell's script blocks and engine
// starts, their fields and telemetry; long observation values cut):
// nothing to upgrade. Schema 21 only adds (program runs, the PowerShell
// history, an observation's time_from): nothing to upgrade. Schema 22
// only adds (rule_matches' evidence; optional KPIs): nothing to upgrade.
// Schema 23 only adds (a process's exit in its enrichment); schema 24 only
// adds (a configured entry's program hash, file.sha256); schema 25 only
// adds (the Applications module, inventory.applications); schema 26 only
// adds (Windows Installer's events); schema 27 only adds (the Network
// module, activity.listeners and activity.remote_addresses; address scopes
// shared and multicast). Schema 28 moves an observation's file and
// signature to its program entity's facts (entity_facts) and adds
// occurrences: an older run shows its entities without facts (re-run the
// host - the user re-runs every build), nothing to upgrade. Schema 29 only
// adds (the Browsers module, inventory.browser_extensions, entity type
// extension). Schema 30 only adds (downloads and visits: file_download,
// browser_visit, entity type domain). Schema 31 only adds (more download
// and visit fields; address and domain facts). Schema 32 only adds (the
// Directory module: Group Policy objects and what they deploy, SYSVOL's
// executables, a domain controller's directory changes; inventory.group_policy;
// entity types gpo and directory_object). Schema 33 only adds (the
// RemoteAccess module: remote_tool, remote_session, remote_transfer;
// inventory.remote_tools, activity.remote_sessions; entity types
// remote_tool and remote_peer). Schema 34 only adds (remote_setting,
// inventory.remote_paths, remote_app_event; more remote.* fields). Schema 35
// only adds (the Webshells module: web_app, web_file, web_module;
// inventory.web_apps, inventory.web_files; entity type web_app). Schema 36
// only adds (Persistence: bits_job, task.triggers, new auto-start
// locations, telemetry bits_client_log). Schema 37 only adds
// (LogIntegrity: audit_policy's local_gpo, group_policy and not_in_force
// columns, the logging_policy dataset). Schema 38 only adds (event_logs,
// gp_extension_run, clock.* fields, two LogIntegrity rules). Schema 39
// only adds (shadow copies read as evidence with -shadow: the run's
// shadow_copies, a source's shadow_copy, a signal's shadow_copy_matches
// and from_shadow_copy). Schema 40 only adds (rule_matches'
// shadow_copy_matches). Schema 41 only adds (the Backup module:
// recovery_state, backup_event, shadow_copies_lost, inventory.recovery,
// entity type recovery). Schema 42 only adds (an occurrence's entity and
// context, when its signal's matches differ). Schema 43 only adds
// (powershell_transcript, the obfuscation measure, PowerShell logging
// telemetry). Schema 44 only adds (wmi_activity, winrm_session,
// process.launched_by, logging_policy rows for PowerShell). Schema 45 only
// adds (av_block, Defender's configuration fields and telemetry). Schema
// 46 only adds (av_history, av.detection_source, AMSI provider entries).
// Schema 47 only adds (host_protection - Windows' own protections as
// telemetry - and code integrity, AppLocker and firewall records).
// Schema 48 only adds (the run's profile). Schema 49 only adds (the Scope
// module: pivot_check, pivot.*, the pivots table, telemetry "Sources read").
// Schema 50 only adds (a module's about.params). Schema 51 renames a pivot's
// note to its context (the Scope pivots table's column).
// Schema 52 only adds (a related entity's role, an entity's related roles).
// Schema 56 keys a host program (cmd.exe, powershell.exe, svchost.exe...)
// by what it runs: an older run keeps one entity for all of it.
// Schema 57 only adds (the run profile's problems). Schema 58 only adds
// (an observation's approved - the profile's baseline; pivot types file,
// sha1, md5). Schema 61: telemetry category Auditing is Security Log
// Audit, Scope's "Sources read" item is gone, and a source the host does
// not have is "absent", not "off" (upgrade61). Schema 62: Security Log
// Audit holds only the Security log's items - Group Policy's run of the
// logging settings is a Logging setting; two labels name the Security log.
// Schema 63: a catalog entry's fields is the list of field names, what each
// means in the run's field_docs once (upgradeFieldDocs).
const CURRENT = 63;

// LABELS_62 are the schema-62 labels of items whose earlier labels did not
// say they are the Security log's.
const LABELS_62 = {
  service_install_auditing: 'Service installations audited (Security log 4697: who installed them)',
  task_change_auditing: "Scheduled task changes audited (Security log 4698-4702, with the task's definition)",
};

// ABSENT_DETAIL is how an older run's "off" log-health item said the host
// does not have its source - Signal's own reasons - which schema 61 states
// as "absent".
const ABSENT_DETAIL = /does not exist on this host|no firewall log file exists|no web site is configured|not joined to a domain|not a domain controller/;

// NO_WEB_SITE and NO_FIREWALL_LOG are Signal 0.86.0's reasons for the two
// sources an older Signal called read when the host had none: no web site
// (a site is always a web_app record, so none read means none there) and
// no firewall log file (its detail said so).
const NO_WEB_SITE = 'no web site is configured on this host (IIS, Apache httpd, nginx, Tomcat)';
const NO_FIREWALL_LOG = 'no firewall log file exists';
const WEB_TYPES = new Set(['web_app', 'web_file', 'web_module']);
const WEB_ITEMS = new Set(['web_apps', 'web_files', 'web_modules']);

// absentSources marks, in an older run's sources, the web and firewall
// sources the host did not have as unavailable, and returns their reasons
// by the telemetry item that states them.
function absentSources(run) {
  const out = {};
  const sources = run.sources || [];
  const web = sources.find((s) => s.evidence === 'web_app');
  const noWeb = Boolean(web && web.status === 'read' && !web.records);
  for (const s of sources) {
    if (s.status !== 'read') continue;
    if (WEB_TYPES.has(s.evidence) && noWeb) {
      Object.assign(s, { status: 'unavailable', reason: NO_WEB_SITE });
      for (const id of WEB_ITEMS) out[id] = NO_WEB_SITE;
    }
    if (s.evidence === 'firewall_connection' && s.detail === NO_FIREWALL_LOG) {
      Object.assign(s, { status: 'unavailable', reason: NO_FIREWALL_LOG, detail: undefined });
      out.firewall_log = NO_FIREWALL_LOG;
    }
  }
  return out;
}

// upgrade61 brings a result's telemetry to schema 61: absent (by Signal's
// reasons, or the sources absentSources found absent) where it said off or
// on for a source the host does not have.
function upgrade61(r, absent) {
  r.telemetry = (r.telemetry || []).filter((t) => t.id !== 'sources_searched');
  for (const t of r.telemetry) {
    if (t.category === 'Auditing') t.category = 'Security Log Audit';
    if (t.id === 'group_policy_logging_applied') t.category = 'Logging settings'; // schema 62
    if (LABELS_62[t.id]) t.label = LABELS_62[t.id];
    if (t.state === 'off' && t.category === 'Log health' && ABSENT_DETAIL.test(t.detail || '')) t.state = 'absent';
    if (absent[t.id]) Object.assign(t, { state: 'absent', detail: absent[t.id] });
  }
}

// What a time is, in Signal's words for a state observed as it read the
// host (schema 59), and for an older run's time, which does not say.
const OBSERVED = 'observed when Signal read the host (its own time is not recorded)';
const UNSTATED = 'its time (a run before Signal 0.81.0 does not say what it is)';

// OLD_SESSION_SOURCE is how schema 11 and earlier named where a session
// was read - wording that read as a remote logon, which a console session
// is not (schema 12 rewords it).
const OLD_SESSION_SOURCE = 'logon sessions open now (Remote Desktop Services)';
const SESSION_SOURCE = 'sessions signed in now (Windows session manager: console and Remote Desktop)';

// isInsight is a finding or catalog entry of the lowest severity schema 9
// and earlier had ("info" before schema 3).
const isInsight = (item) => item.severity === 'insight' || item.severity === 'info';

// DROPPED are the datasets schema 4 no longer has.
const DROPPED = new Set(['command_lines', 'command_line_activity_samples', 'event_activity_samples', 'suspicious_process_creations']);

// ROLES are the identity tables of the older modules, by dataset name.
const ROLES = { users: 'identity.account', computers: 'identity.computer', workstations: 'identity.workstation', ips: 'identity.ip' };

// Observation fields the older modules wrote: what an event is about, in
// order of preference, and its own time.
const ENTITY_FIELDS = ['process.command_line', 'process.name', 'log.subject'];
const TIME_FIELDS = ['process.start_time', 'log.event_time'];
const first = (fields, names) => names.map((n) => fields[n]).find((v) => v !== undefined && v !== null && v !== '');

const num = (v) => (typeof v === 'number' ? v : undefined);
const bool = (v) => (typeof v === 'boolean' ? v : undefined);
const state = (on) => (on === undefined ? 'unknown' : on ? 'on' : 'off');
const undetermined = (known, text) => (known ? text : 'could not be determined');

// securityLog returns SecurityLog's KPIs and telemetry from its summary -
// modules/securitylog/present.go, for runs written before it existed.
function securityLog(s, datasets) {
  const kpis = [];
  const size = num(s.log_size_mb);
  if (size !== undefined) {
    const k = { id: 'security_log_size', label: 'Security log size', value: `${size} MB` };
    const max = num(s.log_max_size_mb);
    if (max !== undefined) {
      const fill = num(s.log_fill_percent) || 0;
      const overwrite = s.log_overwrites_oldest === true;
      k.sub = `of a ${max} MB maximum · ${overwrite ? 'overwrites oldest' : 'does not overwrite'}`;
      k.bar = fill;
      k.status = fill >= 95 && !overwrite ? 'bad' : fill >= 95 || max < 128 ? 'warn' : 'good';
    }
    kpis.push(k);
  }
  const days = num(s.window_days);
  if (days !== undefined) {
    kpis.push({ id: 'security_log_window', label: 'Security log time window', value: `${days} days`, sub: `${s.oldest_event} → ${s.newest_event}`, status: days < 7 ? 'warn' : 'good' });
  }
  if (num(s.events_scanned) !== undefined) {
    kpis.push({ id: 'security_log_events', label: 'Security log events read', value: String(s.events_scanned), ...(s.log_records_reported !== undefined ? { sub: `the log reports ${s.log_records_reported} records` } : {}) });
  }
  const cleared = bool(s.log_cleared);
  if (cleared !== undefined) {
    const clears = ((datasets.find((d) => d.name === 'log_clear_events') || {}).rows || []).length;
    kpis.push(cleared
      ? { id: 'security_log_cleared', label: 'Security log cleared', value: 'Yes', sub: `${clears} clear event(s), last by ${s.last_cleared_by}`, status: 'bad' }
      : { id: 'security_log_cleared', label: 'Security log cleared', value: 'No', sub: 'no event 1102 in the log', status: 'good' });
  }
  if (num(s.computer_names_seen) !== undefined && s.computer_names) {
    kpis.push({ id: 'security_log_computer_names', label: 'Computer names in the log', value: String(s.computer_names_seen), sub: s.computer_names, status: s.computer_names_overlap ? 'warn' : 'good' });
  }
  const enabled = num(s.audit_subcategories_enabled);
  const max = num(s.log_max_size_mb);
  const telemetry = [
    { id: 'audit_policy_enabled', label: 'Audit policy enabled', state: state(enabled === undefined ? undefined : enabled > 0), detail: undetermined(enabled !== undefined, `${enabled} of ${s.audit_subcategories_total} subcategories audited`) },
    { id: 'security_log_window_7d', label: 'Security log window of 7 days or more', state: state(days === undefined ? undefined : days >= 7), detail: undetermined(days !== undefined, `${days} days`) },
    { id: 'security_log_max_128mb', label: 'Security log maximum of 128 MB or more', state: state(max === undefined ? undefined : max >= 128), detail: undetermined(max !== undefined, `${max} MB`) },
    { id: 'security_log_never_cleared', label: 'Security log never cleared', state: state(cleared === undefined ? undefined : !cleared), detail: undetermined(cleared !== undefined, `${s.clear_count} clear event(s)`) },
  ];
  return { kpis, telemetry };
}

// sec4688 returns Sec4688's KPIs and telemetry from its summary -
// modules/sec4688/present.go.
function sec4688(s) {
  const policy = (id, label, key, offStatus) => {
    const on = bool(s[key]);
    if (on === undefined) return { id, label, value: 'Unknown', sub: 'could not be determined' };
    return on ? { id, label, value: 'Enabled', status: 'good' } : { id, label, value: 'Disabled', status: offStatus };
  };
  const kpis = [
    policy('process_creation_audit', 'Process Creation auditing', 'process_creation_audit_enabled', 'bad'),
    policy('commandline_capture', 'Command-line capture', 'commandline_logging_enabled', 'warn'),
  ];
  if (num(s.events_scanned) !== undefined) {
    kpis.push({ id: 'process_creations', label: 'Process creations read', value: String(s.events_scanned), sub: 'every process start (event 4688) in the Security log, checked against the rules' });
  }
  const item = (id, label, key) => {
    const on = bool(s[key]);
    return { id, label, state: state(on), ...(on === undefined ? { detail: 'could not be determined' } : {}) };
  };
  return { kpis, telemetry: [item('process_creation_audit', 'Process Creation auditing on', 'process_creation_audit_enabled'), item('commandline_logging', 'Command lines recorded', 'commandline_logging_enabled')] };
}

const PRESENTERS = { SecurityLog: (r) => securityLog(r.summary || {}, r.datasets || []), Sec4688: (r) => sec4688(r.summary || {}) };

// observedAt says an older observation (before schema 59) is of a state
// observed as Signal read the host: a state's evidence, its time within
// the run - Signal stamped what it found as it ran. A state with a time of
// its own, before the run, keeps it.
function observedAt(o, run) {
  if (!o.source || o.source.kind !== 'state') return false;
  const t = Date.parse(o.first || o.time);
  const from = Date.parse(run.started);
  const to = Date.parse(run.finished || run.started);
  return Number.isNaN(t) || Number.isNaN(from) || (t >= from - 60000 && t <= (Number.isNaN(to) ? from : to) + 60000);
}

// upgradeObservation fills an older observation's time, entity, context
// and value from its fields, and what its time is (schema 59).
function upgradeObservation(o, run) {
  if (o.time_is === undefined) {
    o.as_of = observedAt(o, run);
    o.time_is = o.as_of ? OBSERVED : UNSTATED;
    for (const x of o.occurrences || []) x.time_is = o.time_is;
  }
  const fields = o.fields || {};
  const entity = String(first(fields, ENTITY_FIELDS) ?? '');
  if (o.time === undefined) o.time = first(fields, TIME_FIELDS) || '';
  if (o.entity === undefined) o.entity = entity;
  if (o.context === undefined && fields['process.name'] && fields['process.name'] !== entity) o.context = fields['process.name'];
  if (o.value === undefined) o.value = fields['process.command_line'] || fields['process.name'] || entity;
}

// renameSec4688 gives an older run's Sec4688 module its current name,
// Processes, and its rules their current prefix, PROC- (schema 8), so a
// host's older collections and its new ones name the same rules the same
// way - rule outcomes, "new since previous collection" and triage all key
// on the rule ID.
function renameSec4688(run) {
  const r = run.modules && run.modules.Sec4688;
  if (!r) return;
  const id = (v) => (typeof v === 'string' && v.startsWith('SEC4688-') ? 'PROC-' + v.slice(8) : v);
  for (const item of [...(r.findings || []), ...(r.rule_catalog || [])]) {
    if (item.rule_id !== undefined) item.rule_id = id(item.rule_id);
    if (item.id !== undefined) item.id = id(item.id);
    if (item.module === 'Sec4688') item.module = 'Processes';
  }
  for (const d of r.datasets || []) {
    const col = d.columns.indexOf('rule_id');
    if (col >= 0) for (const row of d.rows) row[col] = id(row[col]);
  }
  r.module = 'Processes';
  delete run.modules.Sec4688;
  run.modules.Processes = r;
}

// TELEMETRY_CATEGORY is the category (schema 11) of every telemetry item
// the modules stated before telemetry had one; an unknown item goes under
// "Other".
const TELEMETRY_CATEGORY = {
  audit_policy_enabled: 'Security Log Audit', audit_policy_change_audit: 'Security Log Audit', process_creation_audit: 'Security Log Audit',
  logon_success_audit: 'Security Log Audit', logon_failure_audit: 'Security Log Audit', special_logon_audit: 'Security Log Audit',
  user_account_management_audit: 'Security Log Audit', security_group_management_audit: 'Security Log Audit',
  commandline_logging: 'Logging settings',
  security_log_recording: 'Log health', security_log_window_7d: 'Log health', security_log_max_128mb: 'Log health', security_log_never_cleared: 'Log health',
};

// ALWAYS_LOGGED are the events Windows writes whatever the audit policy,
// with what each means - since schema 11 never "expected" (see Signal's
// modules/securitylog/helpers.go).
const ALWAYS_LOGGED = {
  521: '(always logged: events could not be written to the Security log)',
  1100: '(always logged: the Event Log service shut down - normal at shutdown, suspicious otherwise)',
  1101: '(always logged: audit events were dropped by the transport)',
  1102: '(always logged: the Security log was cleared)',
  1104: '(always logged: the Security log is full and does not overwrite)',
  1105: '(always logged: the log was archived automatically when full)',
  1108: '(always logged: the Event Log service could not process an event)',
};

// upgradeRecent brings a result's parts that changed in schemas 11 and 12
// up: telemetry categories and the clear item's wording (a clear
// older than the log's oldest event cannot be known), the always-logged
// events' statuses, the audit policy changes as one row per change, and
// the session source's wording (schema 12).
function upgradeRecent(r) {
  for (const t of r.telemetry || []) {
    if (!t.category) t.category = TELEMETRY_CATEGORY[t.id] || 'Other';
    if (t.id === 'security_log_never_cleared') t.label = "No log clear in the log's time window";
  }
  for (const d of r.datasets || []) {
    const c = (name) => d.columns.indexOf(name);
    if (d.name === 'event_ids') {
      for (const row of d.rows) {
        const id = row[c('event_id')];
        if (!ALWAYS_LOGGED[id]) continue;
        row[c('subcategories')] = ALWAYS_LOGGED[id];
        row[c('expected')] = false;
        if (row[c('status')] !== 'not_read') row[c('status')] = row[c('present')] ? 'condition_occurred' : 'condition_not_seen';
      }
    }
    if (d.role === 'entity.account' || d.role === 'accounts.excluded') {
      const src = c('sources');
      for (const row of d.rows) if (typeof row[src] === 'string') row[src] = row[src].split(OLD_SESSION_SOURCE).join(SESSION_SOURCE);
    }
    if (d.role === 'activity.audit_policy_changes' && c('time') < 0) {
      d.rows = d.rows.map((row) => [row[c('first_seen')], row[c('subcategory')], row[c('changes')], row[c('changed_by')], row[c('via')], row[c('count')]]);
      d.columns = ['time', 'subcategory', 'changes', 'changed_by', 'via', 'count'];
    }
  }
}

// upgradeFieldDocs brings a run's rule catalog to schema 63: each entry's
// fields map ({field: {doc, derived}}) becomes the list of its names, the
// text moving to the run's field_docs, once.
function upgradeFieldDocs(run) {
  for (const r of Object.values(run.modules || {})) {
    for (const e of r.rule_catalog || []) {
      if (!e.fields || Array.isArray(e.fields)) continue;
      run.field_docs = run.field_docs || {};
      Object.assign(run.field_docs, e.fields);
      e.fields = Object.keys(e.fields).sort();
    }
  }
}

// upgrade brings run up to the current schema, in place, and returns it.
// A run already at the current schema is returned unchanged.
function upgrade(run) {
  const from = Number(run.schema_version) || 0;
  // Signal 0.45.0-0.53.0 wrote a host without shadow copies' copies as
  // null: none, a list like any other.
  if (run.shadow_copies && run.shadow_copies.copies === null) run.shadow_copies.copies = [];
  if (from >= CURRENT) return run;
  for (const [name, r] of Object.entries(run.modules || {})) {
    if (r.findings) r.findings = r.findings.filter((f) => !isInsight(f)); // schema 9 and earlier
    if (r.rule_catalog) r.rule_catalog = r.rule_catalog.filter((e) => !isInsight(e));
    for (const f of r.findings || []) (f.observations || []).forEach((o) => upgradeObservation(o, run));
    r.datasets = (r.datasets || []).filter((d) => !DROPPED.has(d.name));
    for (const d of r.datasets) if (!d.role && ROLES[d.name]) d.role = ROLES[d.name];
    if (!r.kpis && !r.telemetry && PRESENTERS[name]) Object.assign(r, PRESENTERS[name](r));
  }
  if (!Array.isArray(run.sources)) run.sources = []; // schema 5 and earlier
  renameSec4688(run); // schema 7 and earlier
  const absent = from < 61 ? absentSources(run) : {};
  for (const r of Object.values(run.modules || {})) {
    upgradeRecent(r); // schema 11 and earlier
    upgrade61(r, absent);
  }
  upgradeFieldDocs(run);
  run.upgraded_from = from;
  run.schema_version = CURRENT;
  return run;
}

// olderOutput says, in plain words, that a run came from a Signal whose
// output is older than this console's (upgraded on import: what later
// Signals report is missing from it, never "none") and what to do; '' for
// a run of the current schema.
function olderOutput(run) {
  const from = run.upgraded_from;
  if (from === undefined || from >= CURRENT) return '';
  return `Collected by Signal ${run.tool_version || '(version not stated)'}, whose output is older (schema ${from}) than the one this console reads (schema ${CURRENT}). `
    + 'It was upgraded on import, but what later versions of Signal report is not in it - missing, not "none". Re-run the host with the current Signal.';
}

module.exports = { upgrade, CURRENT, OBSERVED, olderOutput };
