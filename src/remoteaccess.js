// The remote access inventories (Signal's inventory.remote_tools and
// activity.remote_sessions, schema 33), stacked across the fleet
// (src/stacked.js):
//
//   tools - one row per product (its catalog name, the same on every
//     host): how it is on each host (installed, portable), the accounts,
//     tenants and servers it is enrolled to, unattended access, its
//     sessions - rarest first: a product only one host has stands out.
//   paths - one row per one of Windows' own ways in (its kind and value): a
//     port forward, an SSH key by its fingerprint, a WinRM relaxation,
//     Remote Assistance, shadowing - rarest first.
//   peers - one row per remote party: a product and the product's ID for
//     the other side of a session, which is the same whichever host it
//     connects to - most hosts first: one ID connected to several hosts is
//     one party reaching many, which no single host can see.
//
// A product is flagged when a RemoteAccess rule's signal names it, a peer
// when one names its ID, or either when an analyst flagged it.
'use strict';

const stacked = require('./stacked');

// parse is a json_group_array's values, without the empty ones.
const parse = (v) => (v ? JSON.parse(v).filter((x) => x !== null && x !== '') : []);
const join = (v) => parse(v).join('; ');

const tools = stacked.of({
  table: 'remote_tools',
  role: 'inventory.remote_tools',
  group: 'lower(product)',
  select: `product, json_group_array(DISTINCT nullif(kind, '')) AS kinds, json_group_array(DISTINCT nullif(mode, '')) AS modes,
    json_group_array(DISTINCT nullif(installed, '')) AS installed, json_group_array(DISTINCT nullif(portable, '')) AS portable,
    min(nullif(first_seen, '')) AS first_seen, max(nullif(last_seen, '')) AS last_seen, json_group_array(DISTINCT nullif(account, '')) AS accounts,
    json_group_array(DISTINCT nullif(tenant, '')) AS tenants, json_group_array(DISTINCT nullif(server, '')) AS servers,
    sum(unattended LIKE 'set%') AS unattended_n, json_group_array(DISTINCT nullif(sessions, '')) AS sessions,
    json_group_array(DISTINCT nullif(allowed, '')) AS allowed`,
  search: `product || ' ' || mode || ' ' || installed || ' ' || portable || ' ' || account || ' ' || tenant || ' ' || server || ' ' || tool_id`,
  order: 'lower(product)',
  flagKind: 'remote_tools',
  ruleKey: (r) => String(r.product).toLowerCase(),
  shape: (r) => ({
    product: r.product, kind: join(r.kinds), modes: join(r.modes), installed: join(r.installed), portable: join(r.portable),
    first_seen: r.first_seen || '', last_seen: r.last_seen || '', accounts: join(r.accounts), tenants: join(r.tenants), servers: join(r.servers),
    unattended_n: r.unattended_n || 0, sessions: join(r.sessions), allowed: join(r.allowed), seen_n: r.seen_n, run_ids: r.run_ids, value: r.product,
  }),
});

const peers = stacked.of({
  table: 'remote_sessions',
  where: "peer_id <> ''",
  role: 'activity.remote_sessions',
  group: "lower(product) || '|' || lower(peer_id)",
  select: `product, peer_id, json_group_array(DISTINCT nullif(peer_name, '')) AS names, json_group_array(DISTINCT nullif(address, '')) AS addresses,
    count(*) AS sessions_n, sum(direction = 'incoming') AS incoming_n, min(nullif(start, '')) AS first_start, max(nullif(start, '')) AS last_start,
    sum(transfers <> '') AS with_transfers_n, json_group_array(DISTINCT nullif(auth, '')) AS auths`,
  search: `product || ' ' || peer_id || ' ' || peer_name || ' ' || address`,
  order: 'lower(product), peer_id',
  mostFirst: true,
  flagKind: 'remote_peers',
  ruleKey: (r) => String(r.peer_id).toLowerCase(),
  shape: (r) => ({
    product: r.product, peer_id: r.peer_id, peer_names: join(r.names), addresses: join(r.addresses), sessions_n: r.sessions_n, incoming_n: r.incoming_n,
    first_start: r.first_start || '', last_start: r.last_start || '', with_transfers_n: r.with_transfers_n, auths: join(r.auths),
    seen_n: r.seen_n, run_ids: r.run_ids, value: `${r.product} ID ${r.peer_id}`,
  }),
});

const paths = stacked.of({
  table: 'remote_paths',
  role: 'inventory.remote_paths',
  group: 'lower(kind) || char(0) || lower(value)',
  select: `kind, value, json_group_array(DISTINCT nullif(detail, '')) AS details, json_group_array(DISTINCT nullif(user, '')) AS users,
    min(nullif(changed, '')) AS first_changed, max(nullif(changed, '')) AS last_changed, json_group_array(DISTINCT nullif("where", '')) AS places`,
  search: `kind || ' ' || value || ' ' || detail || ' ' || user`,
  order: 'lower(kind), lower(value)',
  flagKind: 'remote_paths',
  ruleKey: (r) => String(r.path_value).toLowerCase(),
  shape: (r) => ({
    kind: r.kind, path_value: r.value, details: join(r.details), users: join(r.users), first_changed: r.first_changed || '', last_changed: r.last_changed || '',
    places: join(r.places), seen_n: r.seen_n, run_ids: r.run_ids, value: `${r.kind}: ${r.value}`,
  }),
});

module.exports = { tools, peers, paths };
