// The topology (Signal schema 55): where the hosts
// sit on the networks and which of them talked to each other - from each
// host's latest collection: its adapters as configured then
// (inventory.network_adapters) and the private addresses it was connected
// with (activity.internal_addresses). Nothing here probes a network; every
// line is what a host recorded.
//
//   subnets - one per network an up adapter is on (its address and prefix):
//             the hosts on it with their address, adapter and DHCP, its
//             gateways, DNS servers and DHCP servers as the hosts state them;
//             each host's role and whether its adapter is virtual (virtualOf),
//             the subnet virtual when every adapter on it is
//   links   - one per host that recorded a connection with an address another
//             host in view has, by that host, port and program - the
//             recording host is not said to be the one that connected (a
//             connection open now does not record who opened it); one
//             connection both hosts recorded is two links
//   others  - the private addresses talked to that no host in view has,
//             each with the hosts that talked to it and its subnet if known
//   unread  - the hosts whose adapters were not read (Network did not run,
//             or a run before schema 55): placed nowhere, never "none"
'use strict';

const { hostOf, hostMeta } = require('./hosts');

const ADAPTERS = 'inventory.network_adapters';
const INTERNAL = 'activity.internal_addresses';

// rowsOf is a run's rows of the dataset with a role, as objects; null when
// the run has no such dataset.
function rowsOf(run, role) {
  for (const result of Object.values(run.modules || {})) {
    for (const ds of result.datasets || []) {
      if (ds.role === role) return ds.rows.map((r) => Object.fromEntries(ds.columns.map((c, i) => [c, r[i]])));
    }
  }
  return null;
}

const list = (v) => String(v || '').split('; ').filter(Boolean);

// v4 is an IPv4 address as a number, or null.
function v4(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((n, x) => n * 256 + Number(x), 0);
}
const dotted = (n) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.');

// network is an IPv4 address's network with its prefix ("10.0.0.0/24"); a
// link-local (169.254/16) or IPv6 address has none here - IPv6 networks
// are not placed (a host's global IPv6 prefix is not the organisation's
// layout, and link-local addresses are on every adapter).
function network(cidr) {
  const [ip, len] = String(cidr).split('/');
  const n = v4(ip);
  const bits = Number(len);
  if (n === null || !(bits >= 1 && bits <= 32) || ip.startsWith('169.254.')) return null;
  const size = 2 ** (32 - bits);
  return { ip, net: `${dotted(Math.floor(n / size) * size)}/${bits}`, start: Math.floor(n / size) * size, size };
}

// virtualOf names why an adapter is virtual - a virtual switch's or
// host-only network's adapter, a VPN or tunnel - from its interface type
// and the device its driver names; '' when neither says so. A virtual
// machine's own adapter (e.g. "Microsoft Hyper-V Network Adapter") is
// that machine's real link and is not called virtual.
const VIRTUAL = /vethernet|virtual ethernet|host-only|vmnet|tap-windows|wintun|wireguard|loopback|wan miniport|npcap|docker|\bwsl\b|zerotier|tailscale|openvpn|anyconnect|fortinet|globalprotect|\bvpn\b/i;
function virtualOf(a) {
  if (/tunnel|ppp/i.test(a.kind || '')) return a.kind;
  const m = `${a.adapter || ''} ${a.device || ''}`.match(VIRTUAL);
  return m ? m[0] : '';
}

function topology(runs) {
  const subnets = new Map();
  const owner = new Map(); // address -> the hosts that have it
  const unread = [];
  for (const run of runs) {
    const adapters = rowsOf(run, ADAPTERS);
    const host = { host: hostOf(run), run_id: run.run_id, role: hostMeta(run).role };
    if (!adapters) { unread.push(host); continue; }
    for (const a of adapters) {
      for (const cidr of list(a.addresses)) {
        const ip = cidr.split('/')[0];
        if (!owner.has(ip)) owner.set(ip, []);
        owner.get(ip).push(host);
        const n = a.status === 'up' ? network(cidr) : null;
        if (!n) continue;
        if (!subnets.has(n.net)) subnets.set(n.net, { subnet: n.net, start: n.start, size: n.size, hosts: [], gateways: new Set(), dns_servers: new Set(), dhcp_servers: new Set() });
        const s = subnets.get(n.net);
        s.hosts.push({ ...host, address: ip, adapter: a.adapter, device: a.device || '', kind: a.kind, dhcp: a.dhcp, virtual: virtualOf(a) });
        list(a.gateways).forEach((g) => s.gateways.add(g));
        list(a.dns_servers).forEach((d) => s.dns_servers.add(d));
        if (a.dhcp_server) s.dhcp_servers.add(a.dhcp_server);
      }
    }
  }
  const subnetOf = (ip) => {
    const n = v4(ip);
    if (n === null) return '';
    const s = [...subnets.values()].find((x) => n >= x.start && n < x.start + x.size);
    return s ? s.subnet : '';
  };

  const links = new Map();
  const others = new Map();
  for (const run of runs) {
    const from = hostOf(run);
    for (const r of rowsOf(run, INTERNAL) || []) {
      const to = (owner.get(r.address) || []).filter((x) => x.run_id !== run.run_id);
      if (to.length === 0) {
        if (owner.has(r.address)) continue; // the host's own address
        const o = others.get(r.address) || { address: r.address, subnet: subnetOf(r.address), hosts: new Set(), ports: new Set(), records: 0 };
        o.hosts.add(from);
        o.ports.add(r.port);
        o.records += Number(r.records) || 0;
        others.set(r.address, o);
        continue;
      }
      for (const t of to) {
        const k = [run.run_id, t.run_id, r.port, r.program].join('\u0000');
        const l = links.get(k) || { recorded_by: from, recorded_run_id: run.run_id, peer: t.host, peer_run_id: t.run_id, address: r.address, port: r.port, program: r.program || '', records: 0, seen_in: new Set(), first_seen: r.first_seen, last_seen: r.last_seen };
        l.records += Number(r.records) || 0;
        String(r.seen_in || '').split(', ').filter(Boolean).forEach((x) => l.seen_in.add(x));
        if (r.first_seen < l.first_seen) l.first_seen = r.first_seen;
        if (r.last_seen > l.last_seen) l.last_seen = r.last_seen;
        links.set(k, l);
      }
    }
  }

  const sorted = (set) => [...set].sort();
  return {
    subnets: [...subnets.values()].sort((a, b) => b.hosts.length - a.hosts.length || a.start - b.start).map(({ start: _start, size: _size, ...s }) => ({
      ...s, virtual: s.hosts.every((x) => x.virtual), hosts: s.hosts.sort((a, b) => (v4(a.address) || 0) - (v4(b.address) || 0)),
      gateways: sorted(s.gateways), dns_servers: sorted(s.dns_servers), dhcp_servers: sorted(s.dhcp_servers),
    })),
    links: [...links.values()].map((l) => ({ ...l, seen_in: sorted(l.seen_in).join(', ') })).sort((a, b) => b.records - a.records),
    others: [...others.values()].map((o) => ({ ...o, hosts: sorted(o.hosts), ports: sorted(o.ports).join(', ') })).sort((a, b) => b.hosts.length - a.hosts.length || b.records - a.records),
    unread,
  };
}

module.exports = { topology };
