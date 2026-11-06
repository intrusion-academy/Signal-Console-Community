// The Topology page's views (GET /api/inventories' topology, from
// src/model/topology.js): the hosts' networks as a map - each subnet a box
// with its hosts, a line for each connection a host recorded with another
// host in view - and beside it the subnets, the connections and the private
// addresses no host in view has, as tables. Every line is what a host
// recorded; nothing is inferred about hosts not imported.

import { h } from '../dom.js';
import { hostLink } from '../components.js';
import { dataTable, col } from '../table.js';

const SVG = 'http://www.w3.org/2000/svg';
const svg = (tag, attrs, ...children) => {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, String(v));
  for (const c of children) if (c != null) el.append(c);
  return el;
};

// Layout of the map: subnets side by side, each a network segment - its
// default gateway drawn above it as a router, its hosts stacked on its bus.
const BOX_W = 250, BOX_GAP = 70, GW = 70, HEAD = 66, ROW = 46, PAD = 14;

// The map's device shapes, about 24x24 around (0, 0), in the page's colours.
// A gateway is a router: the address the hosts send other networks' traffic
// to. Nothing the hosts record says whether it filters, so it is never drawn
// or named as a firewall.
const DEVICE = {
  Client: () => [svg('rect', { x: -10, y: -9, width: 20, height: 13, rx: 1.5 }), svg('path', { d: 'M -4 8 h 8 M 0 4 v 4' })],
  Server: () => [svg('rect', { x: -7, y: -11, width: 14, height: 22, rx: 1.5 }), svg('path', { d: 'M -4 -6 h 8 M -4 -1 h 8 M -4 4 h 8' })],
  router: () => [svg('rect', { x: -12, y: -5, width: 24, height: 10, rx: 3 }), svg('path', { d: 'M -7 -5 v -6 M 7 -5 v -6 M -6 0 h 3 M 1 0 h 1 M 5 0 h 1' })],
};
DEVICE['Domain Controller'] = DEVICE.Server;
const device = (kind, x, y, cls) => svg('g', { class: `topo-device ${cls}`, transform: `translate(${x} ${y})` }, ...(DEVICE[kind] || DEVICE.Client)());

// topologyMap draws the subnets, their gateways and the recorded
// connections between their hosts; a host on two subnets is drawn in each,
// its connections from the first. Hovering a host lights its connections.
export function topologyMap(t) {
  if (!t.subnets.length) return null;
  const owner = new Map(t.subnets.flatMap((s) => s.hosts.map((x) => [x.address, x.host])));
  const named = (ip) => (owner.has(ip) ? `${ip} (${owner.get(ip)})` : ip);
  const at = new Map(); // run_id -> [x, y, right edge] of its first drawing
  const tallest = Math.max(...t.subnets.map((s) => s.hosts.length));
  const width = t.subnets.length * (BOX_W + BOX_GAP) - BOX_GAP + 2 * PAD + 50; // room for a curve that bows out of the last box
  const height = GW + HEAD + tallest * ROW + 2 * PAD + 10;
  const boxes = t.subnets.map((s, i) => {
    const x = PAD + i * (BOX_W + BOX_GAP);
    const top = PAD + GW;
    const busX = x + 18;
    const mid = x + BOX_W / 2;
    const meta = [s.dhcp_servers.length ? `DHCP ${s.dhcp_servers.join(', ')}` : 'no DHCP server stated', s.virtual ? 'virtual network' : ''].filter(Boolean).join(' · ');
    const gw = s.gateways.length
      ? svg('g', { class: 'topo-gw' },
        svg('title', {}, 'The default gateway the hosts on this subnet state: the router they send other networks\' traffic to. Whether it filters traffic is not recorded.'),
        svg('line', { x1: mid, y1: PAD + 24, x2: mid, y2: top, class: 'topo-uplink' }),
        device('router', mid, PAD + 18, 'router'),
        svg('text', { x: mid + 20, y: PAD + 14, class: 'topo-host-name' }, 'default gateway'),
        svg('text', { x: mid + 20, y: PAD + 28, class: 'topo-host-addr' }, s.gateways.map(named).join(', ')))
      : svg('text', { x: x + 12, y: PAD + 44, class: 'topo-meta' }, 'no default gateway stated');
    const hosts = s.hosts.map((x0, j) => {
      const y = top + HEAD + j * ROW + 4;
      const dc = x0.role === 'Domain Controller';
      if (!at.has(x0.run_id)) at.set(x0.run_id, [x, y, x + BOX_W]);
      return svg('g', { class: `topo-host${x0.virtual ? ' virtual' : ''}`, 'data-run': x0.run_id },
        svg('title', {}, `${x0.host} (${x0.role || 'host'})\n${x0.address} on ${x0.adapter}${x0.device ? ` - ${x0.device}` : ''}${x0.virtual ? `\nA virtual adapter (${x0.virtual})` : ''}`),
        svg('line', { x1: busX, y1: y, x2: x + 30, y2: y, class: 'topo-drop' }),
        device(x0.role, x + 44, y, dc ? 'dc' : ''),
        svg('text', { x: x + 62, y: y - 3, class: 'topo-host-name' }, dc ? `${x0.host} · DC` : x0.host),
        svg('text', { x: x + 62, y: y + 12, class: 'topo-host-addr' }, `${x0.address} · ${x0.adapter}${x0.virtual ? ' · virtual' : ''}`));
    });
    return svg('g', {},
      gw,
      svg('rect', { x, y: top, width: BOX_W, height: HEAD + s.hosts.length * ROW, rx: 6, class: `topo-box${s.virtual ? ' virtual' : ''}` }),
      svg('text', { x: x + 12, y: top + 22, class: 'topo-subnet' }, s.subnet),
      svg('text', { x: x + 12, y: top + 40, class: 'topo-meta' }, meta),
      svg('line', { x1: busX, y1: top + HEAD - 12, x2: busX, y2: top + HEAD + (s.hosts.length - 1) * ROW + 4, class: 'topo-bus' }),
      ...hosts);
  });
  // One line per pair of hosts, whichever recorded it.
  const pairs = new Map();
  for (const l of t.links) pairs.set([l.recorded_run_id, l.peer_run_id].sort().join('|'), l);
  const lines = [...pairs.values()].filter((l) => at.has(l.recorded_run_id) && at.has(l.peer_run_id)).map((l) => {
    const [ax, ay, aEnd] = at.get(l.recorded_run_id);
    const [bx, by, bEnd] = at.get(l.peer_run_id);
    // Within one box the curve bows out to its right; across boxes it joins their facing edges.
    const d = ax === bx
      ? `M ${aEnd - 8} ${ay} C ${aEnd + 40} ${ay}, ${bEnd + 40} ${by}, ${bEnd - 8} ${by}`
      : (() => { const [l1, r1] = ax < bx ? [[aEnd, ay], [bx, by]] : [[bEnd, by], [ax, ay]]; const m = (l1[0] + r1[0]) / 2; return `M ${l1[0]} ${l1[1]} C ${m} ${l1[1]}, ${m} ${r1[1]}, ${r1[0]} ${r1[1]}`; })();
    return svg('path', { d, class: `topo-link${ax === bx ? '' : ' across'}`, 'data-a': l.recorded_run_id, 'data-b': l.peer_run_id },
      svg('title', {}, `${l.recorded_by} - ${l.peer}: port ${l.port}${l.program ? ` (${l.program})` : ''}`));
  });
  const map = svg('svg', { viewBox: `0 0 ${width} ${height}`, width, height, role: 'img', 'aria-label': 'Map of the hosts\' networks' }, ...boxes, ...lines);
  map.addEventListener('mouseover', (e) => {
    const g = e.target.closest && e.target.closest('.topo-host');
    map.classList.toggle('lit', !!g);
    for (const p of map.querySelectorAll('.topo-link')) p.classList.toggle('on', !!g && (p.dataset.a === g.dataset.run || p.dataset.b === g.dataset.run));
  });
  map.addEventListener('mouseleave', () => map.classList.remove('lit'));
  const key = (cls, text) => h('span', { class: 'topo-key' }, h('i', { class: cls }), text);
  return h('div', {}, h('div', { class: 'topo-frame' }, map),
    h('div', { class: 'topo-legend mut' },
      key('k-box', 'subnet - a network an up adapter is on'), key('k-box virtual', 'virtual network - only virtual adapters on it'),
      key('k-link', 'connection recorded within a subnet'), key('k-link across', 'connection recorded across subnets'),
      h('span', {}, 'Computer: a client · tower: a server or domain controller (DC) · router: the default gateway the hosts state (whether it filters is not recorded). A virtual adapter is a virtual switch\'s, host-only network\'s, VPN\'s or tunnel\'s, by its type and device name; a virtual machine\'s own adapter is its real link. Hover a host to light its connections.')));
}

// subnetsView is one row per subnet: its hosts and what they state of it.
export function subnetsView(t) {
  const owner = new Map(t.subnets.flatMap((s) => s.hosts.map((x) => [x.address, x.host])));
  const named = (ips) => ips.map((ip) => (owner.has(ip) ? `${ip} (${owner.get(ip)})` : ip)).join('\n');
  const rows = t.subnets.map((s) => ({ ...s, hosts_n: s.hosts.length, network_kind: s.virtual ? 'virtual' : 'not named virtual', host_text: s.hosts.map((x) => `${x.host} ${x.address} ${x.adapter}`).join('\n'), gateway_list: named(s.gateways), dns_list: named(s.dns_servers), dhcp_list: named(s.dhcp_servers) }));
  return dataTable(rows, [
    col('subnet', 'subnet', { label: 'Subnet', icon: 'topology', desc: 'A network an adapter that is up is on: its address and prefix length, as the host configured it now.', wrap: false }),
    col('hosts_n', 'hosts_n', { label: 'Hosts', icon: 'hosts', desc: 'The hosts in view with an address on it.' }),
    col('host_text', 'host_text', { label: 'Hosts on it', icon: 'hosts', desc: 'Each host, its address and adapter (DHCP or set by hand).',
      render: (v, r) => h('div', {}, ...r.hosts.map((x) => h('div', {}, hostLink(x), h('span', { class: 'mut' }, ` ${x.address} · ${x.adapter}${x.dhcp === 'yes' ? ' · DHCP' : ''}${x.virtual ? ` · virtual (${x.virtual})` : ''}`)))) }),
    col('network_kind', 'network_kind', { label: 'Network', icon: 'layers', desc: "Virtual when every adapter on it is virtual - a virtual switch's, host-only network's, VPN's or tunnel's, by its interface type and device name. A virtual machine's own adapter is its real link and is not called virtual." }),
    col('gateway_list', 'gateway_list', { label: 'Gateways', icon: 'link', desc: 'The default gateways the hosts on it state; a host in view with that address is named.' }),
    col('dns_list', 'dns_list', { label: 'DNS servers', icon: 'server', desc: 'The DNS servers the hosts on it ask; a host in view with that address is named.' }),
    col('dhcp_list', 'dhcp_list', { label: 'DHCP servers', icon: 'server', desc: 'The DHCP servers that gave the hosts on it their address.' }),
  ], { rowKey: (r) => r.subnet, height: 'auto', filename: 'topology-subnets' });
}

// linksView is every connection a host recorded with another host in view.
export function linksView(t) {
  return dataTable(t.links, [
    col('recorded_by', 'recorded_by', { label: 'Recorded by', icon: 'hosts', desc: 'The host whose run recorded the connection. A connection open now does not record which end opened it, so this is not said to be the host that connected.',
      render: (v, r) => hostLink({ host: v, run_id: r.recorded_run_id }) }),
    col('peer', 'peer', { label: 'With', icon: 'peer', desc: 'The host in view that has the other end\'s address now (its adapters). The address may have belonged to another machine when the connection was recorded.',
      render: (v, r) => hostLink({ host: v, run_id: r.peer_run_id }) }),
    col('address', 'net_address'), col('port', 'net_port'), col('program', 'net_program'), col('records', 'net_records'), col('seen_in', 'net_seen_in'),
    col('first_seen'), col('last_seen'),
  ], { rowKey: (r) => [r.recorded_run_id, r.peer_run_id, r.port, r.program].join('|'), height: 'auto', filename: 'topology-connections' });
}

// othersView is every private address talked to that no host in view has.
export function othersView(t) {
  const rows = t.others.map((o) => ({ ...o, host_list: o.hosts.join('\n'), seen_n: o.hosts.length }));
  return dataTable(rows, [
    col('address', 'net_address', { desc: 'A private address the hosts were connected with that no host in view has - a host not imported, a server, a printer, or an address that has moved.' }),
    col('subnet', 'subnet', { label: 'Subnet', icon: 'topology', desc: 'The subnet in view it falls in; empty when it is on none of them.' }),
    col('ports', 'ports', { label: 'Ports', icon: 'value', desc: 'The ports used with it.' }),
    col('records', 'net_records'),
    col('host_list', 'host_list', { label: 'Talked to by', icon: 'hosts', desc: 'The hosts in view that recorded a connection with it.' }),
  ], { rowKey: (r) => r.address, height: 'scroll', filename: 'topology-other-addresses' });
}

// unreadView names the hosts placed nowhere: their adapters were not read.
export function unreadView(t) {
  return h('div', {}, h('p', { class: 'mut' }, 'Their adapters were not read - the Network module did not run, or the run is from Signal before 0.73.0. They are not shown on the map; that is not "on no network".'),
    h('div', {}, ...t.unread.map((x, i) => h('span', {}, i ? ', ' : '', hostLink(x)))));
}
