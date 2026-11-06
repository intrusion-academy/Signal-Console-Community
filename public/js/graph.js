// entityGraph draws the Signals page's entities and the entities their
// signals name as one graph, built to scope an investigation: a node per
// entity across the hosts in view (the same account or program on several
// hosts is one node, ringed), drawn as its type's icon, sized by the worst severity of its open
// signals and then their number - the most critical catch the eye first -
// coloured by that severity - faded when none is open, grey when it has no signals of its
// own - and a line from each entity to every entity its signals name (an
// entity with no line is left out). Clicking a node lights what it is
// linked to and shows its cards on the graph's right: the hosts it has
// signals on (each opening its page there), its links, what Signal read
// about it with VirusTotal's answer, and its analyst flag - an entity
// VirusTotal called malicious or suspicious carries a "VT" mark; dragging a node
// moves it; the graph zooms and pans, and arranges the entities in focus
// into shapes or their order in time. An analyst may add entities and
// links Signal did not report (src/analystGraph.js): drawn apart - framed,
// dashed, in the accent - and named as the analyst's everywhere. A simple
// force layout, run a fixed number of steps.
import { h, mono, svgIcon, iconMarkup, fetchJSON, ts } from './dom.js';
import { svgEl, sevTag, entityIcon, SEVERITY_RANK, checkboxDropdown, roleWords, fullWindow, bigModeButtons, factsCard, ENTITY_TYPES } from './components.js';
import { pageLink } from './router.js';
import { flagReason } from './table.js';

const W = 1200;
// LIMIT is how many entities the graph draws without asking: above it the
// analyst is warned of the wait and may draw anyway (measured 2026-11-04
// in a browser on a 1,000-host test fleet: 2,400 entities with 14,000 links
// laid out in 12-25 s; the work grows faster than the count).
const LIMIT = 1500;
// CELL is the reach of the layout's repulsion (both act on nodes closer than
// 120 px), so only nodes in touching CELL squares are compared.
const CELL = 120;
// SIZE is a node's radius by the worst severity of its open signals - the
// most severe catch the eye first; more open signals add to it, never
// past the next severity's size.
const SIZE = { critical: 34, high: 21, medium: 13, low: 9 }; // each step clearly bigger than the one below
const radius = (n) => (n.analyst ? 12 : n.open ? (SIZE[n.severity] || 9) + Math.min(4, Math.sqrt(n.open - 1) * 1.5) : n.hosts.length ? 7 : 5);
const HINT = 'Click an entity to light what it is linked to and see its cards; Ctrl (⌘) or Shift + click, or Select many, adds more to the selection; Fold cards uncovers the entities behind them; hover an entity to see its links at a glance; drag it to move it. Depth: how many links from the selection are lit (and kept by Hide others). With two selected, Shortest path shows the chain of links between them. Insights lists the most connected entities, those on the most hosts, the separate groups and what analysts marked. Zoom with the wheel; drag the background to move; ⤢ fills the window, ⛶ the screen; Fit, Reset. Search by type or name (Enter goes to each match). Types, Hosts, Rules and Relationships narrow what is drawn. Arrange lays out the selection and its links (else every entity shown). Image saves the view as a PNG. Keys, with the graph focused: Esc clears the selection, F fits.';
const worse = (a, b) => (!a || (b && (SEVERITY_RANK[b] ?? 9) < (SEVERITY_RANK[a] ?? 9)) ? b : a);
// ANALYST_WORDS is how a link an analyst added reads when they gave no words.
const ANALYST_WORDS = 'linked by an analyst';
// BY_ANALYST is the Rules filter's choice for the links analysts added.
const BY_ANALYST = 'added by an analyst';

// buildGraph merges the rows (one per host and entity) into a node per
// entity and their links, at most MAX nodes, with the analyst's entities
// and links (src/analystGraph.js) added.
function buildGraph(rows, analyst) {
  const nodes = new Map();
  const node = (x) => {
    const k = x.node || x.id; // an account known by name alone is one host's (model/entities.js nodeId)
    if (!nodes.has(k)) nodes.set(k, { key: k, id: x.id, type: x.type, display: x.display || x.id, hosts: [], open: 0, severity: '', first: '', links: new Set(), words: new Map(), analyst: null });
    return nodes.get(k);
  };
  for (const r of rows) {
    const n = node(r);
    n.hosts.push({ run_id: r.run_id, host: r.host, severity: r.severity, open_n: r.open_n });
    n.open += r.open_n;
    n.severity = worse(n.severity, r.severity);
    if (r.first_seen && (!n.first || r.first_seen < n.first)) n.first = r.first_seen;
  }
  const edges = new Map();
  // A link's words are kept on both ends, each read from that end: a
  // program's "started by" is its parent's "started".
  const say = (from, to, words) => {
    if (!from.words.has(to)) from.words.set(to, new Set());
    from.words.get(to).add(words);
  };
  const edge = (a, b) => {
    const key = [a.key, b.key].sort().join('\u0000');
    if (!edges.has(key)) edges.set(key, { a, b, rules: new Set(), roles: new Set(), analyst: [] });
    a.links.add(b); b.links.add(a);
    return edges.get(key);
  };
  for (const r of rows) {
    for (const x of r.related || []) {
      const rk = r.node || r.id, xk = x.node || x.id;
      if (xk === rk) continue;
      const a = nodes.get(rk), b = node(x);
      const e = edge(a, b);
      for (const rule of x.rules || []) e.rules.add(rule);
      for (const role of x.roles || []) {
        e.roles.add(role);
        say(a, b, roleWords(role));
        say(b, a, roleWords(role, true));
      }
    }
  }
  // Hosts: each linked entity is joined to every host it has signals on (a
  // node per host - the same as the host's own entity), so an account or a
  // program on several hosts shows which. Only entities already drawn are
  // joined; a host's line says "on this host", never more. With one host in
  // view it would only tie everything to it, so it is left out.
  const manyHosts = new Set(rows.map((r) => r.host)).size > 1;
  for (const n of manyHosts ? [...nodes.values()] : []) {
    if (n.type === 'host' || !n.links.size) continue;
    for (const x of n.hosts) {
      const hn = node({ id: `host:${String(x.host).toLowerCase()}`, type: 'host', display: x.host });
      if (hn === n) continue;
      edge(n, hn);
      say(n, hn, 'on this host');
      say(hn, n, 'has signals about it');
    }
  }
  for (const x of analyst.entities) node({ node: x.key, id: x.key, type: x.type, display: x.name }).analyst = x;
  for (const l of analyst.links) {
    const a = nodes.get(l.a), b = nodes.get(l.b);
    if (!a || !b) continue; // an end outside the hosts in view
    edge(a, b).analyst.push(l);
    const words = `${l.words || ANALYST_WORDS} (added by ${l.added_by})`;
    say(a, b, words);
    say(b, a, words);
  }
  return { list: [...nodes.values()].filter((n) => n.links.size || n.analyst), edges: [...edges.values()] };
}

// layout places the nodes: near pairs repel, every link pulls, all drift to
// the centre.
// nearPairs calls fn(a, b) once for every pair of nodes in the same or
// touching CELL squares - every pair closer than CELL - yielding its share
// of the pass done every 64 nodes.
function* nearPairs(list, fn) {
  const grid = new Map();
  const cell = (v) => Math.floor(v / CELL) + 64; // + 64: a node moved a little past the edge keeps its own key
  list.forEach((n, i) => {
    n.i = i;
    const k = cell(n.x) * 4096 + cell(n.y), c = grid.get(k);
    if (c) c.push(n); else grid.set(k, [n]);
  });
  for (let i = 0; i < list.length; i++) {
    const a = list[i], cx = cell(a.x), cy = cell(a.y);
    for (let gx = cx - 1; gx <= cx + 1; gx++) {
      for (let gy = cy - 1; gy <= cy + 1; gy++) {
        const c = grid.get(gx * 4096 + gy);
        if (c) for (const b of c) if (b.i > i) fn(a, b);
      }
    }
    if (i % 64 === 63) yield i / list.length;
  }
}

// runAll runs a layout generator to its end at once.
const runAll = (g) => { while (!g.next().done); };

// layout and spreadOut are generators: they yield their share of the work
// done (0-1), so a large graph can be laid out between frames (place).
function* layout(list, edges, H) {
  for (const n of list) { n.x = W / 2 + (Math.random() - 0.5) * W * 0.8; n.y = H / 2 + (Math.random() - 0.5) * H * 0.8; }
  for (let step = 0; step < 300; step++) {
    const t = 1 - step / 300;
    for (const a of list) { a.dx = (W / 2 - a.x) * 0.05; a.dy = (H / 2 - a.y) * 0.05; }
    for (const f of nearPairs(list, (a, b) => {
      const dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 0.01, f = d2 < 14400 ? 800 / d2 : 0; // only near nodes repel each other
      a.dx += dx * f; a.dy += dy * f; b.dx -= dx * f; b.dy -= dy * f;
    })) yield (step + f) / 300;
    for (const { a, b } of edges) {
      const dx = b.x - a.x, dy = b.y - a.y, f = 0.05;
      a.dx += dx * f; a.dy += dy * f; b.dx -= dx * f; b.dy -= dy * f;
    }
    for (const a of list) {
      a.x = Math.min(W - 20, Math.max(20, a.x + Math.max(-20, Math.min(20, a.dx)) * t));
      a.y = Math.min(H - 20, Math.max(20, a.y + Math.max(-20, Math.min(20, a.dy)) * t));
    }
  }
}

// spreadOut is the default view: the laid-out nodes stretched over the whole
// graph (room on the right for the labels), then moved apart until no two
// overlap - what Reset returns to.
function* spreadOut(list, H) {
  const box = (k) => [Math.min(...list.map((n) => n[k])), Math.max(...list.map((n) => n[k]))];
  const [x0, x1] = box('x'), [y0, y1] = box('y');
  for (const n of list) {
    n.x = 40 + ((n.x - x0) / (x1 - x0 || 1)) * (W - 280);
    n.y = 40 + ((n.y - y0) / (y1 - y0 || 1)) * (H - 80);
  }
  for (let pass = 0; pass < 80; pass++) {
    let moved = false;
    for (const f of nearPairs(list, (a, b) => {
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 0.01, gap = (radius(a) + radius(b)) * 1.12 + 14 - d; // their circles (see the nodes) never touch
      if (gap <= 0) return;
      moved = true;
      a.x -= (dx / d) * gap / 2; a.y -= (dy / d) * gap / 2; b.x += (dx / d) * gap / 2; b.y += (dy / d) * gap / 2;
    })) yield (pass + f) / 80;
    for (const n of list) { n.x = Math.min(W - 240, Math.max(20, n.x)); n.y = Math.min(H - 20, Math.max(20, n.y)); }
    if (!moved) break;
  }
}

// shape is where each of the nodes goes for an arrangement, around (cx,
// cy): a star (the centre - the selection, else the most severe - in the
// middle, the rest around it), a row or a column (most severe first), a
// circle, a grid, or a row in time order (first seen; unknown last).
function shape(kind, nodes, centre, cx, cy) {
  const gap = Math.max(...nodes.map(radius)) * 2.3 + 36;
  const out = new Map();
  const ring = (list, r, turn = 0) => list.forEach((n, i) => {
    const a = turn + (2 * Math.PI * i) / list.length - Math.PI / 2;
    out.set(n, { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) });
  });
  const line = (list, dx, dy) => list.forEach((n, i) => out.set(n, { x: cx + (i - (list.length - 1) / 2) * dx, y: cy + (i - (list.length - 1) / 2) * dy }));
  const sorted = nodes.slice().sort(bySeverity);
  if (kind === 'star') {
    const middle = centre.length ? centre : sorted.slice(0, 1);
    const rest = sorted.filter((n) => !middle.includes(n));
    const inner = middle.length > 1 ? Math.max(gap, (gap * middle.length) / (2 * Math.PI)) : 0;
    if (middle.length > 1) ring(middle, inner); else out.set(middle[0], { x: cx, y: cy });
    ring(rest, Math.max(inner + gap * 1.6, (gap * rest.length) / (2 * Math.PI)), Math.PI / Math.max(1, rest.length));
  } else if (kind === 'row') {
    line(sorted, gap, 0);
  } else if (kind === 'column') {
    line(sorted, 0, gap * 0.7);
  } else if (kind === 'circle') {
    ring(sorted, Math.max(gap * 1.2, (gap * sorted.length) / (2 * Math.PI)));
  } else if (kind === 'grid') {
    const cols = Math.ceil(Math.sqrt(sorted.length));
    sorted.forEach((n, i) => out.set(n, { x: cx + ((i % cols) - (cols - 1) / 2) * gap * 1.6, y: cy + (Math.floor(i / cols) - (Math.ceil(sorted.length / cols) - 1) / 2) * gap }));
  } else if (kind === 'timeline') {
    line(nodes.slice().sort((a, b) => (a.first || '\uffff').localeCompare(b.first || '\uffff') || bySeverity(a, b)), gap * 1.5, 0);
  }
  return out;
}

const label = (n) => `${n.type}: ${n.display}`;
// wordsOf is what m is to n, as their links' roles say ("started by").
const wordsOf = (n, m) => [...(n.words.get(m) || [])].join(', ');
const vtWords = (v) => `${v.malicious} malicious, ${v.suspicious} suspicious of ${v.engines} engines`;
const short = (s) => (s.length > 28 ? s.slice(0, 27) + '…' : s);
const bySeverity = (a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || b.open - a.open;

// icon is a node's drawing: its type's icon, 2r wide, outlined in its
// severity's colour and filled with a tint of it.
function icon(type, r, color) {
  const el = svgEl('svg', { x: -r, y: -r, width: 2 * r, height: 2 * r, viewBox: '0 0 24 24', class: 'ent-graph-icon', style: `stroke: ${color}; fill: ${color}` });
  el.innerHTML = iconMarkup(entityIcon(type));
  return el;
}

// placeWhy puts a line's label - what its ends are to each other, and
// under it the rules whose signals link them - at its middle.
function placeWhy(l) {
  const x = (l.a.x + l.b.x) / 2;
  l.text.setAttribute('x', x);
  l.text.setAttribute('y', (l.a.y + l.b.y) / 2 - 3);
  for (const t of l.text.children) t.setAttribute('x', x);
}

// moveNode draws a node where it is now, its lines following.
function moveNode(n) {
  n.el.setAttribute('transform', `translate(${n.x},${n.y})`);
  for (const l of n.lines) {
    const end = l.a === n ? 1 : 2;
    l.el.setAttribute(`x${end}`, n.x);
    l.el.setAttribute(`y${end}`, n.y);
    placeWhy(l);
  }
}

// drag lets a node be moved with the pointer, its lines following; a move
// of a few pixels or more is a drag, not a click.
function drag(svg, n) {
  n.el.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    e.stopPropagation(); // a node moves; the graph does not pan
    n.el.setPointerCapture(e.pointerId);
    const toSvg = svg.getScreenCTM().inverse();
    const start = { x: e.clientX, y: e.clientY };
    n.dragged = false;
    const move = (ev) => {
      if (!n.dragged && Math.hypot(ev.clientX - start.x, ev.clientY - start.y) < 4) return;
      n.dragged = true;
      const pt = svg.createSVGPoint();
      pt.x = ev.clientX; pt.y = ev.clientY;
      const p = pt.matrixTransform(toSvg);
      n.x = p.x; n.y = p.y;
      moveNode(n);
    };
    const up = () => { n.el.removeEventListener('pointermove', move); n.el.removeEventListener('pointerup', up); };
    n.el.addEventListener('pointermove', move);
    n.el.addEventListener('pointerup', up);
  });
}

const still = () => Boolean(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

// zoomable lets the graph zoom (the wheel over it, around the pointer; the
// + and - buttons, around the centre) and pan (dragging its background) by
// moving its viewBox (start: the view to begin with); Reset shows it whole
// again. Returns the buttons. A pan of a few pixels or more is not a click
// (svg.panned).
function zoomable(svg, H, { fitBox, reset, start }) {
  const vb = start ? { ...start } : { x: 0, y: 0, w: W, h: H };
  const set = () => svg.setAttribute('viewBox', `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
  set();
  const zoom = (k, cx, cy) => {
    const w = Math.min(Math.max(W, vb.w), Math.max(W / 12, vb.w * k));
    const f = w / vb.w;
    vb.x = cx - (cx - vb.x) * f; vb.y = cy - (cy - vb.y) * f; vb.w = w; vb.h *= f;
    set();
  };
  const toSvg = (e) => {
    const pt = svg.createSVGPoint();
    pt.x = e.clientX; pt.y = e.clientY;
    return pt.matrixTransform(svg.getScreenCTM().inverse());
  };
  svg.addEventListener('wheel', (e) => {
    e.preventDefault(); // zoom the graph, not scroll the page
    const p = toSvg(e);
    zoom(Math.exp(Math.max(-100, Math.min(100, e.deltaY)) * 0.0014), p.x, p.y); // gentle: about 15% a wheel notch, in step with the wheel's speed
  }, { passive: false });
  svg.addEventListener('pointerdown', (e) => {
    svg.setPointerCapture(e.pointerId);
    const from = { x: e.clientX, y: e.clientY, vx: vb.x, vy: vb.y, scale: vb.w / svg.getBoundingClientRect().width };
    svg.panned = false;
    const move = (ev) => {
      if (!svg.panned && Math.hypot(ev.clientX - from.x, ev.clientY - from.y) < 4) return;
      svg.panned = true;
      vb.x = from.vx - (ev.clientX - from.x) * from.scale;
      vb.y = from.vy - (ev.clientY - from.y) * from.scale;
      set();
    };
    const up = () => { svg.removeEventListener('pointermove', move); svg.removeEventListener('pointerup', up); };
    svg.addEventListener('pointermove', move);
    svg.addEventListener('pointerup', up);
  });
  const centre = (k) => () => zoom(k, vb.x + vb.w / 2, vb.y + vb.h / 2);
  // fit shows a box (the visible entities) as large as the graph's frame
  // allows, keeping the graph's proportions.
  const fit = () => {
    const b = fitBox();
    if (!b) return;
    const w = Math.max(b.w, b.h * (W / H), 60), hh = w * (H / W);
    Object.assign(vb, { x: b.x + b.w / 2 - w / 2, y: b.y + b.h / 2 - hh / 2, w, h: hh });
    set();
  };
  // centreOn glides the view to a point at the same zoom (at once when the
  // system asks for reduced motion).
  let gliding = 0;
  const centreOn = (x, y) => {
    const from = { x: vb.x, y: vb.y }, to = { x: x - vb.w / 2, y: y - vb.h / 2 };
    const begin = performance.now(), mine = ++gliding;
    const step = (now) => {
      if (mine !== gliding) return; // a newer glide took over
      const t = still() ? 1 : Math.min(1, (now - begin) / 350), e = 1 - (1 - t) ** 3;
      vb.x = from.x + (to.x - from.x) * e; vb.y = from.y + (to.y - from.y) * e;
      set();
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };
  const bar = h('div', { class: 'ent-graph-zoom' },
    h('button', { class: 'ghost', title: 'Zoom in (or the mouse wheel over the graph)', onclick: centre(0.85) }, '+'),
    h('button', { class: 'ghost', title: 'Zoom out', onclick: centre(1 / 0.85) }, '−'),
    h('button', { class: 'ghost', title: 'Fit the entities shown to the graph', onclick: fit }, 'Fit'),
    h('button', { class: 'ghost', title: 'Start over, as when the page loads: layout, filter, search and view', onclick: (e) => reset(e.currentTarget.closest('.ent-graph-frame')) }, 'Reset'),
    ...bigModeButtons('.ent-graph-frame'));
  return { bar, centreOn, fit, view: () => ({ ...vb }) };
}

// IMAGE_STYLE are the computed styles copied onto each element of the saved
// image, so it looks as the graph does without the page's stylesheet.
const IMAGE_STYLE = ['display', 'visibility', 'opacity', 'fill', 'fill-opacity', 'stroke', 'stroke-width', 'stroke-opacity', 'stroke-dasharray',
  'stroke-linecap', 'stroke-linejoin', 'paint-order', 'font-family', 'font-size', 'font-weight', 'font-style', 'text-anchor', 'transform', 'transform-origin', 'transform-box'];

// saveImage downloads the graph's current view as a PNG at twice its size
// on screen, on the frame's background.
function saveImage(svg, frame) {
  const clone = svg.cloneNode(true);
  const from = [svg, ...svg.querySelectorAll('*')], to = [clone, ...clone.querySelectorAll('*')];
  from.forEach((el, i) => {
    const cs = window.getComputedStyle(el);
    to[i].setAttribute('style', IMAGE_STYLE.map((p) => `${p}:${cs.getPropertyValue(p)}`).join(';'));
  });
  const box = svg.getBoundingClientRect(), scale = 2;
  const [x, y, w, hh] = svg.getAttribute('viewBox').split(' ').map(Number);
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.setAttribute('width', box.width * scale);
  clone.setAttribute('height', box.height * scale);
  clone.prepend(svgEl('rect', { x, y, width: w, height: hh, fill: window.getComputedStyle(frame).backgroundColor || '#fff' }));
  const img = new window.Image();
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = box.width * scale;
    canvas.height = box.height * scale;
    canvas.getContext('2d').drawImage(img, 0, 0);
    canvas.toBlob((blob) => {
      const a = h('a', { href: URL.createObjectURL(blob), download: `entity-graph-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.png` });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    }, 'image/png');
  };
  img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(new window.XMLSerializer().serializeToString(clone));
}

// entityGraph is the graph of the rows. opts: flags (the graph keys of
// the entities analysts flagged, lower case), analyst ({entities, links} -
// GET /api/graph/analyst), editable (the account may change things), vt
// (GET /api/entities/virustotal: VirusTotal's flagged entities by ID),
// focus (the graph key of an entity to start selected - an entity's page),
// pickAnalyst (what of the analysts' entities and links to draw, after a
// change - those of the entity's page), bare (the options start hidden -
// the round button at the bottom right shows them).
// Reset draws it again from scratch, as when the page loads; a change by
// the analyst draws it again keeping the layout, view and selection - both
// in the same full-window or full-screen mode.
export function entityGraph(rows, opts = {}) {
  const wrap = h('div');
  const start = () => (opts.focus ? { chosen: [opts.focus], current: opts.focus } : null);
  // An entity's page starts with its entity selected, its cards folded
  // (the page says it all) and the view fitted to what is drawn.
  const ctx = { flags: new Set(opts.flags || []), analyst: opts.analyst || { entities: [], links: [] }, editable: Boolean(opts.editable), vt: opts.vt || {}, keep: start(), fresh: Boolean(opts.focus), bare: Boolean(opts.bare) };
  const show = (inWindow, onScreen) => {
    wrap.replaceChildren(drawGraph(rows, ctx));
    const next = wrap.querySelector('.ent-graph-frame');
    if (inWindow && next) fullWindow(next);
    if (onScreen && next && next.requestFullscreen) next.requestFullscreen();
  };
  // Above LIMIT the analyst is asked first (once for this graph), and the
  // layout runs between frames with its progress and a Stop - a redraw after
  // the analyst's change keeps the positions and lays out nothing.
  const draw = (frame) => {
    const inWindow = frame && frame.classList.contains('full-window'), onScreen = frame && document.fullscreenElement === frame;
    if (inWindow) fullWindow(frame);
    const { list, edges } = buildGraph(rows, ctx.analyst);
    if (list.length <= LIMIT || (ctx.keep && ctx.keep.pos)) return show(inWindow, onScreen);
    if (!ctx.big) {
      wrap.replaceChildren(bigWarning(list.length, rows, () => { ctx.big = true; draw(null); }));
      return;
    }
    const bar = h('progress', { max: 1, value: 0 });
    let stop = null;
    wrap.replaceChildren(h('div', { class: 'card' },
      h('div', {}, `Laying out ${list.length.toLocaleString()} entities - this takes a while; the page stays usable.`), bar, ' ',
      h('button', { class: 'ghost', onclick: () => stop && stop() }, 'Stop - draw as laid out so far')));
    stop = place(list, edges, heightOf(list), wrap, (f) => { bar.value = f; }, () => {
      ctx.laid = new Map(list.map((n) => [n.key, { x: n.x, y: n.y }]));
      show(inWindow, false); // full screen needs a click: not entered again after a wait
    });
  };
  ctx.reset = (frame) => { ctx.keep = start(); ctx.fresh = Boolean(opts.focus); draw(frame); };
  ctx.redraw = async (frame, keep) => {
    ctx.analyst = (opts.pickAnalyst || ((x) => x))(await fetchJSON('/api/graph/analyst'));
    ctx.keep = keep;
    draw(frame);
  };
  draw(null);
  return wrap;
}

// heightOf is the graph's height: room grows with the entities.
const heightOf = (list) => Math.max(500, Math.min(1400, list.length * 8));

// place lays the graph out between frames (about 30 ms of work at a time),
// telling progress(0-1) and then done() - also when the returned stop is
// called, keeping the positions reached. It ends quietly if its view (wrap)
// leaves the page.
function place(list, edges, H, wrap, progress, done) {
  const parts = [layout(list, edges, H), spreadOut(list, H)];
  let k = 0, over = false, shown = false;
  const end = () => { if (!over) { over = true; done(); } };
  const tick = () => {
    if (over) return;
    shown = shown || wrap.isConnected;
    if (shown && !wrap.isConnected) { over = true; return; }
    const until = performance.now() + 30;
    while (k < parts.length && performance.now() < until) {
      const r = parts[k].next();
      if (r.done) k++;
      else progress(k === 0 ? r.value * 0.75 : 0.75 + r.value * 0.25);
    }
    if (k < parts.length) setTimeout(tick, 0); else end();
  };
  setTimeout(tick, 0);
  return end;
}

// bigWarning is what the graph says above LIMIT entities: how many, the
// wait, and the choice - narrow the view (the page's filters, the Types
// filter after drawing) or draw anyway.
function bigWarning(n, rows, drawAnyway) {
  const hosts = new Set(rows.map((r) => r.run_id)).size;
  const wait = n > 5000 ? 'several minutes' : n > 2500 ? 'a minute or two' : 'up to half a minute'; // measured: 2,400 in 12-25 s
  return h('div', { class: 'card' },
    h('p', {}, h('b', {}, `${n.toLocaleString()} entities on ${hosts.toLocaleString()} host${hosts === 1 ? '' : 's'}`),
      ` - more than the ${LIMIT.toLocaleString()} the graph draws without asking.`),
    h('p', { class: 'mut' }, `Laying them out takes ${wait} (the page stays usable, with a Stop), and a graph this large is slow to move and hard to read. Fewer hosts (the Hosts filter above) give a graph that answers faster.`),
    h('button', { class: 'btn', onclick: drawAnyway }, 'Draw anyway'));
}

function drawGraph(rows, ctx) {
  const { list, edges } = buildGraph(rows, ctx.analyst);
  if (!list.length) return h('div', { class: 'mut' }, 'The signals name no other entities - nothing to connect.');
  const H = heightOf(list);
  // A layout made between frames (place) is used as it is.
  const laid = ctx.laid;
  ctx.laid = null;
  if (laid) for (const n of list) Object.assign(n, laid.get(n.key) || { x: W / 2, y: H / 2 });
  else if (!(ctx.keep && ctx.keep.pos && list.length > LIMIT)) { runAll(layout(list, edges, H)); runAll(spreadOut(list, H)); }
  else for (const n of list) Object.assign(n, { x: W / 2, y: H / 2 }); // a large redraw: the kept positions follow
  // An entity's page draws its entity close to what it is linked to - lines
  // half as long - so fitting the view shows entities and names about
  // twice as large.
  const hub = ctx.fresh && ctx.keep && list.find((n) => n.key === ctx.keep.current);
  if (hub) for (const n of list) Object.assign(n, { x: hub.x + (n.x - hub.x) / 2, y: hub.y + (n.y - hub.y) / 2 });
  for (const n of list) n.home = { x: n.x, y: n.y }; // where Arrange's "the layout" returns
  // A redraw after the analyst's change keeps every node where it was; a
  // new one starts beside an entity it is linked to.
  const kept = ctx.keep && ctx.keep.pos;
  if (kept) {
    for (const n of list) if (kept.has(n.key)) Object.assign(n, kept.get(n.key));
    for (const n of list) {
      if (kept.has(n.key)) continue;
      const near = [...n.links].find((m) => kept.has(m.key));
      Object.assign(n, near ? { x: near.x + 70, y: near.y + 50 } : { x: W / 2, y: H / 2 });
    }
  }

  const panel = h('div', { class: 'ent-graph-cards', hidden: true });
  // A line's rules are named without their module's prefix (EXEC-, PERSIST-):
  // the rest of the ID says what the rule saw.
  const lines = edges.map((e) => {
    const added = e.analyst.map((l) => l.words || ANALYST_WORDS);
    return { ...e, ruleIds: [...e.rules], rules: [...e.rules].map((r) => r.replace(/^[A-Z]+-/, '')).join(', '),
      // thicker the more rules and relationships say so
      el: svgEl('line', { x1: e.a.x, y1: e.a.y, x2: e.b.x, y2: e.b.y, class: 'ent-graph-edge' + (e.analyst.length ? ' analyst' : ''),
        style: `--w: ${1 + Math.min(2, (e.rules.size + e.roles.size + added.length - 1) * 0.4)}` }), text: svgEl('text', { class: 'ent-graph-why' }) };
  });
  lines.forEach(placeWhy);
  for (const n of list) n.lines = [];
  for (const l of lines) { l.a.lines.push(l); if (l.b !== l.a) l.b.lines.push(l); } // each node's lines, in one pass
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, class: 'ent-graph', role: 'img', 'aria-label': `${list.length} entities, ${edges.length} links` });
  // show is what is drawn: the entity types and hosts chosen (all, when
  // none is), and a selected entity with everything linked to it, whatever
  // its type or host. A search's matches show whatever their type. The
  // Rules filter keeps the lines of the chosen rules, and the entities
  // those lines join. Hide others leaves the selection and what is within
  // Depth links of it alone.
  let types = null;
  let roles = null; // the roles chosen (all, when none is)
  let hosts = null; // the hosts chosen (all, when none is)
  let rulesSel = null; // the rules chosen (all, when none is)
  let depth = 1; // how many links from the selection are in focus
  let path = null; // the shortest path shown: its entities in order
  let extra = null; // the Insights or legend card, while open
  let alone = false; // Hide others
  // chosen are the selected entities - one, or several when Ctrl (⌘) is
  // held or "Select many" is on; current is the one whose cards are shown
  // (the last chosen).
  const chosen = new Set();
  let current = null;
  let many = false;
  let form = null; // the analyst's add-an-entity card, while open
  // addKey: does this click add to the selection - Ctrl (⌘) held, or Select many on.
  const addKey = (e) => many || Boolean(e && (e.ctrlKey || e.metaKey || e.shiftKey));
  let shut = ctx.fresh; // the cards folded away to a tab, so every entity can be clicked
  let found = null;
  let shortNames = true; // names cut short by default
  // focus is the selected entities, those within depth links of them, and
  // the path shown (refocus works it out once per drawing).
  let focus = new Set();
  const refocus = () => {
    focus = new Set(chosen);
    let edge = [...chosen];
    for (let d = 0; d < depth; d++) {
      const next = [];
      for (const c of edge) for (const m of c.links) if (!focus.has(m)) { focus.add(m); next.push(m); }
      edge = next;
    }
    for (const m of path || []) focus.add(m);
  };
  const inFocus = (m) => focus.has(m);
  // names writes each label: whole, or cut when short names are on - but
  // whole for the selected entities, their links and a search's matches.
  const names = () => {
    for (const m of list) m.text.textContent = !shortNames || inFocus(m) || (found && found.has(m)) ? m.full : m.brief;
  };
  // onHost: one of the chosen hosts has signals about it - or, for an
  // entity with none of its own, about an entity it is linked to.
  const onHost = (m) => !hosts || m.hosts.some((x) => hosts.has(x.host)) || (!m.hosts.length && [...m.links].some((o) => o.hosts.some((x) => hosts.has(x.host))));
  const show = () => {
    refocus();
    names();
    const narrowed = alone && chosen.size > 0;
    const base = (m) => (narrowed ? inFocus(m) : (((!types || types.has(m.type)) && onHost(m)) || Boolean(m.analyst) || inFocus(m) || Boolean(found && found.has(m))));
    const said = (l) => !roles || [...l.roles].some((r) => roles.has(r));
    const ruled = (l) => !rulesSel || l.ruleIds.some((r) => rulesSel.has(r)) || (l.analyst.length > 0 && rulesSel.has(BY_ANALYST));
    const lineOk = (l) => base(l.a) && base(l.b) && said(l) && ruled(l) && (!narrowed || (focus.has(l.a) && focus.has(l.b)));
    const joined = new Set(lines.filter(lineOk).flatMap((l) => [l.a, l.b]));
    const seen = (m) => base(m) && (!rulesSel || joined.has(m) || chosen.has(m) || Boolean(found && found.has(m)));
    for (const m of list) m.el.style.display = seen(m) ? '' : 'none';
    for (const l of lines) for (const el of [l.el, l.text]) el.style.display = lineOk(l) && seen(l.a) && seen(l.b) ? '' : 'none';
  };
  // select makes n the selection, or - add - adds it to the selection, or
  // takes it out when it is in already; null clears it.
  const select = (n, add) => {
    path = null;
    if (!add) chosen.clear();
    if (n && add && chosen.has(n)) {
      chosen.delete(n);
      if (current === n) current = [...chosen].pop() || null;
    } else if (n) {
      chosen.add(n);
      current = n;
    } else {
      current = null;
    }
    paint();
  };
  const paint = () => {
    show();
    svg.classList.toggle('focus', chosen.size > 0);
    for (const m of list) {
      m.el.classList.toggle('lit', inFocus(m));
      m.el.classList.toggle('sel', chosen.has(m));
      m.el.classList.toggle('onpath', Boolean(path) && path.includes(m));
      m.flag.style.display = ctx.flags.has(m.key.toLowerCase()) ? '' : 'none';
    }
    for (const l of lines) {
      const from = chosen.has(l.a) ? l.a : chosen.has(l.b) ? l.b : null;
      const lit = chosen.size > 0 && focus.has(l.a) && focus.has(l.b);
      for (const el of [l.el, l.text]) el.classList.toggle('lit', lit);
      l.el.classList.toggle('path', Boolean(path) && path.includes(l.a) && path.includes(l.b) && Math.abs(path.indexOf(l.a) - path.indexOf(l.b)) === 1);
      // the label reads from a selected end: what the other end is to it,
      // and under it the rules whose signals say so
      if (from) {
        const words = wordsOf(from, from === l.a ? l.b : l.a);
        l.text.replaceChildren(...(words ? [svgEl('tspan', {}, words)] : []),
          ...(l.rules ? [svgEl('tspan', { class: 'ent-graph-rules', ...(words ? { dy: '1.15em' } : {}) }, l.rules)] : []));
        placeWhy(l);
      }
    }
    panel.hidden = !current && !form && !extra;
    panel.classList.toggle('shut', shut);
    // The cards fold away to a tab - they cover the entities behind them.
    const fold = h('button', { class: 'ghost ent-graph-fold', title: shut ? 'Show the cards' : 'Fold the cards away, to click the entities behind them',
      onclick: (e) => { e.stopPropagation(); shut = !shut; paint(); } }, shut ? `‹ Cards${chosen.size > 1 ? ` - ${chosen.size} selected` : ''}` : 'Fold cards ›');
    panel.replaceChildren(fold, ...(shut ? [] : [...(form ? [form] : []), ...(extra ? [extra()] : []), ...(chosen.size > 1 ? [selectedCard()] : []), ...(path ? [pathCard()] : []), ...(current ? details(current) : [])]));
  };
  const frameOf = () => svg.closest('.ent-graph-frame');
  // keep is what a redraw after the analyst's change holds on to.
  const keep = (select) => ({ pos: new Map(list.map((n) => [n.key, { x: n.x, y: n.y }])), view: zoom.view(), chosen: [...chosen].map((n) => n.key), current: select || (current && current.key) });
  const change = async (call) => {
    try {
      await call();
    } catch (err) {
      window.alert(err.message); // the analyst's change failed: say why
      return;
    }
    ctx.redraw(frameOf(), keep());
  };
  const post = (url, body) => fetchJSON(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const card = (title, ...body) => h('div', { class: 'ent-graph-card' }, h('div', { class: 'sig-side-title' }, title), ...body);
  const factsOf = new Map(); // what Signal read about an entity, fetched once
  // details is the cards of a selected entity: what it is, the hosts it has
  // signals on (each opening its page there), what it is linked to (each
  // selectable; Ctrl or ⌘ adds it to the selection), the links analysts
  // added, its flag, and what Signal read about it with VirusTotal's answer.
  const details = (n) => {
    const links = [...n.links].sort(bySeverity);
    const added = n.lines.flatMap((l) => l.analyst.map((x) => [x, l.a === n ? l.b : l.a]));
    const out = [
      card(h('span', {}, svgIcon(entityIcon(n.type)), ' ', n.type), mono(n.display),
        n.severity ? h('div', {}, sevTag(n.severity), h('span', { class: 'mut' }, ` - ${n.open} open signal${n.open === 1 ? '' : 's'}`)) : null,
        n.analyst ? h('div', { class: 'ent-graph-analyst-note' }, `Added by ${n.analyst.added_by}, ${ts(n.analyst.at)} - the analyst's entity, not one Signal reported.`) : null,
        n.analyst && n.analyst.note ? h('div', {}, n.analyst.note) : null,
        n.analyst && ctx.editable ? h('button', { class: 'ghost danger', onclick: () => change(() => fetchJSON(`/api/graph/analyst/entities/${n.analyst.id}`, { method: 'DELETE' })) }, 'Remove this entity and its links') : null),
      card(n.hosts.length ? `Signals on ${n.hosts.length} host${n.hosts.length === 1 ? '' : 's'}` : 'No signals of its own',
        ...(n.hosts.length
          ? n.hosts.map((x) => h('div', {}, sevTag(x.severity), ' ', pageLink('signals', { entity: n.id, host: x.run_id }, x.host), h('span', { class: 'mut' }, ` - ${x.open_n} open`)))
          : [h('div', { class: 'mut' }, n.analyst ? 'Signal reported nothing about it.' : 'It is named by the signals of the entities it is linked to.')])),
      card(`Linked to ${links.length}`, h('div', { class: 'ent-graph-links' }, ...links.map((m) => h('button', { class: 'ghost', title: label(m), onclick: (e) => go(m, e) },
        wordsOf(n, m) ? h('span', { class: 'mut' }, `${wordsOf(n, m)} `) : null, svgIcon(entityIcon(m.type)), ' ', m.severity ? sevTag(m.severity, m.display) : m.display)))),
    ];
    if (added.length) {
      out.push(card(`Links added by analysts (${added.length})`, ...added.map(([x, m]) => h('div', { class: 'ent-graph-chosen' },
        h('span', {}, h('span', { class: 'mut' }, `${x.words || ANALYST_WORDS}: `), m.display, h('span', { class: 'mut' }, ` - ${x.added_by}, ${ts(x.at)}`)),
        ctx.editable ? h('button', { class: 'ghost', title: 'Remove this link', 'aria-label': 'Remove this link', onclick: () => change(() => fetchJSON(`/api/graph/analyst/links/${x.id}`, { method: 'DELETE' })) }, '×') : null))));
    }
    const flagged = ctx.flags.has(n.key.toLowerCase());
    out.push(card('Flagged by analysts', h('div', { class: 'mut' }, flagged ? 'Flagged - listed in Overview\'s "Flagged items".' : 'Not flagged.'),
      ctx.editable ? h('button', { class: 'ghost', onclick: async () => {
        const reason = flagged ? '' : flagReason(label(n));
        if (!flagged && !reason) return;
        await fetchJSON('/api/flags', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: 'entities', key: n.key.toLowerCase(), label: label(n), on: !flagged, reason }) });
        if (flagged) ctx.flags.delete(n.key.toLowerCase()); else ctx.flags.add(n.key.toLowerCase());
        paint();
      } }, svgIcon('flagged'), flagged ? ' Remove the flag' : ' Flag it') : null));
    // What Signal read about it, from a collection that knows it: its own
    // host's, else a linked entity's (the run that named it).
    const run = n.analyst ? null : (n.hosts[0] || [...n.links].flatMap((m) => m.hosts)[0] || {}).run_id;
    if (run) {
      const slot = h('div', { class: 'ent-graph-card' }, h('span', { class: 'mut' }, 'Reading what Signal read about it…'));
      const fill = (facts) => slot.replaceChildren(factsCard(`What Signal read about the ${n.type}`, entityIcon(n.type), facts));
      if (factsOf.has(n.key)) fill(factsOf.get(n.key));
      else fetchJSON(`/api/entities/facts?host=${encodeURIComponent(run)}&ids=${encodeURIComponent(n.id)}`).then((f) => { factsOf.set(n.key, f[n.id] || null); fill(f[n.id] || null); }).catch(() => slot.remove());
      out.push(slot);
    }
    if (ctx.editable && chosen.size > 1 && chosen.has(n)) {
      const words = h('input', { type: 'text', class: 'cond-value', placeholder: 'what the link is, e.g. same operator' });
      out.push(card(`Link ${n.display} to the other ${chosen.size - 1} selected`, words,
        h('button', { class: 'btn', onclick: () => change(() => Promise.all([...chosen].filter((m) => m !== n).map((m) => post('/api/graph/analyst/links', { a: n.key, b: m.key, words: words.value })))) }, 'Add the links')));
    }
    return out;
  };
  // addForm is the card where an analyst adds an entity Signal did not
  // report, linked to the selected entities if they wish.
  const addForm = () => {
    const type = h('select', {}, ...ENTITY_TYPES.map((t) => h('option', { value: t }, t)), h('option', { value: 'other' }, 'other'));
    const name = h('input', { type: 'text', class: 'cond-value', placeholder: 'name, e.g. 203.0.113.7 or C:\\temp\\x.exe' });
    const note = h('input', { type: 'text', class: 'cond-value', placeholder: 'where it came from (optional)' });
    const words = h('input', { type: 'text', class: 'cond-value', placeholder: 'what the link is (optional)' });
    const linkTo = [...chosen];
    return card('Add an entity (the analyst\'s)', h('label', { class: 'toggle' }, 'Type ', type), name, note,
      linkTo.length ? h('div', {}, h('div', { class: 'mut' }, `Linked to the ${linkTo.length} selected:`), words) : h('div', { class: 'mut' }, 'Select entities first to link it to them.'),
      h('div', { class: 'row' },
        h('button', { class: 'btn', onclick: () => change(async () => {
          const e = await post('/api/graph/analyst/entities', { type: type.value, name: name.value, note: note.value });
          await Promise.all(linkTo.map((m) => post('/api/graph/analyst/links', { a: e.key, b: m.key, words: words.value })));
          form = null;
        }) }, 'Add'),
        h('button', { class: 'ghost', onclick: () => { form = null; paint(); } }, 'Cancel')));
  };
  // selectedCard lists the selected entities: each shows its cards, × takes
  // it out of the selection.
  const selectedCard = () => h('div', { class: 'ent-graph-card' }, h('div', { class: 'sig-side-title' }, `Selected ${chosen.size}`),
    h('div', { class: 'ent-graph-links' }, ...[...chosen].map((m) => h('div', { class: 'ent-graph-chosen' },
      h('button', { class: 'ghost', title: `Show its cards - ${label(m)}`, onclick: () => { current = m; paint(); } },
        svgIcon(entityIcon(m.type)), ' ', m === current ? h('b', {}, m.display) : m.display),
      h('button', { class: 'ghost', title: 'Take it out of the selection', 'aria-label': `Take ${m.display} out of the selection`, onclick: () => select(m, true) }, '×')))),
    chosen.size === 2 ? h('button', { class: 'ghost', title: 'The shortest chain of links between the two selected entities', onclick: () => {
      const [a, b] = [...chosen];
      path = shortestPath(a, b) || [];
      paint();
    } }, 'Shortest path between them') : null,
    h('button', { class: 'ghost', onclick: () => select(null) }, 'Clear the selection'));
  // shortestPath is the fewest links from a to b (breadth first), or null.
  const shortestPath = (a, b) => {
    const prev = new Map([[a, null]]);
    const queue = [a];
    for (let i = 0; i < queue.length && !prev.has(b); i++) for (const m of queue[i].links) if (!prev.has(m)) { prev.set(m, queue[i]); queue.push(m); }
    if (!prev.has(b)) return null;
    const seq = [];
    for (let c = b; c; c = prev.get(c)) seq.unshift(c);
    return seq;
  };
  // pathCard is the path shown: each entity, and between two what the next
  // one is to it.
  const pathCard = () => card(path.length ? `Shortest path - ${path.length - 1} link${path.length === 2 ? '' : 's'}` : 'No path',
    ...(path.length ? path.map((m, i) => h('div', {},
      i ? h('div', { class: 'mut ent-graph-step' }, `↓ ${wordsOf(path[i - 1], m) || 'linked'}`) : null,
      h('button', { class: 'ghost', title: label(m), onclick: () => centreOn(m.x, m.y) }, svgIcon(entityIcon(m.type)), ' ', m.severity ? sevTag(m.severity, m.display) : m.display)))
      : [h('div', { class: 'mut' }, 'They are not linked, even through other entities, in this graph.')]),
    h('button', { class: 'ghost', onclick: () => { path = null; paint(); } }, 'Clear the path'));
  // pick lists entities as buttons that select and bring each into view.
  const pick = (ms, note) => h('div', { class: 'ent-graph-links' }, ...ms.map((m) => h('button', { class: 'ghost', title: label(m), onclick: (e) => go(m, e) },
    svgIcon(entityIcon(m.type)), ' ', m.severity ? sevTag(m.severity, m.display) : m.display, h('span', { class: 'mut' }, ` ${note(m)}`))));
  // insights is what the graph says at a glance: its hubs, what spans hosts,
  // its separate groups (each selectable whole), and what analysts marked.
  const insights = () => {
    const top = (score) => list.filter((m) => score(m) > 0).sort((a, b) => score(b) - score(a) || bySeverity(a, b)).slice(0, 5);
    const groups = [];
    const done = new Set();
    for (const m of list) {
      if (done.has(m)) continue;
      const g = [m];
      done.add(m);
      for (let i = 0; i < g.length; i++) for (const x of g[i].links) if (!done.has(x)) { done.add(x); g.push(x); }
      groups.push(g);
    }
    groups.sort((a, b) => b.length - a.length);
    const marked = list.filter((m) => m.analyst || ctx.flags.has(m.key.toLowerCase()));
    const vtFlagged = list.filter((m) => ctx.vt[m.id]);
    const spanning = top((m) => (m.hosts.length > 1 ? m.hosts.length : 0));
    return card('Insights',
      h('div', { class: 'detail-title' }, 'Most connected'), pick(top((m) => m.links.size), (m) => `${m.links.size} links`),
      ...(spanning.length ? [h('div', { class: 'detail-title' }, 'On the most hosts'), pick(spanning, (m) => `${m.hosts.length} hosts`)] : []),
      h('div', { class: 'detail-title' }, 'Most open signals'), pick(top((m) => m.open), (m) => `${m.open} open`),
      h('div', { class: 'detail-title' }, `${groups.length} separate group${groups.length === 1 ? '' : 's'}`),
      h('div', { class: 'ent-graph-links' }, ...groups.slice(0, 5).map((g, i) => h('button', { class: 'ghost', title: 'Select every entity of this group', onclick: () => {
        path = null;
        chosen.clear();
        for (const m of g) chosen.add(m);
        current = g.slice().sort(bySeverity)[0];
        paint();
        zoom.fit();
      } }, `Group ${i + 1}: ${g.length} entities, worst ${g.slice().sort(bySeverity)[0].severity || 'none'}`))),
      ...(vtFlagged.length ? [h('div', { class: 'detail-title' }, 'Flagged by VirusTotal (its answer, not Signal\'s finding)'), pick(vtFlagged, (m) => vtWords(ctx.vt[m.id]))] : []),
      ...(marked.length ? [h('div', { class: 'detail-title' }, 'Flagged or created by analysts'), pick(marked, (m) => (m.analyst ? `created manually by ${m.analyst.added_by}` : 'flagged'))] : []));
  };
  // legend says what the drawing means.
  const legend = () => card('What you see',
    h('div', {}, 'A line joins an entity to one its signals name; a selected entity\'s lines say what each linked entity is to it, as the signal\'s record states it (else the rules whose signals link them); thicker: more rules or relationships say so.'),
    h('div', {}, 'One node per entity across hosts: a domain account is the same account, a program the same path (not necessarily the same file), an address the same address (a private one not necessarily the same machine); an account known by name alone is never joined across hosts.'),
    h('div', {}, 'Icon: its type. Size: the worst severity of its open signals, then how many. Colour: that severity. Moving dashed ring: on more than one host. Faded: none open. Grey: no signals of its own. Pulsing: an open critical signal. Red flag: flagged by an analyst. VT: VirusTotal called its file, address or domain malicious or suspicious - VirusTotal\'s answer, not Signal\'s finding.'),
    h('div', { class: 'ent-graph-analyst-note' }, 'Framed in a dashed square, in the accent, with dashed lines: created manually by the analyst named - their statement, not Signal\'s finding.'));
  for (const n of list) {
    const r = radius(n);
    const named = n.analyst || (n.hosts.length && (n.open > 0 || n.hosts.length > 1)); // labelled always; the rest when lit
    const fr = r * 1.12 + 5;
    n.el = svgEl('g', { class: `ent-graph-node${n.hosts.length && !n.open ? ' faded' : ''}${n.analyst ? ' analyst' : ''}` },
      svgEl('title', {}, n.analyst ? `${label(n)} - created manually by ${n.analyst.added_by} (the analyst's, not Signal's)`
        : `${label(n)} - ${n.hosts.length ? `${n.open} open signal(s) on ${n.hosts.map((x) => x.host).join(', ')}` : 'no signals of its own'}`),
      // the circles clear the icon at its grown size (it scales 1.12 on hover and selection)
      svgEl('circle', { r: r * 1.12 + 3, class: 'ent-graph-hit' }),
      n.hosts.length > 1 ? svgEl('circle', { r: r * 1.12 + 6, class: 'ent-graph-ring' }) : '',
      n.analyst ? svgEl('rect', { x: -fr, y: -fr, width: 2 * fr, height: 2 * fr, class: 'ent-graph-frame-analyst' }) : '',
      icon(n.type, r, n.analyst ? 'var(--acc)' : n.severity ? `var(--sev-${n.severity}, var(--mut))` : 'var(--mut)'),
      n.flag = svgEl('svg', { x: r * 0.5, y: -r * 1.12 - 12, width: 13, height: 13, viewBox: '0 0 24 24', class: 'ent-graph-flagmark' }),
      ctx.vt[n.id] ? svgEl('g', { class: 'ent-graph-vtmark', transform: `translate(${-r * 1.12 - 14} ${-r * 1.12 - 6})` },
        svgEl('title', {}, `VirusTotal: ${vtWords(ctx.vt[n.id])} - its answer, not Signal's finding`), svgEl('rect', { width: 18, height: 11, rx: 2 }), svgEl('text', { x: 9, y: 8.5 }, 'VT')) : '',
      n.text = svgEl('text', { x: r * 1.12 + (n.analyst ? 9 : 6), y: 4, class: named ? '' : 'opt' }),
      svgEl('text', { y: r * 1.12 + 18, class: 'ent-graph-when' }, n.analyst ? `created manually by ${n.analyst.added_by}` : n.first ? ts(n.first) : 'time not known'));
    n.flag.innerHTML = iconMarkup('flagged');
    const hostsNote = n.hosts.length > 1 ? ` (${n.hosts.length} hosts)` : '';
    const mark = n.analyst ? ` (created manually by ${n.analyst.added_by})` : '';
    n.full = label(n) + hostsNote + mark;
    n.brief = short(label(n)) + hostsNote + mark;
    n.text.textContent = n.brief;
    if (n.open && n.severity === 'critical') n.el.classList.add('urgent'); // pulses: triage first
    moveNode(n);
    // A click shows the entity's cards, folded or not, options shown or not.
    n.el.addEventListener('click', (e) => { e.stopPropagation(); if (!n.dragged) { shut = false; select(n, addKey(e)); } });
    // Hovering an entity shows its links at a glance; the rest dims.
    n.el.addEventListener('pointerenter', () => near(n, true));
    n.el.addEventListener('pointerleave', () => near(n, false));
    drag(svg, n);
  }
  // near marks an entity, its links and their lines while it is hovered -
  // only with nothing selected: a selection stays as it is until a click
  // changes it.
  function near(n, on) {
    svg.classList.toggle('hovering', on && chosen.size === 0);
    for (const el of [n.el, ...[...n.links].map((m) => m.el), ...n.lines.map((l) => l.el)]) el.classList.toggle('near', on);
  }
  // The biggest - the most severe - are drawn last, on top.
  svg.append(...lines.map((l) => l.el), ...lines.map((l) => l.text), ...list.slice().sort((a, b) => radius(a) - radius(b)).map((n) => n.el));
  svg.addEventListener('click', () => { if (!svg.panned) select(null); });
  const fitBox = () => {
    const shown = list.filter((n) => n.el.style.display !== 'none');
    if (!shown.length) return null;
    const boxes = shown.map((n) => { const b = n.el.getBBox(); return [n.x + b.x, n.y + b.y, n.x + b.x + b.width, n.y + b.y + b.height]; });
    const x = Math.min(...boxes.map((b) => b[0])) - 20, y = Math.min(...boxes.map((b) => b[1])) - 20;
    return { x, y, w: Math.max(...boxes.map((b) => b[2])) + 20 - x, h: Math.max(...boxes.map((b) => b[3])) + 20 - y };
  };
  const zoom = zoomable(svg, H, { fitBox, reset: ctx.reset, start: ctx.keep && ctx.keep.view });
  const { bar: zoomButtons, centreOn } = zoom;
  // go selects an entity picked from a card or the search and brings it to
  // the middle of the view - it may be out of sight when zoomed in.
  const go = (m, e) => { select(m, addKey(e)); centreOn(m.x, m.y); };

  // arrange moves the entities in focus (the selection and its links; else
  // every entity shown) into a shape, gliding there, then fits the view to
  // what is shown. "home" puts every entity back where the layout put it.
  let arranging = 0;
  const arrange = (kind) => {
    const shown = list.filter((m) => m.el.style.display !== 'none');
    const nodes = kind === 'home' ? list : chosen.size ? shown.filter(inFocus) : shown;
    if (!nodes.length) return;
    const v = zoom.view();
    const to = kind === 'home' ? new Map(list.map((m) => [m, m.home])) : shape(kind, nodes, [...chosen].filter((m) => nodes.includes(m)), v.x + v.w / 2, v.y + v.h / 2);
    svg.classList.toggle('timeline', kind === 'timeline');
    const from = new Map([...to.keys()].map((m) => [m, { x: m.x, y: m.y }]));
    const begin = performance.now(), mine = ++arranging;
    const step = (now) => {
      if (mine !== arranging) return;
      const t = still() ? 1 : Math.min(1, (now - begin) / 500), e = 1 - (1 - t) ** 3;
      for (const [m, p] of to) {
        m.x = from.get(m).x + (p.x - from.get(m).x) * e;
        m.y = from.get(m).y + (p.y - from.get(m).y) * e;
        moveNode(m);
      }
      if (t < 1) requestAnimationFrame(step); else zoom.fit();
    };
    requestAnimationFrame(step);
  };
  const arrangeMenu = h('select', { title: 'Arrange the selection and its links (else every entity shown)', 'aria-label': 'Arrange',
    onchange: (e) => { arrange(e.target.value); e.target.value = ''; } },
  h('option', { value: '' }, 'Arrange…'), h('option', { value: 'star' }, 'Star - the selection in the middle'), h('option', { value: 'row' }, 'Row (horizontal)'),
  h('option', { value: 'column' }, 'Column (vertical)'), h('option', { value: 'circle' }, 'Circle'), h('option', { value: 'grid' }, 'Grid'),
  h('option', { value: 'timeline' }, 'Timeline - first seen, left to right'), h('option', { value: 'home' }, 'Back to the layout'));

  // search marks the entities whose type or name holds the text (the rest
  // dim).
  const search = h('input', { type: 'search', class: 'ent-graph-search', placeholder: 'Search entities', 'aria-label': 'Search entities' });
  let hit = -1; // the match Enter went to last
  search.addEventListener('input', () => {
    hit = -1;
    const q = search.value.trim().toLowerCase();
    found = q ? new Set(list.filter((n) => label(n).toLowerCase().includes(q))) : null;
    svg.classList.toggle('searching', Boolean(found));
    for (const n of list) n.el.classList.toggle('match', Boolean(found) && found.has(n));
    search.title = found ? `${found.size} found` : '';
    show();
  });
  // Enter goes to the next match, the most severe first, round again after
  // the last (Shift+Enter: the one before).
  search.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || !found || !found.size) return;
    const matches = [...found].sort(bySeverity);
    hit = (hit + (e.shiftKey ? -1 : 1) + matches.length) % matches.length;
    search.title = `${hit + 1} of ${matches.length}`;
    go(matches[hit]);
  });
  const labelled = (name, control) => h('label', { class: 'ent-graph-ctl' }, h('span', { class: 'mut' }, name), control);
  const allTypes = [...new Set(list.map((n) => n.type))].sort();
  const count = (t) => list.filter((n) => n.type === t).length;
  const typeFilter = checkboxDropdown(allTypes, (picked) => {
    types = picked.size && picked.size < allTypes.length ? picked : null;
    for (const c of chosen) if (types && !types.has(c.type)) select(c, true); // a type left out leaves the selection
    show();
  }, allTypes, (t) => `${t} (${count(t)})`).el;
  // Hosts: the entities the chosen hosts have signals about, here in the
  // graph (the page's own filter decides what the graph holds).
  const allHosts = [...new Set(rows.map((r) => r.host))].sort();
  const perHost = new Map();
  for (const n of list) for (const x of new Set(n.hosts.map((y) => y.host))) perHost.set(x, (perHost.get(x) || 0) + 1);
  const hostFilter = allHosts.length > 1 ? checkboxDropdown(allHosts, (picked) => {
    hosts = picked.size && picked.size < allHosts.length ? picked : null;
    show();
  }, allHosts, (x) => `${x} (${perHost.get(x) || 0})`).el : null;
  // Rules narrow the lines to those the chosen rules' signals make (or the
  // analysts' links).
  const allRules = [...new Set(lines.flatMap((l) => l.ruleIds))].sort().concat(lines.some((l) => l.analyst.length) ? [BY_ANALYST] : []);
  const ruleFilter = allRules.length > 1 ? checkboxDropdown(allRules, (picked) => {
    rulesSel = picked.size && picked.size < allRules.length ? picked : null;
    show();
  }, allRules, (r) => `${r} (${lines.filter((l) => (r === BY_ANALYST ? l.analyst.length > 0 : l.ruleIds.includes(r))).length})`).el : null;
  // Relationships narrow the lines to the links of the chosen kinds.
  const allRoles = [...new Set(lines.flatMap((l) => [...l.roles]))].sort();
  const roleFilter = allRoles.length ? checkboxDropdown(allRoles, (picked) => {
    roles = picked.size && picked.size < allRoles.length ? picked : null;
    show();
  }, allRoles, (r) => `${roleWords(r)} (${lines.filter((l) => l.roles.has(r)).length})`).el : null;
  const NAMES_TIP = ' (the selected entity, its links and search matches stay whole)';
  const nameToggle = h('button', { class: 'ghost', onclick: () => { shortNames = !shortNames; paintToggle(); names(); } });
  const paintToggle = () => {
    const what = shortNames ? 'Show names whole' : 'Cut names short';
    nameToggle.replaceChildren(svgIcon(shortNames ? 'namesFull' : 'namesShort'));
    nameToggle.title = what + NAMES_TIP;
    nameToggle.setAttribute('aria-label', what);
  };
  paintToggle();
  // toggle is an on/off button of the bar.
  const toggle = (text, title, onSet) => {
    const b = h('button', { class: 'ghost', title, 'aria-pressed': 'false', onclick: () => {
      const on = !b.classList.contains('on');
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', String(on));
      onSet(on);
    } }, text);
    return b;
  };
  // "Select many": every click adds to the selection (or takes out), as
  // Ctrl (⌘) + click always does.
  const manyToggle = toggle('Select many', 'Select many: every click adds an entity to the selection, or takes it out (Ctrl, ⌘ or Shift + click does it without this)', (on) => { many = on; });
  const aloneToggle = toggle('Hide others', 'Hide everything but the selected entities and their links (with nothing selected, everything shows)', (on) => { alone = on; show(); });
  const imageButton = h('button', { class: 'ghost', title: 'Save the graph as you see it as a PNG image', onclick: () => saveImage(svg, frameOf()) }, 'Image');
  const addButton = ctx.editable ? h('button', { class: 'ghost', title: 'Add an entity Signal did not report - marked as yours - linked to the selected entities', onclick: () => { form = addForm(); paint(); } }, '+ Entity') : null;
  const depthMenu = h('select', { title: 'How many links from the selection are lit, and kept by Hide others', 'aria-label': 'Depth', onchange: (e) => { depth = Number(e.target.value); paint(); } },
    ...[1, 2, 3].map((d) => h('option', { value: String(d) }, `${d} link${d === 1 ? '' : 's'}`)));
  // panelToggle opens a card of its own over the graph (Insights, the
  // legend), or closes it.
  const panelToggle = (text, title, make) => h('button', { class: 'ghost', title, onclick: () => { extra = extra === make ? null : make; paint(); } }, text);
  zoomButtons.prepend(search, nameToggle, manyToggle, aloneToggle, labelled('Depth', depthMenu), labelled('Types', typeFilter), ...(hostFilter ? [labelled('Hosts', hostFilter)] : []),
    ...(ruleFilter ? [labelled('Rules', ruleFilter)] : []), ...(roleFilter ? [labelled('Relationships', roleFilter)] : []), arrangeMenu,
    panelToggle('Insights', 'The most connected entities, those on the most hosts, the separate groups, what analysts marked', insights), imageButton, ...(addButton ? [addButton] : []),
    panelToggle('?', 'What the drawing means', legend));

  const spread = list.filter((n) => n.hosts.length > 1).length;
  const unlinked = new Set(rows.map((r) => r.id)).size - list.filter((n) => n.hosts.length).length;
  // The round button at the bottom right hides every option - all but
  // filling the window and full screen - to leave the entities alone, and
  // shows them again; kept across redraws. A clicked entity's cards show
  // either way.
  const bareButton = h('button', { class: 'ghost ent-graph-bare-toggle', 'aria-pressed': String(ctx.bare) });
  const showBare = () => {
    frame.classList.toggle('bare', ctx.bare);
    bareButton.setAttribute('aria-pressed', String(ctx.bare));
    bareButton.title = ctx.bare ? 'Show the graph\'s options' : 'Hide the graph\'s options - the entities alone';
    bareButton.replaceChildren(svgIcon('sliders'));
  };
  bareButton.onclick = (e) => { e.stopPropagation(); ctx.bare = !ctx.bare; showBare(); };
  const frame = h('div', { class: 'ent-graph-frame', tabindex: '0' }, zoomButtons, svg, panel, bareButton);
  showBare();
  // The cards start below the bar, however many lines it wraps to.
  if (window.ResizeObserver) new window.ResizeObserver(() => frame.style.setProperty('--bar-h', `${zoomButtons.offsetHeight}px`)).observe(zoomButtons);
  // Off screen, the graph's animations pause (nothing to see, nothing to spend).
  if (window.IntersectionObserver) new window.IntersectionObserver(([e]) => svg.classList.toggle('idle', !e.isIntersecting)).observe(frame);
  // On a page whose filter bar sticks, the graph's bar slides down to stay
  // below it while the graph's top is scrolled under it (not in the
  // window- or screen-filling modes).
  let placing = 0;
  const placeBar = () => {
    placing = 0;
    const big = frame.classList.contains('full-window') || document.fullscreenElement === frame;
    const sticky = parseFloat(window.getComputedStyle(frame).getPropertyValue('--sticky-top')) || 0;
    const shift = big ? 0 : Math.max(0, Math.min(sticky - frame.getBoundingClientRect().top + 4, frame.clientHeight - zoomButtons.offsetHeight - 60));
    frame.style.setProperty('--bar-shift', `${shift}px`);
  };
  window.addEventListener('scroll', () => { if (!placing && frame.isConnected) placing = requestAnimationFrame(placeBar); }, { passive: true });
  frame.addEventListener('keydown', (e) => {
    if (e.target.closest('input, select, textarea')) return;
    if (e.key === 'Escape') select(null);
    else if (e.key === 'f' || e.key === 'F') zoom.fit();
  });
  // A redraw keeps the selection.
  if (ctx.keep) {
    for (const k of ctx.keep.chosen) { const m = list.find((x) => x.key === k); if (m) chosen.add(m); }
    current = list.find((x) => x.key === ctx.keep.current) || [...chosen].pop() || null;
  }
  paint();
  if (ctx.fresh && window.requestAnimationFrame) requestAnimationFrame(() => { if (svg.isConnected && svg.getBBox) zoom.fit(); });
  ctx.fresh = false;
  return h('div', {},
    h('div', { class: 'mut sig-small' }, `${list.length} entities, ${edges.length} links${spread ? `, ${spread} with signals on more than one host` : ''}${ctx.analyst.entities.length ? `, ${ctx.analyst.entities.length} created manually by analysts` : ''}. `,
      'The graph\'s ? button says what the drawing means; Insights shows where to start.',
      unlinked ? ` Not drawn: ${unlinked} with no links.` : ''),
    frame, h('div', { class: 'mut sig-small' }, HINT));
}
