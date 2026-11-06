// DOM, fetch and formatting helpers every other module uses. No framework,
// no CDN: a tool meant for restricted or air-gapped incident-response
// networks must not depend on an external fetch succeeding just to draw
// itself, so every icon and chart is inline SVG.

// h builds a DOM element without a templating engine: h('div', {class:'x'}, 'text', childEl, ...).
// Attribute values of null/undefined are skipped entirely (not stringified
// to "null"/"undefined") because a browser treats the mere *presence* of
// some attributes (e.g. an <option>'s "selected") as true regardless of
// their value - setAttribute('selected', undefined) still marks it selected.
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const k in attrs || {}) {
    const v = attrs[k];
    if (v === null || v === undefined) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el[k] = v;
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(c));
  }
  return el;
}

// apiFetch is fetch for the API.
export const apiFetch = (url, opts = {}) => fetch(url, opts);

// fetchJSON fetches an API response as JSON. A 401 (no session, or one that
// expired) raises the "signal:signin" window event, which main.js answers
// with the sign-in page; any other failure throws with the server's error.
export async function fetchJSON(url, opts) {
  const res = await apiFetch(url, opts);
  if (res.status === 401) window.dispatchEvent(new window.Event('signal:signin'));
  if (!res.ok) {
    const text = await res.text();
    let message = text;
    try { message = JSON.parse(text).error || text; } catch { /* not JSON: the text itself */ }
    throw new Error(message);
  }
  return res.json();
}

// ts renders an ISO timestamp with a zone as "2026-09-26 21:02:47 UTC"
// (whole seconds) - converted from whatever offset it carries, so every
// time on the pages is UTC, as Signal records it. A value without a zone
// (a date, a time its source recorded without one) is shown as it is.
export function ts(s) {
  if (!s) return '—';
  const v = String(s);
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:\d\d)$/.test(v)) return v.replace(/^(\d{4}-\d\d-\d\d)T/, '$1 ');
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? v : d.toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
}

// mono renders machine text - a command line, a file path - in the code
// font, so it reads as literal text rather than prose.
export function mono(v) {
  return v ? h('span', { class: 'mono' }, breakable(String(v))) : '—';
}

// fitToWindow makes a popup that opens downward (a dropdown, a column's
// filter) end at the window's bottom edge: its CSS caps its height at
// --fit, the room below its top (never under min px), so a long list
// scrolls inside it instead of running off the screen - where a sticky
// bar's popup could never be scrolled to. Called once it is shown.
export function fitToWindow(panel, min = 160) {
  panel.style.setProperty('--fit', `${Math.max(min, window.innerHeight - panel.getBoundingClientRect().top - 12)}px`);
}

// breakable splits machine text into pieces a line may break between:
// after a separator (\ / . , ; : = _ -) or every 24 characters of an
// unbroken run - so a narrow column wraps "CORP\alice" at the backslash, not
// letter by letter, and a long path at its folders.
export function breakable(text) {
  const out = [];
  let piece = '';
  let run = 0;
  for (const ch of text) {
    piece += ch;
    run = /[\\/.,;:=_\-\s]/.test(ch) ? 0 : run + 1;
    if (run === 0 || run >= 24) {
      out.push(piece, document.createElement('wbr'));
      piece = '';
      run = 0;
    }
  }
  if (piece) out.push(piece);
  return out;
}

// keyValues renders [name, value] pairs as a compact wrapped list - an
// event's fields, a finding's evidence. A value may be a node (a link).
export function keyValues(pairs) {
  return h('div', { class: 'kv' }, pairs.map(([k, v]) => h('div', {}, h('span', {}, k + ': '), v && v.nodeType ? v : String(v ?? '—'))));
}

// ICONS are 24x24 stroke icons (inline SVG path data), used for column
// headers and summary strips. svgIcon renders one at the current text color.
const ICONS = {
  report: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M9 15l2 2 4-4"/>',
  license: '<path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h6"/><path d="M13 3l5 5v2"/><line x1="8" y1="9" x2="11" y2="9"/><line x1="8" y1="13" x2="12" y2="13"/><circle cx="17.5" cy="15.5" r="2.5"/><path d="M16 17.5 15.5 22l2-1.2 2 1.2-.5-4.5"/>',
  sliders: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
  namesShort: '<line x1="2" y1="12" x2="9" y2="12"/><polyline points="6 9 9 12 6 15"/><line x1="22" y1="12" x2="15" y2="12"/><polyline points="18 9 15 12 18 15"/>',
  namesFull: '<line x1="3" y1="12" x2="21" y2="12"/><polyline points="7 8 3 12 7 16"/><polyline points="17 8 21 12 17 16"/>',
  lifebuoy: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><line x1="5.6" y1="5.6" x2="9.2" y2="9.2"/><line x1="14.8" y1="14.8" x2="18.4" y2="18.4"/><line x1="18.4" y1="5.6" x2="14.8" y2="9.2"/><line x1="9.2" y1="14.8" x2="5.6" y2="18.4"/>',
  snapshot: '<path d="M3 12a9 9 0 1 0 3-6.7"/><polyline points="3 3 3 8 8 8"/><polyline points="12 7 12 12 15 14"/>',
  remote: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><polyline points="10 7 14 10 10 13"/>',
  peer: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="11" r="2.5"/><path d="M5.5 17a3.5 3.5 0 0 1 7 0"/><line x1="15" y1="9" x2="18" y2="9"/><line x1="15" y1="13" x2="18" y2="13"/>',
  webserver: '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><polyline points="9 5.5 7.5 7 9 8.5"/><polyline points="15 5.5 16.5 7 15 8.5"/><line x1="6" y1="17" x2="6.01" y2="17"/>',
  webapp: '<rect x="2" y="4" width="20" height="16" rx="2"/><line x1="2" y1="9" x2="22" y2="9"/><line x1="5" y1="6.5" x2="5.01" y2="6.5"/><polyline points="9 12 7 14.5 9 17"/><polyline points="15 12 17 14.5 15 17"/>',
  policy: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="14 3 14 9 20 9"/><polyline points="8 15 11 18 16 12"/>',
  tree: '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-3a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v3"/>',
  severity: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  module: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.3 7 12 12 20.7 7"/><line x1="12" y1="22" x2="12" y2="12"/>',
  id: '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>',
  title: '<polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/>',
  hosts: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  evaluated: '<path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><polyline points="22 4 12 14 9 11"/>',
  notEvaluated: '<circle cx="12" cy="12" r="10"/><line x1="4.9" y1="4.9" x2="19.1" y2="19.1"/>',
  dependency: '<path d="M9 17H7A5 5 0 0 1 7 7"/><path d="M15 7h2a5 5 0 0 1 4 8"/><line x1="8" y1="12" x2="12" y2="12"/><line x1="2" y1="2" x2="22" y2="22"/>',
  moduleOff: '<path d="M21 10V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l2-1.14"/><polyline points="3.3 7 12 12 20.7 7"/><line x1="12" y1="22" x2="12" y2="12"/><line x1="17" y1="17" x2="22" y2="22"/><line x1="22" y1="17" x2="17" y2="22"/>',
  ruleOff: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9.5" y1="12.5" x2="14.5" y2="17.5"/><line x1="14.5" y1="12.5" x2="9.5" y2="17.5"/>',
  flagged: '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>',
  outcome: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  matches: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
  reason: '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  details: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>',
  coverage: '<path d="M21.2 15.9A10 10 0 1 1 8 2.8"/><path d="M22 12A10 10 0 0 0 12 2v10z"/>',
  clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  firstSeen: '<path d="M3 12a9 9 0 1 0 9-9 9.8 9.8 0 0 0-6.7 2.7L3 8"/><polyline points="3 3 3 8 8 8"/><polyline points="12 7 12 12 15 14"/>',
  count: '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
  layers: '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
  plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  open: '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
  edit: '<path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/>',
  archive: '<rect x="2" y="3" width="20" height="5" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><line x1="10" y1="12" x2="14" y2="12"/>',
  restore: '<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>',
  trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
  briefcase: '<rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
  eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  status: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  success: '<polyline points="20 6 9 17 4 12"/>',
  failure: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  value: '<path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L2 12V2h10l8.6 8.6a2 2 0 0 1 0 2.8z"/><line x1="7" y1="7" x2="7.01" y2="7"/>',
  dataset: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.7-4 3-9 3s-9-1.3-9-3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/>',
  mode: '<rect x="1" y="5" width="22" height="14" rx="7"/><circle cx="16" cy="12" r="3"/>',
  signals: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
  runs: '<polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/>',
  server: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
  topology: '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-2.5a2.5 2.5 0 0 1 2.5-2.5h9a2.5 2.5 0 0 1 2.5 2.5V17"/>',
  globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  puzzle: '<path d="M19.44 7.85c-.05.32.06.65.29.88l1.57 1.57a2.41 2.41 0 0 1 0 3.41l-1.61 1.61a.98.98 0 0 1-.84.28c-.47-.07-.8-.48-.97-.93a2.5 2.5 0 1 0-3.21 3.21c.45.17.86.5.93.97a.98.98 0 0 1-.28.84l-1.61 1.61a2.41 2.41 0 0 1-3.41 0l-1.57-1.57a1.03 1.03 0 0 0-.88-.29c-.49.07-.84.5-1.02.97a2.5 2.5 0 1 1-3.24-3.24c.46-.18.89-.53.97-1.02a1.03 1.03 0 0 0-.29-.88l-1.57-1.57a2.41 2.41 0 0 1 0-3.41L4.23 8.77c.24-.24.58-.35.92-.3.51.08.88.53 1.07 1.01a2.5 2.5 0 1 0 3.26-3.26c-.48-.2-.93-.56-1.01-1.07-.05-.34.06-.68.3-.92l1.53-1.53a2.41 2.41 0 0 1 3.41 0l1.57 1.57c.23.23.56.34.88.29.49-.07.84-.5 1.02-.97a2.5 2.5 0 1 1 3.24 3.24c-.46.18-.89.53-.97 1.02Z"/>',
  link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  plug: '<path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/>',
  apps: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  scroll: '<path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v3h4"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/>',
  windows: '<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="12" y1="3" x2="12" y2="21"/>',
  version: '<circle cx="12" cy="12" r="3"/><line x1="3" y1="12" x2="9" y2="12"/><line x1="15" y1="12" x2="21" y2="12"/>',
  // timeline: a rail with events on it
  timeline: '<line x1="6" y1="3" x2="6" y2="21"/><circle cx="6" cy="7" r="2"/><circle cx="6" cy="16" r="2"/><line x1="10" y1="7" x2="20" y2="7"/><line x1="10" y1="16" x2="17" y2="16"/>',
  gauge: '<path d="M12 14l4-4"/><path d="M3.3 19a10 10 0 1 1 17.4 0"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  logon: '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6"/><path d="M15.5 7.5l3 3L22 7l-3-3"/>',
  expand: '<polyline points="13 17 18 12 13 7"/><polyline points="6 17 11 12 6 7"/>',
  collapse: '<polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/>',
  sun: '<circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="22"/><line x1="4.9" y1="4.9" x2="6.3" y2="6.3"/><line x1="17.7" y1="17.7" x2="19.1" y2="19.1"/><line x1="2" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="22" y2="12"/><line x1="4.9" y1="19.1" x2="6.3" y2="17.7"/><line x1="17.7" y1="6.3" x2="19.1" y2="4.9"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  search: '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  // background tasks: a loader's spokes (the top bar's tasks menu; it turns while one runs)
  tasks: '<line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/>',
  // the Graph page: three nodes joined by edges
  graph: '<circle cx="5" cy="6" r="2.5"/><circle cx="18" cy="5" r="2.5"/><circle cx="12" cy="18" r="2.5"/><line x1="7.2" y1="7" x2="10.5" y2="16"/><line x1="16" y1="6.6" x2="13.4" y2="16"/><line x1="7.4" y1="5.7" x2="15.6" y2="5.2"/>',
  filter: '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>',
  warning: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
};

// virusTotalLink opens a hash in VirusTotal: a file by its MD5, SHA-1 or
// SHA-256; an import hash by a search.
export function virusTotalLink(type, hash) {
  const href = type === 'IMPHASH' ? `https://www.virustotal.com/gui/search/imphash%253A${hash}` : `https://www.virustotal.com/gui/file/${hash}`;
  return h('a', { href, target: '_blank', rel: 'noopener noreferrer', class: 'mono', title: 'Open in VirusTotal' }, breakable(hash));
}

// iconMarkup is an icon's SVG drawing (a 24x24 viewBox), for an icon drawn
// inside an SVG of its own (the entity graph's nodes).
export const iconMarkup = (name) => ICONS[name] || '';

export function svgIcon(name) {
  const el = h('span', { class: 'icon', 'aria-hidden': 'true' });
  el.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
  return el;
}

// countUp rolls a figure up from zero to its value once it is on screen,
// then leaves its exact text. A value that is not a plain whole number,
// reduced motion, or no animation frames (the tests' jsdom) leaves the
// element as it is - its text is always the true value at rest.
export function countUp(el) {
  const text = el.textContent;
  if (!/^[1-9]\d*$/.test(text) || typeof requestAnimationFrame !== 'function') return el;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return el;
  const end = Number(text);
  let start = null, waits = 0;
  el.style.minWidth = `${text.length}ch`; // the figure does not move its label about as it grows
  const step = (t) => {
    if (!el.isConnected) { if (++waits < 600) requestAnimationFrame(step); return; } // not on the page yet
    if (start === null) start = t;
    const p = Math.min(1, (t - start) / 700);
    el.textContent = p < 1 ? String(Math.round(end * (1 - (1 - p) ** 3))) : text;
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
  return el;
}

// withTip attaches a hover card to an element: tipContent shows below it
// while the pointer is over it, flipped to open leftward when it would run
// past the window's right edge. Column headers and host links both use it.
export function withTip(el, tipContent, cls) {
  const tip = h('span', { class: 'tip' }, tipContent);
  return h('span', {
    class: 'has-tip' + (cls ? ' ' + cls : ''),
    // The card is placed against the window below its anchor (flipped to
    // end at the anchor's right edge when it would leave the window, and
    // above the anchor when there is more room there); a card taller than
    // the room it has scrolls within it.
    onmouseenter: (e) => {
      const r = e.currentTarget.getBoundingClientRect();
      const width = cls && cls.includes('tip-wide') ? 380 : 260;
      const left = r.left - 8 + width > window.innerWidth - 8 ? r.right + 8 - width : r.left - 8;
      const below = window.innerHeight - r.bottom - 16;
      const above = r.top - 16;
      tip.style.left = `${Math.max(8, left)}px`;
      tip.style.maxHeight = `${Math.max(below, above)}px`;
      tip.style.top = below >= above ? `${r.bottom + 8}px` : '';
      tip.style.bottom = below >= above ? '' : `${window.innerHeight - r.top + 8}px`;
    },
  }, el, tip);
}
