// URLs and navigation. Every page has its own URL - /overview, /signals,
// /autoruns, /applications, /extensions, /grouppolicy, /remoteaccess, /webservers, /network, /protection, /audit,
// /users, /hosts, /rules, /modules, /settings, /license, /import (the server
// answers each with the same app; see server.js) - and its state lives in
// the query string, so any view can be bookmarked, shared, reloaded, or
// reached with the browser's back and forward buttons:
//   Overview:    ?hosts=&os=&role=
//   Signals:     ?host=<run id>&type=&modules=&severity=&rule=&tactic=&triage=&evidence=&show=,
//                or ?entity=<type:key>&host=<run id>&signal=<sid> for one entity's page
//   Autoruns, Applications, Extensions, Group Policy, Remote Access, Web Servers, Network, Protection, Audit Policy: ?hosts=&os=&role=
//   Rules:       ?module=&severity=&outcome=&origin=&hosts=&mode=&group=, &rule=<id> opens that rule
//   Modules:     ?module=<name> opens that module
//   Users:       ?scope=&kind=&show=, or ?user=<key> for one account's page
//   Hosts:       ?os=&role=&domain=&status=, or ?host=<run id> for one host's page
//   Settings:    ?profile=<sha256> opens a profile in the builder, ?new=1 a new one (/profiles, its name before
//                console 0.69.0, still opens it)

import { h } from './dom.js';

// NAV is the side navigation, in order: each page's name (its URL), label
// and icon (dom.js ICONS); null is the divider between the pages of what the
// hosts recorded and the pages about Signal itself (its rules, modules
// the settings - HTTPS and the profiles that scope its runs - and its license).
// The one list of pages - main.js builds the navigation from it.
export const NAV = [
  ['overview', 'Overview', 'gauge'],
  ['signals', 'Signals', 'signals'],
  ['timeline', 'Timeline', 'timeline'],
  ['graph', 'Graph', 'graph'],
  ['topology', 'Topology', 'topology'],
  ['audit', 'Audit Policy', 'layers'],
  ['autoruns', 'Autoruns', 'clock'],
  ['applications', 'Applications', 'apps'],
  ['extensions', 'Extensions', 'puzzle'],
  ['grouppolicy', 'Group Policy', 'policy'],
  ['remoteaccess', 'Remote Access', 'remote'],
  ['webservers', 'Web Servers', 'webserver'],
  ['network', 'Network', 'globe'],
  ['protection', 'Protection', 'shield'],
  ['recovery', 'Recovery', 'lifebuoy'],
  ['users', 'Users', 'user'],
  ['hosts', 'Hosts', 'hosts'],
  null,
  ['reports', 'Reports', 'report'],
  ['rules', 'Rules', 'scroll'],
  ['modules', 'Modules', 'module'],
  ['settings', 'Settings', 'sliders'],
  ['license', 'License', 'license'],
];

// HOME is the page an unknown address and a new sign-in open.
export const HOME = 'overview';
export const PAGES = [...NAV.filter(Boolean).map(([page]) => page), 'import', 'login'];
const scopeOf = () => '';
const withScope = (params) => params;

// rerender is the app's render function (main.js registers it), which go()
// calls after changing the URL.
let rerender = () => {};
export function onNavigate(fn) { rerender = fn; }
export function render() { return rerender(); }

export function currentPage() {
  const name = location.pathname.replace(/^\/+|\/+$/g, '');
  if (name === 'profiles') return 'settings'; // the page's name before console 0.69.0: old links and bookmarks
  return PAGES.includes(name) ? name : HOME;
}

export function urlParams() {
  return new URLSearchParams(location.search);
}

// queryString encodes a {name: value} map as a query string - a list as
// comma-separated values, and an empty value (or an empty list) left out -
// for page URLs and API requests alike.
export function queryString(params = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    const s = Array.isArray(v) ? v.join(',') : v;
    if (s !== undefined && s !== null && s !== '') q.set(k, s);
  }
  return q.toString();
}

// pageUrl builds a page's URL from a {name: value} map, carrying only what
// differs from the page's default (see queryString) - and, in the Pro
// edition, what the current page is about (withScope), unless params name
// another.
export function pageUrl(page, params = {}) {
  const qs = queryString(withScope(params));
  return `/${page}${qs ? '?' + qs : ''}`;
}

// go navigates to a page (a new history entry) and renders it.
export function go(page, params) {
  history.pushState(null, '', pageUrl(page, params));
  return render();
}

// setParams records the current page's state in its URL without adding a
// history entry or re-rendering - for filters and selections changed on the
// page itself. A null/empty value removes that parameter.
export function setParams(params) {
  if ('hosts' in params) rememberHosts([].concat(params.hosts || []));
  const q = urlParams();
  for (const [k, v] of Object.entries(params)) {
    const s = Array.isArray(v) ? v.join(',') : v;
    if (s === undefined || s === null || s === '') q.delete(k);
    else q.set(k, s);
  }
  const qs = q.toString();
  history.replaceState(null, '', location.pathname + (qs ? '?' + qs : ''));
}

// listParam reads a comma-separated URL parameter as an array (empty when
// absent).
export function listParam(name) {
  const v = urlParams().get(name);
  if (!v && name === 'hosts') return rememberedHosts();
  return v ? v.split(',') : [];
}

// The host filter is one choice across the pages (the user): the hosts
// (run IDs) last chosen on any page's Hosts filter, kept in this
// browser and read by every page whose URL names none - so a choice made on
// one page holds on the next. Choosing every host clears it.
const hostsKey = () => `signal-console.hosts.${scopeOf()}`;
export function rememberedHosts() {
  try { return String(window.localStorage.getItem(hostsKey()) || '').split(',').filter(Boolean); } catch { return []; }
}
export function rememberHosts(ids) {
  try {
    if (ids.length) window.localStorage.setItem(hostsKey(), ids.join(','));
    else window.localStorage.removeItem(hostsKey());
  } catch { /* not remembered: each page starts with every host */ }
}

// A page's last state is kept in this browser (the user,
// 2026-11-04): the Signals list's filters, restored when the list opens
// again without any, and the Timeline's address and the signal opened from
// it, for the entity page's way back. Not kept (private window, storage
// blocked): each page starts as it would.
const stateKey = (name) => `signal-console.${name}.${scopeOf()}`;
export function rememberState(name, value) {
  try { window.localStorage.setItem(stateKey(name), JSON.stringify(value)); } catch { /* not kept */ }
}
export function rememberedState(name) {
  try { return JSON.parse(window.localStorage.getItem(stateKey(name)) || 'null'); } catch { return null; }
}

// LINK_MODES are how an in-app link and a row that opens a page open it
// (Settings, Links - kept in this browser): in this tab (the default, the
// user 2026-10-23), a new tab, or a new window of its own - a minimal
// window without tabs or toolbar. The sidebar and a page's own selectors
// always navigate in place (go).
export const LINK_MODES = ['same', 'tab', 'window'];
const LINK_KEY = 'signal-console.link-mode';

export function linkMode() {
  try {
    const m = window.localStorage.getItem(LINK_KEY);
    return LINK_MODES.includes(m) ? m : 'same';
  } catch { return 'same'; }
}

export function setLinkMode(mode) {
  try { window.localStorage.setItem(LINK_KEY, mode); } catch { /* not remembered: fine */ }
}

// openUrl opens an in-app address as the link mode says.
function openUrl(url) {
  const mode = linkMode();
  if (mode === 'same') {
    history.pushState(null, '', url);
    render();
  } else if (mode === 'window') {
    window.open(url, '_blank', `popup,noopener,width=${Math.round(window.screen.availWidth * 0.7)},height=${Math.round(window.screen.availHeight * 0.8)}`);
  } else {
    window.open(url, '_blank', 'noopener');
  }
}

// openPage opens a page as the link mode says.
export function openPage(page, params) {
  openUrl(pageUrl(page, params));
}

// pageLink is an in-app link: a real href (to copy), opening as the link
// mode says (a modified click keeps the browser's own meaning). A click on
// it does not also reach the row or header it sits in.
export function pageLink(page, params, ...children) {
  const href = pageUrl(page, params);
  return h('a', { href, target: linkMode() === 'same' ? null : '_blank', rel: 'noopener', onclick: (e) => linkClick(e, href) }, ...children);
}

// linkClick is an in-app link's click: in this tab or a new window it is
// handled here; a new tab is the browser's own (target _blank).
export function linkClick(e, href) {
  e.stopPropagation();
  if (e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0 || linkMode() === 'tab') return;
  e.preventDefault();
  openUrl(href);
}
