// Signal Console - front end entry point.
//
// A small, dependency-free single-page app: no framework, no build step -
// the browser loads these ES modules as they are. The pages, in the side
// navigation (router.js NAV): Overview (the fleet dashboard, with every
// analyst flag), Signals (every rule match as a signal of its own, with
// filters, grouping, triage and suppression rules), Entities, the fleet
// inventories - Autoruns, Applications, Network, Protection (the antivirus
// exclusions), Audit Policy (the policy, event IDs and changes) - Users
// (with the logons) and Hosts (each with a page per
// account or host); then, past a divider, the pages about Signal itself -
// Rules (the full detection catalog, fired or not, built-in or imported)
// and Modules (what each module is and how it ran) - and Import (from the header's button), behind a
// sign-in page. Every page but a host's history works on each host's latest
// collection. Each page is one module in pages/ whose render function
// fetches its data and fills the container it is given.
//
// Modules: dom.js (DOM, fetch and format helpers), router.js (URLs and
// navigation), session.js (the signed-in account), components.js (shared
// cards, tags and filters), table.js (the table component and its column
// dictionary), pages/*.js.

import { startSectionNav } from './sectionNav.js';
import { h, svgIcon, fetchJSON } from './dom.js';
import { setRunModules } from './components.js';
import { openFinder, setupFinder } from './finder.js';
import { setupTasks } from './tasks.js';
import { drawUpdateBanner } from './updates.js';
import { onNavigate, currentPage, go, pageUrl, pageLink, PAGES, NAV, HOME } from './router.js';
import { loadSession, sessionUser, canEdit, setSession } from './session.js';
import { renderOverviewPage } from './pages/overview.js';
import { renderSignalsPage } from './pages/signals.js';
import { renderTimelinePage } from './pages/timeline.js';
import { renderGraphPage } from './pages/graph.js';
import { renderAutorunsPage, renderApplicationsPage, renderExtensionsPage, renderGroupPolicyPage, renderRemoteAccessPage, renderWebServersPage, renderNetworkPage, renderTopologyPage, renderProtectionPage, renderRecoveryPage, renderAuditPage } from './pages/inventoryPages.js';
import { renderRules } from './pages/rules.js';
import { renderModulesPage } from './pages/modules.js';
import { renderSettingsPage } from './pages/settings.js';
import { renderLicensePage } from './pages/license.js';
import { renderReportsPage } from './pages/reports.js';
import { renderHostsPage } from './pages/hosts.js';
import { renderUsersPage } from './pages/users.js';
import { renderImport, updateHeaderStats } from './pages/import.js';
import { renderLogin } from './pages/login.js';

const RENDERERS = {
  overview: renderOverviewPage, signals: renderSignalsPage, timeline: renderTimelinePage, graph: renderGraphPage, autoruns: renderAutorunsPage, applications: renderApplicationsPage, extensions: renderExtensionsPage, grouppolicy: renderGroupPolicyPage, remoteaccess: renderRemoteAccessPage, webservers: renderWebServersPage,
  network: renderNetworkPage, topology: renderTopologyPage, protection: renderProtectionPage, recovery: renderRecoveryPage, audit: renderAuditPage, reports: renderReportsPage, rules: renderRules,
  modules: renderModulesPage, settings: renderSettingsPage, license: renderLicensePage, users: renderUsersPage, hosts: renderHostsPage, import: renderImport,
};

// The side navigation starts collapsed - icons only, each named on hover -
// and its toggle expands it to show the pages' names; the choice is
// remembered in this browser (a convenience: without storage it simply
// starts collapsed).
const NAV_KEY = 'signal-console.nav-expanded';
function storedExpanded() {
  try { return window.window.localStorage.getItem(NAV_KEY) === '1'; } catch { return false; }
}
function setExpanded(expanded) {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.toggle('expanded', expanded);
  const toggle = document.getElementById('navToggle');
  const label = expanded ? 'Collapse the navigation' : 'Expand the navigation';
  toggle.replaceChildren(svgIcon(expanded ? 'collapse' : 'expand'), h('span', { class: 'nav-label' }, 'Collapse'));
  toggle.setAttribute('aria-label', label);
  toggle.setAttribute('aria-expanded', String(expanded));
  toggle.title = label;
  try { window.window.localStorage.setItem(NAV_KEY, expanded ? '1' : '0'); } catch { /* not remembered: fine */ }
}
// The theme: the OS's until the header's theme button (after Import) picks
// light or dark, which this browser then remembers.
const THEME_KEY = 'signal-console.theme';
function effectiveTheme() {
  const chosen = document.documentElement.dataset.theme;
  if (chosen) return chosen;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function drawThemeButton() {
  const btn = document.getElementById('themeBtn');
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  btn.replaceChildren(svgIcon(next === 'light' ? 'sun' : 'moon'));
  btn.title = `Switch to ${next} mode`;
  btn.setAttribute('aria-label', btn.title);
}
function setupTheme() {
  try {
    const saved = window.window.localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
  } catch { /* not remembered: the OS's theme */ }
  document.getElementById('themeBtn').addEventListener('click', () => {
    const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { window.window.localStorage.setItem(THEME_KEY, next); } catch { /* not remembered */ }
    drawThemeButton();
  });
  drawThemeButton();
}

// placeTip puts a collapsed sidebar's label beside its icon: the label is
// fixed (see style.css), so the scrolling page list does not clip it.
function placeTip(e) {
  const tip = e.currentTarget.querySelector('.nav-tip');
  const r = e.currentTarget.getBoundingClientRect();
  tip.style.left = `${r.right + 12}px`;
  tip.style.top = `${r.top + r.height / 2}px`;
}

function buildNav() {
  document.getElementById('tabs').replaceChildren(...NAV.map((item) => (item === null ? h('div', { class: 'nav-sep', role: 'separator' })
    : h('button', { 'data-tab': item[0], 'aria-label': item[1], onclick: () => go(item[0], {}), onmouseenter: placeTip, onfocus: placeTip },
      svgIcon(item[2]), h('span', { class: 'nav-label' }, item[1]), h('span', { class: 'nav-tip', role: 'tooltip' }, item[1])))));
  document.getElementById('navToggle').addEventListener('click', () => setExpanded(!document.getElementById('sidebar').classList.contains('expanded')));
  setExpanded(storedExpanded());
}

// hideEmptyPages leaves out of the navigation the data pages no host's
// latest collection has data for - each still opens by its URL. Asked on
// every render, so an import or a removal shows or hides them.
// A data page not reviewed on every host gets a yellow mark (reviews).
// loadRunModules tells the module badges every module of the runs (so one
// naming them all reads "All") - on every page, as an import may have
// brought a module.
async function loadRunModules() {
  const res = await fetchJSON('/api/modules').catch(() => ({ modules: [] }));
  setRunModules(res.modules.map((m) => m.name));
}

async function hideEmptyPages() {
  const [{ empty }, reviews] = await Promise.all([fetchJSON('/api/inventories/pages').catch(() => ({ empty: [] })), fetchJSON('/api/reviews').catch(() => ({}))]);
  document.querySelectorAll('#tabs button').forEach((b) => {
    b.hidden = empty.includes(b.dataset.tab);
    const r = reviews[b.dataset.tab];
    b.classList.toggle('unreviewed', Boolean(r && r.state === 'not_reviewed'));
    b.querySelector('.nav-tip').textContent = b.getAttribute('aria-label') + (r && r.state === 'not_reviewed' ? ' - not reviewed' : '');
  });
}

// onData reports whether the page is about the runs (the finder's scope).
const onData = () => Boolean(sessionUser()) && currentPage() !== 'login';

// drawHeader shows the signed-in account (with Sign out) and the parts of
// the header an account may use: none but the title when signed out, no
// Import button for a read-only account.
function drawHeader() {
  const user = sessionUser();
  document.body.classList.toggle('signed-out', !user);
  document.getElementById('importBtn').style.display = canEdit() ? '' : 'none';
  document.getElementById('findBtn').style.display = onData() ? '' : 'none';
  document.getElementById('tasksBtn').style.display = user ? '' : 'none';
  const box = document.getElementById('userBox');
  box.replaceChildren(...(user ? [
    h('span', { class: 'mut', title: { admin: 'Admin account', analyst: 'Analyst account', viewer: 'Read-only account' }[user.role] }, `${user.username} · ${user.role}`),
    h('button', { class: 'ghost', onclick: async () => {
      await fetch('/api/auth/logout', { method: 'POST' });
      setSession(null);
      go('login', {});
    } }, 'Sign out'),
  ] : []));
  if (user) updateHeaderStats();
  if (user) drawCredit();
  if (user) drawUpdateBanner();
}

// editionBadge names the edition in force beside the credit, linked to the
// License page: Community in the warning colour with what it does not allow.
function editionBadge(ed) {
  const community = ed.edition === 'community';
  const tip = community
    ? `Community edition: licensed, free of charge, solely to defend the computers, networks and systems you or your organisation own or operate, and for personal, educational and non-commercial research use. Services to third parties, resale, redistribution outside your organisation and incorporation into another product require a commercial license (Pro or Enterprise) from Intrusion Academy.${ed.problem ? ` (${ed.problem})` : ''} See the License page.`
    : `${ed.label}, licensed to ${ed.customer} until ${String(ed.expires).slice(0, 10)}. See the license.`;
  return pageLink('license', {}, h('span', { class: `about-edition ${community ? 'edition-community' : 'edition-licensed'}`, title: tip }, svgIcon('license'),` ${community ? 'Community' : ed.label.replace(' edition', '')}`));
}

// drawCredit writes the console's version, its author and the edition at
// the left of the top bar, once per page load.
let creditDrawn = false;
async function drawCredit() {
  if (creditDrawn) return;
  creditDrawn = true;
  const about = await fetchJSON('/api/about').catch(() => null);
  if (!about) { creditDrawn = false; return; }
  document.getElementById('headerAbout').replaceChildren(
    h('span', { class: 'about-version', title: 'Signal Console version' }, `v${about.version}`),
    h('span', { class: 'about-credit' }, h('span', { class: 'about-by' }, 'Developed by '), h('a', { href: about.author_url, target: '_blank', rel: 'noopener', title: `${about.author}: ${about.author_url}` }, about.author)),
    editionBadge(about.edition));
}

// setTitle names the page in the browser's tab and history: "Network |
// Signal Console".
function setTitle(name) {
  const page = NAV.find((item) => item && item[0] === name);
  const label = page ? page[1] : { import: 'Import', login: 'Sign in' }[name];
  document.title = label ? `${label} | Signal Console` : 'Signal Console';
}

// renderGeneration guards against a race: if the user navigates again
// before a page's own async render finishes, the stale render must not end
// up on screen. Each renderer builds into a detached container; only once
// it resolves, and only if no newer navigation happened, is that container
// attached to #app.
let renderGeneration = 0;

async function render() {
  const mine = ++renderGeneration;
  const app = document.getElementById('app');
  delete app.dataset.page;
  if (!sessionUser() && !(await loadSession())) {
    if (mine !== renderGeneration) return;
    return showLogin(mine);
  }
  let name = currentPage();
  // The sign-in page, once signed in, opens the home page.
  if (name === 'login') { history.replaceState(null, '', pageUrl(HOME)); name = HOME; }
  const onRuns = true;
  if (name === 'import' && !canEdit()) { history.replaceState(null, '', pageUrl('overview')); name = 'overview'; }
  setTitle(name);
  drawHeader();
  if (onRuns) hideEmptyPages();
  if (onRuns) await loadRunModules();
  document.querySelectorAll('#tabs button').forEach((b) => {
    b.classList.toggle('on', b.dataset.tab === name);
    if (b.dataset.tab === name) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });
  document.getElementById('importBtn').classList.toggle('on', name === 'import');
  app.replaceChildren(loadingView(document.title.replace(/ \| Signal Console$/, '')));

  const built = h('div');
  try {
    await RENDERERS[name](built);
  } catch (err) {
    if (mine !== renderGeneration) return;
    if (!sessionUser()) return showLogin(mine); // the session ended while the page loaded
    hideSplash();
    app.replaceChildren(h('div', { class: 'card' }, `Failed to load: ${err.message}`));
    return;
  }
  if (mine !== renderGeneration) return; // a newer navigation happened while this one was loading
  app.replaceChildren(built);
  hideSplash();
  app.dataset.page = `${name}:${mine}`; // for tests: this navigation's page is on screen
  const focus = built.querySelector('.focus-row'); // a deep link's target, e.g. /rules?rule=<rule id>
  if (focus && focus.scrollIntoView) focus.scrollIntoView({ block: 'center' });
}

// loadingView is what a page shows while it loads: the logo's mark
// breathing over a running bar and the page's name - shown only after a
// moment (CSS), so a fast page never flashes it.
const loadingView = (label) => h('div', { class: 'page-loading', role: 'status' },
  h('div', { class: 'loader' }, h('span', { class: 'brand-mark' }), h('span', { class: 'loader-bar' }), h('span', { class: 'mut' }, `Loading ${label}…`)));

// hideSplash fades out the start-up splash (index.html) once the first
// page or the sign-in form is on screen.
function hideSplash() {
  const splash = document.getElementById('splash');
  if (!splash || splash.classList.contains('gone')) return;
  splash.classList.add('gone');
  setTimeout(() => splash.remove(), 400);
}

// showLogin replaces the page with the sign-in form, remembering the page
// that was asked for, and opens it once signed in.
async function showLogin(mine) {
  hideSplash();
  const app = document.getElementById('app');
  if (currentPage() !== 'login' || location.pathname !== '/login') {
    const next = location.pathname === '/login' ? '' : location.pathname + location.search;
    history.replaceState(null, '', `/login${next ? '?next=' + encodeURIComponent(next) : ''}`);
  }
  setTitle('login');
  drawHeader();
  await renderLogin(app, (next) => {
    history.replaceState(null, '', next.startsWith('/') && !next.startsWith('//') ? next : `/${HOME}`);
    render();
  });
  app.dataset.page = `login:${mine}`;
}

// A request refused for want of a session (it expired, or the account was
// signed out elsewhere) shows the sign-in page.
window.addEventListener('signal:signin', () => {
  if (!sessionUser()) return;
  setSession(null);
  render();
});

// setupKeys is the keyboard's way through a page's tables: "/" to the first
// table's search, j / k to the next or previous row (every table on the
// page, in order), Enter to open or unfold the row, Esc out of a search box.
// Keys typed into a field are its own.
function setupKeys() {
  let current = null;
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.target.closest('input, textarea, select, [contenteditable]')) {
      if (e.key === 'Escape' && e.target.type === 'search') e.target.blur();
      return;
    }
    const app = document.getElementById('app');
    if (e.key === '/') {
      const box = app.querySelector('.data-table input[type=search]');
      if (box) { e.preventDefault(); box.focus(); box.select(); }
    } else if (e.key === 'j' || e.key === 'k') {
      const rows = [...app.querySelectorAll('.tw > table > tbody > tr:not(.detail-row):not(.skeleton-row)')].filter((r) => r.offsetParent);
      if (!rows.length) return;
      const at = rows.indexOf(current);
      const next = rows[at < 0 ? 0 : Math.max(0, Math.min(rows.length - 1, at + (e.key === 'j' ? 1 : -1)))];
      if (current) current.classList.remove('kbd-row');
      current = next;
      current.classList.add('kbd-row');
      current.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter' && e.target === document.body && current && current.isConnected) {
      current.click();
    }
  });
}

onNavigate(render);
setupTheme();
setupKeys();
setupFinder(onData);
buildNav();
const importBtn = document.getElementById('importBtn');
importBtn.replaceChildren(svgIcon('upload')); // an icon; its name is the button's aria-label and tooltip
importBtn.addEventListener('click', () => go('import', {}));
setupTasks(document.getElementById('tasksBtn'));
const findBtn = document.getElementById('findBtn');
findBtn.replaceChildren(svgIcon('search'));
startSectionNav(document.getElementById('app'));
findBtn.addEventListener('click', openFinder);
window.addEventListener('popstate', render);
if (!PAGES.includes(location.pathname.replace(/^\/+|\/+$/g, ''))) history.replaceState(null, '', `/${HOME}` + location.search);
render();

// A page's review mark changed: the navigation's marks follow.
window.addEventListener('reviews-changed', () => hideEmptyPages());
