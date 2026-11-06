// The Graph page (after Timeline): the entity graph on its own, taking the
// page's width and height (it was a card on Overview until console 0.116.0).
// One node per entity across the hosts in view, a line to every entity its
// signals name and to each host it has signals on; the host filter (shared
// across the pages) chooses the hosts. The graph's own bar holds its
// options (search, Types, Hosts, Arrange, big modes...); ⤢ fills the window
// with the top bar still above it, ⛶ the whole screen.

import { h, fetchJSON } from '../dom.js';
import { filterBar, stickyPage, hostScopeFilters } from '../components.js';
import { entityGraph } from '../graph.js';
import { canEdit } from '../session.js';

const DEFAULT_HOSTS = 20, MAX_IN_URL = 200;

export async function renderGraphPage(container) {
  const runs = (await fetchJSON('/api/runs')).filter((r) => r.latest);
  const body = h('div', { class: 'graph-page' });
  // A large fleet opens on its DEFAULT_HOSTS riskiest hosts, not every host:
  // the graph's cost grows with what it draws (the user, 2026-11-04).
  const riskiest = runs.length > DEFAULT_HOSTS
    ? runs.slice().sort((a, b) => (b.risk || 0) - (a.risk || 0) || String(a.host).localeCompare(String(b.host))).slice(0, DEFAULT_HOSTS).map((r) => r.run_id)
    : null;
  const scope = hostScopeFilters(runs, load, riskiest);
  const bar = filterBar(scope.fields);
  stickyPage(container, bar);
  container.replaceChildren(bar, body);

  let generation = 0;
  async function load() {
    const mine = ++generation;
    const chosen = scope.selected();
    if (chosen.length === 0) {
      body.replaceChildren(h('div', { class: 'card mut' }, runs.length ? 'No host matches the filters.' : 'No hosts yet - import a Signal run first.'));
      return;
    }
    const inView = new Set(chosen.map((r) => r.run_id));
    // Only the chosen hosts' entities are asked for - unless so many are
    // chosen that their IDs would make the address too long; then all
    // come and the page keeps the chosen.
    const some = chosen.length < runs.length && chosen.length <= MAX_IN_URL;
    const [flags, entities, analyst, vt] = await Promise.all([fetchJSON('/api/flags'), fetchJSON('/api/entities' + (some ? `?runs=${encodeURIComponent([...inView].join(','))}` : '')), fetchJSON('/api/graph/analyst'), fetchJSON('/api/entities/virustotal')]);
    if (mine !== generation) return;
    const rows = entities.rows.filter((r) => inView.has(r.run_id));
    const ranked = riskiest && chosen.length === riskiest.length && chosen.every((r) => riskiest.includes(r.run_id));
    body.replaceChildren(...[
      ranked ? h('div', { class: 'mut sig-small' }, `Showing the ${riskiest.length} riskiest of ${runs.length.toLocaleString()} hosts (by open signals' risk) - choose others with Hosts.`) : null,
      rows.length
        ? entityGraph(rows, { flags: flags.filter((f) => f.kind === 'entities').map((f) => f.key), analyst, vt, editable: canEdit() })
        : h('div', { class: 'card mut' }, 'No signals name any entity yet - nothing to graph.')].filter(Boolean)); // the DOM's own replaceChildren prints a null
  }
  await load();
}
