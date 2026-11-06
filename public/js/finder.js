// The finder: one box, from any page about the runs (the top bar's search button
// or Ctrl+K), that finds an entity by its name, key or one of its facts - a
// SHA-256, a path, a signer, an address - across every host's latest
// collection (GET /api/entities/find): "where else is this?". Each answer
// names what matched and the hosts where it does, those with signals about
// it first; its name opens its page, a host opens it on that host.

import { h, fetchJSON, mono, svgIcon } from './dom.js';
import { pageLink, queryString } from './router.js';
import { entityIcon } from './components.js';

// MAX_HOSTS is how many hosts an answer names; the rest are counted.
const MAX_HOSTS = 8;

let panel = null;

// openFinder shows the finder (once), its box focused.
export function openFinder() {
  if (!panel) panel = buildPanel();
  document.body.append(panel);
  const box = panel.querySelector('input');
  box.focus();
  box.select();
}

function closeFinder() {
  if (panel) panel.remove();
}

function buildPanel() {
  const results = h('div', { class: 'finder-results' });
  let timer = 0;
  let asked = 0;
  const search = async (text) => {
    const mine = ++asked;
    if (text.trim().length < 3) return results.replaceChildren(h('div', { class: 'mut' }, 'Type 3 characters or more: a name, a path, a SHA-256, an account, an address…'));
    let answer;
    try {
      answer = await fetchJSON(`/api/entities/find?${queryString({ q: text })}`);
    } catch (err) {
      if (mine === asked) results.replaceChildren(h('div', { class: 'mut' }, `The search failed: ${err.message}`));
      return;
    }
    if (mine !== asked) return; // a newer search was typed meanwhile
    if (!answer.rows.length) return results.replaceChildren(h('div', { class: 'mut' }, 'No entity any host\'s latest collection knows has this in its name or facts.'));
    results.replaceChildren(...answer.rows.map(answerRow),
      ...(answer.more ? [h('div', { class: 'mut' }, `Only the first ${answer.rows.length} are shown - type more to narrow it.`)] : []));
  };
  const box = h('input', {
    type: 'search', placeholder: 'Find an entity across the hosts - name, path, SHA-256, account, address…', 'aria-label': 'Find an entity',
    oninput: (e) => { clearTimeout(timer); timer = setTimeout(() => search(e.target.value), 200); },
  });
  const frame = h('div', { class: 'finder', role: 'dialog', 'aria-label': 'Find an entity' },
    h('div', { class: 'finder-bar' }, svgIcon('search'), box, h('button', { class: 'ghost', onclick: closeFinder, title: 'Close (Esc)' }, 'Close')),
    h('div', { class: 'mut finder-note' }, 'Every host\'s latest collection: the entities its signals are about or name, and those Signal read facts about. A match is text, not proof the hosts share one thing.'),
    results);
  const veil = h('div', { class: 'finder-veil', onclick: (e) => { if (e.target === veil) closeFinder(); } }, frame);
  veil.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.stopPropagation(); closeFinder(); } });
  search('');
  return veil;
}

// answerRow is one entity found: its type and name (its page), what
// matched, and the hosts where it does - those with signals about it
// first, each opening its page on that host.
function answerRow(r) {
  const hosts = r.hosts.slice(0, MAX_HOSTS).map((x) => pageLink('signals', { entity: r.id, host: x.run_id },
    x.subject ? h('b', { title: 'Signals are about it on this host' }, x.host) : h('span', { title: 'Named by signals or read about on this host - no signal is about it' }, x.host)));
  const signals = r.subject_n ? `signals about it on ${r.subject_n} of ${r.hosts.length} host${r.hosts.length === 1 ? '' : 's'}` : `no signal about it - named or read about on ${r.hosts.length} host${r.hosts.length === 1 ? '' : 's'}`;
  return h('div', { class: 'finder-row' },
    h('div', {}, pageLink('signals', { entity: r.id }, h('span', { class: 'entity-link' }, svgIcon(entityIcon(r.type)), mono(r.display))), h('span', { class: 'mut' }, ` ${r.type}`)),
    h('div', { class: 'mut sig-small' }, `matched: ${r.matched.join(', ')} · ${signals}`),
    h('div', { class: 'finder-hosts' }, ...hosts.flatMap((a, i) => [i ? ', ' : '', a]), r.hosts.length > MAX_HOSTS ? h('span', { class: 'mut' }, ` and ${r.hosts.length - MAX_HOSTS} more`) : null));
}

// setupFinder wires Ctrl+K (⌘K) to the finder on every page about the runs.
export function setupFinder(inCase) {
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'k' && inCase()) {
      e.preventDefault();
      openFinder();
    }
  });
}
