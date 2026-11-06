// The ATT&CK coverage matrix (Overview): tactics as columns, each
// technique a cell coloured by how many of Signal's rules mapped to it were
// evaluated - 0, 1, 2, 3+, red to green, the count always written
// in the cell. Techniques are collapsed to their sub-techniques by default;
// a cell's caret, or "Expand all", unfolds them. A technique with a rule
// that was not evaluated carries the not-evaluated mark, its hover card
// naming the rules and why; one Signal cannot see from a host is greyed,
// with the reason. ⤢ and ⛶ fill the browser window or the screen, as the
// entity graph's do. The data is /api/dashboards/attack (model/attack.js).

import { h, withTip } from './dom.js';
import { bigModeButtons } from './components.js';

const BANDS = [[0, '0 rules'], [1, '1 rule'], [2, '2 rules'], [3, '3+ rules']];
const band = (n) => BANDS.filter(([min]) => n >= min).length - 1;

// coverageText is a cell's coverage in words: the rules evaluated, and with
// several hosts in view on how many at least one was.
function coverageText(c, hosts) {
  const rules = `${c.count} rule${c.count === 1 ? '' : 's'} evaluated`;
  if (hosts === 1) return rules;
  return `${rules} · ${c.hosts_covered} of ${hosts} hosts, ${Math.round((100 * c.hosts_covered) / hosts)}%`;
}

function cellTip(c, hosts) {
  if (c.out_of_scope) return h('span', {}, h('b', {}, `${c.id} ${c.name}`), h('br'), `Out of Signal's scope: ${c.out_of_scope}`);
  return h('span', {}, h('b', {}, `${c.id} ${c.name}`), h('br'), coverageText(c, hosts),
    c.rules.length ? h('div', { class: 'mut' }, c.rules.join(', ')) : null,
    ...c.not_evaluated.map((n) => h('div', { class: 'matrix-missed' }, `Not evaluated: ${n.rule} - `,
      hosts === 1 && n.reason ? n.reason : n.reasons.map((r) => `${r.label} on ${r.hosts} host${r.hosts === 1 ? '' : 's'}`).join('; '))));
}

function cell(c, hosts, sub) {
  const cls = `matrix-cell ${c.out_of_scope ? 'cov-out' : `cov-${band(c.count)}`}${sub ? ' matrix-sub' : ''}`;
  const body = h('div', { class: 'matrix-body' },
    h('div', { class: 'matrix-name' }, c.name),
    h('div', { class: 'matrix-meta' }, h('span', { class: 'mono' }, c.id),
      c.out_of_scope ? h('span', {}, 'out of scope') : h('span', {}, hosts === 1 ? `${c.count}` : `${c.count} · ${Math.round((100 * c.hosts_covered) / hosts)}%`),
      c.not_evaluated.length ? h('span', { class: 'matrix-flag', 'aria-label': 'rules not evaluated' }, '!') : null));
  return h('div', { class: cls, 'data-attack-id': c.id }, withTip(body, cellTip(c, hosts), 'matrix-tip'));
}

function technique(t, hosts) {
  if (!t.subs.length) return h('div', { class: 'matrix-group' }, cell(t, hosts, false));
  const subs = h('div', { class: 'matrix-subs', hidden: true });
  const toggle = h('button', { class: 'matrix-caret', type: 'button', title: `${t.subs.length} sub-techniques`, 'aria-expanded': 'false' }, `▸ ${t.subs.length}`);
  const group = h('div', { class: 'matrix-group' }, toggle, cell(t, hosts, false), subs);
  group.expand = (open) => {
    if (open && !subs.childElementCount) subs.replaceChildren(...t.subs.map((s) => cell(s, hosts, true)));
    subs.hidden = !open;
    toggle.textContent = `${open ? '▾' : '▸'} ${t.subs.length}`;
    toggle.setAttribute('aria-expanded', String(open));
  };
  toggle.onclick = () => group.expand(subs.hidden);
  return group;
}

export function attackMatrix(m) {
  const one = m.hosts === 1;
  const columns = m.tactics.map((tactic) => h('div', { class: `matrix-col${tactic.out_of_scope ? ' cov-out-col' : ''}` },
    h('div', { class: 'matrix-head', title: tactic.out_of_scope ? `Out of Signal's scope: ${tactic.out_of_scope}` : '' },
      h('div', {}, tactic.name), h('div', { class: 'mut' }, `${tactic.techniques.length} techniques`)),
    ...tactic.techniques.map((t) => technique(t, m.hosts))));
  const groups = () => columns.flatMap((c) => [...c.querySelectorAll('.matrix-group')]).filter((g) => g.expand);
  let open = false;
  const all = h('button', { type: 'button', class: 'ghost' }, 'Expand all');
  all.onclick = () => {
    open = !open;
    groups().forEach((g) => g.expand(open));
    all.textContent = open ? 'Collapse all' : 'Expand all';
  };
  const legend = h('div', { class: 'matrix-legend' },
    ...BANDS.map(([, label], i) => h('span', {}, h('i', { class: `cov-${i}` }), label)),
    h('span', {}, h('i', { class: 'cov-out' }), 'out of Signal\'s scope'),
    h('span', {}, h('b', { class: 'matrix-flag' }, '!'), 'a mapped rule was not evaluated'));
  return h('div', {},
    h('p', { class: 'mut card-intro' },
      one ? 'Each Windows technique of ATT&CK, coloured by how many of Signal\'s rules mapped to it were evaluated (flagged or clear) on this host. '
        : 'Each Windows technique of ATT&CK, coloured by how many of Signal\'s rules mapped to it were evaluated on at least one host in view; the percentage is the share of hosts on which at least one of them was. Read the colour and the percentage together. ',
      'A sub-technique\'s rules count toward its technique. Coverage is a reference, not a verdict: a covered technique may still have happened - by evasion, or with its evidence absent or removed.'),
    h('div', { class: 'matrix-wrap' },
      h('div', { class: 'matrix-bar' }, all, legend, h('span', { class: 'mut' }, `ATT&CK Enterprise ${m.version}, Windows (MITRE, ${String(m.modified).slice(0, 10)})`),
        h('span', { class: 'matrix-modes' }, ...bigModeButtons('.matrix-wrap'))),
      h('div', { class: 'matrix-frame' }, h('div', { class: 'attack-matrix', style: `grid-template-columns: repeat(${columns.length}, minmax(150px, 1fr))` }, ...columns))));
}
