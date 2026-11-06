// Shared page components: tags, the narrative, module badges, cards and the
// error-isolating section wrapper, filter bars and summary strips, grouping,
// host links, KPI cards and telemetry; an entity's facts card, the
// occurrence timeline and the triage block, shared by the signal and entity
// pages. The house style (the Rules page's look) lives here, so every page
// gets it by using these.

import { h, ts, mono, withTip, svgIcon, fetchJSON, virusTotalLink, fitToWindow, countUp } from './dom.js';
import { pageLink, listParam, setParams } from './router.js';
import { canEdit } from './session.js';

export const SEVERITY_RANK = { critical: -1, high: 0, medium: 1, low: 2 };

// ATTACK_TACTICS are ATT&CK Enterprise's tactics in kill-chain order (as of
// release 20.0, src/data/attack.json) - the groups of "group by ATT&CK
// tactic" (Rules and Signals pages); Defense Evasion, split by 20.0 into
// Stealth and Defense Impairment, stays for runs of Signal before 0.59.0.
// NO_TACTIC is the group of what has no ATT&CK mapping.
export const ATTACK_TACTICS = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Stealth', 'Defense Impairment', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
export const NO_TACTIC = 'No ATT&CK mapping';

// CORE names data Signal itself collects at the start of a run - the host's
// identity, who collected it and when - rather than any module.
export const CORE = 'Signal core';
// CONSOLE is the module of the console's own rules (src/consoleRules.js).
export const CONSOLE = 'Console';

// sevTag renders a severity as colored text with no background. Each
// severity has its own color, shared with no other tag (see style.css).
// quotedTitle is a signal's title with what it names - the values it quotes,
// such as a pivot point and its profile - set apart (italic, coloured), so
// the words of the rule and the values of this signal read differently.
export function quotedTitle(title) {
  const text = String(title ?? '');
  return h('span', {}, text.split(/("[^"]+")/).map((part, i) => (i % 2 ? h('em', { class: 'title-var' }, part) : part)));
}

export function sevTag(severity, text) {
  return h('span', { class: 'tagtext sev-' + severity }, text || severity);
}

// RULE_OUTCOME describes the three outcomes a rule can have on one host -
// its wording and its color - once, for every place that shows one.
export const RULE_OUTCOME = {
  flagged: { label: 'flagged', cls: 'st-flagged' },
  clear: { label: 'evaluated, no match', cls: 'st-ran' },
  not_run: { label: 'not evaluated', cls: 'st-notrun' },
};

export function outcomeTag(status) {
  const o = RULE_OUTCOME[status];
  return h('span', { class: 'tagtext ' + o.cls }, o.label);
}

// TRIAGE is the one definition of the triage states' wording and color.
export const TRIAGE = {
  new: { label: 'open', cls: 'tr-new' }, // stored as "new"; an untriaged signal is open
  // reviewed: a decision before 0.16.0 offered only open, benign and escalated - still shown as it was.
  reviewed: { label: 'reviewed', cls: 'tr-reviewed' },
  benign: { label: 'benign', cls: 'tr-benign' },
  escalated: { label: 'escalated', cls: 'tr-escalated' },
  // flagged: an analyst's flag with its reason, among the Reports page's
  // triage notes - never a signal's state.
  flagged: { label: 'flagged', cls: 'tr-escalated' },
};

export function triageTag(state) {
  const t = TRIAGE[state] || TRIAGE.new;
  return h('span', { class: 'tagtext ' + t.cls }, t.label);
}

// EVENT_STATUS is how SecurityLog's per-event-ID statuses read; each is
// colored by its ev-<status> class (style.css), a different color each.
export const EVENT_STATUS = {
  ok: 'present as expected',
  absent_common: 'absent (normally frequent)',
  absent: 'absent',
  present_policy_off: 'present, policy off',
  unmapped: 'not tied to a subcategory',
  policy_unknown: 'policy unknown',
  not_read: 'log not read',
  condition_occurred: 'always logged: its condition occurred',
  condition_not_seen: 'always logged: its condition did not occur',
};

// TELEMETRY_STATE is how a telemetry item's state reads and is colored.
const TELEMETRY_STATE = { on: 'tagtext st-ran', off: 'tagtext sev-high', unknown: 'mut' };

// SOURCE_STATUS describes whether an evidence source was read - its wording
// and color - once, for every place that shows one.
export const SOURCE_STATUS = {
  read: { label: 'read', cls: 'st-ran' },
  partial: { label: 'partly read', cls: 'ev-absent' },
  not_read: { label: 'not read', cls: 'st-notrun' },
  off: { label: 'off - not recorded', cls: 'ev-absent' },
  unavailable: { label: 'no source', cls: 'st-notrun' },
};

export function sourceTag(status) {
  const s = SOURCE_STATUS[status] || { label: status || 'unknown', cls: 'mut' };
  return h('span', { class: 'tagtext ' + s.cls }, s.label);
}

export function telemetryTag(state) {
  return h('span', { class: TELEMETRY_STATE[state] || 'mut' }, state || 'unknown');
}

// countCell renders a count as colored text in the given tag class, or a
// muted zero - so a column of counts reads at a glance which rows have any.
export function countCell(n, cls) {
  return h('span', { class: n ? 'tagtext ' + cls : 'mut' }, String(n));
}

// attackName is a technique as ATT&CK itself writes it, with its ID:
// "[T1059.001] Command and Scripting Interpreter: PowerShell".
function attackName(a) {
  return `[${a.id}] ${a.technique}${a.sub_technique ? ': ' + a.sub_technique : ''}`;
}

// attackTags renders a finding's or rule's ATT&CK techniques; the ID is
// kept as data-attack-id, the tactic shown on hover. A tag with no resolved
// name (not an ATT&CK ID) is shown as it is.
export function attackTags(attack, tags) {
  const refs = attack || [];
  const named = new Set(refs.map((a) => a.id));
  const chips = [
    ...refs.map((a) => h('span', { class: 'tag', 'data-attack-id': a.id, title: `${a.tactic}: ${a.label}` }, attackName(a))),
    ...(tags || []).filter((t) => !named.has(t)).map((t) => h('span', { class: 'tag' }, t)),
  ];
  return chips.length ? h('div', { style: 'margin-top:8px' }, chips) : null;
}

// fillTemplate renders a rule's own title/detail/focus text - which carries
// {placeholder}s, e.g. "{count} process creation(s)..." - with each
// placeholder replaced by the value it actually had on the hosts where the
// rule flagged. Those values are recovered from each flagged host's finding,
// whose text is the same template already expanded by Signal: the template
// is turned into a pattern with one capture per placeholder and matched
// against it. Across several hosts, {count} is summed, other numbers are
// shown as a range, and anything else is listed. Where no host flagged
// there is no value to show, and the placeholder is rendered as a named,
// styled variable rather than as raw "{...}" text.
export function fillTemplate(template, hosts, field) {
  if (!template || !template.includes('{')) return template || '';
  const re = /\{([A-Za-z_][A-Za-z0-9_.]*)\}/g;
  const names = [...template.matchAll(re)].map((m) => m[1]);
  const literal = template.split(re).filter((_, i) => i % 2 === 0);
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp('^' + literal.map(esc).join('([\\s\\S]*?)') + '$');
  const values = names.map(() => []);
  const flagged = (hosts || []).filter((x) => x.status === 'flagged' && x[field]);
  for (const x of flagged) {
    const m = pattern.exec(x[field]);
    if (m) names.forEach((_, i) => values[i].push(m[i + 1]));
  }
  const show = (name, vals) => {
    if (vals.length === 0) return h('span', { class: 'ph', title: 'filled in per host when this rule flags' }, name.replace(/[_.]/g, ' '));
    const nums = vals.map(Number);
    let text;
    if (nums.every((n) => !Number.isNaN(n))) {
      const lo = Math.min(...nums), hi = Math.max(...nums);
      text = name === 'count' ? String(nums.reduce((a, b) => a + b, 0)) : (lo === hi ? String(lo) : `${lo}–${hi}`);
    } else {
      text = [...new Set(vals)].join(', ');
    }
    const note = flagged.length > 1
      ? (name === 'count' ? `total across the ${flagged.length} flagged hosts` : `across the ${flagged.length} flagged hosts`)
      : 'on the one flagged host';
    return h('span', { class: 'ph-val', title: note }, text);
  };
  const out = [];
  literal.forEach((lit, i) => {
    out.push(lit);
    if (i < names.length) out.push(show(names[i], values[i]));
  });
  return h('span', {}, out);
}

// NARRATIVE is the three questions every signal and rule answers, in the
// order they are asked: what happened (detail), so what (impact) and what
// next (focus). narrative renders an item's answers as labelled
// paragraphs; fill(text, key) turns each answer's text into what is shown.
const NARRATIVE = [['detail', 'What happened'], ['impact', 'Why it matters'], ['focus', 'What next']];

export function narrative(item, fill = (text) => text) {
  const rows = NARRATIVE.filter(([key]) => item[key]).map(([key, label]) =>
    h('div', { class: 'narrative-row' }, h('span', { class: 'narrative-label' }, label), h('span', {}, fill(item[key], key))));
  return rows.length ? h('div', { class: 'narrative' }, rows) : null;
}

// runModules is every module the runs in view have (main.js
// setRunModules, from /api/modules), so a badge naming them all can say
// "All".
let runModules = [];
export const setRunModules = (names) => { runModules = names; };
const BADGE_MAX = 4; // a badge names this many modules; a toggle shows the rest

// moduleBadge is the small label on a card saying which module(s)
// generated the data it shows, each opening that module on the Modules
// page (CORE is not a module and is not linked). Every module of the runs
// reads "All" (the Modules page); more than BADGE_MAX shows the first
// ones and a "+N" toggle for the rest.
export function moduleBadge(modules) {
  const list = [...new Set(modules || [])].filter(Boolean).sort();
  if (list.length === 0) return null;
  const mods = list.filter((m) => m !== CORE);
  const tip = mods.length === 0
    ? 'Collected by Signal itself at the start of the run, not by a module'
    : `Data from the ${list.join(', ')} module${list.length === 1 ? '' : 's'}`;
  const all = runModules.length > 1 && runModules.every((m) => mods.includes(m));
  const link = (m) => (m === CORE || m === CONSOLE ? m : pageLink('modules', { module: m }, m)); // the console's own rules are no Signal module
  const join = (items) => items.flatMap((m, i) => [i ? h('span', { class: 'sep' }, '·') : null, m]);
  if (all) {
    return h('span', { class: 'module-badge', title: `Data from every module of the runs: ${list.join(', ')}` }, svgIcon('module'),
      join([pageLink('modules', {}, 'All'), ...(list.includes(CORE) ? [CORE] : [])]));
  }
  const badge = h('span', { class: 'module-badge', title: tip }, svgIcon('module'), join(list.slice(0, BADGE_MAX).map(link)));
  if (list.length > BADGE_MAX) {
    const rest = list.slice(BADGE_MAX);
    const more = h('button', { class: 'badge-more', title: `Show the other ${rest.length}: ${rest.join(', ')}`, onclick: (e) => {
      e.stopPropagation(); // a badge sits in a collapsible card's header
      more.replaceWith(...join(rest.map(link)).filter(Boolean));
    } }, `+${rest.length}`);
    badge.append(h('span', { class: 'sep' }, '·'), more);
  }
  return badge;
}

// sourceLine names the module(s) whose data a view is built from.
export function sourceLine(modules) {
  return h('div', { class: 'source-line' }, moduleBadge(modules) || h('span', { class: 'mut' }, 'No selected run has a module with this data.'));
}

// truncatedList renders a list of values one per line, showing the first
// `max` and a "+N more" toggle for the rest, so a cell listing hundreds of
// items cannot stretch its table. render turns one item into its text or
// node.
export function truncatedList(items, max = 3, render = String) {
  const list = items || [];
  if (list.length === 0) return '—';
  const join = (xs) => xs.map((x) => h('span', { class: 'list-item' }, render(x)));
  const box = h('span', { class: 'list-items' }, join(list.slice(0, max)));
  if (list.length <= max) return box;
  let open = false;
  const more = h('button', {
    class: 'linklike',
    onclick: (e) => {
      e.stopPropagation();
      open = !open;
      box.replaceChildren(...join(open ? list : list.slice(0, max)));
      more.textContent = open ? 'show less' : `+${list.length - max} more`;
    },
  }, `+${list.length - max} more`);
  return h('span', { class: 'truncated-list' }, box, ' ', more);
}

// hostLink is one host - x is anything carrying its run_id, host, os,
// os_build and role - shown as text (its name by default), opening the
// host's page, with a hover card saying what the host is.
export function hostLink(x, text = x.host) {
  const os = [x.os, x.os_build && `build ${x.os_build}`].filter(Boolean).join(', ');
  return withTip(pageLink('hosts', { host: x.run_id }, text),
    [h('b', {}, x.host), h('span', {}, os || 'operating system not recorded'), x.role && h('span', {}, x.role), h('span', { class: 'mut' }, 'Opens the host\'s page')]);
}

export function hostLinks(hosts) {
  return truncatedList(hosts, 3, (x) => hostLink(x));
}

// ruleLinks lists the rules that flagged a value, each opening the rule.
export function ruleLinks(rules) {
  return truncatedList(rules, 3, (r) => pageLink('rules', { rule: r.rule_id }, h('span', { class: 'tagtext st-flagged' }, r.rule_id)));
}

// hostLabels names each run for a host filter or list: its host name,
// disambiguated by run ID only where two runs share a name.
export function hostLabels(runs) {
  const count = {};
  for (const r of runs) count[r.host] = (count[r.host] || 0) + 1;
  return new Map(runs.map((r) => [r.run_id, count[r.host] > 1 ? `${r.host} (${r.run_id})` : r.host]));
}

// detailBlock is one titled, spaced section of an expanded row's detail
// panel, so every panel's sections are separated the same way.
export function detailBlock(title, ...children) {
  return h('div', { class: 'detail-block' }, title && h('div', { class: 'detail-title' }, title), ...children);
}

// codeBlock renders lines of [text, tokenClass] pairs as a flat, dark,
// monospaced block - a rule's detection logic.
export function codeBlock(lines) {
  return h('pre', { class: 'code-block' }, lines.map((parts) =>
    h('div', {}, parts.map(([text, cls]) => (cls ? h('span', { class: 'cb-' + cls }, text) : text)))));
}

// appendCard appends a node only if one was built: section() returns null
// when its content declines to render, and a native append() would print
// that null as the text "null".
export function appendCard(container, node) {
  if (node) container.append(node);
}

// collapsibleCard wraps content in a card whose header toggles it open/shut
// on click - every section() card and every group card - so collapsing
// behaves identically everywhere, and content is never rebuilt on toggle.
// opts: collapsed (start shut), modules (the header's module badge), cls
// (an extra card class).
// titleText is a card title's words, for the section navigator.
function titleText(title) {
  return typeof title === 'string' ? title : (title?.textContent || '').trim();
}

export function collapsibleCard(title, contentNode, opts = {}) {
  let open = !opts.collapsed;
  const body = h('div', { style: open ? '' : 'display:none' }, contentNode);
  const chevron = h('span', { class: 'chevron', style: `transform:rotate(${open ? 90 : 0}deg)` }, '▸');
  const header = h('h2', {
    class: 'collapsible', 'data-title': titleText(title),
    onclick: () => {
      open = !open;
      body.style.display = open ? '' : 'none';
      chevron.style.transform = `rotate(${open ? 90 : 0}deg)`;
    },
  }, chevron, title, moduleBadge(opts.modules));
  return h('div', { class: 'card' + (opts.cls ? ' ' + opts.cls : '') }, header, body);
}

// section builds one card by calling build() and wrapping what it returns.
// If build throws - a dataset missing in a run, an unexpected data shape -
// the error is shown as that card's content instead of propagating, so one
// broken section never silently takes the cards after it down too. A card
// with a title is collapsible and starts collapsed unless opts.collapsed is
// false; opts.modules names its data's module(s). A card with no title (a
// warning banner; opts.cls gives it its style) is never collapsible. An
// error always shows open.
export function section(title, build, opts = {}) {
  const plainCard = (content) => h('div', { class: 'card' + (opts.cls ? ' ' + opts.cls : '') }, content);
  try {
    const content = build();
    if (content === null) return null;
    if (!title) return plainCard(content);
    return collapsibleCard(title, content, { collapsed: opts.collapsed !== false, modules: opts.modules });
  } catch (err) {
    console.error(`section "${title}" failed:`, err);
    const msg = h('div', { class: 'result-err' }, `Could not render this section: ${err.message}`);
    if (!title) return plainCard(msg);
    return collapsibleCard(title, msg, { modules: opts.modules });
  }
}

// closeOpenDropdown closes the checkbox dropdown that is open, if any: at
// most one is open at a time.
let closeOpenDropdown = null;

// checkboxDropdown is a multi-select control styled like a plain <select>.
// "All" and specific items are mutually exclusive: picking an item clears
// "All", and clearing every item falls back to "All". initialSelected
// (default: every option) restores a selection read from the URL. With a
// single option, "All" and that option are the same selection: the control
// names the option and lists it alone, chosen - one host is shown as that
// host, never as "All". Returns {el, get}.
// labelOf names an option for a reader (default: the option itself).
export function checkboxDropdown(options, onChange, initialSelected, labelOf = (o) => o) {
  let selected = new Set(initialSelected && initialSelected.length ? initialSelected : options);
  const only = options.length === 1;
  const btn = h('button', { class: 'ghost', style: 'min-width:180px; text-align:left', onclick: toggle }, label());
  const panel = h('div', { class: 'card dd-panel', style: 'display:none' });
  const el = h('div', { style: 'position:relative; display:inline-block' }, btn, panel);

  function label() {
    if (only) return labelOf(options[0]);
    if (selected.size === 0 || selected.size === options.length) return 'All';
    if (selected.size === 1) return labelOf([...selected][0]);
    return `${selected.size} of ${options.length} selected`;
  }

  function row(text, checked, onchange) {
    return h('label', { style: 'display:flex; align-items:center; gap:8px; padding:4px 2px; cursor:pointer; white-space:nowrap' },
      h('input', { type: 'checkbox', checked: checked ? 'checked' : null, onchange }), text);
  }

  function rebuild() {
    if (only) {
      const r = row(labelOf(options[0]), true, null);
      r.querySelector('input').disabled = true; // the only choice: nothing else to pick
      panel.replaceChildren(r, h('div', { class: 'mut', style: 'padding:4px 2px; font-size:12px' }, 'The only one imported'));
      return;
    }
    const allRow = row('All', selected.size === options.length || selected.size === 0, (e) => {
      selected = e.target.checked ? new Set(options) : new Set();
      commit();
    });
    const itemRows = options.map((opt) => row(labelOf(opt), selected.has(opt), (e) => {
      if (e.target.checked) selected.add(opt);
      else selected.delete(opt);
      if (selected.size === 0) selected = new Set(options);
      commit();
    }));
    panel.replaceChildren(allRow, h('div', { style: 'border-top:1px solid var(--bd); margin:4px 0' }), ...itemRows);
  }

  function commit() {
    btn.textContent = label();
    rebuild();
    onChange(new Set(selected));
  }

  // A click anywhere else closes the panel, and opening one dropdown closes
  // any other that is open (the button's click stops at it, so the other's
  // document listener would never hear it). The document listener exists
  // only while the panel is open, so a replaced page leaves nothing behind.
  function close() {
    panel.style.display = 'none';
    document.removeEventListener('click', close);
    if (closeOpenDropdown === close) closeOpenDropdown = null;
  }
  function toggle(e) {
    e.stopPropagation();
    if (panel.style.display !== 'none') return close();
    if (closeOpenDropdown) closeOpenDropdown();
    panel.style.display = 'block';
    fitToWindow(panel);
    document.addEventListener('click', close);
    closeOpenDropdown = close;
  }
  panel.onclick = (e) => e.stopPropagation();

  rebuild();
  return { el, get: () => new Set(selected) };
}

// filterBar is a page's filter bar: labeled controls in one card, kept on
// screen while scrolling (see stickyPage). fields is [[label, ...controls]].
export function filterBar(fields) {
  return h('div', { class: 'card filters sticky-bar' },
    fields.map(([label, ...controls]) => h('label', {}, h('span', { class: 'mut' }, label), ...controls)));
}

// stickyPage makes a page's filter bar stick to the top of the window and
// every table header on the page stick just below it.
export function stickyPage(container, bar) {
  container.classList.add('sticky-page');
  if (window.ResizeObserver) new ResizeObserver(() => container.style.setProperty('--sticky-top', bar.offsetHeight + 'px')).observe(bar);
}

// summaryStrip is a page's at-a-glance numbers: one row of icon, big
// number and label per item ({icon, value, label, cls, link} - cls a tag
// color class, link [page, params] to open what it counts), with the
// module(s) the numbers come from at its end.
export function summaryStrip(items, modules) {
  return h('div', { class: 'card summary-strip' }, items.map(({ icon, value, label, cls, link }) => {
    const num = countUp(h('span', { class: 'summary-value' + (cls ? ' tagtext ' + cls : '') }, String(value)));
    return h('div', { class: 'summary-item' }, svgIcon(icon), link ? pageLink(link[0], link[1], num) : num, h('span', { class: 'mut' }, label));
  }), moduleBadge(modules));
}

// severityItems are the summary-strip items of signals counted by
// severity, each opening those signals on the Signals page within
// linkParams' scope.
export function severityItems(counts, linkParams) {
  return Object.keys(SEVERITY_RANK).map((s) => ({ icon: 'severity', value: counts[s], label: s, cls: counts[s] ? 'sev-' + s : null, link: counts[s] ? ['signals', { ...linkParams, severity: s }] : null }));
}

// selectionFromUrl reads a multi-select filter's choice from the URL
// parameter `name` (comma-separated), keeping only values among options -
// toOption maps a URL value to its option. Absent or unknown means "all".
export function selectionFromUrl(name, options, toOption = (v) => v, fallback = options) {
  const picked = listParam(name).map(toOption).filter((o) => options.includes(o));
  return new Set(picked.length ? picked : fallback);
}

// groupHead is a group card's header: the group's name, how many rows it
// holds, and any further facts (nodes) about it.
export function groupHead(name, n, noun, ...facts) {
  return h('span', { class: 'group-head' }, h('span', { class: 'group-name' }, name),
    h('span', { class: 'mut' }, `${n.toLocaleString()} ${noun}${n === 1 ? '' : 's'}`), ...facts);
}

// groupedView splits rows into one collapsible card per group (the Rules
// page's "Group by"): keysOf(row) is the group - or groups - a row belongs
// to; order lists the groups to show (default: every group present,
// largest first); head(key, rows) is a card's header, build(rows, key) its
// content, and empty the note for a group in order with no rows.
export function groupedView(rows, { keysOf, order, head, build, empty }) {
  const groups = new Map();
  for (const r of rows) {
    for (const k of [].concat(keysOf(r))) {
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(r);
    }
  }
  const keys = order || [...groups.keys()].sort((a, b) => groups.get(b).length - groups.get(a).length || String(a).localeCompare(String(b)));
  return keys.map((k) => {
    const g = groups.get(k) || [];
    if (g.length === 0 && !empty) return null;
    return collapsibleCard(head(k, g), g.length ? build(g, k) : h('div', { class: 'mut' }, empty), { collapsed: true, cls: 'group' });
  }).filter(Boolean);
}

// tabbedPanel shows several related views in one panel, one at a time:
// tabs is [{id, title, count, build() -> Node}]. Each view is built the
// first time its tab opens and then kept, so switching back preserves it.
// variant 'sub' draws a panel nested in another's tab (smaller tabs).
export function tabbedPanel(tabs, variant) {
  const built = new Map();
  const bar = h('div', { class: 'row tab-bar' + (variant ? ' tab-bar-' + variant : '') });
  const body = h('div');
  function show(id) {
    for (const b of bar.children) b.classList.toggle('on', b.dataset.id === id);
    if (!built.has(id)) built.set(id, tabs.find((t) => t.id === id).build());
    body.replaceChildren(built.get(id));
  }
  for (const t of tabs) bar.append(h('button', { class: 'chip', 'data-id': t.id, onclick: () => show(t.id) }, `${t.title} (${t.count.toLocaleString()})`));
  if (tabs.length) show(tabs[0].id);
  return h('div', {}, bar, body);
}

// KPI_CLASS colors a value by its status: green good, red bad, orange
// (--attn) for a warning - the values that call for a look stand out.
const KPI_CLASS = { good: 'kpi-good', warn: 'kpi-warn', bad: 'kpi-bad' };

// moduleKpis is one module's KPIs as its module stated them (Signal's
// core.KPI), in one card of rows like the host's identity facts: label,
// value (colored by status) with its sub line and second number, and - for
// a warn or bad value - the note saying what it means and what to do.
function moduleKpis(name, kpis) {
  const rows = kpis.flatMap((k) => {
    const value = h('td', {},
      countUp(h('span', { class: 'kpi-v ' + (KPI_CLASS[k.status] || '') }, k.value)),
      k.second ? h('span', { class: 'mut' }, ` · ${k.second.value} ${k.second.label}`) : null,
      k.sub ? h('div', { class: 'mut' }, k.sub) : null);
    const row = h('tr', { 'data-kpi': k.id }, h('td', { class: 'mut' }, k.label), value);
    const noted = k.note && (k.status === 'warn' || k.status === 'bad');
    return noted ? [row, h('tr', { class: 'kpi-note-row' }, h('td', { colspan: '2' }, h('div', { class: 'kpi-note ' + KPI_CLASS[k.status] }, k.note)))] : [row];
  });
  return h('div', { class: 'card facts kpi-module' }, h('h2', { class: 'card-head' }, name, moduleBadge([name])), h('table', {}, rows));
}

// kpiGrid lays out a host's KPIs - [{module, kpis}] - one card per module,
// the modules with a value that calls for a look (warn or bad) first.
export function kpiGrid(modules) {
  const shown = modules.filter((m) => m.kpis.length);
  if (!shown.length) return null;
  const attention = (m) => m.kpis.some((k) => k.status === 'bad') ? 0 : m.kpis.some((k) => k.status === 'warn') ? 1 : 2;
  const ordered = [...shown].sort((a, b) => attention(a) - attention(b));
  return h('div', { class: 'grid kpi-modules' }, ordered.map((m) => moduleKpis(m.name, m.kpis)));
}

// stackBar is one horizontal bar split into colored parts ([[count, cls,
// title]]), for the dashboard's telemetry and freshness cards.
export function stackBar(parts) {
  const total = parts.reduce((n, [c]) => n + c, 0) || 1;
  return h('div', { class: 'stack-bar' }, parts.filter(([c]) => c > 0).map(([c, cls, title]) => h('i', { class: cls, title: `${title}: ${c}`, style: `width:${(c * 100) / total}%` })));
}

// factCard is a card of labelled facts, headed by its title and the
// module(s) - or Signal core - the facts come from (a host's or a user's
// identity).
export function factCard(title, modules, pairs) {
  return h('div', { class: 'card facts' },
    h('h2', { class: 'card-head', 'data-title': titleText(title) }, title, moduleBadge(modules)),
    h('table', {}, pairs.filter(([, v]) => v !== undefined).map(([k, v]) =>
      h('tr', {}, h('td', { class: 'mut' }, k), h('td', {}, v && v.nodeType ? v : String(v === '' || v == null ? '—' : v))))));
}

// fullWindow makes a frame fill the browser's page area (the window and
// its tabs stay), or puts it back; Esc puts it back too.
export function fullWindow(frame) {
  const on = frame.classList.toggle('full-window');
  const esc = (e) => { if (e.key === 'Escape') fullWindow(frame); };
  if (on) { frame.esc = esc; document.addEventListener('keydown', esc); } else document.removeEventListener('keydown', frame.esc);
}

// bigModeButtons are the ⤢ (fill the browser window) and ⛶ (full screen)
// buttons of the frame they sit in, found by its selector.
export function bigModeButtons(frameSelector) {
  const frameOf = (e) => e.currentTarget.closest(frameSelector);
  return [
    h('button', { class: 'ghost big-mode', title: 'Fill the browser window (Esc leaves it)', onclick: (e) => fullWindow(frameOf(e)) }, '⤢'),
    h('button', { class: 'ghost big-mode', title: 'Full screen (Esc leaves it)', onclick: (e) => {
      const frame = frameOf(e);
      if (document.fullscreenElement) document.exitFullscreen();
      else if (frame.requestFullscreen) frame.requestFullscreen();
    } }, '⛶')];
}

// svgEl creates an SVG element with attributes and children.
export function svgEl(tag, attrs = {}, ...children) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined) el.setAttribute(k, v);
  for (const c of children.flat()) if (c) el.append(c);
  return el;
}

// TREND_SERIES are the trend chart's two series: their key in a day's
// counts, label and color token (validated as a pair, light and dark).
const TREND_SERIES = [
  { key: 'logons', label: 'Logons', color: 'var(--chart-logons)' },
  { key: 'failures', label: 'Failed logons', color: 'var(--chart-failures)' },
];

// calendarDays fills the days between the first and the last of days
// ([{day, ...counts}], "YYYY-MM-DD", any order) with zeros, so a quiet day
// shows as a gap rather than disappearing.
function calendarDays(days) {
  if (!days.length) return [];
  const byDay = new Map(days.map((d) => [d.day, d]));
  const sorted = [...byDay.keys()].sort();
  const out = [];
  for (let t = Date.parse(sorted[0] + 'T00:00:00Z'); t <= Date.parse(sorted[sorted.length - 1] + 'T00:00:00Z'); t += 86400000) {
    const day = new Date(t).toISOString().slice(0, 10);
    out.push(byDay.get(day) || { day, logons: 0, failures: 0 });
  }
  return out;
}

// trendChart is logons and failed logons per day: one stacked bar per day
// (logons on the baseline, failures above them), the scale's maximum, the
// first, middle and last day, a legend with each series' total, and each
// day's counts on hover. days: [{day, logons, failures}].
export function trendChart(days, { title = 'Logons and failed logons per day (UTC)' } = {}) {
  const series = calendarDays(days);
  if (!series.length) return h('div', { class: 'mut' }, 'No logon activity recorded.');
  const W = Math.max(1000, series.length * 8), H = 190, left = 40, right = 8, top = 12, bottom = 24;
  const plotW = W - left - right, plotH = H - top - bottom;
  const max = Math.max(1, ...series.map((d) => d.logons + d.failures));
  const slot = plotW / series.length;
  const barW = Math.max(1, slot - 2);
  const y = (v) => (v / max) * plotH;
  const tip = h('div', { class: 'trend-tip', hidden: 'hidden' });
  const bars = series.map((d, i) => {
    const x = left + i * slot + (slot - barW) / 2;
    let base = top + plotH;
    const parts = [];
    TREND_SERIES.forEach((s, si) => {
      const v = d[s.key];
      if (!v) return;
      const hgt = Math.max(1, y(v) - (parts.length ? 2 : 0)); // a 2px surface gap between stacked segments
      const isTop = !TREND_SERIES.slice(si + 1).some((n) => d[n.key]);
      const r = isTop ? Math.min(2, barW / 2, hgt) : 0;
      const yTop = base - hgt;
      parts.push(svgEl('path', { fill: s.color, d: `M${x},${base}V${yTop + r}q0,-${r} ${r},-${r}h${barW - 2 * r}q${r},0 ${r},${r}V${base}Z` }));
      base = yTop - 2;
    });
    const hit = svgEl('rect', { x: left + i * slot, y: top, width: slot, height: plotH, fill: 'transparent', class: 'trend-hit' });
    const group = svgEl('g', { class: 'trend-day' }, ...parts, hit);
    group.addEventListener('mouseenter', () => {
      tip.replaceChildren(h('b', {}, d.day), ...TREND_SERIES.map((s) => h('div', {}, h('i', { class: 'swatch', style: `background:${s.color}` }), `${s.label}: ${d[s.key].toLocaleString()}`)));
      tip.hidden = false;
      tip.style.left = `${((left + (i + 0.5) * slot) / W) * 100}%`;
    });
    group.addEventListener('mouseleave', () => { tip.hidden = true; });
    return group;
  });
  const text = (x, yy, s, anchor = 'middle') => svgEl('text', { x, y: yy, 'text-anchor': anchor, class: 'trend-axis' }, s);
  const mid = series[Math.floor(series.length / 2)].day;
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `${title}: ${series.length} days, up to ${max} a day` },
    svgEl('line', { x1: left, x2: W - right, y1: top, y2: top, class: 'trend-grid' }),
    svgEl('line', { x1: left, x2: W - right, y1: top + plotH, y2: top + plotH, class: 'trend-base' }),
    text(left - 4, top + 4, max.toLocaleString(), 'end'), text(left - 4, top + plotH, '0', 'end'),
    text(left, H - 4, series[0].day, 'start'), series.length > 2 ? text(W / 2, H - 4, mid) : null, text(W - right, H - 4, series[series.length - 1].day, 'end'),
    ...bars);
  const totals = TREND_SERIES.map((s) => series.reduce((n, d) => n + d[s.key], 0));
  return h('div', { class: 'trend' },
    h('div', { class: 'trend-legend' }, TREND_SERIES.map((s, i) => h('span', {}, h('i', { class: 'swatch', style: `background:${s.color}` }), `${s.label} `, h('b', {}, totals[i].toLocaleString())))),
    h('div', { class: 'trend-plot' }, svg, tip));
}

// renderEnrichment shows what Signal found out about an event's subject
// after the fact - a file's own timestamps, its signature, whether the
// process is still running - the same way for every module.
export function renderEnrichment(en) {
  if (!en) return null;
  const rows = [];
  if (en.file) {
    rows.push(h('div', {}, h('b', {}, 'File: '),
      en.file.exists
        ? `exists, last modified ${ts(en.file.modified)} (created ${ts(en.file.created)}, accessed ${ts(en.file.accessed)})`
        : h('span', { class: 'result-err' }, 'not found on disk')));
  }
  if (en.signature) {
    const s = en.signature;
    let text, cls;
    if (!s.signed) {
      text = 'not signed'; cls = 'mut';
    } else if (s.valid) {
      text = `signed and valid — ${s.signer || '(signer name unavailable)'}`; cls = 'result-ok';
    } else {
      text = `signed but INVALID — ${s.signer || '(signer name unavailable)'}`; cls = 'result-err';
    }
    rows.push(h('div', {}, h('b', {}, 'Signature: '), h('span', { class: cls }, text)));
  }
  if (en.process) {
    rows.push(h('div', {}, h('b', {}, 'Process: '),
      en.process.still_running
        ? h('span', { class: 'result-ok' }, 'still running')
        : h('span', {}, 'not running' + (en.process.note ? ` (${en.process.note})` : ''))));
  }
  if (en.gaps && en.gaps.length > 0) {
    rows.push(h('div', { class: 'mut' }, 'Not determined: ' + en.gaps.map((g) => `${g.item} (${g.reason})`).join('; ')));
  }
  if (rows.length === 0) return null;
  return h('div', { class: 'enrichment' }, rows);
}

// hostScopeFilters is the host filters Overview and Inventories share -
// Hosts (by name), OS build and Role, over every host's latest collection,
// kept in the URL (hosts=<run ids>, os=, role=) - as {fields, selected()}.
// onChange is called after every change.
// defaultHosts (run IDs) is the hosts chosen when neither the URL nor the
// remembered choice names any (the Graph page's riskiest; else every host).
export function hostScopeFilters(runs, onChange, defaultHosts = null) {
  const labels = hostLabels(runs);
  const osOf = (r) => [r.os, r.os_build].filter(Boolean).join(' ') || 'not recorded';
  const options = {
    hosts: runs.map((r) => labels.get(r.run_id)),
    os: [...new Set(runs.map(osOf))].sort(),
    roles: [...new Set(runs.map((r) => r.role))].sort(),
  };
  const sel = {
    hosts: selectionFromUrl('hosts', options.hosts, (id) => labels.get(id), defaultHosts ? defaultHosts.map((id) => labels.get(id)) : options.hosts),
    os: selectionFromUrl('os', options.os),
    roles: selectionFromUrl('role', options.roles),
  };
  const all = (key) => sel[key].size === options[key].length;
  const pick = (key) => (s) => {
    sel[key] = s.size ? s : new Set(options[key]);
    setParams({
      hosts: all('hosts') ? null : runs.filter((r) => sel.hosts.has(labels.get(r.run_id))).map((r) => r.run_id),
      os: all('os') ? null : [...sel.os], role: all('roles') ? null : [...sel.roles],
    });
    onChange();
  };
  return {
    fields: [
      ['Hosts', checkboxDropdown(options.hosts, pick('hosts'), [...sel.hosts]).el],
      ['OS build', checkboxDropdown(options.os, pick('os'), [...sel.os]).el],
      ['Role', checkboxDropdown(options.roles, pick('roles'), [...sel.roles]).el],
    ],
    selected: () => runs.filter((r) => sel.hosts.has(labels.get(r.run_id)) && sel.os.has(osOf(r)) && sel.roles.has(r.role)),
  };
}

// ENTITY_ICONS are each entity type's icon.
const ENTITY_ICONS = { host: 'hosts', program: 'terminal', file: 'file', account: 'user', address: 'globe', log: 'dataset', service: 'layers', task: 'clock', application: 'apps', extension: 'puzzle', domain: 'link', gpo: 'policy', directory_object: 'tree', remote_tool: 'remote', remote_peer: 'peer', web_app: 'webapp', recovery: 'lifebuoy', product: 'shield', threat: 'warning', setting: 'mode', wmi_consumer: 'plug' };
export const entityIcon = (type) => ENTITY_ICONS[type] || 'target';
export const ENTITY_TYPES = Object.keys(ENTITY_ICONS); // the types an analyst may give an entity added by hand

// ROLES are Signal's relationship words (schema 52, Signal's
// internal/entity/role.go): each role, how it reads from the subject toward
// the related entity, its inverse, and how that reads.
const ROLE_PAIRS = [
  ['parent', 'started by', 'child', 'started'], ['ran_as', 'ran as', 'ran', 'ran'], ['user', 'user', 'user_of', 'user of'],
  ['actor', 'done by', 'did', 'did'], ['target', 'acted on', 'target_of', 'acted on by'], ['from', 'from', 'source_of', 'source of'],
  ['to', 'to', 'reached_by', 'reached by'], ['remote', 'other end', 'remote', 'other end'], ['runs', 'runs', 'run_by', 'run by'],
  ['hijacks', 'hijacks', 'hijacked_by', 'hijacked by'], ['recorded_by', 'recorded by', 'recorded', 'recorded'],
  ['detected_as', 'detected as', 'detected_in', 'detected in'], ['process', 'process', 'process_of', 'process of'],
  ['excludes', 'excludes', 'excluded_by', 'excluded by'], ['in_file', 'in file', 'holds', 'holds'], ['peer', 'peer', 'tool', 'tool'],
  ['transferred', 'transferred', 'transferred_by', 'transferred by'], ['deploys', 'deploys', 'deployed_by', 'deployed by'], ['site', 'site', 'serves', 'serves'],
];
const ROLES = new Map(ROLE_PAIRS.flatMap(([a, aw, b, bw]) => [[a, { words: aw, inverse: b }], [b, { words: bw, inverse: a }]]));

// roleWords is how a role reads - from the subject toward the related
// entity, or (inverse) from the related entity back; a role this app does
// not know reads as itself.
export function roleWords(role, inverse = false) {
  const r = ROLES.get(role);
  if (!r) return role;
  return inverse ? ROLES.get(r.inverse).words : r.words;
}

// entityLink opens an entity's page on a host: its type's icon and name.
export function entityLink(e, host, text = e.display) {
  return pageLink('signals', { entity: e.id || `${e.type}:${e.key}`, host }, h('span', { class: 'entity-link' }, svgIcon(entityIcon(e.type)), text));
}

// factShown shows a fact by its kind: a time, a hash (opens VirusTotal), a
// path, or text - with its tone as a colored pill.
function factShown(f) {
  const v = f.kind === 'time' ? ts(f.value) : ['sha256', 'sha1', 'md5'].includes(f.kind) ? virusTotalLink(f.kind.toUpperCase(), f.value) : f.kind === 'path' ? mono(f.value) : f.value;
  return f.tone ? h('span', { class: 'sig-pill ' + f.tone }, v) : h('span', {}, v);
}

// vtItems is what VirusTotal is asked about an entity (src/virustotal.js
// itemsOf): its SHA-256 hashes, a public address, a domain.
function vtItems(facts) {
  const out = facts.facts.filter((f) => /sha-256/i.test(f.label) && /^[0-9a-f]{64}$/i.test(f.value)).map((f) => ['file', f.value.toLowerCase()]);
  if (facts.type === 'address' && facts.facts.some((f) => f.label === 'Scope' && f.value === 'public')) out.push(['ip', facts.key]);
  if (facts.type === 'domain') out.push(['domain', String(facts.key).toLowerCase()]);
  return out;
}

// vtVerdict is VirusTotal's answer for one item, filled in when it arrives:
// the engines' verdicts with the lookup's date, "waiting for VirusTotal"
// while it is queued, or nothing when the lookups are off. The items a page
// asks for are fetched together.
const vtAsked = new Map();
let vtTimer = 0;
function vtVerdict(kind, value) {
  const el = h('span', { class: 'vt-tag mut' }, '…');
  vtAsked.set(`${kind}:${value}`, [...(vtAsked.get(`${kind}:${value}`) || []), el]);
  clearTimeout(vtTimer);
  vtTimer = setTimeout(async () => {
    const asked = new Map(vtAsked);
    vtAsked.clear();
    const answers = await fetchJSON(`/api/virustotal?items=${encodeURIComponent([...asked.keys()].join(','))}`).catch(() => []);
    for (const a of answers) for (const node of asked.get(`${a.kind}:${a.value}`) || []) vtFill(node, a);
  }, 0);
  return el;
}

function vtFill(el, a) {
  if (a.state === 'off') return el.closest('.sig-side-row')?.remove();
  if (a.state === 'queued') return el.replaceChildren('waiting for VirusTotal (queued)');
  if (a.state === 'not_found') return el.replaceChildren(`not known to VirusTotal (${ts(a.looked_up)})`);
  const bad = a.malicious + a.suspicious;
  el.className = 'vt-tag';
  el.replaceChildren(h('span', { class: bad ? 'sev-high' : 'result-ok' }, `${a.malicious} malicious, ${a.suspicious} suspicious`),
    ` of ${a.malicious + a.suspicious + a.harmless + a.undetected} engines`, a.detail ? ` · ${a.detail}` : '', h('span', { class: 'mut' }, ` (looked up ${ts(a.looked_up)})`));
}

// factsCard is what Signal read about an entity at collection (Signal
// schema 28): one row per fact, where it was read on hover, and what could
// not be read - the same card for an entity of any type, on every page.
// head is the card's title (a link to the entity's page, or text).
export function factsCard(head, icon, facts) {
  const rows = facts ? facts.facts.map((f) => h('div', { class: 'sig-side-row' }, withTip(h('span', { class: 'mut' }, f.label), `Read from ${f.source}`), factShown(f))) : [];
  if (facts) rows.push(...vtItems(facts).map(([kind, value]) => h('div', { class: 'sig-side-row' }, withTip(h('span', { class: 'mut' }, 'VirusTotal says'), `VirusTotal's answer for ${value} - not Signal's finding`), vtVerdict(kind, value))));
  const gaps = facts && facts.gaps.length ? h('div', { class: 'mut sig-small' }, 'Not determined: ' + facts.gaps.map((g) => `${g.item} (${g.reason})`).join('; ')) : null;
  const none = !facts ? h('div', { class: 'mut' }, 'Nothing read about it: Signal reads no facts of this type, or the collection is older than Signal 0.33.0.')
    : !rows.length && !gaps ? h('div', { class: 'mut' }, 'Nothing more is known about it.') : null;
  return h('div', { class: 'sig-side-card' }, h('div', { class: 'sig-side-title' }, svgIcon(icon), head), ...rows, gaps, none);
}

// MAX_MARKS is how many marks a lane draws one by one; past it they become
// TIMELINE_BINS bars of their density - every occurrence still counted,
// and listed on its signal's page.
const MAX_MARKS = 400;
const TIMELINE_BINS = 120;

// occurrenceTimeline draws signals on one time axis, a lane each: every
// occurrence a mark at its time (a time range, a bar), colored by the
// signal's severity, a lane no longer open faded. lanes: [{label (node),
// severity, open, times: [{time, time_from}], ranged}] - ranged: only the
// first and last are known, drawn as one bar between them.
export function occurrenceTimeline(lanes) {
  const ms = (t) => Date.parse(t);
  const all = lanes.flatMap((l) => l.times.flatMap((t) => [t.time, t.time_from].filter(Boolean).map(ms))).filter((x) => !Number.isNaN(x));
  if (!all.length) return null;
  const lo = Math.min(...all);
  const span = Math.max(...all) - lo;
  const pct = (t) => (span ? ((ms(t) - lo) / span) * 100 : 50);
  const bar = (cls, from, to, title) => h('i', { class: cls + ' tl-range', style: `left:${pct(from)}%;width:${Math.max(pct(to) - pct(from), 0.6)}%`, title });
  const track = (l) => {
    const cls = 'tl-mark sev-' + l.severity;
    if (l.ranged) return [bar(cls, l.times[0].time, l.times[1].time, `between ${ts(l.times[0].time)} and ${ts(l.times[1].time)}`)];
    if (l.times.length > MAX_MARKS) {
      const bins = new Array(TIMELINE_BINS).fill(0);
      for (const t of l.times) bins[Math.min(TIMELINE_BINS - 1, Math.floor((pct(t.time) / 100) * TIMELINE_BINS))]++;
      const top = Math.max(...bins);
      return bins.map((n, i) => (n ? h('i', { class: cls + ' tl-bin', style: `left:${(i / TIMELINE_BINS) * 100}%;width:${100 / TIMELINE_BINS}%;height:${Math.max(15, (n / top) * 100)}%`, title: `${n} occurrences` }) : null));
    }
    return l.times.map((t) => (t.time_from ? bar(cls, t.time_from, t.time, `between ${ts(t.time_from)} and ${ts(t.time)}`) : h('i', { class: cls, style: `left:${pct(t.time)}%`, title: ts(t.time) })));
  };
  // The axis: the first and last time and the middle one; within one day
  // the date is written once, on the first.
  const oneDay = ts(new Date(lo).toISOString()).slice(0, 10) === ts(new Date(lo + span).toISOString()).slice(0, 10);
  const ticks = (span ? [0, 0.5, 1] : [0]).map((f, i) => {
    const t = ts(new Date(lo + f * span).toISOString());
    return h('span', { class: 'tl-tick', style: `left:${f * 100}%` }, oneDay && i ? t.slice(11) : t);
  });
  return h('div', { class: 'tl' },
    lanes.map((l) => h('div', { class: 'tl-lane' + (l.open === false ? ' tl-faded' : '') },
      h('div', { class: 'tl-label' }, h('i', { class: 'tl-dot sev-' + l.severity }), l.label), h('div', { class: 'tl-track' }, track(l)))),
    h('div', { class: 'tl-axis' + (span ? '' : ' one') }, ticks));
}

// TRIAGE_CHOICES are the decisions an analyst records: open (stored as
// "new"), benign or escalated.
export const TRIAGE_CHOICES = ['new', 'benign', 'escalated'];

// noteText is a triage note with a little markdown, built as DOM (never
// HTML): **bold**, *italic*, `code`, lines starting "- " as a list, and
// line breaks kept.
export function noteText(text) {
  const inline = (line) => line.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/).filter(Boolean).map((part) => (
    /^\*\*.+\*\*$/.test(part) ? h('strong', {}, part.slice(2, -2)) : /^\*.+\*$/.test(part) ? h('em', {}, part.slice(1, -1)) : /^`.+`$/.test(part) ? h('code', {}, part.slice(1, -1)) : part));
  const out = [];
  let list = null;
  for (const line of String(text || '').split('\n')) {
    if (/^\s*[-*] /.test(line)) {
      if (!list) out.push(list = h('ul', {}));
      list.append(h('li', {}, ...inline(line.replace(/^\s*[-*] /, ''))));
    } else {
      list = null;
      out.push(h('div', {}, ...(line ? inline(line) : [' '])));
    }
  }
  return h('div', { class: 'md-note' }, ...out);
}

// triageBlock is a decision - an entity's, covering its signals, or a
// signal's own: what it applies to (scope), the state chosen, a note
// saying why (required; a little markdown, with a preview), and Save
// (or Ctrl+Enter), which alone records it (save(state, note, sids)) - and
// its history (history()): when, by whom, and for a signal decided apart,
// its rule. With signals [{sid, rule_id, title, triage}] given, the
// analyst decides all of them or chooses which (sids: null for all). t is
// the current decision {state, note, at, by}; refresh() redraws the page.
// A read-only account sees the decision and its history, nothing to change.
export function triageBlock(t, { save, history, scope, signals }, refresh) {
  const status = h('span', { class: 'mut' }, t.at ? `last decided ${ts(t.at)}${t.by ? ` by ${t.by}` : ''}${t.mixed ? ' - its signals are decided differently, see each one\'s tag' : ''}` : '');
  const historyBox = h('div', { class: 'triage-history' });
  history().then((changes) => historyBox.replaceChildren(...(changes.length ? [h('div', { class: 'mut' }, 'History:'), ...changes.slice().reverse().map((c) =>
    h('div', { class: 'triage-change' }, h('div', { class: 'mut' }, `${ts(c.at)}${c.by ? ` — ${c.by}` : ''} — `, triageTag(c.state),
      c.signal ? h('span', {}, ' — signal ', h('span', { class: 'mono' }, c.signal)) : c.covers_n != null ? ` — ${c.covers_n} signal${c.covers_n === 1 ? '' : 's'}` : ''),
    c.note ? noteText(c.note) : null))] : [])));
  const current = t.note ? noteText(t.note) : null;
  if (!canEdit()) return detailBlock('Triage', scope, h('div', {}, triageTag(t.state), ' ', status), current, historyBox);
  let chosen = t.state;
  const note = h('textarea', { class: 'note', rows: '3', placeholder: 'Why: what you found, why you decided so (required). **bold**, *italic*, `code`, "- " for a list' });
  note.value = t.note || '';
  note.onclick = (e) => e.stopPropagation();
  note.onkeydown = (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); doSave(); } };
  const preview = h('div', { class: 'md-preview', hidden: true });
  const previewBtn = h('button', { class: 'ghost', title: 'See the note as it will read' }, 'Preview');
  previewBtn.onclick = (e) => {
    e.stopPropagation();
    preview.hidden = !preview.hidden;
    previewBtn.textContent = preview.hidden ? 'Preview' : 'Edit';
    note.hidden = !preview.hidden;
    preview.replaceChildren(noteText(note.value));
  };
  const chips = h('div', { class: 'row' });
  const drawChips = () => chips.replaceChildren(...TRIAGE_CHOICES.map((state) =>
    h('button', { class: 'chip' + (chosen === state ? ' on' : ''), onclick: (e) => { e.stopPropagation(); chosen = state; drawChips(); } }, TRIAGE[state].label)));
  drawChips();
  // Applies to: every signal, or those ticked.
  let picks = null;
  let applies = null;
  if (signals && signals.length > 1) {
    const all = h('input', { type: 'checkbox', checked: 'checked' });
    picks = signals.map((x) => ({ sid: x.sid, box: h('input', { type: 'checkbox', checked: 'checked' }), x }));
    const sync = () => { all.checked = picks.every((p) => p.box.checked); all.indeterminate = !all.checked && picks.some((p) => p.box.checked); };
    all.onchange = () => { for (const p of picks) p.box.checked = all.checked; sync(); };
    for (const p of picks) p.box.onchange = sync;
    applies = h('div', { class: 'triage-applies' }, h('div', { class: 'mut' }, 'Applies to:'),
      h('label', { class: 'triage-pick all' }, all, ` all ${signals.length} signals`),
      ...picks.map((p) => h('label', { class: 'triage-pick' }, p.box, ' ', sevTag(p.x.severity), ' ', h('span', { class: 'mono' }, p.x.rule_id), ' ', h('span', { class: 'mut' }, p.x.title), ' ', triageTag(p.x.triage))));
  }
  async function doSave() {
    if (!note.value.trim()) {
      status.textContent = 'Write a note saying why before saving.';
      return;
    }
    const sids = picks && !picks.every((p) => p.box.checked) ? picks.filter((p) => p.box.checked).map((p) => p.sid) : null;
    if (sids && !sids.length) {
      status.textContent = 'Tick at least one signal it applies to.';
      return;
    }
    try {
      await save(chosen, note.value, sids);
      refresh();
    } catch (err) {
      status.textContent = `could not save: ${err.message}`;
    }
  }
  return detailBlock('Triage', scope, applies, chips, note, preview,
    h('div', { class: 'row' }, h('button', { class: 'btn', title: 'Save (Ctrl+Enter)', onclick: (e) => { e.stopPropagation(); doSave(); } }, 'Save'), previewBtn, status), historyBox);
}

// entityTriage is the save and history of an entity's triage on a host
// (its collection's run ID), for triageBlock.
export function entityTriage(id, host) {
  return {
    // sids: the signals chosen, each decided apart - null: the entity as a whole.
    save: (state, note, sids) => (sids
      ? Promise.all(sids.map((sid) => fetchJSON(`/api/signals/${encodeURIComponent(sid)}/triage`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ state, note }) })))
      : fetchJSON('/api/entities/triage', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id, host, state, note }) })),
    history: () => fetchJSON(`/api/entities/history?id=${encodeURIComponent(id)}&host=${encodeURIComponent(host)}`),
  };
}

// copyButton copies text to the clipboard; where the browser refuses
// (no permission, not a secure page), it shows the text to select instead.
// title says what it copies.
export function copyButton(label, text, title) {
  const btn = h('button', { class: 'ghost', title }, label);
  btn.onclick = async () => {
    try {
      await window.navigator.clipboard.writeText(text());
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = label; }, 1500);
    } catch {
      const area = h('textarea', { class: 'note', rows: '8', readonly: 'readonly' });
      area.value = text();
      btn.replaceWith(area);
      area.select();
    }
  };
  return btn;
}
