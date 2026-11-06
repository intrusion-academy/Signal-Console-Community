// The Timeline page: every signal of the hosts' latest collections on one
// time rail (signals.js timeRail, as on an entity's page) - each its start,
// a dot of its severity, the time that passed since the one before, a row
// with its title, host, entity, rule, matches and triage, none of its data;
// a row opens it on its entity's page. Days are headed with their date and
// count. To read and narrow it: a sticky filter bar (Host, Severity,
// Module, Tags, Show, Found at collection, Order - oldest or newest first,
// a search, Go to date) kept in the URL, and a summary strip (signals,
// hosts, the span they cover, the busiest day - Busiest day goes to it).
//
// The analyst's part (src/timeline.js): tags on every item, filtered by
// Tags (several at once), and events added by hand - at the time the
// analyst gives, in their own colour, marked "added manually" and by whom.
//
// Every time on the rail says what it is (Signal's time_is: "event
// logged", "process started"). A state observed as Signal read the host
// (as_of) stands at its anchor - the best time Windows recorded about it,
// named ("registry key last written") - when it has one; with none, its
// time is only the collection's, so by default each host's are one folded
// block at its collection time, saying so (Found at collection).
import { h, fetchJSON, ts } from '../dom.js';
import { urlParams, setParams, pageUrl, linkMode, linkClick, rememberState, rememberedState } from '../router.js';
import {
  SEVERITY_RANK, ENTITY_TYPES, sevTag, triageTag, filterBar, stickyPage, summaryStrip, checkboxDropdown, selectionFromUrl, section, CORE, quotedTitle,
} from '../components.js';
import { canEdit } from '../session.js';
import { timeRail, startOf } from './signals.js';

const closed = (s) => s.suppressed || s.triage === 'benign';
const MANUAL = 'Added manually'; // a manual event's module, in the Modules filter
const NO_TAG = '(no tag)';
const NO_HOST = '(no host)';
// A large fleet opens on its DEFAULT_HOSTS riskiest hosts, and the rail
// draws at most RAIL_LIMIT rows without asking (the user, 2026-11-04: the
// page must not break at 1,000 hosts). MAX_IN_URL: more chosen hosts than
// this and every signal is asked for, filtered here (the address's length).
const DEFAULT_HOSTS = 20, RAIL_LIMIT = 2000, MAX_IN_URL = 200;
const keyOf = (s) => s.key || s.sid;
const json = (method, body) => ({ method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

// row is one signal on the rail, a link to it on its entity's page (from=
// timeline: that page offers the way back). Opening it keeps the Timeline's
// address and the signal, so coming back scrolls to it (main.js scrolls to
// the .focus-row).
const row = (s) => h('a', {
  class: `ent-sig sev-edge-${s.severity} rail-row${closed(s) ? ' closed' : ''}${(rememberedState('timeline') || {}).sid === s.sid ? ' focus-row' : ''}`,
  href: pageUrl('signals', { entity: s.entity_id, host: s.run_id, signal: s.sid, from: 'timeline' }),
  target: linkMode() === 'same' ? null : '_blank', title: 'Open it on its entity\'s page',
  onclick: (e) => { rememberState('timeline', { url: location.pathname + location.search, sid: s.sid }); linkClick(e, e.currentTarget.getAttribute('href')); },
}, h('div', { class: 'ent-sig-head' }, h('span'), sevTag(s.severity),
  h('div', { class: 'ent-sig-main' }, h('span', { class: 'ent-sig-title' }, quotedTitle(s.title)),
    h('div', { class: 'ent-sig-what' }, h('span', { class: 'mono' }, s.host), ' · ', `${s.entity_type}: `, h('span', { class: 'mono' }, s.entity_display))),
  h('div', { class: 'ent-sig-meta' }, h('span', { class: 'mut mono ent-sig-rule' }, s.rule_id),
    h('span', { class: 'mut ent-sig-n' }, s.count > 1 ? `${s.count.toLocaleString()} matches, last ${ts(s.last)}` : '1 match')),
  h('span', { class: 'ent-sig-tri' }, s.suppressed ? h('span', { class: 'mut' }, 'suppressed') : triageTag(s.triage))));

// goToDay scrolls to the first day on the rail at or after d (in the
// rail's order, the first one on or before it when newest first).
function goToDay(box, d, desc) {
  const heads = [...box.querySelectorAll('.rail-day')];
  const head = heads.find((x) => (desc ? x.dataset.day <= d : x.dataset.day >= d)) || heads[heads.length - 1];
  if (!head) return;
  head.scrollIntoView({ behavior: 'smooth', block: 'start' });
  head.classList.add('flash');
  setTimeout(() => head.classList.remove('flash'), 1600);
}

// asEvent is a manual event as a rail item.
const asEvent = (e) => ({
  ...e, manual: true, first: e.time, first_seen: e.time, last: e.time, time_is: 'given by the analyst', time_from: '', module: MANUAL, entity_display: e.entity_name, count: 1,
});

export async function renderTimelinePage(container) {
  const q = urlParams();
  const runs = (await fetchJSON('/api/runs')).filter((r) => r.latest);
  let mine = await fetchJSON('/api/timeline');
  // The Hosts filter is kept as run IDs, like every page's (router.js
  // rememberedHosts); the rail lists hosts by name. Every host is a choice,
  // whether its signals are loaded or not.
  const nameOf = new Map(runs.map((r) => [r.run_id, r.host]));
  const idsOf = (name) => [...nameOf].filter(([, n]) => n === name).map(([id]) => id);
  const hostChoices = () => [...new Set([...runs.map((r) => r.host), ...mine.events.map((e) => e.host || NO_HOST)])].sort();
  const riskiest = runs.length > DEFAULT_HOSTS
    ? runs.slice().sort((a, b) => (b.risk || 0) - (a.risk || 0) || String(a.host).localeCompare(String(b.host))).slice(0, DEFAULT_HOSTS).map((r) => r.host)
    : null;
  // By default the riskiest hosts' signals, and every manual event not
  // about another imported host.
  const byRisk = riskiest && hostChoices().filter((n) => riskiest.includes(n) || !idsOf(n).length);
  const firstHosts = selectionFromUrl('hosts', hostChoices(), (v) => nameOf.get(v) || v, byRisk || hostChoices());
  // signals are the chosen hosts' only: fetched again when Hosts changes.
  let signals = [], generation = 0;
  async function loadSignals(names) {
    const mineGen = ++generation;
    const ids = [...names].flatMap(idsOf);
    const some = ids.length < runs.length && ids.length <= MAX_IN_URL;
    const got = await fetchJSON('/api/dashboards/timeline' + (some ? `?hosts=${encodeURIComponent(ids.join(','))}` : ''));
    if (mineGen !== generation) return false;
    signals = got.map((s) => ({ ...s, first_seen: s.first, time: s.last, unplaced: s.as_of && !s.anchor })).filter(startOf);
    return true;
  }
  await loadSignals(firstHosts);
  const editable = canEdit();
  const rowsNow = () => [...signals, ...mine.events.map(asEvent)];
  const tagsOf = (s) => mine.tags[keyOf(s)] || [];
  const tagOptions = () => [...new Set(Object.values(mine.tags).flat())].sort().concat(NO_TAG);
  const hostOf = (s) => s.host || NO_HOST;
  const optionsNow = () => ({
    hosts: hostChoices(),
    severities: Object.keys(SEVERITY_RANK),
    modules: [...new Set(rowsNow().map((s) => s.module))].sort(),
    tags: tagOptions(),
  });
  let options = optionsNow();
  const sel = {
    hosts: firstHosts,
    severities: selectionFromUrl('severity', options.severities),
    modules: selectionFromUrl('modules', options.modules),
    tags: selectionFromUrl('tags', options.tags),
    show: q.get('show') === 'all' ? 'all' : 'open',
    atrun: ['rail', 'hide'].includes(q.get('atrun')) ? q.get('atrun') : 'group',
    order: q.get('order') === 'newest' ? 'newest' : 'oldest',
    text: q.get('q') || '',
  };
  const every = (key) => sel[key].size === options[key].length;
  // The riskiest-hosts default is not a choice: it stays out of the URL, so
  // it is not remembered for the other pages.
  const byDefault = () => byRisk && sel.hosts.size === byRisk.length && byRisk.every((n) => sel.hosts.has(n));
  let allRows = false, cut = false; // allRows: the analyst chose to draw every row - until the next filter change
  const syncUrl = () => {
    allRows = false;
    setParams({
      hosts: every('hosts') || byDefault() ? null : [...sel.hosts].flatMap((n) => (idsOf(n).length ? idsOf(n) : [n])), severity: every('severities') ? null : [...sel.severities], modules: every('modules') ? null : [...sel.modules],
      tags: every('tags') ? null : [...sel.tags], show: sel.show === 'all' ? 'all' : null, atrun: sel.atrun === 'group' ? null : sel.atrun,
      order: sel.order === 'newest' ? 'newest' : null, q: sel.text || null,
    });
  };
  const pick = (key) => (s) => {
    sel[key] = s.size ? s : new Set(options[key]);
    syncUrl();
    if (key !== 'hosts') return draw();
    // Other hosts' signals are fetched; the Modules and Tags choices follow
    // them (a filter that chose everything still does).
    const all = { modules: every('modules'), tags: every('tags') };
    loadSignals(sel.hosts).then((fresh) => {
      if (!fresh) return;
      options = optionsNow();
      for (const k of ['modules', 'tags']) {
        sel[k] = all[k] ? new Set(options[k]) : new Set([...sel[k]].filter((x) => options[k].includes(x)));
        if (!sel[k].size) sel[k] = new Set(options[k]);
        slots[k].replaceChildren(checkboxDropdown(options[k], pick(k), [...sel[k]]).el);
      }
      draw();
    });
  };
  const choose = (key, list) => h('select', { onchange: (e) => { sel[key] = e.target.value; syncUrl(); draw(); } },
    list.map(([v, t]) => h('option', { value: v, selected: v === sel[key] ? 'selected' : null }, t)));
  const search = h('input', { type: 'search', placeholder: 'Host, entity, rule, title or tag', value: sel.text });
  search.oninput = () => { sel.text = search.value.trim(); syncUrl(); draw(); };
  const dateBox = h('input', { type: 'date', class: 'date-box', title: 'Go to the first item of this day (UTC)' });
  const railBox = h('div', { class: 'rail-panel' });
  const busiestBtn = h('button', { class: 'ghost', title: 'Go to the day the most signals began' }, 'Busiest day');
  // Going to a day draws every row first when the rail was cut short.
  const goDay = (d) => {
    if (cut) { allRows = true; draw(); }
    goToDay(railBox, d, sel.order === 'newest');
  };
  dateBox.onchange = () => { if (dateBox.value) goDay(dateBox.value); };
  const dropdownSlot = (key) => h('span', {}, checkboxDropdown(options[key], pick(key), [...sel[key]]).el);
  const slots = { hosts: dropdownSlot('hosts'), modules: dropdownSlot('modules'), tags: dropdownSlot('tags') };
  const formBox = h('div');
  const addBtn = editable ? h('button', { class: 'tl-add-btn', title: 'Add an event to the timeline by hand', onclick: () => openForm() }, '+ Add event') : null;
  const bar = filterBar([
    ['Host', slots.hosts],
    ['Severity', checkboxDropdown(options.severities, pick('severities'), [...sel.severities]).el],
    ['Modules', slots.modules],
    ['Tags', slots.tags],
    ['Show', choose('show', [['open', 'open and escalated'], ['all', 'every signal, benign and suppressed too']])],
    ['Found at collection', choose('atrun', [['group', 'one block per host, at its collection'], ['rail', 'on the rail, at the collection time'], ['hide', 'hidden']])],
    ['Order', choose('order', [['oldest', 'oldest first'], ['newest', 'newest first']])],
    ['Search', search],
    ['Go to', h('span', { class: 'row' }, dateBox, busiestBtn)],
    ...(addBtn ? [['', addBtn]] : []),
  ]);
  const summaryBox = h('div');
  const tagList = h('datalist', { id: 'tl-tag-list' });

  // refresh takes the server's answer after a change: the options follow
  // (a filter that chose everything still does), and the rail is drawn again.
  function refresh(answer) {
    const all = Object.fromEntries(Object.keys(slots).map((k) => [k, every(k)]));
    mine = answer;
    options = optionsNow();
    for (const k of Object.keys(slots)) {
      sel[k] = all[k] ? new Set(options[k]) : new Set([...sel[k]].filter((x) => options[k].includes(x)));
      if (!sel[k].size) sel[k] = new Set(options[k]);
      slots[k].replaceChildren(checkboxDropdown(options[k], pick(k), [...sel[k]]).el);
    }
    syncUrl();
    draw();
  }

  // tagsLine is an item's tags, each removable, and "+ tag" to add one
  // (suggesting the tags already used) - for an analyst; a viewer sees the tags.
  function tagsLine(s) {
    const key = keyOf(s);
    const tags = tagsOf(s);
    const save = (next) => fetchJSON('/api/timeline/tags', json('PUT', { item: key, tags: next })).then(refresh).catch((err) => window.alert(err.message));
    const line = h('div', { class: 'tl-tags' }, tags.map((t) => h('span', { class: 'tl-tag' }, t,
      editable ? h('button', { class: 'tl-tag-x', title: `Remove the tag ${t}`, onclick: () => save(tags.filter((x) => x !== t)) }, '×') : null)));
    if (!editable) return tags.length ? line : null;
    const add = h('button', { class: 'tl-tag-add', title: 'Tag it - Enter to add, Esc to cancel' }, '+ tag');
    add.onclick = () => {
      const input = h('input', { type: 'text', class: 'tl-tag-input', list: 'tl-tag-list', placeholder: 'tag', maxlength: '40' });
      input.onkeydown = (e) => {
        if (e.key === 'Escape') input.replaceWith(add);
        if (e.key === 'Enter' && input.value.trim()) save([...tags, input.value.trim()]);
      };
      input.onblur = () => { if (input.isConnected) input.replaceWith(add); };
      add.replaceWith(input);
      input.focus();
    };
    line.append(add);
    return line;
  }

  // manualRow is an event added by hand: its own colour, "added manually",
  // by whom, and - for an analyst - Edit and Remove.
  const manualRow = (e) => h('div', { class: `ent-sig rail-manual sev-edge-${e.severity}` },
    h('div', { class: 'ent-sig-head' }, h('span'), sevTag(e.severity),
      h('div', { class: 'ent-sig-main' }, h('span', { class: 'ent-sig-title' }, quotedTitle(e.title)),
        e.host || e.entity_name ? h('div', { class: 'ent-sig-what' }, e.host ? h('span', { class: 'mono' }, e.host) : null, e.host && e.entity_name ? ' · ' : '',
          e.entity_name ? [`${e.entity_type || 'entity'}: `, h('span', { class: 'mono' }, e.entity_name)] : null) : null,
        e.description ? h('div', { class: 'tl-desc' }, e.description) : null),
      h('div', { class: 'ent-sig-meta' }, h('span', { class: 'tl-manual-tag' }, 'added manually'),
        h('span', { class: 'mut ent-sig-n', title: `Added ${ts(e.at)}` }, `by ${e.added_by}`)),
      h('span', { class: 'ent-sig-tri' }, editable ? [
        h('button', { class: 'ghost', title: 'Edit this event', onclick: () => openForm(e) }, 'Edit'),
        h('button', { class: 'ghost', title: 'Remove this event', onclick: () => window.confirm(`Remove "${e.title}" from the timeline?`)
          && fetchJSON(`/api/timeline/events/${e.id}`, { method: 'DELETE' }).then(refresh).catch((err) => window.alert(err.message)) }, 'Remove'),
      ] : null)),
    tagsLine(e));

  // collectionBlock is a host's signals found as they were when Signal
  // ran - folded, at its collection time, saying they have no time of their own.
  const collectionBlock = (b) => h('details', { class: `ent-sig rail-collection sev-edge-${b.severity}` },
    h('summary', {}, h('span', { class: 'ent-sig-title' }, `${b.items.length} signal${b.items.length === 1 ? '' : 's'} found as they were when Signal ran on `, h('span', { class: 'mono' }, b.host)),
      h('div', { class: 'mut sig-small' }, 'States observed as Signal read the host, with no time Windows recorded to place them by: their time is the collection\'s, not when they happened.')),
    h('div', { class: 'rail-collection-list' }, b.items.map(itemOf)));

  const itemOf = (s) => (s.manual ? manualRow(s) : s.block ? collectionBlock(s) : h('div', { class: 'tl-item' }, row(s), tagsLine(s)));

  // openForm opens the event form - empty, or an event to edit. Its time is
  // UTC, like every time here; it takes its place on the rail by it.
  function openForm(e = null) {
    const now = new Date().toISOString().slice(0, 19);
    const f = {
      time: h('input', { type: 'datetime-local', step: '1', value: e ? e.time.slice(0, 19) : (dateBox.value ? `${dateBox.value}T00:00:00` : now), required: 'required' }),
      severity: h('select', {}, Object.keys(SEVERITY_RANK).map((v) => h('option', { value: v, selected: (e ? e.severity : 'medium') === v ? 'selected' : null }, v))),
      title: h('input', { type: 'text', maxlength: '300', placeholder: 'What happened', value: e ? e.title : '' }),
      description: h('textarea', { rows: '3', maxlength: '4000', placeholder: 'Details, the source of what you know (optional)' }, e ? e.description : ''),
      host: h('input', { type: 'text', list: 'tl-host-list', maxlength: '200', placeholder: 'optional', value: e ? e.host : '' }),
      entity_type: h('select', {}, ['', ...ENTITY_TYPES].map((v) => h('option', { value: v, selected: (e ? e.entity_type : '') === v ? 'selected' : null }, v || '(none)'))),
      entity_name: h('input', { type: 'text', maxlength: '500', placeholder: 'optional', value: e ? e.entity_name : '' }),
    };
    const err = h('div', { class: 'tl-form-err' });
    const close = () => formBox.replaceChildren();
    const submit = () => {
      if (!f.time.value || !f.title.value.trim()) { err.textContent = 'An event needs its time and a title.'; return; }
      const body = Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value]));
      body.time = `${f.time.value.length === 16 ? `${f.time.value}:00` : f.time.value}Z`;
      fetchJSON(e ? `/api/timeline/events/${e.id}` : '/api/timeline/events', json(e ? 'PUT' : 'POST', body)).then((a) => { close(); refresh(a); }).catch((x) => { err.textContent = x.message; });
    };
    const field = (label, el, wide) => h('label', { class: `tl-field${wide ? ' wide' : ''}` }, h('span', {}, label), el);
    formBox.replaceChildren(h('div', { class: 'card tl-form' },
      h('h2', { class: 'card-head' }, h('span', { class: 'tl-manual-tag' }, 'added manually'), e ? 'Edit the event' : 'Add an event to the timeline'),
      h('div', { class: 'tl-form-grid' },
        field('Time (UTC)', f.time), field('Severity', f.severity), field('Title', f.title, true), field('Description', f.description, true),
        field('Host', f.host), field('Entity type', f.entity_type), field('Entity name', f.entity_name)),
      h('datalist', { id: 'tl-host-list' }, options.hosts.filter((x) => x !== NO_HOST).map((x) => h('option', { value: x }))),
      err,
      h('div', { class: 'row' }, h('button', { class: 'tl-add-btn', onclick: submit }, e ? 'Save' : 'Add to the timeline'), h('button', { class: 'ghost', onclick: close }, 'Cancel'))));
    f.title.onkeydown = (x) => { if (x.key === 'Enter') submit(); };
    f.title.focus();
    formBox.scrollIntoView({ block: 'nearest' });
  }

  function draw() {
    tagList.replaceChildren(...options.tags.filter((t) => t !== NO_TAG).map((t) => h('option', { value: t })));
    const text = sel.text.toLowerCase();
    const wantTag = (s) => every('tags') || (tagsOf(s).length ? tagsOf(s).some((t) => sel.tags.has(t)) : sel.tags.has(NO_TAG));
    let list = rowsNow().filter((s) => sel.hosts.has(hostOf(s)) && sel.severities.has(s.severity) && sel.modules.has(s.module) && (sel.show === 'all' || !closed(s))
      && wantTag(s) && !(s.unplaced && sel.atrun === 'hide')
      && (!text || `${s.host} ${s.entity_display} ${s.rule_id || ''} ${s.title} ${s.description || ''} ${tagsOf(s).join(' ')}`.toLowerCase().includes(text)));
    const shown = list;
    if (sel.atrun === 'group') {
      const blocks = new Map();
      for (const s of list.filter((x) => x.unplaced)) {
        const b = blocks.get(s.run_id) || { block: true, key: `run:${s.run_id}`, host: s.host, first: s.collected || startOf(s), items: [], severity: s.severity };
        b.first_seen = b.first; b.time = b.first; b.time_is = 'the collection (when Signal ran)';
        b.items.push(s);
        if ((SEVERITY_RANK[s.severity] ?? 9) < (SEVERITY_RANK[b.severity] ?? 9)) b.severity = s.severity;
        blocks.set(s.run_id, b);
      }
      for (const b of blocks.values()) b.items.sort((x, y) => (SEVERITY_RANK[x.severity] ?? 9) - (SEVERITY_RANK[y.severity] ?? 9));
      list = [...list.filter((x) => !x.unplaced), ...blocks.values()];
    }
    list.sort((a, b) => String(startOf(a)).localeCompare(String(startOf(b))) || (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
    if (sel.order === 'newest') list.reverse();
    const days = new Map();
    for (const s of shown.filter((x) => !x.manual && !x.unplaced)) { const d = ts(startOf(s)).slice(0, 10); days.set(d, (days.get(d) || 0) + 1); }
    const busiest = [...days].sort((a, b) => b[1] - a[1])[0];
    const times = list.map(startOf).sort();
    const manualN = shown.filter((s) => s.manual).length;
    const stateN = shown.filter((s) => s.unplaced).length;
    summaryBox.replaceChildren(summaryStrip([
      { icon: 'signals', value: shown.length - manualN, label: 'signals' },
      ...(stateN ? [{ icon: 'eye', value: stateN, label: 'of them found at collection, no recorded time to place them by' }] : []),
      ...(manualN ? [{ icon: 'edit', value: manualN, label: 'added manually', cls: 'tl-manual-count' }] : []),
      { icon: 'hosts', value: new Set(shown.filter((s) => s.host).map((s) => s.host)).size, label: 'hosts' },
      { icon: 'clock', value: new Set(times.map((t) => ts(t).slice(0, 10))).size, label: `days${times.length ? `, ${ts(times[0]).slice(0, 10)} → ${ts(times[times.length - 1]).slice(0, 10)}` : ''}` },
      ...(busiest ? [{ icon: 'firstSeen', value: busiest[1], label: `on the busiest day, ${busiest[0]}` }] : []),
    ], [...new Set(shown.filter((s) => !s.manual).map((s) => s.module))].sort()));
    busiestBtn.disabled = !busiest;
    busiestBtn.onclick = () => busiest && goDay(busiest[0]);
    cut = !allRows && list.length > RAIL_LIMIT;
    const note = [
      byDefault()
        ? h('div', { class: 'mut sig-small' }, `Showing the ${riskiest.length} riskiest of ${runs.length.toLocaleString()} hosts (by open signals' risk) - choose others with Host.`) : null,
      cut ? h('div', { class: 'card' }, h('b', {}, `The first ${RAIL_LIMIT.toLocaleString()} of ${list.length.toLocaleString()} rows are drawn`),
        ` (${sel.order === 'newest' ? 'newest' : 'oldest'} first). Drawing every row stops the page answering while it draws - about a second for each 1,000 rows on a test machine. Fewer hosts or a search narrow it. `,
        h('button', { class: 'ghost', onclick: () => { allRows = true; draw(); } }, `Draw all ${list.length.toLocaleString()}`)) : null,
    ];
    railBox.replaceChildren(...note.filter(Boolean), list.length
      ? timeRail(cut ? list.slice(0, RAIL_LIMIT) : list, itemOf, { days: true })
      : h('div', { class: 'mut' }, rowsNow().length ? 'Nothing matches the filters.' : 'No signals yet - import a Signal run first.'));
  }

  stickyPage(container, bar);
  container.replaceChildren(bar, summaryBox, formBox, tagList,
    section('Timeline — every signal of the hosts\' latest collections, in the order they began', () => h('div', {},
      h('div', { class: 'mut sig-small' }, 'When each began (UTC), the time that passed between two - rounded when long, more space for days and months - and each day\'s count. A row opens the signal on its entity\'s page. Under each time, what it is. A state observed as Signal read the host stands at the time Windows recorded about it (a key\'s last write, an install time - named, in amber); one with none is in its host\'s block at the collection time. Events in their own colour were added by hand.'), railBox),
    { collapsed: false, modules: options.modules.filter((m) => m !== MANUAL).length ? options.modules.filter((m) => m !== MANUAL) : [CORE] }));
  syncUrl();
  draw();
}
