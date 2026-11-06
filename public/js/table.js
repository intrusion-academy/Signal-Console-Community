// The one table component every page uses (dataTable), and the one
// dictionary of column kinds (COLUMNS, via col).

import { h, ts, mono, breakable, withTip, svgIcon, fetchJSON, virusTotalLink, fitToWindow } from './dom.js';
import { canEdit } from './session.js';
import { pageLink } from './router.js';
import { OPS, BLANK, applyFilters, distinctValues } from './columnFilter.js';
import {
  sevTag, triageTag, TRIAGE, SEVERITY_RANK, countCell, stackBar, hostLink, hostLinks, ruleLinks, truncatedList, RULE_OUTCOME, sourceTag, telemetryTag, tabbedPanel, quotedTitle,
} from './components.js';

// flagCell is a row's flag (src/flags.js - one feature for every
// inventory): a red flag when a rule's signal names the row, the console
// flagged it by one of its rules, or an analyst flagged it - every reason
// written under the flag, each its own line; an analyst sets their own flag
// by clicking, giving the reason, or removes it (a rule's or the console's
// flag stays). The row carries its identity (flag_kind, flag_key,
// flag_label) from the server.
export function flagCell(row) {
  const why = () => [
    ...String(row.flag_rules || '').split('\n').filter(Boolean).map((x) => ['Signal rule', x]),
    ...String(row.flag_console || '').split('\n').filter(Boolean).map((x) => ['Console', x]),
    ...(row.flagged_by_analyst ? [[`Analyst ${row.flagged_by_analyst}`, row.flag_reason || '(no reason - flagged before reasons were asked)']] : []),
  ];
  const icon = () => h('span', { class: row.flagged === 'flagged' ? 'flag-on' : 'flag-off', title: why().length ? 'Flagged - the reasons are below the flag' : 'not flagged' }, svgIcon('flagged'));
  const reasons = () => (why().length ? h('div', { class: 'flag-why' }, ...why().map(([who, x]) => h('div', {}, h('b', {}, `${who}: `), x))) : null);
  const cell = h('div', { class: 'flag-cell' });
  const btn = canEdit() && row.flag_key ? h('button', { class: 'flag-btn', 'aria-label': 'Flag this row' }, icon()) : null;
  const paint = () => {
    if (btn) {
      // The button toggles the analyst's own flag: a click flags, the next unflags.
      const mine = Boolean(row.flagged_by_analyst);
      btn.setAttribute('aria-pressed', String(mine));
      btn.title = mine ? 'Remove your flag' : row.flagged === 'flagged' ? "Flag this row too (a rule's or the console's flag stays while its signal does)" : 'Flag this row';
      btn.classList.toggle('flag-mine', mine);
      btn.replaceChildren(icon());
    }
    cell.replaceChildren(...[btn || icon(), reasons()].filter(Boolean));
  };
  paint();
  if (!btn) return cell;
  btn.onclick = async (e) => {
    e.stopPropagation();
    const on = !row.flagged_by_analyst;
    const reason = on ? flagReason(row.flag_label) : '';
    if (on && !reason) return;
    await fetchJSON('/api/flags', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: row.flag_kind, key: row.flag_key, label: row.flag_label, on, reason }) });
    row.flagged_by_analyst = on ? 'you, now' : '';
    row.flag_reason = reason;
    row.flagged = row.flag_rules || row.flag_console || on ? 'flagged' : 'not flagged';
    paint();
  };
  return cell;
}

// flagReason asks the analyst why they flag an item; empty when cancelled.
// The reason is listed in Flagged items and the Reports page's triage
// notes, and goes into the report.
export function flagReason(label) {
  return String(window.prompt(`Why do you flag "${label}"? The reason is listed in Flagged items and the report's triage notes.`) || '').trim();
}

// dataTable(rows, columns, opts): search box, click-to-sort columns, CSV
// export, optional expandable detail rows, paging.
//
// columns: [{key, label, render?(value, row) -> string|Node, wrap?, icon?, desc?}]
//   row[key] is what search, sorting and CSV export read, so keep it a
//   plain value and put presentation in render - that keeps an exported CSV
//   usable. wrap lets a long-text column wrap; icon shows the header as an
//   icon, with label and desc in a hover card.
// opts.detail(row, {refresh}) -> Node | null - clicking a row toggles a
//   detail panel below it; "Expand all" / "Collapse all" appear in the
//   toolbar. A panel is built once per row and kept, so collapsing and
//   reopening it (or re-sorting, or paging back) preserves its state.
//   refresh() redraws the row's own cells in place (a signal's triage).
// opts.open(row) - clicking a row (not one of its links) opens it elsewhere
//   - a signal's own page - instead of a detail panel.
// opts.rowKey(row) - a row's identity (default: the row object itself); a
//   remote table's rows are new objects on every request, so it needs one
//   for its open panels to survive paging.
// opts.rowClass(row, prev) -> class names for a row, given the row above it
//   on the page (null for the first) - e.g. a line where a group ends.
// opts.focus(row) -> bool - rows to open and highlight from the start (a
//   deep link's target).
// opts.pageSize - rows per page (default 50; 0: every row on one page).
// opts.height - how a table holds every row instead of paging (pageSize is
//   then ignored): 'auto' (auto-height) - the table grows with its rows,
//   for the only panel of a page; 'scroll' - its frame keeps the window's
//   height and scrolls, for a panel among others. The app's rule: a page's
//   only panel is auto-height; a panel beside others scrolls.
// opts.remote({q, sort, dir, offset, limit}) -> Promise<{rows, total,
//   total_all?}> - the rows live on the server: every page, search, sort
//   and CSV export (limit 0: every row) is a request; `rows` is ignored.
// opts.filename - the CSV file's name, without extension.
//
// Every column header has a filter, as in a spreadsheet (column.filter
// false leaves one out): its distinct values to keep, and/or a text
// condition - see columnFilter.js, shared with the server for a remote
// table. column.filterLabel(value) names a value in its list.
// ENTITY_MAX is the longest entity a table cell shows; the rest is on hover
// and on the signal's own page.
const ENTITY_MAX = 160;

export function dataTable(rows, columns, opts = {}) {
  let query = '';
  let sort = null;
  let page = 0;
  let generation = 0; // a remote page that arrives after a newer request is dropped
  const keyOf = opts.rowKey || ((row) => row);
  const expanded = new Set(); // keys of rows whose detail panel is open
  const panels = new Map(); // key -> its detail panel (or null), built on first open
  const pageSize = opts.height ? 0 : opts.pageSize ?? 50;
  const detail = opts.detail;
  // A table with a Severity column edges each row in its severity's color,
  // so a long list can be read by severity at a glance.
  const sevEdge = columns.some((c) => c.key === 'severity');
  const source = opts.remote
    ? (req) => opts.remote({ ...req, filters: req.filters.length ? JSON.stringify(req.filters) : '', sort: req.sort ? req.sort.key : '', dir: req.sort && req.sort.dir < 0 ? 'desc' : 'asc' })
    : localSource(rows, columns);
  const filters = new Map(); // column key -> {key, values, op, text}
  const request = (req) => source({ ...req, filters: [...filters.values()] });

  const root = h('div', { class: 'data-table' });
  const info = h('span', { class: 'mut' });
  let debounce = null;
  const search = h('input', {
    type: 'search', placeholder: 'Search…', title: 'Search this table. Keys: / searches the page\'s first table; j / k move through rows; Enter opens the row',
    oninput: (e) => {
      query = e.target.value.toLowerCase();
      page = 0;
      clearTimeout(debounce);
      if (opts.remote) debounce = setTimeout(draw, 250); // one request per pause in typing, not per keystroke
      else draw();
    },
  });
  // clearFilters removes every column filter at once; it is offered only
  // while one is applied (paint updates it).
  const clearFilters = h('button', { class: 'ghost', disabled: 'disabled', onclick: () => { filters.clear(); page = 0; draw(); } }, 'Clear filters');
  const tools = [search, h('button', { class: 'ghost', onclick: exportCSV }, 'Export CSV'), clearFilters];
  if (detail) {
    tools.push(
      h('button', { class: 'ghost', onclick: () => whenReady(request({ q: query, sort, offset: 0, limit: 0 }), (res) => { res.rows.forEach((r) => expanded.add(keyOf(r))); draw(); }) }, 'Expand all'),
      h('button', { class: 'ghost', onclick: () => { expanded.clear(); draw(); } }, 'Collapse all'));
  }
  tools.push(info);
  const tw = h('div', { class: opts.height === 'auto' ? 'tw tw-auto' : 'tw' });
  const pager = h('div', { class: 'pager' });
  root.append(h('div', { class: 'row toolbar' }, tools), tw, pager);

  function exportCSV() {
    whenReady(request({ q: query, sort, offset: 0, limit: 0 }), (res) => {
      // A text cell a spreadsheet would read as a formula (=, +, -, @, tab or
      // carriage return first) - a command line or file name an attacker
      // wrote on the host - is prefixed with ' so it opens as text.
      const esc = (v) => {
        v = v ?? '';
        if (typeof v === 'string' && /^[=+\-@\t\r]./s.test(v)) v = "'" + v; // a lone "-" (Windows' no-value mark) is no formula
        return /[",\r\n]/.test(v) ? '"' + String(v).replace(/"/g, '""') + '"' : v;
      };
      const lines = [columns.map((c) => esc(c.label)).join(',')];
      for (const row of res.rows) lines.push(columns.map((c) => esc(row[c.key])).join(','));
      // The byte-order mark makes spreadsheet applications (Excel) read the
      // file as UTF-8 instead of guessing a legacy code page.
      const blob = new Blob(['﻿' + lines.join('\n')], { type: 'text/csv;charset=utf-8' });
      h('a', { href: URL.createObjectURL(blob), download: (opts.filename || 'export') + '.csv' }).click();
    });
  }

  const trs = new Map(); // key -> its table row, as last drawn
  const widths = new Map(); // column key -> width in px, once a column is resized
  const cells = (row) => columns.map((c) => h('td', { class: c.wrap ? 'wrap' : null }, c.render ? c.render(row[c.key], row) : String(row[c.key] ?? '—')));

  function panelFor(row) {
    const k = keyOf(row);
    if (!panels.has(k)) panels.set(k, detail(row, { refresh: () => { const tr = trs.get(k); if (tr) tr.replaceChildren(...cells(row)); } }));
    return panels.get(k);
  }

  function detailRow(row) {
    const panel = panelFor(row);
    return panel ? h('tr', { class: 'detail-row' }, h('td', { colspan: columns.length }, panel)) : null;
  }

  // A single row toggles in place rather than redrawing the table, so the
  // page does not jump and every other open panel stays as it is.
  function toggle(tr, row) {
    const next = tr.nextSibling;
    const k = keyOf(row);
    if (expanded.has(k)) {
      expanded.delete(k);
      if (next && next.classList && next.classList.contains('detail-row')) next.remove();
      return;
    }
    const dtr = detailRow(row);
    if (!dtr) return;
    expanded.add(k);
    tr.after(dtr);
  }

  function drawPager(pages) {
    if (pages <= 1) { pager.replaceChildren(); return; }
    const goTo = (p) => { page = p; draw(); };
    const btn = (label, p, on) => h('button', { class: 'chip' + (on ? ' on' : ''), disabled: p < 0 || p >= pages ? 'disabled' : null, onclick: () => goTo(p) }, label);
    const first = Math.max(0, Math.min(page - 3, pages - 7));
    const nums = [];
    for (let p = first; p < Math.min(pages, first + 7); p++) nums.push(btn(String(p + 1), p, p === page));
    pager.replaceChildren(btn('‹', page - 1), ...nums, btn('›', page + 1), h('span', { class: 'mut' }, `page ${page + 1} of ${pages}`));
  }

  function paint(res) {
    const pages = pageSize ? Math.max(1, Math.ceil(res.total / pageSize)) : 1;
    const thead = h('tr', {}, columns.map((c) =>
      h('th', {
        // alarm(row): a column whose header rings while a row it shows is
        // in alarm - the Flagged column's flag while any row is flagged.
        class: [c.wrap ? 'wrap' : '', c.alarm && (opts.remote ? res.rows : rows).some(c.alarm) ? 'th-alarm' : ''].filter(Boolean).join(' ') || null,
        'data-label': c.label, 'aria-label': c.label,
        onclick: () => { sort = { key: c.key, dir: sort && sort.key === c.key ? -sort.dir : 1 }; page = 0; draw(); },
      }, c.icon ? headerIcon(c) : c.label, sort && sort.key === c.key ? (sort.dir > 0 ? ' ▲' : ' ▼') : '', c.filter === false ? null : filterButton(c),
      h('span', { class: 'col-grip', title: 'Drag to resize; double-click to reset all', onclick: (e) => e.stopPropagation(), ondblclick: resetWidths, onmousedown: (e) => resizeStart(e, c) }))));
    const body = [];
    trs.clear();
    let prev = null;
    for (const row of res.rows) {
      const cls = [opts.focus && opts.focus(row) ? 'focus-row' : '', opts.rowClass ? opts.rowClass(row, prev) : ''].filter(Boolean).join(' ');
      prev = row;
      const tr = h('tr', { class: cls || null }, cells(row));
      if (sevEdge && row.severity in SEVERITY_RANK) tr.classList.add('sev-row-' + row.severity);
      trs.set(keyOf(row), tr);
      body.push(tr);
      if (opts.open) {
        tr.classList.add('clickable');
        tr.onclick = (e) => { if (!e.target.closest('a, button, input, select')) opts.open(row); };
      }
      if (!detail) continue;
      tr.onclick = () => toggle(tr, row);
      if (expanded.has(keyOf(row))) {
        const dtr = detailRow(row);
        if (dtr) body.push(dtr);
      }
    }
    tw.replaceChildren(h('table', { class: detail || opts.open ? 'expandable' : null }, h('thead', {}, thead), h('tbody', {}, body)));
    applyWidths();
    clearFilters.disabled = filters.size === 0;
    clearFilters.title = filters.size ? `Remove the ${filters.size} column filter${filters.size === 1 ? '' : 's'} applied` : 'No column filter applied';
    const all = res.total_all ?? res.total;
    info.textContent = `${res.total.toLocaleString()} of ${all.toLocaleString()} row${all === 1 ? '' : 's'}`;
    drawPager(pages);
    root.dataset.ready = String(generation); // for tests: this request's rows are on screen
  }

  // Column resizing, as in a spreadsheet: dragging a header's right edge
  // sets that column's width. The first drag fixes every column at its
  // current width, so the others keep theirs; the widths survive redraws.
  function applyWidths() {
    const table = tw.firstChild;
    if (!table || !widths.size) return;
    let sum = 0;
    table.querySelectorAll(':scope > thead th').forEach((th, i) => {
      const w = widths.get(columns[i].key);
      th.style.width = w + 'px';
      sum += w;
    });
    table.style.tableLayout = 'fixed';
    table.style.width = sum + 'px';
  }

  function resizeStart(e, c) {
    e.preventDefault();
    e.stopPropagation();
    const ths = [...tw.firstChild.querySelectorAll(':scope > thead th')];
    if (!widths.size) ths.forEach((th, i) => widths.set(columns[i].key, th.offsetWidth));
    const x0 = e.clientX, w0 = widths.get(c.key);
    const move = (ev) => { widths.set(c.key, Math.max(40, w0 + ev.clientX - x0)); applyWidths(); };
    const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  }

  function resetWidths(e) {
    e.stopPropagation();
    widths.clear();
    draw();
  }

  // filterButton is a column header's filter: it opens the column's filter
  // panel, and shows when the column is filtered.
  function filterButton(c) {
    const btn = h('button', { class: 'th-filter' + (filters.has(c.key) ? ' on' : ''), title: `Filter ${c.label}`, 'aria-label': `Filter ${c.label}` }, svgIcon('filter'));
    btn.onclick = (e) => { e.stopPropagation(); openFilter(c, btn); };
    return btn;
  }

  // distinctOf is a column's values among the rows the other columns'
  // filters keep - from the server for a remote table.
  function distinctOf(c) {
    const others = [...filters.values()].filter((f) => f.key !== c.key);
    if (!opts.remote) return distinctValues(applyFilters(rows, others), c.key);
    return opts.remote({ q: query, filters: others.length ? JSON.stringify(others) : '', distinct: c.key, limit: 1 }).then((res) => res.distinct);
  }

  // openFilter shows a column's filter panel under its header: a text
  // condition, and its distinct values (searchable) to keep. Apply sets the
  // filter; Clear removes it.
  function openFilter(c, anchor) {
    root.querySelectorAll('.col-filter').forEach((x) => x.remove());
    const cur = filters.get(c.key) || { key: c.key, values: [], op: 'contains', text: '' };
    const op = h('select', {}, OPS.map((o) => h('option', { value: o, selected: o === cur.op ? 'selected' : null }, o === 'startswith' ? 'starts with' : o === 'endswith' ? 'ends with' : o)));
    const text = h('input', { type: 'text', value: cur.text, placeholder: 'text' });
    const find = h('input', { type: 'search', placeholder: 'Search values…' });
    const list = h('div', { class: 'col-filter-values' }, h('span', { class: 'mut' }, 'Loading…'));
    const picked = new Set(cur.values);
    let values = [];
    const label = (v) => (v === BLANK || !c.filterLabel ? v : c.filterLabel(v));
    const drawList = () => {
      const q = find.value.toLowerCase();
      const shown = values.filter((v) => !q || label(v.value).toLowerCase().includes(q));
      list.replaceChildren(...shown.map((v) => h('label', {},
        h('input', { type: 'checkbox', checked: picked.has(v.value) ? 'checked' : null, onchange: (e) => (e.target.checked ? picked.add(v.value) : picked.delete(v.value)) }),
        h('span', { class: 'col-filter-text' }, label(v.value)), h('span', { class: 'mut' }, v.count.toLocaleString()))));
      if (!shown.length) list.append(h('span', { class: 'mut' }, 'No value'));
    };
    find.oninput = drawList;
    whenReady(distinctOf(c), (d) => { values = d.values; drawList(); if (d.more) list.append(h('div', { class: 'mut' }, 'More values than shown - search or use the text condition.')); });
    const done = () => { panel.remove(); window.document.removeEventListener('click', outside, true); page = 0; draw(); };
    const apply = () => {
      const f = { key: c.key, values: [...picked], op: op.value, text: text.value.trim() };
      if (f.values.length || f.text) filters.set(c.key, f);
      else filters.delete(c.key);
      done();
    };
    const panel = h('div', { class: 'card col-filter', onclick: (e) => e.stopPropagation() },
      h('div', { class: 'col-filter-title' }, c.label),
      h('div', { class: 'row' }, op, text), find, list,
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: apply }, 'Apply'), h('button', { class: 'ghost', onclick: () => { filters.delete(c.key); done(); } }, 'Clear')));
    const outside = (e) => { if (!panel.contains(e.target)) { panel.remove(); window.document.removeEventListener('click', outside, true); } };
    window.document.addEventListener('click', outside, true);
    const at = anchor.getBoundingClientRect(), box = root.getBoundingClientRect();
    panel.style.left = `${Math.max(0, Math.min(at.left - box.left, box.width - 300))}px`;
    panel.style.top = `${at.bottom - box.top + 4}px`;
    root.append(panel);
    fitToWindow(panel, 180);
    text.focus();
  }

  // drawInterim puts rows in place of the table's body - under the header
  // already drawn, if any - while a server page is on its way, or when it
  // could not be had.
  function drawInterim(rows) {
    const table = tw.firstChild;
    if (table && table.tBodies && table.tBodies[0]) table.tBodies[0].replaceChildren(...rows);
    else tw.replaceChildren(h('table', {}, h('tbody', {}, rows)));
  }
  // Placeholder rows for a server page slow to arrive: the table keeps its
  // place and shows that rows are coming.
  const skeleton = () => Array.from({ length: Math.min(pageSize || 8, 8) }, () =>
    h('tr', { class: 'skeleton-row', 'aria-hidden': 'true' }, columns.map(() => h('td', {}, h('span', { class: 'skeleton' })))));

  function draw() {
    const mine = ++generation;
    delete root.dataset.ready;
    const slow = opts.remote ? setTimeout(() => { if (mine === generation) drawInterim(skeleton()); }, 150) : null;
    const done = whenReady(request({ q: query, sort, offset: page * pageSize, limit: pageSize }), (res) => {
      clearTimeout(slow);
      if (mine !== generation) return;
      const pages = pageSize ? Math.max(1, Math.ceil(res.total / pageSize)) : 1;
      if (page > pages - 1) { page = pages - 1; draw(); return; } // the rows shrank under the current page
      paint(res);
    });
    if (done && typeof done.catch === 'function') {
      done.catch((err) => {
        clearTimeout(slow);
        if (mine !== generation) return;
        drawInterim([h('tr', {}, h('td', { colspan: String(columns.length), class: 'mut' }, `Could not load these rows: ${err.message}. Sort, search or change page to try again.`))]);
      });
    }
  }

  if (opts.focus && !opts.remote) {
    const focused = rows.filter(opts.focus);
    focused.forEach((r) => expanded.add(keyOf(r)));
    if (focused.length && pageSize) page = Math.floor(rows.indexOf(focused[0]) / pageSize);
  }
  draw();
  return root;
}

// localSource is dataTable's page source for rows it holds itself: search
// across the columns, sort, and slice - synchronously, so a local table is
// drawn (and exported) the moment it is asked to be.
function localSource(rows, columns) {
  return ({ q, sort, offset, limit, filters }) => {
    let r = applyFilters(rows, filters);
    if (q) r = r.filter((row) => columns.some((c) => String(row[c.key] ?? '').toLowerCase().includes(q)));
    if (sort) {
      r = r.slice().sort((a, b) => {
        const x = a[sort.key], y = b[sort.key];
        return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x ?? '').localeCompare(String(y ?? ''))) * sort.dir;
      });
    }
    return { total: r.length, total_all: rows.length, rows: limit ? r.slice(offset, offset + limit) : r };
  };
}

// whenReady calls fn with v right away, or once v resolves if it is a
// promise - so a local table's result and a remote table's request are
// handled by the same code.
function whenReady(v, fn) {
  return v && typeof v.then === 'function' ? v.then(fn) : fn(v);
}

// headerIcon is an icon column header: the icon, with the column's name
// and description in its hover card.
function headerIcon(c) {
  return withTip(svgIcon(c.icon), [h('b', {}, c.label), c.desc && h('span', {}, c.desc)], 'th-icon');
}

// when renders a timestamp in a cell: its date and its time, each kept on
// one line, so a narrow column breaks it only between the two.
function when(v) {
  if (!v) return '—';
  const [date, ...time] = ts(v).split(' ');
  return h('span', {}, h('span', { class: 'nw' }, date), ' ', h('span', { class: 'nw' }, time.join(' ')));
}

// lines renders a text holding several values - split by sep - one value
// per line (render turns one into its node; plain text by default).
function lines(v, sep, render = (x) => x) {
  const parts = String(v ?? '').split(sep).filter(Boolean);
  return parts.length ? truncatedList(parts, 50, render) : '—';
}

// mark renders a yes/no value (a count over one host: 0 or 1) as an icon:
// a check colored yesCls, or a cross colored noCls - a plain dash when noCls
// is null (nothing to say) - each named for screen readers and on hover.
export function mark(v, { yesCls = 'mark-yes', noCls = 'mark-no', yes = 'yes', no = 'no' } = {}) {
  if (!v && noCls === null) return h('span', { class: 'mut', title: no }, '—');
  return h('span', { class: 'mark ' + (v ? yesCls : noCls), title: v ? yes : no, role: 'img', 'aria-label': v ? yes : no }, svgIcon(v ? 'success' : 'failure'));
}

// COLUMNS is every kind of column the app's tables show - its header icon,
// its name and description (the header's hover card), and how its cells
// render - defined once. A table lists its columns with col(); anything a
// table says differently is passed as an override, never a second copy.
//
// A column counting hosts reads differently when only one host is in view
// (see forHosts): its `one` form - its name, description and cells for
// that one host (a mark instead of 0 or 1) - or `one: null` when it has
// nothing to say about one host (how many hosts; which hosts).
const COLUMNS = {
  // Findings and rules
  severity: { label: 'Severity', icon: 'severity', desc: 'How urgent it is: critical, high, medium or low.', render: (v) => sevTag(v) },
  module: { label: 'Module', icon: 'module', desc: 'The Signal module the data comes from.' },
  title: { label: 'Title', icon: 'title', desc: 'What was found.', wrap: true, render: (v) => quotedTitle(v) },
  rule_id: { label: 'Rule ID', icon: 'id', desc: 'The rule\'s unique ID; its first part names the module. Opens the rule on the Rules page.', render: (v) => (v ? pageLink('rules', { rule: v }, breakable(v)) : '—') },
  first_seen: { label: 'First seen', icon: 'firstSeen', desc: `The earliest occurrence in the data (UTC).`, render: when },
  last_seen: { label: 'Last seen', icon: 'clock', desc: `The latest occurrence in the data (UTC).`, render: when },
  count: { label: 'Count', icon: 'count', desc: 'How many times it occurred.', render: (v) => (v ?? 0).toLocaleString() },
  // Rule outcomes across hosts (Rules page)
  hosts_n: { label: 'Hosts', icon: 'hosts', desc: 'Imported hosts in scope: all of them, or those chosen in the Hosts filter.', one: null },
  evaluated_n: {
    label: 'Evaluated on', icon: 'evaluated', desc: 'Hosts where the rule was evaluated against the host\'s data.', render: (v) => countCell(v, RULE_OUTCOME.clear.cls),
    one: { label: 'Evaluated', desc: 'Whether the rule was evaluated against the host\'s data.', render: (v) => mark(v, { yesCls: RULE_OUTCOME.clear.cls, noCls: RULE_OUTCOME.not_run.cls, yes: 'evaluated', no: 'not evaluated' }) },
  },
  not_evaluated_n: {
    label: 'Not evaluated on', icon: 'notEvaluated', desc: 'Hosts where the rule could not be evaluated; the next three columns say why.', render: (v) => countCell(v, RULE_OUTCOME.not_run.cls),
    one: { label: 'Why not evaluated', wrap: true, desc: 'Why the rule could not be evaluated on the host.', render: (v, row) => (v ? h('span', { class: 'tagtext ' + RULE_OUTCOME.not_run.cls }, row.scope[0].reason) : '—') },
  },
  dependency_n: { label: 'Dependency not met', icon: 'dependency', desc: 'Not evaluated because data or a policy the rule needs was unavailable: the policy is off or undetermined, the log was not read, or a fact was not collected.', render: (v) => countCell(v, RULE_OUTCOME.not_run.cls), one: null },
  module_n: { label: 'Module not run', icon: 'moduleOff', desc: 'Not evaluated because the rule\'s module was not run on the host, or failed there.', render: (v) => countCell(v, RULE_OUTCOME.not_run.cls), one: null },
  rule_n: { label: 'Rule not run', icon: 'ruleOff', desc: 'Not evaluated because the rule was excluded from the run (signal -exclude-rules), the host\'s Signal version does not include it, or - an imported rule - the host\'s run was not given its rule file.', render: (v) => countCell(v, RULE_OUTCOME.not_run.cls), one: null },
  rule_file: { label: 'Rule file', icon: 'file', wrap: true, desc: 'A rule file given to Signal with -rules, as the host\'s run named it.', render: (v) => mono(v) },
  rule_ids: { label: 'Rules', icon: 'id', wrap: true, desc: 'The rules loaded from it; each opens on the Rules page.', render: (v) => truncatedList(v, 5, (id) => pageLink('rules', { rule: id }, id)) },
  origin: {
    label: 'Origin', icon: 'file',
    desc: "Where the rule comes from: built-in (shipped with its module, inside Signal), imported (a rule file given to Signal with -rules when it ran) or console (Signal Console's own rule, module Console - checked over the imported runs with the console's own data, such as CISA's catalog). Hover an imported rule for its file.",
    render: (v, row) => (v === 'imported' ? h('span', { class: 'tagtext origin-imported', title: (row.rule_files || []).join('\n') || row.origin }, 'imported')
      : v === 'console' ? h('span', { class: 'tagtext', title: "Signal Console's own rule" }, 'console') : h('span', { class: 'mut' }, 'built-in')),
  },
  flagged_n: {
    label: 'Flagged on', icon: 'flagged', desc: 'Hosts where the rule matched; its matches are signals on the Signals page.', render: (v) => countCell(v, RULE_OUTCOME.flagged.cls),
    one: { label: 'Flagged', desc: 'Whether the rule matched on the host; its matches are signals on the Signals page.', render: (v) => mark(v, { yesCls: RULE_OUTCOME.flagged.cls, noCls: null, yes: 'flagged', no: 'not flagged' }) },
  },
  outcome: { label: 'Outcome', icon: 'outcome', desc: 'Flagged, evaluated with no match, or not evaluated.' },
  matches: { label: 'Matches', icon: 'matches', desc: 'How many events matched the rule on this host.', render: (v) => (v === '' || v == null ? '—' : countCell(v, RULE_OUTCOME.flagged.cls)) },
  reason: { label: 'Why not evaluated', icon: 'reason', desc: 'Why the rule could not be evaluated on this host.', render: (v) => v || '—' },
  details: { label: 'Details', icon: 'details', desc: 'The finding\'s text where the rule flagged, or the full reason it was not evaluated.', wrap: true },
  // Signals (Signals page)
  time: {
    label: 'Time', icon: 'clock', desc: `When it happened (UTC): the event's own time, or a matched value's latest occurrence; "between" two times when only a range is known (a typed PowerShell command). Blank for a state of the host rather than an event.`,
    render: (v, row) => (row.time_from ? h('span', {}, 'between ', when(row.time_from), ' and ', when(v)) : when(v)),
  },
  entity: {
    label: 'Entity', icon: 'target', wrap: true,
    desc: 'What the signal is about - a command line, an account - with the line that qualifies it (the executable of a command line) above it. Blank for a state of the host as a whole.',
    render: (v, row) => {
      const text = String(v ?? '');
      const cut = text.length > ENTITY_MAX ? text.slice(0, ENTITY_MAX) + '…' : text;
      return h('span', { class: 'entity-clamp', title: cut !== text ? text.slice(0, 4000) : null },
        row.context ? h('span', { class: 'entity' }, mono(row.context), h('span', { class: 'mono mut' }, breakable(cut))) : mono(cut));
    },
  },
  evidence: {
    label: 'Evidence', icon: 'dataset', wrap: true,
    desc: 'What the signal is built on - and so what it proves: a process creation is history (it started then; it may be gone), a running process is now. Hover for where it was read.',
    render: (v, row) => (v ? h('span', { title: row.source ? `${row.source.proves} - read from ${row.source.description}` : v }, v) : h('span', { class: 'mut' }, row.kind === 'state' ? 'state of the host' : 'not recorded')),
  },
  // Users and logons (Users page, a user's page, the Logons inventory)
  user: { label: 'Account', icon: 'user', desc: 'The account, DOMAIN\\name (or its SID when no host records a name); opens its page on the Users tab.', render: (v, row) => (row.key ? pageLink('users', { user: row.key }, mono(v)) : mono(v)) },
  scope: { label: 'Defined in', icon: 'layers', desc: 'Where the account is defined: the host itself (local), a domain, a Microsoft account, or Entra ID.' },
  account_kind: { label: 'Kind', icon: 'value', desc: 'person: someone\'s account; default: an account Windows creates (Administrator, Guest), shown because it is enabled or was used.' },
  account_sources: { label: 'Known from', icon: 'dataset', wrap: true, desc: 'How the hosts know the account: their account database (SAM), the Administrators group, a profile on disk, an open session, logon events.', render: (v) => truncatedList(String(v || '').split('; ').filter(Boolean)) },
  admin_n: {
    label: 'Administrator on', icon: 'shield', desc: 'Hosts where the account is a member of the local Administrators group.', render: (v) => countCell(v, v ? 'sev-medium' : ''),
    one: { label: 'Administrator', desc: 'Whether the account is a member of the host\'s local Administrators group.', render: (v) => mark(v, { yesCls: 'sev-medium', noCls: null, yes: 'administrator', no: 'not an administrator' }) },
  },
  logged_on_n: {
    label: 'Signed in now on', icon: 'eye', desc: 'Hosts where the account was signed in to an interactive session when Signal ran - at the console or by Remote Desktop, active or disconnected - not counting the session Signal itself ran in (the analyst collecting the host).', render: (v) => countCell(v),
    one: { label: 'Signed in now', desc: 'Whether the account was signed in to an interactive session when Signal ran (console or Remote Desktop, active or disconnected), not counting the session Signal ran in.', render: (v) => mark(v, { noCls: null, yes: 'signed in', no: 'not signed in' }) },
  },
  logons: { label: 'Logons', icon: 'logon', desc: 'Successful logons (event 4624) in the hosts\' Security logs.', render: (v) => (v ?? 0).toLocaleString() },
  failures: { label: 'Failed logons', icon: 'failure', desc: 'Failed logons (event 4625) for the account.', render: (v) => countCell(v, v ? 'sev-medium' : '') },
  privileged: { label: 'Administrative logons', icon: 'key', desc: 'Logons given administrative privileges (event 4672).', render: (v) => (v ?? 0).toLocaleString() },
  account_signals_n: { label: 'Signals', icon: 'signals', desc: 'Open signals about the account: signals whose line or event names it.', render: (v) => countCell(v, v ? 'sev-high' : '') },
  enabled: { label: 'Enabled', icon: 'success', desc: 'For a local account: enabled or disabled. Blank for an account defined elsewhere.', render: (v) => (v === true ? 'yes' : v === false ? 'no' : '—') },
  admin: { label: 'Administrator', icon: 'shield', desc: 'A member of the host\'s local Administrators group.', render: (v) => (v ? h('span', { class: 'tagtext sev-medium' }, 'yes') : 'no') },
  groups: { label: 'Local groups', icon: 'layers', wrap: true, desc: 'The host\'s local groups the account belongs to.', render: (v) => lines(v, /,\s*|;\s*/) },
  profile_path: { label: 'Profile', icon: 'folder', wrap: true, desc: 'The account\'s profile folder on the host - it signed in interactively there.', render: (v) => (v ? mono(v) : '—') },
  logged_on_now: {
    label: 'Signed in now', icon: 'eye', wrap: true,
    desc: 'The account\'s interactive session when Signal ran, exactly as Windows lists it: console or Remote Desktop, active or disconnected (and since when), from which client. The session Signal itself ran in is the analyst collecting the host - shown, but not counted as the account being signed in.',
    render: (v, row) => (row.session ? h('span', { class: v ? '' : 'mut' }, row.session) : 'no'),
  },
  type_name: { label: 'Logon type', icon: 'logon', desc: 'How it logged on: interactive (at the console), network (file shares, remote tools), remote interactive (Remote Desktop), service, batch, new credentials (runas /netonly)...', render: (v, row) => `${v}${row.logon_type ? ` (${row.logon_type})` : ''}` },
  logon_source: { label: 'From', icon: 'globe', desc: 'Where the logon came from: its address, or the workstation name it claimed; "-" for the host itself.', render: (v, row) => h('span', { title: row.source_scope || '' }, mono(v || '-')) },
  source_scope: { label: 'Address kind', icon: 'globe', desc: 'public: routable on the Internet; private: an internal network; loopback: the host itself.', render: (v) => (v === 'public' ? h('span', { class: 'tagtext sev-high' }, v) : v || '—') },
  auth_package: { label: 'Authentication', icon: 'key', desc: 'The authentication package: Kerberos, NTLM, Negotiate. NTLM from other hosts is what pass-the-hash uses.' },
  elevated: { label: 'Elevated', icon: 'shield', desc: 'Logons with an elevated (full administrator) token.', render: (v) => (v ?? 0).toLocaleString() },
  failure_reason: { label: 'Why it failed', icon: 'reason', desc: 'The failure\'s reason: wrong password (the account exists), no such user, account disabled, locked out...' },
  sid: { label: 'SID', icon: 'id', desc: 'The account\'s SID - for a Remote Desktop client connection, the only way its log names who ran the client; the name beside it is the one the host\'s logons give that SID.', render: (v) => (v ? mono(v) : '—') },
  session_how: { label: 'How', icon: 'logon', desc: 'How the session was signed in to: remote desktop, or console (at the machine - its session manager records those too). Blank for a sign-out, which does not say.', render: (v) => v || '—' },
  rdp_event: { label: 'Step', icon: 'id', wrap: true, desc: 'What Remote Desktop recorded, with its event: connection accepted (131), wrong user name or password (140), authenticated (1149 - with Network Level Authentication off, only a connection), signed in (21), shell started (22), signed out (23), disconnected (24), reconnected (25); for the client: connecting (1024, an attempt) and multi-transport set up (1102, the connection was made).' },
  rdp_server: { label: 'Server', icon: 'server', desc: 'The server this host\'s Remote Desktop client connected to, as the user typed it (a name or an address) or its address.', render: (v) => mono(v || '-') },
  account_changes: {
    label: 'Changes', icon: 'firstSeen', wrap: true,
    desc: 'The changes the Security log records of the account, in time order, with who made each: created, enabled, disabled, password reset, flags changed, locked out, SID history added, deleted, added to or removed from Administrators.',
    render: (v) => {
      const changes = String(v || '').split('; ').filter(Boolean);
      // Each change starts with its time (RFC 3339), shown as every other time is.
      const shown = (c) => c.replace(/^(\S+Z) /, (m, t) => `${ts(t)}: `);
      return changes.length ? truncatedList(changes, 2, (c) => h('span', { title: shown(c) }, shown(c))) : '—';
    },
  },
  target_server: { label: 'For server', icon: 'server', desc: 'The server the credentials were used for: localhost for a local run-as, another host for a remote connection.', render: (v) => mono(v || '-') },
  subject: { label: 'Used by', icon: 'user', desc: 'The account that used the credentials.', render: (v) => mono(v || '-') },
  process: { label: 'Process', icon: 'terminal', wrap: true, desc: 'The process that used them.', render: (v) => (v ? mono(v) : '—') },
  account_notes: {
    label: 'Notes', icon: 'warning', wrap: true,
    desc: 'What a host notes about the account that is not a signal: the built-in Administrator enabled, a profile folder no account owns.',
    render: (v) => {
      const notes = Array.isArray(v) ? v : String(v || '').split('; ').filter(Boolean);
      return notes.length ? truncatedList(notes, 1, (n) => h('span', { class: 'tagtext sev-medium tag-wraps', title: n }, n.split(':')[0])) : '—';
    },
  },
  excluded_reason: { label: 'Why left out', icon: 'reason', wrap: true, desc: 'Why the account is not a user of its own: Windows\' own identity, a group, a computer, or a default account never enabled or used.' },
  // Evidence sources (a host's page)
  source: {
    label: 'Evidence', icon: 'dataset', wrap: true,
    desc: 'An evidence type the modules used. A historical record says something happened then; a state says it is so now. Hover for where it is read from.',
    render: (v, row) => h('span', { title: [row.kind === 'state' ? 'state of the host at the run' : 'historical record', row.provider && `from ${row.provider}${row.channel ? ` (${row.channel} log)` : ''}`].filter(Boolean).join(' - ') }, v),
  },
  source_status: {
    label: 'State', icon: 'evaluated',
    desc: 'read: found and read completely (its records may be none); partly read; not read; off - not recorded: read with no record while something it depends on is off, so Windows writes none of it and its emptiness proves nothing; no source: the host does not have it (no log file, no web site, not a domain member). A rule over evidence that was not read is "not evaluated", never "no match".',
    render: (v) => sourceTag(v),
  },
  records: { label: 'Records', icon: 'count', desc: 'Records of this evidence the run produced.', render: (v) => (v ?? 0).toLocaleString() },
  prerequisites: {
    label: 'Depends on', icon: 'dependency', wrap: true,
    desc: 'Conditions without which this evidence is not written, or a field of it is empty - each with its state on the host. Hover for how the state was established.',
    render: (v, row) => (row.prereqs.length
      ? h('div', {}, row.prereqs.map((p) => h('div', { title: p.reason || p.basis }, telemetryTag(p.state), ' ', p.label)))
      : h('span', { class: 'mut' }, 'nothing')),
  },
  source_reason: { label: 'What it means', icon: 'notEvaluated', wrap: true, desc: 'What the state means on this host: how much was read, what it depends on that is off, or why it was not read - in Signal\'s words where Signal gives them.' },
  fleet_n: {
    label: 'On hosts', icon: 'coverage',
    desc: 'How many hosts\' current collections have the same signal - the same rule matching the same value. 1: seen on this host alone, which on a fleet of similar machines is what stands out.',
    render: (v) => (v === 1 ? h('span', { class: 'tagtext tr-new', title: 'seen on this host alone' }, '1') : String(v ?? '—')),
  },
  tactic: { label: 'ATT&CK tactic', icon: 'layers', desc: 'The ATT&CK tactics of the rule\'s techniques.', wrap: true, render: (v) => lines(v, /;\s*/) },
  triage: { label: 'Triage', icon: 'status', desc: 'The analyst\'s decision: open (not looked at yet), reviewed, benign or escalated - of the entity the signal is about, as a whole (on the entity\'s page or the signal\'s), or of the signal alone when it is about none. It carries over to the host\'s next collection.', render: (v) => triageTag(v), filterLabel: (v) => (TRIAGE[v] ? TRIAGE[v].label : v) },
  risk: { label: 'Risk', icon: 'gauge', desc: 'Open signals weighted by severity: critical 40, high 20, medium 5, low 1; an escalated signal counts twice. Suppressed and benign signals count nothing.', render: (v) => h('b', { class: v ? 'tagtext sev-high' : 'mut' }, String(v)) },
  new_n: { label: 'New', icon: 'firstSeen', desc: 'Signals not in the host\'s previous collection; blank for its first collection.', render: (v) => (v === '' ? '—' : countCell(v, 'tr-new')) },
  untriaged_n: { label: 'Untriaged', icon: 'eye', desc: 'Open signals nobody has triaged yet.', render: (v, row) => (v ? pageLink('signals', { host: row.run_id, triage: 'new' }, countCell(v, 'tr-new')) : countCell(0)) },
  // Hosts and runs (Hosts and Import pages). A host cell links to the
  // host's page: any row with a host column carries its run_id, host, os,
  // os_build and role (see hostLink).
  host: { label: 'Host', icon: 'hosts', desc: 'The host; opens its page on the Hosts tab.', render: (v, row) => hostLink(row, v), one: null },
  change_time: { label: 'Change time', icon: 'clock', desc: `When the change was made (UTC).`, render: when },
  os: { label: 'Operating system', icon: 'windows', desc: 'The Windows edition the host runs.', wrap: true, render: (v) => v || '—' },
  os_build: { label: 'Build', icon: 'version', desc: 'The Windows build number.', render: (v) => v || '—' },
  role: { label: 'Role', icon: 'server', desc: 'Client, Server, Domain Controller - or Evidence, for a forensic collection.' },
  domain: { label: 'Domain', icon: 'globe', desc: 'The domain (or workgroup) the host belongs to.' },
  tool_version: { label: 'Signal version', icon: 'version', desc: 'The version of Signal that collected the host.' },
  signals_n: { label: 'Signals', icon: 'signals', desc: 'Signals (critical, high, medium or low) on the host, colored by the most severe; opens them on the Signals page.', render: (v, row) => (v ? pageLink('signals', { host: row.run_id }, countCell(v, 'sev-' + row.top_severity)) : countCell(0)) },
  warnings_n: {
    label: 'Warnings', icon: 'warning',
    desc: 'Cards on the host\'s page whose state is not good - a small or stale log, a policy off, the built-in Administrator enabled - each saying what it means for an investigation. Hover for which.',
    render: (v, row) => withTip(countCell(v, 'sev-medium'), (row.warnings || []).map((w) => h('span', {}, `${w.label}: ${w.value}`)).concat(v ? [] : [h('span', {}, 'none')])),
  },
  gaps_n: { label: 'Coverage gaps', icon: 'notEvaluated', desc: 'What a module could not check on the host, and module errors.', render: (v) => countCell(v, 'ev-absent') },
  telemetry_off_n: {
    label: 'Telemetry off', icon: 'shield', desc: 'Telemetry the host\'s modules depend on that is off there (and how much could not be determined); hover for which.',
    render: (v, row) => withTip(h('span', {}, countCell(v, 'sev-high'), row.telemetry_unknown_n ? h('span', { class: 'mut' }, ` · ${row.telemetry_unknown_n} unknown`) : null),
      (row.telemetry || []).filter((t) => t.state !== 'on').map((t) => h('span', {}, `${t.state}: ${t.label}`)).concat(row.telemetry && row.telemetry.every((t) => t.state === 'on') ? [h('span', {}, 'everything on')] : [])),
  },
  mode: { label: 'Mode', icon: 'mode', desc: 'live (the running system) or forensics (collected evidence).' },
  started: { label: 'Collected', icon: 'clock', desc: `When Signal ran on the host (UTC).`, render: when },
  modules: { label: 'Modules', icon: 'module', desc: 'The Signal modules the run included.', wrap: true, render: (v) => truncatedList(v) },
  run: { label: 'Run ID', icon: 'id', desc: 'The run\'s unique ID. Remove deletes the imported run from this app (not from the host).' },
  signal_count: { label: 'Signals', icon: 'signals', desc: 'Open signals in the run (critical, high, medium or low; suppressed and benign ones left out).' },
  // Modules (Modules page)
  module_name: { label: 'Module', icon: 'module', desc: 'The Signal module; expand the row for what it is, how it ran on each host, and its rules.', render: (v) => h('b', {}, v) },
  description: { label: 'What it answers', icon: 'details', wrap: true, desc: 'The module\'s own description of what it tells a responder.', render: (v) => v || h('span', { class: 'mut' }, 'not recorded (a run older than Signal 0.9.0)') },
  versions: { label: 'Version', icon: 'version', desc: 'The module\'s version on the hosts (several when hosts ran different Signal versions).' },
  ran_n: { label: 'Ran on', icon: 'hosts', desc: 'Hosts whose latest collection included the module.', one: null },
  problem_n: {
    label: 'Partial or failed', icon: 'notEvaluated', desc: 'Hosts where the module ran partially (something could not be checked), failed, or was skipped. Expand the row for why.', render: (v) => countCell(v, 'ev-absent'),
    one: { label: 'Status', icon: 'status', desc: 'ok, partial (something could not be checked - expand the row for what), failed or skipped.', render: (_v, row) => h('span', { class: 'tagtext ' + (row.hosts[0].status === 'ok' ? 'st-ran' : 'ev-absent') }, row.hosts[0].status) },
  },
  not_run_n: { label: 'Not run on', icon: 'moduleOff', desc: 'Hosts whose latest collection did not include the module.', render: (v) => countCell(v, 'st-notrun'), one: null },
  duration_avg_ms: {
    label: 'Time', icon: 'clock', desc: 'How long the module took, on average across its hosts (the slowest in the hover).', render: (v, row) => (v == null ? '—' : h('span', { title: `slowest: ${row.duration_max_ms} ms` }, `${v.toLocaleString()} ms`)),
    one: { desc: 'How long the module took on the host.', render: (v) => (v == null ? '—' : `${v.toLocaleString()} ms`) },
  },
  evidence_names: { label: 'Evidence it reads', icon: 'dataset', wrap: true, desc: 'The evidence the module subscribes to - read once for every module by Signal\'s providers.', render: (v) => truncatedList(String(v || '').split('; ').filter(Boolean)) },
  rules_n: { label: 'Rules', icon: 'scroll', desc: 'Its rules: built-in, and imported from rule files (hover). Opens them on the Rules page.', render: (v, row) => pageLink('rules', { module: row.name }, withTip(h('span', {}, String(v), row.imported_n ? h('span', { class: 'tagtext origin-imported' }, ` +${row.imported_n} imported`) : null), [h('span', {}, `${row.builtin_n} built-in, ${row.imported_n} imported`), ...row.rule_files.map((f) => h('span', { class: 'mono' }, f))])) },
  module_signals_n: { label: 'Signals', icon: 'signals', desc: 'Open signals from the module, across its hosts; opens them on the Signals page.', render: (v, row) => (v ? pageLink('signals', { modules: row.name }, countCell(v, 'sev-high')) : countCell(0)) },
  module_warnings_n: { label: 'Warnings', icon: 'warning', desc: 'The module\'s cards whose state is not good, across its hosts.', render: (v) => countCell(v, 'sev-medium') },
  status: { label: 'Status', icon: 'status', desc: 'ok, partial (something could not be checked - see its gaps), failed or skipped.', render: (v) => h('span', { class: 'tagtext ' + (v === 'ok' ? 'st-ran' : 'ev-absent') }, v) },
  duration_ms: { label: 'Time', icon: 'clock', desc: 'How long the module took on the host.', render: (v) => (v == null ? '—' : `${v.toLocaleString()} ms`) },
  version: { label: 'Version', icon: 'version', desc: 'The module\'s version on the host.' },
  gap_list: { label: 'Gaps and errors', icon: 'notEvaluated', wrap: true, desc: 'What the module could not check on the host, and its errors.', render: (_v, row) => (row.gaps_n ? h('div', {}, [...row.gaps, ...row.errors].map((g) => h('div', {}, g))) : h('span', { class: 'mut' }, 'none')) },
  warning_list: { label: 'Warnings', icon: 'warning', wrap: true, desc: 'Its cards whose state is not good on the host (see the host\'s page for what each means).', render: (_v, row) => (row.warnings_n ? truncatedList(row.warnings) : h('span', { class: 'mut' }, 'none')) },
  // Audit policy and event IDs (SecurityLog)
  category: { label: 'Category', icon: 'layers', desc: 'The advanced audit policy category.' },
  subcategory: { label: 'Subcategory', icon: 'folder', desc: 'The advanced audit policy subcategory.' },
  success_n: {
    label: 'Success audited on', icon: 'success', desc: 'Hosts that audit this subcategory\'s successful attempts. Expand the row for which.', render: (v) => countCell(v, 'st-ran'),
    one: { label: 'Success audited', desc: 'Whether the host audits this subcategory\'s successful attempts - without it, its success events are never written.', render: (v) => mark(v, { yes: 'successes audited', no: 'successes not audited' }) },
  },
  failure_n: {
    label: 'Failure audited on', icon: 'failure', desc: 'Hosts that audit this subcategory\'s failed attempts. Expand the row for which.', render: (v) => countCell(v, 'st-ran'),
    one: { label: 'Failure audited', desc: 'Whether the host audits this subcategory\'s failed attempts - without it, its failure events are never written.', render: (v) => mark(v, { yes: 'failures audited', no: 'failures not audited' }) },
  },
  off_n: { label: 'Not audited on', icon: 'notEvaluated', desc: 'Hosts that audit neither successes nor failures of this subcategory. Expand the row for which.', render: (v) => countCell(v, 'st-notrun'), one: null },
  local_gpo: { label: 'Local GPO', icon: 'layers', wrap: true, desc: 'What the local Group Policy object (System32\\GroupPolicy) sets for the subcategory; blank where it sets nothing. One value per setting seen across the hosts.' },
  gp_audit: { label: 'Group Policy', icon: 'policy', wrap: true, desc: 'What Group Policy applied for the subcategory - every GPO merged, the local one included (security\\audit\\audit.csv); blank where it sets nothing. One value per setting seen across the hosts.' },
  gp_off_n: {
    label: "Group Policy's setting off on", icon: 'warning', desc: 'Hosts where a direction Group Policy turns on (Success or Failure) is off in the policy in force, and no legacy audit category explains it: the policy was changed on the host after Group Policy applied it (LOGINT-AUDIT-GPO-NOT-IN-FORCE). Expand the row for which.', render: (v) => countCell(v, 'sev-medium'),
    one: { label: "Group Policy's setting in force", desc: 'Whether every direction Group Policy turns on is on in the policy in force - "off" is LOGINT-AUDIT-GPO-NOT-IN-FORCE.', render: (v, row) => (v ? h('span', { class: 'tagtext sev-medium' }, 'off on this host') : row.group_policy ? h('span', { class: 'tagtext st-ran' }, 'in force') : '—') },
  },
  log_name: { label: 'Log', icon: 'scroll', desc: 'The event log (its channel name).', render: (v) => mono(v) },
  log_recording: {
    label: 'Recording', icon: 'status', desc: 'Whether the log records now: yes; "no - turned off" (Windows, or the product that adds it, records to it from the start - LOGINT-LOG-TURNED-OFF); off from the start on some Windows versions; not on this host (the product is not installed); unknown, with why.',
    render: (v) => (String(v).startsWith('no - ') ? h('span', { class: 'tagtext sev-medium' }, v) : v === 'yes' ? h('span', { class: 'tagtext st-ran' }, v) : v || '—'),
  },
  log_read_by: { label: 'Read by', icon: 'module', wrap: true, desc: 'The Signal modules that read the log, and what for - what is missing while it does not record.' },
  log_size_mb: { label: 'Size (MB)', icon: 'value', desc: 'The log file\'s size now.' },
  log_max_mb: { label: 'Maximum (MB)', icon: 'layers', desc: 'The log\'s configured maximum size.' },
  log_when_full: { label: 'When full', icon: 'outcome', wrap: true, desc: 'What the log does when it reaches its maximum: overwrite its oldest records, or keep them (archive or stop recording).' },
  log_records: { label: 'Records', icon: 'matches', desc: 'The records the log holds now.' },
  log_oldest: { label: 'Oldest record', icon: 'firstSeen', desc: 'The time of the log\'s oldest record - how far back it reaches.', render: (v) => (v ? when(v) : '—') },
  log_window: { label: 'Window (days)', icon: 'clock', desc: 'How many days before the collection the log\'s oldest record is.' },
  log_setting: { label: 'Setting', icon: 'policy', desc: "The logging setting: the Security log's maximum size, what it does when full, and whether legacy audit categories or the subcategory settings win." },
  layer_local: { label: 'Local', icon: 'hosts', wrap: true, desc: "The setting's own value on the host (the log's own registry key); \"not read\" where Windows keeps it in a database Signal does not read." },
  layer_gp: { label: 'Group Policy', icon: 'layers', wrap: true, desc: 'What Group Policy sets: Administrative Templates (the policy key) and the security templates Group Policy applied; "not set" where neither does.' },
  layer_in_force: { label: 'In force', icon: 'status', wrap: true, desc: 'What the host does now, as Windows reports it (the Event Log service, LSA).' },
  layer_decided_by: { label: 'Decided by', icon: 'target', wrap: true, desc: "Which layer decides the value, by Windows' own precedence - the event logs' policy key overrides a log's own setting; a security template writes the log's own setting; SCENoApplyLegacyAuditPolicy decides between legacy categories and subcategories - and which GPOs can have set it." },
  event_ids: { label: 'Event IDs', icon: 'matches', desc: 'The event IDs the subcategory produces: (S) with Success auditing, (F) with Failure, (S,F) either - one line each.', wrap: true, render: (v) => lines(v, / (?=\()/, mono) },
  event_id: { label: 'Event ID', icon: 'id', desc: 'The Windows Security event ID.' },
  audit_changes: {
    label: 'Change', icon: 'outcome', desc: 'What the change did: Success or Failure auditing added (green) or removed (amber - the subcategory\'s events stop from then on).',
    render: (v) => (/removed/i.test(v || '') ? h('span', { class: 'tagtext sev-medium' }, v) : /added/i.test(v || '') ? h('span', { class: 'tagtext st-ran' }, v) : v || '—'),
  },
  audit_via: { label: 'How', icon: 'layers', desc: 'Group Policy (the computer\'s own account applying a policy) or an account changing it directly - which is a signal (SECLOG-POLICY-CHANGED).' },
  subcategories: {
    label: 'Subcategories', icon: 'folder', wrap: true, render: (v) => lines(v, /;\s*/),
    desc: 'The audit subcategories that produce the event - or, in parentheses, "always logged" and what it means: Windows writes such an event whenever its condition occurs, whatever the audit policy (1100 the Event Log service shut down, 1102 the log was cleared, 1104 the log is full...).',
  },
  expected_n: {
    label: 'Expected on', icon: 'target', desc: 'Hosts whose effective audit policy should produce this event. An always-logged event is never expected: it is written when its condition occurs.',
    one: { label: 'Expected', desc: 'Whether the host\'s effective audit policy should produce this event.', render: (v) => mark(v, { yesCls: '', noCls: null, yes: 'expected by the policy', no: 'not expected' }) },
  },
  present_n: {
    label: 'Present on', icon: 'eye', desc: 'Hosts whose log contains the event.', render: (v) => countCell(v, 'ev-ok'),
    one: { label: 'Present', desc: 'Whether the host\'s log contains the event.', render: (v) => mark(v, { yesCls: 'ev-ok', noCls: null, yes: 'in the log', no: 'not in the log' }) },
  },
  absent_n: {
    label: 'Expected but absent on', icon: 'notEvaluated', desc: 'Hosts whose policy should produce the event but whose log does not contain it: a logging gap, or a cleared log. Expand the row for which.', render: (v) => countCell(v, 'ev-absent'),
    one: { label: 'Expected but absent', desc: 'The host\'s policy should produce the event, but its log does not contain it: a logging gap, or a cleared log.', render: (v) => (v ? h('span', { class: 'tagtext ev-absent' }, 'absent') : '—') },
  },
  policy_off_n: {
    label: 'Present with policy off on', icon: 'status', desc: 'Hosts whose log contains the event although their current policy does not produce it: the policy changed after it was logged. Expand the row for which.', render: (v) => countCell(v, 'ev-present_policy_off'),
    one: { label: 'Present with policy off', desc: 'The host\'s log contains the event although its current policy does not produce it: the policy changed after it was logged.', render: (v) => (v ? h('span', { class: 'tagtext ev-present_policy_off' }, 'policy off') : '—') },
  },
  // Identities
  value: { label: 'Value', icon: 'value', desc: 'The address, account or computer name.' },
  flagged: { label: 'Flagged', icon: 'flagged', wrap: true, desc: 'A red flag: a rule\'s signal names it on one of its hosts, the console flagged it by one of its rules, or an analyst flagged it (each reason is written under the flag: the Signal rule and its title, the console\'s rule and reason, the analyst and theirs; an analyst clicks to flag, giving the reason, or to unflag - fleet-wide, listed in Overview\'s Flagged items). Filter by flagged / not flagged. While any row is flagged, the header flag rings.', render: (_v, row) => flagCell(row), alarm: (row) => row.flagged === 'flagged' },
  // Telemetry coverage (Overview): true - the setting is on, the log was
  // read; false - it is not; unknown - not determined, or not collected.
  telemetry_item: { label: 'Item', icon: 'eye', wrap: true, desc: 'What a module\'s detection depends on: an audit setting, a logging setting, a log\'s health, a protection, an operating system feature. Hover for what its state means.', render: (v, row) => h('span', { title: row.detail || '' }, v) },
  telemetry_true: { label: 'True', icon: 'success', desc: 'Hosts where it is true: the setting is on, the log was read in full.', render: (v) => countCell(v, 'st-ran') },
  telemetry_false: { label: 'False', icon: 'failure', desc: 'Hosts where it is false: the setting is off, or the log is turned off.', render: (v) => countCell(v, 'sev-high') },
  telemetry_absent: { label: 'Not on host', icon: 'ruleOff', desc: 'Hosts that do not have its source - no web site, no firewall log file, a log that does not exist: neither true (it is not there) nor false (nothing is turned off).', render: (v) => countCell(v, 'mut') },
  telemetry_unknown: { label: 'Unknown', icon: 'notEvaluated', desc: 'Hosts where it could not be determined, or a collection that does not report it - never counted as false.', render: (v) => (v ? String(v) : h('span', { class: 'mut' }, '0')) },
  telemetry_bar: { label: 'Hosts', icon: 'hosts', desc: 'True, false and unknown across the hosts.', filter: false, render: (_v, row) => stackBar([[row.yes, 'yes', 'true'], [row.no, 'no', 'false'], [row.unknown, 'unknown', 'unknown']]) },
  telemetry_state: { label: 'State', icon: 'status', desc: 'True: the setting is on, the log was read in full. False: it is off, or the log is turned off. Not on host: the host does not have its source (no web site, no firewall log file, a log that does not exist). Unknown: it could not be determined - never counted as false.', render: (v) => h('span', { class: v === 'True' ? 'tagtext st-ran' : v === 'False' ? 'tagtext sev-high' : 'mut' }, v) },
  telemetry_detail: { label: 'What it means', icon: 'details', wrap: true, desc: 'What the state means for an investigation, as the module states it.', render: (v) => v || '—' },
  note_at: { label: 'When', icon: 'clock', desc: 'When the analyst recorded the decision and its note (UTC).', render: (v) => ts(v) },
  note_by: { label: 'Analyst', icon: 'user', desc: 'The account that recorded it.', render: (v) => v || '—' },
  note_entity: { label: 'About', icon: 'target', wrap: true, desc: 'What the decision is about: an entity on a host (covering its signals at the time), or one signal about no entity.', render: (v, row) => (row.run_id ? pageLink('signals', { entity: row.entity_id, host: row.run_id }, v) : mono(v)) },
  note_rules: { label: 'Rules', icon: 'scroll', desc: 'The rules whose signals the entity or signal has.', render: (v) => (v ? truncatedList(v.split(', '), 3, mono) : '—') },
  note_covers: { label: 'Signals', icon: 'count', desc: 'How many signals the decision covered when it was made.' },
  note_text: { label: 'Note', icon: 'details', wrap: true, desc: "The analyst's note: what was found and why it was decided so - every decision has one." },
  flag_at: { label: 'Flagged at', icon: 'clock', desc: `When the analyst flagged it (UTC).`, render: (v) => ts(v) },
  flag_item: { label: 'Item', icon: 'target', wrap: true, desc: 'What was flagged, as its page names it.', render: (v) => mono(v) },
  flag_where: { label: 'Where', icon: 'layers', desc: 'The page and table it was flagged on; opens the page.', render: (v, row) => (row.page ? pageLink(row.page, {}, v) : v) },
  flag_by: { label: 'Flagged by', icon: 'user', desc: 'The analyst who flagged it, or the console (by one of its own rules).', render: (v, row) => (row.source === 'console' ? h('b', {}, 'Console') : v) },
  flag_rule: { label: 'Console rule', icon: 'scroll', desc: "The console's rule that flagged it - empty for an analyst's flag.", render: (v) => (v ? mono(v) : '—') },
  flag_reason: { label: 'Reason', icon: 'details', wrap: true, desc: "Why it was flagged: the analyst's reason, or the console rule's.", render: (v) => v || '—' },
  app_kev: { label: 'Known exploited (CISA)', icon: 'warning', wrap: true, desc: "CVEs CISA's Known Exploited Vulnerabilities catalog lists for this application's product (matched by name and publisher) whose affected versions, as NIST's NVD gives them, include an installed version - with what each is. A CVE whose versions could not be compared (not looked up yet, no range for the product, a version that is not a number) is counted apart, never flagged.", render: (v, row) => h('span', {}, v ? truncatedList(v.split('; '), 3, (x) => h('span', { class: 'sev-high' }, x)) : '—', row.kev_unchecked ? h('div', { class: 'mut' }, `${row.kev_unchecked} listed CVE${row.kev_unchecked === 1 ? '' : 's'} not compared with the version`) : null) },
  app_name: { label: 'Application', icon: 'apps', desc: 'The application\'s name as its installer recorded it (one row per name and publisher across the hosts).', render: (v) => mono(v) },
  publisher: { label: 'Publisher', icon: 'value', desc: 'The publisher as the installer wrote it - not checked against any signature.', render: (v) => v || '—' },
  app_versions: { label: 'Versions', icon: 'version', desc: 'Every version recorded on the hosts.', render: (v) => truncatedList(v ? v.split(',') : []) },
  app_location: { label: 'Folder', icon: 'folder', desc: 'The install folder(s) as recorded; empty when the installer recorded none.', render: (v) => (v ? truncatedList(v.split(','), 3, mono) : '—') },
  installed: { label: 'Installed', icon: 'firstSeen', desc: 'The earliest install date the hosts record - a day written by the installer, so it can be absent or wrong.', render: (v) => (v ? ts(v).slice(0, 10) : '—') },
  app_user: { label: 'For user', icon: 'user', desc: 'The users it is installed for, when it is in a user\'s registry; empty: for the machine.', render: (v) => (v ? truncatedList(v.split(','), 3, mono) : 'machine') },
  web_server: { label: 'Server', icon: 'webserver', desc: 'The web server: IIS, Apache httpd, nginx or Apache Tomcat.' },
  web_versions: { label: 'Version', icon: 'version', desc: "The server's version on each host: IIS's from its registry key, the others' from their program's version resource.", render: (v) => v || '—' },
  web_site: { label: 'Site', icon: 'webapp', wrap: true, desc: "IIS's site name, or the configuration file a document root is declared in for the other servers.", render: (v) => mono(v) },
  web_roots: { label: 'Folders served', icon: 'folder', wrap: true, desc: 'Each application or virtual directory: its URL path and its folder on disk.', render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : '—') },
  web_bindings: { label: 'Listens on', icon: 'server', wrap: true, desc: 'Where the configuration says it listens: protocol, address, port, host name. Configured - not proof the port is open now.', render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : '—') },
  web_identities: { label: 'Runs as', icon: 'user', wrap: true, desc: "The account the site's code runs as - an IIS pool's identity, the service's account otherwise. A webshell runs as this account; LocalSystem is the computer itself.", render: (v) => (v ? truncatedList(v.split('; '), 3, (x) => (/LocalSystem/.test(x) ? h('b', { class: 'tagtext sev-medium' }, x) : x)) : '—') },
  web_holds: { label: 'Holds', icon: 'apps', wrap: true, desc: 'What its files are, by the server-side script types found, and the products recognised by their folders (Exchange, SharePoint).', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  web_files: { label: 'Examined', icon: 'details', wrap: true, desc: 'The files walked and the server-side scripts among them, per host - and whether the walk stopped at its limit (the rest not examined).', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  web_last_deployment: { label: 'Last deployment', icon: 'firstSeen', desc: "The newest time five or more of its files were written within ten minutes - its last deployment, as the files' times record it.", render: (v) => when(v) },
  web_running: { label: 'Running now', icon: 'terminal', wrap: true, desc: "Its worker processes in the process table when Signal ran (IIS starts a pool's worker on its first request - none running is not unusual).", render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : '—') },
  web_flagged: { label: 'Scripts with indicators', icon: 'flagged', wrap: true, desc: 'How many of its scripts carry a webshell indicator, by confidence, per host.', render: (v) => (v ? truncatedList(v.split('; '), 3, (x) => h('b', { class: 'tagtext sev-high' }, x)) : '—') },
  web_detections: { label: 'Antivirus detections', icon: 'shield', wrap: true, desc: "The antivirus's detections of files in its folders: threat, file, time, what the product did.", render: (v) => (v ? truncatedList(v.split('; '), 3, (x) => h('b', { class: 'tagtext sev-high' }, x)) : '—') },
  web_file: { label: 'Script', icon: 'file', wrap: true, desc: "The script's path - one row per path across the hosts.", render: (v) => mono(v) },
  web_sites: { label: 'Site', icon: 'webapp', wrap: true, desc: 'The server and site it is in, per host.', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  web_urls: { label: 'URL', icon: 'link', wrap: true, desc: 'The URL path it is served at - what a request for it names in the request log.', render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : '—') },
  web_confidence: { label: 'Confidence', icon: 'severity', desc: 'How strongly its indicators together point to a webshell: high, medium or low - an assessment for triage, not a verdict. Its content is not read.', render: (v) => (v ? h('b', { class: `tagtext sev-${v === 'high' ? 'high' : v === 'medium' ? 'medium' : 'low'}` }, v) : '—') },
  web_indicators: { label: 'Indicators', icon: 'warning', wrap: true, desc: "Each indicator: written alone after the site's last deployment, in an upload, image or temporary folder, the only script among static files, a hidden or system attribute, a disguised name, requested with POST, detected by the antivirus, written inside the period.", render: (v) => (v ? truncatedList(v.split('; '), 4) : '—') },
  web_requests: { label: 'Requests', icon: 'logon', wrap: true, desc: "What the site's request log (IIS) records of it in the part read: count, methods, statuses, client addresses, first and last. None found is not never requested.", render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  web_created: { label: 'Created', icon: 'firstSeen', desc: 'The earliest creation time across the hosts, as the file system records it (the time can be changed by whoever can write the file).', render: (v) => when(v) },
  web_modified: { label: 'Modified', icon: 'clock', desc: 'The latest write time across the hosts, as the file system records it.', render: (v) => when(v) },
  ra_path_kind: { label: 'Way in', icon: 'key', wrap: true, desc: "Which of Windows' own ways in: a port forward (netsh portproxy), an SSH key authorized for the administrators or a user, a WinRM listener or relaxation, the WinRM client's trusted hosts, Remote Assistance, Remote Desktop shadowing." },
  ra_path_value: { label: 'Configured', icon: 'value', wrap: true, desc: "The setting as configured: a forward's listening and target address/port, a key's type, SHA-256 fingerprint and comment (never the key), a value's data.", render: (v) => mono(v) },
  ra_path_detail: { label: 'What it allows', icon: 'details', wrap: true, desc: 'What the setting allows, in words, and its options (a key\'s restrictions, whether the service is installed and runs).', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  ra_path_user: { label: 'For user', icon: 'user', desc: 'The account it is for (a user\'s authorized keys); empty: the machine.', render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : 'machine') },
  ra_path_changed: { label: 'Last written', icon: 'clock', desc: 'The latest write of the key or file holding it across the hosts - the setting\'s change, or another one beside it.', render: (v) => when(v) },
  ra_path_where: { label: 'Kept in', icon: 'folder', wrap: true, desc: 'The registry key or file it was read from.', render: (v) => (v ? truncatedList(v.split('; '), 2, mono) : '—') },
  ra_product: { label: 'Product', icon: 'remote', desc: 'The remote access product, by Signal\'s catalog name - the same on every host. Identified by its program\'s version resource first, so a renamed copy is still the product.', render: (v) => mono(v) },
  ra_kind: { label: 'Kind', icon: 'module', desc: 'Remote control, remote support (a person invited to connect) or an RMM agent (an organisation\'s console reaches the host through it).' },
  ra_modes: { label: 'How it is here', icon: 'status', wrap: true, desc: 'Installed (an installation, a service, its install folder), portable (it ran, or left its files, from outside any install location with no installation), installed and portable (a second copy beside the installed one), or traces only (its files remain, no program or installation found) - per host.', render: (v) => truncatedList(v ? v.split('; ') : [], 3, (x) => (x.includes('portable') ? h('b', { class: 'tagtext sev-high' }, x) : x)) },
  ra_installed: { label: 'Installed', icon: 'apps', wrap: true, desc: 'What records it as installed on the hosts: an installed application (date, for whom), a service, its install folder, Windows Installer.', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  ra_portable: { label: 'Portable copies', icon: 'folder', wrap: true, desc: 'Each copy that ran or left its files outside an install location: path, kind of folder, who ran it, how often and when, whether the file is still there. A copy that ran only before the installation is the installer and says so.', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  ra_first_seen: { label: 'First seen', icon: 'firstSeen', desc: 'The earliest time any host records it: an install date, a folder\'s creation, a run, a log line. Earlier presence may have left no record.', render: (v) => when(v) },
  ra_last_seen: { label: 'Last seen', icon: 'clock', desc: 'The latest time any host records it in use: a run, a log line, a running process.', render: (v) => when(v) },
  ra_accounts: { label: 'Account', icon: 'user', wrap: true, desc: 'The account signed in to it or that enrolled it, from its configuration - who controls it from the vendor\'s side. Blank: none recorded, or its configuration is not read.', render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : '—') },
  ra_tenants: { label: 'Tenant', icon: 'layers', wrap: true, desc: 'The organisation or group it is enrolled to, from its configuration.', render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : '—') },
  ra_servers: { label: 'Server', icon: 'server', wrap: true, desc: 'The server it is configured to report to - one that is not the vendor\'s is an organisation\'s own, or someone\'s (RA-CUSTOM-SERVER).', render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : '—') },
  ra_unattended: { label: 'Unattended access', icon: 'key', desc: 'On how many of its hosts its configuration holds an unattended access password or key - someone can connect without a person accepting. The value is never read.', render: (v) => (v ? h('b', { class: 'tagtext sev-medium' }, `set on ${v}`) : '—') },
  ra_sessions: { label: 'Sessions', icon: 'logon', wrap: true, desc: 'The sessions its logs record on each host: incoming and outgoing, peers, span. Blank: none recorded, or Signal does not read this product\'s logs yet - unknown, not none.', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  ra_allowed: { label: 'Approved', icon: 'success', wrap: true, desc: 'Whether the analyst\'s approved list (RemoteAccess.allowed) includes it, per host. Blank: no list was given - authorization unknown, never assumed.', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  ra_peer_id: { label: 'Peer ID', icon: 'peer', desc: 'The product\'s ID for the other side of a session - the same whichever host it connects to.', render: (v) => mono(v) },
  ra_peer_names: { label: 'Name it gave', icon: 'title', wrap: true, desc: 'The names the other side gave itself, as the logs record them - chosen by that side.', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  ra_addresses: { label: 'Addresses recorded', icon: 'globe', wrap: true, desc: 'The addresses the product recorded for its connections - the other side\'s, or the vendor\'s relay it came through.', render: (v) => (v ? truncatedList(v.split('; '), 3, mono) : '—') },
  ra_sessions_n: { label: 'Sessions', icon: 'logon', desc: 'How many sessions with it the logs record across the selected hosts.' },
  ra_incoming_n: { label: 'Incoming', icon: 'logon', desc: 'How many of them were incoming - the other side controlling the host.', render: (v) => (v ? h('b', { class: 'tagtext sev-medium' }, String(v)) : '0') },
  ra_first_start: { label: 'First session', icon: 'firstSeen', desc: 'The earliest session start recorded.', render: (v) => when(v) },
  ra_last_start: { label: 'Latest session', icon: 'clock', desc: 'The latest session start recorded.', render: (v) => when(v) },
  ra_with_transfers: { label: 'With file transfers', icon: 'file', desc: 'How many of its sessions moved files, as the logs record them.', render: (v) => (v ? h('b', { class: 'tagtext sev-high' }, String(v)) : '0') },
  ra_auths: { label: 'How allowed', icon: 'key', wrap: true, desc: 'How its sessions were allowed, as the product records it: accepted at the screen, the unattended password, a saved token.', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  gpo_names: { label: 'GPO', icon: 'policy', wrap: true, desc: 'The GPO\'s display name as each host recorded it - a member\'s from when Group Policy applied it, a domain controller\'s from GPT.INI when the GPO does not apply to it (which the Group Policy tools do not keep current). Chosen by whoever created it.', render: (v) => truncatedList(v ? v.split('; ') : [], 3) },
  gpo_guid: { label: 'GUID', icon: 'id', desc: 'The GPO\'s GUID - its identity in the directory and its folder in SYSVOL; the same on every host of a domain.', render: (v) => mono(v) },
  gpo_status: { label: 'Domain status', icon: 'notEvaluated', wrap: true, desc: 'Whether the GPO is in the SYSVOL of a domain controller of its domain among the selected hosts. "Not in its domain controller\'s SYSVOL": a member applied it, and a controller collected after that does not have it - deleted, or not replicated there. Blank: no domain controller of its domain was collected.', render: (v) => (v ? (v.startsWith('not in') ? h('b', { class: 'tagtext sev-medium' }, v) : v) : '—') },
  gpo_deploys: { label: 'Deploys', icon: 'layers', wrap: true, desc: 'What the GPO deploys, counted by kind (tasks, scripts, file copies, services, registry values...) - each thing is listed in the host\'s Directory tables and read by the rules.', render: (v) => truncatedList(v ? v.split('; ') : [], 3) },
  gpo_links: { label: 'Linked to', icon: 'link', wrap: true, desc: 'Where the GPO is linked as far as the hosts know - the link through which it applied, or a link the domain controller\'s Security log recorded. Blank: not known (Signal never queries the directory) - never "not linked".', render: (v) => truncatedList(v ? v.split('; ') : [], 3, mono) },
  gpo_extensions: { label: 'How it acts', icon: 'module', wrap: true, desc: 'The Group Policy client-side extensions that process it (Scheduled Tasks preferences, Scripts, Registry...).', render: (v) => truncatedList(v ? v.split('; ') : [], 3) },
  gpo_versions: { label: 'Versions', icon: 'version', desc: 'The GPO\'s versions as the hosts recorded them: each edit of its computer or user settings adds one. Different versions on two hosts: one has not applied the latest edit.', render: (v) => truncatedList(v ? v.split('; ') : [], 3) },
  gpo_changed_by: { label: 'Changed by', icon: 'user', wrap: true, desc: 'Who created, edited or linked it and when, from a domain controller\'s Security log - only with Directory Service Changes auditing on.', render: (v) => (v ? truncatedList(v.split('; '), 3) : '—') },
  gpo_created: { label: 'Folder created', icon: 'clock', desc: 'When its folder was created in a domain controller\'s SYSVOL (or arrived there by replication).', render: (v) => when(v) },
  gpo_changed: { label: 'Last edited', icon: 'clock', desc: 'When its GPT.INI was last written in a domain controller\'s SYSVOL - every edit with the Group Policy tools raises its version there.', render: (v) => when(v) },
  gpo_applied: { label: 'Last applied', icon: 'clock', desc: 'The latest time a member\'s Group Policy recorded applying it (the last change of what applied, not each refresh).', render: (v) => when(v) },
  ext_names: { label: 'Extension', icon: 'puzzle', wrap: true, desc: 'The extension\'s name as its manifest declares it - chosen by its author, so it can imitate another\'s (one row per ID across the hosts; every name it had listed).', render: (v) => truncatedList(v ? v.split(',') : [], 3, mono) },
  ext_id: { label: 'ID', icon: 'id', desc: 'The extension\'s ID: the same in every Chromium-based browser (32 letters); for Firefox the add-on\'s ID.', render: (v) => mono(v) },
  ext_browsers: { label: 'Browsers', icon: 'globe', desc: 'The browsers it is installed in, on the hosts.', render: (v) => truncatedList(v ? v.split(',') : []) },
  ext_installed_by: { label: 'Installed by', icon: 'layers', wrap: true, desc: 'How the browsers record it was installed: store; package file (not a store); policy; external program; unpacked folder; command line; temporary (debugging).', render: (v) => truncatedList(v ? v.split(',') : []) },
  in_period: { label: 'In the period', icon: 'clock', desc: 'Whether it was installed (a GPO: created, changed or applied) in the period the scoping profile gave, on at least one of the hosts - by Signal. "no" also when a host was given no period, or ran a Signal before 0.60.0 (applications, extensions).' },
  ext_installed: { label: 'Installed', icon: 'firstSeen', desc: `The earliest time a browser recorded it was first installed, on the hosts (UTC).`, render: (v) => (v ? ts(v) : '—') },
  ext_capabilities: { label: 'May', icon: 'warning', wrap: true, desc: 'What its permissions let it do (read and change every site, read cookies, see or block web requests, debug pages, talk to programs on this computer, change the proxy, manage other extensions, read browsing history) - what it may do, not what it did.', render: (v) => (v ? truncatedList([...new Set(v.split(/[;,] ?/).map((x) => x.trim()).filter(Boolean))], 4) : '—') },
  ext_update_url: { label: 'Updates from', icon: 'globe', wrap: true, desc: 'Where the browsers fetch its updates from - whoever runs that server can change it; blank for none.', render: (v) => (v ? truncatedList(v.split(','), 2, mono) : '—') },
  ext_forced_by: { label: 'Forced by', icon: 'shield', wrap: true, desc: 'The policy value forcing it on the browser (ExtensionInstallForcelist); blank when none does.', render: (v) => (v ? truncatedList(v.split(','), 2, mono) : '—') },
  ext_user: { label: 'Users', icon: 'user', desc: 'The Windows accounts whose browser profiles have it.', render: (v) => (v ? truncatedList(v.split(','), 3, mono) : '—') },
  net_protocol: { label: 'Protocol', icon: 'layers', desc: 'TCP or UDP.' },
  net_address: { label: 'Address', icon: 'globe', desc: 'For a listener, the address it listens on (0.0.0.0 and :: are every address the host has); for an Internet address, the other end.', render: (v) => mono(v) },
  net_port: { label: 'Port', icon: 'id', desc: 'For a listener, the port it listens on; for an Internet address, the other end\'s port.', render: (v) => mono(v) },
  net_program: { label: 'Program', icon: 'terminal', wrap: true, desc: 'The program of the process that held it, as the source names it - a drive path, a device path (Security 5156), or a name only (System, or a process Signal could not open). Blank when no source names it (the firewall\'s log).', render: (v) => (v ? mono(v) : '—') },
  net_records: { label: 'Records', icon: 'count', desc: 'Records of it across the selected hosts: one per connection each source recorded (a connection two sources saw is two), and one for each open at the collection.', render: (v) => (v ?? 0).toLocaleString() },
  net_seen_in: { label: 'Seen in', icon: 'dataset', desc: 'Where it was seen: open now (the host\'s connection table at the collection), Security 5156, Sysmon 3, the firewall\'s log.' },
  location: { label: 'Location', icon: 'layers', desc: 'Where the entry is configured: a service or driver, a scheduled task, a Run key, a logon script, Winlogon, IFEO, an LSA package, a COM override, a Startup folder, a PowerShell profile, a WMI subscription...' },
  entry: { label: 'Entry', icon: 'value', wrap: true, desc: 'What it is configured under: the service\'s key name, the task\'s path, the registry value\'s name, the file\'s name.', render: (v) => mono(v) },
  command: { label: 'Runs', icon: 'terminal', wrap: true, desc: 'What it runs, exactly as configured (environment variables unexpanded).', render: (v) => (v ? mono(v) : '—') },
  signer: { label: 'Signer', icon: 'shield', wrap: true, desc: 'Who signed the code it runs (the service\'s DLL, for a svchost service), as its signature names it; blank when unsigned or not checked.', render: (v) => v || '—' },
  signature: {
    label: 'Signature', icon: 'evaluated', desc: 'Whether the code\'s signature verifies: valid, invalid (signed, but it does not verify), unsigned, not found (no such file); blank when it could not be checked.',
    render: (v) => (v ? h('span', { class: 'tagtext ' + (v === 'valid' ? 'st-ran' : 'sev-medium') }, v) : '—'),
  },
  sha256: { label: 'SHA-256', icon: 'key', wrap: true, desc: 'The SHA-256 of the program at its path when Signal ran (Signal 0.29.0 and later); opens it in VirusTotal. Blank when the file was not found or not read.', render: (v) => (v ? virusTotalLink('SHA256', v) : '—') },
  exclusion: { label: 'Exclusion', icon: 'folder', wrap: true, desc: 'What the antivirus does not scan, exactly as configured: a path, a process, a file extension or an address - environment variables and wildcards unexpanded.', render: (v) => mono(v) },
  exclusion_kind: { label: 'Kind', icon: 'layers', desc: 'path: a file or folder; process: files the process opens; extension: files with it; ip address: network inspection of it.' },
  product: { label: 'Product', icon: 'shield', desc: 'The antivirus product the exclusion is configured in.' },
  exclusions_n: {
    label: 'Exclusions', icon: 'count', desc: 'The exclusions configured in the host\'s antivirus now; unknown when Signal could not read them (Defender shows them only to administrators) - never "none".',
    render: (v, row) => (row.state === 'read' ? countCell(v, v ? 'sev-medium' : '') : h('span', { class: 'tagtext ev-absent', title: row.reason }, row.state === 'unknown' ? 'unknown' : 'not collected')),
  },
  exclusion_reason: { label: 'Why unknown', icon: 'reason', wrap: true, desc: 'Why the host\'s exclusions are not known.', render: (v) => v || '—' },
  datasets: { label: 'Datasets', icon: 'dataset', desc: 'The module/dataset tables it was found in.', wrap: true, render: (v) => truncatedList(v) },
  // Fleet-wide inventories (Autoruns, Applications, Network, Protection, Audit Policy)
  flagged_by: { label: 'Flagged by', icon: 'flagged', desc: 'The rules that matched this on at least one host; each opens the rule on the Rules page.', wrap: true, render: (_v, row) => ruleLinks(row.flagged_by) },
  // Entities (Entities page, a host's entities)
  entity_type: { label: 'Type', icon: 'layers', desc: 'What kind of thing the entity is: a program, a file, an account, a service, a scheduled task, an address, a log, a security product, a threat, a WMI consumer, an installed application, a network setting (a hosts entry, a proxy, a share), a browser extension, a site (domain), a Group Policy object, a directory object (an object of the domain changed on a domain controller), a remote access tool (a product on a host), a remote peer (the other side of a remote access session, by the product\'s ID for it).' },
  entity_name: { label: 'Entity', icon: 'target', wrap: true, desc: 'What the signals are about, as a host recorded it. One row is one thing: the same program, account or task by one normalised key on every host (a path without letter case or prefixes, an account by its SID).', render: (v) => mono(v) },
  entity_hashes: { label: 'SHA-256s', icon: 'key', desc: 'How many different SHA-256s its file has across the hosts (Signal 0.33.0 and later): one path with more than one is a different file under the same name - worth a look.', render: (v) => (v > 1 ? h('b', { class: 'tagtext sev-medium' }, String(v)) : v ? '1' : '—') },
  open_n: { label: 'Open signals', icon: 'signals', desc: 'Signals about it that are open - not triaged benign, not suppressed - of all its signals.', render: (v, row) => countCell(`${v} of ${row.signals_n}`, v ? 'sev-' + row.severity : 'result-ok') },
  entity_matches: { label: 'Matches', icon: 'matches', desc: 'How many rule matches its signals stand for, on every host.', render: (v) => (v ?? 0).toLocaleString() },
  entity_rules: { label: 'Rules', icon: 'id', wrap: true, desc: 'The rules that matched it, from every module; each opens on the Rules page.', render: (v) => truncatedList(String(v || '').split('; ').filter(Boolean), 4, (id) => pageLink('rules', { rule: id }, id)) },
  caveats_n: { label: 'Caveats', icon: 'warning', desc: 'Evidence its signals came from that was not read completely on a host: there may be more about it than shown.', render: (v) => (v ? h('span', { class: 'tagtext sev-medium' }, String(v)) : '—') },
  seen_n: { label: 'Seen on', icon: 'coverage', desc: 'How many hosts it was seen on.', one: null },
  host_names: { label: 'Hosts', icon: 'hosts', desc: 'The hosts it was seen on; each opens that host\'s page.', wrap: true, render: (_v, row) => hostLinks(row.hosts), one: null },
  // Profiles (the Profiles page)
  profile_name: { label: 'Name', icon: 'title', desc: 'The profile\'s name, as written in it.' },
  profile_saved: { label: 'Saved here', icon: 'dataset', desc: 'Whether this console holds the profile itself. A profile the hosts were given that is not saved here is known only by its name and hash, from their runs.', render: (v) => mark(v, { no: 'not saved here' }) },
  profile_window: { label: 'Window', icon: 'clock', desc: 'Where the investigation\'s focus starts: a time, or a duration back from each run.', render: (v) => v || '—' },
  pivots_n: { label: 'Pivot points', icon: 'target', desc: 'How many pivot points the profile holds (unknown for a profile not saved here).', render: (v) => (v == null ? 'unknown' : String(v)) },
  profile_hosts: { label: 'Hosts given it', icon: 'hosts', desc: 'The hosts whose latest collection was given this profile; each opens that host\'s page.', wrap: true, render: (_v, row) => (row.hosts.length ? hostLinks(row.hosts) : '—') },
  saved_by: { label: 'Saved by', icon: 'user', desc: `Who saved it here, and when (UTC).`, render: (v, row) => (v ? `${v}, ${ts(row.saved_at)}` : '—') },
  profile_sha256: { label: 'SHA-256', icon: 'key', desc: 'The SHA-256 of the profile\'s JSON as written - what each run reports, so a run finds its profile here.', render: (v) => mono(v) },
};

export function col(key, name = key, overrides = {}) {
  return { key, ...COLUMNS[name], ...overrides };
}

// forHosts adjusts columns to how many hosts are in view: with one, every
// column that counts hosts takes its one-host form (see COLUMNS), and those
// with nothing to say about a single host are dropped; with more, the
// columns are the fleet's - counts, statistics - as defined.
export function forHosts(columns, hostCount) {
  if (hostCount !== 1) return columns;
  return columns.filter((c) => c.one !== null).map((c) => (c.one ? { ...c, ...c.one } : c));
}

// telemetryCoverage is, per item the modules' detection depends on, one
// tab per category (like the audit policy): for several hosts, on how many
// it is true, false or undetermined; for one host, its state - with what
// it means (a host's own items: on, off or unknown). Its page has other panels, so each table scrolls in its frame.
export function telemetryCoverage(items, hosts) {
  if (!items.length) return h('div', { class: 'mut' }, 'No module reported telemetry.');
  const intro = h('p', { class: 'mut card-intro' },
    'Many signals come from events Windows writes only when it is set to - those rules depend on the items below. Others read the host\'s current state (running processes, accounts, profiles, sessions) and need only a running host, so they do not appear here.');
  const columns = hosts === 1
    ? [col('label', 'telemetry_item'), col('state', 'telemetry_state'), col('detail', 'telemetry_detail')]
    : [col('label', 'telemetry_item'), col('yes', 'telemetry_true'), col('no', 'telemetry_false'), col('absent', 'telemetry_absent'), col('unknown', 'telemetry_unknown'), col('yes', 'telemetry_bar')];
  const rows = items.map((t) => {
    const yes = t.yes ?? t.state === 'on', no = t.no ?? t.state === 'off', absent = t.absent ?? t.state === 'absent';
    return { ...t, category: t.category || 'Other', state: yes ? 'True' : no ? 'False' : absent ? 'Not on host' : 'Unknown', detail: t.detail || '' };
  });
  const categories = [...new Set(rows.map((t) => t.category))];
  return h('div', {}, intro, tabbedPanel(categories.map((c) => {
    const mine = rows.filter((t) => t.category === c);
    return { id: c, title: c, count: mine.length, build: () => dataTable(mine, columns, { height: 'scroll', filename: `telemetry_${c.toLowerCase().replace(/[^a-z]+/g, '_')}` }) };
  }), 'sub'));
}

// sourcesView is the evidence sources: for one host (rows of its run's
// sources), each with whether it was read, its records, the time they span,
// its prerequisites and why it was not read; across hosts (rows with
// per-status host counts), how many hosts read each completely, partly, not
// at all or do not have it, with the records across them.
export function sourcesView(sources, name) {
  if (!sources.length) return h('div', { class: 'mut' }, 'Not recorded - collected by a Signal older than 0.6.0.');
  const span = [
    col('oldest', 'first_seen', { label: 'Oldest', desc: `The earliest record of this evidence (UTC).` }),
    col('newest', 'last_seen', { label: 'Newest', desc: `The latest record of this evidence (UTC).` }),
  ];
  if (!('status' in sources[0])) {
    const hostsCol = (key, label, cls, icon) => col(key, 'count', { label, icon, desc: `Hosts whose evidence was ${label.toLowerCase()}.`, render: (v) => (v ? h('span', { class: 'tagtext ' + cls }, String(v)) : h('span', { class: 'mut' }, '0')) });
    return dataTable(sources, [col('label', 'source'), hostsCol('read', 'Read', 'st-ran', 'success'), hostsCol('partial', 'Partly read', 'ev-absent', 'notEvaluated'),
      hostsCol('not_read', 'Not read', 'sev-high', 'failure'), hostsCol('off', 'Off - not recorded', 'ev-absent', 'ruleOff'), hostsCol('unavailable', 'No source', 'mut', 'ruleOff'), col('records'), ...span],
    { filename: 'fleet-sources', rowKey: (r) => r.evidence });
  }
  const cols = [col('label', 'source'), col('state', 'source_status'), col('records'), col('note', 'source_reason'), ...span, col('prerequisites')];
  return dataTable(sources, cols, { filename: `${name}-sources`, rowKey: (r) => r.evidence });
}

