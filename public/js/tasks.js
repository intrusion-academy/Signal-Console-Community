// The tasks menu: the top bar's button between the finder and Import,
// listing the work the console runs in the background now - VirusTotal
// lookups, NVD's affected versions of CISA's catalog, any task that takes
// time (src/tasks.js, GET /api/tasks) - each with what it is doing, how far
// it is, and a link to where it is set up. The button counts the tasks
// with something to do and turns while one runs.

import { h, fetchJSON, svgIcon } from './dom.js';
import { pageLink } from './router.js';

const POLL = 15000; // the button's count, every 15 seconds
const POLL_OPEN = 3000; // the menu's rows while it is open

// STATE is each task state's tag.
const STATE = {
  running: { label: 'running', cls: 'st-ran' },
  waiting: { label: 'waiting', cls: 'ev-absent' },
  paused: { label: 'paused', cls: 'mut' },
};

// row is one task: its title and state, what it is doing, its progress.
function row(t) {
  const s = STATE[t.state] || { label: t.state, cls: 'mut' };
  const pct = t.total ? Math.round((100 * (t.done || 0)) / t.total) : null;
  return h('div', { class: 'task-row' },
    h('div', { class: 'task-head' }, t.page ? pageLink(t.page, t.params || {}, t.title) : h('b', {}, t.title), h('span', { class: `tagtext ${s.cls}` }, s.label)),
    h('div', { class: 'mut' }, t.detail || ''),
    pct === null ? null : h('div', { class: 'task-bar', title: `${t.done} of ${t.total} done` }, h('span', { style: `width:${pct}%` })),
    pct === null ? null : h('div', { class: 'mut task-n' }, `${t.done.toLocaleString()} of ${t.total.toLocaleString()} done (${pct}%)`));
}

// setupTasks draws the button and runs its count and menu.
export function setupTasks(btn) {
  btn.replaceChildren(svgIcon('tasks'), h('span', { class: 'task-count' }));
  const panel = h('div', { class: 'card dd-panel tasks-panel', role: 'menu' });
  let open = false;
  let timer = null;
  const paint = (list) => {
    const active = list.filter((t) => t.state === 'running' || t.state === 'waiting');
    btn.querySelector('.task-count').textContent = list.length ? String(list.length) : '';
    btn.classList.toggle('tasks-busy', active.length > 0);
    btn.title = list.length ? `Background tasks: ${list.length}` : 'Background tasks: none running';
    if (open) {
      panel.replaceChildren(h('div', { class: 'task-title' }, 'Background tasks'),
        ...(list.length ? list.map(row) : [h('div', { class: 'mut' }, 'Nothing runs in the background now.')]));
    }
  };
  const poll = async () => {
    clearTimeout(timer);
    try {
      paint(await fetchJSON('/api/tasks'));
    } catch { /* signed out, or the server is away: tried again */ }
    timer = setTimeout(poll, open ? POLL_OPEN : POLL);
  };
  const close = () => {
    open = false;
    panel.remove();
  };
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (open) return close();
    open = true;
    const r = btn.getBoundingClientRect();
    panel.style.top = `${r.bottom + 4}px`;
    panel.style.right = `${Math.max(8, window.innerWidth - r.right)}px`;
    document.body.append(panel);
    poll();
  });
  document.addEventListener('click', (e) => { if (open && !panel.contains(e.target)) close(); });
  document.addEventListener('keydown', (e) => { if (open && e.key === 'Escape') close(); });
  poll();
}
