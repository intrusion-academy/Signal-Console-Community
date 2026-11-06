// Reports: the compromise assessment report of the hosts (Word or PDF, built
// by the server from the findings and the analysts' triage - src/report.js)
// and every triage note the analysts wrote, newest first. Before a report
// is generated with open signals no analyst triaged, or data pages not
// reviewed on every host, the page says what is still open and asks.

import { h, fetchJSON, apiFetch } from '../dom.js';
import { pageLink } from '../router.js';
import { CORE, section, summaryStrip } from '../components.js';
import { dataTable, col } from '../table.js';
import { canEdit } from '../session.js';

// openWork lists what is still open, each linking to where it is done.
function openWork(r) {
  const items = [];
  if (r.untriaged) items.push(h('li', {}, pageLink('signals', { triage: 'new' }, `${r.untriaged} open signal${r.untriaged === 1 ? '' : 's'}`), ` on ${r.untriaged_entities} entit${r.untriaged_entities === 1 ? 'y' : 'ies'} not triaged`));
  for (const u of r.unreviewed) items.push(h('li', {}, pageLink(u.page, {}, u.label), ` reviewed on ${u.reviewed} of ${u.hosts} host${u.hosts === 1 ? '' : 's'} with entries`));
  return items;
}

// warning is the sentence the confirmation asks with.
function warning(r) {
  const parts = [];
  if (r.untriaged) parts.push(`${r.untriaged} open signal(s) not triaged`);
  if (r.unreviewed.length) parts.push(`${r.unreviewed.length} data page(s) not reviewed on every host: ${r.unreviewed.map((u) => u.label).join(', ')}`);
  return `The assessment is not complete:\n\n- ${parts.join('\n- ')}\n\nThe report will say so on its first page and list the open items. Generate it anyway?`;
}

// generator is the report form: the analyst's summary and the two formats.
function generator(r) {
  const summary = h('textarea', { class: 'note', rows: 6, placeholder: 'Analyst summary: scope, what was found, the conclusion and recommended actions. It opens the report.' });
  const status = h('span', { class: 'mut' });
  const make = (format) => async () => {
    if (!r.ready && !window.confirm(warning(r))) return;
    status.textContent = 'Generating...';
    const res = await apiFetch(`/api/reports/${format}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ summary: summary.value }) });
    if (!res.ok) { status.textContent = `Could not generate the report: ${(await res.json().catch(() => ({}))).error || res.status}`; return; }
    const name = (/filename="([^"]+)"/.exec(res.headers.get('content-disposition') || '') || [])[1] || `report.${format}`;
    const a = h('a', { href: URL.createObjectURL(await res.blob()), download: name });
    a.click();
    URL.revokeObjectURL(a.href);
    status.textContent = `Downloaded ${name}`;
  };
  const items = openWork(r);
  return h('div', {},
    h('p', { class: 'mut card-intro' }, 'A compromise assessment report of the hosts imported: the analyst summary below, the findings by triage decision with each analyst\'s note, the open findings, the inventory reviews, the suppression rules, the hosts in scope and the limits of what was collected. Built from every host\'s latest collection.'),
    items.length ? h('div', { class: 'card report-warn' }, h('b', {}, 'Not ready: a report now would be incomplete.'), h('ul', {}, ...items)) : null,
    r.hosts ? null : h('div', { class: 'mut' }, 'No hosts yet - import a Signal run first.'),
    canEdit() ? h('div', { class: 'report-form' }, summary,
      h('div', {}, h('button', { class: 'btn', disabled: r.hosts ? null : '', onclick: make('docx') }, 'Word (.docx)'), ' ', h('button', { class: 'btn', disabled: r.hosts ? null : '', onclick: make('pdf') }, 'PDF'), ' ', status))
      : h('div', { class: 'mut' }, 'This account is read-only: an analyst generates the report.'));
}

export async function renderReportsPage(container) {
  const { readiness: r, notes } = await fetchJSON('/api/reports');
  container.replaceChildren(
    summaryStrip([
      { icon: 'hosts', value: r.hosts, label: r.hosts === 1 ? 'host' : 'hosts', link: ['hosts', {}] },
      { icon: 'eye', value: r.untriaged, label: 'untriaged', cls: r.untriaged ? 'tr-new' : null, link: r.untriaged ? ['signals', { triage: 'new' }] : null },
      { icon: 'flagged', value: r.escalated, label: 'escalated', cls: r.escalated ? 'tr-escalated' : null, link: r.escalated ? ['signals', { triage: 'escalated' }] : null },
      { icon: 'layers', value: r.unreviewed.length, label: 'pages not reviewed', cls: r.unreviewed.length ? 'tr-new' : null },
      { icon: 'details', value: notes.length, label: 'triage notes' },
    ], [CORE]),
    section('Compromise assessment report', () => generator(r), { collapsed: false, modules: [CORE] }),
    section(`Triage notes (${notes.length})`, () => (notes.length ? dataTable(notes, [
      col('at', 'note_at'), col('by', 'note_by'), col('state', 'triage', { desc: 'The decision recorded with the note: open (reopened), benign, escalated - or reviewed, before console 0.16.0.' }),
      col('note', 'note_text'), col('host'), col('entity', 'note_entity'), col('rules', 'note_rules'), col('covers_n', 'note_covers'),
    ], { height: 'scroll', filename: 'triage-notes' }) : h('div', { class: 'mut' }, 'No analyst has triaged anything yet.')), { collapsed: false, modules: [CORE] }));
}
