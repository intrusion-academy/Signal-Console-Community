// The Import page: upload Signal run files (each checked against the
// output contract on the server), how to collect them from the hosts, and
// the list of imported runs - each host's current collection and its
// earlier ones, how each arrived - with a Remove button each, and Remove
// selected for several at once.

import { h, fetchJSON, apiFetch, mono, ts, withTip } from '../dom.js';
import { pageLink } from '../router.js';
import { countCell, summaryStrip, detailBlock, codeBlock } from '../components.js';
import { dataTable, col } from '../table.js';

// collectCard says how runs reach this page from many hosts: each host
// writes its run into one shared folder, and the folder's files are
// uploaded here together.
function collectCard() {
  return h('div', { class: 'card' }, h('h2', { class: 'card-head' }, 'Collecting runs from many hosts'),
    detailBlock('On each host', codeBlock([
      [['# each run is written as <host>-<run id>.json into the shared folder', 'comment']],
      [['signal', 'kw'], [' live -all '], ['-o ', 'field'], ['\\\\fileserver\\signal-runs\\', 'val']],
    ]), h('div', { class: 'mut' }, 'Then choose every file of the folder above: one upload takes up to 200 files, each checked against the output contract.')));
}

// updateHeaderStats shows how many hosts are imported, next to the Import
// button: hosts, not runs - a host's earlier collections are its history.
export async function updateHeaderStats(runs) {
  const r = (runs || (await fetchJSON('/api/runs'))).filter((x) => x.latest);
  document.getElementById('headerStats').textContent = `${r.length} host${r.length === 1 ? '' : 's'} imported`;
}

export async function renderImport(container) {
  const fileInput = h('input', { type: 'file', accept: '.json', multiple: true });
  const drop = h('div', { class: 'dropzone' }, 'Drop one or more Signal JSON files here, or ', h('label', { class: 'btn', style: 'display:inline-block;margin-left:6px' }, 'Choose files', fileInput));
  const resultBox = h('div');
  const runsBox = h('div');

  async function doImport(files) {
    if (!files || files.length === 0) return;
    const fd = new FormData();
    for (const f of files) fd.append('files', f);
    resultBox.textContent = 'Uploading…';
    try {
      const res = await fetchJSON('/api/import', { method: 'POST', body: fd });
      resultBox.replaceChildren(
        h('div', {}, res.imported.map((r) => h('div', { class: 'result-ok' }, `✓ ${r.file} → ${r.host} (${r.run_id})`))),
        h('div', {}, res.errors.map((r) => h('div', { class: 'result-err' }, `✗ ${r.file}: ${r.error}`))));
    } catch (err) {
      resultBox.replaceChildren(h('div', { class: 'result-err' }, `✗ ${err.message}`));
    }
    loadRuns();
  }
  fileInput.onchange = (e) => doImport(e.target.files);
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('over'); };
  drop.ondragleave = () => drop.classList.remove('over');
  drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove('over'); doImport(e.dataTransfer.files); };

  async function loadRuns() {
    const runs = (await fetchJSON('/api/runs')).map((r) => ({ ...r, collection: r.latest ? 'current' : 'earlier' }));
    // picked are the run IDs ticked for Remove selected; a row's box reads
    // it each time the row is drawn (paging, sorting).
    const picked = new Set();
    const removeSelected = h('button', { class: 'ghost danger', disabled: 'disabled', onclick: async () => {
      if (!confirm(`Remove ${picked.size} imported run${picked.size === 1 ? '' : 's'}? This cannot be undone.`)) return;
      await fetchJSON('/api/runs/remove', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ids: [...picked] }) });
      loadRuns();
    } }, 'Remove selected');
    const showPicked = () => {
      removeSelected.disabled = !picked.size;
      removeSelected.textContent = picked.size ? `Remove selected (${picked.size})` : 'Remove selected';
      for (const box of runsBox.querySelectorAll('input.run-pick')) box.checked = picked.has(box.value);
    };
    const pickAll = (on) => { for (const r of runs) picked[on ? 'add' : 'delete'](r.run_id); showPicked(); };
    const pickBox = (id) => h('input', { type: 'checkbox', class: 'run-pick', value: id, checked: picked.has(id) ? 'checked' : null, 'aria-label': 'Select this run',
      onclick: (e) => e.stopPropagation(), onchange: (e) => { picked[e.target.checked ? 'add' : 'delete'](id); showPicked(); } });
    const columns = [
      col('host'),
      col('mode'), col('started'),
      col('collection', 'mode', { label: 'Collection', icon: 'runs', desc: '"current": the host\'s latest collection, which every page shows; "earlier": part of the host\'s collection history.',
        render: (v) => h('span', { class: v === 'current' ? 'tagtext st-ran' : 'mut' }, v) }),
      col('tool_version', 'tool_version', { render: (v, row) => h('span', {}, row.older_output ? withTip(h('span', {}, v, ' ', h('span', { class: 'tagtext ev-absent' }, 'older output')), row.older_output) : v,
        row.withdrawn_signal ? [' ', withTip(h('span', { class: 'tagtext withdrawn-tag' }, 'withdrawn version'), `${row.withdrawn_signal}. Re-run the host with the current Signal (signal update).`)] : '') }),
      col('imported_by', 'mode', { label: 'Arrived', icon: 'upload', desc: 'How and when the run arrived: uploaded, and by which analyst.',
        render: (v, row) => h('span', {}, v || '—', row.imported ? h('span', { class: 'mut' }, ` · ${ts(row.imported)}`) : null) }),
      col('modules'),
      col('signal_count', 'signal_count', { render: (v, row) => (v ? pageLink('signals', { host: row.run_id }, countCell(v, 'sev-high')) : countCell(0)) }),
      col('run_id', 'run', { render: (v, row) => h('span', { class: 'run-cell' }, pickBox(v), mono(v), h('button', {
        class: 'ghost danger', onclick: async (e) => {
          e.stopPropagation();
          if (!confirm(`Remove the imported run for ${row.host} (${v})? This cannot be undone.`)) return;
          await apiFetch(`/api/runs/${v}`, { method: 'DELETE' });
          loadRuns();
        },
      }, 'Remove')) }),
    ];
    const total = (key) => runs.filter((r) => r.latest).reduce((n, r) => n + (r[key] || 0), 0); // the fleet as it is now: current collections only
    runsBox.replaceChildren(
      summaryStrip([
        { icon: 'runs', value: runs.length, label: 'runs imported' },
        { icon: 'hosts', value: runs.filter((r) => r.latest).length, label: 'hosts' },
        { icon: 'signals', value: total('signal_count'), label: 'open signals now', cls: total('signal_count') ? 'sev-high' : null },
      ]),
      h('div', { class: 'row' }, h('button', { class: 'ghost', onclick: () => pickAll(true) }, `Select all ${runs.length}`),
        h('button', { class: 'ghost', onclick: () => pickAll(false) }, 'Clear selection'), removeSelected),
      dataTable(runs, columns, { filename: 'runs' }));
    updateHeaderStats(runs);
  }

  container.replaceChildren(h('div', { class: 'card' }, drop, h('div', { class: 'import-result' }, resultBox)), collectCard(), runsBox);
  await loadRuns();
}
