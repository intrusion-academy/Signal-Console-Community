// Column filters, like a spreadsheet's: per column, the values to keep
// (any of them) and/or a text condition (contains, equals, starts with,
// ends with - case-insensitive). The same code filters a table the browser
// holds and, on the server (src/model, src/persistence.js), a table it
// pages - so a filter means the same everywhere. No DOM here.
//
// A filter is {key, values?: [text], op?: OP, text?: string}; a row passes
// every filter. A cell's texts are its value as text, or each element of a
// list; a blank cell is BLANK.

export const OPS = ['contains', 'equals', 'startswith', 'endswith'];
export const BLANK = '(blank)';

// cellTexts is a cell's value as the texts a filter compares.
export function cellTexts(v) {
  if (Array.isArray(v)) return v.length ? v.map((x) => (x && typeof x === 'object' ? x.host || x.label || JSON.stringify(x) : String(x ?? ''))) : [BLANK];
  if (v === null || v === undefined || v === '') return [BLANK];
  return [String(v)];
}

const TEST = {
  contains: (s, t) => s.includes(t),
  equals: (s, t) => s === t,
  startswith: (s, t) => s.startsWith(t),
  endswith: (s, t) => s.endsWith(t),
};

// passes reports whether a row passes one filter.
function passes(row, f) {
  const texts = cellTexts(row[f.key]);
  if (f.values && f.values.length && !texts.some((t) => f.values.includes(t))) return false;
  if (f.text) {
    const test = TEST[f.op] || TEST.contains;
    const want = String(f.text).toLowerCase();
    if (!texts.some((t) => test(t.toLowerCase(), want))) return false;
  }
  return true;
}

// applyFilters keeps the rows that pass every filter.
export function applyFilters(rows, filters) {
  return filters && filters.length ? rows.filter((r) => filters.every((f) => passes(r, f))) : rows;
}

// parseFilters reads filters from a query string's JSON (the server side):
// anything malformed is no filter.
export function parseFilters(json) {
  try {
    const list = JSON.parse(json || '[]');
    return Array.isArray(list) ? list.filter((f) => f && typeof f.key === 'string') : [];
  } catch {
    return [];
  }
}

// distinctValues is a column's distinct texts with how many rows have each,
// most frequent first - at most max of them (more says there were others).
export function distinctValues(rows, key, max = 500) {
  const n = new Map();
  for (const r of rows) for (const t of new Set(cellTexts(r[key]))) n.set(t, (n.get(t) || 0) + 1);
  const values = [...n].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
  return { values: values.slice(0, max), more: values.length > max };
}

// filterRequest is what a server-paged table asks for: the rows that pass
// the filters, or - for one column's dropdown - its distinct values among
// the rows that pass the other columns' filters.
export function filterRequest(rows, params) {
  const filters = parseFilters(params.filters);
  if (params.distinct) return { distinct: distinctValues(applyFilters(rows, filters.filter((f) => f.key !== params.distinct)), String(params.distinct)) };
  return { rows: applyFilters(rows, filters) };
}
