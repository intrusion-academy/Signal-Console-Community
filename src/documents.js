// Documents: a report's blocks (src/report.js - title, h, p, warn, kv,
// table) written as a Word file (.docx: Office Open XML in a zip) or a PDF
// (the standard Helvetica fonts, A4) - by hand, with Node's own zlib, so
// the console takes no dependency for them.
'use strict';

const zlib = require('zlib');
const { zip } = require('./zip');

// eslint-disable-next-line no-control-regex -- control characters are not allowed in XML
const xml = (s) => String(s ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// DOCX_WIDTH is the text width of an A4 page with 2 cm margins, in twips.
const DOCX_WIDTH = 9638;

function docx(blocks, title) {
  const run = (text, { b, sz = 20, color } = {}) => String(text ?? '').split('\n').map((line, i) =>
    `<w:r><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>${b ? '<w:b/>' : ''}${color ? `<w:color w:val="${color}"/>` : ''}<w:sz w:val="${sz}"/></w:rPr>${i ? '<w:br/>' : ''}<w:t xml:space="preserve">${xml(line)}</w:t></w:r>`).join('');
  const para = (inner, { before = 0, after = 120, keep, shade, border } = {}) =>
    `<w:p><w:pPr>${keep ? '<w:keepNext/>' : ''}${border ? `<w:pBdr><w:left w:val="single" w:sz="24" w:space="6" w:color="${border}"/></w:pBdr>` : ''}${shade ? `<w:shd w:val="clear" w:color="auto" w:fill="${shade}"/>` : ''}<w:spacing w:before="${before}" w:after="${after}" w:line="240" w:lineRule="auto"/></w:pPr>${inner}</w:p>`;
  const cell = (text, width, head) => `<w:tc><w:tcPr><w:tcW w:w="${width}" w:type="dxa"/>${head ? '<w:shd w:val="clear" w:color="auto" w:fill="E7E9EC"/>' : ''}</w:tcPr>${para(run(text, { b: head, sz: 16 }), { after: 0 })}</w:tc>`;
  const table = (blk, head = true) => {
    const total = blk.widths.reduce((a, b) => a + b, 0);
    const widths = blk.widths.map((w) => Math.floor((w / total) * DOCX_WIDTH));
    const row = (cells, head) => `<w:tr>${head ? '<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>' : '<w:trPr><w:cantSplit/></w:trPr>'}${cells.map((c, i) => cell(c, widths[i], head)).join('')}</w:tr>`;
    const border = (side) => `<w:${side} w:val="single" w:sz="4" w:space="0" w:color="B8BDC4"/>`;
    return `<w:tbl><w:tblPr><w:tblW w:w="${DOCX_WIDTH}" w:type="dxa"/><w:tblLayout w:type="fixed"/><w:tblBorders>${['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map(border).join('')}</w:tblBorders><w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>${widths.map((w) => `<w:gridCol w:w="${w}"/>`).join('')}</w:tblGrid>${head ? row(blk.head, true) : ''}${blk.rows.map((r) => row(r)).join('')}</w:tbl>${para('', { after: 120 })}`;
  };
  const body = blocks.map((blk) => {
    switch (blk.t) {
      case 'title': return para(run(blk.text, { b: true, sz: 40, color: '1F3A5F' }), { after: 240 });
      case 'h': return para(run(blk.text, { b: true, sz: 28, color: '1F3A5F' }), { before: 280, after: 120, keep: true });
      case 'warn': return para(run(blk.text, { b: true, sz: 20, color: '8A4B00' }), { before: 120, after: 160, shade: 'FFF4E0', border: 'D98200' });
      case 'kv': return table({ widths: [1, 3], rows: blk.rows }, false);
      case 'table': return table(blk);
      default: return para(run(blk.text));
    }
  }).join('');
  const footer = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:jc w:val="center"/></w:pPr>${run(`${title} - page `, { sz: 16, color: '6B7280' })}<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="6B7280"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:rPr><w:sz w:val="16"/><w:color w:val="6B7280"/></w:rPr><w:instrText>PAGE</w:instrText></w:r><w:r><w:rPr><w:sz w:val="16"/><w:color w:val="6B7280"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>`;
  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>${body}<w:sectPr><w:footerReference w:type="default" r:id="rIdFooter"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr></w:body></w:document>`;
  return zip([
    { name: '[Content_Types].xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>' },
    { name: '_rels/.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>' },
    { name: 'word/_rels/document.xml.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>' },
    { name: 'word/document.xml', data: document },
    { name: 'word/footer1.xml', data: footer },
  ]);
}

// HELVETICA is Helvetica's advance width (per 1000 units) of each character
// from space (32) to tilde (126) - the standard font's metrics, for wrapping.
const HELVETICA = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
  1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
  333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];

// latin turns text into what the standard fonts' WinAnsi encoding holds:
// typographic punctuation to its plain form, anything else outside Latin-1
// to "?".
const PLAIN = { 0x2018: "'", 0x2019: "'", 0x201c: '"', 0x201d: '"', 0x2013: '-', 0x2014: '-', 0x2212: '-', 0x2026: '...', 0x2022: '-', 0x00b7: '-', 9: '    ' };
const latin = (s) => Array.from(String(s ?? ''), (ch) => {
  const c = ch.codePointAt(0);
  if (PLAIN[c]) return PLAIN[c];
  return c === 10 || (c >= 32 && c <= 126) || (c >= 160 && c <= 255) ? ch : '?';
}).join('');

function textWidth(s, size, bold) {
  let w = 0;
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    w += c >= 32 && c <= 126 ? HELVETICA[c - 32] : 556;
  }
  return (w * size * (bold ? 1.07 : 1)) / 1000;
}

// wrap breaks text into lines no wider than width - at spaces, and inside a
// word (a path, a hash) too long for a line.
function wrap(text, size, width, bold) {
  const out = [];
  for (const para of latin(text).split('\n')) {
    let line = '';
    for (const word of para.split(' ')) {
      const next = line ? `${line} ${word}` : word;
      if (textWidth(next, size, bold) <= width) { line = next; continue; }
      if (line) out.push(line);
      line = '';
      let rest = word;
      while (textWidth(rest, size, bold) > width) {
        let n = rest.length - 1;
        while (n > 1 && textWidth(rest.slice(0, n), size, bold) > width) n--;
        out.push(rest.slice(0, n));
        rest = rest.slice(n);
      }
      line = rest;
    }
    out.push(line);
  }
  return out;
}

const pdfString = (s) => `(${s.replace(/[\\()]/g, (c) => `\\${c}`)})`;

// pdf lays the blocks out on A4 pages and writes the file.
function pdf(blocks, title) {
  const W = 595;
  const H = 842;
  const M = 50;
  const width = W - 2 * M;
  const pages = [];
  let ops;
  let y;
  const newPage = () => { ops = []; pages.push(ops); y = H - M; };
  const ensure = (h) => { if (y - h < M + 20) newPage(); };
  const text = (s, x, size, bold, color = '0 0 0') => ops.push(`BT ${color} rg /${bold ? 'F2' : 'F1'} ${size} Tf ${x.toFixed(2)} ${y.toFixed(2)} Td ${pdfString(s)} Tj ET`);
  const lines = (s, size, bold, { color, gap = 4, indent = 0 } = {}) => {
    for (const l of wrap(s, size, width - indent, bold)) {
      ensure(size + 2);
      y -= size + 2;
      text(l, M + indent, size, bold, color);
    }
    y -= gap;
  };
  const table = (blk, head = true) => {
    const size = 8;
    const pad = 3;
    const total = blk.widths.reduce((a, b) => a + b, 0);
    const cols = blk.widths.map((w) => (w / total) * width);
    const draw = (cells, bold) => {
      const wrapped = cells.map((c, i) => wrap(String(c ?? ''), size, cols[i] - 2 * pad, bold));
      const h = Math.max(...wrapped.map((l) => l.length)) * (size + 2) + 2 * pad;
      return { wrapped, h, bold };
    };
    const put = (row) => {
      const top = y;
      if (row.bold) ops.push(`0.906 0.914 0.925 rg ${M} ${(top - row.h).toFixed(2)} ${width} ${row.h.toFixed(2)} re f`);
      let x = M;
      row.wrapped.forEach((cell, i) => {
        y = top - pad;
        for (const l of cell) { y -= size + 2; text(l, x + pad, size, row.bold); }
        ops.push(`0.72 0.74 0.77 RG 0.5 w ${x.toFixed(2)} ${(top - row.h).toFixed(2)} ${cols[i].toFixed(2)} ${row.h.toFixed(2)} re S`);
        x += cols[i];
      });
      y = top - row.h;
    };
    const header = head ? draw(blk.head, true) : null;
    let first = true;
    for (const cells of blk.rows) {
      const row = draw(cells.map(String), false);
      const need = row.h + (header && first ? header.h : 0);
      if (y - need < M + 20) { newPage(); first = true; }
      if (header && first) put(header);
      first = false;
      put(row);
    }
    y -= 10;
  };
  newPage();
  for (const blk of blocks) {
    switch (blk.t) {
      case 'title': lines(blk.text, 20, true, { color: '0.122 0.227 0.373', gap: 12 }); break;
      case 'h': ensure(60); y -= 10; lines(blk.text, 13, true, { color: '0.122 0.227 0.373', gap: 6 }); break;
      case 'warn': {
        const l = wrap(blk.text, 10, width - 16, true);
        const h = l.length * 12 + 12;
        ensure(h);
        ops.push(`1 0.957 0.878 rg ${M} ${(y - h).toFixed(2)} ${width} ${h.toFixed(2)} re f 0.851 0.51 0 rg ${M} ${(y - h).toFixed(2)} 3 ${h.toFixed(2)} re f`);
        const top = y;
        y -= 6;
        for (const s of l) { y -= 12; text(s, M + 10, 10, true, '0.541 0.294 0'); }
        y = top - h - 10;
        break;
      }
      case 'kv': table({ widths: [1, 3], rows: blk.rows }, false); break;
      case 'table': table(blk); break;
      default: lines(blk.text, 10, false, { gap: 8 });
    }
  }
  pages.forEach((p, i) => {
    ops = p;
    y = 30;
    const foot = latin(`${title} - page ${i + 1} of ${pages.length}`);
    text(foot, (W - textWidth(foot, 8)) / 2, 8, false, '0.42 0.45 0.5');
  });

  // Objects: 1 catalog, 2 pages, 3-4 fonts, then a page and its content each.
  const objects = [];
  const kids = pages.map((_, i) => `${5 + i * 2} 0 R`).join(' ');
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[2] = `<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>`;
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';
  objects[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>';
  const streams = [];
  pages.forEach((p, i) => {
    const n = 5 + i * 2;
    objects[n] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${n + 1} 0 R >>`;
    streams[n + 1] = zlib.deflateSync(Buffer.from(p.join('\n'), 'latin1'));
  });
  const info = objects.length > streams.length ? objects.length : streams.length;
  objects[info] = `<< /Title ${pdfString(latin(title))} /Producer (Signal Console) /CreationDate (D:${new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)}Z) >>`;
  const chunks = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  const offsets = [];
  let length = chunks[0].length;
  for (let n = 1; n <= info; n++) {
    const body = streams[n]
      ? Buffer.concat([Buffer.from(`${n} 0 obj\n<< /Length ${streams[n].length} /Filter /FlateDecode >>\nstream\n`, 'latin1'), streams[n], Buffer.from('\nendstream\nendobj\n', 'latin1')])
      : Buffer.from(`${n} 0 obj\n${objects[n]}\nendobj\n`, 'latin1');
    offsets[n] = length;
    chunks.push(body);
    length += body.length;
  }
  const xref = [`xref\n0 ${info + 1}\n0000000000 65535 f \n`, ...offsets.slice(1).map((o) => `${String(o).padStart(10, '0')} 00000 n \n`)].join('');
  chunks.push(Buffer.from(`${xref}trailer\n<< /Size ${info + 1} /Root 1 0 R /Info ${info} 0 R >>\nstartxref\n${length}\n%%EOF\n`, 'latin1'));
  return Buffer.concat(chunks);
}

module.exports = { docx, pdf };
