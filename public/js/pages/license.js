// The License page: the license Signal and Signal Console are used under,
// in plain words and as written (LICENSE), the required notice (NOTICE),
// and the third-party packages the console runs on
// (THIRD_PARTY_NOTICES.md) - all served by GET /api/about/license.

import { h, fetchJSON } from '../dom.js';
import { section, summaryStrip, detailBlock } from '../components.js';
import { dataTable, col } from '../table.js';

// inline renders **bold** and ***bold*** as strong text, the only markup
// the license's paragraphs use.
function inline(text) {
  return text.split(/\*\*\*?([^*]+)\*\*\*?/).map((part, i) => (i % 2 ? h('strong', {}, part) : part));
}

// licenseText renders the license's Markdown as headings and paragraphs:
// its own title is the card's, a line of <url> is a link.
function licenseText(md) {
  return h('div', { class: 'license-text' }, md.split('\n').filter((l) => l.trim() && !l.startsWith('# ')).map((line) => {
    if (line.startsWith('## ')) return h('h3', {}, line.slice(3));
    const url = /^<(https:\/\/[^>]+)>$/.exec(line.trim());
    if (url) return h('p', {}, h('a', { href: url[1], target: '_blank', rel: 'noopener' }, url[1]));
    return h('p', {}, inline(line));
  }));
}

// noticeText renders NOTICE's paragraphs (blank-line separated, wrapped
// for a text file) as flowing text; the first, its heading and copyright,
// keeps a line each.
function noticeText(text) {
  return h('div', { class: 'license-text' }, text.trim().split(/\n\s*\n/).map((para, i) => (i === 0
    ? h('p', {}, para.split('\n').flatMap((line, j) => (j ? [h('br'), line] : [h('strong', {}, line)])))
    : h('p', {}, para.split('\n').map((l) => l.trim()).join(' ')))));
}

const textLinks = () => h('div', { class: 'mut' }, 'As plain text: ',
  ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md'].flatMap((f, i) => [i ? ' · ' : '', h('a', { href: '/legal/' + f, target: '_blank', rel: 'noopener' }, f)]));

export async function renderLicensePage(container) {
  const [about, lic] = await Promise.all([fetchJSON('/api/about'), fetchJSON('/api/about/license')]);
  const kinds = new Set(lic.packages.map((p) => p.license));
  container.replaceChildren(...[
    summaryStrip([
      { icon: 'version', value: about.version, label: 'Signal Console' },
      { icon: 'license', value: about.edition.edition === 'community' ? 'Community' : about.edition.label.replace(' edition', ''), label: about.edition.customer ? `licensed to ${about.edition.customer}` : lic.name },
      { icon: 'module', value: lic.packages.length, label: `third-party packages, under ${[...kinds].join(', ')}` },
    ]),
    section('What the license allows', () => h('div', { class: 'license-text' },
      about.edition.customer ? detailBlock('This console', h('p', {}, `${about.edition.label}, licensed to ${about.edition.customer} until ${about.edition.expires.slice(0, 10)} - the terms of your commercial license agreement with Intrusion Academy apply and prevail; the Signal Community License below governs any use without one.`)) : null,
      detailBlock('Allowed', h('p', {}, "Free of charge, an organisation (with the entities it controls, is controlled by or is under common control with) may use, copy and modify Signal and Signal Console solely to defend the computers, networks and systems it owns or operates, including its own incident response, threat hunting and compromise assessment. Personal, educational and non-commercial research use is also permitted.")),
      detailBlock('Requires a commercial license', h('p', {}, 'The following require a written commercial license (Signal Pro or Signal Enterprise) from Intrusion Academy: providing any service to a third party with the software or its output, paid or not (incident response, digital forensics, compromise or gap assessment, threat hunting, managed detection); selling, renting, sublicensing or redistributing the software; and incorporating the software, its rules or its output formats into a product or service offered to others.')),
      detailBlock('No warranty', h('p', {}, 'To the fullest extent permitted by law, the software is provided "as is", without warranty of any kind, and Intrusion Academy accepts no liability for its use. This summary is for convenience only: the full license text below prevails, and it is not legal advice.')),
      textLinks()), { collapsed: false }),
    section(lic.name, () => licenseText(lic.license), { collapsed: false }),
    section('Notice', () => noticeText(lic.notice), { collapsed: false }),
    section('Third-party software', () => dataTable(lic.packages, [
      col('name', 'title', { label: 'Package', icon: 'module', desc: 'An npm package Signal Console runs on (a production dependency, direct or indirect). Its license text is in its folder under node_modules.' }),
      col('version', 'version', { desc: 'The version installed, locked in package-lock.json.' }),
      col('license', 'title', { label: 'License', icon: 'license', desc: 'The license the package states.' }),
    ], { height: 'scroll', filename: 'third-party-packages' }), { collapsed: false }),
  ].filter(Boolean));
}
