// CISA's Known Exploited Vulnerabilities catalog (Settings): the console
// flags an installed application whose vendor and product the catalog
// lists, with the CVEs and what each is. Not a vulnerability scanner: the
// catalog names products, not affected versions, so each CVE matched by
// name is checked against the affected versions NVD gives for it
// (src/nvd.js): only an installed version inside them is flagged.
//
// The catalog is one file in the data folder (kev.json, CISA's JSON as
// published), fetched from CISA on request or copied there by hand on a
// console without Internet access. It is read once into a shared,
// read-only index (vendor + product -> entries) and replaced whole on an
// update - never changed in place (CAPACITY.md: shared data is never
// edited after it is read). Its size depends on the catalog, not on the
// hosts.
'use strict';

const fs = require('fs');
const path = require('path');
const db = require('./db');
const nvd = require('./nvd');

const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const FILE = path.join(db.DATA_DIR, 'kev.json');
const RULE = 'CONSOLE-KEV-PRODUCT';

let index = null; // { version, released, count, file_time, byWord: first word -> [{vendor, product, label, names, entries}] }

// words is a name as compared: lower case, versions, architectures and
// bracketed parts removed, punctuation as spaces.
const words = (s) => String(s || '').toLowerCase()
  .replace(/\([^)]*\)|\[[^\]]*\]/g, ' ')
  .replace(/\b(x64|x86|64-bit|32-bit|amd64|arm64)\b/g, ' ')
  .replace(/\bv?\d+(\.\d+)+\b/g, ' ')
  .replace(/[^a-z0-9+#]+/g, ' ')
  .trim().replace(/\s+/g, ' ');

// build indexes a catalog document.
function build(doc, fileTime) {
  if (!doc || !Array.isArray(doc.vulnerabilities)) throw new Error('not the CISA KEV catalog (no "vulnerabilities" list)');
  const byProduct = new Map();
  for (const v of doc.vulnerabilities) {
    const vendor = words(v.vendorProject);
    const product = words(v.product);
    if (!vendor || !product) continue;
    const key = `${vendor}\u0000${product}`;
    let p = byProduct.get(key);
    if (!p) byProduct.set(key, p = { vendor, product, label: `${v.vendorProject} ${v.product}`, names: [product, `${vendor} ${product}`], entries: [] });
    p.entries.push({
      cve: v.cveID, name: v.vulnerabilityName || '', cwes: (v.cwes || []).join(', '), ransomware: v.knownRansomwareCampaignUse === 'Known', added: v.dateAdded || '',
    });
  }
  // byWord: each product under the first word of each of its names, so an
  // application is compared with the few products its name can start with.
  const byWord = new Map();
  for (const p of byProduct.values()) {
    for (const w of new Set(p.names.map((x) => x.split(' ')[0]))) {
      if (!byWord.has(w)) byWord.set(w, []);
      byWord.get(w).push(p);
    }
  }
  return { version: doc.catalogVersion || '', released: doc.dateReleased || '', count: doc.vulnerabilities.length, file_time: fileTime, byWord };
}

// load reads the file once (again after an update).
function load() {
  if (index) return index;
  if (!fs.existsSync(FILE)) return null;
  index = build(JSON.parse(fs.readFileSync(FILE, 'utf8')), fs.statSync(FILE).mtime.toISOString());
  return index;
}

// warnDays is how old CISA's release of the catalog may be before Settings
// and the Applications page warn (CISA adds to it most weeks).
const warnDays = () => (db.meta('kev_warn_days', undefined, db.main()) === undefined ? DEFAULT_WARN : Number(db.meta('kev_warn_days', undefined, db.main())));
const DEFAULT_WARN = 7;

// ageOf is how many whole days ago CISA released the catalog held.
const ageOf = (released) => (released ? Math.floor((Date.now() - Date.parse(released)) / 86400000) : null);

// setWarnDays saves the age to warn at (0: never).
function setWarnDays(days) {
  const n = Number(days);
  if (!Number.isInteger(n) || n < 0 || n > 365) throw new Error('the warning age is whole days, 0 (never) to 365');
  db.meta('kev_warn_days', n, db.main());
}

// status is what the Settings page shows.
function status() {
  let error = '';
  try { load(); } catch (e) { error = `kev.json could not be read: ${e.message}`; }
  const age = index ? ageOf(index.released) : null;
  return { nvd: nvd.status(), age_days: age, warn_days: warnDays(), old: Boolean(index && warnDays() && age !== null && age > warnDays()), loaded: Boolean(index), version: index ? index.version : '', released: index ? index.released : '', count: index ? index.count : 0, file: FILE, file_time: index ? index.file_time : '', source: URL, error };
}

// update fetches the catalog from CISA and replaces the file and index.
async function update() {
  const res = await fetch(URL, { signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`CISA answered ${res.status}`);
  const text = await res.text();
  const next = build(JSON.parse(text), new Date().toISOString());
  fs.writeFileSync(FILE + '.tmp', text);
  fs.renameSync(FILE + '.tmp', FILE);
  index = next;
  return status();
}

// reload drops the index, so a file copied by hand is read.
function reload() {
  index = null;
  return status();
}

// matchesOf is the catalog's products an application matches: its name
// (as compared) is the product, or the vendor and product, alone or
// followed by more words - and the vendor is in its publisher or name.
function matchesOf(name, publisher) {
  const ix = load();
  if (!ix) return [];
  const n = words(name);
  const pub = words(publisher);
  if (!n) return [];
  return (ix.byWord.get(n.split(' ')[0]) || []).filter((p) => (pub.includes(p.vendor) || n.includes(p.vendor))
    && p.names.some((x) => n === x || n.startsWith(`${x} `)));
}

// checked is an application's matched CVEs, each with whether an installed
// version is affected (src/nvd.js: yes / no / unknown).
function checked(app) {
  return matchesOf(app.name, app.publisher).flatMap((p) => p.entries.map((e) => ({ ...e, label: p.label, affected: nvd.affected(e.cve, app.name, app.versions) })));
}

// flagsOf is an application's console flags: one per matched product with
// a CVE whose affected versions (NVD) cover an installed version - the
// rule's name and its reason. A CVE not yet checked, or whose versions
// cannot be compared, flags nothing.
function flagsOf(app, list = checked(app)) {
  const byProduct = new Map();
  for (const e of list.filter((x) => x.affected === 'yes')) {
    if (!byProduct.has(e.label)) byProduct.set(e.label, []);
    byProduct.get(e.label).push(e.cve);
  }
  return [...byProduct].map(([label, cves]) => ({
    rule: RULE,
    reason: `Installed version ${app.versions} is in the affected versions NVD gives for ${cves.join(', ')} - CVE${cves.length === 1 ? '' : 's'} CISA's Known Exploited Vulnerabilities catalog lists as exploited in ${label} (product matched by name and publisher).`,
  }));
}

// cvesOf is an application's affected CVEs as the table shows them: CVE,
// what it is, its CWE, ransomware use.
function cvesOf(app, list = checked(app)) {
  return list.filter((e) => e.affected === 'yes')
    .map((e) => `${e.cve}: ${e.name}${e.cwes ? ` (${e.cwes})` : ''}${e.ransomware ? ' - used in ransomware campaigns' : ''}`).join('; ');
}

// uncheckedOf is how many of an application's matched CVEs could not be
// compared with its versions (not looked up yet, no range for the product,
// a version that is not a number).
const uncheckedOf = (app, list = checked(app)) => list.filter((e) => e.affected === 'unknown').length;

// assess is all three for one application, its CVEs checked once.
function assess(app) {
  const list = checked(app);
  return { flags: flagsOf(app, list), cves: cvesOf(app, list), unchecked: uncheckedOf(app, list) };
}

module.exports = { status, update, reload, setWarnDays, flagsOf, cvesOf, uncheckedOf, assess, words, build, RULE };
