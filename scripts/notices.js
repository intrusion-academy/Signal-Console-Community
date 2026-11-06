// THIRD_PARTY_NOTICES.md - every npm package signal-console runs on (the
// production dependencies, not the test and lint tools), with its version
// and license, read from node_modules:
//
//   npm run notices             rewrite THIRD_PARTY_NOTICES.md
//   npm run notices -- check    exit 1 if the file does not match (npm test)
//
// Run it after any change to the dependencies. The software bill of
// materials in CycloneDX form comes from npm itself: npm run sbom.
'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const FILE = path.join(__dirname, '..', 'THIRD_PARTY_NOTICES.md');

function license(pkg) {
  if (typeof pkg.license === 'string') return pkg.license;
  if (pkg.license && pkg.license.type) return pkg.license.type;
  if (Array.isArray(pkg.licenses)) return pkg.licenses.map((l) => l.type).join(' OR '); // the older form (busboy)
  return 'not stated';
}

function render() {
  const dirs = execSync('npm ls --omit=dev --all --parseable', { encoding: 'utf8' })
    .trim().split(/\r?\n/).slice(1); // the first line is signal-console itself
  const rows = new Map();
  for (const dir of dirs) {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    rows.set(`${pkg.name}@${pkg.version}`, `| ${pkg.name} | ${pkg.version} | ${license(pkg)} |`);
  }
  const lines = [...rows.keys()].sort().map((k) => rows.get(k));
  return [
    '# Third-party software in signal-console',
    '',
    'The npm packages signal-console runs on (production dependencies, direct',
    'and indirect), written by `npm run notices`. Each license text is in the',
    'package\'s folder under `node_modules/`. The browser side loads no',
    'third-party code. The CycloneDX bill of materials: `npm run sbom`.',
    '',
    '| Package | Version | License |',
    '|---|---|---|',
    ...lines,
    '',
  ].join('\n');
}

const text = render();
if (process.argv[2] === 'check') {
  const current = fs.existsSync(FILE) ? fs.readFileSync(FILE, 'utf8') : '';
  if (current !== text) {
    console.error('THIRD_PARTY_NOTICES.md is out of date: npm run notices');
    process.exit(1);
  }
  console.log('notices: THIRD_PARTY_NOTICES.md is current');
} else {
  fs.writeFileSync(FILE, text);
  console.log(`wrote ${FILE}`);
}
