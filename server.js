// Signal Console - entry point.
//
// A small Express server with two jobs: serve the static single-page front
// end (public/), and serve the JSON API it calls (src/routes/*) to import
// Signal run documents and read them back as signals, hosts, rules,
// inventories and dashboard data. Runs and triage are kept in one SQLite
// database (src/db.js); the model computed from them is cached per change
// (src/cache.js).
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const store = require('./src/store');
const auth = require('./src/auth');
const prompt = require('./src/prompt');
const db = require('./src/db');

// 7446 is SIGN on a phone keypad.
const PORT = process.env.PORT || 7446;
// HTTPS when both are set (PEM files); otherwise plain HTTP, for a reverse
// proxy that terminates TLS in front of it or a single analyst's machine.
const TLS_CERT = process.env.SIGNAL_CONSOLE_TLS_CERT;
const TLS_KEY = process.env.SIGNAL_CONSOLE_TLS_KEY;
const license = require('./src/license');
const AUTHOR = 'Intrusion Academy';
const AUTHOR_URL = 'https://intrusion.academy/signal';

const app = express();
app.disable('x-powered-by');

// Security headers on every answer: the pages load nothing from another
// origin and run no inline script (style attributes are set by h(), hence
// 'unsafe-inline' for styles only), may not be framed, and the browser
// takes each file as the type stated.
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});

// Every API route needs a signed-in account (src/auth.js), except signing
// in itself; a viewer account may only read.
const updates = require('./src/updates');
// A restart to apply an update waits for every run being received.
app.use('/api/import', updates.track);
app.use(express.json({ limit: '1mb' })); // sign-in, triage and suppression requests; runs arrive through /api/import
app.use('/api/auth', auth.routes());
app.use('/api', auth.requireAuth);
// The console's own: VirusTotal's lookups and settings, the accounts.
app.use('/api/virustotal', require('./src/routes/virustotal'));
app.use('/api/settings/accounts', require('./src/routes/accounts'));
// The audit log (src/audit.js) - sign-ins, account changes, run removals,
// newest first; admins only.
app.get('/api/settings/audit', (req, res) => (req.user.role === 'admin'
  ? res.json({ events: require('./src/audit').list(), kept: require('./src/audit').MAX_ROWS })
  : res.status(403).json({ error: 'only an admin reads the audit log' })));
// Updates (src/updates.js): the banner's state for every user; the
// settings, checks and updating for admins.
app.get('/api/updates', (req, res) => res.json(updates.status(false)));
const adminOnly = (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'only an admin changes this server-wide setting' }));
const updateAnswer = (res, work) => Promise.resolve().then(work).then((s) => res.json(s), (err) => res.status(400).json({ error: err.message }));
app.get('/api/settings/updates', adminOnly, (req, res) => res.json(updates.status(true)));
app.put('/api/settings/updates', adminOnly, (req, res) => updateAnswer(res, () => updates.settings(req.body || {})));
app.post('/api/settings/updates/check', adminOnly, (req, res) => updateAnswer(res, () => updates.checkNow()));
app.post('/api/settings/updates/apply', adminOnly, (req, res) => updateAnswer(res, async () => { await updates.apply(true); return updates.status(true); }));
app.post('/api/settings/updates/upload', adminOnly, require('multer')({ storage: require('multer').memoryStorage(), limits: { fileSize: 512 * 1024 * 1024, files: 2 } })
  .fields([{ name: 'file', maxCount: 1 }, { name: 'package', maxCount: 1 }]), (req, res) => updateAnswer(res, () => {
  const f = (req.files || {}).file;
  if (!f) throw new Error('give the update file (updates.json)');
  const pkg = (req.files || {}).package;
  return updates.upload(f[0].buffer.toString('utf8'), pkg ? pkg[0].buffer : null);
}));
// The background tasks the console runs now (src/tasks.js), for the top
// bar's tasks menu.
app.get('/api/tasks', (req, res) => res.json(require('./src/tasks').list()));
// Everything else is about the runs and the analysts' work on them: scope
// runs the request within its data file (src/db.js).
const scope = (req, res, next) => db.within(db.MAIN, next);
app.use('/api/import', scope, require('./src/routes/import'));
app.use('/api/runs', scope, require('./src/routes/runs'));
app.use('/api/signals', scope, require('./src/routes/signals'));
app.use('/api/hosts', scope, require('./src/routes/hosts'));
app.use('/api/users', scope, require('./src/routes/users'));
app.use('/api/entities', scope, require('./src/routes/entities'));
app.use('/api/dashboards', scope, require('./src/routes/dashboards'));
app.use('/api/rules', scope, require('./src/routes/rules'));
app.use('/api/modules', scope, require('./src/routes/modules'));
app.use('/api/inventories', scope, require('./src/routes/inventories'));
app.use('/api/flags', scope, require('./src/routes/flags'));
app.use('/api/reviews', scope, require('./src/routes/reviews'));
app.use('/api/graph', scope, require('./src/routes/graph'));
app.use('/api/timeline', scope, require('./src/routes/timeline'));
app.use('/api/profiles', scope, require('./src/routes/profiles'));
app.use('/api/reports', scope, require('./src/routes/reports'));
app.get('/api/about', (req, res) => res.json({ version: require('./package.json').version, license: license.NAME, edition: license.status(), author: AUTHOR, author_url: AUTHOR_URL }));
// The edition (src/license.js): every user reads it.
app.get('/api/settings/license', (req, res) => res.json(license.status()));
// The License page: the license and notice as written, and the third-party
// packages from THIRD_PARTY_NOTICES.md's table.
app.get('/api/about/license', (req, res) => {
  const text = (file) => fs.readFileSync(path.join(__dirname, file), 'utf8');
  const packages = text('THIRD_PARTY_NOTICES.md').split('\n').filter((l) => /^\| [^-P]/.test(l))
    .map((l) => l.split('|').slice(1, 4).map((c) => c.trim())).map(([name, version, license]) => ({ name, version, license }));
  res.json({ name: license.NAME, license: text('LICENSE'), notice: text('NOTICE'), packages });
});
// The Settings page's HTTPS section: whether this server answers over
// HTTPS, and its certificate as read from the configured file (never the
// key).
app.get('/api/settings/https', (req, res) => {
  const out = { https: Boolean(TLS_CERT && TLS_KEY), behind_proxy: process.env.SIGNAL_CONSOLE_SECURE_COOKIE === '1', request_secure: req.secure, port: PORT };
  if (TLS_CERT) {
    try {
      const c = new (require('crypto').X509Certificate)(fs.readFileSync(TLS_CERT));
      out.certificate = { file: TLS_CERT, subject: c.subject, issuer: c.issuer, names: c.subjectAltName || '', valid_from: new Date(c.validFrom).toISOString(), valid_to: new Date(c.validTo).toISOString(), sha256: c.fingerprint256, self_signed: c.subject === c.issuer };
    } catch (e) {
      out.certificate_error = `the certificate file could not be read: ${e.message}`;
    }
  }
  res.json(out);
});
// The Settings page's Server group: this process's memory, the data
// directory's size, and the runs in memory - how many, their database file
// and the model's last rebuild (measured at scale by
// scripts/benchmark.js).
app.get('/api/settings/server', (req, res) => {
  const size = (file) => ['', '-wal'].reduce((n, ext) => n + (fs.existsSync(file + ext) ? fs.statSync(file + ext).size : 0), 0);
  const m = process.memoryUsage();
  const heap = { used: m.heapUsed, total: m.heapTotal, limit: require('v8').getHeapStatistics().heap_size_limit, rss: m.rss };
  const inMemory = db.loaded('store').includes(db.MAIN);
  res.json({
    node: process.version, uptime_seconds: Math.round(process.uptime()), heap,
    data: { dir: db.DATA_DIR, db_bytes: size(db.MAIN) },
    runs: inMemory ? db.within(db.MAIN, () => ({
      runs_in_memory: store.all().filter((r) => !r.shell).length, older_runs: store.all().filter((r) => r.shell).length, rebuild: cache.lastRebuild(),
    })) : null,
  });
});
// The Settings page's Known exploited vulnerabilities group: CISA's KEV
// catalog the console flags applications by (src/kev.js) - its state,
// an update from CISA, and a reload of a file copied by hand.
const kev = require('./src/kev');
app.get('/api/settings/kev', (req, res) => res.json(kev.status()));
app.post('/api/settings/kev/update', adminOnly, async (req, res) => {
  try {
    res.json(await kev.update());
  } catch (e) {
    res.status(502).json({ error: `the catalog could not be fetched from CISA: ${e.message}` });
  }
});
app.post('/api/settings/kev/reload', adminOnly, (req, res) => res.json(kev.reload()));
app.put('/api/settings/kev/nvd', adminOnly, (req, res) => {
  try {
    const b = req.body || {};
    if (b.warn_days !== undefined) kev.setWarnDays(b.warn_days);
    require('./src/nvd').configure(b);
    res.json(kev.status());
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
app.use('/api', (req, res) => res.status(404).json({ error: 'no such API route' }));

// Everything under public/ is served as-is: index.html, the js/ modules,
// style.css - the text files gzip-compressed when the browser accepts it
// (src/compress.js), the rest by express.static.
app.use(require('./src/compress').staticGzip(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));
// The license, its notice and the third-party list as text (the License page links them).
for (const file of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']) {
  app.get(`/legal/${file}`, (req, res) => res.type('text/plain').sendFile(path.join(__dirname, file)));
}

// Every page of the front end has its own URL (/overview, /rules, ...; see
// PAGES in public/js/router.js, the one list of pages). They are all the
// same single-page app: the server answers any one-word path with
// index.html, and the front end renders the page it names (an unknown name
// shows the Overview) with its state in the query string.
app.get(/^\/[a-z]+$/, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// VirusTotal lookups, when an analyst turned them on (Settings), of what
// the latest runs in memory name.
const cache = require('./src/cache');
const inMemory = () => db.loaded('store').includes(db.MAIN);
require('./src/virustotal').start(
  () => (inMemory() ? db.within(db.MAIN, () => cache.latest()) : []),
  () => (inMemory() ? db.within(db.MAIN, () => String(store.version())) : ''));

const server = TLS_CERT && TLS_KEY
  ? require('https').createServer({ cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) }, app)
  : require('http').createServer(app);

// banner is the start-up lines, as signal.exe prints them: the wordmark in
// its blue gradient, the version and slogan, the author and the license -
// in colour on a terminal, plain text otherwise.
function banner() {
  const tty = process.stdout.isTTY && !process.env.NO_COLOR;
  const esc = String.fromCharCode(27);
  const paint = (style, text) => (tty ? `${esc}[${style}m${text}${esc}[0m` : text);
  const wordmark = [
    '╭────╴  ╷  ╭────╴  ╷╲   ╷    ╱╲    ╷',
    '╰────╮  │  │  ──┐  │ ╲  │   ╱  ╲   │',
    '╶────╯  ╵  ╰────┘  ╵  ╲ ╵  ╱    ╲  └────',
  ];
  const lines = wordmark.map((line) => '  ' + [...line].map((c, i, all) => {
    const t = i / (all.length - 1);
    return paint(`1;38;2;${41 - Math.round(11 * t)};${200 - Math.round(77 * t)};255`, c);
  }).join(''));
  const version = require('./package.json').version;
  return ['', ...lines, '',
    `  ${paint('1;94', `Signal Console ${version}`)} ${paint('2', "· DFIR Survey: The First Minute of Every Investigation. Where to Look & What You Can't See!")}`,
    `  ${paint('2', 'Developed by')} ${paint('1', AUTHOR)} ${paint('2', '·')} ${paint('34', AUTHOR_URL)}`,
    `  ${paint('2', 'License')} ${license.status().label} ${paint('2', `· ${license.NAME} · see LICENSE and NOTICE`)}`, ''].join('\n');
}

// firstAccount: a console with no account asks, in the shell that started
// it (the user: often an SSH session on a Linux server, where no browser
// can reach the console from the machine itself), for its first account -
// an admin, its name and password typed twice - before it listens. With no
// terminal (a service), it starts without one and says how to add it.
let bannerShown = false;
async function firstAccount() {
  if (auth.listUsers().length) return;
  if (!process.stdin.isTTY) {
    console.log('No account yet - add the first one on this machine: npm run users -- add <name> admin');
    return;
  }
  console.log(banner());
  bannerShown = true;
  console.log('No account yet: create the first one - an admin, who adds the others on Settings → Users.');
  for (;;) {
    try {
      const name = String(await prompt.ask('Account name [admin]: ')).trim() || 'admin';
      await auth.addUser(name, 'admin', await prompt.readPassword(`Password for ${name} (at least ${auth.MIN_PASSWORD} characters): `), { actor: 'first start' });
      console.log(`Created ${name} (admin).`);
      return;
    } catch (err) {
      console.log(`Not created: ${err.message}. Try again.`);
    }
  }
}

firstAccount().then(() => {
  // Started by launch.js (a release package): every database file is opened -
  // and so migrated - before saying ready, so a version that cannot open
  // the data fails its trial while nothing was written, and is rolled back.
  if (process.send) db.openAll();
  server.listen(PORT, () => {
    if (!bannerShown) console.log(banner());
    console.log(`Signal Console listening on ${TLS_CERT && TLS_KEY ? 'https' : 'http'}://localhost:${PORT}`);
    if (process.send) process.send('ready');
    updates.start();
  });
});
