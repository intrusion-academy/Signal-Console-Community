// Compressed static files. The front end's text files (public/: the
// JavaScript modules, the stylesheet, the page) are sent gzip-compressed to
// a browser that accepts it - about a fifth of their size - which is most
// of a first page load for an analyst on a remote link. Each file is
// compressed once and kept in memory until it changes on disk (checked by
// its modification time on every request, so an edited file is never sent
// stale). Images are already compressed and are left to express.static, as
// is every request this does not answer.
//
// Only these files are compressed, never the API's answers: those mix
// session data with text read from hosts, the situation where compression can
// leak a secret to an attacker who controls part of the page (BREACH).
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const TEXT = new Set(['.js', '.css', '.html', '.svg', '.json', '.txt']);

// staticGzip returns the middleware for the files under root.
function staticGzip(root) {
  const base = path.resolve(root);
  const cache = new Map(); // file -> { mtimeMs, gz, etag }
  return (req, res, next) => {
    if ((req.method !== 'GET' && req.method !== 'HEAD') || !/\bgzip\b/.test(req.headers['accept-encoding'] || '')) return next();
    let rel;
    try {
      rel = decodeURIComponent(req.path);
    } catch {
      return next();
    }
    if (rel.endsWith('/')) rel += 'index.html';
    const file = path.join(base, rel);
    if (!file.startsWith(base + path.sep) || !TEXT.has(path.extname(file).toLowerCase())) return next();
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      return next();
    }
    if (!stat.isFile()) return next();
    let entry = cache.get(file);
    if (!entry || entry.mtimeMs !== stat.mtimeMs) {
      const gz = zlib.gzipSync(fs.readFileSync(file), { level: zlib.constants.Z_BEST_COMPRESSION });
      entry = { mtimeMs: stat.mtimeMs, gz, etag: `"gz-${crypto.createHash('sha1').update(gz).digest('hex')}"` };
      cache.set(file, entry);
    }
    res.type(path.extname(file));
    res.setHeader('Content-Encoding', 'gzip');
    res.setHeader('Vary', 'Accept-Encoding');
    res.setHeader('Cache-Control', 'public, max-age=0');
    res.setHeader('ETag', entry.etag);
    if (req.fresh) return res.status(304).end();
    res.setHeader('Content-Length', entry.gz.length);
    return req.method === 'HEAD' ? res.end() : res.end(entry.gz);
  };
}

module.exports = { staticGzip };
