// Import off the main thread: parsing and validating an uploaded run
// document (tens of megabytes at most) would otherwise stall every other
// request while it runs. One worker thread serves every import, one file at
// a time, in order; the main thread only stores the result.
'use strict';

const { Worker, isMainThread, parentPort } = require('worker_threads');

if (!isMainThread) {
  // The worker: {id, name, buffer} in, {id, doc} or {id, error} out.
  const { problems } = require('./contract');
  parentPort.on('message', ({ id, buffer }) => {
    try {
      const doc = JSON.parse(Buffer.from(buffer).toString('utf8'));
      const bad = problems(doc);
      parentPort.postMessage(bad.length ? { id, error: bad.slice(0, 5).join('; ') + (bad.length > 5 ? `; and ${bad.length - 5} more` : '') } : { id, doc });
    } catch (err) {
      parentPort.postMessage({ id, error: `invalid JSON: ${err.message}` });
    }
  });
} else {
  // MAX_FILE_MB bounds one run document, however it arrives: a run is
  // signals and small identity tables, not raw data, so tens of megabytes is
  // already far beyond a real one.
  module.exports.MAX_FILE_MB = 50;

  let worker = null;
  let nextId = 0;
  const pending = new Map();

  // start creates the worker on first use and restarts it if it dies,
  // failing whatever it was working on.
  const start = () => {
    worker = new Worker(__filename);
    worker.unref();
    worker.on('message', ({ id, doc, error }) => {
      const p = pending.get(id);
      pending.delete(id);
      if (p) p.resolve({ doc, error });
    });
    worker.on('error', (err) => {
      for (const p of pending.values()) p.resolve({ error: `import failed: ${err.message}` });
      pending.clear();
      worker = null;
    });
  };

  // parse validates one uploaded file: {doc} when it is a valid run
  // document, {error} saying why not.
  module.exports.parse = (buffer) => new Promise((resolve) => {
    if (!worker) start();
    const id = nextId++;
    pending.set(id, { resolve });
    const copy = new Uint8Array(buffer); // a copy the worker takes ownership of
    worker.postMessage({ id, buffer: copy }, [copy.buffer]);
  });
}
