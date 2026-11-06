// The import endpoint: accepts one or more Signal JSON documents (bulk
// import from multiple devices is just "select more than one file") and
// stores each as its own run, "upload by <account>". Each file is parsed and
// checked against the output contract (src/contract.js) in a worker thread
// (src/importWorker.js).
'use strict';

const express = require('express');
const multer = require('multer');
const store = require('../store');
const db = require('../db');
const scope = (req, res, next) => db.within(db.MAIN, next);
const { parse, MAX_FILE_MB } = require('../importWorker');

// MAX_FILES is the most files one upload takes - more is refused, not cut.
const MAX_FILES = 200;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_FILE_MB * 1024 * 1024, files: MAX_FILES } });
const router = express.Router();

// POST /api/import - multipart form upload, field name "files" (repeatable).
router.post('/', (req, res, next) => upload.array('files')(req, res, (err) => {
  if (err) {
    const why = { LIMIT_FILE_SIZE: `a file is larger than ${MAX_FILE_MB} MB`, LIMIT_FILE_COUNT: `more than ${MAX_FILES} files in one upload - upload them in parts` }[err.code];
    return res.status(400).json({ error: why || err.message });
  }
  next();
}), scope, async (req, res) => { // the data file again: the upload's stream callbacks run outside the request's
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'no files uploaded' });
  }
  const imported = [];
  const errors = [];
  for (const file of req.files) {
    const { doc, error } = await parse(file.buffer);
    if (error) {
      errors.push({ file: file.originalname, error });
      continue;
    }
    store.save(doc, `upload by ${req.user.username}`, file.buffer.toString('utf8'));
    imported.push({ file: file.originalname, run_id: doc.run_id, host: doc.host ? doc.host.hostname : doc.run_id });
  }
  res.json({ imported, errors });
});

module.exports = router;
