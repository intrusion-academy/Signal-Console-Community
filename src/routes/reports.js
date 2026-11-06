// The reports API (src/report.js, src/documents.js):
//
//   GET  /api/reports
//     the runs' readiness for a report (open signals not triaged, data
//     pages not reviewed on every host) and every triage note, newest first.
//   POST /api/reports/:format {summary}
//     the compromise assessment report as a Word (docx) or PDF file, with
//     the analyst's summary.
'use strict';

const express = require('express');
const report = require('../report');
const documents = require('../documents');

const router = express.Router();

const TYPES = {
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  pdf: 'application/pdf',
};

router.get('/', (req, res) => res.json({ readiness: report.readiness(), notes: report.notes() }));

router.post('/:format', (req, res) => {
  const format = req.params.format;
  if (!TYPES[format]) return res.status(400).json({ error: 'a report is docx or pdf' });
  const title = 'Compromise Assessment';
  const name = `compromise-assessment-${new Date().toISOString().slice(0, 10)}.${format}`;
  const summary = String((req.body || {}).summary || '').slice(0, 20000);
  const blocks = report.build({ user: req.user.username, summary });
  const file = documents[format](blocks, title);
  res.set({ 'Content-Type': TYPES[format], 'Content-Disposition': `attachment; filename="${name}"` }).send(file);
});

module.exports = router;
