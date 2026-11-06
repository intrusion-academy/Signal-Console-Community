// The analyst's part of the Timeline page (src/timeline.js):
//
//   GET    /api/timeline              {tags: {item: [tag]}, events: [...]}
//   PUT    /api/timeline/tags         {item, tags} - an item's tags, replaced
//   POST   /api/timeline/events       {time, severity, title, description, host, entity_type, entity_name}
//   PUT    /api/timeline/events/:id   the same fields - edit it
//   DELETE /api/timeline/events/:id   remove it, with its tags
'use strict';

const express = require('express');
const timeline = require('../timeline');

const router = express.Router();

// answer runs a change and answers the whole list, or 400 with its error.
const answer = (res, fn) => {
  try {
    if (fn() === false) return res.status(404).json({ error: 'no such event' });
    res.json(timeline.list());
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

router.get('/', (req, res) => res.json(timeline.list()));
router.put('/tags', (req, res) => answer(res, () => timeline.setTags((req.body || {}).item, (req.body || {}).tags, req.user.username)));
router.post('/events', (req, res) => answer(res, () => timeline.addEvent(req.body || {}, req.user.username)));
router.put('/events/:id', (req, res) => answer(res, () => timeline.updateEvent(req.params.id, req.body || {})));
router.delete('/events/:id', (req, res) => answer(res, () => timeline.removeEvent(req.params.id)));

module.exports = router;
