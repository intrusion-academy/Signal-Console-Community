// The analyst's additions to the entity graph (src/analystGraph.js):
//
//   GET    /api/graph/analyst              every analyst entity and link
//   POST   /api/graph/analyst/entities     {type, name, note} - add an entity
//   DELETE /api/graph/analyst/entities/:id remove it, with its links
//   POST   /api/graph/analyst/links        {a, b, words} - link two entities
//   DELETE /api/graph/analyst/links/:id    remove a link
'use strict';

const express = require('express');
const graph = require('../analystGraph');

const router = express.Router();

router.get('/analyst', (req, res) => res.json(graph.list()));

router.post('/analyst/entities', (req, res) => {
  try {
    res.json(graph.addEntity(req.body || {}, req.user.username));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/analyst/links', (req, res) => {
  try {
    graph.addLink(req.body || {}, req.user.username);
    res.json(graph.list());
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/analyst/entities/:id', (req, res) => (graph.removeEntity(req.params.id) ? res.json(graph.list()) : res.status(404).json({ error: 'no such entity' })));
router.delete('/analyst/links/:id', (req, res) => (graph.removeLink(req.params.id) ? res.json(graph.list()) : res.status(404).json({ error: 'no such link' })));

module.exports = router;
