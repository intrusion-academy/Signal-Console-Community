// The browser extensions inventory (Signal's inventory.browser_extensions,
// schema 29), stacked across the fleet (src/stacked.js) over the
// extensions table: one row per extension (its ID - the same in every
// Chromium-based browser) - its names, versions, browsers, how it was
// installed, what it may do and its users listed - with how many hosts
// have it, rarest first: an extension only one host has stands out.
//
// An extension is flagged when a Browsers rule's signal names it on one of
// its hosts (by its ID), or when an analyst flagged it - by its ID.
'use strict';

module.exports = require('./stacked').of({
  table: 'extensions',
  role: 'inventory.browser_extensions',
  group: 'lower(id)',
  select: `id, group_concat(DISTINCT nullif(name, '')) AS names, group_concat(DISTINCT nullif(version, '')) AS versions,
    group_concat(DISTINCT nullif(browser, '')) AS browsers, group_concat(DISTINCT nullif(installed_by, '')) AS installed_by,
    max(from_store = 'true') AS from_store, min(nullif(installed, '')) AS installed, group_concat(DISTINCT nullif(capabilities, '')) AS capabilities,
    group_concat(DISTINCT nullif(update_url, '')) AS update_url, group_concat(DISTINCT nullif(forced_by, '')) AS forced_by,
    group_concat(DISTINCT nullif(user, '')) AS user, max(in_period = 'true') AS in_period`,
  search: `id || ' ' || name || ' ' || browser || ' ' || installed_by || ' ' || capabilities || ' ' || update_url || ' ' || user`,
  order: 'lower(id)',
  flagKind: 'extensions',
  ruleKey: (r) => String(r.id).toLowerCase(),
  shape: (r) => ({
    ...r, names: r.names || '', versions: r.versions || '', browsers: r.browsers || '', installed_by: r.installed_by || '', from_store: r.from_store ? 'yes' : 'no',
    installed: r.installed || '', capabilities: r.capabilities || '', update_url: r.update_url || '', forced_by: r.forced_by || '', user: r.user || '', in_period: r.in_period ? 'yes' : 'no', value: r.id,
  }),
});
