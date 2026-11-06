// The console's edition and license: status() is the
// edition in force, NAME the license this copy is used under.
// This is the Community edition, licensed under the Signal Community
// License 1.0.0 (LICENSE, NOTICE).
'use strict';

const NAME = 'Signal Community License 1.0.0';

// status is the edition in force.
const status = () => ({ edition: 'community', label: 'Community edition', license: NAME });

module.exports = { NAME, status };
