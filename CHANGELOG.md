# Changelog

Releases of Signal Console Community. The full release notes of Signal are in
the documentation: <https://intrusion.academy/signal/doc/latest>.

## 1.0.4 - 2026-11-25

Updates from inside the console.

- The console updates itself, installed from a clone too: `npm start` now starts it through the launcher, which applies a new version in `app/`, backs up the data first, and goes back to the previous version if the new one does not start. A later `git pull` still works: the newest version runs.
- The README installs from the release ZIP (`node launch.js`), with a clone as the second way.
- An update package is checked to be this edition's before it is unpacked; any other is refused.
- To update from 1.0.1-1.0.3 installed from a clone: once by hand - `git pull`, `npm ci --omit=dev`, then `npm start` from now on. A console from the release ZIP started with `node launch.js` updates itself. Your data folder is kept.

## 1.0.3 - 2026-11-25

A security update of third-party packages. No change to what the console does.

- multer 2.5.0, body-parser 1.20.9 and qs 6.16.2: each fixes a published denial-of-service weakness (GHSA-q7qp-rjg7-q26m, GHSA-27r3-jxmh-p828, GHSA-6pq8-jhm2-2vcw). `npm audit` reports none.
- To update from 1.0.2: `git pull`, or download the ZIP again, then `npm ci` and restart the console. Your data folder is kept.

## 1.0.2 - 2026-11-23

Compatibility with the next Signal release.

- Accepts Signal runs of output schema 64. The shape of a Signal live run is unchanged; without this update the console would refuse the next Signal release as "from a newer Signal".
- A run that was not made by Signal live is refused before it is stored, with one sentence saying so.
- To update from 1.0.1: `git pull`, or download the ZIP again, then restart the console. Your data folder is kept.

## 1.0.1 - 2026-11-18

A fix for a console that stopped on its loading screen.

- Fixed: the console never got past its loading screen, on every page including sign-in. A sentence on Settings, License was quoted so that the browser could not read the page's script. The server, imports and accounts were not affected.
- To update from 1.0.0: `git pull`, or download the ZIP again, then restart the console. Your data folder is kept.

## 0.124.0 - 2026-11-06

First public release of the Community Edition.

- Import of Signal run files (up to 200 files of up to 50 MB per upload), validated against Signal's output contract.
- Overview, Signals, entity pages, timeline, graph, topology, stacking pages, ATT&CK coverage and compromise assessment reports.
- Local accounts with admin, analyst and viewer roles, an audit log, and HTTPS.
