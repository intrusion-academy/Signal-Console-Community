# Changelog

Releases of Signal Console Community. The full release notes of Signal are in
the documentation: <https://intrusion.academy/signal/doc/latest>.

## 1.0.1 - 2026-11-18

A fix for a console that stopped on its loading screen.

- Fixed: the console never got past its loading screen, on every page including sign-in. A sentence on Settings, License was quoted so that the browser could not read the page's script. The server, imports and accounts were not affected.
- To update from 1.0.0: `git pull`, or download the ZIP again, then restart the console. Your data folder is kept.

## 0.124.0 - 2026-11-06

First public release of the Community Edition.

- Import of Signal run files (up to 200 files of up to 50 MB per upload), validated against Signal's output contract.
- Overview, Signals, entity pages, timeline, graph, topology, stacking pages, ATT&CK coverage and compromise assessment reports.
- Local accounts with admin, analyst and viewer roles, an audit log, and HTTPS.
