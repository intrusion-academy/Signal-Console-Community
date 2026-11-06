# Security Policy

## Reporting a vulnerability

Please report a suspected vulnerability in Signal Console Community
privately, through <https://intrusion.academy/signal>. Do not open a public
issue for it.

Include the version (top bar or `package.json`), what you did, what happened
and, where possible, the steps to reproduce it. Do not include data from a
host you investigated.

Intrusion Academy will acknowledge a report, assess it and tell you the
outcome. A confirmed vulnerability is fixed in a new release; the reporter
is credited, if they wish, once the fix is out.

## Supported versions

Only the latest release receives security fixes.

## Running it safely

- Run the console on a trusted host and reach it over HTTPS
  (`SIGNAL_CONSOLE_TLS_CERT` and `SIGNAL_CONSOLE_TLS_KEY`, or a reverse proxy
  that terminates TLS).
- Give each analyst their own account; keep admin accounts few.
- The console stores the imported runs and the analysts' triage in its
  `data` folder: protect and back up that folder as investigation data.
