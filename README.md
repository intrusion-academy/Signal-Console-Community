# Signal Console — Community Edition

*Signal DFIR Survey: The First Minute of Every Investigation. Where to Look & What You Can't See!*

Signal Console is the web console for **Signal**, the Windows live-response
survey tool by Intrusion Academy (<https://intrusion.academy/signal>). It
imports the JSON run files Signal writes on each host and shows the hosts
together: the signals each rule raised, their triage, the evidence each
host could and could not provide, and the pages that stack what the hosts
have in common and what is rare.

This repository is the source of the **Community Edition**, published by
Intrusion Academy under the Signal Community License 1.0.0 (see
[License](#license)).

## Requirements

- Node.js 22.5 or later (the console uses Node's built-in `node:sqlite`).
- No front-end dependency, no build step and no Internet access: the
  browser loads the files in `public/` as they are.
- The Signal executable (Community Edition), obtained on request from
  <https://intrusion.academy/signal>.

## Installation

```
npm ci --omit=dev
npm start
```

The console listens on port 7446 (`PORT` to change) and keeps its data in
`data/` (`SIGNAL_CONSOLE_DATA` for another folder). On its first start with
no account it asks, in the same terminal, for an administrator's name and
password before it listens.

## Collecting and importing runs

1. Run Signal on each host, writing its run file to a folder you collect,
   for example a share:

   ```
   signal live -all -o \\fileserver\signal-runs\
   ```

2. Sign in to the console and open **Import**. Choose or drop the run files;
   one upload takes up to 200 files of up to 50 MB each. Every file is
   checked against Signal's output contract before it is stored; a file
   from a newer Signal is refused with the reason.

The console holds one set of runs. Remove runs from the Import page when
they are no longer needed.

## Accounts

Every page and every API route requires a signed-in account. Accounts are
local to the console; there is no self-registration.

| Role | Rights |
|---|---|
| admin | everything, including accounts, settings and the audit log |
| analyst | triage, suppression rules, flags, import and removal of runs |
| viewer | read-only; the server refuses any change |

Accounts are managed by an administrator on **Settings → Users**, or on the
server:

```
npm run users -- add <name> analyst|admin|viewer
npm run users -- list | passwd <name> | role <name> <role> | disable <name> | enable <name> | remove <name>
```

Passwords are stored as salted scrypt hashes. Sessions are random tokens in
an HttpOnly, SameSite=Strict cookie, of which the database keeps only a
hash; a session ends after 8 hours idle, after 7 days in any event, at sign
out, and when its account changes. Repeated failed sign-ins are refused for
15 minutes. Sign-ins, refusals and account changes are recorded in the
audit log (Settings → Audit log, administrators only).

## Security

- Serve the console over HTTPS beyond a single machine: set
  `SIGNAL_CONSOLE_TLS_CERT` and `SIGNAL_CONSOLE_TLS_KEY` to a PEM
  certificate (with its chain) and key, or place it behind a reverse proxy
  and set `SIGNAL_CONSOLE_SECURE_COOKIE=1`.
- Every response carries security headers: a Content-Security-Policy that
  allows only the console's own files, no framing, `nosniff`, no referrer,
  and HSTS over HTTPS.
- Report a vulnerability as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Intrusion Academy. All rights reserved except as granted by
the Signal Community License 1.0.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).

In summary, and without limiting the license text, which prevails:

- You may use, study and modify this software, free of charge, solely to
  defend the computers and networks that you or your organisation own or
  operate.
- Providing services to third parties with it (incident response,
  compromise or gap assessments, threat hunting, managed detection),
  reselling or redistributing it, or incorporating it into another product
  requires a commercial license (Pro or Enterprise) from Intrusion Academy.
- The software is provided "as is", without warranty of any kind.

Third-party packages and their licenses are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Commercial editions, services and training: <https://intrusion.academy/signal>.
