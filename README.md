<p align="center">
  <a href="https://intrusion.academy/signal"><img src=".github/assets/banner.svg" alt="Signal Console, Community Edition, by Intrusion Academy" width="100%"></a>
</p>

<p align="center">
  <a href="https://intrusion.academy/signal"><img alt="Website" src="https://img.shields.io/badge/website-intrusion.academy%2Fsignal-2c6aa8?style=for-the-badge"></a>
  <a href="https://intrusion.academy/signal/doc/latest"><img alt="Documentation" src="https://img.shields.io/badge/docs-latest-3b8fe0?style=for-the-badge"></a>
  <a href="#license"><img alt="License" src="https://img.shields.io/badge/license-Signal%20Community%201.0.0-16a34a?style=for-the-badge"></a>
</p>
<p align="center">
  <img alt="Edition" src="https://img.shields.io/badge/edition-Community-22c55e">
  <img alt="Version" src="https://img.shields.io/badge/version-0.124.0-1e222a">
  <img alt="Node.js" src="https://img.shields.io/badge/node-%E2%89%A5%2022.5-417e38?logo=nodedotjs&logoColor=white">
  <img alt="Hosts" src="https://img.shields.io/badge/hosts-Windows%2010%20%7C%2011%20%7C%20Server-0078d4">
  <img alt="DFIR" src="https://img.shields.io/badge/DFIR-live%20response-d97706">
  <img alt="MITRE ATT&CK" src="https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-dc2626">
</p>

Signal Console is the web console of [Signal](https://intrusion.academy/signal),
a Windows DFIR survey tool by Intrusion Academy. It imports the run files
Signal writes on each host and shows the hosts together.

[Website](https://intrusion.academy/signal) ·
[Documentation](https://intrusion.academy/signal/doc/latest) ·
[Quick start](#quick-start) ·
[Editions](#editions)

## Part of Signal

This repository is one part of Signal. Signal itself is a read-only
executable that runs on Windows hosts and writes one JSON run file per host.
The console reads those files.

<p align="center">
  <img src=".github/assets/how-it-works.svg" alt="signal.exe runs on each host and writes a JSON run file; Signal Console reads the run files of all hosts" width="100%">
</p>

| Part | Description |
|---|---|
| Signal (`signal.exe`) | Runs on a host in about a minute and reads only what Windows records. It installs nothing and changes nothing. The Community executable is available on request from [intrusion.academy/signal](https://intrusion.academy/signal). |
| Signal Console (this repository) | The web console for reviewing and triaging the runs of all hosts. |
| Documentation | Modules, rules, the output format, deployment and the console pages: [intrusion.academy/signal/doc/latest](https://intrusion.academy/signal/doc/latest). |

This README covers installing and running the console. For everything else,
see the [documentation](https://intrusion.academy/signal/doc/latest).

## Features

- **Signals.** What each rule raised on each host, with its evidence and the analysts' triage.
- **Evidence gaps.** For each host, the evidence it could not provide, such as cleared or disabled logs and missing sources.
- **Entities.** One page per user, process, service or file, combining what every source records about it, with its timeline and links.
- **Stacking.** Programs, services, persistence, remote-access tools and other items, counted across hosts to show what is common and what is rare.
- **ATT&CK coverage.** The MITRE ATT&CK matrix of the rules evaluated on the hosts in view.
- **Timeline and graph.** Events across hosts in UTC, with analyst tags and notes, and a graph of related entities.
- **Topology.** The networks the hosts are on and the connections between hosts.
- **Reports.** A compromise assessment report from the findings and their triage.
- **Self-hosted.** No cloud service, no telemetry and no build step. Local accounts with roles, an audit log and HTTPS.

## Quick start

Requirements: Node.js 22.5 or later (for the built-in `node:sqlite`) and the
Signal executable.

```bash
git clone https://github.com/intrusion-academy/Signal-Console-Community.git
cd Signal-Console-Community
npm ci --omit=dev
npm start
```

On first start the console prompts in the terminal for an administrator
name and password, then listens on http://localhost:7446. `PORT` sets
another port; `SIGNAL_CONSOLE_DATA` sets a data folder other than `data/`.

### Collecting and importing runs

1. Download Signal (`signal.exe`) from Intrusion Academy at [intrusion.academy/signal](https://intrusion.academy/signal). Signal is not included in this repository.

2. Run Signal on each host and write the run file to a folder you collect, for example a share:

   ```
   signal live -all -o \\fileserver\signal-runs\
   ```

3. Sign in, open **Import** and select the run files. An upload takes up to 200 files of up to 50 MB each. Each file is validated against Signal's output contract before it is stored; a file from a newer version of Signal is refused with the reason.

The console holds one set of runs. Runs can be removed on the Import page.

## Accounts

Every page and API route requires a signed-in account. Accounts are local to
the console; there is no self-registration.

| Role | Permissions |
|---|---|
| `admin` | Everything, including accounts, settings and the audit log |
| `analyst` | Triage, suppression rules, flags, importing and removing runs |
| `viewer` | Read only |

Administrators manage accounts on **Settings > Users**, or on the server:

```bash
npm run users -- add <name> analyst|admin|viewer
npm run users -- list | passwd <name> | role <name> <role> | disable <name> | enable <name> | remove <name>
```

Passwords are stored as salted scrypt hashes. Sessions use a random token in
an HttpOnly, SameSite=Strict cookie, stored only as a hash. A session ends
after 8 hours idle, after 7 days, at sign-out, or when its account changes.
Repeated failed sign-ins lock the account for 15 minutes. Sign-ins and
account changes are recorded in the audit log.

## Security

- Beyond a single machine, serve the console over HTTPS: set `SIGNAL_CONSOLE_TLS_CERT` and `SIGNAL_CONSOLE_TLS_KEY` to a PEM certificate (with its chain) and key, or run it behind a reverse proxy and set `SIGNAL_CONSOLE_SECURE_COOKIE=1`.
- Responses carry a Content-Security-Policy limited to the console's own files, deny framing, and set `nosniff`, no referrer and, over HTTPS, HSTS.
- To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Editions

| | Community | Pro | Enterprise / Consultant |
|---|:---:|:---:|:---:|
| Price | Free | Commercial | Commercial |
| `signal.exe` live mode, all modules | Yes | Yes | Yes |
| Console: import, triage, entities, timeline, ATT&CK, reports | Yes | Yes | Yes |
| Collection at scale and multiple investigations | No | Yes | Yes |
| Windows forensics mode | No | Yes | Yes |
| Linux, macOS and cloud editions | No | Planned | Planned |
| Services to third parties | No | No | Yes |
| Engagement support, exclusive threat-intelligence rules, training | No | No | Yes |

For Pro, Enterprise, services and training, see [intrusion.academy/signal](https://intrusion.academy/signal).

## License

Copyright 2026 Intrusion Academy. All rights reserved except as granted by
the Signal Community License 1.0.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).

Summary (the license text prevails):

- You may use, study and modify the software free of charge to defend the computers and networks that you or your organisation own or operate. Personal, educational and non-commercial research use is also permitted.
- A commercial license (Pro or Enterprise) is required to provide services to third parties with it (incident response, compromise or gap assessments, threat hunting, managed detection), to resell or redistribute it, or to incorporate it into another product.
- The software is provided "as is", without warranty of any kind.

Third-party packages and their licenses are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

Signal is developed by [Intrusion Academy](https://intrusion.academy/signal).
[Website](https://intrusion.academy/signal) ·
[Documentation](https://intrusion.academy/signal/doc/latest) ·
[Security](SECURITY.md) ·
[License](LICENSE)
