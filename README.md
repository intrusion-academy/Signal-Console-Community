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
  <img alt="Build step" src="https://img.shields.io/badge/build%20step-none-7c3aed">
</p>

<p align="center">
  <b>Signal Console is the web console of <a href="https://intrusion.academy/signal">Signal</a>, the Windows DFIR survey by Intrusion Academy.</b><br>
  It brings every host's Signal run into one place, so you can see where to look first and what each host could not show you.
</p>

<p align="center">
  <a href="https://intrusion.academy/signal"><b>Get Signal</b></a> ·
  <a href="https://intrusion.academy/signal/doc/latest"><b>Read the documentation</b></a> ·
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="#editions"><b>Editions</b></a>
</p>

---

## 🧭 Part of Signal

This repository holds **one part** of Signal: the console. Signal itself is a
small, read-only executable that you run on Windows hosts. It writes one JSON
run file per host, and the console reads those files.

<p align="center">
  <img src=".github/assets/how-it-works.svg" alt="signal.exe runs on each host, writes a JSON run file, and Signal Console shows all hosts together" width="100%">
</p>

| | |
|---|---|
| **Signal** (`signal.exe`) | The survey. Runs on each host in about a minute, reads only what Windows already records, and changes nothing. The Community executable is free; request it at **[intrusion.academy/signal](https://intrusion.academy/signal)**. |
| **Signal Console** (this repository) | The web console where analysts look at every host together, triage what the rules raised and build the picture of the investigation. |
| **Documentation** | Modules, rules, the output format, deployment and the console pages, in full: **[intrusion.academy/signal/doc/latest](https://intrusion.academy/signal/doc/latest)**. |

> [!TIP]
> New to Signal? Start with the documentation at
> **[intrusion.academy/signal/doc/latest](https://intrusion.academy/signal/doc/latest)**.
> This README covers only how to run the console.

## ✨ What the console shows

- **🎯 Signals first.** What every rule raised on every host, ranked, with the evidence behind it and a triage decision per analyst.
- **🕳️ What you can't see.** For each host, the evidence it could not provide (logs cleared or switched off, sources missing), so a missing answer never reads as a "no".
- **🧩 One page per entity.** A user, process, service or file is shown with what every source says about it, its timeline, its links and its signals.
- **📊 Stacking across hosts.** What the hosts have in common and what is rare: programs, services, persistence, remote-access tools and more.
- **🗺️ ATT&CK coverage.** The MITRE ATT&CK matrix of the rules evaluated on the hosts in view.
- **🕒 Timeline and graph.** Events across hosts in UTC, with analyst tags and notes, and a graph of how the entities relate.
- **🌐 Topology.** The networks the hosts sit on and which hosts talked to each other.
- **📝 Reports.** A compromise assessment report built from the findings and the analysts' triage.
- **🔒 Local and private.** No cloud, no telemetry and no build step. Local accounts with roles, an audit log, and HTTPS.

## 🚀 Quick start

**Requirements:** Node.js 22.5 or later (the console uses Node's built-in
`node:sqlite`), and the Signal executable from
[intrusion.academy/signal](https://intrusion.academy/signal).

```bash
git clone https://github.com/intrusion-academy/Signal-Console-Community.git
cd Signal-Console-Community
npm ci --omit=dev
npm start
```

On its first start, the console asks in the terminal for an administrator's
name and password, then listens on **http://localhost:7446**. Set `PORT` to
use another port and `SIGNAL_CONSOLE_DATA` to keep its data somewhere other
than `data/`.

### Collect and import runs

1. **Run Signal on each host** and write its run file to a folder you collect, for example a share:

   ```
   signal live -all -o \\fileserver\signal-runs\
   ```

2. **Import.** Sign in, open **Import**, and choose or drop the run files. One upload takes up to 200 files of up to 50 MB each. Each file is checked against Signal's output contract before it is stored, and a file from a newer Signal is refused with the reason.

The console holds one set of runs. Remove runs on the Import page when you
no longer need them.

## 👥 Accounts

Every page and every API route needs a signed-in account. Accounts are local
to the console; nobody can register themselves.

| Role | Can |
|---|---|
| `admin` | Everything, including accounts, settings and the audit log |
| `analyst` | Triage, suppression rules, flags, and importing and removing runs |
| `viewer` | Read only; the server refuses any change |

An administrator manages accounts on **Settings → Users**, or on the server:

```bash
npm run users -- add <name> analyst|admin|viewer
npm run users -- list | passwd <name> | role <name> <role> | disable <name> | enable <name> | remove <name>
```

<details>
<summary><b>How sign-in is protected</b></summary>

- Passwords are stored as salted scrypt hashes.
- A session is a random token in an HttpOnly, SameSite=Strict cookie, and the database keeps only a hash of it.
- A session ends after 8 hours idle, after 7 days at most, at sign-out, and when its account changes.
- After repeated failed sign-ins, the account is refused for 15 minutes.
- Sign-ins, refusals and account changes are recorded in the audit log (Settings → Audit log, administrators only).

</details>

## 🛡️ Security

- **Use HTTPS beyond a single machine.** Set `SIGNAL_CONSOLE_TLS_CERT` and `SIGNAL_CONSOLE_TLS_KEY` to a PEM certificate (with its chain) and key. Or put the console behind a reverse proxy and set `SIGNAL_CONSOLE_SECURE_COOKIE=1`.
- **Security headers on every response:** a Content-Security-Policy that allows only the console's own files, no framing, `nosniff`, no referrer, and HSTS over HTTPS.
- **Report a vulnerability** privately, as described in [SECURITY.md](SECURITY.md).

## 🏷️ Editions

| | **Community** | **Pro** | **Enterprise / Consultant** |
|---|:---:|:---:|:---:|
| Price | Free | Commercial | Commercial |
| `signal.exe` live mode, every module | ✅ | ✅ | ✅ |
| Console: import, triage, entities, timeline, ATT&CK, reports | ✅ | ✅ | ✅ |
| Collection at scale and multiple investigations | — | ✅ | ✅ |
| Windows forensics mode | — | ✅ | ✅ |
| Linux, macOS and cloud editions | — | Planned | Planned |
| Services to third parties | — | — | ✅ |
| Engagement support, exclusive threat-intelligence rules, training | — | — | ✅ |

See **[intrusion.academy/signal](https://intrusion.academy/signal)** for Pro, Enterprise, services and training.

## 📜 License

Copyright 2026 Intrusion Academy. All rights reserved except as granted by
the **Signal Community License 1.0.0** ([LICENSE](LICENSE), [NOTICE](NOTICE)).

In summary (the license text prevails):

- ✅ **You may** use, study and modify this software, free of charge, to defend the computers and networks that you or your organisation own or operate. Personal, educational and non-commercial research use is also allowed.
- 💼 **You need a commercial license (Pro or Enterprise)** to provide services to third parties with it (incident response, compromise or gap assessments, threat hunting, managed detection), to resell or redistribute it, or to build it into another product.
- ⚠️ It is provided "as is", without warranty of any kind.

Third-party packages and their licenses are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

<p align="center">
  <a href="https://intrusion.academy/signal"><img src="public/img/signal-mark-dark.png" width="48" alt="Signal"></a><br>
  <b>Signal</b> by <a href="https://intrusion.academy/signal">Intrusion Academy</a><br>
  <a href="https://intrusion.academy/signal">Website</a> · <a href="https://intrusion.academy/signal/doc/latest">Documentation</a> · <a href="SECURITY.md">Security</a> · <a href="LICENSE">License</a>
</p>
