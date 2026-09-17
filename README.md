# Multi-Protocol Honeypot Network — `honey`

A defensive-security **demonstration project**: a network of fake services
that *invites* simulated attacks, captures everything an attacker does, turns
it into **threat intelligence**, and raises alerts — all on your own machine.

It ships with **two distinct deliverables**:

| Deliverable | What it is | Sockets? |
|---|---|---|
| **Live honeypot network** (`main.py`) | Six real protocol servers (SSH, HTTP, FTP, Telnet, MySQL, SMTP) that accept any login, log every interaction, and feed a live web dashboard | Yes |
| **Offline demonstration model** (`demo/demo_model.py`) | A standalone *simulation* of the whole network — attacker personas probe a virtual node graph, pushed through the *same* detection pipeline | No |

Because both run through the **same event bus, database, intel engine and
alert rules**, the offline model is a faithful model of the real system: what
you see simulated, the live network does for real.

```
D:\honey\
├── README.md                     ← you are here
├── requirements.txt
├── config.json                   # ports, banners, thresholds, dashboard
├── main.py                       # start the real honeypots + dashboard
├── honey/                        # core engine (importable package)
│   ├── config.py                 # config.json loader + defaults
│   ├── database.py               # SQLite persistence (connections, creds, …)
│   ├── eventlog.py               # event bus + coloured console logging
│   ├── intel.py                  # threat-intel engine (risk 0-100 + classes)
│   ├── alerts.py                 # alert rules + severities
│   ├── reporting.py              # self-contained HTML threat report
│   └── honeypots/                # one server per protocol
│       ├── base.py               # threaded socket-server base
│       ├── ssh_hp.py             # paramiko server + fake shell
│       ├── http_hp.py            # fake Apache + decoy paths
│       ├── ftp_hp.py             # fake ProFTPD
│       ├── telnet_hp.py          # fake shell over telnet
│       ├── mysql_hp.py           # protocol-faithful MySQL v10 handshake
│       └── smtp_hp.py            # fake Postfix open-relay trap
├── dashboard/
│   ├── app.py                    # Flask REST API + SSE live stream
│   └── static/index.html         # single-page dashboard
├── demo/
│   ├── demo_model.py             # ★ offline simulation + HTML report
│   └── attack_simulator.py       # ★ real attacks at the real honeypots
├── scripts/
│   ├── start.bat                 # launch the live network + dashboard
│   ├── demo_model.bat            # run the offline simulation + report
│   └── attack_demo.bat           # start honeypots, then fire scripted attacks
└── data/                         # runtime: honey.db, host.key, reports/
```

---

## 1. Install

Requires **Python 3.10+**.

```bash
pip install -r requirements.txt     # flask, paramiko
```

---

## 2. Demo A — offline simulation (no sockets)

The quickest way to see everything the project does. Simulates attacker
personas (botnet, web scanner, credential stuffer, telnet worm, database
thief, spambot, stealth operator) probing the six honeypots and plays back
the **real detection pipeline** as a coloured timeline, then writes and opens
a self-contained HTML threat-intelligence report.

```bash
python demo\demo_model.py
# or
scripts\demo_model.bat
```

Options:

```
--steps 200       number of simulated actions
--seed 42         random seed (reproducible runs)
--speed 0.05      seconds per action (0 = full speed)
--no-report       skip the HTML report
--report FILE     custom report path
```

Output: `data\reports\demo_report.html` (inline-SVG charts, offline-friendly).

---

## 3. Demo B — live network + real attacks

### Step 1 — start the network

```bash
python main.py
# or
scripts\start.bat
```

You'll see each honeypot announce its port and the dashboard address:

```
[main] 6/6 honeypot(s) listening:
  [main]   • ssh      on 0.0.0.0:22
  [main]   • http     on 0.0.0.0:80
  [main]   • ftp      on 0.0.0.0:21
  [main]   • telnet   on 0.0.0.0:23
  [main]   • mysql    on 0.0.0.0:3306
  [main]   • smtp     on 0.0.0.0:25
  [main]   • dashboard   at http://127.0.0.1:8080
```

If a standard port is taken (or your Windows user can't bind low ports), use
the included high-port config instead:

```bash
python main.py --config data\test_config.json
```

### Step 2 — fire real attacks (second terminal)

```bash
python demo\attack_simulator.py --plan sweep
# or
scripts\attack_demo.bat
```

Each attacker persona binds its client socket to its **own loopback address**
(`127.0.0.2` … `127.0.0.7`), so the intel engine and dashboard see a genuine
multi-source attack landscape. Three scenarios:

| Plan | Behaviour |
|---|---|
| `sweep` | Six personas, each hammering its own protocol |
| `targeted` | One botnet node attacks **all six** protocols (multi-vector) |
| `stealth` | Slow, low-volume probing from a single source |

### Step 3 — watch it get detected

Open **http://127.0.0.1:8080** — the dashboard streams live events via SSE:
connections, captured credentials, commands, and alerts, with per-source risk
scoring. The same data is in `data\honey.db`.

---

## 4. Attacking with real tools

The honeypots speak standard protocols with realistic banners, so everyday
security tools work against them. All traffic is loopback-only.

```bash
# Port scan
nmap -sV 127.0.0.1

# SSH brute-force
hydra -l admin -P words.txt ssh://127.0.0.1
ssh root@127.0.0.1                # any password works -> fake shell

# HTTP decoys
curl -i http://127.0.0.1/wp-login.php
curl -i http://127.0.0.1/.env
# then open the page in a browser

# FTP / Telnet
ftp 127.0.0.1                     # USER admin / PASS admin
telnet 127.0.0.1                  # log in with anything, run commands

# MySQL / SMTP
mysql -h 127.0.0.1 -u root -proot
nc 127.0.0.1 25                   # EHLO / MAIL FROM / RCPT TO / DATA
```

Everything you type is captured in the database, scored, and shown on the
dashboard.

---

## 5. The threat-intelligence model

`honey/intel.py` keeps a per-source-IP profile and emits a **risk score
(0-100)** and one classification per update:

- **recon-scan** — rapid, shallow probing (many web paths)
- **brute-force** — repeated login attempts within a window
- **credential-stuffing** — default / common credentials tried
- **spam-relay** — SMTP open-relay behaviour (RCPT bursts)
- **multi-vector** — the same host hits 3+ protocols

The score combines burst pressure, persistence, protocol reach, credential
breadth, default-credential hits, and spam evidence. Alerts (`honey/alerts.py`)
fire at configurable severities — e.g. brute-force HIGH, multi-vector
CRITICAL. All thresholds live in `config.json` under `intel` and `alerts`.

---

## 6. Configuration

`config.json` controls everything:

- `protocols.*` — port, enabled flag, banner per service
- `http_decoy_paths` — the sensitive-looking URLs the web honeypot serves
- `default_credentials` — list of known-default creds (drives
  credential-stuffing detection)
- `intel.*` — thresholds for scoring / classification
- `alerts.*` — rule enable + severity
- `dashboard.*` — dashboard host/port

Use `python main.py --config <path>` (and `demo/attack_simulator.py
--config <path>`) to switch configurations — `data\test_config.json` is a
high-port, loopback-friendly variant for safe testing.

---

## 7. Data & reports

- **`data\honey.db`** — SQLite (WAL mode): `connections`, `credentials`,
  `commands`, `intel`, `alerts`.
- **`data\reports\threat_report.html`** — offline HTML report of whatever is
  in the database (inline-SVG charts, credential table, alert log). The demo
  model writes `demo_report.html`.

To re-render the live DB's report after an attack:

```bash
python -c "from honey.database import Database; from honey.reporting import generate_report; generate_report(Database(), output_path='data/reports/live_report.html')"
```

---

## 8. Extension ideas

Out of scope for this demonstration, but natural next steps:

- systemd / Windows service deployment
- geo-IP lookup and ASN enrichment per source
- email / SIEM / Slack alert forwarding
- time-based risk decay and attacker *bans*
- more protocols (RDP, VNC, DNS, SIP) and more decoy content

---

## ⚠️ Use responsibly

This project exists for **defensive security training and demonstration**.
Honeypots attract attacker traffic by design — run them only on networks you
control, and never point them at production systems or the internet without
proper isolation.

