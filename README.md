# Red Team Toolkit

An educational security assessment toolkit in Python. It scans network services,
audits configuration, analyses authentication logs, and turns version strings
into a prioritised patch list — then writes a report you can hand to whoever
owns the system.

> **Only test systems you own or have written permission to test.** See
> [docs/SAFETY.md](docs/SAFETY.md) for the authorization model, and
> `docker compose up -d` for a bundled lab to practise on.

```
rtt logs --file lab/logs/auth.log
```

```
Findings (8)
   medium=3  high=4  critical=1

    CRIT  Successful login for 'root' after 53 failures  (log.compromise-indicator)
        The log shows 53 failed attempts for 'root' followed by a success from 198.51.100.77,
        203.0.113.44. This is the single highest-signal event in an authentication log: either the
        attacker guessed the password, or they already had it and the failures were misdirection.
        fix: Treat as a probable compromise. Reset the credential, revoke active sessions and API
             tokens, review everything that account touched, and check for persistence.

    HIGH  203.0.113.44 generated 60 failed logins  (log.bruteforce-source)
        60 failures and 1 successes from 203.0.113.44 across 9 account(s) in 60s (61.0
        attempts/min). Top targets: root, admin, oracle, postgres, jenkins.
        fix: Block or rate-limit the source, force a password reset for any account it touched, and
             confirm whether the throttle that should have stopped it is actually enabled.

    HIGH  Account 'root' attacked from 2 addresses  (log.distributed-attack)
        53 failures for 'root' from 2 distinct sources, which is the shape of a distributed
        guessing attempt rather than a single noisy client.
        fix: Require MFA on this account and alert on the aggregate across source addresses.

    HIGH  Password-spray pattern from 198.51.100.9: 14 accounts, at most 1 attempt(s) each
        15 failures from 198.51.100.9 spread across 14 distinct account(s) in 28s, with no
        account taking more than 1 attempt(s) (jsmith was the most targeted). This is the shape
        of password spraying, which is deliberately engineered to stay below per-account lockout
        thresholds, so per-account alerting alone will not catch it.
        fix: Alert on the distinct-account count per source address over a sliding window rather
             than per account, and enforce MFA so a sprayed password is not sufficient.

    MED   198.51.100.9 generated 15 failed logins  (log.bruteforce-source)
    MED   Probing of 11 generic service account name(s)  (log.account-enumeration)

   findings               8  (critical=1   high=4   medium=3)
   highest severity       CRITICAL
```

Four attack shapes in one file, separated by what the numbers mean rather than how
big they are: a single-source flood, a distributed attempt on one account, spraying
thin across many, and generic-account enumeration.

## Contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Output and exit codes](#output-and-exit-codes)
- [Authorization model](#authorization-model)
- [What each module checks](#what-each-module-checks)
- [Lab](#lab)
- [Project layout](#project-layout)
- [Development](#development)
- [Roadmap](#roadmap)
---

## Why this exists

The first version of this project was 313 lines, and it printed a reverse shell.
It counted the word "failed" in a log file and called the result a finding. It
treated ports 22, 80 and 443 as "common" and had no notion of severity.

This version keeps the same shape — a handful of modules behind one CLI — and
changes what the modules actually do:

- **Findings, not numbers.** Every check returns a severity, an explanation of
  why it matters, and a concrete fix. A missing `X-Frame-Options` header is not
  a line of output; it is a clickjacking exposure with a one-line remedy.
- **The number is the point.** 200 failed logins is noise. 200 failures against
  one account from one address in 40 seconds, followed by a success, is a
  probable compromise. The log module builds the aggregation that makes the
  difference visible.
- **Scoring that resists decoration.** `P@ssw0rd2024!` looks strong and is
  weak. The password analyser decomposes a candidate into the cheapest pattern
  that explains it — dictionary word, keyboard walk, leet substitution, year,
  repeated run — and estimates from there, so length and character-class count
  cannot disguise a predictable password.
- **Defensive breadth.** Firewall rulesets, SSH configuration, TLS posture,
  stored password hashes and email authentication were all missing. They are the
  controls an assessor spends most of their time on.
- **It cannot be used to break into anything.** There is no login attempt, no
  shell, no exploit. The `attack` command orchestrates the assessment; the
  credential stage reads a wordlist and scores it locally.

---

## Install

```bash
git clone https://github.com/vinay-kumar-kode/Red-Team-Toolkit.git
cd Red-Team-Toolkit

# Option A: run straight from the checkout, no install
python3 main.py --help

# Option B: install, which gives you the shorter `rtt` command
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
rtt --help
```

One runtime dependency (`requests`). Everything else is standard library, which
matters when the assessment machine has no package manager.

Requires Python 3.10 or newer. Tested on 3.10 through 3.13.

> Paths in the examples are relative to the repository root, so run the commands
> from there unless you installed the package.

---

## Quick start

```bash
# Bring up deliberately vulnerable lab targets on 127.0.0.1
docker compose up -d

# Full assessment across every lab service, all report formats
rtt attack --target 127.0.0.1 --i-understand \
    --ports 22,3000,5432,6379,8081,8088,2222 \
    --format all --output reports/

# Open reports/rtt-attack-<timestamp>.html
```

Nothing above leaves loopback, and `--i-understand` is the flag that says you
are authorised to test the target.

The `--ports` list is explicit because the default set of 31 common ports misses
three of the seven lab targets: Juice Shop on 3000, DVWA on 8081 and sshd on
2222. Omit it and the scan covers 4 of the 7 services the lab is running, which
is exactly the kind of quiet gap that makes a scan look clean.

Already have a log or a config to review? Every offline command works with no
target and no authorization at all:

```bash
rtt logs --file lab/logs/auth.log
rtt hash-audit --file lab/hashes/dump.txt
rtt ssh --config lab/ssh/sshd_config
rtt phishing --file lab/logs/phish.eml
```

---

## Commands

### Network

These open a socket, so they need `--i-understand` and stay inside the default
scope.

```bash
# Port scan with service fingerprinting, banner capture and CVE mapping
rtt scan --target 127.0.0.1 --i-understand
rtt scan --target 127.0.0.1 --ports 22,80,3000,8000-8010 -t 0.5 --i-understand
rtt scan --target 127.0.0.1 --no-banners --no-cve --i-understand

# HTTP/HTTPS configuration review
rtt webscan --url http://127.0.0.1:8088 --i-understand
rtt webscan --url https://target --reflect --i-understand
rtt webscan --url http://127.0.0.1:8088 --no-paths --i-understand

# TLS protocol, cipher and certificate audit
rtt tls --target 127.0.0.1 --port 8443 --matrix --i-understand

# SSH: grade a config offline, or probe a live service without authenticating
rtt ssh --config /etc/ssh/sshd_config
rtt ssh --target 127.0.0.1 --port 2222 --i-understand

# The whole workflow
rtt attack --target 127.0.0.1 --wordlist wordlists/creds.txt --i-understand
```

### Offline

These read files or reason locally. No network, no authorization, safe to run
anywhere.

```bash
# Password strength, with the pattern that explains the score
rtt password --check 'P@ssw0rd2024'
rtt password --user jsmith < wordlist.txt        # flags the account name too
rtt password --file passwords.txt
rtt password --wordlist wordlists/creds.txt      # cost of exhausting a combo list

# Stored password hashes: algorithm, cost parameters, reuse, crack time
rtt hash-audit --file lab/hashes/dump.txt
cat hashes.txt | rtt hash-audit

# Authentication log analysis
rtt logs --file /var/log/auth.log
rtt logs --file /var/log/auth.log --threshold 3 --window 120
rtt logs --file /var/log/auth.log --detect-rules

# Firewall ruleset: iptables-save, nft, ufw or firewall-cmd output
iptables-save > fw.txt && rtt firewall --file fw.txt
nft list ruleset > nft.txt && rtt firewall --file nft.txt

# Email authentication and phishing triage
rtt phishing --file lab/logs/phish.eml
rtt phishing --directory inbox/
rtt phishing --stdin < message.eml

# Detection rules and IOC extraction
rtt detect --file suspicious.log
rtt detect --rules                              # print the rule catalogue
rtt detect --file app.log --extra-rules myrules.tsv

# CVE matching against the bundled offline database
rtt cve-lookup --product 'Apache HTTP Server' --version 2.4.49
rtt cve-lookup --list
rtt cve-lookup --file versions.txt              # one "product version" per line
```

Every command has `--help`.

---

## Output and exit codes

`--json` controls **stdout**. `--format` controls **what gets written to disk**.
They are separate, and mixing them up is the most common surprise:

```bash
# Human-readable summary on stdout
rtt logs --file /var/log/auth.log

# Machine-readable on stdout and nothing else, so this pipes
rtt logs --file /var/log/auth.log --json | jq '.findings[] | select(.severity=="critical")'

# Write report files (json, html and txt) into a directory
rtt attack --target 127.0.0.1 --i-understand --format all --output reports/

# Write nothing at all
rtt ssh --config /etc/ssh/sshd_config --format none
```

| Flag | Effect |
|---|---|
| `--json` | Bundle as JSON on stdout, and suppress all human output |
| `--format text\|json\|html\|all\|none` | Report file formats to write |
| `--output DIR` | Where to write them (default `reports/`, or `$RTT_OUTDIR`) |
| `--basename NAME` | Filename stem, instead of `rtt-<command>-<timestamp>` |
| `-q, --quiet` | Suppress all output, keep the exit code |
| `--no-color` | Disable ANSI colour (`NO_COLOR` env var also works) |
| `--show-all` | Print every finding, not the first 12 |

The HTML report is a single self-contained file with no external assets and no
network requests, so it can be attached to a ticket or emailed and still render
offline. The text and JSON reports never contain a password, even when the
assessment was about one.

| Exit code | Meaning |
|---|---|
| `0` | Ran cleanly, or findings below the threshold |
| `1` | Findings at or above `--fail-on` |
| `2` | Usage or runtime error, including a refused target |

That makes the tool usable as a CI gate:

```bash
# Fail the build on a weak SSH config, print nothing
rtt ssh --config /etc/ssh/sshd_config --format none -q --fail-on high || exit 1

# Fail on anything critical, and keep the JSON for the job log
rtt firewall --file fw.txt --json -q --fail-on critical > gate.json || exit 1
```

---

## Authorization model

Network commands require an explicit acknowledgement and stay inside a default
scope.

| Target | Default | Override |
|---|---|---|
| Loopback `127.0.0.0/8`, `::1` | allowed | — |
| RFC1918 `10/8`, `172.16/12`, `192.168/16` | allowed | — |
| Public internet | **refused** | `--allow-public` |
| Metadata, CGNAT, multicast, reserved | **refused, no override** | none |

```bash
rtt scan --target 10.20.30.40 --i-understand                 # private: fine
rtt scan --target 8.8.8.8 --i-understand                    # refused: outside default scope
rtt scan --target 8.8.8.8 --i-understand --allow-public     # allowed, deliberately
rtt scan --target 169.254.169.254 --allow-public            # refused, always
```

The metadata row is checked before the acknowledgement, so it cannot be reached
by any combination of flags. `--scope` widens the permitted ranges and is
repeatable:

```bash
rtt scan --target 10.20.30.40 --i-understand --scope 10.20.0.0/16
```

Full details, including rate-limiting advice and what each module actually
sends, in [docs/SAFETY.md](docs/SAFETY.md).

---

## What each module checks

**`scanner`** — concurrent TCP connect across a bounded pool; distinguishes
`closed` (refused) from `filtered` (dropped), which are different signals; reads
service banners with a protocol-appropriate probe; reads a greeting from
unregistered ports, because SSH, FTP, SMTP, MySQL and Redis all speak first;
sends one `HEAD` to a silent odd port, because web apps on odd ports are common;
extracts product and version; maps versions to CVEs. Ports are capped at 4096
per scan, and any single range at 4096 wide, so a typo cannot become a packet
storm.

**`password`** — decomposes each candidate into the cheapest explanatory pattern
(dictionary word, leet substitution, keyboard row or walk, sequence, repeat,
date, the account name), then estimates the two attack costs that actually
matter: online against a login endpoint, and offline on one GPU. `--user` feeds
the account name in, so `jsmith-Summer2024` is reported as a username-derived
password rather than a 17-character one. Never writes the password into a report.

**`webscan`** — security-header baseline with per-header severity, leaky
`Server`/`X-Powered-By` banners, CSP strength analysis including the
`default-src` fallback and nonce and hash forms, cookie attributes, TRACE and
write methods, and 18 accidentally-published paths. All requests are read-only.
The reflection check only reports *whether* a harmless alphanumeric marker came
back and flags it for manual review; deciding exploitability is not a call this
tool should make for you.

**`logs`** — brute force, password spraying (spread thin across accounts to stay
under the per-account lockout), distributed attacks, generic-account probing,
failure bursts, and the fail-then-success sequence. Parses syslog, sshd, Apache
and Nginx shapes plus a tolerant generic classifier, and infers the year that
syslog omits from the file's mtime.

**`tls_audit`** — protocol version, certificate chain and hostname validity,
`notBefore`/`notAfter`, over-long lifetimes, negotiated cipher, compression.
Classifies CBC-era suites by effective key length, because OpenSSL names them
without the word CBC. Continues the audit after a validation failure so the rest
still runs, and says "not checked" rather than implying a clean result when
verification was disabled. `--matrix` probes each protocol version in isolation,
and `client_offered_versions()` reports which versions your own OpenSSL can even
offer, so a client-side policy is never mistaken for a server finding.

**`ssh_audit`** — offline `sshd_config` grading including `Include` globs, `Match`
blocks, and the difference between a weak explicit value and an unset keyword
falling back to a weak default. Live mode reads the banner and the
pre-authentication algorithm proposal and flags weak KEX, ciphers, MACs and host
keys. **No authentication is attempted.**

**`hash_audit`** — identifies bcrypt, argon2i/d, scrypt, yescrypt, pbkdf2,
md5crypt, DES-crypt, MD5/SHA families and Django formats; judges cost parameters
against current guidance; estimates crack time; finds reused passwords by
identical digest. Hashes are never cracked.

**`firewall_audit`** — iptables, nftables, ufw and firewalld. Default-deny on the
input path, world-reachable sensitive ports, missing `ESTABLISHED,RELATED`,
unlogged drops, SSH without a rate limit, and rule ordering. Ordering analysis
excludes stateful and loopback accepts, so a correct ruleset does not produce a
false positive. An `ACCEPT` output policy is not flagged, because that is the
correct setting.

**`phishing`** — SPF/DKIM/DMARC verdicts, Reply-To and Return-Path mismatches,
display-name tricks, lookalike domains (including character-substitution
normalisation, so `paypa1-secure.com` reads as PayPal), URLs embedding
credentials before the real host, bare-IP links, deceptive attachments, and
manufactured urgency. Clean mail stays clean, which is the point: a triage tool
you have to re-read for false positives is a tool you stop reading.

**`cve_lookup`** — offline version-range matching. Every result is labelled a
candidate: the bundled database is a small curated subset, and a product it does
not cover is reported as *unknown*, never as *clean*.

**`detect`** (module `payload.py`, `payload` is an accepted alias) — fourteen
detection rules mapped to MITRE ATT&CK, applied to log text, plus IOC extraction
that filters out private, loopback and documentation ranges so a blocklist does
not fill up with `10.0.0.1`. This module replaced the original payload generator;
see [docs/SAFETY.md](docs/SAFETY.md#what-changed-from-version-1-and-why).

---

## Lab

```bash
docker compose up -d
```

| Target | Port | Why it is there |
|---|---|---|
| DVWA | 8081 | Web app on a non-standard port, no security headers |
| Juice Shop | 3000 | A modern SPA, so header grading has something realistic |
| nginx | 8088 | Serves `/.env` and `/.git/config`; TRACE on; permissive CSP |
| sshd | 2222 | A deliberately weak `sshd_config` |
| redis | 6379 | No authentication, the default that should be flagged |
| postgres | 5432 | TLS and credential-surface checks |
| TLS (opt-in) | 8443 | Self-signed, 800-day certificate, TLS 1.0 accepted |

Everything binds to `127.0.0.1`. Add the TLS target with
`docker compose --profile tls up -d`, then `docker compose down -v` to tear the
whole lab down.

The repository also ships sample inputs that need no Docker at all. Each one is
annotated with the findings it is designed to produce:

```bash
rtt logs --file lab/logs/auth.log          # brute force + spray + fail-then-success
rtt hash-audit --file lab/hashes/dump.txt  # every algorithm detector
rtt ssh --config lab/ssh/sshd_config       # every SSH setting check
rtt phishing --file lab/logs/phish.eml     # lookalike domain + DMARC fail
rtt phishing --file lab/logs/legit.eml     # the clean baseline, for contrast
```

---

## Project layout

```
redteam_toolkit/
  cli.py              argparse, exit codes, output contracts
  config.py           service map, header baseline, severity scales
  models.py           Report / Finding, the shape every module returns
  guardrails.py       the authorization gate
  modules/            one file per capability
  reporting/          text, JSON and self-contained HTML renderers
  utils/              address handling, terminal output
data/cve_db.json      offline CVE subset
docs/SAFETY.md        authorization model and data handling
lab/                  sample inputs and the docker lab
tests/                538 tests, hermetic
```

Every module is a function that takes options and returns a `Report`, so the
CLI stays thin and each module is usable from a script or a notebook:

```python
from redteam_toolkit.modules import ssh_audit

report = ssh_audit.audit_config("/etc/ssh/sshd_config")
for finding in report.at_or_above("high"):
    print(finding.title, "->", finding.remediation)
```

---

## Development

```bash
make dev        # venv + editable install with dev extras
make test       # pytest
make cov        # coverage report, writes htmlcov/
make lint       # ruff check + ruff format --check
make typecheck  # mypy, strict
make check      # everything CI runs
make build      # sdist and wheel
make lab        # bring up the vulnerable lab
make demo       # full assessment against the lab, all report formats
```

CI runs lint, format, mypy and the suite on Python 3.10 through 3.13, plus a
smoke test of the offline commands, an assertion that the authorization gate
refuses an unacknowledged scan, a check that the HTML report is self-contained,
and a build-and-install check that runs the installed console script.

Pre-commit hooks are configured:

```bash
pip install pre-commit && pre-commit install
```

---

## Roadmap

- [x] Severity model with remediation on every finding
- [x] JSON and self-contained HTML reports
- [x] Concurrent scanning with banner capture and version extraction
- [x] Offline CVE matching
- [x] Firewall, SSH, TLS, hash and email audits
- [x] Authorization gate with a default-scope allowlist
- [x] Password scoring that resists decoration
- [x] CI, strict typing, 538 tests
- [ ] Live credential auditing against a lab service, still loopback-only
- [ ] Risk scoring across a whole estate, not one host at a time
- [ ] Remediation diffs: show the config change, not just the finding
- [ ] SBOM ingestion so a scan can be matched against a real inventory

---

## License

MIT. See [LICENSE](LICENSE).

The bundled CVE data is a curated educational subset, and its affected-version
ranges should be spot-checked against upstream before you rely on them
operationally. Verify every match against the vendor advisory and NVD.
