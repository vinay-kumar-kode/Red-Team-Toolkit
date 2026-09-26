# Safety model

Read this before pointing the toolkit at anything you do not own.

## The one rule

**Only test a target you own or have written permission to test.** In most
jurisdictions, running a scanner or a credential check against someone else's
systems without authorisation is a computer-misuse offence regardless of intent.
"Educational" and "just a port scan" are not defences.

If you do not have that permission in writing, use the bundled lab instead:
`docker compose up -d`.

## What changed from version 1, and why

The original `payload` module printed a reverse-shell command string. It was
removed rather than extended. The replacement is a detection-engineering module:
a rule catalogue mapped to MITRE ATT&CK, a log matcher, and an IOC extractor.

Printing a working callback command teaches an attacker and helps nobody
defensive. A rule that *detects* the same command helps the person who has to
respond to it.

## The attack side is simulation-only

The `attack` workflow reads a combo wordlist and scores the passwords in it
**locally**. It never sends a credential to the target. There is no login
attempt, no session establishment, and no way to make any module in this project
authenticate against anything.

That constraint is enforced by construction: no module imports a credential
store, and no module performs a login. `tests/test_detect.py` asserts the
detection module has no process-execution surface either.

## Authorization gate

Every command that opens a socket goes through
`redteam_toolkit.guardrails.authorize`, which applies two independent checks.

**1. Acknowledgement.** You must confirm you are authorised.

- In a terminal: an interactive `Type 'yes' to continue:` prompt.
- Non-interactively (CI, scripts): the `--i-understand` flag.

Without one of these the command exits `2` and contacts nothing.

**2. Scope.** The resolved addresses must fall inside the permitted range.

| Range | Default | How to widen |
|---|---|---|
| Loopback `127.0.0.0/8`, `::1` | allowed | — |
| RFC1918 `10/8`, `172.16/12`, `192.168/16` | allowed | — |
| Public internet | **refused** | `--allow-public` |
| Link-local, CGNAT, multicast, reserved | **refused always** | not possible |

The last row is not overridable by any flag. It covers `169.254.169.254`, the
cloud instance-metadata address, along with carrier-grade NAT and multicast. A
mistake in a scan target should not be able to read another tenant's instance
credentials, so that path is closed with no override:

```console
$ rtt scan --target 169.254.169.254 --i-understand --allow-public --scope 0.0.0.0/0
   [x] refusing to probe 169.254.169.254: this range is infrastructure that does not
       belong to the operator (metadata, CGNAT, multicast). It cannot be allowed.
```

Add legitimate internal ranges with `--scope`, which is repeatable:

```bash
rtt scan --target 10.20.30.40 --i-understand --scope 10.20.0.0/16
```

## What the network modules actually do

| Module | Sends | Notes |
|---|---|---|
| `scanner` | TCP `connect()` to each requested port, plus one protocol-appropriate probe or `HEAD` request | Banners are length-capped at 512 bytes |
| `webscan` | `GET`/`HEAD`/`OPTIONS` to the target URL and a fixed list of 18 sensitive paths | Read-only. No writes, no uploads, no traversal |
| `tls_audit` | One TLS handshake, plus one per protocol version with `--matrix` | The KEXINIT exchange is unauthenticated by design |
| `ssh_audit` | One connection to read the banner and the algorithm proposal | **No authentication is attempted** |
| `attack` | Runs the above | The credential stage is a local file read |

`ssh_audit --config` and every offline module read files only and need no
authorization at all.

## Rate limiting and blast radius

The scanner defaults are deliberately modest: a 1-second per-port timeout and 64
concurrent connections. Both are adjustable.

- `--timeout 0.2 --workers 16` for a fast sweep of a large range.
- `--timeout 3 --workers 8` when the target is remote and latency matters.

Port-range parsing is capped at 4096 ports, and any single range at 4096 wide, so
a typo cannot turn into a packet storm.

## Reporting responsibly

Written reports contain IPs, hostnames, usernames, service versions and
sometimes the contents of `auth.log`. Anyone who can read a report can read
your network's weaknesses.

- `reports/` is gitignored. Do not commit report output.
- The password analyser never writes a password into a report. Pattern matches
  are redacted, so a report cannot reconstruct the value it was assessing.
  `tests/test_password.py` asserts this.
- Share a report with the same care as the findings themselves, and give the
  recipient a way to act on it rather than just a list of numbers.

## Data handling

- Passwords are analysed in memory and never written to disk or transmitted.
- Hashes are identified and cost-rated. They are never cracked.
- CVE matching reads a local JSON file. There is no telemetry and no outbound
  request other than the target traffic a command is explicitly asked to send.

## Responsible disclosure

If you find a real vulnerability using this tool on a system you are authorised
to test, report it to the owner privately and give them time to fix it before
disclosing. `docs/`-quality write-ups with an impact section get fixed far
faster than a bare CVE number.
