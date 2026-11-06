# CVE2PoC — Usage Guide (defensive edition)

> **Just want to see Zimbra's CVEs?** Use the helper — `./zimbra-cve.sh install`
> then `./zimbra-cve.sh show 10.1` (valid: 10.1, 10.0, 9.0, 8.8). See
> [`../QuickStart.md`](../QuickStart.md). This guide is the fuller reference for
> driving `cve2poc` directly.

This guide focuses on the **defender's workflow** — "how urgent is this for me,
and is there a fix?" — using a hosted **Zimbra** deployment as the running
example. The same commands work for any product.

The Zimbra workflow deliberately does not trust one source of truth. Vendor
release notes, Zimbra's Security Center, NVD/CVE.org, exploit indexes, and
third-party CVE sites each provide part of the picture, and any one of them can
be incomplete for a given CVE or release. The goal is to put the pieces on one
screen so you can make the operational call.

> These examples use the defensive features added in this fork (triage scoring,
> `--watch`, `--show-state`). If `cve2poc --help` doesn't list `--watch`, you're
> on the upstream build. Reinstall from this checkout with
> `./zimbra-cve.sh update` or
> `uv tool install --force --python 3.12 <path-to-this-checkout>`.

---

## 1. Find the CPE for your product

The watch feature takes a **CPE** (Common Platform Enumeration) string — a
standardized identifier for a piece of software at a given version. It looks
like this:

```
cpe:2.3:a:zimbra:collaboration:10.0.0
        │  │      │             │
        │  │      │             └─ version
        │  │      └─ product
        │  └─ vendor
        └─ part (a = application, o = OS, h = hardware)
```

**You don't have to guess it.** Ask CVE2PoC for the exact strings by looking up
any known CVE for your product with `--cve2cpe`:

```bash
cve2poc --cve2cpe CVE-2024-27443
```

```
Known Affected Software Configurations (CPE2.3)
-----------------------------------------------
cpe:2.3:a:zimbra:collaboration:10.0.0
cpe:2.3:a:zimbra:collaboration:10.0.1
cpe:2.3:a:zimbra:collaboration:10.0.2
...
```

Copy the line that matches the version you actually run. (Alternatively, browse
the official NVD CPE dictionary at <https://nvd.nist.gov/products/cpe/search>.)

To go the other way — see which CVEs a CPE is associated with — use `--cpe2cve`:

```bash
cve2poc --cpe2cve "cpe:2.3:a:zimbra:collaboration:10.0.0"
```

```
List of Affected CVE IDs
------------------------
CVE-2023-41106
CVE-2024-27443
...
```

> **Tip:** a *versioned* CPE (`...:10.0.0`) matches CVEs affecting that exact
> version. Point `--watch` at the version you're running in production.

---

## 2. Triage a single CVE

A normal lookup now ends with a **Defensive Triage** panel that folds CISA KEV,
EPSS, public-PoC maturity, weaponized modules and CVSS into one urgency verdict —
and flags the case that matters most when your vendor is slow to patch:
**a credible public exploit exists but no fix is referenced.**

```bash
cve2poc CVE-2024-27443
```

```
╭─ Defensive Triage — CVE-2024-27443 ──────────────────────────────────────────╮
│ Risk: CRITICAL  (score 74/100)                                               │
│ Public exploit: Yes    Weaponized module: Yes    Fixed: not reported fixed — │
│ assume vulnerable                                                            │
│                                                                              │
│   • ⚠ Credible public exploit exists but NO fix is referenced                │
│   • Listed in CISA KEV (known exploited in the wild)                         │
│   • Elevated EPSS (19.54%)                                                   │
│   • Nuclei template available (also usable to self-scan your hosts)          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

How the score is composed:

| Signal                         | Weight  |
|--------------------------------|---------|
| CISA KEV (exploited in wild)   | +40     |
| EPSS (exploitation likelihood) | up to +20 |
| Metasploit module              | +15     |
| Nuclei template                | +8      |
| Exploit-DB entry               | +7      |
| Public GitHub PoC(s)           | +6 / +12 (by maturity) |
| CVSS base score                | up to +10 |

The **danger-zone** flag only fires on a *credible* exploit (KEV, a weaponized
module, ≥10 stars, or ≥3 PoC repos) — a single throwaway PoC won't inflate the
label. Fix detection reads the CVE.org record (patched version / `patch`-tagged
reference / vendor solution). If your vendor never publishes structured fix data,
"none referenced" means *we couldn't find one* — treat it as "verify manually",
not a guarantee no patch exists.

> The Nuclei line is a source signal only. This tool does not run Nuclei or scan
> hosts; it reports that a public template exists.

### GitHub indexes and Metasploit pull requests

GitHub discovery checks **both** Nomi-sec and Trickest, combines their entries,
and keeps each original repository, file, directory, or pull request (PR) link. Repository
metadata is fetched using only `owner/repository`; a link to a specific file or
PR is not replaced with the repository homepage. Metadata failures leave the
reference visible, and stars on a parent repository do not become stars on an
individual file or PR.

The tool also searches titles and descriptions of pull requests in
`rapid7/metasploit-framework` for the exact CVE ID. For example:

```bash
cve2poc CVE-2026-93637
```

Matching PRs appear under **Metasploit PR references (informational)** with
their current open, draft, closed, merged, or unknown status. A PR reference is
a candidate for manual review: it does not establish that a module was merged,
released, or verified. PR references do not increase the GitHub PoC count or
the weaponized-module score. The existing Metasploit module index remains the
source for that score, even when a PR is marked merged.

Discovery reuses `GITHUB_API_TOKEN` for GitHub's application programming
interface (API) when configured; raw index requests do not receive that token.
Requests have finite
timeouts and results are cached within a run. Index collection is bounded to
50 entries per source and PR search to 20 results per CVE; incomplete or
truncated results produce warnings. GitHub rate limits stop further API
lookups in that run and leave an explicit warning. An unavailable source is
reported as incomplete rather than as a successful search with no matches.
`--limit` controls terminal display; `--language` filters indexed references
using repository language metadata and does not hide PR mentions.

The same discovery data is available in single-CVE output, batch JSON/HTML,
`--list`, `--zimbra-scan`, and watch state. Batch JSON keeps full evidence URLs,
PR status, source warnings, and completion flags under `GitHub Discovery`.
The HTML Metasploit Yes/No filter refers to indexed modules, independently of
the informational PR links in that column. Discovery reads public indexes and
GitHub metadata; it does not fetch or execute the linked PoC code.

---

## 3. Watch a product for new / worsening CVEs

`--watch` resolves every CVE affecting a CPE, triages each, and keeps a small
state file between runs so it reports only **what changed**. This is the
early-warning feed: run it on a schedule and stop finding out about exploits by
rumor.

### First run — establishes a baseline

```bash
cve2poc --watch "cpe:2.3:a:zimbra:collaboration:10.0.0"
```

```
[*] Resolving 15 CVE(s) for cpe:2.3:a:zimbra:collaboration:10.0.0 ...
[*] First run — establishing a baseline of 15 CVE(s). Future runs will report only changes.

🔥 Danger zone — public exploit, NO vendor fix
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ CVE ID     ┃   Risk   ┃ Score ┃  EPSS  ┃ KEV ┃ PoCs ┃ Weaponized ┃  Fixed?  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ CVE-2024-… │ CRITICAL │  74   │ 19.54% │ Yes │  5   │    Yes     │    No     │
└────────────┴──────────┴───────┴────────┴─────┴──────┴────────────┴───────────┘
... (full baseline table follows) ...

[*] State saved to /home/you/.cve2poc/watch/cpe_2_3_a_zimbra_collaboration_10_0_0-3555f264.json
```

CVE IDs in these tables are terminal hyperlinks to the NVD detail page when your
terminal supports OSC-8 links.

### Later runs — only deltas

```bash
cve2poc --watch "cpe:2.3:a:zimbra:collaboration:10.0.0"
```

```
[+] No new CVEs since last run.
Updates to tracked CVEs
  CVE-2024-27443: added to CISA KEV, weaponized exploit module appeared,
                  new public PoC(s) (0→5), EPSS jump (1.0%→19.54%),
                  entered danger zone (public exploit, no fix)
```

A CVE is reported as *worsened* when any of these happen since the last run:
added to CISA KEV · a weaponized module appeared · new public PoC(s) ·
EPSS jumped ≥10 points · it entered the danger zone.

New Metasploit PR references and changes to their status are also reported as
updates, without changing the risk score on that basis. A failed or partial PR
search retains previously observed PR references and their last known status,
with a warning that the refresh is incomplete. Unchanged PRs remain in saved
state and can be displayed with `--show-state`; source warnings remain visible
on watch runs even when no CVE changed.

### Run it on a schedule (cron)

```cron
# 8am daily — email yourself the changes for your Zimbra version
0 8 * * *  cve2poc --watch "cpe:2.3:a:zimbra:collaboration:10.0.0" | mail -s "Zimbra CVE watch" you@example.com
```

### Custom state file location

By default state lives at `~/.cve2poc/watch/<cpe-slug>-<short-hash>.json`.
Override it:

```bash
cve2poc --watch "cpe:2.3:a:zimbra:collaboration:10.0.0" --state-file /srv/monitoring/zimbra.json
```

---

## 4. Re-display a saved watch without hitting the network

`--show-state` reads a saved state file and renders it offline:

```bash
cve2poc --show-state ~/.cve2poc/watch/cpe_2_3_a_zimbra_collaboration_10_0_0-3555f264.json
```

```
[*] Watched product: cpe:2.3:a:zimbra:collaboration:10.0.0  (last run: 2026-07-01T17:17:05Z)

🔥 Danger zone — public exploit, NO vendor fix
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┓
│ CVE-2024-… │ CRITICAL │  74   │ 19.54% │ Yes │  5   │    Yes     │    No     │
└────────────┴──────────┴───────┴────────┴─────┴──────┴────────────┴───────────┘
Tracked CVEs (from saved state)
... (all CVEs, sorted most-urgent first) ...
```

Prefer raw JSON? The state file is plain JSON, so `jq` works too:

```bash
# Just the danger-zone CVEs, most urgent first
jq -r '.cves | to_entries
       | map(select(.value.danger_zone))
       | sort_by(-.value.score)[]
       | "\(.key)\t\(.value.score)\t\(.value.label)"' \
  ~/.cve2poc/watch/cpe_2_3_a_zimbra_collaboration_10_0_0-3555f264.json
```

---

## 5. Batch report for a set of CVEs

Have a list of CVEs from an advisory? Drop them in a file (one per line) and
generate JSON + HTML reports:

```bash
printf "CVE-2024-27443\nCVE-2023-41106\n" > zimbra_cves.txt
cve2poc -f zimbra_cves.txt -o ./reports
```

Produces `cve2poc_report_<date>_<time>.json` and `.html` (sortable table) in
`./reports`.

---

## 6. Quick reference

| Task                                        | Command |
|---------------------------------------------|---------|
| Discover the CPE for your product           | `cve2poc --cve2cpe <known-CVE>` |
| List CVEs for a CPE                          | `cve2poc --cpe2cve "<cpe>"` |
| Triage a single CVE (+ find PoCs)           | `cve2poc <CVE>` |
| Just the CVE description                     | `cve2poc <CVE> -d` |
| All Zimbra CVEs (keyword), sorted by version  | `cve2poc --zimbra-scan 10.1` |
| Show the full CVE table for a CPE (read-only)| `cve2poc --list "<cpe>"` |
| Watch a product for changes                 | `cve2poc --watch "<cpe>"` |
| Re-render a saved watch (offline)           | `cve2poc --show-state <file>` |
| Batch report (JSON + HTML)                   | `cve2poc -f <file> -o <dir>` |
| Show version (with banner)                   | `cve2poc --version` |

The ASCII banner is **off by default**; add `--banner` to show it, or run
`cve2poc --version`. Run `cve2poc --help` for the full flag list.

---

## 7. Run the discovery regression tests

From a checkout, install the project dependencies and run the offline tests:

```bash
uv sync --python 3.12
uv run python -m unittest discover -s tests -v
```

The tests use mocked public-source responses and make no network requests.
They cover exact-CVE PR discovery, preserved URLs, rate limits and malformed
responses, triage separation, CLI/report integration, and watch-state updates.
One HTML-filter test executes the generated JavaScript when `node` is on PATH;
it is skipped otherwise. Node is not a runtime dependency of CVE2PoC.

To check live discovery using this checkout:

```bash
uv run cve2poc --version
uv run cve2poc CVE-2026-93637
```

These commands use the project's local environment. They do not reinstall the
separately installed `cve2poc` tool used by `./zimbra-cve.sh`. Check any discovery
warnings when reviewing the result: a failed search cannot establish that no
public references exist.
