# CVE2PoC - Zimbra defensive CVE tracking

This tool helps Zimbra operators track CVEs, public PoCs, CISA KEV, EPSS,
weaponized modules, and whether a credible fix record is visible. It also keeps
the general CVE2PoC public-PoC lookup features available for single-CVE
research.

The reason for this project is operational: one way to defend a Zimbra
deployment is to see what public security research and exploit indexes already
expose. Zimbra
security information is spread across vendor release notes, NVD/CVE.org, exploit
indexes, and third-party CVE sites, and those sources can lag, disagree, or
disappear behind broken filtered views. This tool pulls those signals together
so an operator can decide whether a risky Zimbra feature update is justified for
their environment.

If your goal is Zimbra operations, start with [QuickStart.md](QuickStart.md).

## Recommended Zimbra Workflow

Use the wrapper script from this checkout:

```sh
./zimbra-cve.sh install          # one-time install via uv, pinned to Python 3.12
./zimbra-cve.sh show 10.1        # full Zimbra CVE table, sorted for the 10.1 line
./zimbra-cve.sh watch 10.1       # stateful monitor for cron
./zimbra-cve.sh cve CVE-2024-27443
./zimbra-cve.sh update           # reinstall from this checkout
```

`show` uses an NVD keyword search for Zimbra, then triages every published CVE it
finds. CVE IDs in the tables are clickable terminal hyperlinks in terminals that
support OSC-8 links, such as GNOME Terminal. Terminals without OSC-8 support
show normal text.

## Installation

The wrapper handles installation:

```sh
./zimbra-cve.sh install
```

It uses `uv` to fetch a managed Python 3.12 and install `cve2poc` as a uv tool.
If `uv` is missing, the script explains the bootstrap first and asks before it
downloads Astral's uv installer and runs it with `sh`. On this system the
installed tool lives at:

- launcher: `~/.local/bin/cve2poc`
- uv tool env: `~/.local/share/uv/tools/cve2poc/`

When `zimbra-cve.sh` is run from a checkout that contains `pyproject.toml`,
`install` and `update` install from that local checkout. They do not pull from a
remote GitHub project.

If you answer no, install `uv` yourself and rerun `./zimbra-cve.sh install`.
In non-interactive shells, the script refuses to bootstrap `uv`.

To install directly without the wrapper:

```sh
uv tool install --force --python 3.12 <path-to-this-checkout>
```

Install from this checkout or from `JimDunphy/CVE2PoC` if you need the
Zimbra/watch/fix-triage features.

## Direct `cve2poc` Commands

The wrapper is easiest for Zimbra, but the direct CLI is still available:

```sh
cve2poc CVE-2024-27443
cve2poc --zimbra-cpe 10.1
cve2poc --zimbra-scan 10.1
cve2poc --watch "$(cve2poc --zimbra-cpe 10.1)"
cve2poc --show-state ~/.cve2poc/watch/<state-file>.json
cve2poc --cve2cpe CVE-2024-27443
cve2poc --cpe2cve "cpe:2.3:a:zimbra:collaboration:10.0.0"
```

Run `cve2poc --help` for the complete current option list.

## Key Features

- Zimbra train shortcuts: `10.1`, `10.0`, `9.0`, and `8.8` resolve to the
  latest patch in that line.
- Full Zimbra keyword scan: shows CVEs even when NVD has weak or missing Zimbra
  CPE version data.
- Cross-source context: complements the
  [Zimbra Security Center](https://wiki.zimbra.com/wiki/Security_Center) and
  third-party CVE sites such as
  [CVEDetails](https://www.cvedetails.com/vulnerability-list/vendor_id-7863/Zimbra.html)
  instead of trusting any single source to be complete.
- Defensive triage: folds CISA KEV, EPSS, public PoCs, weaponized modules, and
  CVSS into a practical risk label.
- Fix signal tracking: reports `Fixed?` as `Yes` only when the CVE record has a
  credible fix signal.
- Stateful watch mode: first run establishes a baseline; later runs report only
  new or worsened CVEs.
- Original CVE2PoC features: GitHub/Nuclei/Exploit-DB/Metasploit lookup,
  CVE/CPE mapping, reports, labs, and bug bounty references.

## Documentation

- [QuickStart.md](QuickStart.md) - shortest path for the Zimbra workflow.
- [doc/usage.md](doc/usage.md) - direct `cve2poc` usage and watch-mode details.
- [doc/SCOPE.md](doc/SCOPE.md) - what this project is and is not trying to do.

## Scope And Safety

This is a defensive research and tracking tool. It queries public vulnerability,
advisory, and PoC databases, then reformats that information so Zimbra operators
can make a patching or mitigation decision.

It does not exploit systems, run PoCs, scan hosts, or touch a target site. Some
single-CVE output includes example command snippets or links for external tools;
those are printed as references only and are not executed.

## Acknowledgement

This project began from the GPLv3
[CVE2PoC](https://github.com/0liverFlow/CVE2PoC) project by Olivier Konaté. It
is independently maintained for defensive Zimbra CVE tracking; project-specific
issues and behavior belong here.
