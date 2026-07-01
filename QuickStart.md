# QuickStart

See and track the CVEs affecting your Zimbra version and their public exploits,
so you can decide whether a CVE is actually worth patching.

Why this exists: Zimbra updates are often feature updates, not narrow security
patches, and applying them can break production systems. At the same time,
Zimbra's own security notes, NVD/CVE.org records, public PoC indexes, and
third-party CVE sites do not always line up cleanly. This tool gives you the
defensive context an operator needs before deciding whether to patch now, test
first, mitigate, or keep watching.

Everything is driven by `zimbra-cve.sh` with a simple verb:

```
./zimbra-cve.sh install          set up the tool (one time)
./zimbra-cve.sh show   10.1      show the full current CVE table  ← the everyday one
./zimbra-cve.sh watch  10.1      monitor: baseline, then only what changed (cron)
./zimbra-cve.sh cve    CVE-...   details + public PoCs for one CVE
./zimbra-cve.sh update           reinstall/update the tool
./zimbra-cve.sh help             cheat sheet
```

The version can be either:

- a **train** — `10.1`, `10.0`, `9.0`, `8.8` — resolved to that line's **latest
  patch**, the same way you'd think "I'm on 10.1"; or
- an **exact version** — `10.1.16`, `9.0.0.p46`, `8.8.15.p47` — for a specific
  patch level.

Either way the right CPE is built automatically — you never craft one by hand.
(Latest-per-train values come from the Zimbra Releases wiki; if you're on a
specific patch, pass it exactly.)

## 1. Install

On any modern Linux box:

```sh
./zimbra-cve.sh install
```

`install` uses [`uv`](https://docs.astral.sh/uv/) to fetch a managed Python 3.12
(so an older system Python can't crash the tool) and install `cve2poc`.

If `uv` is missing, the script stops and explains the bootstrap step before doing
anything: it will ask before downloading Astral's uv installer and running it
with `sh`. Only a shell and `curl`/`wget` are required if you approve that
bootstrap.
If you answer no, install `uv` yourself and rerun `./zimbra-cve.sh install`.
In non-interactive shells, the script refuses to bootstrap `uv`.

When this script is run from this checkout, `install` and `update` install from
the local source tree into uv's tool environment. On a normal setup the launcher
is `~/.local/bin/cve2poc`, pointing into `~/.local/share/uv/tools/cve2poc/`.

## 2. See what your Zimbra version has

```sh
./zimbra-cve.sh show 10.1        # sort by relevance to the 10.1 line
./zimbra-cve.sh show 10.0.18     # or an exact patch level
```

`show` discovers **every** CVE that mentions Zimbra (NVD keyword search — these
are assigned by third parties/MITRE, *not* by Zimbra, so it doesn't depend on
Zimbra's spotty CPE bookkeeping), triages each, and **sorts by relevance to your
version**:

- **Affects 10.1? = Yes** — NVD's version data puts your line in range.
- **? (unknown)** — the CVE mentions Zimbra but has no usable version data; kept,
  not dropped, so serious CVEs NVD never tied to a version still surface.
- **no** — NVD's data rules your line out (shown last).

Every CVE also carries **Fixed? = No unless there's a credible fix record** —
Zimbra not reporting a fix does not count as fixed. It's read-only and it's a
full scan (~150 CVEs, ~30–60s).

The CVE IDs are clickable terminal hyperlinks to NVD in terminals that support
OSC-8 links, such as GNOME Terminal. Terminals without OSC-8 support, including
some macOS terminal setups, will still show the plain CVE IDs.

## 3. Dig into one CVE

When something looks serious, look at the CVE directly for its triage panel and
links to public PoCs and advisories. Review the reference, then apply **your
own** judgment about whether it's reachable in your environment.

```sh
./zimbra-cve.sh cve CVE-2024-27443
```

## 4. Monitor over time (cron)

`watch` is the stateful monitor: the first run prints a baseline, and every run
after that prints only what is **new or has worsened** (added to KEV, a PoC
dropped, EPSS jumped, …). Ideal for a scheduled job:

```cron
0 8 * * *  /path/to/zimbra-cve.sh watch 10.1 | mail -s "Zimbra CVE watch" you@example.com
```

Each version keeps its own history, so you can watch several (10.1, 10.0, 9.0,
8.8) independently.

## Upgrade

```sh
./zimbra-cve.sh update
```

---

`show` vs `watch`: use **show** to look now (full list, read-only); use **watch**
to be told what changed (stateful, for cron). Full command reference is in
[`doc/usage.md`](doc/usage.md); the project's charter is in
[`doc/SCOPE.md`](doc/SCOPE.md).
