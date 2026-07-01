# SCOPE

> Status: independent GPLv3 hard fork.
> A different product, not a patch set.
> Public, free — built for the Zimbra community. Fork-specific bugs belong to
> this fork.

## One line

Track the CVEs affecting a Zimbra deployment and their public exploits, so an
operator can decide whether a given CVE is worth patching.

## The problem it exists to solve

For a Zimbra operator, patching is not free. Zimbra ships **feature updates, not
narrow security-only patches**, so any update can break production while trying
to fix it. The default posture is therefore often *don't patch unless there is a
good reason*.

At the same time, the signal is fragmented. Zimbra's
[Security Center](https://wiki.zimbra.com/wiki/Security_Center) and release
notes can be useful, but CVE details may be missing, delayed, or marked `TBD`.
Third-party sites such as
[CVEDetails](https://www.cvedetails.com/vulnerability-list/vendor_id-7863/Zimbra.html)
can lag or fail. NVD and CVE.org may mention Zimbra without usable version data.
Public PoCs and exploit modules can appear before an operator has a clean vendor
answer.

This tool exists for that gap: one way to defend is to know what public security
research and exploit indexes already expose, then add local operational context.
For each CVE, the operator needs to answer: is it plausibly real for my version,
is it exploited in the wild, is there a public PoC or weaponized module, is
there a credible fix signal, and is the vulnerable surface reachable in my
environment?

## What it does

- **Show what Zimbra has.** For a Zimbra version, list the affecting CVEs with
  transparent risk signals (CISA KEV, EPSS, public-PoC maturity, weaponized
  modules, and whether a vendor fix exists). Use `show` to see the full list any
  time (read-only), or `watch` to monitor from cron and report only what is new
  or has worsened since last run.
- **Show public PoC context.** For any CVE, surface public PoC/advisory
  references so the operator can judge exploitability **in their own
  environment** (e.g. is the vector even reachable behind trusted address
  space).

The tool presents facts and public vulnerability intelligence. It does not
exploit systems, run PoCs, scan hosts, or touch a target site. It may print
example command snippets or links for external tools, but it does not execute
them. **It does not render an automated patch verdict** — the operator applies
their own operational context and decides whether to patch, mitigate, isolate,
test first, or keep watching. Deliberately no "recommendation engine," no fuzzy
logic.

## Principles

- **Operator decides.** The tool informs; you know your environment.
- **Transparent signals only.** Every number/flag traces to a source; nothing
  is a black box.
- **Zimbra is the guide, not a cage.** We optimize for Zimbra; the core does not
  hardcode it in a way that blocks other uses later.
- **Few docs.** Top level is `README.md` + `QuickStart.md`; everything else
  lives under `doc/` and may or may not be published.

## Out of scope (parked, not rejected)

- Automated patch recommendations / verdict engine.
- Custom operational/config checks (footguns that are not upstream CVEs).
- A generic multi-product / plugin framework.
- Running exploits, scanners, or attack tooling.
