"""
Product watch mode for CVE2PoC.

Defenders don't think in CVE IDs — they think "I run Zimbra 10.0.x". This module
takes a CPE, resolves the CVEs affecting it, triages each one, and — by keeping a
small state file between runs — reports what is *new or has worsened* since
last time (new CVE, newly added to CISA KEV, a PoC just dropped, an EPSS spike,
or a slide into the "public exploit, no fix" danger zone), plus changes to
tracked Metasploit PR references.

Run it from cron against your product CPE and it becomes an early-warning feed
instead of something you only reach for after hearing a rumor.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich import print as rprint
from rich.table import Table
from rich.text import Text
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
)

from CVE2PoC.core.cpe import cpe_to_cveid
from CVE2PoC.core.cve import download_cisa_kev, download_first_epss
from CVE2PoC.core.discovery import GithubDiscoveryClient
from CVE2PoC.core.discovery_output import plain_text, poc_metrics
from CVE2PoC.core.exploits import download_exploits_db
from CVE2PoC.core.report import get_cve_record_and_exploits
from CVE2PoC.core.triage import compute_triage, LABEL_COLORS

# Upper bound on how many CVEs we deep-process in a single run. Silent caps read
# as "we covered everything" when we didn't, so if we exceed this we log it.
WATCH_MAX = 500

# EPSS increase (in percentage points) considered a meaningful worsening.
EPSS_JUMP_THRESHOLD = 10


def _default_state_path(cpe):
    """Derive a per-CPE state file under ~/.cve2poc/watch/.

    A short hash of the full CPE is appended so CPEs that differ only in
    punctuation (e.g. '...:10.0.0' vs '...:10.0.0:-') can't collide on the same
    file after slugification (the readable slug alone would strip the trailing
    ':-' and clash).
    """
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", cpe).strip("_") or "watch"
    digest = hashlib.sha1(cpe.encode("utf-8")).hexdigest()[:8]
    state_dir = os.path.expanduser("~/.cve2poc/watch")
    os.makedirs(state_dir, exist_ok=True)
    return os.path.join(state_dir, f"{slug}-{digest}.json")


def _load_state(path):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            rprint(f"[gold1][!][/gold1] Could not read existing state file {path}; treating as a first run.")
    return {}


def _save_state(path, state):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def _snapshot(cve_id, headers, kevs, epss_data, exploits_db, discovery_client=None):
    """
    Build a compact, comparable snapshot of a CVE's current risk posture.
    Returns (cve_id, snapshot_dict) or (cve_id, None) if it should be skipped
    (no record, reserved, or rejected).
    """
    result, error = get_cve_record_and_exploits(
        cve_id, headers, kevs, epss_data, exploits_db,
        discovery_client=discovery_client,
    )
    if error or result is None:
        return cve_id, None

    cve_record = result["cve_record"]
    if cve_record is None or cve_record.get("state") in ("RESERVED", "REJECTED", "N/A"):
        return cve_id, None

    gh_exploits, _ = result["github_pocs"]
    other_sources = result["pocs_from_other_sources"]
    discovery = result.get("github_discovery") or {"pocs": gh_exploits or []}
    gh_count, _ = poc_metrics(discovery)
    discovery_warnings = list(discovery.get("warnings") or [])

    triage = compute_triage(
        cve_record, gh_poc_count=gh_count, other_sources=other_sources
    )

    return cve_id, {
        "kev": cve_record.get("kev", "No"),
        "epss": cve_record.get("epss", "N/A"),
        "base_score": cve_record.get("base_score", "N/A"),
        "severity": cve_record.get("severity", "N/A"),
        "gh_pocs": gh_count,
        "weaponized": triage["weaponized"],
        "has_fix": triage["has_fix"],
        "score": triage["score"],
        "label": triage["label"],
        "danger_zone": triage["danger_zone"],
        "product": cve_record.get("affected_product", "N/A"),
        # PR references are discovery context, not indexed PoCs or proof that a
        # module is available. Keep them out of the triage inputs above.
        "metasploit_prs": [dict(pr) for pr in discovery.get("metasploit_prs", [])],
        "metasploit_prs_complete": discovery.get(
            "metasploit_prs_complete", not discovery_warnings
        ),
        "discovery_warnings": discovery_warnings,
    }


def _pr_status(pr):
    """Use the verified PR state without implying that an open PR was merged."""
    state = pr.get("state") or "unknown"
    if state == "open" and pr.get("draft"):
        return "open (draft)"
    return state


def _retain_pr_evidence(old, snap):
    """Preserve last-known PR references when the current search is incomplete.

    A failed or partial search is not evidence that a previously observed PR
    disappeared. Fresh results take precedence, including any verified state
    changes, while missing references survive until a complete search succeeds.
    """
    if snap.get("metasploit_prs_complete", True):
        return snap

    current = {pr["url"]: dict(pr) for pr in snap.get("metasploit_prs", [])}
    retained = 0
    references_retained = False
    for previous in old.get("metasploit_prs", []):
        fresh = current.get(previous["url"])
        reference_urls = list(dict.fromkeys(
            (fresh or {}).get("reference_urls", []) + previous.get("reference_urls", [])
        ))
        if fresh is None or (
            _pr_status(fresh) == "unknown" and _pr_status(previous) != "unknown"
        ):
            current[previous["url"]] = dict(previous)
            retained += 1
        elif (
            fresh.get("state") == previous.get("state")
            and fresh.get("draft") is None
            and previous.get("draft") is not None
        ):
            fresh["draft"] = previous["draft"]
            if "status" in previous:
                fresh["status"] = previous["status"]
            retained += 1
        kept = current[previous["url"]]
        if reference_urls and kept.get("reference_urls") != reference_urls:
            kept["reference_urls"] = reference_urls
            references_retained = True
    if not retained and not references_retained:
        return snap

    updated = dict(snap)
    updated["metasploit_prs"] = list(current.values())
    updated["discovery_warnings"] = list(snap.get("discovery_warnings") or [])
    warning = (
        f"Metasploit PR search incomplete; retaining {retained} previously "
        "observed PR reference(s) with last known status."
    ) if retained else (
        "Metasploit PR search incomplete; retaining previously observed PR evidence URLs."
    )
    if warning not in updated["discovery_warnings"]:
        updated["discovery_warnings"].append(warning)
    return updated


def _detect_changes(old, snap):
    """Return worsening risk signals and changes to public PR references."""
    deltas = []
    if old.get("kev") != "Yes" and snap["kev"] == "Yes":
        deltas.append("added to CISA KEV")
    if not old.get("weaponized") and snap["weaponized"]:
        deltas.append("weaponized exploit module appeared")
    if snap["gh_pocs"] > old.get("gh_pocs", 0):
        deltas.append(f"new public PoC(s) ({old.get('gh_pocs', 0)}→{snap['gh_pocs']})")
    old_epss, new_epss = old.get("epss"), snap["epss"]
    if (
        isinstance(old_epss, (int, float))
        and isinstance(new_epss, (int, float))
        and new_epss - old_epss >= EPSS_JUMP_THRESHOLD
    ):
        deltas.append(f"EPSS jump ({old_epss}%→{new_epss}%)")
    if not old.get("danger_zone") and snap["danger_zone"]:
        deltas.append("entered danger zone (public exploit, no fix)")

    previous_prs = {pr["url"]: pr for pr in old.get("metasploit_prs", [])}
    for pr in snap.get("metasploit_prs", []):
        previous = previous_prs.get(pr["url"])
        status = _pr_status(pr)
        if previous is None:
            deltas.append(f"new Metasploit PR ({status}): {pr['url']}")
        elif status != "unknown" and _pr_status(previous) != status:
            deltas.append(
                f"Metasploit PR {pr['url']}: {_pr_status(previous)}→{status}"
            )
    return deltas


def _cve_link(cve_id):
    """
    Render a CVE ID as a single clickable terminal hyperlink to its NVD page.
    Returned as a Text object (not markup) so rich's number highlighter can't
    fragment it into multiple spans. Terminals that support OSC 8 make it
    clickable; the rest just show the plain ID.
    """
    # Use an explicit span, not a base Text style. Rich may pad table cells to
    # the column width; a base style can make that trailing whitespace clickable.
    link = Text(cve_id)
    link.stylize(
        f"underline bright_blue link https://nvd.nist.gov/vuln/detail/{cve_id}",
        0,
        len(cve_id),
    )
    return link


def _cve_status_line(cve_id, message):
    """Render an inline status line with a single linked CVE ID span."""
    line = Text("  ")
    line.append_text(_cve_link(cve_id))
    line.append(f": {message}")
    return line


def _print_discovery_details(rows, pr_cve_ids=None):
    """Show selected PR context and all source failures, even on unchanged runs.

    Text objects keep titles, URLs, and error messages literal rather than
    interpreting untrusted source text as Rich markup. Repeated source failures
    are grouped so a shared outage does not print once per CVE.
    """
    warnings = {}
    for cve_id, snap in rows:
        prs = snap.get("metasploit_prs", []) if (
            pr_cve_ids is None or cve_id in pr_cve_ids
        ) else []
        for pr in prs:
            number = f" #{pr['number']}" if pr.get("number") else ""
            line = _cve_status_line(
                cve_id, f"Metasploit PR{number} ({_pr_status(pr)}) "
            )
            line.append(plain_text(pr["url"]), style="underline bright_blue")
            if pr.get("title"):
                line.append(f" — {' '.join(plain_text(pr['title']).split())}")
            rprint(line)
            for reference_url in dict.fromkeys(pr.get("reference_urls", [])):
                if reference_url != pr["url"]:
                    evidence = Text("    Evidence: ")
                    evidence.append(plain_text(reference_url), style="underline bright_blue")
                    rprint(evidence)
        for warning in snap.get("discovery_warnings", []):
            warnings.setdefault(warning, set()).add(cve_id)

    for warning, cve_ids in warnings.items():
        if len(cve_ids) == 1:
            line = _cve_status_line(next(iter(cve_ids)), "Discovery incomplete: ")
        else:
            line = Text(f"  Discovery incomplete for {len(cve_ids)} CVEs: ")
        line.append(plain_text(warning), style="gold1")
        rprint(line)


def _risk_table(title, rows):
    """Build a table of CVEs sorted by triage score (most urgent first)."""
    table = Table(title=title, show_lines=True, header_style="bold", title_justify="left")
    # Never truncate the CVE ID — it's the one field that must always be readable.
    table.add_column("CVE ID", no_wrap=True, min_width=13)
    table.add_column("Risk", justify="center")
    table.add_column("Score", justify="center")
    table.add_column("EPSS", justify="center")
    table.add_column("KEV", justify="center")
    table.add_column("PoCs", justify="center")
    table.add_column("Weaponized", justify="center")
    table.add_column("Fixed?", justify="center")

    for cve_id, snap in rows:
        color = LABEL_COLORS.get(snap["label"], "white")
        epss = f"{snap['epss']}%" if isinstance(snap["epss"], (int, float)) else "N/A"
        kev = "[red1]Yes[/red1]" if snap["kev"] == "Yes" else "No"
        weaponized = "[red1]Yes[/red1]" if snap["weaponized"] else "No"
        # Policy: only "Yes" with a credible fix record; otherwise assume not
        # fixed. A vendor that doesn't report the fix doesn't earn the benefit
        # of the doubt.
        if snap["has_fix"]:
            fix = "[spring_green2]Yes[/spring_green2]"
        else:
            fix = "[red1]No[/red1]"
        table.add_row(
            _cve_link(cve_id),
            f"[{color}]{snap['label']}[/{color}]",
            str(snap["score"]),
            epss,
            kev,
            str(snap["gh_pocs"]),
            weaponized,
            fix,
        )
    return table


def show_state(state_path):
    """
    Render a previously saved watch state file as a sorted risk table, without
    touching the network. Entry point for --show-state. Returns an exit code.
    """
    if not os.path.exists(state_path):
        rprint(f"[red3][-][/red3] State file not found: {state_path}")
        return 1
    state = _load_state(state_path)
    cves = state.get("cves", {})
    if not cves:
        rprint(f"[gold1][!][/gold1] No CVEs recorded in {state_path}")
        return 0

    rprint(
        f"[bright_blue][*][/bright_blue] Watched product: "
        f"[bright_yellow]{state.get('cpe', 'N/A')}[/bright_yellow]  "
        f"(last run: {state.get('last_run', 'N/A')})\n"
    )
    rows = sorted(cves.items(), key=lambda x: x[1]["score"], reverse=True)
    danger = [(c, s) for c, s in rows if s.get("danger_zone")]
    if danger:
        rprint(_risk_table("🔥 Danger zone — public exploit, NO vendor fix", danger))
        print()
    rprint(_risk_table("Tracked CVEs (from saved state)", rows))
    _print_discovery_details(rows)
    return 0


def _resolve_cpe(cpe):
    """
    Resolve a CPE to a list of CVE IDs. Returns (cve_ids, exit_code): on success
    exit_code is None; on failure cve_ids is None and exit_code is set.
    """
    cve_ids_raw = cpe_to_cveid(cpe)
    if cve_ids_raw == "Incorrect Format":
        rprint(
            "[red3][-][/red3] The CPE format is incorrect "
            "(e.g: cpe:2.3:a:zimbra:collaboration:10.0.0)"
        )
        return None, 1
    if cve_ids_raw == "N/A":
        # Zero results here is often good news for a patched version — don't
        # dress it up as an error. (NVD also returns nothing for a version it
        # simply doesn't have data for.)
        rprint(
            "[spring_green2][+][/spring_green2] No CVEs returned for this CPE — "
            "nothing known to affect this version (or it isn't in NVD's data)."
        )
        return None, 0
    return [c.strip() for c in cve_ids_raw.split("\n") if c.strip()], None


def _apply_cap(current_ids):
    """Cap CVEs processed per run at WATCH_MAX, logging (never silently) any skipped."""
    if len(current_ids) > WATCH_MAX:
        dropped = len(current_ids) - WATCH_MAX
        rprint(
            f"[gold1][!][/gold1] {len(current_ids)} CVEs affect this CPE; "
            f"processing the first {WATCH_MAX} and skipping {dropped}. "
            f"Use a more specific CPE (include a version) to narrow the set."
        )
        return current_ids[:WATCH_MAX]
    return current_ids


def _snapshot_all(cve_ids, headers, threads):
    """Download the shared databases once, then snapshot every CVE concurrently.

    Shows progress the whole way through so the tool never looks hung during the
    (potentially large) database downloads and the per-CVE lookups.
    """
    # One client per collection shares cached references and rate-limit state
    # across all workers.
    discovery_client = GithubDiscoveryClient(headers=headers[0] if headers else None)

    # Phase 1: the big shared downloads (KEV, EPSS, Metasploit/ExploitDB/Nuclei).
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        progress.add_task(
            "[bright_blue][*][/bright_blue] Downloading CVE / exploit databases…",
            total=None,
        )
        kevs = download_cisa_kev()
        epss_data = download_first_epss()
        exploits_db = download_exploits_db()

    # Phase 2: triage each CVE, with a live count so slow runs show progress.
    snapshots = {}
    with Progress(
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Triaging CVEs", total=len(cve_ids))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(
                    _snapshot, cve_id, headers, kevs, epss_data, exploits_db,
                    discovery_client=discovery_client,
                ): cve_id
                for cve_id in cve_ids
            }
            for future in as_completed(futures):
                cve_id, snap = future.result()
                if snap is not None:
                    snapshots[cve_id] = snap
                progress.advance(task)
    return snapshots


def run_list(cpe, headers, threads):
    """
    Print the full current CVE triage table for a CPE. Read-only: no state file
    is read or written. Entry point for --list (the `show` verb).
    """
    current_ids, err = _resolve_cpe(cpe)
    if current_ids is None:
        return err
    current_ids = _apply_cap(current_ids)

    rprint(
        f"[bright_blue][*][/bright_blue] Resolving {len(current_ids)} CVE(s) for "
        f"[bright_yellow]{cpe}[/bright_yellow] ..."
    )
    snapshots = _snapshot_all(current_ids, headers, threads)
    if not snapshots:
        rprint("[gold1][!][/gold1] No published CVEs to show for this CPE.")
        return 0

    rows = sorted(snapshots.items(), key=lambda x: x[1]["score"], reverse=True)
    danger = [(c, s) for c, s in rows if s["danger_zone"]]
    print()
    if danger:
        rprint(_risk_table("🔥 Danger zone — public exploit, NO vendor fix", danger))
        print()
    rprint(_risk_table(f"CVEs affecting {cpe}", rows))
    _print_discovery_details(rows)
    return 0


def _scan_table(title, spec, rows):
    """Risk table for the keyword scan, with an 'Affects <spec>?' column."""
    table = Table(title=title, show_lines=True, header_style="bold", title_justify="left")
    table.add_column("CVE ID", no_wrap=True, min_width=13)
    table.add_column(f"Affects {spec}?", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Score", justify="center")
    table.add_column("EPSS", justify="center")
    table.add_column("KEV", justify="center")
    table.add_column("PoCs", justify="center")
    table.add_column("Weaponized", justify="center")
    table.add_column("Fixed?", justify="center")

    affects_style = {
        "yes": "[red1]Yes[/red1]",
        "no": "[grey58]no[/grey58]",
        "unknown": "[gold1]?[/gold1]",
    }
    for cve_id, snap in rows:
        color = LABEL_COLORS.get(snap["label"], "white")
        epss = f"{snap['epss']}%" if isinstance(snap["epss"], (int, float)) else "N/A"
        kev = "[red1]Yes[/red1]" if snap["kev"] == "Yes" else "No"
        weaponized = "[red1]Yes[/red1]" if snap["weaponized"] else "No"
        fix = "[spring_green2]Yes[/spring_green2]" if snap["has_fix"] else "[red1]No[/red1]"
        table.add_row(
            _cve_link(cve_id),
            affects_style.get(snap["affects"], "?"),
            f"[{color}]{snap['label']}[/{color}]",
            str(snap["score"]),
            epss,
            kev,
            str(snap["gh_pocs"]),
            weaponized,
            fix,
        )
    return table


def run_zimbra_scan(spec, headers, threads):
    """
    Discover ALL Zimbra CVEs via NVD keyword search (Zimbra-independent), triage
    each, and sort by relevance to `spec` (a train like 10.1 or an exact version)
    then by risk. Nothing is dropped — CVEs NVD can't tie to the version are kept
    and marked '?'. Read-only. Entry point for --zimbra-scan (the `show` verb).
    """
    from CVE2PoC.core.zimbra import fetch_zimbra_cves, affects

    nvd_headers = headers[1] if len(headers) > 1 else None
    rprint(
        "[bright_blue][*][/bright_blue] Discovering all Zimbra CVEs "
        "(NVD keyword search 'zimbra') ..."
    )
    ranges_by_id = fetch_zimbra_cves(nvd_headers)
    if not ranges_by_id:
        rprint(
            "[red3][-][/red3] Could not fetch Zimbra CVEs from NVD "
            "(rate limit? add an NVD API key via --api-keys)."
        )
        return 1

    rprint(
        f"[bright_blue][*][/bright_blue] {len(ranges_by_id)} Zimbra CVE(s) — triaging, "
        f"sorted by relevance to [bright_yellow]{spec}[/bright_yellow] ..."
    )
    snapshots = _snapshot_all(list(ranges_by_id.keys()), headers, threads)

    rows = []
    for cve_id, snap in snapshots.items():
        snap["affects"] = affects(ranges_by_id.get(cve_id, []), spec)
        rows.append((cve_id, snap))
    rank = {"yes": 0, "unknown": 1, "no": 2}
    rows.sort(key=lambda x: (rank.get(x[1]["affects"], 1), -x[1]["score"]))

    print()
    danger = [
        (c, s) for c, s in rows if s["danger_zone"] and s["affects"] in ("yes", "unknown")
    ]
    if danger:
        rprint(
            _scan_table(
                f"🔥 Danger zone possibly affecting {spec} — public exploit, not fixed",
                spec,
                danger,
            )
        )
        print()
    rprint(_scan_table(f"All Zimbra CVEs (sorted by relevance to {spec})", spec, rows))
    rprint(
        "[grey58]Affects column: Yes = NVD says this version is in range · "
        "no = NVD's version data excludes it · ? = no version data, verify manually[/grey58]"
    )
    _print_discovery_details(rows)
    return 0


def run_watch(cpe, state_path, headers, threads):
    """
    Entry point for --watch. Returns a process exit code.
    """
    current_ids, err = _resolve_cpe(cpe)
    if current_ids is None:
        return err

    if state_path is None:
        state_path = _default_state_path(cpe)

    prev = _load_state(state_path)
    prev_cves = prev.get("cves", {})
    is_first_run = not prev_cves

    current_ids = _apply_cap(current_ids)

    rprint(
        f"[bright_blue][*][/bright_blue] Resolving {len(current_ids)} CVE(s) for "
        f"[bright_yellow]{cpe}[/bright_yellow] ..."
    )
    snapshots = _snapshot_all(current_ids, headers, threads)
    for cve_id, snap in snapshots.items():
        if cve_id in prev_cves:
            snapshots[cve_id] = _retain_pr_evidence(prev_cves[cve_id], snap)

    # New CVEs (unseen in the previous run)
    new_rows = [(c, s) for c, s in snapshots.items() if c not in prev_cves]
    new_rows.sort(key=lambda x: x[1]["score"], reverse=True)

    # Known CVEs with worsening risk signals or changes to public PR references.
    changed = []
    for cve_id, snap in snapshots.items():
        if cve_id in prev_cves:
            deltas = _detect_changes(prev_cves[cve_id], snap)
            if deltas:
                changed.append((cve_id, snap, deltas))
    changed.sort(key=lambda x: x[1]["score"], reverse=True)

    # ---- Report ----
    print()
    if is_first_run:
        rprint(
            f"[bright_blue][*][/bright_blue] First run — establishing a baseline of "
            f"{len(snapshots)} CVE(s). Future runs will report only changes.\n"
        )

    danger = [(c, s) for c, s in new_rows if s["danger_zone"]]
    if danger:
        rprint(_risk_table("🔥 Danger zone — public exploit, NO vendor fix", danger))
        print()

    if new_rows:
        heading = "Baseline (all currently affecting CVEs)" if is_first_run else "New CVEs since last run"
        rprint(_risk_table(heading, new_rows))
        print()
    elif not is_first_run:
        rprint("[spring_green2][+][/spring_green2] No new CVEs since last run.")

    if changed:
        rprint(_risk_table("Updates to tracked CVEs", [(c, s) for c, s, _ in changed]))
        for cve_id, _, deltas in changed:
            rprint(_cve_status_line(cve_id, ", ".join(deltas)))
        print()
    elif not is_first_run:
        rprint(
            "[spring_green2][+][/spring_green2] No new risk signals or "
            "Metasploit PR changes observed in previously tracked CVEs."
        )

    # When nothing changed there's no table; point the user at the full list.
    if not is_first_run and not new_rows and not changed:
        rprint(
            f"[bright_blue][*][/bright_blue] {len(snapshots)} CVE(s) tracked. "
            f"See them all: cve2poc --show-state {state_path}"
        )

    rows = sorted(snapshots.items(), key=lambda x: x[1]["score"], reverse=True)
    changed_ids = {c for c, _ in new_rows} | {c for c, _, _ in changed}
    _print_discovery_details(rows, pr_cve_ids=changed_ids)

    # ---- Persist state ----
    state = {
        "cpe": cpe,
        "last_run": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cves": snapshots,
    }
    _save_state(state_path, state)
    rprint(f"[bright_blue][*][/bright_blue] State saved to {state_path}")
    return 0
