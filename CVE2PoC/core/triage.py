"""
Defensive triage scoring for CVE2PoC.

CVE2PoC was built to answer the attacker's question ("give me a PoC for this
CVE"). This module answers the defender's question instead: *how urgent is this
for me right now, and is anyone going to fix it?*

It folds the signals the tool already gathers — CISA KEV, EPSS, public PoC
maturity, weaponized modules (Metasploit/Nuclei/Exploit-DB) and CVSS — into a
single 0-100 urgency score, and crucially flags the worst quadrant for someone
running slow-to-patch software (e.g. Zimbra): a *public exploit exists but no
vendor fix is referenced*.
"""

from rich.panel import Panel


LABEL_COLORS = {
    "CRITICAL": "red1",
    "HIGH": "dark_orange",
    "MEDIUM": "gold1",
    "LOW": "spring_green2",
}


def has_vendor_fix(cve_record):
    """
    Return True only if there is a *credible* fix record: a patched/unaffected
    version, a reference tagged as a patch, or a vendor-provided solution
    (captured by extract_fix_info() in core/cve.py).

    Policy: the burden of proof is on "fixed". If the record carries no such
    evidence — including when a vendor simply never reports the fix — we treat
    the CVE as NOT fixed (assume vulnerable). Absence of a fix record is never
    interpreted as "safe".
    """
    return bool(
        cve_record.get("fixed_versions")
        or cve_record.get("patch_references")
        or cve_record.get("has_solution")
    )


def is_weaponized(other_sources):
    """
    True if a turnkey exploit/module exists (Metasploit, Exploit-DB or Nuclei),
    as returned by search_exploits_from_other_sources().
    """
    if not other_sources:
        return False
    return any(k in other_sources for k in ("metasploit", "exploitdb", "nuclei"))


def _epss_value(cve_record):
    """EPSS is stored as 'epss_score' (single lookup) or 'epss' (report path)."""
    epss = cve_record.get("epss_score")
    if epss is None:
        epss = cve_record.get("epss", "N/A")
    return epss


def compute_triage(cve_record, gh_poc_count=0, gh_max_stars=0, other_sources=None):
    """
    Compute a defensive urgency assessment for a CVE.

    :param cve_record: CVE record dict (must carry 'kev'; may carry EPSS, base
                       score, severity and the fix signals from extract_fix_info)
    :param gh_poc_count: number of public GitHub PoC repositories found
    :param gh_max_stars: highest star count among those repositories (maturity)
    :param other_sources: dict from search_exploits_from_other_sources()
    :returns: dict with score, label, weaponized, exploit_available, has_fix,
              danger_zone and a human-readable list of reasons.
    """
    other_sources = other_sources or {}
    reasons = []
    score = 0

    # In-the-wild exploitation (CISA KEV) — the strongest single signal.
    if cve_record.get("kev") == "Yes":
        score += 40
        reasons.append("Listed in CISA KEV (known exploited in the wild)")

    # EPSS: probability of exploitation in the next 30 days (stored as a percent).
    epss = _epss_value(cve_record)
    if isinstance(epss, (int, float)):
        if epss >= 50:
            score += 20
            reasons.append(f"High EPSS ({epss}% chance of exploitation)")
        elif epss >= 10:
            score += 12
            reasons.append(f"Elevated EPSS ({epss}%)")
        elif epss >= 1:
            score += 5

    # Weaponization: fully packaged, point-and-shoot tooling.
    if "metasploit" in other_sources:
        score += 15
        reasons.append("Metasploit module available")
    if "nuclei" in other_sources:
        score += 8
        reasons.append("Nuclei template available (also usable to self-scan your hosts)")
    if "exploitdb" in other_sources:
        score += 7
        reasons.append("Exploit-DB entry available")

    # Public PoC maturity on GitHub.
    if gh_poc_count:
        if gh_max_stars >= 50 or gh_poc_count >= 5:
            score += 12
            reasons.append(
                f"Mature public PoC(s) on GitHub ({gh_poc_count} repo(s), up to {gh_max_stars}★)"
            )
        else:
            score += 6
            reasons.append(f"Public PoC(s) on GitHub ({gh_poc_count} repo(s))")

    # CVSS base severity (weakest signal; PoCs/KEV matter more operationally).
    base = cve_record.get("base_score")
    if isinstance(base, (int, float)):
        if base >= 9:
            score += 10
        elif base >= 7:
            score += 6
        elif base >= 4:
            score += 2

    score = min(score, 100)

    weaponized = is_weaponized(other_sources)
    exploit_available = weaponized or bool(gh_poc_count)
    fix = has_vendor_fix(cve_record)

    # A *credible* public exploit — not just a single low-star stub. This gates
    # the danger-zone flag so we don't scream CRITICAL over a throwaway PoC.
    # (Fix data is often missing rather than confirmed-absent, so we require the
    # exploit side of the equation to be convincing before raising the alarm.)
    credible_exploit = (
        weaponized
        or cve_record.get("kev") == "Yes"
        or gh_max_stars >= 10
        or gh_poc_count >= 3
    )
    danger_zone = credible_exploit and not fix

    if danger_zone:
        reasons.insert(
            0, "⚠ Credible public exploit exists and it is NOT reported fixed"
        )

    if score >= 70:
        label = "CRITICAL"
    elif score >= 45:
        label = "HIGH"
    elif score >= 20:
        label = "MEDIUM"
    else:
        label = "LOW"

    # A credible exploit with no available fix is operationally serious even if
    # the composite score is moderate — escalate, but never fabricate CRITICAL.
    if danger_zone and label in ("LOW", "MEDIUM"):
        label = "HIGH"

    return {
        "score": score,
        "label": label,
        "weaponized": weaponized,
        "exploit_available": exploit_available,
        "has_fix": fix,
        "danger_zone": danger_zone,
        "reasons": reasons,
    }


def display_triage(cve_id, triage):
    """
    Render a triage result as a rich Panel for the single-CVE lookup view.
    """
    label = triage["label"]
    color = LABEL_COLORS.get(label, "white")

    if triage["has_fix"]:
        fix_txt = "[spring_green2]yes[/spring_green2]"
    else:
        fix_txt = "[red1]not reported fixed — assume vulnerable[/red1]"
    weap_txt = "[red1]Yes[/red1]" if triage["weaponized"] else "No"
    exploit_txt = (
        "[red1]Yes[/red1]" if triage["exploit_available"] else "not found"
    )

    lines = [
        f"Risk: [{color}]{label}[/{color}]  (score {triage['score']}/100)",
        f"Public exploit: {exploit_txt}    Weaponized module: {weap_txt}    Fixed: {fix_txt}",
    ]
    if triage["reasons"]:
        lines.append("")
        lines.extend(f"  • {reason}" for reason in triage["reasons"])

    border = "red1" if triage["danger_zone"] else color
    return Panel(
        "\n".join(lines),
        title=f"Defensive Triage — {cve_id}",
        title_align="left",
        border_style=border,
    )
