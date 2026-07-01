"""
Zimbra version → CPE resolution.

This is the one Zimbra-specific module (the tool core stays generic). It turns a
friendly version spec into the NVD CPE to query:

  * a train shortcut ('10.1', '10.0', '9.0', '8.8') resolves to that line's
    latest GA patch, matching how Zimbra admins think ("I'm on 10.1");
  * an exact version ('10.1.16', '9.0.0.p46', '8.8.15.p47') is used as-is, for
    when you want a specific patch level.

CPE update-field convention (verified against NVD):
  * 10.x plain patches use update '-'    (10.1.18  -> ...:10.1.18:-)
  * 8.8.15 / 9.0.0 use a 'pNN' update    (9.0.0 P46 -> ...:9.0.0:p46)
"""

import re

import requests

from CVE2PoC.core.user_agent import get_user_agent

# Fallback latest-GA patch per train, from https://wiki.zimbra.com/wiki/Zimbra_Releases
# (captured 2026-07-01). Used only if the live wiki lookup fails; otherwise the
# current values are pulled fresh (see _fetch_latest). Exact versions never need
# this table.
LATEST_FALLBACK = {
    "10.1": "10.1.18",
    "10.0": "10.0.18",
    "9.0": "9.0.0.p46",
    "8.8": "8.8.15.p47",
}

# Raw wikitext of the releases page; latest patch per train is a simple regex
# (equivalent to `curl … | grep -oE … | sort -V | tail -1`).
_WIKI_URL = "https://wiki.zimbra.com/index.php?title=Zimbra_Releases&action=raw"
_TRAIN_PATTERNS = {
    "10.1": (r"10\.1\.(\d+)", "10.1.{n}"),
    "10.0": (r"10\.0\.(\d+)", "10.0.{n}"),
    "9.0": (r"9\.0\.0/P(\d+)", "9.0.0.p{n}"),
    "8.8": (r"8\.8\.15/P(\d+)", "8.8.15.p{n}"),
}

_CPE_PREFIX = "cpe:2.3:a:zimbra:collaboration"
# base version (2 or 3 dotted numbers) + optional trailing patch token 'pNN'
_VERSION_RE = re.compile(r"^(\d+(?:\.\d+){1,2})(?:[.\-]?p(\d+))?$")


def version_to_cpe(version):
    """
    Build the NVD CPE for an exact Zimbra version string. Accepts patch
    spellings '.p46', 'p46', ' P46', '.P46'. Raises ValueError if unrecognized.
    """
    normalized = version.strip().lower().replace(" ", "")
    match = _VERSION_RE.match(normalized)
    if not match:
        raise ValueError(
            f"Unrecognized Zimbra version '{version}'. "
            f"Use a train (10.1, 10.0, 9.0, 8.8) or an exact version "
            f"(e.g. 10.1.16, 9.0.0.p46, 8.8.15.p47)."
        )
    base, patch = match.group(1), match.group(2)
    update = f"p{patch}" if patch else "-"
    return f"{_CPE_PREFIX}:{base}:{update}"


_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_zimbra_cves(nvd_headers=None):
    """
    Discover every CVE that mentions Zimbra via NVD's keyword search — the
    Zimbra-independent view (these are assigned by MITRE / third parties, not by
    Zimbra). Returns {cve_id: [range dicts]} where each range dict carries the
    zimbra version bounds NVD recorded (used to judge relevance to a version).
    Returns {} on failure.
    """
    headers = nvd_headers or {"User-Agent": get_user_agent()}
    results = {}
    start = 0
    while True:
        try:
            resp = requests.get(
                _NVD_API,
                params={
                    "keywordSearch": "zimbra",
                    "resultsPerPage": 2000,
                    "startIndex": start,
                },
                headers=headers,
                timeout=30,
            )
        except requests.RequestException:
            break
        if resp.status_code != 200:
            break
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        for item in vulns:
            cve = item["cve"]
            ranges = []
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if ":zimbra:" not in criteria:
                            continue
                        parts = criteria.split(":")
                        ranges.append(
                            {
                                "version": parts[5] if len(parts) > 5 else "*",
                                "startIncluding": match.get("versionStartIncluding"),
                                "startExcluding": match.get("versionStartExcluding"),
                                "endIncluding": match.get("versionEndIncluding"),
                                "endExcluding": match.get("versionEndExcluding"),
                            }
                        )
            results[cve["id"]] = ranges
        total = data.get("totalResults", 0)
        start += data.get("resultsPerPage", len(vulns))
        if not vulns or start >= total:
            break
    return results


def _vt(version):
    """Parse a version string to a comparable int tuple; None if unusable."""
    if not version or version in ("*", "-"):
        return None
    nums = re.findall(r"\d+", version)
    return tuple(int(n) for n in nums[:4]) if nums else None


def affects(ranges, spec):
    """
    Judge whether a CVE (given its zimbra version ranges) is relevant to a spec:
      'yes'     — a version in the spec's line falls within a recorded range
      'no'      — the CVE has zimbra version data, none of which covers the spec
      'unknown' — the CVE mentions Zimbra but carries no usable version data
    A train spec ('10.1') matches any 10.1.x; an exact spec matches precisely.
    """
    spec_t = _vt(spec)
    if not spec_t:
        return "unknown"
    is_train = len(spec_t) == 2
    saw_version = False

    for r in ranges:
        exact = _vt(r.get("version"))
        lo = _vt(r.get("startIncluding")) or _vt(r.get("startExcluding"))
        hi = _vt(r.get("endIncluding")) or _vt(r.get("endExcluding"))
        hi_incl = r.get("endIncluding") is not None
        if exact or lo or hi:
            saw_version = True

        if exact:
            if is_train and exact[:2] == spec_t:
                return "yes"
            if not is_train and exact[: len(spec_t)] == spec_t:
                return "yes"

        if lo or hi:
            if is_train:
                band_lo = spec_t + (0,)
                band_hi = spec_t + (10**6,)
                lo_ok = hi is None or (band_lo <= hi if hi_incl else band_lo < hi)
                hi_ok = lo is None or band_hi >= lo
            else:
                lo_ok = hi is None or (spec_t <= hi if hi_incl else spec_t < hi)
                hi_ok = lo is None or spec_t >= lo
            if lo_ok and hi_ok:
                return "yes"

    return "no" if saw_version else "unknown"


def _fetch_latest(train):
    """
    Best-effort lookup of a train's latest patch from the Zimbra wiki. Returns
    the version string, or None on any failure so the caller can fall back.
    """
    pattern, fmt = _TRAIN_PATTERNS[train]
    try:
        resp = requests.get(
            _WIKI_URL, headers={"User-Agent": get_user_agent()}, timeout=15
        )
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    numbers = [int(n) for n in re.findall(pattern, resp.text)]
    return fmt.format(n=max(numbers)) if numbers else None


def resolve(spec):
    """
    Resolve a Zimbra version spec to (resolved_version, cpe):
      * a train shortcut ('10.1', …) -> that train's latest patch, looked up live
        from the Zimbra wiki (falling back to LATEST_FALLBACK if the wiki is
        unreachable);
      * an exact version -> itself (no network).
    Raises ValueError on anything unrecognized.
    """
    spec = spec.strip()
    if spec in _TRAIN_PATTERNS:
        version = _fetch_latest(spec) or LATEST_FALLBACK[spec]
    else:
        version = spec
    return version, version_to_cpe(version)
