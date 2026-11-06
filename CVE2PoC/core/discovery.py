"""Read public reference indexes and Metasploit PR metadata; never fetch PoC code.

``GithubDiscoveryClient.discover(cve_id)`` returns ``pocs``, ``metasploit_prs``,
``warnings``, ``pocs_complete`` and ``metasploit_prs_complete``. PR ``state`` is
open, closed, merged or unknown; ``draft`` is a bool (or None if unavailable).
A candidate PR is a reference, not evidence of a released/verified exploit.
Clients are safe to share between workers and cache results only for their life.
"""

from copy import deepcopy
import re
from threading import Lock
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
from markdown import markdown
import requests

from CVE2PoC.core.user_agent import get_user_agent

_MISSING = object()
_MSF = "rapid7/metasploit-framework"
_INDEX_REPOS = {
    "fkie-cad/nvd-json-data-feeds", "nomi-sec/poc-in-github",
    "arpsyndicate/cvemon", "arpsyndicate/cve-scores",
}


def _github_url(url):
    """Return repository and kind without losing a file/PR's original URL."""
    # urlsplit strips some control characters. Reject them before parsing so
    # the stored/displayed reference and the validated URL remain identical.
    if not isinstance(url, str) or any(ord(char) < 32 or ord(char) == 127 for char in url):
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            return None
        if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
            return None
        if parsed.hostname.lower() != "github.com":
            return "", "reference", None
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2 or any(not re.fullmatch(r"[\w.-]+", p, re.ASCII) for p in parts[:2]):
            return None
        repo = "/".join(parts[:2])
        kind, number = "reference", None
        if len(parts) == 2:
            kind = "repository"
        elif parts[2] == "blob" and len(parts) >= 5:
            kind = "file"
        elif parts[2] == "tree" and len(parts) >= 4:
            kind = "directory"
        elif parts[2] == "pull" and len(parts) >= 4 and parts[3].isdigit():
            kind, number = "pull_request", int(parts[3])
        return repo, kind, number
    except (TypeError, ValueError):
        return None


def _exact_cve(cve_id, item):
    text = "\n".join(str(item.get(key) or "") for key in ("title", "body"))
    return re.search(r"(?<![\w-])" + re.escape(cve_id) + r"(?![\w-])", text, re.I) is not None


def _trickest_links(text):
    soup = BeautifulSoup(markdown(text), "html.parser")
    for heading in soup.find_all(re.compile(r"^h[1-6]$")):
        if heading.get_text(" ", strip=True).casefold() != "github":
            continue
        for sibling in heading.next_siblings:
            if re.fullmatch(r"h[1-6]", sibling.name or ""):
                break
            if sibling.name not in ("ul", "ol"):
                continue
            for item in sibling.find_all("li"):
                links = [a["href"] for a in item.find_all("a", href=True)]
                if not links:
                    links = re.findall(r"https?://[^\s<>]+", item.get_text(" ", strip=True))
                yield from links


class GithubDiscoveryClient:
    def __init__(self, headers=None, *, timeout=(3.05, 10), max_pocs=50,
                 max_prs=20, request_get=None):
        self.headers = {"User-Agent": get_user_agent(), **(headers or {})}
        self.timeout = timeout
        self.max_pocs = max(1, min(int(max_pocs), 100))
        self.max_prs = max(1, min(int(max_prs), 100))
        self._get = request_get or requests.get
        self._lock, self._metadata_lock, self._pr_lock = Lock(), Lock(), Lock()
        self._api_lock = Lock()
        self._cache, self._cve_locks, self._metadata = {}, {}, {}
        self._pr_blocked = None

    def _request(self, url, label, warnings, *, json=True, params=None, absent=True):
        if urlsplit(url).hostname != "api.github.com":
            return self._fetch(url, label, warnings, json=json, params=params, absent=absent)
        # Share the send gate across search, PR details and repository metadata.
        # A worker queued before a rate limit must recheck before sending.
        with self._api_lock:
            with self._lock:
                blocked = self._pr_blocked
            if blocked:
                warnings.append(f"{label} skipped: {blocked}; results may be incomplete.")
                return None, False
            return self._fetch(url, label, warnings, json=json, params=params, absent=absent)

    def _fetch(self, url, label, warnings, *, json=True, params=None, absent=True):
        # Raw indexes need no credentials. Redirects are not followed, so tokens
        # cannot leave the known GitHub API origin through redirect responses.
        api = urlsplit(url).hostname == "api.github.com"
        headers = dict(self.headers) if api else {
            k: v for k, v in self.headers.items() if k.lower() in ("user-agent", "accept")
        }
        try:
            response = self._get(url, headers=headers, timeout=self.timeout,
                                 params=params, allow_redirects=False)
        except requests.RequestException as exc:
            warnings.append(f"{label}: request failed ({type(exc).__name__}); results may be incomplete.")
            return None, False
        status = response.status_code
        if status == 404 and absent:
            return _MISSING, True
        if status != 200:
            warnings.append(f"{label}: HTTP {status}; results may be incomplete.")
            if api and status in (403, 429):
                with self._lock:
                    self._pr_blocked = f"HTTP {status} from GitHub API"
            return None, False
        if not json:
            return response.text, True
        try:
            return response.json(), True
        except (ValueError, requests.exceptions.JSONDecodeError):
            warnings.append(f"{label}: invalid JSON; results may be incomplete.")
            return None, False

    def _repo_metadata(self, repo):
        # Serialize and cache metadata lookups, including failures, across CVEs.
        with self._metadata_lock:
            key = repo.casefold()
            if key not in self._metadata:
                warnings = []
                with self._lock:
                    blocked = self._pr_blocked
                if blocked:
                    data, ok = None, False
                    warnings.append(f"Repository metadata skipped: {blocked}; references retained.")
                else:
                    data, ok = self._request(f"https://api.github.com/repos/{repo}",
                                             f"Repository {repo}", warnings)
                if data is _MISSING:
                    data = {}
                elif ok and not isinstance(data, dict):
                    warnings.append(f"Repository {repo}: invalid metadata; reference retained.")
                    data = {}
                self._metadata[key] = (data or {}, warnings)
            return self._metadata[key]

    def _poc(self, raw, source, warnings):
        if not isinstance(raw, dict) or not isinstance(raw.get("html_url"), str):
            return None
        url = raw["html_url"].strip(" ")
        info = _github_url(url)
        if not info:
            return None
        repo, kind, _ = info
        if repo.casefold() in _INDEX_REPOS and kind == "repository":
            return None
        result = {"html_url": url, "full_name": repo, "kind": kind,
                  "description": raw.get("description") or "", "sources": [source],
                  "stargazers_count": 0, "forks": 0, "programming_language": "N/A"}
        meta = {}
        if repo and not (repo.casefold() == _MSF and kind == "pull_request"):
            meta, meta_warnings = self._repo_metadata(repo)
            warnings.extend(meta_warnings)
        result["description"] = str(result["description"] or meta.get("description") or "")
        result["programming_language"] = str(meta.get("language") or raw.get("programming_language") or "N/A")
        # Repository popularity is not popularity of an individual deep link.
        if kind == "repository":
            for key in ("stargazers_count", "forks"):
                value = meta.get(key, raw.get(key, 0))
                result[key] = value if isinstance(value, int) and value >= 0 else 0
        for key in ("created_at", "updated_at"):
            if raw.get(key) or (kind == "repository" and meta.get(key)):
                result[key] = raw.get(key) or meta[key]
        return result

    def _pull(self, item, number, sources, *, detail=False, reference_urls=None):
        state = item.get("state", "unknown")
        if state not in ("open", "closed"):
            state = "unknown"
        if detail and (item.get("merged") is True or item.get("merged_at")):
            state = "merged"
        draft = item.get("draft") if isinstance(item.get("draft"), bool) else None
        return {"url": f"https://github.com/{_MSF}/pull/{number}", "number": number,
                "title": str(item.get("title") or "Metasploit PR reference"),
                "state": state, "draft": draft, "sources": list(dict.fromkeys(sources)),
                "reference_urls": list(dict.fromkeys(reference_urls or [f"https://github.com/{_MSF}/pull/{number}"])),
                "status": "draft" if state == "open" and draft else state,
                "cve_match_verified": bool(item)}

    @staticmethod
    def _valid_pull(item, number):
        if not isinstance(item, dict) or item.get("number") != number:
            return False
        info = _github_url(item.get("html_url"))
        return bool(info and info[0].casefold() == _MSF
                    and info[1] == "pull_request" and info[2] == number
                    and item.get("state") in ("open", "closed")
                    and isinstance(item.get("draft"), bool)
                    and (item["state"] == "open" or isinstance(item.get("merged"), bool)))

    def _metasploit(self, cve_id, seeds, warnings):
        # Search is serialized so one rate-limit response stops the next worker.
        with self._pr_lock:
            with self._lock:
                blocked = self._pr_blocked
            candidates, complete = {}, True
            if blocked:
                warnings.append(f"Metasploit PR search skipped: {blocked}; retry in a later run.")
                data, complete = None, False
            else:
                data, complete = self._request(
                    "https://api.github.com/search/issues", "Metasploit PR search", warnings,
                    params={"q": f'"{cve_id}" repo:{_MSF} is:pr in:title,body',
                            "per_page": self.max_prs, "page": 1}, absent=False)
            if complete and (not isinstance(data, dict) or not isinstance(data.get("items"), list)
                             or not isinstance(data.get("total_count"), int)
                             or not isinstance(data.get("incomplete_results"), bool)):
                warnings.append("Metasploit PR search: invalid response schema; results may be incomplete.")
                complete = False
                data = None
            items = data.get("items", []) if isinstance(data, dict) else []
            if isinstance(data, dict) and (data.get("incomplete_results") or
                    data.get("total_count", len(items)) > len(items) or len(items) > self.max_prs):
                warnings.append("Metasploit PR search is partial or truncated; additional PRs may exist.")
                complete = False
            for item in items[:self.max_prs]:
                if not isinstance(item, dict):
                    warnings.append("Metasploit PR search: malformed result omitted; results may be incomplete.")
                    complete = False
                    continue
                info = _github_url(item.get("html_url"))
                if (not info or info[0].casefold() != _MSF or info[1] != "pull_request"
                        or item.get("number") != info[2] or not isinstance(item.get("pull_request"), dict)):
                    warnings.append("Metasploit PR search: malformed or mismatched result omitted; results may be incomplete.")
                    complete = False
                    continue
                if not _exact_cve(cve_id, item):
                    continue
                number = info[2]
                seed = seeds.pop(number, {})
                sources = ["github-pr-search"] + seed.get("sources", [])
                references = seed.get("reference_urls", []) + [item["html_url"]]
                candidates[number] = self._pull(item, number, sources, reference_urls=references)
                # A closed issue-search result alone cannot distinguish merged.
                if item.get("state") != "open" or not isinstance(item.get("draft"), bool):
                    with self._lock:
                        blocked = self._pr_blocked
                    details, ok = (None, False) if blocked else self._request(
                        f"https://api.github.com/repos/{_MSF}/pulls/{number}",
                        f"Metasploit PR #{number}", warnings, absent=False)
                    if ok and self._valid_pull(details, number) and _exact_cve(cve_id, details):
                        candidates[number] = self._pull(details, number, sources, detail=True,
                                                         reference_urls=references)
                    else:
                        if ok:
                            warnings.append(f"Metasploit PR #{number}: invalid or mismatched metadata; candidate retained with unknown state.")
                        candidates[number]["state"] = candidates[number]["status"] = "unknown"
                        complete = False
            remaining = self.max_prs - len(candidates)
            if len(seeds) > remaining:
                warnings.append("Metasploit PR references truncated; additional candidates may exist.")
                complete = False
            for number, seed in list(seeds.items())[:remaining]:
                sources, references = seed["sources"], seed["reference_urls"]
                with self._lock:
                    blocked = self._pr_blocked
                details, ok = (None, False) if blocked else self._request(
                    f"https://api.github.com/repos/{_MSF}/pulls/{number}",
                    f"Metasploit PR #{number}", warnings, absent=False)
                if ok and self._valid_pull(details, number):
                    if not _exact_cve(cve_id, details):
                        continue
                    candidates[number] = self._pull(details, number, sources, detail=True,
                                                     reference_urls=references)
                else:
                    if ok:
                        warnings.append(f"Metasploit PR #{number}: invalid metadata; reference retained with unknown state.")
                    candidates[number] = self._pull({}, number, sources, reference_urls=references)
                    complete = False
            return sorted(candidates.values(), key=lambda item: item["number"]), complete

    def discover(self, cve_id):
        cve_id = str(cve_id).strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            return {"pocs": [], "metasploit_prs": [], "warnings": ["Invalid CVE identifier."],
                    "pocs_complete": False, "metasploit_prs_complete": False}
        with self._lock:
            cve_lock = self._cve_locks.setdefault(cve_id, Lock())
        with cve_lock:
            with self._lock:
                if cve_id in self._cache:
                    return deepcopy(self._cache[cve_id])
            warnings, entries, pocs, seeds = [], [], {}, {}
            year = cve_id.split("-")[1]
            nomi, nomi_ok = self._request(
                f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/refs/heads/master/{year}/{cve_id}.json",
                "Nomi-sec index", warnings)
            trickest, trickest_ok = self._request(
                f"https://raw.githubusercontent.com/trickest/cve/refs/heads/main/{year}/{cve_id}.md",
                "Trickest index", warnings, json=False)
            if nomi is not _MISSING and nomi_ok:
                if isinstance(nomi, list):
                    entries.extend((entry, "nomi-sec") for entry in nomi[:self.max_pocs])
                    if len(nomi) > self.max_pocs:
                        warnings.append("Nomi-sec index truncated; additional references may exist.")
                        nomi_ok = False
                else:
                    warnings.append("Nomi-sec index: expected a JSON list; results may be incomplete.")
                    nomi_ok = False
            if trickest is not _MISSING and trickest_ok:
                links = list(_trickest_links(trickest))
                entries.extend(({"html_url": url}, "trickest") for url in links[:self.max_pocs])
                if len(links) > self.max_pocs:
                    warnings.append("Trickest index truncated; additional references may exist.")
                    trickest_ok = False
            for raw, source in entries:
                if not isinstance(raw, dict) or not isinstance(raw.get("html_url"), str):
                    warnings.append(f"{source}: malformed reference omitted; results may be incomplete.")
                    nomi_ok = False
                    continue
                poc = self._poc(raw, source, warnings)
                if poc is None:
                    continue
                info = _github_url(poc["html_url"])
                if poc["full_name"].casefold() == _MSF and poc["kind"] == "pull_request":
                    seed = seeds.setdefault(info[2], {"sources": [], "reference_urls": []})
                    seed["sources"].append(source)
                    seed["reference_urls"].append(poc["html_url"])
                    continue
                key = poc["html_url"].rstrip("/")
                if key in pocs:
                    pocs[key]["sources"] = list(dict.fromkeys(pocs[key]["sources"] + [source]))
                else:
                    pocs[key] = poc
            prs, prs_complete = self._metasploit(cve_id, seeds, warnings)
            result = {"pocs": list(pocs.values()), "metasploit_prs": prs,
                      "warnings": list(dict.fromkeys(warnings)),
                      "pocs_complete": nomi_ok and trickest_ok,
                      "metasploit_prs_complete": prs_complete}
            with self._lock:
                self._cache[cve_id] = deepcopy(result)
            return result
