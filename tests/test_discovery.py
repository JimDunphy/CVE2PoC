"""Offline regression tests for public reference discovery (no PoC execution)."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Event, Lock
import unittest

import requests

from CVE2PoC.core.discovery import GithubDiscoveryClient

CVE = "CVE-2026-93637"
OTHER_CVE = "CVE-2026-93638"
PR_URL = "https://github.com/rapid7/metasploit-framework/pull/22070"
PR_API = "https://api.github.com/repos/rapid7/metasploit-framework/pulls/22070"
SEARCH = "https://api.github.com/search/issues"
REPO = "https://github.com/example/research"
FILE = REPO + "/blob/main/poc.py"


class Response:
    def __init__(self, data=None, *, status=200, text="", bad_json=False):
        self.data, self.status_code, self.text = data, status, text
        self.bad_json = bad_json

    def json(self):
        if self.bad_json:
            raise ValueError("not JSON")
        return deepcopy(self.data)


def pull(**changes):
    value = {"number": 22070, "html_url": PR_URL,
             "title": f"Module references {CVE}", "body": "Public research reference",
             "state": "open", "draft": False,
             "pull_request": {"url": PR_API}}
    value.update(changes)
    return value


def search(items=(), **changes):
    value = {"items": list(items), "total_count": len(items), "incomplete_results": False}
    value.update(changes)
    return Response(value)


class Router:
    def __init__(self, *, nomi=None, trickest=None, results=None, metadata=None, details=None):
        self.nomi = nomi if nomi is not None else Response(status=404)
        self.trickest = trickest if trickest is not None else Response(status=404)
        self.results = results if results is not None else search()
        self.metadata = metadata if metadata is not None else Response({
            "description": "Research repository", "language": "Python",
            "stargazers_count": 1000, "forks": 30, "updated_at": "2026-10-01T00:00:00Z"})
        self.details = details if details is not None else Response(pull())
        self.calls, self.lock = [], Lock()

    def __call__(self, url, **kwargs):
        with self.lock:
            self.calls.append((url, deepcopy(kwargs)))
        if "/nomi-sec/PoC-in-GitHub/" in url:
            value = self.nomi
        elif "/trickest/cve/" in url:
            value = self.trickest
        elif url == SEARCH:
            value = self.results
        elif "/repos/rapid7/metasploit-framework/pulls/" in url:
            value = self.details
        elif url.startswith("https://api.github.com/repos/"):
            value = self.metadata
        else:
            raise AssertionError(f"Unexpected fetch: {url}")
        if isinstance(value, Exception):
            raise value
        return value

    def count(self, fragment):
        return sum(fragment in url for url, _ in self.calls)


class DiscoveryTests(unittest.TestCase):
    def run_discovery(self, router, **kwargs):
        return GithubDiscoveryClient(request_get=router, **kwargs).discover(CVE)

    def test_empty_nomi_does_not_mask_trickest_deep_link(self):
        router = Router(nomi=Response([]), trickest=Response(text=f"#### Github\n- {FILE}"))
        result = self.run_discovery(router)
        self.assertEqual(result["pocs"][0]["html_url"], FILE)
        self.assertEqual(result["pocs"][0]["full_name"], "example/research")
        self.assertEqual(result["pocs"][0]["kind"], "file")
        self.assertEqual(result["pocs"][0]["stargazers_count"], 0)
        self.assertTrue(result["pocs_complete"])
        self.assertIn("https://api.github.com/repos/example/research", [u for u, _ in router.calls])
        self.assertFalse(any("/repos/example/research/blob/" in u for u, _ in router.calls))

    def test_control_characters_are_rejected_before_url_parsing(self):
        for url in ("\n" + REPO, REPO + "\t", FILE + "\x1b[31m",
                    REPO + "\x7f", "https://git\nhub.com/example/research"):
            with self.subTest(url=url):
                router = Router(nomi=Response([{"html_url": url}]))
                result = self.run_discovery(router)
                self.assertEqual(result["pocs"], [])
                self.assertEqual(router.count("/repos/example/research"), 0)

    def test_both_feeds_merge_and_deduplicate_sources(self):
        router = Router(nomi=Response([{"html_url": REPO}, {"html_url": FILE}]),
                        trickest=Response(text=f"#### GitHub\n- [File]({FILE})\n- {REPO}/tree/main/tools"))
        result = self.run_discovery(router)
        self.assertEqual(len(result["pocs"]), 3)
        by_url = {p["html_url"]: p for p in result["pocs"]}
        self.assertEqual(by_url[FILE]["sources"], ["nomi-sec", "trickest"])
        self.assertEqual(by_url[REPO]["stargazers_count"], 1000)
        self.assertEqual(by_url[REPO + "/tree/main/tools"]["kind"], "directory")
        self.assertEqual(router.count("/repos/example/research"), 1)

    def test_empty_github_section_cannot_consume_next_sections_list(self):
        for content in (f"#### Github\nNo entry\n#### Other\n- {REPO}",
                        f"#### References\n- {REPO}"):
            with self.subTest(content=content):
                result = self.run_discovery(Router(trickest=Response(text=content)))
                self.assertEqual(result["pocs"], [])
                self.assertTrue(result["pocs_complete"])

    def test_metadata_failure_retains_evidence_and_feed_counts(self):
        router = Router(nomi=Response([{"html_url": REPO, "stargazers_count": 3}]),
                        metadata=Response(status=503))
        result = self.run_discovery(router)
        self.assertEqual(result["pocs"][0]["html_url"], REPO)
        self.assertEqual(result["pocs"][0]["stargazers_count"], 3)
        self.assertTrue(any("HTTP 503" in w for w in result["warnings"]))
        self.assertTrue(result["pocs_complete"])

    def test_bad_json_is_visible_and_other_feed_still_works(self):
        router = Router(nomi=Response(bad_json=True),
                        trickest=Response(text=f"#### Github\n- {FILE}"))
        result = self.run_discovery(router)
        self.assertEqual(result["pocs"][0]["html_url"], FILE)
        self.assertFalse(result["pocs_complete"])
        self.assertTrue(any("Nomi-sec" in w and "invalid JSON" in w for w in result["warnings"]))

    def test_absent_feeds_are_distinct_from_http_and_timeout_errors(self):
        result = self.run_discovery(Router())
        self.assertEqual(result["warnings"], [])
        self.assertTrue(result["pocs_complete"])
        for error in (Response(status=403), Response(status=429), Response(status=500), requests.Timeout()):
            with self.subTest(error=error):
                result = self.run_discovery(Router(nomi=error))
                self.assertFalse(result["pocs_complete"])
                self.assertTrue(any("Nomi-sec" in w for w in result["warnings"]))

    def test_credentials_go_only_to_api_and_no_redirects_are_followed(self):
        router = Router()
        self.run_discovery(router, headers={"Authorization": "Bearer test-secret", "Cookie": "test=1"})
        for url, kwargs in router.calls:
            self.assertEqual(kwargs["timeout"], (3.05, 10))
            self.assertFalse(kwargs["allow_redirects"])
            if url.startswith("https://raw.githubusercontent.com/"):
                self.assertNotIn("Authorization", kwargs["headers"])
                self.assertNotIn("Cookie", kwargs["headers"])
            else:
                self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-secret")

    def test_open_pr_fixture_appears_as_candidate_without_inflating_pocs(self):
        router = Router(results=search([pull()]))
        result = self.run_discovery(router)
        self.assertEqual(result["pocs"], [])
        self.assertTrue(result["metasploit_prs_complete"])
        self.assertEqual(result["metasploit_prs"][0]["url"], PR_URL)
        self.assertEqual(result["metasploit_prs"][0]["state"], "open")
        self.assertEqual(result["metasploit_prs"][0]["draft"], False)
        query = next(k["params"]["q"] for u, k in router.calls if u == SEARCH)
        self.assertIn(f'"{CVE}"', query)
        self.assertIn("repo:rapid7/metasploit-framework is:pr in:title,body", query)

    def test_search_verifies_exact_cve_repo_and_pr_identity(self):
        values = [pull(title="CVE-2026-936370"),
                  pull(html_url="https://github.com/attacker/other/pull/22070"),
                  pull(html_url="https://github.com/rapid7/metasploit-framework.evil/pull/22070"),
                  pull(number=999), pull(pull_request=None),
                  pull(title="Unrelated", body=f"Reference: {CVE.lower()}")]
        result = self.run_discovery(Router(results=search(values)))
        self.assertEqual(len(result["metasploit_prs"]), 1)
        self.assertEqual(result["metasploit_prs"][0]["title"], "Unrelated")

    def test_draft_closed_and_merged_states_remain_distinct(self):
        result = self.run_discovery(Router(results=search([pull(draft=True)])))
        self.assertEqual(result["metasploit_prs"][0]["status"], "draft")
        for merged, expected in ((False, "closed"), (True, "merged")):
            with self.subTest(merged=merged):
                router = Router(results=search([pull(state="closed")]),
                                details=Response(pull(state="closed", merged=merged)))
                result = self.run_discovery(router)
                self.assertEqual(result["metasploit_prs"][0]["state"], expected)
                self.assertTrue(result["metasploit_prs_complete"])

    def test_detail_failure_keeps_candidate_with_unknown_status(self):
        router = Router(results=search([pull(state="closed")]), details=Response(status=500))
        result = self.run_discovery(router)
        self.assertEqual(result["metasploit_prs"][0]["state"], "unknown")
        self.assertFalse(result["metasploit_prs_complete"])
        self.assertTrue(any("PR #22070" in w for w in result["warnings"]))

    def test_malformed_details_do_not_mislabel_closed_as_unmerged(self):
        for details in (pull(state="closed"), [], pull(html_url="https://github.com/other/repo/pull/22070")):
            with self.subTest(details=details):
                router = Router(results=search([pull(state="closed")]), details=Response(details))
                result = self.run_discovery(router)
                self.assertEqual(result["metasploit_prs"][0]["state"], "unknown")
                self.assertFalse(result["metasploit_prs_complete"])
                self.assertTrue(any("metadata" in w for w in result["warnings"]))

    def test_feed_pr_moves_to_candidates_and_deduplicates_search(self):
        router = Router(nomi=Response([{"html_url": PR_URL}]),
                        trickest=Response(text=f"#### Github\n- {PR_URL}"),
                        results=search([pull()]))
        result = self.run_discovery(router)
        self.assertEqual(result["pocs"], [])
        self.assertEqual(len(result["metasploit_prs"]), 1)
        self.assertEqual(set(result["metasploit_prs"][0]["sources"]),
                         {"github-pr-search", "nomi-sec", "trickest"})

    def test_deep_pr_evidence_url_survives_candidate_deduplication(self):
        deep = PR_URL + "/files/abcdef1234?diff=split#diff-123"
        for results, details in ((search([pull()]), Response(pull())),
                                 (search(), Response(pull())),
                                 (Response(status=429), Response(status=404))):
            with self.subTest(results=results):
                router = Router(trickest=Response(text=f"#### Github\n- [Module change]({deep})"),
                                results=results, details=details)
                result = self.run_discovery(router)
                candidate = result["metasploit_prs"][0]
                self.assertEqual(candidate["url"], PR_URL)
                self.assertIn(deep, candidate["reference_urls"])
                self.assertEqual(result["pocs"], [])

    def test_feed_pr_can_be_found_when_search_does_not_return_it(self):
        router = Router(trickest=Response(text=f"#### Github\n- {PR_URL}"),
                        details=Response(pull()))
        result = self.run_discovery(router)
        self.assertEqual(result["metasploit_prs"][0]["url"], PR_URL)
        self.assertTrue(result["metasploit_prs_complete"])
        self.assertEqual(result["pocs"], [])

    def test_feed_pr_detail_failure_keeps_unverified_reference(self):
        router = Router(trickest=Response(text=f"#### Github\n- {PR_URL}"), details=Response(status=404))
        result = self.run_discovery(router)
        self.assertEqual(result["metasploit_prs"][0]["state"], "unknown")
        self.assertIsNone(result["metasploit_prs"][0]["draft"])
        self.assertFalse(result["metasploit_prs_complete"])

    def test_rate_limit_breaker_prevents_subsequent_search_requests(self):
        for status in (403, 429):
            with self.subTest(status=status):
                router = Router(results=Response(status=status))
                client = GithubDiscoveryClient(request_get=router)
                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(client.discover, (CVE, OTHER_CVE)))
                self.assertEqual(router.count(SEARCH), 1)
                self.assertTrue(all(not r["metasploit_prs_complete"] for r in results))
                self.assertTrue(any("skipped" in w for r in results for w in r["warnings"]))

    def test_threaded_cache_is_single_fetch_and_returned_results_are_independent(self):
        router = Router(results=search([pull()]))
        client = GithubDiscoveryClient(request_get=router)
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(client.discover, [CVE] * 8))
        self.assertEqual(router.count(SEARCH), 1)
        self.assertEqual(router.count("/nomi-sec/"), 1)
        results[0]["metasploit_prs"][0]["state"] = "tampered"
        self.assertEqual(client.discover(CVE)["metasploit_prs"][0]["state"], "open")

    def test_partial_or_truncated_search_is_explicit(self):
        for extra in ({"incomplete_results": True}, {"total_count": 20}):
            with self.subTest(extra=extra):
                result = self.run_discovery(Router(results=search([pull()], **extra)))
                self.assertFalse(result["metasploit_prs_complete"])
                self.assertTrue(any("partial or truncated" in w for w in result["warnings"]))
                self.assertEqual(len(result["metasploit_prs"]), 1)

    def test_invalid_search_schema_does_not_look_like_a_complete_empty_result(self):
        for data in ([], {}, {"items": [], "total_count": None, "incomplete_results": False}):
            with self.subTest(data=data):
                result = self.run_discovery(Router(results=Response(data)))
                self.assertFalse(result["metasploit_prs_complete"])
                self.assertTrue(result["warnings"])

    def test_malformed_search_items_mark_results_incomplete(self):
        for item in (None, {}, pull(pull_request=None)):
            with self.subTest(item=item):
                result = self.run_discovery(Router(results=search([item, pull()])))
                self.assertFalse(result["metasploit_prs_complete"])
                self.assertTrue(any("malformed" in w for w in result["warnings"]))
                self.assertEqual(len(result["metasploit_prs"]), 1)

    def test_rate_limit_stops_metadata_worker_that_already_passed_precheck(self):
        metadata_ready, release_metadata = Event(), Event()
        metadata_url = "https://api.github.com/repos/example/research"
        router = Router(results=Response(status=429))

        def routed(url, **kwargs):
            if "/nomi-sec/" in url and url.endswith(f"/{CVE}.json"):
                return Response([{"html_url": FILE}])
            return router(url, **kwargs)

        client = GithubDiscoveryClient(request_get=routed)
        original_request = client._request

        def delayed_request(url, *args, **kwargs):
            if url == metadata_url:
                metadata_ready.set()
                if not release_metadata.wait(5):
                    raise AssertionError("Timed out waiting for rate-limit response")
            return original_request(url, *args, **kwargs)

        client._request = delayed_request
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(client.discover, CVE)
            try:
                self.assertTrue(metadata_ready.wait(5))
                blocked = client.discover(OTHER_CVE)
                self.assertFalse(blocked["metasploit_prs_complete"])
            finally:
                release_metadata.set()
            result = pending.result(timeout=5)
        self.assertEqual(router.count(metadata_url), 0)
        self.assertEqual(result["pocs"][0]["html_url"], FILE)
        self.assertTrue(any("skipped" in w for w in result["warnings"]))

    def test_external_references_are_not_fetched_and_aggregate_roots_are_excluded(self):
        external = "https://research.example/advisory"
        router = Router(nomi=Response([{"html_url": external},
                        {"html_url": "https://github.com/nomi-sec/PoC-in-GitHub"},
                        {"html_url": "https://secret@github.com/example/research"}]))
        result = self.run_discovery(router)
        self.assertEqual([p["html_url"] for p in result["pocs"]], [external])
        self.assertEqual(result["pocs"][0]["kind"], "reference")
        self.assertEqual(result["pocs"][0]["full_name"], "")
        self.assertFalse(any(u == external for u, _ in router.calls))

    def test_feed_truncation_and_malformed_entries_are_visible(self):
        result = self.run_discovery(Router(nomi=Response([{"html_url": REPO}, {"html_url": FILE}])), max_pocs=1)
        self.assertFalse(result["pocs_complete"])
        self.assertEqual(len(result["pocs"]), 1)
        result = self.run_discovery(Router(nomi=Response([None, {"html_url": FILE}])))
        self.assertEqual(result["pocs"][0]["html_url"], FILE)
        self.assertFalse(result["pocs_complete"])
        self.assertTrue(any("malformed reference" in w for w in result["warnings"]))

    def test_invalid_cve_causes_no_network_requests(self):
        router = Router()
        result = GithubDiscoveryClient(request_get=router).discover("../bad")
        self.assertEqual(router.calls, [])
        self.assertFalse(result["pocs_complete"])
        self.assertFalse(result["metasploit_prs_complete"])


if __name__ == "__main__":
    unittest.main()
