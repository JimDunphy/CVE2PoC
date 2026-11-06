"""Watch discovery integration, with all network-backed entry points mocked."""

from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, sentinel

from rich.console import Console

from CVE2PoC.core import watch


CVE = "CVE-2026-93637"
OTHER_CVE = "CVE-2026-12345"
CPE = "cpe:2.3:a:zimbra:collaboration:10.1.16"
HEADERS = ({"Authorization": "Bearer test-token"}, {})


def pr(number=22070, state="open", draft=False):
    return {
        "url": f"https://github.com/rapid7/metasploit-framework/pull/{number}",
        "number": number,
        "title": "Zimbra GraphQL reference",
        "state": state,
        "draft": draft,
    }


def snapshot(prs=None, warnings=None, complete=True):
    return {
        "kev": "No",
        "epss": 0.1,
        "base_score": 7.5,
        "severity": "HIGH",
        "gh_pocs": 0,
        "weaponized": False,
        "has_fix": False,
        "score": 6,
        "label": "LOW",
        "danger_zone": False,
        "product": "Zimbra",
        "metasploit_prs": deepcopy(prs or []),
        "metasploit_prs_complete": complete,
        "discovery_warnings": list(warnings or []),
    }


def result(pocs=None, prs=None, warnings=None, complete=True):
    pocs = pocs or []
    return {
        "cve_record": {
            "state": "PUBLISHED", "kev": "No", "epss": 0.1,
            "base_score": 7.5, "severity": "HIGH", "affected_product": "Zimbra",
        },
        "github_pocs": (pocs, "combined.json"),
        "pocs_from_other_sources": {},
        "github_discovery": {
            "pocs": pocs,
            "metasploit_prs": prs or [],
            "warnings": warnings or [],
            "metasploit_prs_complete": complete,
        },
    }


def rendered(function, *args):
    output = io.StringIO()
    console = Console(
        file=output, width=260, force_terminal=False, color_system=None,
        highlight=False,
    )
    with patch.object(watch, "rprint", console.print), redirect_stdout(output):
        status = function(*args)
    return status, output.getvalue()


class SnapshotDiscoveryTests(unittest.TestCase):
    def test_pr_evidence_is_persisted_without_changing_risk(self):
        data = result(prs=[pr()], warnings=["Index unavailable"], complete=True)
        with patch.object(
            watch, "get_cve_record_and_exploits", return_value=(data, None)
        ) as lookup:
            cve_id, snap = watch._snapshot(
                CVE, HEADERS, [], {}, (), discovery_client=sentinel.client
            )

        lookup.assert_called_once_with(
            CVE, HEADERS, [], {}, (), discovery_client=sentinel.client
        )
        self.assertEqual(cve_id, CVE)
        self.assertEqual(snap, snapshot([pr()], ["Index unavailable"]))
        self.assertEqual(snap["gh_pocs"], 0)
        self.assertFalse(snap["weaponized"])
        self.assertFalse(snap["danger_zone"])

    def test_indexed_pr_reference_does_not_count_as_a_poc(self):
        data = result(
            pocs=[
                {"kind": "repository", "stargazers_count": 3},
                {"kind": "pull_request", "stargazers_count": 100000},
            ],
            prs=[pr()],
        )
        with patch.object(
            watch, "get_cve_record_and_exploits", return_value=(data, None)
        ):
            _, snap = watch._snapshot(CVE, HEADERS, [], {}, ())
        self.assertEqual(snap["gh_pocs"], 1)
        self.assertEqual(snap["score"], 12)
        self.assertFalse(snap["weaponized"])
        self.assertFalse(snap["danger_zone"])

    def test_legacy_lookup_result_still_builds_a_snapshot(self):
        data = result(pocs=[{"html_url": "https://github.com/example/poc"}])
        data.pop("github_discovery")
        with patch.object(
            watch, "get_cve_record_and_exploits", return_value=(data, None)
        ):
            _, snap = watch._snapshot(CVE, HEADERS, [], {}, ())
        self.assertEqual(snap["gh_pocs"], 1)
        self.assertEqual(snap["metasploit_prs"], [])
        self.assertEqual(snap["discovery_warnings"], [])

    def test_collection_shares_one_client_across_workers(self):
        def collect(cve_id, *args, discovery_client=None):
            return cve_id, snapshot()

        with ExitStack() as stack:
            client = stack.enter_context(patch.object(
                watch, "GithubDiscoveryClient", return_value=sentinel.client
            ))
            collect_mock = stack.enter_context(patch.object(
                watch, "_snapshot", side_effect=collect
            ))
            for name in ("download_cisa_kev", "download_first_epss", "download_exploits_db"):
                stack.enter_context(patch.object(watch, name, return_value={}))
            stack.enter_context(patch.object(watch, "Progress"))
            snaps = watch._snapshot_all([CVE, OTHER_CVE], HEADERS, threads=2)

        client.assert_called_once_with(headers=HEADERS[0])
        self.assertEqual(set(snaps), {CVE, OTHER_CVE})
        self.assertEqual(collect_mock.call_count, 2)
        for call in collect_mock.call_args_list:
            self.assertIs(call.kwargs["discovery_client"], sentinel.client)


class WatchChangeTests(unittest.TestCase):
    def test_legacy_snapshot_has_no_spurious_changes(self):
        old = snapshot()
        for key in ("metasploit_prs", "metasploit_prs_complete", "discovery_warnings"):
            old.pop(key)
        self.assertEqual(watch._detect_changes(old, snapshot()), [])
        changes = watch._detect_changes(old, snapshot([pr()]))
        self.assertEqual(len(changes), 1)
        self.assertIn("new Metasploit PR (open)", changes[0])
        self.assertIn(pr()["url"], changes[0])
        self.assertNotIn("weaponized", changes[0])
        self.assertNotIn("new public PoC", changes[0])

    def test_pr_lifecycle_changes_are_detected(self):
        cases = [
            (pr(), pr(state="merged"), "open→merged"),
            (pr(), pr(state="closed"), "open→closed"),
            (pr(draft=True), pr(), "open (draft)→open"),
        ]
        for old, new, transition in cases:
            with self.subTest(transition=transition):
                changes = watch._detect_changes(snapshot([old]), snapshot([new]))
                self.assertEqual(len(changes), 1)
                self.assertIn(transition, changes[0])
                self.assertIn(new["url"], changes[0])

    def test_failed_search_retains_previous_references(self):
        old = snapshot([pr()])
        latest = snapshot(warnings=["PR search rate limited"], complete=False)
        retained = watch._retain_pr_evidence(old, latest)
        self.assertEqual(retained["metasploit_prs"], [pr()])
        self.assertIn("last known status", retained["discovery_warnings"][-1])
        self.assertEqual(watch._detect_changes(old, retained), [])
        self.assertEqual(latest["metasploit_prs"], [])

    def test_partial_results_preserve_fresh_changes_and_missing_evidence(self):
        old = snapshot([pr(), pr(22071)])
        latest = snapshot(
            [pr(state="merged")], ["PR search results truncated"], complete=False
        )
        retained = watch._retain_pr_evidence(old, latest)
        self.assertEqual(retained["metasploit_prs"], [pr(state="merged"), pr(22071)])
        changes = watch._detect_changes(old, retained)
        self.assertEqual(len(changes), 1)
        self.assertIn("open→merged", changes[0])

    def test_missing_status_details_do_not_erase_known_state(self):
        old = snapshot([pr(draft=True)])
        for fresh in (pr(state="unknown", draft=None), pr(draft=None)):
            with self.subTest(fresh=fresh):
                latest = snapshot([fresh], ["PR details unavailable"], complete=False)
                retained = watch._retain_pr_evidence(old, latest)
                self.assertEqual(retained["metasploit_prs"], old["metasploit_prs"])
                self.assertEqual(watch._detect_changes(old, retained), [])
                self.assertIsNone(latest["metasploit_prs"][0]["draft"])

    def test_complete_empty_search_does_not_retain_stale_references(self):
        latest = snapshot()
        self.assertIs(watch._retain_pr_evidence(snapshot([pr()]), latest), latest)
        self.assertEqual(latest["metasploit_prs"], [])


class WatchOutputTests(unittest.TestCase):
    def test_incomplete_refresh_preserves_and_displays_original_evidence_urls(self):
        previous = pr()
        original_url = previous["url"] + "/files/abc123?diff=split#diff-original"
        fresh_url = previous["url"] + "/files/def456?diff=unified#diff-new"
        previous["reference_urls"] = [previous["url"], original_url]
        for state in ("open", "unknown"):
            with self.subTest(state=state):
                fresh = pr(state=state)
                fresh["reference_urls"] = [fresh_url, fresh["url"]]
                latest = snapshot([fresh], ["PR search incomplete"], complete=False)
                retained = watch._retain_pr_evidence(snapshot([previous]), latest)
                self.assertEqual(
                    set(retained["metasploit_prs"][0]["reference_urls"]),
                    {previous["url"], original_url, fresh_url},
                )
                self.assertEqual(latest["metasploit_prs"][0]["reference_urls"], fresh["reference_urls"])
                _, output = rendered(watch._print_discovery_details, [(CVE, retained)])
                self.assertEqual(output.count(original_url), 1)
                self.assertEqual(output.count(fresh_url), 1)
                self.assertIn("(open)", output)

    def test_discovery_text_is_literal_and_repeated_warnings_are_grouped(self):
        reference = pr()
        reference["title"] = "[red]Literal title[/red] [/unmatched]"
        warning = "PR search [yellow]rate limited[/yellow]"
        _, output = rendered(watch._print_discovery_details, [
            (CVE, snapshot([reference], [warning], complete=False)),
            (OTHER_CVE, snapshot(warnings=[warning], complete=False)),
        ])
        self.assertIn(reference["url"], output)
        self.assertIn(reference["title"], output)
        self.assertIn("(open)", output)
        self.assertIn("Discovery incomplete for 2 CVEs", output)
        self.assertEqual(output.count(warning), 1)

    def test_saved_state_shows_discovery_and_accepts_legacy_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "watch.json"
            current = snapshot([pr()], ["PR search rate limited"], complete=False)
            path.write_text(json.dumps({"cpe": CPE, "cves": {CVE: current}}))
            status, output = rendered(watch.show_state, str(path))
            self.assertEqual(status, 0)
            self.assertIn(pr()["url"], output)
            self.assertIn("PR search rate limited", output)

            legacy = snapshot()
            for key in ("metasploit_prs", "metasploit_prs_complete", "discovery_warnings"):
                legacy.pop(key)
            path.write_text(json.dumps({"cpe": CPE, "cves": {CVE: legacy}}))
            status, output = rendered(watch.show_state, str(path))
            self.assertEqual(status, 0)
            self.assertIn(CVE, output)
            self.assertNotIn("Discovery incomplete", output)

    def test_list_and_keyword_scan_show_discovery_context(self):
        current = snapshot([pr()], ["PR search rate limited"], complete=False)
        with patch.object(watch, "_resolve_cpe", return_value=([CVE], None)), \
                patch.object(watch, "_snapshot_all", return_value={CVE: current}):
            status, output = rendered(watch.run_list, CPE, HEADERS, 2)
        self.assertEqual(status, 0)
        self.assertIn(pr()["url"], output)
        self.assertIn("PR search rate limited", output)

        with patch("CVE2PoC.core.zimbra.fetch_zimbra_cves", return_value={CVE: []}), \
                patch("CVE2PoC.core.zimbra.affects", return_value="yes"), \
                patch.object(watch, "_snapshot_all", return_value={CVE: current}):
            status, output = rendered(watch.run_zimbra_scan, "10.1", HEADERS, 2)
        self.assertEqual(status, 0)
        self.assertIn(pr()["url"], output)
        self.assertIn("PR search rate limited", output)

    def test_unchanged_watch_hides_pr_details_but_keeps_outage_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "watch.json"
            path.write_text(json.dumps({"cpe": CPE, "cves": {CVE: snapshot([pr()])}}))
            outage = snapshot(warnings=["PR search rate limited"], complete=False)
            recovery = snapshot([pr()])
            with patch.object(watch, "_resolve_cpe", return_value=([CVE], None)), \
                    patch.object(watch, "_snapshot_all", side_effect=[
                        {CVE: outage}, {CVE: recovery}
                    ]):
                status, first_output = rendered(watch.run_watch, CPE, str(path), HEADERS, 2)
                retained = json.loads(path.read_text())["cves"][CVE]
                self.assertEqual(status, 0)
                self.assertEqual(retained["metasploit_prs"], [pr()])
                self.assertFalse(retained["metasploit_prs_complete"])
                self.assertIn("last known status", first_output)
                self.assertIn("PR search rate limited", first_output)

                status, second_output = rendered(watch.run_watch, CPE, str(path), HEADERS, 2)
                recovered = json.loads(path.read_text())["cves"][CVE]
                self.assertEqual(status, 0)
                self.assertEqual(recovered["metasploit_prs"], [pr()])
                self.assertTrue(recovered["metasploit_prs_complete"])
                self.assertEqual(recovered["discovery_warnings"], [])

            for output in (first_output, second_output):
                self.assertNotIn(pr()["url"], output)
                self.assertNotIn("Metasploit PR #22070", output)
                self.assertIn("No new risk signals or Metasploit PR changes", output)
                self.assertNotIn("new Metasploit PR (", output)
                self.assertNotIn("Updates to tracked CVEs", output)
            self.assertNotIn("Discovery incomplete", second_output)


if __name__ == "__main__":
    unittest.main()
