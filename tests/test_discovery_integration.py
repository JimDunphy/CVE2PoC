"""Offline regressions for CLI, batch JSON/HTML, and triage integration."""

import copy
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

from bs4 import BeautifulSoup
from rich.console import Console

import CVE2PoC
from CVE2PoC.core import report
from CVE2PoC.core.discovery_output import poc_metrics, render_discovery
from CVE2PoC.core.triage import compute_triage


CVE = "CVE-2026-93637"
PR_URL = "https://github.com/rapid7/metasploit-framework/pull/22070"
PR_FILES_URL = PR_URL + "/files/abc123?view=split#diff-example"
FILE_URL = "https://github.com/example/research/blob/main/poc.py?raw=1&view=full#L2"
CVE_RECORD = {
    "cve_id": CVE,
    "state": "PUBLISHED",
    "publication_date": "2026-10-28",
    "base_score": 7.5,
    "severity": "HIGH",
    "vendor": "Zimbra",
    "affected_product": "Zimbra Collaboration",
    "cwe": ["CWE-307"],
    "vector_string": "CVSS:3.1/AV:N",
    "kev": "No",
    "epss": 0.1,
}
PR = {
    "url": PR_URL,
    "number": 22070,
    "title": "Zimbra GraphQL module [literal text]",
    "state": "open",
    "draft": False,
    "reference_urls": [PR_FILES_URL],
}
DISCOVERY = {
    "pocs": [],
    "metasploit_prs": [PR],
    "warnings": [],
    "pocs_complete": True,
    "metasploit_prs_complete": True,
}


def record_result(discovery):
    return {
        "cve_id": CVE,
        "cve_record": copy.deepcopy(CVE_RECORD),
        "pocs_from_other_sources": {},
        "github_pocs": (discovery["pocs"], "combined.json"),
        "github_discovery": discovery,
    }, None


class DiscoveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch(
            "requests.get", side_effect=AssertionError("Unexpected network request")
        ))
        self.client = Mock()
        self.client.discover.return_value = copy.deepcopy(DISCOVERY)
        self.stack.enter_context(patch.object(
            CVE2PoC, "GithubDiscoveryClient", return_value=self.client
        ))
        self.stack.enter_context(patch.object(CVE2PoC, "load_dotenv"))
        self.stack.enter_context(patch.object(CVE2PoC.argcomplete, "autocomplete"))
        self.stack.enter_context(patch.object(CVE2PoC.socket, "setdefaulttimeout"))
        self.stack.enter_context(patch.object(
            CVE2PoC, "retrieve_cve_info_from_cve_org",
            side_effect=lambda *args: copy.deepcopy(CVE_RECORD),
        ))
        for name, value in {
            "download_first_epss": [],
            "get_epss": 0.1,
            "download_cisa_kev": [],
            "is_kev": ("No", None),
            "download_exploits_db": ({}, [], []),
            "search_exploits_from_other_sources": {},
            "search_pre_built_vulnerable_docker_environments": "N/A",
        }.items():
            self.stack.enter_context(patch.object(CVE2PoC, name, return_value=value))
        self.output = io.StringIO()
        console = Console(file=self.output, width=160, color_system=None)
        self.stack.enter_context(patch.object(CVE2PoC, "rprint", console.print))

    def test_single_cve_shows_open_pr_without_promoting_triage(self):
        self.stack.enter_context(patch.object(sys, "argv", ["cve2poc", CVE]))
        triage = self.stack.enter_context(patch.object(
            CVE2PoC, "compute_triage", wraps=compute_triage
        ))
        CVE2PoC.main()
        output = self.output.getvalue()
        self.assertIn(PR_URL, output)
        self.assertIn(PR_FILES_URL, output)
        self.assertIn("open", output)
        self.assertIn("informational", output)
        self.client.discover.assert_called_once_with(CVE)
        self.assertEqual(triage.call_args.kwargs["gh_poc_count"], 0)
        self.assertEqual(triage.call_args.kwargs["gh_max_stars"], 0)
        self.assertNotIn("metasploit", triage.call_args.kwargs["other_sources"])

    def test_single_cve_exposes_source_failure_and_keeps_pr(self):
        discovery = copy.deepcopy(DISCOVERY)
        discovery.update(pocs_complete=False, warnings=["Trickest: HTTP 503"])
        self.client.discover.return_value = discovery
        self.stack.enter_context(patch.object(sys, "argv", ["cve2poc", CVE]))
        CVE2PoC.main()
        self.assertIn("HTTP 503", self.output.getvalue())
        self.assertIn("discovery is incomplete", self.output.getvalue())
        self.assertIn(PR_URL, self.output.getvalue())

    def test_batch_json_and_html_keep_urls_status_and_warnings(self):
        discovery = copy.deepcopy(DISCOVERY)
        discovery["pocs"] = [{
            "html_url": FILE_URL,
            "kind": "file",
            "description": 'Example <script>alert("x")</script> & reference',
            "sources": ["Trickest"],
            "programming_language": "Python",
            "stargazers_count": 0,
            "forks": 0,
        }]
        discovery["warnings"] = ["Metadata lookup: HTTP 403"]
        self.stack.enter_context(patch.object(
            CVE2PoC, "get_cve_record_and_exploits",
            return_value=record_result(discovery),
        ))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            cves = path / "cves.txt"
            cves.write_text(CVE + "\n")
            self.stack.enter_context(patch.object(
                sys, "argv", ["cve2poc", "-f", str(cves), "-o", directory]
            ))
            with self.assertRaises(SystemExit) as exit_context:
                CVE2PoC.main()
            self.assertEqual(exit_context.exception.code, 0)
            saved = json.loads(next(path.glob("cve2poc_report_*.json")).read_text())
            evidence = saved[CVE]["GitHub Discovery"]
            self.assertEqual(evidence["pocs"][0]["html_url"], FILE_URL)
            self.assertEqual(evidence["metasploit_prs"][0]["url"], PR_URL)
            self.assertEqual(saved[CVE]["PoCs"]["Metasploit"], "No")
            self.assertEqual(saved[CVE]["PoCs"]["Metasploit PRs"][0]["state"], "open")
            html = next(path.glob("cve2poc_report_*.html")).read_text()
            soup = BeautifulSoup(html, "html.parser")
            self.assertIsNotNone(soup.find("a", href=FILE_URL))
            self.assertIsNotNone(soup.find("a", href=PR_URL))
            self.assertIsNotNone(soup.find("a", href=PR_FILES_URL))
            self.assertNotIn('<script>alert("x")</script>', html)
            self.assertIn("Metadata lookup: HTTP 403", soup.get_text())

    def test_report_collector_uses_supplied_client_and_normalizes_cve(self):
        with patch.object(report, "retrieve_cve_info_from_cve_org",
                          return_value=copy.deepcopy(CVE_RECORD)), \
             patch.object(report, "get_epss", return_value=0.1), \
             patch.object(report, "is_kev", return_value=("No", None)), \
             patch.object(report, "search_exploits_from_other_sources", return_value={}):
            result, error = report.get_cve_record_and_exploits(
                CVE.lower(), [{}, {}], [], [], ({}, [], []), self.client
            )
        self.assertIsNone(error)
        self.client.discover.assert_called_once_with(CVE)
        self.assertEqual(result["github_discovery"]["metasploit_prs"][0]["url"], PR_URL)

    def test_html_rejects_unsafe_links_and_escapes_pr_titles(self):
        discovery = copy.deepcopy(DISCOVERY)
        discovery["metasploit_prs"][0].update(
            url='javascript:alert("x")',
            title='</a><script>alert("x")</script>',
        )
        html = report._metasploit_discovery_cell("No", discovery)
        self.assertNotIn('href="javascript:', html)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<a ", report._evidence_link("https://user:password@example.test/", "x"))

    def test_incomplete_no_match_is_unknown_in_json_and_html(self):
        discovery = copy.deepcopy(DISCOVERY)
        discovery.update(pocs_complete=False, metasploit_prs=[], warnings=["Nomi-sec: timeout"])
        record = {"PoCs": {}}
        report.add_discovery_to_report(record, discovery)
        self.assertEqual(record["PoCs"]["GitHub"], "Unknown")
        self.assertIn("Unknown: lookup incomplete", report._github_discovery_cell(discovery))

    def test_rich_titles_stay_literal_and_language_filter_keeps_prs(self):
        discovery = copy.deepcopy(DISCOVERY)
        discovery["metasploit_prs"][0]["title"] = "[red]literal[/red]\x1b[2J"
        output = io.StringIO()
        Console(file=output, width=160, color_system=None).print(
            render_discovery(discovery, language="Python")
        )
        self.assertIn("[red]literal[/red]", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn(PR_URL, output.getvalue())

    def test_parent_repository_stars_and_pr_mentions_do_not_inflate_metrics(self):
        discovery = {
            "pocs": [
                {"kind": "pull_request", "stargazers_count": 99999},
                {"kind": "file", "stargazers_count": 99999},
                {"kind": "repository", "stargazers_count": 2},
            ],
            "metasploit_prs": [PR],
        }
        self.assertEqual(poc_metrics(discovery), (2, 2))

    @unittest.skipUnless(shutil.which("node"), "Node is optional for report JavaScript verification")
    def test_report_javascript_filters_indexed_status_independently_of_pr_text(self):
        discovery = copy.deepcopy(DISCOVERY)
        discovery["pocs"] = [{
            "html_url": FILE_URL, "description": "File reference", "kind": "file"
        }]
        record = {
            "PoCs": {"GitHub": "No", "Metasploit": "No", "ExploitDB": "No", "Nuclei": "No"},
            "CWE": "CWE-307", "Base Score": 7.5, "EPSS": 0.1, "KEV": "No",
            "Vector String": "CVSS:3.1/AV:N",
        }
        report.add_discovery_to_report(record, discovery)
        with tempfile.TemporaryDirectory() as directory:
            report.generate_html_report({CVE: record}, directory)
            html = next(Path(directory).glob("*.html")).read_text()
        soup = BeautifulSoup(html, "html.parser")
        script = "\n".join(tag.get_text() for tag in soup.find_all("script") if not tag.get("src"))
        empty = copy.deepcopy(DISCOVERY)
        empty["metasploit_prs"][0]["title"] = "Yes is only text in this unmerged PR"
        unknown = {**empty, "pocs_complete": False}
        warning_with_count = {**empty, "warnings": ["Retry (12) requests later"]}
        def contents(cell):
            return BeautifulSoup(cell, "html.parser").td.decode_contents()
        cells = [
            contents(report._github_discovery_cell(discovery)),
            contents(report._github_discovery_cell(empty)),
            contents(report._github_discovery_cell(unknown)),
            contents(report._github_discovery_cell(warning_with_count)),
            contents(report._metasploit_discovery_cell("No", empty)),
            contents(report._metasploit_discovery_cell("https://example.test/module", empty)),
        ]
        # Run the generated inline JS with a tiny DOM/DataTables capture stub.
        # This checks actual renderer behavior without loading remote resources.
        runner = """
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
let options;
global.document = {};
global.localStorage = {getItem: () => null, setItem: () => {}};
const chain = new Proxy({}, {get: (_, name) =>
  name === 'ready' ? cb => cb() :
  name === 'DataTable' ? cfg => {options = cfg; return chain;} :
  () => chain});
global.$ = () => chain;
$.fn = {dataTable: {ext: {search: []}}};
eval(input.script);
const github = options.columnDefs.find(c => c.targets === 6).render;
const metasploit = options.columnDefs.find(c => c.targets === 8).render;
process.stdout.write(JSON.stringify([
  ...input.cells.slice(0, 4).map(c => github(c, 'filter')),
  ...input.cells.slice(4).map(c => metasploit(c, 'filter'))
]));
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", runner],
            input=json.dumps({"script": script, "cells": cells}),
            text=True, capture_output=True, check=True, timeout=10,
        )
        self.assertEqual(json.loads(result.stdout), ["Yes", "No", "Unknown", "No", "No", "Yes"])


if __name__ == "__main__":
    unittest.main()
