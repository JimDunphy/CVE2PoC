"""Presentation of indexed evidence and separate, informational PR references."""

import re

from rich.console import Group
from rich.table import Table
from rich.text import Text


def plain_text(value):
    """Keep API text literal and remove terminal control characters."""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(value or ""))


def poc_metrics(discovery):
    """Keep PR mentions and parent-repository popularity out of PoC scoring."""
    pocs = [
        poc for poc in discovery.get("pocs", [])
        if poc.get("kind") != "pull_request"
    ]
    stars = [
        poc.get("stargazers_count", 0) for poc in pocs
        if poc.get("kind") == "repository"
        and isinstance(poc.get("stargazers_count", 0), int)
    ]
    return len(pocs), max(stars, default=0)


def render_discovery(discovery, limit=10, language=None):
    """Render source results without interpreting remote text as Rich markup."""
    parts = []
    pocs = sorted(
        discovery.get("pocs", []),
        key=lambda item: (item.get("stargazers_count", 0), item.get("forks", 0)),
        reverse=True,
    )
    if language:
        pocs = [
            poc for poc in pocs
            if str(poc.get("programming_language", "")).casefold() == language.casefold()
        ]
    if pocs:
        table = Table(title="Indexed PoC references", show_lines=True)
        table.add_column("Source")
        table.add_column("Reference", overflow="fold")
        table.add_column("Language")
        for poc in pocs[:limit]:
            sources = ", ".join(poc.get("sources", []))
            description = plain_text(poc.get("description"))
            url = plain_text(poc.get("html_url"))
            table.add_row(
                Text(sources),
                Text(f"{description}\n{url}" if description else url),
                Text(plain_text(poc.get("programming_language", "N/A"))),
            )
        parts.append(table)
        if len(pocs) > limit:
            parts.append(Text(f"Showing {limit} of {len(pocs)} indexed references."))
    elif language:
        parts.append(Text(f"No indexed references matched language {plain_text(language)}."))
    elif discovery.get("pocs_complete", not discovery.get("warnings")):
        parts.append(Text("No PoC references matched in Nomi-sec or Trickest."))
    else:
        parts.append(Text("Indexed PoC discovery is incomplete; no references were returned."))

    prs = discovery.get("metasploit_prs", [])
    if prs:
        table = Table(title="Metasploit PR references (informational)", show_lines=True)
        table.add_column("PR")
        table.add_column("Status")
        table.add_column("Reference", overflow="fold")
        for pr in prs[:limit]:
            state = plain_text(pr.get("state", "unknown"))
            if pr.get("draft") and state == "open":
                state = "open (draft)"
            urls = list(dict.fromkeys(
                [pr.get("url", "")] + pr.get("reference_urls", [])
            ))
            table.add_row(
                Text(f"#{pr.get('number', '?')}"),
                Text(state),
                Text(plain_text(pr.get("title")) + "\n"
                     + "\n".join(plain_text(url) for url in urls if url)),
            )
        parts.append(table)
        parts.append(Text(
            "PR references are candidates for review; they do not change the "
            "indexed PoC count or weaponized-module score."
        ))
        if language:
            parts.append(Text("The language filter applies to indexed references, not PR mentions."))
        if len(prs) > limit:
            parts.append(Text(f"Showing {limit} of {len(prs)} PR references."))
    elif discovery.get("metasploit_prs_complete", not discovery.get("warnings")):
        parts.append(Text("No exact-CVE matches in Metasploit PR titles or descriptions."))
    else:
        parts.append(Text("Metasploit PR discovery is incomplete; no matches were returned."))

    for message in discovery.get("warnings", []):
        parts.append(Text(f"Discovery warning: {plain_text(message)}", style="yellow"))
    return Group(*parts)
