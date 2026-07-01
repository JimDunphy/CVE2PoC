# Example Reports

These files show what the command output looked like when captured for documentation.
They are not current security advice. Public vulnerability data changes over time;
run the commands yourself for current Zimbra CVE status.

The output was captured without terminal color codes so the Markdown stays readable.

| File | Command |
| --- | --- |
| [Show-10.1.md](Show-10.1.md) | `NO_COLOR=1 COLUMNS=160 ./zimbra-cve.sh show 10.1` |
| [Watch-10.1.0.md](Watch-10.1.0.md) | `NO_COLOR=1 COLUMNS=160 ./zimbra-cve.sh watch 10.1.0 --state-file /tmp/cve2poc-example-watch-10.1.0.json` |
| [Watch-Second-Run.md](Watch-Second-Run.md) | `NO_COLOR=1 COLUMNS=160 ./zimbra-cve.sh watch 10.1.0 --state-file /tmp/cve2poc-example-watch-10.1.0.json` |
| [CVE-2024-27443.md](CVE-2024-27443.md) | `NO_COLOR=1 COLUMNS=160 ./zimbra-cve.sh cve CVE-2024-27443` |
| [CVE-2024-45519.md](CVE-2024-45519.md) | `NO_COLOR=1 COLUMNS=160 ./zimbra-cve.sh cve CVE-2024-45519` |
