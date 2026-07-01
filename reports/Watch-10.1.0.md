# Example: `./zimbra-cve.sh watch 10.1.0`

> Example output only. Generated on 2026-07-01 from public data available at that time.
> Public vulnerability data changes over time; run the command yourself for current status.
> This example uses a temporary state file so it does not modify a real watch baseline.

Command used to capture this Markdown example:

```sh
NO_COLOR=1 COLUMNS=160 ./zimbra-cve.sh watch 10.1.0 --state-file /tmp/cve2poc-example-watch-10.1.0.json
```

Output:

```text
[*] Resolving 4 CVE(s) for cpe:2.3:a:zimbra:collaboration:10.1.0:- ...



[*] First run — establishing a baseline of 4 CVE(s). Future runs will report only changes.

Baseline (all currently affecting CVEs)
┏━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━┳━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━┓
┃ CVE ID         ┃  Risk  ┃ Score ┃ EPSS  ┃ KEV ┃ PoCs ┃ Weaponized ┃ Fixed? ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━╇━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━┩
│ CVE-2024-45518 │ MEDIUM │  24   │ 20.3% │ No  │  2   │     No     │   No   │
├────────────────┼────────┼───────┼───────┼─────┼──────┼────────────┼────────┤
│ CVE-2025-67809 │  LOW   │   2   │ 0.23% │ No  │  0   │     No     │   No   │
├────────────────┼────────┼───────┼───────┼─────┼──────┼────────────┼────────┤
│ CVE-2024-45515 │  LOW   │   2   │ 0.28% │ No  │  0   │     No     │   No   │
├────────────────┼────────┼───────┼───────┼─────┼──────┼────────────┼────────┤
│ CVE-2025-27914 │  LOW   │   2   │ 0.25% │ No  │  0   │     No     │   No   │
└────────────────┴────────┴───────┴───────┴─────┴──────┴────────────┴────────┘

[*] State saved to /tmp/cve2poc-example-watch-10.1.0.json
```
