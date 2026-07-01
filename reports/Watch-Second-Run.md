# Example: second `./zimbra-cve.sh watch 10.1.0` run

> Example output only. Generated on 2026-07-01 from public data available at that time.
> Public vulnerability data changes over time; run the command yourself for current status.
> This example uses a temporary state file that was already initialized by a first watch run.

Command used to capture this Markdown example:

```sh
NO_COLOR=1 COLUMNS=160 ./zimbra-cve.sh watch 10.1.0 --state-file /tmp/cve2poc-example-watch-10.1.0.json
```

Output:

```text
[*] Resolving 4 CVE(s) for cpe:2.3:a:zimbra:collaboration:10.1.0:- ...



[+] No new CVEs since last run.
[+] No worsening of previously tracked CVEs.
[*] 4 CVE(s) tracked. See them all: cve2poc --show-state /tmp/cve2poc-example-watch-10.1.0.json
[*] State saved to /tmp/cve2poc-example-watch-10.1.0.json
```
