# C2 — Supplementary physical probe evidence

These nine unmodified `nc` probe records come from a separate validation run of the same qualified C2 rule used in the curated lifecycle campaign. They preserve the original command, outcome and collection metadata; source paths and SHA-256 hashes are in `SOURCE_MAP.csv`.

The probes demonstrate denial of the target IP/port conjunction, preservation of single-field near matches, and restoration after withdrawal. The curated S6/S9 native snapshots independently establish the presence and later removal of that same effective rule. The supplementary probes are not presented as measurements taken during the curated S6/S9 collection.

## Recorded observations

| Probe phase | Target | Native command result | Record |
| --- | --- | --- | --- |
| S6 pre-installation | 80.71.158.10:8443 | connection succeeded (`rc=0`) | `S6_before_target.json` |
| S6 pre-installation | 80.71.158.20:8443 | connection succeeded (`rc=0`) | `S6_before_nearmatch_ip.json` |
| S6 pre-installation | 80.71.158.10:8444 | connection succeeded (`rc=0`) | `S6_before_nearmatch_port.json` |
| S6 after installation | 80.71.158.10:8443 | timeout (`rc=1`) | `S6_after_target.json` |
| S6 after installation | 80.71.158.20:8443 | connection succeeded (`rc=0`) | `S6_after_nearmatch_ip.json` |
| S6 after installation | 80.71.158.10:8444 | connection succeeded (`rc=0`) | `S6_after_nearmatch_port.json` |
| S6 later verification | 80.71.158.10:8443 | timeout (`rc=1`) | `S6_later_target.json` |
| S9 pre-withdrawal | 80.71.158.10:8443 | timeout (`rc=1`) | `S9_before_removal_target.json` |
| S9 after final withdrawal | 80.71.158.10:8443 | connection succeeded (`rc=0`) | `S9_after_removal_target.json` |

The supplementary-run and curated S6 rules share the same canonical identity `1ea6780cd9062adac8e7d9a6ee27982330bb99eaa1680f2aeae537b362c510f4` and native enforcement marker `rq1_a2_01_c2_ipport|CorpFirewall|IpTables`. Both target source `10.20.10.10/32`, destination `80.71.158.10/32`, TCP destination port `8443`, and new connections (`--ctstate NEW`). The curated lifecycle campaign independently documents the C2 rule installed at S6 and absent at S9; A2's independent traffic observations also confirm the conjunction's precision.

