# RQ1-A4-01 — Outbound HTTP URL prohibition (single pilot)

**Verdict:** PASS. One URLhaus IoC was explicitly mapped to an isolated laboratory URL; the original external indicator URL was never contacted.

**Allocation:** EgressProxy/Squid and BranchProxy/Squid; one HSPL, five recorded source scopes and two effective configuration rules. No HTTPS URL-path semantics claimed.

Per-cell HTTP statuses are shown as **target / query / near-match / same-host benign / other-host same-path**:

| Source scope | Baseline | Deployed | Restored |
|---|---|---|---|
| Employees (egress_proxy) | 200/200/404/200/200 | 403/403/404/200/200 | 200/200/404/200/200 |
| Finance (egress_proxy) | 200/200/404/200/200 | 403/403/404/200/200 | 200/200/404/200/200 |
| Guests (egress_proxy) | 200/200/404/200/200 | 403/403/404/200/200 | 200/200/404/200/200 |
| Devices (egress_proxy) | 200/200/404/200/200 | 403/403/404/200/200 | 200/200/404/200/200 |
| Branch_Users (branch_proxy) | 200/200/404/200/200 | 403/403/404/200/200 | 200/200/404/200/200 |

**Independent evidence:** Squid access logs establish proxy traversal and TCP_DENIED/403 for target requests; origin Apache access logs independently establish that blocked requests were not forwarded. The two generated managed blocks were withdrawn, returning both proxy configurations and all observed traffic to the saved baseline. Existing network restrictions were checked throughout.

**Scope:** One A4 pilot, not the full RQ1 suite or the stateful CTI lifecycle of RQ2. See physical/final_verdict.json and physical/evidence/.
