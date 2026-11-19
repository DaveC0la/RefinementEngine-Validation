# RQ1-A7-01 — Outbound malicious-domain prohibition (native Squid pilot)

**Verdict:** PASS (single A7 pilot, not aggregate RQ1).

**CTI:** Kali365 `kali365.xyz`, explicitly mapped to controlled `malware-c2.example`.

**Allocation:** EgressProxy/Squid and BranchProxy/Squid. One parent HSPL expanded
into five source-population contributions and two owned configuration rules.

Each cell reports target / subdomain / same-domain alternative path / benign domain / direct IP:

| Source population | Baseline | Deployed | Restored |
|---|---|---|---|
| employee (egress_proxy) | 200/200/200/200/200 | 403/403/403/200/200 | 200/200/200/200/200 |
| finance (egress_proxy) | 200/200/200/200/200 | 403/403/403/200/200 | 200/200/200/200/200 |
| guest_host (egress_proxy) | 200/200/200/200/200 | 403/403/403/200/200 | 200/200/200/200/200 |
| iot_device (egress_proxy) | 200/200/200/200/200 | 403/403/403/200/200 | 200/200/200/200/200 |
| branch_user (branch_proxy) | 200/200/200/200/200 | 403/403/403/200/200 | 200/200/200/200/200 |

**Independent evidence:** Requests matching the domain ACL show `TCP_DENIED/403`
at their assigned Squid proxy and are absent from the malicious-origin Apache log;
permitted requests reach the corresponding malicious or benign origin. The alternate
proxy is not used, and the pre-existing network restriction remains effective.
Both managed domain ACLs are withdrawn with exact baseline restoration.

**Static negative control:** The unresolvable lookalike domain
`malware-c2.example.invalid` is checked using DNS label-suffix semantics,
not counted as a live HTTP success.

**Scope:** Isolated explicit HTTP proxy only. Neither `kali365.xyz` nor
other external malicious endpoints are contacted. No HTTPS/SNI validation.
Experimental withdrawal is not the RQ2 CTI lifecycle.

See `physical/final_verdict.json` and `physical/evidence/`.
