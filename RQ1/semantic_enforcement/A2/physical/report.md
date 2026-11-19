# RQ1-A2-01 — Physical validation (pilot)

**Verdict:** PASS (single pilot instance; not a full A-series generalisation result)

**Input:** EmployeeHost prohibited from reaching the controlled C2 endpoint `80.71.158.10:8443/TCP` (substituted for CTI `102.220.161.63:10213`).

**Allocated controls:** `corp_fw` / IpTables

| Observation | Baseline | Deployed | Restored |
|---|---|---|---|
| C2 TCP/8443 | HTTP 200 | Blocked (TCP timeout) | HTTP 200 |
| Same C2, TCP/8444 | HTTP 200 | HTTP 200 | HTTP 200 |
| Other IP, TCP/8443 | HTTP 200 | HTTP 200 | HTTP 200 |
| Independent benign HTTP | HTTP 200 | HTTP 200 | HTTP 200 |
| Existing denied flow | Denied | Denied | Denied |
| Managed A2 rule | Absent | Present, counter increased | Absent |

**Interpretation:** Refinement selected a path-covering firewall and generated an IP-and-port-specific rule. Live traffic and the firewall counter verified enforcement; near-match and unrelated traffic remained permitted. The initial firewall rule definitions were restored after withdrawal.

**Limits:** This evidence covers one controlled A2 pilot, with TCP chosen for the lab; the original CTI record does not specify a transport. The reset is an experimental cleanup, not an RQ2 lifecycle test.

**Evidence:** `physical/final_verdict.json` and `physical/evidence/`.
