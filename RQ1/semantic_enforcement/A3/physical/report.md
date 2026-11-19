# RQ1-A3-01 — Inbound URL/path enforcement (pilot)

**Verdict:** PASS (one pilot instance, not the full A-series generalisation).

**Input:** URLhaus `http://221.15.9.104:39894/bin.sh`, represented by the planted isolated-lab public application resource `/malicious/public/path`; traffic comes from external test hosts.

**Allocation:** `WebApplicationFirewall` / ModSecurity (`waf`).

| Observation | Baseline | Deployed | Restored |
|---|---|---|---|
| Malicious URI path | HTTP 200 | HTTP 403 | HTTP 200 |
| Same path with query | HTTP 200 | HTTP 403 | HTTP 200 |
| Longer near-match path | HTTP 404 | HTTP 404 | HTTP 404 |
| Benign application root | HTTP 200 | HTTP 200 | HTTP 200 |
| Second external source, malicious path | HTTP 200 | HTTP 403 | HTTP 200 |
| Existing baseline-denied flow | Denied | Denied | Denied |
| Generated WAF rule | Absent | Present | Absent |

**Independent physical evidence:** The WAF logged the denied requests while the backend did not receive them; positive controls appeared in both logs. The rule and its exact owner marker were removed without changing the original WAF configuration.

**Scope:** The URLhaus URL is not contacted, and its original host/path are explicitly substituted with a controlled local resource. Experiment reset is not the RQ2 CTI lifecycle evaluation.

**Evidence:** `physical/final_verdict.json` and `physical/evidence/`.
