# RQ1-A6-01 — Outbound HTTP User-Agent prohibition (validation extension pilot)

**Verdict:** PASS (single A6 extension pilot, not aggregate RQ1).

**Indicator:** Original GoBrute User-Agent with comma preserved in refinement and emission.

**Allocation:** EgressProxy/Squid and BranchProxy/Squid; one HSPL expanded into five
source contributions and two effective rules. The cloned TOSCA subtype, runtime capability
alias and Squid emitter adapter are **not native frozen-engine functionality**.

Each cell is original indicator / embedded indicator / near-match / benign:

| Source population | Baseline | Deployed | Restored |
|---|---|---|---|
| employee (egress_proxy) | 200/200/200/200 | 403/403/200/200 | 200/200/200/200 |
| finance (egress_proxy) | 200/200/200/200 | 403/403/200/200 | 200/200/200/200 |
| guest_host (egress_proxy) | 200/200/200/200 | 403/403/200/200 | 200/200/200/200 |
| iot_device (egress_proxy) | 200/200/200/200 | 403/403/200/200 | 200/200/200/200 |
| branch_user (branch_proxy) | 200/200/200/200 | 403/403/200/200 | 200/200/200/200 |

**Independent evidence:** Both Squid proxy access logs show denied traffic as
`TCP_DENIED/403`, and blocked requests are absent from the origin Apache logs.
Permitted requests appear at the origin, and the pre-existing network restriction remains active.
Ownership-based withdrawal returns both live configuration files to baseline.

**Scope:** Explicit HTTP proxy only; no HTTPS inspection. The parent HSPL and CTI
mapping are single-origin, but the synthetic expanded ownership entries have distinct
`ioc_id` values. Experiment reset is not the RQ2 CTI lifecycle.

See `physical/final_verdict.json` and `physical/evidence/`.
