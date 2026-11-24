# RefinementEngine — Curated validation evidence

This repository accompanies *RefinementEngine: Refining CTI-Driven Network Policies and Adapting Their Enforcement Across Heterogeneous Security Controls* (IEEE TDSC submission).

It is a **scientific evidence dataset**, not a release of the proprietary RefinementEngine implementation. It publishes original policy inputs, independently specified reference expectations (curated where stated), the Kathará network and relevant baseline configuration, observed native rule content, traffic outcomes, allocation inputs/results, and lifecycle ownership/binding records. It does not reproduce the complete proprietary refinement-to-deployment execution.

## Navigate

- [`topology/`](topology/) — data-plane Kathará topology, addressing, selected startup/baseline configuration, network diagram, and test CTI data.
- [`RQ1/scenarios/A1`–`A7`](RQ1/scenarios/) — each original HSPL, curated reference expectations, recorded native snapshots and baseline/deployed/restored traffic observations.
- [`RQ1/context/B1`–`B3`](RQ1/context/) — changes to topology/control context, independent expectations, selected rules and outcome records.
- [`RQ1/negative/C1`–`C3`](RQ1/negative/) — unsupported/infeasible requirements, original case inputs, **unaltered frozen oracles** (plus a concise reading view), and recorded negative/control results.
- [`RQ1/allocation/`](RQ1/allocation/) — five operational allocation inputs, three **constructed (not physically deployed)** multipath coverage instances, independent enumeration and the 25-repetition timing summaries.
- [`RQ2/`](RQ2/) — lifecycle state matrix, owner/binding records, CTI observations, selected observed native configurations, representative HTTP probes and reversed-owner withdrawal.
- [`SOURCE_MAP.csv`](SOURCE_MAP.csv) — file-level provenance for verbatim files and extracted reference/native contents; traffic tables also contain an original record path and SHA-256 for each row.

## Interpretation and known boundaries

- **A3/A5:** The modelled `MaliciousHost` endpoint represents a generic external source for path and placement reasoning, not a source-IP matching condition. The independent expectations require URL-path and User-Agent restrictions at the protected service regardless of the originating address; native WAF rules and traffic probes from distinct external sources confirm the evaluated behavior.
- **A4:** the tested Squid predicate is a **host-qualified HTTP URL**, not a generic path-only match; the test uses a controlled laboratory endpoint substituted for the original indicator resource.
- **A5:** the observed WAF rule uses User-Agent containment (`@contains`); literal, embedded, benign, and near-match requests provide discriminating tests of that native predicate.
- **A6:** the native Squid rules and recorded traffic observations demonstrate User-Agent filtering at both designated proxies for the evaluated indicator and five represented client populations, including embedded and near-match checks.
- **A7/RQ2 proxies:** two proxy-local domain-denial blocks apply to the five represented source groups tested through the designated proxies. The native blocks do not have source predicates, so exclusion of every other possible proxy client is not established.
- **Native-rule observations:** laboratory rule materialization from intermediate refinement artifacts was exercised for the physical cases; the recorded traffic does not independently validate every intermediate MSPL-to-native translation stage in the architectural workflow.
- **C2 supplementary probes:** `RQ2/supporting_runs/2026-11-01_C2/` preserves original target and near-match observations from a separate run of the same effective rule. The S6/S9 native snapshots establish installation and removal; the supplementary probes and A2 corroborate matching precision.
- **S9 native evidence:** final device snapshots record the state after withdrawal. Earlier captures are retained under `RQ2/states/S9/native/pre_removal/`.
- **RQ2:** the S4–S9 transitions continue from a restored, verified S3 checkpoint with matching ownership, native configurations and traffic decisions. The study evaluates sequential, successfully completed state transitions.
- **Source:** the original full validation archive remains the research record at https://github.com/DaveC0la/RefinementEngine-Validation . This package is a curated view; some `reference_expectations.json` files selectively extract semantic fields from original frozen oracles. It never claims to reproduce byte-for-byte those full original oracle files. Verbatim native `stdout` contents are identified by source-file hashes.

See [`METHODS.md`](METHODS.md) for methodology and [`verify_release.py`](verify_release.py) for checksum, table and selected semantic-invariant checks.
