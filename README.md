# RefinementEngine — Experimental Validation Artifacts

This archive accompanies the evaluation of **RefinementEngine: Refining CTI-Driven Network Policies and Adapting Their Enforcement Across Heterogeneous Security Controls**.
It contains the network model, experimental inputs, independent reference outcomes, measured allocation results, and recorded device and traffic observations for RQ1 and RQ2.

## Contents

| Directory | Contents |
|---|---|
| `topology/` | Kathará laboratory configuration, device initialization, network diagram, addressing, baseline policy and sample CTI dataset |
| `RQ1/semantic_enforcement/` | Seven A-series prohibition experiments (inputs, oracles, generated rules, configuration and traffic evidence) |
| `RQ1/network_context/` | B1–B3 enforcement-point, path and capability variation experiments |
| `RQ1/negative_cases/` | C1–C3 unsupported/infeasible prohibitions and reference tests |
| `RQ1/allocation_quality/` | Five B-series allocation traces, three constructed multipath cases, recorded greedy/ILP outcomes and timing summary |
| `RQ2/states/` | S0–S9 baseline and extended lifecycle campaign, including CTI observations, ownership state, device snapshots and traffic evidence |
| `RQ2/reversed_withdrawal/` | Separate domain-owner withdrawal-order experiment |
| `RQ2/continuity/` | Physical S3 recheck and S4 preparation evidence for the extended campaign |
| `SHA256SUMS.txt` | Integrity hashes for the distributed files |

Read `METHODS.md` for the study design, `topology/README.md` for the lab topology, and `RQ1/README.md` and `RQ2/README.md` for the evidence layout.

## Verification

From the extracted archive root:

```sh
sha256sum -c SHA256SUMS.txt
python3 verify_artifacts.py
```

These checks validate file integrity and selected relationships between the recorded results and experimental states; they do not rerun the proprietary refinement pipeline or the Kathará deployment.

## Availability and scope

The network laboratory and recorded experimental evidence are provided for inspection and independent analysis. Machine-specific workspace prefixes in non-hash-linked command metadata have been normalised to `/workspace/` for distribution; the original S3 traffic reports are retained byte-for-byte so their recorded cross-references remain verifiable.
The RefinementEngine implementation is not included. The control-plane containers in the distributed Kathará topology are placeholders; the published topology preserves the modelled data-plane network and baseline device configuration, not a standalone end-to-end RefinementEngine installation.

The extended RQ2 campaign uses a verified S3 baseline reconstructed in an isolated instance of the laboratory before progressing through S4–S9.
The S4–S9 evidence must be interpreted together with `RQ2/continuity/` and the original S0–S3 records, rather than as a single uninterrupted recorded process from the original S0 execution.
The reversed-withdrawal experiment is an independent companion run.

The source-IP indicators SRC-A and SRC-B are independently identified records with the same value, as are domain indicators DOM-A and DOM-B.
The additional indicators are UA (User-Agent) and C2 (destination IP with TCP-port qualifier).

The benchmark contains five operational allocation traces and three deliberately constructed abstract path-coverage instances; the latter were not deployed as physical network scenarios.
Recorded computation times cover allocation only, not end-to-end deployment latency.

This artifact contains experimental observations and lab tooling, not a public release of the RefinementEngine source code.
