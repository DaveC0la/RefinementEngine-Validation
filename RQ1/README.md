# RQ1 experiments

`semantic_enforcement/A1`–`A7` contain selected structured HSPL inputs, independent oracles, generated native-rule output and physical evidence.
`network_context/B1`–`B3` contain scenario inputs, independent oracles, native configurations and results for placement changes.
`negative_cases/C1`–`C3` contain tests in which the requested prohibition cannot be expressed or placed, along with corresponding feasible controls.

`allocation_quality/timing_summary.csv` reproduces the archived greedy/ILP allocation cardinalities and benchmark timings.
`allocation_quality/real/inputs/` contains the five B-series allocation inputs; `allocation_quality/synthetic/` contains three abstract multipath coverage structures and their recorded results.
Each cohort is identified separately because the constructed examples were not physically deployed.

The published material includes recorded inputs and observations but excludes internal refiner, translator and orchestration source code.
