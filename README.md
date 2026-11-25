# RefinementEngine — Validation Evidence

Companion dataset for *RefinementEngine: Refining Network Intents and Adapting Their CTI-based Enforcement Across Heterogeneous Security Controls*.

The repository collects the experimental inputs, expected results, native configurations and recorded traffic observations used to evaluate RefinementEngine. The experiments address initial enforcement across heterogeneous controls (RQ1) and adaptation as CTI changes (RQ2).

## Evidence by research question

| Experiment | What is evaluated | Evidence |
| --- | --- | --- |
| RQ1 — A1–A7 | Correct matching and enforcement for IP, IP/port, URL, User-Agent and domain restrictions | [`RQ1/scenarios/`](RQ1/scenarios/) |
| RQ1 — B1–B3 | Allocation under changes in available controls or modelled paths | [`RQ1/context/`](RQ1/context/) |
| RQ1 — C1–C3 | Identification of unsupported or infeasible requirements | [`RQ1/negative/`](RQ1/negative/) |
| RQ1 — allocation | Greedy allocation versus an optimal ILP reference | [`RQ1/allocation/`](RQ1/allocation/) |
| RQ2 — S0–S9 | Rule ownership, adaptation and configuration changes across CTI updates | [`RQ2/`](RQ2/) |
| Network | Enterprise topology and baseline configurations | [`topology/`](topology/) |

## Reading the evidence

For **RQ1**, each A-case contains the original HSPL input, reference expectations, native configuration snapshots before and after enforcement, and traffic observations. B-cases contain the relevant control/path changes and physical observations; C-cases pair negative inputs with feasible controls. Allocation inputs and results are in `RQ1/allocation/`.

For **RQ2**, start with [`state_matrix.csv`](RQ2/state_matrix.csv), then inspect `RQ2/states/S1/` through `S9/`. Each state records effective-rule ownership, deployment bindings, observed native configuration and representative traffic outcomes. [`reversed_withdrawal/`](RQ2/reversed_withdrawal/) provides the complementary owner-withdrawal order. See [`RQ2/README.md`](RQ2/README.md) for the state sequence.

[`METHODS.md`](METHODS.md) describes the experimental setting, checks and measurement procedure.
