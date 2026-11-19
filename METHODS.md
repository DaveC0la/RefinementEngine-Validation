# Evaluation design and evidence interpretation

## RQ1 — Enforcement across supported contexts

The seven A-series cases assess source-IP filtering, destination IP with TCP port, inbound URL-path filtering, outbound URL-path filtering, inbound User-Agent filtering, outbound User-Agent filtering, and domain/subdomain filtering.
Each case is compared with a separately defined semantic oracle and selected traffic observations before deployment, during enforcement and, where recorded, after withdrawal.
The B-series changes enforcement topology, traffic paths or security-control availability while retaining the prohibition being evaluated.
C1–C3 respectively assess unsupported temporal matching, inability to enforce an entire conjunction at one eligible control, and control placement outside a required traffic path.
A1 includes an explicitly labelled preliminary verdict in the original preserved record; its evidence must not be treated as proof of more checks than the record reports.

## Allocation benchmark

The five B-series allocation traces are operational instances with a single modelled path.
The three constructed multipath coverage instances (AS1–AS3) use deterministic abstract coverage inputs, not separately deployed Kathará topologies.
Greedy and ILP comparisons use the same candidate/path coverage data.
The archived PuLP/CBC measurements report median and 95th-percentile times over 25 repetitions after a warm-up, including ILP model preparation and solver execution.
These results document the measured trade-off for the supplied instances and do not establish asymptotic complexity or full refinement latency.

## RQ2 — Controlled adaptation

The campaign maintains effective-rule identities and owner records across successive states.
At S4, a second source-IP indicator shares the Edge Firewall rule while a second domain indicator shares both proxy rules.
At S5, the first domain owner retires but the two proxy rules remain for the second owner.
At S6, the original source-IP owner retires while its rule remains for the second owner; the User-Agent rule is removed and the C2 rule is installed.
At S7, the remaining domain owner retires and the two proxy rules are removed.
S8 repeats reconciliation twice without changing the desired enforcement.
S9 withdraws the remaining source-IP and C2 indicators and verifies restoration of the original baseline.
The cumulative operation history contains five additions and five removals; zero managed rules remain after S9.

Actionability decisions use controlled structured CTI evidence with two consecutive non-actionable evaluations before withdrawal.
The experiments establish behaviour under those supplied observations, not the reliability or timeliness of live threat feeds.
Traffic probes cover representative tested flows, not every possible packet or routing condition.
Recorded operation counts are not exhaustive device-command traces.

## How to inspect

- Read an independent oracle or CTI input before its corresponding verdict and physical observations.
- For each RQ2 state, inspect the owner's effective-rule set and the accompanying native configuration snapshots.
- Compare configuration changes with additions/removals in `RQ2/state_matrix.csv`.
- Check both matching and near-match traffic observations for changes to intended enforcement.
- Verify `RQ2/continuity/` before treating the extended S4–S9 evidence as a continuation of the accepted S3 baseline.
