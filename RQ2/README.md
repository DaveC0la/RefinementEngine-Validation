# RQ2 — CTI-driven adaptation

[`state_matrix.csv`](state_matrix.csv) summarises the S0–S9 lifecycle experiment. Each `states/Sn/` directory contains the recorded owner/effective-rule state, native configurations and traffic observations for that step.

| States | Main observation |
| --- | --- |
| S0–S3 | Baseline followed by source-IP, WAF User-Agent and two proxy domain restrictions |
| S4–S5 | Independently managed IoCs share existing rules; withdrawing one domain IoC retains both proxy rules |
| S6 | Shared source-IP rule retained, WAF rule removed, qualified destination-IP/port rule added |
| S7–S8 | Final domain owner withdrawn; repeated unchanged reconciliation leaves the remaining rules intact |
| S9 | Remaining firewall restrictions withdrawn and baseline restored |

The reported five additions and five removals concern CTI-managed effective rules. Ownership changes that retain an existing rule do not require configuration operations. Compare `lifecycle_state.json` with the corresponding `native/` and `traffic_observations.csv` records to examine each step.

[`reversed_withdrawal/`](reversed_withdrawal/) tests the opposite removal order of the two domain IoCs. [`supporting_runs/ip_port_precision/`](supporting_runs/ip_port_precision/) contains additional IP/port precision probes.
