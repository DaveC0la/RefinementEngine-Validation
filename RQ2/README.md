# RQ2 lifecycle evidence

`state_matrix.csv` uses the stable indicator names SRC-A, SRC-B, DOM-A, DOM-B, UA and C2.
Each `states/Sn/` directory contains the available state-specific evidence and, where present, its lifecycle state record.
The final campaign combines the original accepted S0–S3 evidence with a physically checked isolated reconstruction of S3 and the extended S4–S9 campaign.
The physical S3 recheck and S4 gate are in `continuity/`.
Do not interpret these as an uninterrupted single filesystem history from S0 to S9.

The key partial-overlap case is S6: SRC-A is withdrawn, the Edge Firewall rule remains for SRC-B, the UA WAF rule is removed, and the C2 firewall rule is installed.
The S9 record reports zero active managed rules, five cumulative additions, five cumulative removals, and restoration of the S0 baseline.
`reversed_withdrawal/` records the distinct companion experiment that withdraws domain owner B before A.

The records include actionability fields, lifecycle state snapshots, acknowledged operations, native device observations and representative traffic probes.
These independent evidence types should be considered together; a successful command acknowledgement alone is not physical verification.
