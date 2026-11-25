# B3 — Change of eligible enforcement control

B3 evaluates a destination-IP/TCP-port prohibition while changing which firewall can receive new managed rules. The original HSPL is in [`input/hspl.xml`](input/hspl.xml); [`input/management_change.json`](input/management_change.json) identifies the change in eligibility. The independently specified expected allocations are in [`reference_expectations.json`](reference_expectations.json), with the original frozen reference also provided.

| Phase | Eligible firewalls | Selected pair | Allocation input |
| --- | --- | --- | --- |
| T0 | Guest Firewall, Edge Firewall | Guest Firewall / IpTables | [`B3_02.json`](../../allocation/real/inputs/B3_02.json) |
| T1 | Edge Firewall | Edge Firewall / IpTables | [`B3_01.json`](../../allocation/real/inputs/B3_01.json) |

The firewall and traffic routing configurations remain unchanged. The native rules are in `native/T0/` and `native/T1/`; `traffic/physical/` records the blocked, near-match and restored traffic checks at both phases.
