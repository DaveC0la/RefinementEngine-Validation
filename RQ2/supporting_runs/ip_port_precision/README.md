# C2 — Additional destination-IP/port checks

These probes test the destination-IP-and-TCP-port restriction also used at S6. They record target traffic and two near matches before installation, while the rule is active, and after withdrawal. The S6 and S9 lifecycle snapshots separately document the installed and withdrawn native rule.

| Probe | Before installation | With rule | After withdrawal |
| --- | --- | --- | --- |
| Target `80.71.158.10:8443` | Connected | Timed out | Connected |
| Different IP, port `8443` | Connected | Connected | — |
| Same IP, port `8444` | Connected | Connected | — |

The nine JSON files preserve the recorded commands and outcomes. The enforced rule matches traffic from `10.20.10.10/32` to `80.71.158.10/32` on TCP destination port `8443`, for newly initiated connections.
