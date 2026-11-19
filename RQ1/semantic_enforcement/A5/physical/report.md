# RQ1-A5-01 — Inbound User-Agent prohibition (single pilot)

**Verdict:** PASS (single A5 pilot, not the full RQ1 result).

**Indicator:** Original GoBrute HTTP User-Agent, including its comma, preserved exactly through refinement and ModSecurity emission. Converter-only reversible comma escaping produces XML exactMatch; the emitter uses `@contains` as explicitly accounted for by the independent physical oracle.

**Placement:** `WebApplicationFirewall / ModSecurity` (`waf`); one managed configuration rule.

| Request | Baseline | Deployed | Restored |
|---|---|---|---|
| target_root | 200 | 403 | 200 |
| target_other_path | 200 | 403 | 200 |
| embedded_indicator | 200 | 403 | 200 |
| benign_root | 200 | 200 | 200 |
| near_match | 200 | 200 | 200 |
| benign_other_path | 200 | 200 | 200 |
| independent_target | 200 | 403 | 200 |
| independent_benign | 200 | 200 | 200 |

**Independent evidence:** WAF access logs contain all requests. Blocked requests are absent from backend Apache logs, while permitted controls appear in both logs. The pre-existing restriction remains in effect. Managed rule withdrawal restores the original WAF configuration.

**Scope:** One original CTI indicator and isolated-lab endpoint mapping; not the RQ2 CTI lifecycle. See `physical/evidence/` and `physical/final_verdict.json`.
