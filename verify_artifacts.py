#!/usr/bin/env python3
"""Check distribution hashes and the principal recorded experiment invariants."""
from pathlib import Path
import hashlib, csv, json

root = Path(__file__).resolve().parent
manifest = (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
files = [p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt"]
expected = {}
for line in manifest:
    digest, marker, name = line.partition("  ")
    if not marker or name in expected:
        raise ValueError("Invalid checksum manifest")
    expected[name] = digest
actual = {p.relative_to(root).as_posix() for p in files}
assert actual == set(expected), "Manifest does not match distributed files"
for name, digest in expected.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name

with (root / "RQ2/state_matrix.csv").open(newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream))
assert len(rows) == 10
assert [int(r["active_rules"]) for r in rows] == [0, 1, 2, 4, 4, 4, 4, 2, 2, 0]
assert sum(int(r["additions"]) for r in rows) == 5
assert sum(int(r["removals"]) for r in rows) == 5

for step, name in [(4,"S4_VERDICT.json"),(5,"S5_VERDICT.json"),
                   (6,"evidence/stage2/S6_VERDICT.json"),
                   (7,"evidence/S7_VERDICT.json"),
                   (8,"evidence/S8_VERDICT.json"),
                   (9,"evidence/S9_VERDICT.json")]:
    data = json.loads((root / "RQ2/states" / f"S{step}" / name).read_text())
    assert data.get("pass") is True, f"S{step} verdict"

s6 = json.loads((root / "RQ2/states/S6/evidence/stage2/S6_VERDICT.json").read_text())
assert s6["source_B_remains_sole_source_owner"] and s6["source_A_withdrawn"]
assert (s6["physical_rule_additions"], s6["physical_rule_removals"]) == (1, 1)
s9 = json.loads((root / "RQ2/states/S9/evidence/S9_VERDICT.json").read_text())
assert (s9["active_effective_rules"], s9["verified_additions"], s9["verified_removals"]) == (0,5,5)
assert s9["s0_firewall_filter_baselines_restored"]
for stage, filename, path_field, hash_field in [
    (4,"S4_traffic_verdict.json","source_report","source_report_sha256"),
    (5,"evidence/traffic_verdict.json","report","report_sha256")]:
    d = json.loads((root / "RQ2/states" / f"S{stage}" / filename).read_text())
    target = root / "RQ2/continuity/s3_traffic_gate" / Path(d[path_field]).name
    assert hashlib.sha256(target.read_bytes()).hexdigest() == d[hash_field], f"S{stage} traffic reference"

with (root / "RQ1/allocation_quality/timing_summary.csv").open(newline="", encoding="utf-8") as stream:
    q = list(csv.DictReader(stream))
assert len(q) == 8
assert [(row["instance"], float(row["excess_pct"])) for row in q[-3:]] == [("AS1",0.),("AS2",25.),("AS3",50.)]
print(f"PASS: {len(files)} files verified; eight allocation records and six extended RQ2 verdicts checked.")
