#!/usr/bin/env python3
"""Verify integrity and selected internal consistency of the curated evidence release."""
import csv, hashlib, json
from pathlib import Path
r=Path(__file__).resolve().parent
for line in (r/'SHA256SUMS.txt').read_text().splitlines():
    digest,path=line.split('  ',1)
    f=r/path
    assert f.is_file() and hashlib.sha256(f.read_bytes()).hexdigest()==digest, f'Integrity mismatch: {path}'
rows={row['instance']:row for row in csv.DictReader((r/'RQ1/allocation/timing_summary.csv').open())}
assert len(rows)==8
assert (int(rows['B3 T0']['candidates']),int(rows['B3 T1']['candidates']))==(2,1)
for sn,required in (('S4',{'EgressProxy':8,'BranchProxy':2}),('S5',{'EgressProxy':4,'BranchProxy':1})):
    s=json.loads((r/f'RQ2/states/{sn}/lifecycle_state.json').read_text())
    counts={x['rule']['device']:len(x['owners']) for x in s['ownership'] if x['rule']['nsf']=='Squid'}
    assert counts==required, (sn,counts)
    report=json.loads((r/f'RQ2/states/{sn}/traffic_report.json').read_text())
    assert report['all_passed'] is True and report['probe_count']==32
    assert len(report['probes'])==32
for case in [f'A{i}' for i in range(1,8)]:
    d=r/'RQ1/scenarios'/case
    assert (d/'input/hspl.xml').is_file() and (d/'reference_expectations.json').is_file()
    assert (d/'traffic_observations.csv').is_file() and any((d/'native').rglob('*.txt'))
for case in ('A5','A7'):
    d=r/'RQ1/scenarios'/case/'native/deployed'
    txt='\n'.join(p.read_text() for p in d.glob('*.txt'))
    if case=='A5':assert 'REQUEST_HEADERS:User-Agent' in txt and '@contains' in txt
    if case=='A7':assert txt.count('http_access deny')>=2 and 'dstdomain' in txt
for case in ('C1','C2','C3'):
    d=r/'RQ1/negative'/case
    assert (d/'reference_expectations.json').exists() and (d/'reported_verdict.json').exists()
    ref=json.loads((d/'reference_expectations.json').read_text())
    verdict=json.loads((d/'reported_verdict.json').read_text())
    assert ref['reference_source_sha256']==verdict['oracle_sha256'], f'Frozen oracle digest mismatch {case}'
    assert hashlib.sha256((d/'original_frozen_oracle.json').read_bytes()).hexdigest()==verdict['oracle_sha256']
# Native ownership retention/removal at both proxies, including complete ACL+deny units.
for sn,blocked in [('S3',True),('S4',True),('S5',True),('S6',True),('S7',False),('S8',False),('S9',False)]:
    for proxy in ('egress_proxy','branch_proxy'):
        txt=(r/f'RQ2/states/{sn}/native/{proxy}.txt').read_text()
        assert ('dstdomain .malware-c2.example' in txt)==blocked, (sn,proxy)
        assert ('http_access deny' in txt)==blocked, (sn,proxy)
# S9 snapshots must be captured after S9's removal operation and omit both managed iptables rules.
for device, marker, original_header in (
    ('edge_fw','rq2_s1_srcip|EdgeFirewall|IpTables','01:26:36'),
    ('corp_fw','rq1_a2_01_c2_ipport|CorpFirewall|IpTables','01:26:40'),
):
    before=(r/f'RQ2/states/S9/native/pre_removal/{device}.txt').read_text()
    after=(r/f'RQ2/states/S9/native/{device}.txt').read_text()
    assert marker in before and marker not in after, device
    assert original_header in after
assert 'http_access deny' in (r/'RQ2/reversed_withdrawal/native/after_B2_egress_proxy.txt').read_text()
assert 'http_access deny' not in (r/'RQ2/reversed_withdrawal/native/final_after_probes_egress_proxy.txt').read_text()

# Historical, separately labeled C2 probe set: inspect actual recorded outcomes.
import json as _json
_c2root = r/'RQ2/supporting_runs/2026-11-01_C2'
for _name, _rc in [
    ('S6_before_target.json', 0), ('S6_before_nearmatch_ip.json', 0),
    ('S6_before_nearmatch_port.json', 0), ('S6_after_target.json', 1),
    ('S6_after_nearmatch_ip.json', 0), ('S6_after_nearmatch_port.json', 0),
    ('S6_later_target.json', 1), ('S9_before_removal_target.json', 1),
    ('S9_after_removal_target.json', 0),
]:
    _record = _json.loads((_c2root/_name).read_text())
    assert _record['rc'] == _rc, ('C2 probe outcome mismatch', _name)
    if _rc == 1:
        assert 'timed out' in _record['stderr'], ('C2 denial evidence missing', _name)

print(f'PASS: {len([x for x in r.rglob("*") if x.is_file()])} total filesystem entries; 8 allocation rows; 7 semantic cases; 3 negative cases; selected lifecycle/native invariants')
