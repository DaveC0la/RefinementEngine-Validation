<#
  verify-policy.ps1   (unified 12-zone connectivity-matrix edition)
  ----------------------------------------------------------------------------
  Verifies the baseline firewall policy of the refinement-engine Kathara lab by
  testing the FULL zone-to-zone connectivity matrix.

  ZONES (all are both source and destination - one representative host each):
    10 internal zones + DMZ Frontend (WAF) + DMZ Backend = 12 zones.
    11 of the 12 zones are mutually routable; the Backend is the exception (it is
    private to the WAF, see below), so PING RESULT == POLICY VERDICT for every
    cell EXCEPT those that touch the Backend, which are 'UNREACH' by construction.
      - internal zones: routed via the core (OSPF).
      - Frontend (172.16.10.0/24): advertised into OSPF by edge_fw; reachable
        from internal; the WAF originates traffic via edge_fw.
      - Backend (172.16.20.0/24): private to the WAF (Option A - "the backend
        speaks only to the WAF"). Its subnet is NOT advertised into the internal
        IGP (the edge_fw route leak was removed) AND edge_fw blackholes it, so:
          * AS DESTINATION: every internal zone has NO route to it - unreachable
            from inside BY CONSTRUCTION. Expected verdict 'UNREACH' (100% loss,
            no policy intent, no drop counter - it is topology, not a firewall
            rule). The ONLY path in is Frontend -> Backend (WAF connected iface).
          * AS SOURCE: the backend has a FORWARD path to edge_fw but NO RETURN
            route, so replies to it are black-holed. Its only intended egress is
            one-way syslog to the SIEM, so Backend -> Security is 'UNREACH' (forward
            leaves, no reply returns - NOT an ACL, no drop counter). Backend ->
            Frontend stays a live PASS (WAF is directly connected). EVERY OTHER
            backend-sourced flow is an explicit deny tested live as 'FAIL' with a
            drop-counter read: the sensitive/internal/Internet zones (hspl30-36)
            and the untrusted zones Guests/Devices/Branch (hspl60-62). The WAF
            (Frontend) is fully routable, so its denies - hspl37-42 plus the
            completion hspl63-66 (Guests/Devices/Branch + Internet) - are all live
            'FAIL'; Frontend -> Backend and Frontend -> Security stay live PASS.
    Internet (80.71.158.0/24): tested BOTH as a destination (egress, in the
    matrix) AND as a SOURCE (the 13th row - perimeter ingress). Because Internet
    hosts have no route to RFC1918 and only tcp/80,443 is DNATed to the WAF, the
    Internet-source row uses the right instrument per cell rather than naive pings:
      - Internet -> Frontend : HTTP GET to the public VIP (203.0.113.2); a 200
        whose body comes from the backend proves Internet->DNAT->WAF->Backend, the
        SOLE sanctioned ingress. (A ping to the WAF's private IP would wrongly read
        'unreachable', so ping is NOT used here.)
      - Internet -> any internal/backend zone : live ping, expected UNREACHABLE at
        the perimeter (no route + no DNAT). These are regression guards (a leak
        flips them) and are COMPLEMENTARY to the presence block, which separately
        asserts the defense-in-depth DROP ACLs (hspl1-11) are loaded. A naive
        Internet->internal ping 'passes' even with those ACLs deleted - it dies at
        the ISP - so presence and live-ingress test different layers on purpose.

  HOW COMPLETENESS IS GUARANTEED
    Baseline = "default-allow with explicit denies". The policy is encoded once
    ($Zones + $Deny); the script GENERATES one check per ordered (src -> dst)
    pair and derives the expected verdict from $Deny (deny if listed, else allow).
    Nothing is hand-picked: every allowed pair and every denied pair is tested.

  TWO CHECK KINDS
    reach   - ping from a source host to a destination IP.
                PASS = allow intent (echo replies). FAIL = deny intent (100% loss);
                the enforcing firewall's FORWARD counter is read to confirm the drop.
    present - assert a DROP rule is loaded in a firewall's chain. Used ONLY for the
                11 Internet-SOURCED rules: Internet hosts have no route to private
                space (the ISP carries no 10/172.16 route; edge_fw only DNATs
                inbound 80/443 to the WAF), so that traffic can't be generated from
                inside the emulation and the rule is verified by being deployed.

  Run from the lab dir after `kathara lstart` + ~30s for OSPF convergence.
  Budget ~5-6 min (denied pings wait out their timeout). Requires the
  devices->branch rule in guest_fw.startup. Clean run prints "0 mismatched".
#>

$PingCount   = 2     # echoes per reach check (ping -c)
$PingTimeout = 2     # seconds per echo       (ping -W)

# --- the 12 zones (source AND destination) -----------------------------------
$Zones = @(
  @{ Z='security';     Code='sec'; Net='10.10.10.0/24';  Dev='refinement_engine'; Ip='10.10.10.10' }
  @{ Z='management';   Code='mgt'; Net='10.10.20.0/24';  Dev='admin_host';        Ip='10.10.20.10' }
  @{ Z='employees';    Code='emp'; Net='10.20.10.0/24';  Dev='employee';          Ip='10.20.10.10' }
  @{ Z='finance';      Code='fnc'; Net='10.20.20.0/24';  Dev='finance';           Ip='10.20.20.10' }
  @{ Z='guests';       Code='gst'; Net='10.30.10.0/24';  Dev='guest_host';        Ip='10.30.10.10' }
  @{ Z='devices';      Code='dvc'; Net='10.30.20.0/24';  Dev='iot_device';        Ip='10.30.20.10' }
  @{ Z='applications'; Code='app'; Net='10.40.10.0/24';  Dev='internal_app';      Ip='10.40.10.10' }
  @{ Z='database';     Code='dbs'; Net='10.40.20.0/24';  Dev='db_server';         Ip='10.40.20.10' }
  @{ Z='identity';     Code='idn'; Net='10.40.30.0/24';  Dev='internal_dns';      Ip='10.40.30.53' }
  @{ Z='branch';       Code='brc'; Net='10.70.10.0/24';  Dev='branch_user';       Ip='10.70.10.10' }
  @{ Z='frontend';     Code='frt'; Net='172.16.10.0/24'; Dev='waf';               Ip='172.16.10.2' }
  @{ Z='backend';      Code='bck'; Net='172.16.20.0/24'; Dev='web_backend';       Ip='172.16.20.10' }
)
# Internet: destination-only (egress). As a source it is the presence block.
$Internet = @{ Z='internet'; Code='int'; Net='80.71.158.0/24'; Dev='benign_web'; Ip='80.71.158.30' }

# --- the policy: every DROP rule for flows ORIGINATED by a testable zone ------
#     key = 'srcNet->dstNet'   value = enforcing firewall (for counter read)
$Deny = @{
  # corp_fw
  '10.20.10.0/24->10.40.20.0/24'='corp_fw'; '10.20.20.0/24->10.40.20.0/24'='corp_fw'
  '10.20.10.0/24->10.20.20.0/24'='corp_fw'; '10.20.10.0/24->10.10.10.0/24'='corp_fw'
  '10.20.20.0/24->10.10.10.0/24'='corp_fw'; '10.20.10.0/24->10.10.20.0/24'='corp_fw'
  '10.20.20.0/24->10.10.20.0/24'='corp_fw'
  # dc_fw
  '10.40.10.0/24->10.10.20.0/24'='dc_fw';   '10.40.20.0/24->10.10.20.0/24'='dc_fw'
  '10.40.30.0/24->10.10.20.0/24'='dc_fw';   '10.40.10.0/24->80.71.158.0/24'='dc_fw'
  '10.40.20.0/24->80.71.158.0/24'='dc_fw'
  # guest_fw (includes devices->branch - add to guest_fw.startup before running)
  '10.30.10.0/24->10.10.10.0/24'='guest_fw'; '10.30.10.0/24->10.10.20.0/24'='guest_fw'
  '10.30.10.0/24->10.20.10.0/24'='guest_fw'; '10.30.10.0/24->10.20.20.0/24'='guest_fw'
  '10.30.10.0/24->10.30.20.0/24'='guest_fw'; '10.30.10.0/24->10.40.10.0/24'='guest_fw'
  '10.30.10.0/24->10.40.20.0/24'='guest_fw'; '10.30.10.0/24->10.40.30.0/24'='guest_fw'
  '10.30.10.0/24->10.70.10.0/24'='guest_fw'
  '10.30.20.0/24->10.10.10.0/24'='guest_fw'; '10.30.20.0/24->10.10.20.0/24'='guest_fw'
  '10.30.20.0/24->10.20.10.0/24'='guest_fw'; '10.30.20.0/24->10.20.20.0/24'='guest_fw'
  '10.30.20.0/24->10.30.10.0/24'='guest_fw'; '10.30.20.0/24->10.40.10.0/24'='guest_fw'
  '10.30.20.0/24->10.40.20.0/24'='guest_fw'; '10.30.20.0/24->10.40.30.0/24'='guest_fw'
  '10.30.20.0/24->10.70.10.0/24'='guest_fw'
  # branch_fw (internal)
  '10.70.10.0/24->10.40.20.0/24'='branch_fw'; '10.70.10.0/24->10.20.20.0/24'='branch_fw'
  '10.70.10.0/24->10.10.10.0/24'='branch_fw'; '10.70.10.0/24->10.10.20.0/24'='branch_fw'
  # admin_fw (mgmt default-deny egress; only non-private dst in our set is Internet)
  '10.10.20.0/24->80.71.158.0/24'='admin_fw'
  # edge_fw : DMZ Frontend (WAF) containment (hspl37-42)
  '172.16.10.0/24->10.20.10.0/24'='edge_fw'; '172.16.10.0/24->10.20.20.0/24'='edge_fw'
  '172.16.10.0/24->10.40.10.0/24'='edge_fw'; '172.16.10.0/24->10.40.20.0/24'='edge_fw'
  '172.16.10.0/24->10.40.30.0/24'='edge_fw'; '172.16.10.0/24->10.10.20.0/24'='edge_fw'
  # edge_fw : DMZ Backend containment + egress (hspl30-36)
  '172.16.20.0/24->10.20.10.0/24'='edge_fw'; '172.16.20.0/24->10.20.20.0/24'='edge_fw'
  '172.16.20.0/24->10.40.10.0/24'='edge_fw'; '172.16.20.0/24->10.40.20.0/24'='edge_fw'
  '172.16.20.0/24->10.40.30.0/24'='edge_fw'; '172.16.20.0/24->10.10.20.0/24'='edge_fw'
  '172.16.20.0/24->80.71.158.0/24'='edge_fw'
  # edge_fw : DMZ source-containment completion (hspl60-66) - untrusted zones for
  #           both DMZ tiers + the WAF's Internet egress
  '172.16.20.0/24->10.30.10.0/24'='edge_fw'; '172.16.20.0/24->10.30.20.0/24'='edge_fw'
  '172.16.20.0/24->10.70.10.0/24'='edge_fw'
  '172.16.10.0/24->10.30.10.0/24'='edge_fw'; '172.16.10.0/24->10.30.20.0/24'='edge_fw'
  '172.16.10.0/24->10.70.10.0/24'='edge_fw'; '172.16.10.0/24->80.71.158.0/24'='edge_fw'
  # NOTE: Frontend has no deny toward Security (log shipping) or Backend (proxy) -
  #       those are ALLOW cells tested as live PASS; all other Frontend egress is
  #       now denied (hspl37-42 + hspl63-66). Backend's only remaining ALLOW egress
  #       is Security (one-way syslog) and Frontend (return): Backend->Security is
  #       UNREACH by construction (no return route; handled in the matrix build,
  #       not here), Backend->Frontend is a live PASS. Every other backend-source
  #       flow is an explicit deny above (hspl30-36 + hspl60-62).
}

# --- Internet-SOURCED rules: presence only (cannot be generated from inside) --
$Present = @(
  @{ Name='internet -> security';    On='edge_fw';   Src='80.71.158.0/24'; Dst='10.10.10.0/24' }
  @{ Name='internet -> management';  On='edge_fw';   Src='80.71.158.0/24'; Dst='10.10.20.0/24' }
  @{ Name='internet -> employees';   On='edge_fw';   Src='80.71.158.0/24'; Dst='10.20.10.0/24' }
  @{ Name='internet -> finance';     On='edge_fw';   Src='80.71.158.0/24'; Dst='10.20.20.0/24' }
  @{ Name='internet -> guests';      On='edge_fw';   Src='80.71.158.0/24'; Dst='10.30.10.0/24' }
  @{ Name='internet -> devices';     On='edge_fw';   Src='80.71.158.0/24'; Dst='10.30.20.0/24' }
  @{ Name='internet -> applications';On='edge_fw';   Src='80.71.158.0/24'; Dst='10.40.10.0/24' }
  @{ Name='internet -> database';    On='edge_fw';   Src='80.71.158.0/24'; Dst='10.40.20.0/24' }
  @{ Name='internet -> identity';    On='edge_fw';   Src='80.71.158.0/24'; Dst='10.40.30.0/24' }
  @{ Name='internet -> backend';     On='edge_fw';   Src='80.71.158.0/24'; Dst='172.16.20.0/24' }
  @{ Name='internet -> branch';      On='branch_fw'; Src='80.71.158.0/24'; Dst='10.70.10.0/24' }
)

# ---- helpers ---------------------------------------------------------------
function Test-Reachable {
    param([string]$From, [string]$To)
    $out = kathara exec $From -- ping -c $PingCount -W $PingTimeout $To 2>&1 | Out-String
    return [bool]($out -match 'bytes from')
}
$ChainCache = @{}
function Get-Chain {
    param([string]$Fw)
    if (-not $ChainCache.ContainsKey($Fw)) {
        $ChainCache[$Fw] = ((kathara exec $Fw -- iptables -S FORWARD 2>&1) | Out-String)
    }
    return $ChainCache[$Fw]
}
function Test-RulePresent {
    param([string]$Fw, [string]$Src, [string]$Dst)
    foreach ($ln in ((Get-Chain -Fw $Fw) -split "`n")) {
        if ($ln -match '-j DROP' -and
            $ln -match ('-s\s+' + [regex]::Escape($Src)) -and
            $ln -match ('-d\s+' + [regex]::Escape($Dst))) { return $true }
    }
    return $false
}
function Get-DropCounter {
    param([string]$Fw, [string]$Src, [string]$Dst)
    $lines = kathara exec $Fw -- iptables -L FORWARD -n -v 2>&1
    $hit = $lines | Where-Object { $_ -match [regex]::Escape($Src) -and $_ -match [regex]::Escape($Dst) } |
           Select-Object -First 1
    if ($hit) { return ($hit.Trim() -split '\s+')[0] }
    return $null
}

# ---- build the full matrix (12 sources x (12 zones + Internet)) -------------
$Dests = $Zones + $Internet
$Matrix = @()
foreach ($s in $Zones) {
    foreach ($d in $Dests) {
        if ($s.Net -eq $d.Net) { continue }
        $key = "$($s.Net)->$($d.Net)"
        if ($d.Net -eq '172.16.20.0/24' -and $s.Net -ne '172.16.10.0/24') {
            # DEST backend, src not frontend: no route TO the backend.
            # Reachable ONLY from Frontend; unreachable from every internal zone
            # BY CONSTRUCTION (no route).
            $exp = 'UNREACH'; $fw = $null
        }
        elseif ($Deny.ContainsKey($key)) { $exp = 'FAIL'; $fw = $Deny[$key] }
        elseif ($s.Net -eq '172.16.20.0/24' -and $d.Net -ne '172.16.10.0/24') {
            # SRC backend, dest not frontend, NOT policy-denied: the ONLY such cell
            # left is Backend -> Security (one-way syslog is allowed, but the reply
            # is black-holed since the backend has no return route). Unreachable BY
            # CONSTRUCTION, NOT an ACL, so no drop counter is expected. (Guests/
            # Devices/Branch are now explicit denies hspl60-62 and hit $Deny above.)
            $exp = 'UNREACH'; $fw = $null
        }
        else                             { $exp = 'PASS'; $fw = $null }
        $Matrix += @{ Src = $s; Dst = $d; Expect = $exp; Fw = $fw }
    }
}

# ---- intent grid ------------------------------------------------------------
Write-Host ""
Write-Host "  Intended policy matrix  (A = allow, D = deny, x = unreachable by construction)"
$hdr = "                 " + (($Dests | ForEach-Object { '{0,-4}' -f $_.Code }) -join '')
Write-Host $hdr -ForegroundColor Cyan
foreach ($s in $Zones) {
    $row = "  {0,-15}" -f $s.Z
    foreach ($d in $Dests) {
        if ($s.Net -eq $d.Net) { $row += '{0,-4}' -f '-'; continue }
        if ($d.Net -eq '172.16.20.0/24' -and $s.Net -ne '172.16.10.0/24') { $row += '{0,-4}' -f 'x'; continue }
        if ($s.Net -eq '172.16.20.0/24' -and $d.Net -ne '172.16.10.0/24' -and
            -not $Deny.ContainsKey("$($s.Net)->$($d.Net)")) { $row += '{0,-4}' -f 'x'; continue }
        $cell = if ($Deny.ContainsKey("$($s.Net)->$($d.Net)")) { 'D' } else { 'A' }
        $row += '{0,-4}' -f $cell
    }
    Write-Host $row
}
# 13th row: Internet as a SOURCE. Allowed only to the published Frontend (VIP);
# denied/unreachable to everything else.
$irow = "  {0,-15}" -f 'internet'
foreach ($d in $Dests) {
    if ($d.Net -eq '80.71.158.0/24') { $irow += '{0,-4}' -f '-'; continue }
    $cell = if ($d.Net -eq '172.16.10.0/24') { 'A' } else { 'D' }
    $irow += '{0,-4}' -f $cell
}
Write-Host $irow
Write-Host "  (x = DMZ_Backend isolated by construction: no route TO it and no return route FROM it - only Frontend <-> Backend works)"
Write-Host "  (internet row: A only at the published frontend VIP; every internal/backend cell is blocked at the perimeter - no route + no DNAT)"

# ---- run reach matrix -------------------------------------------------------
Write-Host ""
Write-Host ("  Live verification - {0} matrix pairs + {1} internet-sourced live + {2} internet-sourced (presence)" -f $Matrix.Count, (1 + ($Zones | Where-Object { $_.Net -ne '172.16.10.0/24' }).Count), $Present.Count)
Write-Host ("  " + ('-' * 72))

$passed = 0; $failed = 0; $lastSrc = ''
foreach ($m in $Matrix) {
    if ($m.Src.Z -ne $lastSrc) {
        Write-Host ("  -- from {0} --" -f $m.Src.Z) -ForegroundColor DarkCyan
        $lastSrc = $m.Src.Z
    }

    $reachable = Test-Reachable -From $m.Src.Dev -To $m.Dst.Ip

    if ($m.Expect -eq 'UNREACH') {
        $ok = (-not $reachable)
        if ($ok) { $passed++ } else { $failed++ }
        $tag   = if ($ok) { '[ OK ]    ' } else { '[MISMATCH]' }
        $color = if ($ok) { 'Green' } else { 'Red' }
        $obs   = if ($reachable) { 'REACHABLE' } else { 'unreachable' }
        Write-Host ("  {0} {1,-13} -> {2,-13} expected=UNREACH observed={3}" -f `
                    $tag, $m.Src.Z, $m.Dst.Z, $obs) -ForegroundColor $color
        if ($ok) {
            $why = if ($m.Src.Net -eq '172.16.20.0/24') {
                       'backend has no return route (isolated by construction)'
                   } else {
                       'no route to backend (isolated by construction)'
                   }
            Write-Host ("                 -> $why") -ForegroundColor DarkGray
        } else {
            Write-Host ("                 -> WARNING: backend reachable on $($m.Src.Z) <-> $($m.Dst.Z) - route to 172.16.20.0/24 leaked into the internal IGP, structural isolation broken") -ForegroundColor Yellow
        }
        continue
    }

    $observed  = if ($reachable) { 'PASS' } else { 'FAIL' }
    $ok        = ($observed -eq $m.Expect)
    if ($ok) { $passed++ } else { $failed++ }

    $tag   = if ($ok) { '[ OK ]    ' } else { '[MISMATCH]' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1,-13} -> {2,-13} expected={3} observed={4}" -f `
                $tag, $m.Src.Z, $m.Dst.Z, $m.Expect, $observed) -ForegroundColor $color

    if ($m.Expect -eq 'FAIL' -and $m.Fw) {
        $dstNet = if ($m.Fw -eq 'admin_fw') { '0.0.0.0/0' } else { $m.Dst.Net }
        $pkts   = Get-DropCounter -Fw $m.Fw -Src $m.Src.Net -Dst $dstNet
        if ($null -ne $pkts) {
            $note = if ([int]$pkts -gt 0) { "dropped $pkts pkt(s) on $($m.Fw)" }
                    else { "rule present on $($m.Fw) but counter=0 (no traffic hit it yet)" }
            Write-Host ("                 -> {0}" -f $note) -ForegroundColor DarkGray
        } else {
            Write-Host ("                 -> WARNING: no matching DROP rule on $($m.Fw)") -ForegroundColor Yellow
        }
    }
}

# ---- run Internet-sourced reachability (perimeter ingress; the 13th row) -----
# Internet hosts have NO route to RFC1918 and only tcp/80,443 is DNATed to the
# WAF, so each cell is tested with the RIGHT instrument, not a naive ping:
#   * Internet -> Frontend : the PUBLISHED service. Tested as HTTP to the public
#       VIP (a ping to the WAF's private IP would wrongly read 'unreachable').
#       A 200 whose body comes from the backend proves the whole sanctioned
#       ingress chain Internet -> DNAT -> WAF -> Backend in one shot.
#   * Internet -> internal/backend : expected UNREACHABLE at the perimeter
#       (no route + no DNAT). Live regression guard - if one ever answers, the
#       perimeter (routing/NAT) has leaked. The matching defense-in-depth DROP
#       being LOADED is asserted separately in the presence block below.
$IngressSrc = 'benign_web'    # legitimate outside client (re-lab/web: has curl + ping)
$Vip        = '203.0.113.2'   # edge_fw public IP; DNAT 80/443 -> WAF
Write-Host ("  -- from internet (perimeter ingress) --") -ForegroundColor DarkCyan

# Positive: the published frontend must serve the backend through the WAF.
$body  = (kathara exec $IngressSrc -- curl -s --max-time 6 "http://$Vip/" 2>&1 | Out-String)
$okFE  = ($body -match 'web_backend')
if ($okFE) { $passed++ } else { $failed++ }
$tag   = if ($okFE) { '[ OK ]    ' } else { '[MISMATCH]' }
$color = if ($okFE) { 'Green' } else { 'Red' }
$obs   = if ($okFE) { 'served-by-backend (HTTP 200 via WAF)' } else { 'NOT served' }
Write-Host ("  {0} {1,-13} -> {2,-13} expected=REACHABLE observed={3}" -f $tag, 'internet', 'frontend', $obs) -ForegroundColor $color
if ($okFE) {
    Write-Host ("                 -> published VIP $Vip -> DNAT -> WAF -> backend OK (sole sanctioned ingress)") -ForegroundColor DarkGray
} else {
    Write-Host ("                 -> WARNING: public web path broken (DNAT, WAF proxy, or backend down)") -ForegroundColor Yellow
}

# Negative: an outside host must reach NO internal/backend zone.
foreach ($z in ($Zones | Where-Object { $_.Net -ne '172.16.10.0/24' })) {
    $reach = Test-Reachable -From $IngressSrc -To $z.Ip
    $ok    = (-not $reach)
    if ($ok) { $passed++ } else { $failed++ }
    $tag   = if ($ok) { '[ OK ]    ' } else { '[MISMATCH]' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    $obs   = if ($reach) { 'REACHABLE' } else { 'unreachable' }
    Write-Host ("  {0} {1,-13} -> {2,-13} expected=UNREACH observed={3}" -f $tag, 'internet', $z.Z, $obs) -ForegroundColor $color
    if ($ok) {
        Write-Host ("                 -> blocked at perimeter (no route to RFC1918 + no inbound DNAT)") -ForegroundColor DarkGray
    } else {
        Write-Host ("                 -> WARNING: internet reached $($z.Z) - PERIMETER LEAK (ISP route or DNAT widened); deny ACL bypassed") -ForegroundColor Yellow
    }
}
$IngressCount = 1 + ($Zones | Where-Object { $_.Net -ne '172.16.10.0/24' }).Count

# ---- run Internet-sourced presence block ------------------------------------
Write-Host ("  -- Internet-sourced denies (presence) --") -ForegroundColor DarkCyan
foreach ($p in $Present) {
    $found    = Test-RulePresent -Fw $p.On -Src $p.Src -Dst $p.Dst
    $observed = if ($found) { 'PRESENT' } else { 'ABSENT' }
    if ($found) { $passed++ } else { $failed++ }
    $tag   = if ($found) { '[ OK ]    ' } else { '[MISMATCH]' }
    $color = if ($found) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1,-22} rule {2} on {3}" -f $tag, $p.Name, $observed, $p.On) -ForegroundColor $color
}

# ---- tally ------------------------------------------------------------------
$total = $Matrix.Count + $IngressCount + $Present.Count
Write-Host ("  " + ('-' * 72))
$summaryColor = if ($failed -eq 0) { 'Green' } else { 'Red' }
Write-Host ("  Result: {0} OK, {1} mismatched  (of {2}: {3} live matrix pairs + {4} internet-sourced live + {5} presence)" -f `
            $passed, $failed, $total, $Matrix.Count, $IngressCount, $Present.Count) -ForegroundColor $summaryColor
Write-Host ""
if ($failed -ne 0) { exit 1 }