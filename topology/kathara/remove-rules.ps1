<#
  remove-rules.ps1
  Reverse of apply-rules.ps1 for the refinement-engine Kathara lab.

  Reads shared/removals.json (written by the engine container's revalidate pass)
  and removes each flagged rule from its lab container, then acks it. Failed
  removals are kept for the next pass.

  Removal is by the rule_id tag every engine-pushed rule carries:
    iptables : iptables-save | grep -v 'comment "<rid>"' | iptables-restore
    squid    : sed -i '/# >>> rid=<rid>/,/# <<< rid=<rid>/d' /etc/squid/re-rules.conf      && squid -k reconfigure
    waf      : sed -i '/# >>> rid=<rid>/,/# <<< rid=<rid>/d' /etc/modsecurity/re-rules.conf && apachectl -k graceful

  Run from the lab directory after `kathara lstart`:
      .\remove-rules.ps1            # watch continuously (Ctrl+C to stop)
      .\remove-rules.ps1 -Once      # process the current removals.json, then exit
#>

param(
    [switch]$Once,
    [int]$IntervalSeconds = 5
)

$ErrorActionPreference = 'Stop'
$Shared    = Join-Path (Get-Location) 'shared'
$LogFile   = Join-Path $Shared 'apply.log'
$Removals  = Join-Path $Shared 'removals.json'
$MapFile   = Join-Path $Shared 'device_map.json'

$Map     = Get-Content -LiteralPath $MapFile -Raw | ConvertFrom-Json
$DevMap  = $Map.devices       # engine name -> lab container
$TypeMap = $Map.nsf_type      # engine nsf  -> control type

function Write-Log {
    param([string]$Msg)
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Msg
    Add-Content -LiteralPath $LogFile -Value $line
    Write-Host $line
}

# reliable JSON-object key lookup by a string variable
function Get-MapValue {
    param($Obj, [string]$Key)
    $p = $Obj.psobject.Properties[$Key]
    if ($p) { return [string]$p.Value } else { return $null }
}

function Get-RemovalScript {
    param([string]$Type, [string]$Rid)
    switch ($Type) {
        'iptables' { return "iptables-save | grep -v 'comment `"$Rid`"' | iptables-restore && echo __RM_OK__" }
        'squid'    { return "sed -i '/# >>> rid=$Rid/,/# <<< rid=$Rid/d' /etc/squid/re-rules.conf && squid -k reconfigure && echo __RM_OK__" }
        'waf'      { return "sed -i '/# >>> rid=$Rid/,/# <<< rid=$Rid/d' /etc/modsecurity/re-rules.conf && apachectl -k graceful && echo __RM_OK__" }
    }
}

function Process-Removals {
    if (-not (Test-Path $Removals)) { return }
    $raw = (Get-Content -LiteralPath $Removals -Raw).Trim()
    if (-not $raw) { return }

    # force a flat array of entry objects (handles single-element / nested cases)
    $entries = @($raw | ConvertFrom-Json)
    if ($entries.Count -eq 1 -and $entries[0] -is [System.Array]) { $entries = @($entries[0]) }
    if ($entries.Count -eq 0) { return }

    $kept = @()
    foreach ($e in $entries) {
        $rid    = [string]$e.rule_id
        $dev    = [string]$e.device
        $nsf    = [string]$e.nsf
        $val    = [string]$e.value
        $sig    = [string]$e.signal
        $labDev = Get-MapValue $DevMap  $dev
        $type   = Get-MapValue $TypeMap $nsf

        if (-not $labDev -or -not $type) {
            Write-Log ("SKIP     no map for {0}/{1} ({2})" -f $dev, $nsf, $rid)
            $kept += $e; continue
        }

        $stageDir = Join-Path (Join-Path $Shared '.staging') $labDev
        if (-not (Test-Path $stageDir)) { New-Item -ItemType Directory -Path $stageDir -Force | Out-Null }
        $h         = [Math]::Abs($rid.GetHashCode()).ToString('x')
        $stageHost = Join-Path $stageDir ("rm_$h.sh")
        [System.IO.File]::WriteAllText($stageHost, (Get-RemovalScript -Type $type -Rid $rid) + "`n")
        $stageCont = "/shared/.staging/$labDev/rm_$h.sh"

        $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $out = (kathara exec $labDev -- sh "$stageCont" 2>&1 | Out-String)
        $ErrorActionPreference = $prevEAP

        if ($out -match '__RM_OK__') {
            Remove-Item -LiteralPath $stageHost -Force -ErrorAction SilentlyContinue
            Write-Log ("REMOVED  {0,-13} {1}  ({2}, {3})" -f $labDev, $val, $sig, $type)
        }
        else {
            $err = (($out -join ' ') -replace '\s+', ' ').Trim()
            Write-Log ("REMFAIL  {0,-13} {1}  -> {2}" -f $labDev, $rid, $err)
            $kept += $e
        }
    }

    $json = if ($kept.Count -gt 0) { ConvertTo-Json -InputObject @($kept) -Depth 6 } else { '[]' }
    [System.IO.File]::WriteAllText($Removals, $json)
}

Write-Log ('remover start (mode: {0})' -f $(if ($Once) { 'once' } else { 'continuous' }))
do {
    Process-Removals
    if (-not $Once) { Start-Sleep -Seconds $IntervalSeconds }
} while (-not $Once)