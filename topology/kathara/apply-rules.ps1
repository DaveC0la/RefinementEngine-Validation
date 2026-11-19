<#
  apply-rules.ps1
  Incremental rule applier for the refinement-engine Kathara lab.

  The Refinement Engine drops a file into  shared/outbox/<device>/*.rules
  (visible inside containers at /shared/outbox/<device>/). This watcher applies
  it INCREMENTALLY -- on top of what is already loaded -- to the matching
  container, then archives it.

    iptables firewalls : iptables-restore --noflush  (append, atomic)
    WAF (Apache+ModSec): append SecRules to /etc/modsecurity/re-rules.conf,
                         then `apachectl -k graceful`
    Squid proxies      : append acl + http_access rules to
                         /etc/squid/re-rules.conf, then `squid -k reconfigure`

  For WAF and Squid the file is appended only if the resulting config passes a
  syntax check; otherwise it is rolled back (the include file is left clean).

  Run from the lab directory (the folder with lab.conf), after `kathara lstart`:
      .\apply-rules.ps1            # watch continuously (Ctrl+C to stop)
      .\apply-rules.ps1 -Once      # process whatever is queued, then exit

  File the engine drops in outbox/<device>/ (name it *.rules):
    iptables -> raw `iptables -A ...` lines, or an iptables-restore fragment
    WAF      -> SecRule directives (unique ids!)
    Squid    -> one destination domain per line (leading dot = subdomains)
  Write to a temp name and rename to *.rules so a half-written file is not read.
#>

param(
    [switch]$Once,
    [int]$IntervalSeconds = 5
)

$ErrorActionPreference = 'Stop'
$Shared  = Join-Path (Get-Location) 'shared'
$LogFile = Join-Path $Shared 'apply.log'

# device -> control type
$Controls = @(
    @{ Name = 'edge_fw';      Type = 'iptables' }
    @{ Name = 'admin_fw';     Type = 'iptables' }
    @{ Name = 'guest_fw';     Type = 'iptables' }
    @{ Name = 'corp_fw';      Type = 'iptables' }
    @{ Name = 'dc_fw';        Type = 'iptables' }
    @{ Name = 'branch_fw';    Type = 'iptables' }
    @{ Name = 'waf';          Type = 'waf' }
    @{ Name = 'egress_proxy'; Type = 'squid' }
    @{ Name = 'branch_proxy'; Type = 'squid' }
)

function Write-Log {
    param([string]$Msg)
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Msg
    Add-Content -LiteralPath $LogFile -Value $line
    Write-Host $line
}

function Ensure-Dirs {
    param([string]$Name)
    foreach ($sub in 'outbox', 'applied', 'failed', '.staging') {
        $p = Join-Path (Join-Path $Shared $sub) $Name
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
}

function Get-ForwardPolicy {
    param([string]$Name)
    $s = kathara exec $Name -- iptables -S FORWARD 2>$null
    $m = ($s | Select-String -Pattern '^-P FORWARD (\w+)')
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return 'ACCEPT'
}

function Stage-Content {
    # Returns the LF text to stage for this control type.
    param([string[]]$Content, [string]$Type, [string]$Policy)
    if ($Type -eq 'iptables') {
        $useful = @($Content | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' })
        if ($useful.Count -gt 0 -and $useful[0].TrimStart().StartsWith('*')) {
            return ($Content -join "`n")                  # already a restore fragment
        }
        $rules = $useful | ForEach-Object { ($_ -replace '^\s*iptables\s+', '').Trim() }
        return (@('*filter', ":FORWARD $Policy [0:0]") + $rules + @('COMMIT')) -join "`n"
    }
    # WAF/Squid: the translator's per-device banner is outside every rid block.
    # If installed, the rid-based remover cannot remove it, breaking exact rollback.
    # Keep the original archive unchanged; deploy only ownership-delimited content.
    # Preserve ALL other comments and rule text verbatim.
    if ($Type -eq 'waf' -or $Type -eq 'squid') {
        $stageLines = @($Content | Where-Object {
            $_ -notmatch '^# RefinementEngine -> [a-z_]+ \(waf|squid\); [0-9]+ rule\(s\)$'
        })
        return ($stageLines -join "`n")
    }
    return ($Content -join "`n")
}

function Get-ApplyCommand {
    # The sh -c command run inside the container. Prints __APPLY_OK__ only on success.
    param([string]$Type, [string]$StageCont)
    switch ($Type) {
        'iptables' {
            return "iptables-restore --noflush < '$StageCont' && echo __APPLY_OK__"
        }
        'waf' {
            $t = '/etc/modsecurity/re-rules.conf'
            return "cp $t $t.re-bak 2>/dev/null; cat '$StageCont' >> $t; " +
                   "if apachectl configtest >/dev/null 2>&1; then apachectl -k graceful && echo __APPLY_OK__; " +
                   "else cp $t.re-bak $t; fi"
        }
        'squid' {
            $t = '/etc/squid/re-rules.conf'
            return "cp $t $t.re-bak 2>/dev/null; cat '$StageCont' >> $t; " +
                   "if squid -k parse >/dev/null 2>&1; then squid -k reconfigure && echo __APPLY_OK__; " +
                   "else cp $t.re-bak $t; fi"
        }
    }
}

function Process-Control {
    param($Ctl)
    Ensure-Dirs -Name $Ctl.Name
    $outbox = Join-Path (Join-Path $Shared 'outbox') $Ctl.Name
    $files = Get-ChildItem -LiteralPath $outbox -Filter '*.rules' -File -ErrorAction SilentlyContinue | Sort-Object Name
    foreach ($f in $files) {
        $content = Get-Content -LiteralPath $f.FullName
        $policy  = if ($Ctl.Type -eq 'iptables') { Get-ForwardPolicy -Name $Ctl.Name } else { 'ACCEPT' }
        $staged  = Stage-Content -Content $content -Type $Ctl.Type -Policy $policy
        $count   = @($content | Where-Object {
            $_ -match '\S' -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*\*' -and
            $_ -notmatch '^\s*:' -and $_ -notmatch '^\s*COMMIT'
        }).Count

        # stage the snippet where the container can read it (LF endings, no CRLF)
        $stageHost = Join-Path (Join-Path (Join-Path $Shared '.staging') $Ctl.Name) ($f.BaseName + '.staged')
        [System.IO.File]::WriteAllText($stageHost, $staged + "`n")
        $stageCont = "/shared/.staging/$($Ctl.Name)/$($f.BaseName).staged"

        $cmd = Get-ApplyCommand -Type $Ctl.Type -StageCont $stageCont
        # Run the native command with stderr merged into stdout. Use a local
        # 'Continue' so harmless stderr (e.g. Apache's AH00558 FQDN warning)
        # is captured as text instead of raising a terminating NativeCommandError.
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $out = (kathara exec $Ctl.Name -- sh -c "$cmd" 2>&1 | Out-String)
        $ErrorActionPreference = $prevEAP
        $ok  = ($out -match '__APPLY_OK__')

        if ($ok) {
            Move-Item -LiteralPath $f.FullName -Destination (Join-Path (Join-Path $Shared 'applied') $Ctl.Name) -Force
            Remove-Item -LiteralPath $stageHost -Force -ErrorAction SilentlyContinue
            Write-Log ('APPLIED  {0,-13} {1}  (+{2} item(s), {3})' -f $Ctl.Name, $f.Name, $count, $Ctl.Type)
        }
        else {
            Move-Item -LiteralPath $f.FullName -Destination (Join-Path (Join-Path $Shared 'failed') $Ctl.Name) -Force
            $err = (($out -join ' ') -replace '\s+', ' ').Trim()
            Write-Log ('FAILED   {0,-13} {1}  -> {2}' -f $Ctl.Name, $f.Name, $err)
        }
    }
}

foreach ($c in $Controls) { Ensure-Dirs -Name $c.Name }
Write-Log ('watcher start (mode: {0}; controls: {1})' -f $(if ($Once) { 'once' } else { 'continuous' }), ($Controls.Name -join ','))

do {
    foreach ($c in $Controls) { Process-Control -Ctl $c }
    if (-not $Once) { Start-Sleep -Seconds $IntervalSeconds }
} while (-not $Once)
