#Requires -Version 5.1
# Diagnosis signals a device alone can measure (docs/27 sections 2.2 and 3.8), sent as TelemetryV1.diag:
#
#   crash  unexpected terminations of DoSvc in 7 days (System log, Service Control Manager 7031 / 7034)
#   up     mean hours powered on per day over 7 days (Kernel-General 12 / 13); an upper bound, sleep is not subtracted
#   flap   how often a connectivity check changed result in 7 days, for checks that changed at least twice
#
# ADR-0002 / ADR-0004: these are measurements with a documented window and unit, never a verdict. Thresholds and
# findings live in packages/analysis. The event-log reads are optional and bounded (5 s together), cached for 24 hours in
# the state file (so an hourly report costs one read a day), and a read that fails is named in notCollected
# (`diag.crash`, `diag.up`), never reported as healthy.
#
# The flap counters live in the state file too: one bucket per check per UTC day, the last 7 days kept, at most 64 checks.
# A change is a flap (Test-DDConnectivityFlap) when its `result|code` differs from the one last committed
# (Get-DDConnectivityComposite) and either side is `fail`, or the code changed within one non-pass result. pass <-> warn is
# not a flap, and the idle-state warns of p2p-listener, p2p-inbound and dosvc-running are read as pass: DoSvc stops when
# idle, which is normal (Microsoft FAQ, see $DDListenerReasons in Health.ps1). A check seen for the first time is not a change. They are committed with the connectivity state, after a report is
# accepted (Update-DDStateAfterTelemetry / Update-DDStateAfterInventory).

Set-StrictMode -Version Latest

$script:DDDiagCacheHours = 24
$script:DDDiagWindowDays = 7
$script:DDDiagBoundSec = 5
$script:DDFlapWindowDays = 7
$script:DDFlapMaxChecks = 64
$script:DDFlapBucketCap = 99
# Checks whose `warn` only says DoSvc is idle (stopped, or not listening): healthy by Microsoft's FAQ, so never a flap.
$script:DDFlapIdleWarnChecks = @('p2p-listener', 'p2p-inbound', 'dosvc-running')

# ---- state validation ------------------------------------------------------------------------------------------

function ConvertTo-DDValidFlapCounts {
    # Keep the buckets that have the right shape, drop the rest; never throws. check -> (yyyyMMdd -> count).
    [CmdletBinding()]
    param($Candidate)

    $out = [ordered]@{}
    if ($Candidate -isnot [System.Collections.IDictionary]) { return $out }
    foreach ($k in $Candidate.Keys) {
        $name = [string]$k
        if ($name -cnotmatch '^[a-z0-9:-]{1,40}$' -or $Candidate[$k] -isnot [System.Collections.IDictionary]) { continue }
        $days = [ordered]@{}
        foreach ($d in $Candidate[$k].Keys) {
            $n = 0
            if ([string]$d -match '^[0-9]{8}$' -and [int]::TryParse([string]$Candidate[$k][$d], [ref]$n) -and $n -ge 1) { $days[[string]$d] = [math]::Min($script:DDFlapBucketCap, $n) }
        }
        if ($days.Count -gt 0) { $out[$name] = $days }
        if ($out.Count -ge $script:DDFlapMaxChecks) { break }
    }
    $out
}

function ConvertTo-DDValidDiagCache {
    # The 24-hour cache of the signals: { at; crash; up; nc }. $null when it does not have exactly that shape.
    [CmdletBinding()]
    param($Candidate)

    if ($Candidate -isnot [System.Collections.IDictionary]) { return $null }
    if ($Candidate['at'] -isnot [string] -or $Candidate['at'] -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { return $null }
    $c = [ordered]@{ at = $Candidate['at']; crash = $null; up = $null; nc = @() }
    $n = 0
    if ($null -ne $Candidate['crash'] -and [int]::TryParse([string]$Candidate['crash'], [ref]$n) -and $n -ge 0 -and $n -le 99) { $c['crash'] = $n }
    if ($null -ne $Candidate['up'] -and [int]::TryParse([string]$Candidate['up'], [ref]$n) -and $n -ge 0 -and $n -le 24) { $c['up'] = $n }
    $nc = New-Object 'System.Collections.Generic.List[object]'
    if ($Candidate['nc'] -is [System.Collections.IEnumerable] -and $Candidate['nc'] -isnot [string]) {
        foreach ($e in $Candidate['nc']) {
            if ($e -is [System.Collections.IDictionary] -and [string]$e['field'] -in 'diag.crash', 'diag.up' -and
                [string]$e['reason'] -in 'unsupported-os', 'insufficient-rights', 'cmdlet-missing', 'timeout', 'skipped-by-flag', 'error') {
                $r = [ordered]@{ field = [string]$e['field']; reason = [string]$e['reason'] }
                if ($e['detail'] -is [string] -and $e['detail']) { $r['detail'] = ([string]$e['detail']).Substring(0, [math]::Min(200, ([string]$e['detail']).Length)) }
                $nc.Add($r)
            }
        }
    }
    $c['nc'] = $nc.ToArray()
    $c
}

# ---- the event-log signals -------------------------------------------------------------------------------------

function Get-DDDiagSignals {
    <#
    .SYNOPSIS
        The DoSvc crash count and the mean powered-on hours, from the cache in the state when it is younger than 24 hours,
        else read from the System log (bounded to 5 s together) and cached.
    .DESCRIPTION
        Never throws: a signal that could not be read is $null and named in NotCollected (diag.crash / diag.up), with the
        reason. The result is cached either way, so a slow or disabled event log costs at most one 5 s bound a day. The cache
        lives in $State['diag']; Invoke-DoctorDOCollector saves the state whether the send succeeded or not.
    .OUTPUTS
        PSCustomObject: Crash (int or $null), Up (int hours 0..24 or $null), NotCollected (records), Cached (bool).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)][datetime] $Now,
        [int] $BoundSec = $script:DDDiagBoundSec,
        [int] $CacheHours = $script:DDDiagCacheHours,
        [switch] $Refresh
    )

    $cache = $null
    if ($State -is [System.Collections.IDictionary] -and $State.Contains('diag')) { $cache = ConvertTo-DDValidDiagCache -Candidate $State['diag'] }
    if ($null -ne $cache -and -not $Refresh) {
        $at = [datetime]::MinValue
        if ([datetime]::TryParse($cache['at'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at)) {
            $age = $Now.ToUniversalTime() - $at
            if ($age -ge [timespan]::FromMinutes(-5) -and $age -lt [timespan]::FromHours($CacheHours)) {
                return [pscustomobject]@{ Crash = $cache['crash']; Up = $cache['up']; NotCollected = @($cache['nc']); Cached = $true }
            }
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $left = { $r = $BoundSec - $sw.Elapsed.TotalSeconds; if ($r -le 0) { throw [System.TimeoutException]::new("The $BoundSec s bound for the diagnosis reads is used up.") }; [int][math]::Ceiling($r) }
    $nc = New-Object 'System.Collections.Generic.List[object]'
    $note = {
        param($field, $err)
        $d = Protect-DDLogText -Text ([string]$err.Exception.Message)
        $nc.Add([ordered]@{ field = $field; reason = (Get-DDNotCollectedReason -ErrorRecord $err); detail = $d.Substring(0, [math]::Min(200, $d.Length)) })
    }

    $crash = $null
    try {
        $name = Get-DDDoSvcDisplayName
        if ([string]::IsNullOrEmpty($name)) { throw 'The DoSvc service was not found, so its crashes cannot be matched.' }
        $events = @(Get-DDServiceTerminationEventsRaw -Days $script:DDDiagWindowDays -TimeoutSec (& $left) -ServiceDisplayName $name)
        $crash = [int](Get-DDDoSvcCrashCount -Events $events -ServiceDisplayName $name -Now $Now -Days $script:DDDiagWindowDays)
    } catch { & $note 'diag.crash' $_ }

    $up = $null
    try {
        $events = @(Get-DDKernelGeneralEventsRaw -Days $script:DDDiagWindowDays -TimeoutSec (& $left))
        # The earliest evidence the device existed decides whether it is new (docs/08): without it the mean is over the full window.
        $historyStart = Get-DDDeviceHistoryStartRaw -TimeoutSec (& $left)
        $hours = Get-DDPoweredOnHours -Events $events -Now $Now -Days $script:DDDiagWindowDays -HistoryStart $historyStart
        if ($null -eq $hours) {
            # Under 24 hours of history (a new device): there is no mean to report, and 0 would read as "rarely on".
            # The reason enum has no "too little history" (ROOT-CHANGES.md), so it is 'error' with the cause in the detail.
            $nc.Add([ordered]@{ field = 'diag.up'; reason = 'error'; detail = 'Less than 24 hours of System log history for Kernel-General 12 and 13, so no mean was computed' })
        } else {
            $up = [int][math]::Min([double]24, [math]::Max([double]0, [math]::Round([double]$hours, [System.MidpointRounding]::AwayFromZero)))
        }
    } catch { & $note 'diag.up' $_ }

    if ($State -is [System.Collections.IDictionary]) {
        $State['diag'] = [ordered]@{ at = (Format-DDIso -Value $Now); crash = $crash; up = $up; nc = $nc.ToArray() }
    }
    [pscustomobject]@{ Crash = $crash; Up = $up; NotCollected = $nc.ToArray(); Cached = $false }
}

# ---- flap counters ---------------------------------------------------------------------------------------------

function Test-DDConnectivityFlap {
    <#
    .SYNOPSIS
        Whether a check's move from the stored `result|code` to this run's result counts as a flap (docs/08).
    .DESCRIPTION
        Counts: any transition that involves `fail` (pass to fail, fail to pass or warn, fail to a different fail code), and
        a change of `code` within the same warn result (warn|a to warn|b; `not-collected` and `not-applicable` are not results the device
        is in, so a code change within them never counts). Does not count: pass <-> warn, anything to or
        from not-applicable / not-collected without a fail, and an unchanged state. The idle-state warns of p2p-listener,
        p2p-inbound and dosvc-running are read as pass first (a stopped DoSvc is normal). A stored value without `|` is the
        bare result an older collector kept: the code it had is unknown, so it never counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $CheckId,
        [AllowNull()][AllowEmptyString()][string] $Previous,
        [Parameter(Mandatory)] $Result
    )

    if ([string]::IsNullOrEmpty($Previous) -or $Previous.IndexOf('|') -lt 0) { return $false }
    $cut = $Previous.IndexOf('|')
    $pr = $Previous.Substring(0, $cut); $pc = $Previous.Substring($cut + 1)
    $cr = [string]$Result['result']; $cc = ''
    if ($null -ne $Result['code']) { $cc = [string]$Result['code'] }
    if ($script:DDFlapIdleWarnChecks -contains $CheckId) {
        if ($pr -ceq 'warn') { $pr = 'pass'; $pc = '' }
        if ($cr -ceq 'warn') { $cr = 'pass'; $cc = '' }
    }
    if ($pr -ceq $cr -and $pc -ceq $cc) { return $false }
    if ($pr -ceq 'fail' -or $cr -ceq 'fail') { return $true }
    # not-collected and not-applicable are not results the device is in (a read that failed, a check that does not apply), so a
    # code change between or within them says nothing about the device; only pass and warn have a code that can change.
    if (@('not-collected', 'not-applicable') -ccontains $pr -or @('not-collected', 'not-applicable') -ccontains $cr) { return $false }
    ($pr -ceq $cr) -and ($pr -cne 'pass')
}

function Merge-DDFlapCounts {
    <#
    .SYNOPSIS
        The flap counters after this run: the old counters with buckets older than 7 days dropped, plus one change for each
        check whose move from -PreviousConnectivity (Get-DDConnectivityState) is a flap (Test-DDConnectivityFlap). Pure: returns a new
        dictionary and leaves its inputs alone. Applying it twice for the same run adds nothing the second time once the
        previous state has been updated, so it can run at both commit points.
    .PARAMETER Counts
        check -> (yyyyMMdd -> count), as kept in the state.
    .PARAMETER Rows
        This run's connectivity results.
    .PARAMETER PreviousConnectivity
        Key -> `result|code` last committed; $null or empty (a first run, or a lost state) counts nothing.
    #>
    [CmdletBinding()]
    param(
        $Counts,
        [AllowEmptyCollection()] $Rows = @(),
        $PreviousConnectivity,
        [Parameter(Mandatory)][datetime] $Now
    )

    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $today = $Now.ToUniversalTime().ToString('yyyyMMdd', $inv)
    $oldest = $Now.ToUniversalTime().AddDays(-($script:DDFlapWindowDays - 1)).ToString('yyyyMMdd', $inv)

    $out = [ordered]@{}
    $src = ConvertTo-DDValidFlapCounts -Candidate $Counts
    foreach ($check in $src.Keys) {
        $days = [ordered]@{}
        foreach ($d in $src[$check].Keys) { if ([string]::CompareOrdinal([string]$d, $oldest) -ge 0 -and [string]::CompareOrdinal([string]$d, $today) -le 0) { $days[[string]$d] = [int]$src[$check][$d] } }
        if ($days.Count -gt 0) { $out[$check] = $days }
    }

    if ($PreviousConnectivity -is [System.Collections.IDictionary] -and $PreviousConnectivity.Count -gt 0) {
        $changed = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($c in @($Rows)) {
            if ($null -eq $c) { continue }
            $k = Get-DDConnectivityKey -Result $c
            if (-not $PreviousConnectivity.Contains($k)) { continue }
            if (Test-DDConnectivityFlap -CheckId ([string]$c['checkId']) -Previous ([string]$PreviousConnectivity[$k]) -Result $c) { [void]$changed.Add([string]$c['checkId']) }
        }
        foreach ($check in $changed) {
            if ($check -cnotmatch '^[a-z0-9:-]{1,40}$') { continue }
            if (-not $out.Contains($check)) { $out[$check] = [ordered]@{} }
            $n = 0; if ($out[$check].Contains($today)) { $n = [int]$out[$check][$today] }
            $out[$check][$today] = [math]::Min($script:DDFlapBucketCap, $n + 1)
        }
    }

    if ($out.Count -gt $script:DDFlapMaxChecks) {
        # Keep the 64 checks that changed most, ties by name, so the file stays small whatever the matrix does.
        $rank = New-Object 'System.Collections.Generic.List[object]'
        foreach ($check in $out.Keys) { $t = 0; foreach ($d in $out[$check].Keys) { $t += [int]$out[$check][$d] }; $rank.Add([pscustomobject]@{ Name = [string]$check; Total = $t }) }
        $cmp = [System.Comparison[object]] { param($a, $b) if ($a.Total -ne $b.Total) { return ($b.Total - $a.Total) }; return [string]::CompareOrdinal($a.Name, $b.Name) }
        $rank.Sort($cmp)
        $kept = [ordered]@{}
        foreach ($r in ($rank | Select-Object -First $script:DDFlapMaxChecks)) { $kept[$r.Name] = $out[$r.Name] }
        $out = $kept
    }
    $out
}

function Get-DDFlapTotals {
    # check -> total changes over the buckets in the state (what diag.flap is chosen from).
    [CmdletBinding()]
    param($Counts)

    $t = [ordered]@{}
    $src = ConvertTo-DDValidFlapCounts -Candidate $Counts
    foreach ($check in $src.Keys) {
        $n = 0
        foreach ($d in $src[$check].Keys) { $n += [int]$src[$check][$d] }
        $t[$check] = $n
    }
    $t
}

function Update-DDFlapState {
    # Commit this run's changes to the state's flapCounts. Called before lastConnectivity is overwritten.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [AllowEmptyCollection()] $Rows = @(), [Parameter(Mandatory)][datetime] $Now)

    $State['flapCounts'] = Merge-DDFlapCounts -Counts $State['flapCounts'] -Rows $Rows -PreviousConnectivity $State['lastConnectivity'] -Now $Now
}

function New-DDDiagInput {
    <#
    .SYNOPSIS
        The `-Diag` argument of ConvertTo-DDTelemetry for one report: the cached or fresh signals plus the flap totals,
        counting this run's changes without committing them.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [AllowEmptyCollection()] $Connectivity = @(), [Parameter(Mandatory)][datetime] $Now)

    $signals = Get-DDDiagSignals -State $State -Now $Now
    $view = Merge-DDFlapCounts -Counts $State['flapCounts'] -Rows $Connectivity -PreviousConnectivity $State['lastConnectivity'] -Now $Now
    [ordered]@{ crash = $signals.Crash; up = $signals.Up; flap = (Get-DDFlapTotals -Counts $view); notCollected = @($signals.NotCollected) }
}
