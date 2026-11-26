#Requires -Version 5.1
# Persistent collector state (docs/08 "State the collector keeps"): sequence number, each job's, peer's and log connection's
# counters at the last accepted report (`counters`, at most 2,000 of each; Compact.ps1), last connectivity results
# (result|code), recently reported HRESULTs, last inventory hash, the per-device salt, the per-check flap counters (7 days, at
# most 64 checks), the 24-hour cache of the diagnosis signals (Diag.ps1) and the file IDs of the jobs already summarised into
# `sources` (at most 2,000; Compact.ps1).
# Stored in a protected file under ProgramData. Written atomically; read tolerantly. If the file is lost the next report
# is a full inventory and a baseline telemetry report: every result is sent once and no bytes are, so what the cache
# already held is never counted as new traffic.
# The state is committed only after a report was accepted (HTTP 202), so a failed send is retried with the
# counter deltas still measured from the last report the server actually received.
# A standard user can create the folder before the collector does and would own it, so the folder is checked
# before anything in it is read or written (Test-DDTrustedDirectory), and a corrupt file is replaced, never moved.

Set-StrictMode -Version Latest

$script:DDStateVersion = 1
$script:DDRecentHresultDays = 7
$script:DDRecentHresultMax = 200
$script:DDTrustedSids = @('S-1-5-18', 'S-1-5-32-544')   # SYSTEM, BUILTIN\Administrators

function Test-DDTrustedDirectory {
    <#
    .SYNOPSIS
        Why the state folder cannot be trusted, or $null when it can. Trusted: not a junction or link, owned by
        SYSTEM or Administrators, access rules protected from inheritance, no Allow rule for any other account, and
        nothing in it the collector did not make (no subfolder, no link). 'missing' when it does not exist. A $null Raw
        (off Windows, where there are no ACLs) is trusted. The reasons name no account: they reach the Intune output.
    #>
    [CmdletBinding()]
    param($Raw)
    if ($null -eq $Raw) { return $null }
    if (-not $Raw.Exists) { return 'missing' }
    if ($Raw.Error) { return 'its permissions could not be read' }
    if ($Raw.ReparsePoint) { return 'it is a junction or symbolic link' }
    if ($script:DDTrustedSids -notcontains [string]$Raw.Owner) { return 'it is owned by an account other than SYSTEM or Administrators' }
    if (-not $Raw.Protected) { return 'it inherits permissions from its parent folder' }
    if (@($Raw.Rules | Where-Object { $_.Type -eq 'Allow' -and $script:DDTrustedSids -notcontains [string]$_.Sid }).Count) { return 'it grants access to accounts other than SYSTEM and Administrators' }
    if ($Raw.Subdirectories -gt 0 -or $Raw.Links -gt 0) { return 'it holds folders or links the collector did not create' }
    $null
}

function Initialize-DDStateDirectory {
    <#
    .SYNOPSIS
        Make the state folder safe before the collector writes in it: create it protected when it is missing.
        When it exists and cannot be trusted, -AllowReset replaces it (Reset-DDStateDirectory) and checks again; only the
        fleet run passes it, and only for the default %ProgramData%\DoctorDO, so nothing outside the collector's own
        folder is ever deleted. Returns $null when the folder is safe to use, else why not: the caller must then neither
        read nor write in it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path, [switch] $AllowReset)
    $raw = Get-DDDirectorySecurityRaw -Path $Path
    if ($null -eq $raw) {
        if (-not (Test-Path -LiteralPath $Path)) { New-DDProtectedDirectory -Path $Path }
        return $null
    }
    $why = Test-DDTrustedDirectory -Raw $raw
    if (-not $why) { return $null }
    if ($why -ne 'missing' -and -not $AllowReset) { return $why }
    try {
        if ($why -eq 'missing') { New-DDProtectedDirectory -Path $Path } else { Reset-DDStateDirectory -Path $Path }
    } catch {
        return $(if ($why -eq 'missing') { "it could not be created ($($_.Exception.Message))" } else { "$why, and it could not be replaced ($($_.Exception.Message))" })
    }
    $after = Test-DDTrustedDirectory -Raw (Get-DDDirectorySecurityRaw -Path $Path)
    if (-not $after) { return $null }
    $(if ($why -eq 'missing') { $after } else { "$why, and after it was replaced $after" })
}

function Get-DDDefaultStatePath {
    [CmdletBinding()]
    param()
    $pd = $env:ProgramData
    if ([string]::IsNullOrEmpty($pd)) { $pd = [System.IO.Path]::GetTempPath() }
    Join-Path -Path $pd -ChildPath 'DoctorDO\state.json'
}

function New-DDRandomHex {
    [CmdletBinding()]
    param([int] $Bytes = 32)
    $b = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-DDState {
    [CmdletBinding()]
    param()
    [ordered]@{
        version           = $script:DDStateVersion
        seq               = 0
        salt              = (New-DDRandomHex -Bytes 32)
        lastInventoryHash = $null
        lastStableHash    = $null
        lastInventoryAt   = $null
        # When the first inventory was accepted: for a week after it the keyframe is daily (Invoke-DoctorDOCollector, E-02).
        firstInventoryAt  = $null
        lastTelemetryAt   = $null
        # Each job's, peer's and log connection's counters at the last accepted report (Get-DDNextCounters): $null until the
        # first, whose telemetry is then a baseline that sends no bytes (docs/08).
        counters          = $null
        backoffUntil      = $null
        consecutiveFailures = 0
        lastConnectivity  = [ordered]@{}
        recentHresults    = @()
        flapCounts        = [ordered]@{}
        diag              = $null
        # File IDs of the finished jobs already summarised into a report's `sources` (docs/08), so each job counts once.
        sourcesSeen       = @()
        # The provisioning section as last sent (ADR-0043): its delivery snapshot is the one captured nearest provisioning.
        provisioning      = $null
    }
}

function ConvertTo-DDValidState {
    # Keep every field that has the right type, replace the rest with defaults. Never throws.
    [CmdletBinding()]
    param($Candidate)

    $s = New-DDState
    if ($Candidate -isnot [System.Collections.IDictionary]) { return $s }
    if ($Candidate['seq'] -is [long] -or $Candidate['seq'] -is [int]) { if ($Candidate['seq'] -ge 0) { $s['seq'] = [int64]$Candidate['seq'] } }
    if ($Candidate['salt'] -is [string] -and $Candidate['salt'] -match '^[0-9a-f]{32,128}$') { $s['salt'] = $Candidate['salt'] }
    foreach ($k in 'lastInventoryHash', 'lastStableHash', 'lastInventoryAt', 'firstInventoryAt', 'lastTelemetryAt', 'backoffUntil') {
        if ($Candidate[$k] -is [string] -and $Candidate[$k].Length -lt 128) { $s[$k] = $Candidate[$k] }
    }
    foreach ($hk in 'lastInventoryHash', 'lastStableHash') { if ($Candidate[$hk] -is [string] -and $Candidate[$hk] -notmatch '^sha256:[0-9a-f]{64}$') { $s[$hk] = $null } }
    if (($Candidate['consecutiveFailures'] -is [long] -or $Candidate['consecutiveFailures'] -is [int]) -and $Candidate['consecutiveFailures'] -ge 0) { $s['consecutiveFailures'] = [int64]$Candidate['consecutiveFailures'] }
    # A state written before collector 0.6.0 has `lastCounters` (two job-list sums) instead: it is dropped, so the first report
    # after the upgrade is a baseline rather than a difference of sums.
    $s['counters'] = ConvertTo-DDValidCounters -Candidate $Candidate['counters']
    if ($Candidate['lastConnectivity'] -is [System.Collections.IDictionary]) {
        $m = [ordered]@{}
        foreach ($k in $Candidate['lastConnectivity'].Keys) { if ($Candidate['lastConnectivity'][$k] -is [string]) { $m[[string]$k] = $Candidate['lastConnectivity'][$k] } }
        $s['lastConnectivity'] = $m
    }
    if ($Candidate['recentHresults'] -is [System.Collections.IEnumerable] -and $Candidate['recentHresults'] -isnot [string]) {
        $l = New-Object 'System.Collections.Generic.List[object]'
        foreach ($r in $Candidate['recentHresults']) {
            if ($r -is [System.Collections.IDictionary] -and $r['hresult'] -is [string] -and $r['hresult'] -match '^0x[0-9A-Fa-f]{8}$' -and $r['at'] -is [string]) {
                $l.Add([ordered]@{ hresult = $r['hresult']; at = $r['at'] })
            }
        }
        $s['recentHresults'] = $l.ToArray()
    }
    $s['flapCounts'] = ConvertTo-DDValidFlapCounts -Candidate $Candidate['flapCounts']
    $s['diag'] = ConvertTo-DDValidDiagCache -Candidate $Candidate['diag']
    if ($Candidate['sourcesSeen'] -is [System.Collections.IEnumerable] -and $Candidate['sourcesSeen'] -isnot [string]) {
        $ids = New-Object 'System.Collections.Generic.List[string]'
        foreach ($id in $Candidate['sourcesSeen']) {
            if ($id -is [string] -and $id.Length -gt 0 -and $id.Length -le 256 -and $ids.Count -lt $script:DDSourcesSeenMax) { $ids.Add($id) }
        }
        $s['sourcesSeen'] = $ids.ToArray()
    }
    if ($Candidate['provisioning'] -is [System.Collections.IDictionary] -and $Candidate['provisioning']['esp'] -is [System.Collections.IDictionary]) { $s['provisioning'] = $Candidate['provisioning'] }
    $s
}

function Read-DDState {
    <#
    .SYNOPSIS
        Read the state file; on any problem return a fresh state. Never writes: a corrupt file stays where it is until the
        next save replaces it (moving a file as SYSTEM in a folder someone else could prepare is unsafe). Nothing is read
        from a folder Test-DDTrustedDirectory does not trust; Untrusted then says why.
    .OUTPUTS
        @{ State = <ordered>; Recovered = <bool>; Reason = <string|null>; Untrusted = <string|null> }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    $why = Test-DDTrustedDirectory -Raw (Get-DDDirectorySecurityRaw -Path (Split-Path -Path $Path -Parent))
    if ($why -eq 'missing' -or -not (Test-Path -LiteralPath $Path)) { return @{ State = (New-DDState); Recovered = $false; Reason = 'absent'; Untrusted = $null } }
    if ($why) { return @{ State = (New-DDState); Recovered = $false; Reason = 'untrusted'; Untrusted = $why } }
    try {
        $text = [System.IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false)))
        $parsed = ConvertFrom-DDJson -Text $text
        if ($parsed -isnot [System.Collections.IDictionary]) { throw 'state root is not an object' }
        return @{ State = (ConvertTo-DDValidState -Candidate $parsed); Recovered = $false; Reason = $null; Untrusted = $null }
    } catch {
        return @{ State = (New-DDState); Recovered = $true; Reason = $_.Exception.Message; Untrusted = $null }
    }
}

function Save-DDState {
    <#
    .SYNOPSIS
        Atomic write: temp file in the same directory, flushed, then replaced over the target.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)] $State)

    $dir = Split-Path -Path $Path -Parent
    $unsafe = Initialize-DDStateDirectory -Path $dir
    if ($unsafe) { throw "The state folder $dir is not safe to use: $unsafe." }
    $State['version'] = $script:DDStateVersion
    $json = ConvertTo-DDCanonicalJson -InputObject $State
    $tmp = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    $fs = New-Object System.IO.FileStream($tmp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough)
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    # A scanner can hold the file for a moment just after it was written, and the replace then fails as a sharing violation. A
    # save that fails after a report was accepted would send that report's bytes again with the next one, so it is retried, briefly.
    for ($attempt = 1; ; $attempt++) {
        try {
            if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) } else { [System.IO.File]::Move($tmp, $Path) }
            break
        } catch {
            $io = ($_.Exception -is [System.IO.IOException]) -or ($_.Exception.InnerException -is [System.IO.IOException])
            if ($io -and $attempt -lt 5) { Start-Sleep -Milliseconds (100 * $attempt); continue }
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            throw
        }
    }
}

function Get-DDRecentHresultList {
    # HRESULT strings reported within the retention window.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)][datetime] $Now)
    $cut = $Now.AddDays(-$script:DDRecentHresultDays)
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($r in @($State['recentHresults'])) {
        $at = [datetime]::MinValue
        if ([datetime]::TryParse($r['at'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at) -and $at -ge $cut) {
            if (-not $out.Contains($r['hresult'])) { $out.Add($r['hresult']) }
        }
    }
    , $out.ToArray()
}

function Add-DDRecentHresults {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Hresults, [Parameter(Mandatory)][datetime] $Now)
    $keep = New-Object 'System.Collections.Generic.List[object]'
    $cut = $Now.AddDays(-$script:DDRecentHresultDays)
    foreach ($r in @($State['recentHresults'])) {
        $at = [datetime]::MinValue
        if ([datetime]::TryParse($r['at'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at) -and $at -ge $cut -and $Hresults -notcontains $r['hresult']) { $keep.Add($r) }
    }
    $stamp = $Now.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    foreach ($h in ($Hresults | Select-Object -Unique)) { $keep.Add([ordered]@{ hresult = $h; at = $stamp }) }
    $arr = $keep.ToArray()
    if ($arr.Count -gt $script:DDRecentHresultMax) { $arr = $arr[($arr.Count - $script:DDRecentHresultMax)..($arr.Count - 1)] }
    $State['recentHresults'] = $arr
}
