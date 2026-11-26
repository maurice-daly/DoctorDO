#Requires -Version 5.1
# Telemetry compaction. This is a line-for-line port of packages/wire/src/compact.ts (ADR-0023), kept
# in the same order so the two can be read side by side. The golden tests in tests/ prove they agree.
#
# Input ("raw"): a bundle-shaped dictionary (see contracts/bundle-v1.schema.json): device, network,
# status, peerInfo, connections, perfSnap, connectivity, errors, notCollected, collector, collectedAt.
# Plus the state's counters from the last accepted report, so each report carries what moved since (docs/08).
# Pure functions: no I/O, no Windows APIs.

Set-StrictMode -Version Latest

$script:DDTopFiles = 25
$script:DDTopPeers = 8
$script:DDTopEndpoints = 24

# Microsoft-operated content hosts a file path may be sent for (MICROSOFT_CONTENT_HOST_SUFFIXES in
# packages/schema/src/content-host.ts, where each suffix carries its Microsoft Learn source). Matched on a label
# boundary. Any other host - a customer's WSUS, cache server or internal web server - never has a path sent.
$script:DDContentHostSuffixes = @(
    'windowsupdate.com', 'delivery.mp.microsoft.com', 'update.microsoft.com', 'definitionupdates.microsoft.com',
    'officecdn.microsoft.com', 'cdn.office.net', 'static.microsoft', 'statics.teams.cdn.live.net',
    'manage.microsoft.com', 'storeedgefd.dsx.mp.microsoft.com', 'xboxlive.com', 'download.microsoft.com')

function Test-DDMicrosoftContentHost {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $HostName)

    if ([string]::IsNullOrEmpty($HostName)) { return $false }
    $h = $HostName.ToLowerInvariant().TrimEnd('.')
    foreach ($s in $script:DDContentHostSuffixes) {
        if ($h -ceq $s -or $h.EndsWith(".$s", [System.StringComparison]::Ordinal)) { return $true }
    }
    $false
}

function Get-DDContentPath {
    # The compact row's path (contentPath in content-path.ts): the path hint re-checked segment by segment, only
    # for a Microsoft content host. A segment that could be an identifier is dropped; at most two remain.
    # Sent under -Anonymise as well: what survives is a Microsoft CDN layout segment, never organisation data.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $HostName, [AllowNull()][AllowEmptyString()][string] $Hint)

    if ([string]::IsNullOrEmpty($Hint) -or -not (Test-DDMicrosoftContentHost -HostName $HostName)) { return $null }
    $segs = @($Hint.Split('/') | Where-Object { $_ -ne '' -and $_ -cmatch '^[A-Za-z0-9._~-]{1,56}$' -and $_ -cnotmatch '[0-9A-Fa-f]{8}' } | Select-Object -First 2)
    if ($segs.Count -eq 0) { return $null }
    '/' + ($segs -join '/')
}

function Get-DDFileHost {
    # The host a compact file row may carry (fileHost in compact.ts). Under -Anonymise only a Microsoft content host, or one
    # already pseudonymised on the device (host:<16 hex>), leaves it.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $HostName, [bool] $Anonymised)

    if ([string]::IsNullOrEmpty($HostName)) { return $null }
    if (-not $Anonymised) { return $HostName }
    if ((Test-DDMicrosoftContentHost -HostName $HostName) -or $HostName -cmatch '^host:[0-9a-f]{16}$') { return $HostName }
    $null
}

function Get-DDConnectivityKey {
    # Identity of a connectivity result: same probe, target, protocol and port (connKey in compact.ts).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Result)

    $port = ''
    if ($null -ne $Result['port']) { $port = [System.Convert]::ToString($Result['port'], [System.Globalization.CultureInfo]::InvariantCulture) }
    '{0}|{1}|{2}|{3}' -f $Result['checkId'], $Result['target'], $Result['protocol'], $port
}

$script:DDMaxConnectivityChanged = 64

function Get-DDConnectivityComposite {
    # The state a check is compared by (connectivityComposite in compact.ts): `result|code`, the code empty when the check
    # has none ("pass|", "fail|not-in-force"). A check that stays `fail` while its code changes is a change worth sending:
    # the server maps result plus code to a finding (docs/27 3.1).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Result)

    $code = $Result['code']
    '{0}|{1}' -f $Result['result'], $(if ($null -eq $code) { '' } else { [string]$code })
}

function Test-DDConnectivityDiffers {
    <#
    .SYNOPSIS
        Whether a result differs from what was last reported for its key. $null (never reported) differs. A stored value
        without `|` is the bare result an older collector kept (`pass`, before it kept `pass|`): it is compared on the result
        alone, so the first run after an upgrade resends nothing that did not change. Anything else is compared on the
        composite (changedConnectivity in compact.ts; the bare-result rule exists only here, where the old state file is read).
    #>
    [CmdletBinding()]
    param([AllowNull()] $Previous, [Parameter(Mandatory)] $Result)

    if ($null -eq $Previous) { return $true }
    $p = [string]$Previous
    if ($p.IndexOf('|') -lt 0) { return ($p -cne [string]$Result['result']) }
    $p -cne (Get-DDConnectivityComposite -Result $Result)
}

function Get-DDConnectivityGroup {
    # Endpoint-health results (checkId ep:<id>) travel as a group (connectivityGroup in compact.ts); $null for any other check.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $CheckId)
    if ($CheckId -and $CheckId.StartsWith('ep:', [System.StringComparison]::Ordinal)) { return $CheckId }
    $null
}

function Select-DDChangedConnectivity {
    <#
    .SYNOPSIS
        The results a telemetry report carries (changedConnectivity in compact.ts): those that differ from the previous
        report (all when there is none), whole endpoint groups, at most 64, in matrix order; a group that would not fit
        whole is left for the next report.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Rows = @(), $PreviousConnectivity, [int] $Max = $script:DDMaxConnectivityChanged)

    $rowsAll = @($Rows)
    $prevOf = {
        param($k)
        if ($null -ne $PreviousConnectivity -and $PreviousConnectivity.Contains($k)) { return $PreviousConnectivity[$k] }
        $null
    }
    $groupsChanged = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($null -ne $PreviousConnectivity) {
        $current = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($c in $rowsAll) { [void]$current.Add((Get-DDConnectivityKey -Result $c)) }
        foreach ($c in $rowsAll) {
            $g = Get-DDConnectivityGroup -CheckId ([string]$c['checkId'])
            if ($null -ne $g -and (Test-DDConnectivityDiffers -Previous (& $prevOf (Get-DDConnectivityKey -Result $c)) -Result $c)) { [void]$groupsChanged.Add($g) }
        }
        foreach ($k in @($PreviousConnectivity.Keys)) {
            $g = Get-DDConnectivityGroup -CheckId (([string]$k).Split('|')[0])
            if ($null -ne $g -and -not $current.Contains([string]$k)) { [void]$groupsChanged.Add($g) }
        }
    }
    $out = New-Object 'System.Collections.Generic.List[object]'
    $taken = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $rowsAll) {
        $g = Get-DDConnectivityGroup -CheckId ([string]$c['checkId'])
        if ($null -eq $g) {
            if ((Test-DDConnectivityDiffers -Previous (& $prevOf (Get-DDConnectivityKey -Result $c)) -Result $c) -and $out.Count -lt $Max) { $out.Add($c) }
            continue
        }
        if ($taken.Contains($g)) { continue }
        if ($null -ne $PreviousConnectivity -and -not $groupsChanged.Contains($g)) { continue }
        [void]$taken.Add($g)
        $members = @($rowsAll | Where-Object { [string]$_['checkId'] -eq $g })
        if ($out.Count + $members.Count -le $Max) { foreach ($m in $members) { $out.Add($m) } }
    }
    , $out
}

# Per-job deltas (docs/08, compact.ts CounterState): the job list, the peer list and the log's connection list are snapshots that
# repeat a job until its cache expires, so the state keeps each entry's counters from the last accepted report and a report carries
# the increase. A part of the state is @{ entries = <key -> counters, ordinal keys>; capped = <bool> }, or $null when never read.
$script:DDMaxCounterEntries = 2000

function New-DDOrdinalMap {
    # An ordered dictionary with case-sensitive keys, as a Map in packages/wire is ([ordered]@{} ignores case).
    [CmdletBinding()]
    param()
    , (New-Object System.Collections.Specialized.OrderedDictionary ([System.StringComparer]::Ordinal))
}

function Get-DDShortId {
    # The first 16 characters of an identifier (shortId in compact.ts).
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    $Value.Substring(0, [math]::Min(16, $Value.Length))
}

function Get-DDJobKey {
    # The state's key for a job: its file ID in lower case (jobKey in compact.ts). The state file is read back into dictionaries
    # that ignore case, so every key is kept in lower case and two that differ only by case are one key everywhere.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $FileId)
    ([string]$FileId).ToLowerInvariant()
}

function Get-DDPeerKey {
    # The state's key for one peer of one job (peerKey in compact.ts).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Row)
    $h = Get-DDPeerHex16 -PeerHash ([string]$Row['peerHash'])
    ('{0}|{1}' -f (Get-DDShortId -Value ([string]$Row['fileId'])), $(if ($null -ne $h) { $h } else { [string]$Row['peerHash'] })).ToLowerInvariant()
}

function Get-DDConnectionKey {
    # The state's key for one connection in the DO log: everything the row says (connectionKey in compact.ts). The log keeps no
    # time per connection, so the state counts how many times each one is in the log.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Row)
    $h = Get-DDPeerHex16 -PeerHash ([string]$Row['destinationHash'])
    $parts = @(
        (Get-DDShortId -Value ([string]$Row['fileId'])), $(if ($null -ne $h) { $h } else { [string]$Row['destinationHash'] }), [string]$Row['peerType'],
        [string]$Row['statusCode'], $(if ([bool]$Row['connected']) { 'true' } else { 'false' }),
        (ConvertTo-DDBigInt $Row['bytesSent']).ToString(), (ConvertTo-DDBigInt $Row['bytesReceived']).ToString())
    ($parts -join '|').ToLowerInvariant()
}

function Get-DDJobCounters {
    # A job's counters in the state's order: the five download sources, then uploads to LAN, Group and Internet peers.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Row)
    , [System.Numerics.BigInteger[]]@(
        (ConvertTo-DDBigInt $Row['bytesFromHttp']), (ConvertTo-DDBigInt $Row['bytesFromLanPeers']), (ConvertTo-DDBigInt $Row['bytesFromGroupPeers']),
        (ConvertTo-DDBigInt $Row['bytesFromInternetPeers']), (ConvertTo-DDBigInt $Row['bytesFromCacheServer']),
        (ConvertTo-DDBigInt $Row['bytesToLanPeers']), (ConvertTo-DDBigInt $Row['bytesToGroupPeers']), (ConvertTo-DDBigInt $Row['bytesToInternetPeers']))
}

function Get-DDCounterIncrease {
    <#
    .SYNOPSIS
        How much one entry's counters rose since the last report (increase in compact.ts). In a snapshot, all of them. An entry the
        state holds: the difference, or all of it when a counter went back (the file left the cache and was downloaded again, or
        DoSvc started the peer's session afresh). An entry it does not hold: all of it when the part is complete (a new job), none
        when it is not (never read, or capped): it is then a starting point, counted from the next report on.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Numerics.BigInteger[]] $Current, [Parameter(Mandatory)][string] $Kind, [AllowNull()] $Part, [Parameter(Mandatory)][string] $Key)
    $n = $Current.Count
    $out = New-Object 'System.Numerics.BigInteger[]' $n
    if ($Kind -eq 'snapshot') { for ($i = 0; $i -lt $n; $i++) { $out[$i] = $Current[$i] }; return , $out }
    $prev = $null
    if ($null -ne $Part -and $Part['entries'].Contains($Key)) { $prev = @($Part['entries'][$Key]) }
    if ($null -eq $prev) {
        if ($null -ne $Part -and -not [bool]$Part['capped']) { for ($i = 0; $i -lt $n; $i++) { $out[$i] = $Current[$i] } }
        return , $out
    }
    $p = New-Object 'System.Numerics.BigInteger[]' $n
    for ($i = 0; $i -lt $n; $i++) { if ($i -lt $prev.Count) { $p[$i] = ConvertTo-DDBigInt $prev[$i] } }
    for ($i = 0; $i -lt $n; $i++) {
        if ($Current[$i] -lt $p[$i]) { for ($j = 0; $j -lt $n; $j++) { $out[$j] = $Current[$j] }; return , $out }
    }
    for ($i = 0; $i -lt $n; $i++) { $out[$i] = $Current[$i] - $p[$i] }
    , $out
}

function Get-DDBigSum {
    # The sum of $Values[$From..$To-1] (sumOf in compact.ts).
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Numerics.BigInteger[]] $Values, [int] $From = 0, [int] $To = 5)
    $t = [System.Numerics.BigInteger]::Zero
    for ($i = $From; $i -lt $To; $i++) { $t = $t + $Values[$i] }
    $t
}

function Test-DDListRead {
    # Whether this collection read a list: no notCollected record with exactly that field ('status', 'peerInfo', 'connections').
    [CmdletBinding()]
    param([AllowEmptyCollection()] $NotCollected = @(), [Parameter(Mandatory)][string] $Field)
    -not @(@($NotCollected) | Where-Object { $null -ne $_ -and [string]$_['field'] -ceq $Field }).Count
}

function Get-DDReadRows {
    # The rows a list contributes (readRows in compact.ts): all in a snapshot; none in a delta or baseline when it was not read.
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Rows = @(), [AllowEmptyCollection()] $NotCollected = @(), [Parameter(Mandatory)][string] $Kind, [Parameter(Mandatory)][string] $Field)
    if ($Kind -eq 'snapshot' -or (Test-DDListRead -NotCollected $NotCollected -Field $Field)) { return , @($Rows) }
    , @()
}

function Get-DDJobDeltas {
    # The job list once per file ID, the first row winning, with each job's counters and their increase (jobsOf in compact.ts).
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Rows = @(), [Parameter(Mandatory)][string] $Kind, [AllowNull()] $Part)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $id = Get-DDJobKey -FileId ([string]$r['fileId'])
        if (-not $seen.Add($id)) { continue }
        $cur = Get-DDJobCounters -Row $r
        $out.Add([pscustomobject]@{ R = $r; Id = $id; Cur = $cur; D = (Get-DDCounterIncrease -Current $cur -Kind $Kind -Part $Part -Key $id) })
    }
    , $out.ToArray()
}

function Get-DDPeerDeltas {
    # The peer list summed per peer key, the first row naming type, subnet and hash, with each one's increase (peersOf in compact.ts).
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Rows = @(), [Parameter(Mandatory)][string] $Kind, [AllowNull()] $Part)
    $by = New-DDOrdinalMap
    foreach ($p in @($Rows)) {
        if ($null -eq $p) { continue }
        $k = Get-DDPeerKey -Row $p
        if ($by.Contains($k)) {
            $x = $by[$k]
            $x.Cur[0] = $x.Cur[0] + (ConvertTo-DDBigInt $p['bytesSent'])
            $x.Cur[1] = $x.Cur[1] + (ConvertTo-DDBigInt $p['bytesReceived'])
        } else {
            $by[$k] = [pscustomobject]@{ P = $p; Cur = [System.Numerics.BigInteger[]]@((ConvertTo-DDBigInt $p['bytesSent']), (ConvertTo-DDBigInt $p['bytesReceived'])) }
        }
    }
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($k in @($by.Keys)) {
        $x = $by[$k]
        $out.Add([pscustomobject]@{ K = [string]$k; P = $x.P; Cur = $x.Cur; D = (Get-DDCounterIncrease -Current $x.Cur -Kind $Kind -Part $Part -Key ([string]$k)) })
    }
    , $out.ToArray()
}

function Get-DDConnectionDeltas {
    # The log's connections counted per connection key, the first row naming type, status and outcome, with how many are new
    # since the last report, never below zero when older ones have left the log (connectionsOf in compact.ts).
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Rows = @(), [Parameter(Mandatory)][string] $Kind, [AllowNull()] $Part)
    $by = New-DDOrdinalMap
    foreach ($c in @($Rows)) {
        if ($null -eq $c) { continue }
        $k = Get-DDConnectionKey -Row $c
        if ($by.Contains($k)) { $by[$k].N = $by[$k].N + 1 } else { $by[$k] = [pscustomobject]@{ C = $c; N = 1 } }
    }
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($k in @($by.Keys)) {
        $x = $by[$k]
        $d = 0
        if ($Kind -eq 'snapshot') { $d = $x.N }
        elseif ($null -ne $Part -and $Part['entries'].Contains([string]$k)) { $d = [math]::Max(0, $x.N - [int]$Part['entries'][[string]$k]) }
        elseif ($null -ne $Part -and -not [bool]$Part['capped']) { $d = $x.N }
        $out.Add([pscustomobject]@{ K = [string]$k; C = $x.C; N = $x.N; D = [int]$d })
    }
    , $out.ToArray()
}

function New-DDCounterPart {
    # A part of the state from a list's entries (key, value pairs), in list order, at most $script:DDMaxCounterEntries (partOf in compact.ts).
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Entries = @())
    $m = New-DDOrdinalMap
    $all = @($Entries)
    for ($i = 0; $i -lt [math]::Min($all.Count, $script:DDMaxCounterEntries); $i++) { $m[$all[$i].Key] = $all[$i].Value }
    [ordered]@{ entries = $m; capped = ($all.Count -gt $script:DDMaxCounterEntries) }
}

function Get-DDNextCounters {
    <#
    .SYNOPSIS
        The counters the state keeps once a report is accepted (nextCounters in compact.ts): for each list this collection read,
        every entry in list order, at most 2,000 (capped when there were more); a list it could not read keeps what the state held,
        so nothing it moved meanwhile is lost or counted twice. Byte counters are kept as decimal strings. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Raw, [AllowNull()] $Previous)
    $nc = @(); if ($null -ne $Raw['notCollected']) { $nc = @($Raw['notCollected']) }
    $prev = ConvertTo-DDValidCounters -Candidate $Previous
    $out = [ordered]@{ jobs = $null; peers = $null; connections = $null }
    if ($null -ne $prev) { foreach ($name in 'jobs', 'peers', 'connections') { $out[$name] = $prev[$name] } }
    if (Test-DDListRead -NotCollected $nc -Field 'status') {
        $e = New-Object 'System.Collections.Generic.List[object]'
        foreach ($j in (Get-DDJobDeltas -Rows @($Raw['status']) -Kind 'snapshot' -Part $null)) {
            $v = New-Object 'System.Collections.Generic.List[string]'
            foreach ($x in $j.Cur) { $v.Add($x.ToString()) }
            $e.Add([pscustomobject]@{ Key = $j.Id; Value = $v.ToArray() })
        }
        $out['jobs'] = New-DDCounterPart -Entries $e.ToArray()
    }
    if (Test-DDListRead -NotCollected $nc -Field 'peerInfo') {
        $e = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in (Get-DDPeerDeltas -Rows @($Raw['peerInfo']) -Kind 'snapshot' -Part $null)) { $e.Add([pscustomobject]@{ Key = $p.K; Value = [string[]]@($p.Cur[0].ToString(), $p.Cur[1].ToString()) }) }
        $out['peers'] = New-DDCounterPart -Entries $e.ToArray()
    }
    if (Test-DDListRead -NotCollected $nc -Field 'connections') {
        $e = New-Object 'System.Collections.Generic.List[object]'
        foreach ($c in (Get-DDConnectionDeltas -Rows @($Raw['connections']) -Kind 'snapshot' -Part $null)) { $e.Add([pscustomobject]@{ Key = $c.K; Value = [int]$c.N }) }
        $out['connections'] = New-DDCounterPart -Entries $e.ToArray()
    }
    $out
}

function ConvertTo-DDValidCounters {
    <#
    .SYNOPSIS
        The state's counters as the compaction reads them: each part with case-sensitive keys and well-formed values, at most
        2,000 entries; a part that is missing or not a part is $null (its next report is a starting point for that list); anything
        that is not a dictionary is $null (a baseline). An entry that is not well formed is dropped and its part marked capped, so
        it is never counted whole again. Never throws.
    #>
    [CmdletBinding()]
    param([AllowNull()] $Candidate)
    if ($Candidate -isnot [System.Collections.IDictionary]) { return $null }
    $out = [ordered]@{ jobs = $null; peers = $null; connections = $null }
    $lengths = @{ jobs = 8; peers = 2 }
    foreach ($name in 'jobs', 'peers', 'connections') {
        $p = $null; if ($Candidate.Contains($name)) { $p = $Candidate[$name] }
        if ($p -isnot [System.Collections.IDictionary] -or -not $p.Contains('entries') -or $p['entries'] -isnot [System.Collections.IDictionary]) { continue }
        $m = New-DDOrdinalMap
        $capped = ($p.Contains('capped') -and $p['capped'] -eq $true)
        foreach ($k in @($p['entries'].Keys)) {
            $key = [string]$k
            $v = $p['entries'][$k]
            $good = $null
            if ($name -eq 'connections') {
                $n = 0
                if (($v -is [int] -or $v -is [long]) -and $v -ge 0 -and [int]::TryParse([string]$v, [ref]$n)) { $good = $n }
            } elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                $arr = @($v)
                if ($arr.Count -eq $lengths[$name] -and @($arr | Where-Object { [string]$_ -cnotmatch '^\d{1,30}$' }).Count -eq 0) { $good = [string[]]@($arr | ForEach-Object { [string]$_ }) }
            }
            if ($null -eq $good -or $key.Length -eq 0 -or $key.Length -gt 512 -or $m.Count -ge $script:DDMaxCounterEntries) { $capped = $true; continue }
            $m[$key] = $good
        }
        $out[$name] = [ordered]@{ entries = $m; capped = [bool]$capped }
    }
    $out
}

function Get-DDPeerHex16 {
    [CmdletBinding()]
    param([AllowNull()][string] $PeerHash)

    if ([string]::IsNullOrEmpty($PeerHash)) { return $null }
    $h = ($PeerHash -creplace '^sha256:', '').ToLowerInvariant()
    if ($h -cmatch '^[0-9a-f]{16,}$') { return $h.Substring(0, 16) }
    $null
}

function Get-DDStableDescending {
    # Descending by BigInteger key with insertion order as the tie-break (Array.prototype.sort is stable;
    # Sort-Object is not on Windows PowerShell 5.1).
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Items, [Parameter(Mandatory)][scriptblock] $Key)

    $wrapped = New-Object 'System.Collections.Generic.List[object]'
    $i = 0
    foreach ($it in $Items) { $wrapped.Add([pscustomobject]@{ I = $i; K = (& $Key $it); V = $it }); $i++ }
    $cmp = [System.Comparison[object]] {
        param($a, $b)
        $c = [System.Numerics.BigInteger]::Compare($b.K, $a.K)
        if ($c -ne 0) { return $c }
        return ($a.I - $b.I)
    }
    $wrapped.Sort($cmp)
    $res = New-Object 'System.Collections.Generic.List[object]'
    foreach ($w in $wrapped) { $res.Add($w.V) }
    , $res.ToArray()
}

function Get-DDFiveCounters {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Numerics.BigInteger[]] $Values)
    , @($Values | ForEach-Object { ConvertTo-DDByteCount -Value $_ })
}

$script:DDDiagFlapMax = 8
$script:DDDiagFlapMin = 2
$script:DDDiagCap = 99

function Select-DDFlapCounts {
    # diag.flap (compact.ts): checks that changed result at least twice in 7 days, the eight most often (ties by name), each
    # count capped at 99; check names that do not fit the wire pattern are dropped. Pure.
    [CmdletBinding()]
    param([AllowNull()] $Counts, [int] $Min = $script:DDDiagFlapMin, [int] $Max = $script:DDDiagFlapMax)

    $rows = New-Object 'System.Collections.Generic.List[object]'
    if ($Counts -is [System.Collections.IDictionary]) {
        foreach ($k in $Counts.Keys) {
            $name = [string]$k
            $n = 0
            if (-not [int]::TryParse([string]$Counts[$k], [ref]$n)) { continue }
            if ($n -lt $Min -or $name -cnotmatch '^[a-z0-9:-]{1,40}$') { continue }
            $rows.Add([pscustomobject]@{ Name = $name; N = [math]::Min($script:DDDiagCap, $n) })
        }
    }
    $cmp = [System.Comparison[object]] { param($a, $b) if ($a.N -ne $b.N) { return ($b.N - $a.N) }; return [string]::CompareOrdinal($a.Name, $b.Name) }
    $rows.Sort($cmp)
    $out = [ordered]@{}
    foreach ($r in ($rows | Select-Object -First $Max)) { $out[$r.Name] = [int]$r.N }
    $out
}

function ConvertTo-DDDiagSection {
    # TelemetryV1.diag (compactDiag in compact.ts) from the measurements; $null when the collector had none (the key is then
    # left out of the report). Absence of a key means "measured, healthy" unless the field is named in notCollected:
    # crash is left out when 0, up is always sent when measured (the threshold lives in packages/analysis), flap holds only
    # the checks that changed at least twice. Pure.
    [CmdletBinding()]
    param([AllowNull()] $Diag)

    if ($null -eq $Diag) { return $null }
    $o = [ordered]@{}
    $crash = $null; if ($Diag.Contains('crash')) { $crash = $Diag['crash'] }
    if ($null -ne $crash) { $c = [int][math]::Min([double]$script:DDDiagCap, [math]::Max([double]0, [double]$crash)); if ($c -gt 0) { $o['crash'] = $c } }
    $up = $null; if ($Diag.Contains('up')) { $up = $Diag['up'] }
    if ($null -ne $up) { $o['up'] = [int][math]::Min([double]24, [math]::Max([double]0, [math]::Round([double]$up, [System.MidpointRounding]::AwayFromZero))) }
    $flapIn = $null; if ($Diag.Contains('flap')) { $flapIn = $Diag['flap'] }
    $flap = Select-DDFlapCounts -Counts $flapIn
    if ($flap.Count -gt 0) { $o['flap'] = $flap }
    $o
}

# Content sources (sources.ts in packages/wire, docs/08 "Content sources"): constants of packages/schema sources.ts.
$script:DDSourceCacheRows = 4
$script:DDSourceHttpRows = 8
$script:DDSourceTimedMinBytes = [System.Numerics.BigInteger]4194304
$script:DDSourcesSeenMax = 2000
$script:DDFinishedStatuses = @('complete', 'caching')

function Test-DDJobFinished {
    # A job that has finished downloading: Status Complete or Caching (Monitor Delivery Optimization). isFinished in sources.ts.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Status)
    if ([string]::IsNullOrEmpty($Status)) { return $false }
    $script:DDFinishedStatuses -contains $Status.ToLowerInvariant()
}

function Get-DDNextSourcesSeen {
    <#
    .SYNOPSIS
        The file IDs the state keeps after a report is accepted (nextSourcesSeen in sources.ts): those already summarised that
        are still in the job list, plus the finished ones this report summarised, in job-list order, at most 2,000. Pure.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Status = @(), [AllowNull()] $Seen = @())
    $seenSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($s in @($Seen)) { if ($null -ne $s) { [void]$seenSet.Add([string]$s) } }
    $out = New-Object 'System.Collections.Generic.List[string]'
    $taken = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in @($Status)) {
        if ($null -eq $r) { continue }
        $id = [string]$r['fileId']
        if ($taken.Contains($id)) { continue }
        if ($seenSet.Contains($id) -or (Test-DDJobFinished -Status ([string]$r['status']))) { $out.Add($id); [void]$taken.Add($id) }
        if ($out.Count -ge $script:DDSourcesSeenMax) { break }
    }
    , $out.ToArray()
}

function Test-DDSourceTimed {
    # A job's time counts for a source that delivered at least 90% of its bytes and at least 4 MiB (timedFor in sources.ts).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Row, [Parameter(Mandatory)][System.Numerics.BigInteger] $Own)
    $ms = $Row['downloadMs']
    if ($null -eq $ms -or [long]$ms -le 0) { return $false }
    $five = (ConvertTo-DDBigInt $Row['bytesFromHttp']) + (ConvertTo-DDBigInt $Row['bytesFromLanPeers']) + (ConvertTo-DDBigInt $Row['bytesFromGroupPeers']) +
        (ConvertTo-DDBigInt $Row['bytesFromInternetPeers']) + (ConvertTo-DDBigInt $Row['bytesFromCacheServer'])
    $total = ConvertTo-DDBigInt $Row['totalBytesDownloaded']
    if ($five -gt $total) { $total = $five }
    ($Own -ge $script:DDSourceTimedMinBytes) -and (($Own * 10) -ge ($total * 9))
}

function Add-DDSourceBytes {
    # Fold one job's bytes from one source into the accumulator for its host ('' for no host). add in sources.ts.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Map, [AllowNull()][AllowEmptyString()][string] $HostName, [Parameter(Mandatory)] $Row, [Parameter(Mandatory)][System.Numerics.BigInteger] $Own)
    if ($Own -le 0) { return }
    $key = $(if ([string]::IsNullOrEmpty($HostName)) { '' } else { $HostName })
    if (-not $Map.Contains($key)) {
        $Map[$key] = @{ Host = $(if ($key -eq '') { $null } else { $key }); Bytes = [System.Numerics.BigInteger]::Zero; Jobs = 0; Ms = [long]0; TBytes = [System.Numerics.BigInteger]::Zero; TJobs = 0 }
    }
    $a = $Map[$key]
    $a.Bytes = $a.Bytes + $Own
    $a.Jobs = $a.Jobs + 1
    if (Test-DDSourceTimed -Row $Row -Own $Own) { $a.Ms = $a.Ms + [long]$Row['downloadMs']; $a.TBytes = $a.TBytes + $Own; $a.TJobs = $a.TJobs + 1 }
}

function ConvertTo-DDSourceRows {
    # Named hosts by bytes (ties by name, ordinal), at most $Max; the rest and the bytes with no host in one h = $null row. rows in sources.ts.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Map, [Parameter(Mandatory)][int] $Max)
    $named = New-Object 'System.Collections.Generic.List[object]'
    foreach ($k in $Map.Keys) { if ($k -ne '') { $named.Add($Map[$k]) } }
    $cmp = [System.Comparison[object]] {
        param($a, $b)
        $c = [System.Numerics.BigInteger]::Compare($b.Bytes, $a.Bytes)
        if ($c -ne 0) { return $c }
        return [string]::CompareOrdinal([string]$a.Host, [string]$b.Host)
    }
    $named.Sort($cmp)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $rest = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $named.Count; $i++) {
        $a = $named[$i]
        if ($i -ge $Max) { $rest.Add($a); continue }
        $o = [ordered]@{ h = $a.Host; b = (ConvertTo-DDByteCount -Value $a.Bytes); n = [int]$a.Jobs }
        if ($a.TJobs -gt 0) { $o['t'] = @([long]$a.Ms, (ConvertTo-DDByteCount -Value $a.TBytes), [int]$a.TJobs) }
        $out.Add($o)
    }
    if ($Map.Contains('')) { $rest.Add($Map['']) }
    if ($rest.Count -gt 0) {
        $bytes = [System.Numerics.BigInteger]::Zero; $jobs = 0; $ms = [long]0; $tb = [System.Numerics.BigInteger]::Zero; $tj = 0
        foreach ($a in $rest) { $bytes = $bytes + $a.Bytes; $jobs = $jobs + $a.Jobs; $ms = $ms + $a.Ms; $tb = $tb + $a.TBytes; $tj = $tj + $a.TJobs }
        $o = [ordered]@{ h = $null; k = [int]([math]::Max(0, $named.Count - $Max)); b = (ConvertTo-DDByteCount -Value $bytes); n = [int]$jobs }
        if ($tj -gt 0) { $o['t'] = @([long]$ms, (ConvertTo-DDByteCount -Value $tb), [int]$tj) }
        $out.Add($o)
    }
    , $out.ToArray()
}

function ConvertTo-DDSourcesSection {
    <#
    .SYNOPSIS
        TelemetryV1.sources from the job list (compactSources in sources.ts): the finished jobs not summarised before, by
        Connected Cache server (CacheHost, BytesFromCacheServer) and by HTTP host (SourceURL host, HTTP bytes without the cache
        bytes), with bytes, jobs and the time of the jobs one source dominated. Empty lists are left out. Pure.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Status = @(), [AllowNull()] $Seen = @(), [bool] $Anonymised)
    $seenSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($s in @($Seen)) { if ($null -ne $s) { [void]$seenSet.Add([string]$s) } }
    $mcc = [ordered]@{}
    $http = [ordered]@{}
    foreach ($r in @($Status)) {
        if ($null -eq $r) { continue }
        if (-not (Test-DDJobFinished -Status ([string]$r['status'])) -or $seenSet.Contains([string]$r['fileId'])) { continue }
        $ch = [string]$r['cacheHost']
        Add-DDSourceBytes -Map $mcc -HostName $(if ($ch -eq '') { $null } else { $ch.ToLowerInvariant() }) -Row $r -Own (ConvertTo-DDBigInt $r['bytesFromCacheServer'])
        $h = [string](Get-DDFileHost -HostName $r['sourceUrlHost'] -Anonymised $Anonymised)
        Add-DDSourceBytes -Map $http -HostName $(if ($h -eq '') { $null } else { $h.ToLowerInvariant() }) -Row $r -Own (ConvertTo-DDBigInt $r['bytesFromHttp'])
    }
    $o = [ordered]@{}
    $c = ConvertTo-DDSourceRows -Map $mcc -Max $script:DDSourceCacheRows
    $w = ConvertTo-DDSourceRows -Map $http -Max $script:DDSourceHttpRows
    if ($c.Count -gt 0) { $o['mcc'] = $c }
    if ($w.Count -gt 0) { $o['http'] = $w }
    $o
}

function ConvertTo-DDTelemetry {
    <#
    .SYNOPSIS
        Compact a raw collection into a TelemetryV1 report (same rules as compactTelemetry in packages/wire).
    .PARAMETER Raw
        Bundle-shaped dictionary.
    .PARAMETER Seq
        Report sequence number.
    .PARAMETER InventoryHash
        Hash of the inventory this report was produced against.
    .PARAMETER PeriodFrom
        Start of the period covered (ISO 8601 UTC string).
    .PARAMETER PeriodTo
        End of the period covered (ISO 8601 UTC string).
    .PARAMETER PreviousConnectivity
        Dictionary of connectivity key to the last reported `result|code` (Get-DDConnectivityComposite); $null means report everything.
    .PARAMETER PreviousCounters
        The per-job, per-peer and per-connection counters at the previous accepted report (the state's `counters`,
        Get-DDNextCounters): the report then carries the increase since (`counters` = 'delta'). $null: there are none (a first
        report, a lost state file), so the report is a 'baseline' and carries no bytes. Not passed at all: the report is a
        'snapshot' of the counters as read (the offline device report, one point in time).
    .PARAMETER RecentHresults
        HRESULTs reported recently: a sample line is attached only to a new one.
    .PARAMETER Diag
        The diagnosis measurements (docs/27): a dictionary with optional crash, up, flap (check -> change count) and
        notCollected (records appended to the report's notCollected). $null: the collector measured nothing, so the report
        carries no `diag` key at all. Present but empty: measured and healthy.
    .PARAMETER SourcesSeen
        File IDs of the jobs earlier reports already summarised into `sources` (the state's sourcesSeen). $null: the job list
        was not read, and the report carries no `sources`. Empty: every finished job is summarised.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Raw,
        [Parameter(Mandatory)][int] $Seq,
        [Parameter(Mandatory)][string] $InventoryHash,
        [Parameter(Mandatory)][string] $PeriodFrom,
        [Parameter(Mandatory)][string] $PeriodTo,
        $PreviousConnectivity = $null,
        $PreviousCounters = $null,
        [string[]] $RecentHresults = @(),
        $Diag = $null,
        $SourcesSeen = $null
    )

    $zero = [System.Numerics.BigInteger]::Zero
    $errorsIn = @(); if ($null -ne $Raw['errors']) { $errorsIn = @($Raw['errors']) }
    $connectivity = @(); if ($null -ne $Raw['connectivity']) { $connectivity = @($Raw['connectivity']) }
    $notCollected = @(); if ($null -ne $Raw['notCollected']) { $notCollected = @($Raw['notCollected']) }

    # What the byte counters measure (TelemetryV1.counters): not passed, a snapshot; no state or no job counters in it, a baseline.
    $prev = $null
    $kind = 'snapshot'
    if ($PSBoundParameters.ContainsKey('PreviousCounters')) {
        $prev = ConvertTo-DDValidCounters -Candidate $PreviousCounters
        $kind = $(if ($null -eq $prev -or $null -eq $prev['jobs']) { 'baseline' } else { 'delta' })
    }
    $part = { param($name) if ($null -ne $prev) { return $prev[$name] }; $null }
    $status = Get-DDReadRows -Rows @($Raw['status'] | Where-Object { $null -ne $_ }) -NotCollected $notCollected -Kind $kind -Field 'status'
    $peerInfo = Get-DDReadRows -Rows @($Raw['peerInfo'] | Where-Object { $null -ne $_ }) -NotCollected $notCollected -Kind $kind -Field 'peerInfo'
    $connections = Get-DDReadRows -Rows @($Raw['connections'] | Where-Object { $null -ne $_ }) -NotCollected $notCollected -Kind $kind -Field 'connections'

    # files: the jobs that moved bytes, the biggest by how much, plus one row that accounts for the rest
    $jobs = Get-DDJobDeltas -Rows $status -Kind $kind -Part (& $part 'jobs')
    $moved = @($jobs | Where-Object { (Get-DDBigSum -Values $_.D) -gt $zero })
    $byBytes = Get-DDStableDescending -Items $moved -Key { param($j) Get-DDBigSum -Values $j.D }
    $topN = [math]::Min($script:DDTopFiles, $byBytes.Count)
    $top = @(); if ($topN -gt 0) { $top = $byBytes[0..($topN - 1)] }
    $rest = @(); if ($byBytes.Count -gt $script:DDTopFiles) { $rest = $byBytes[$script:DDTopFiles..($byBytes.Count - 1)] }

    $filesOut = New-Object 'System.Collections.Generic.List[object]'
    foreach ($j in $top) {
        $r = $j.R
        $filesOut.Add([ordered]@{
                id     = $r['fileId']
                size   = ConvertTo-DDByteCount -Value (ConvertTo-DDBigInt -Value $r['fileSize'])
                b      = Get-DDFiveCounters -Values @($j.D[0], $j.D[1], $j.D[2], $j.D[3], $j.D[4])
                mode   = [long]$r['downloadMode']
                status = $r['status']
                pri    = $r['priority']
                caller = $r['predefinedCallerApplication']
                host   = Get-DDFileHost -HostName $r['sourceUrlHost'] -Anonymised ([bool]$Raw['anonymised'])
                path   = Get-DDContentPath -HostName $r['sourceUrlHost'] -Hint $r['sourceUrlPathHint']
                ch     = $r['cacheHost']
            })
    }
    $filesOther = $null
    if ($rest.Count -gt 0) {
        $sums = @($zero, $zero, $zero, $zero, $zero)
        foreach ($j in $rest) { for ($k = 0; $k -lt 5; $k++) { $sums[$k] = $sums[$k] + $j.D[$k] } }
        $filesOther = [ordered]@{ count = $rest.Count; b = (Get-DDFiveCounters -Values $sums) }
    }
    # perf: the same increases over every job, uploads included, and by priority
    $totals = New-Object 'System.Numerics.BigInteger[]' 8
    $foreground = $zero; $background = $zero
    foreach ($j in $jobs) {
        for ($k = 0; $k -lt 8; $k++) { $totals[$k] = $totals[$k] + $j.D[$k] }
        if ([string]$j.R['priority'] -ceq 'Foreground') { $foreground = $foreground + (Get-DDBigSum -Values $j.D) }
        elseif ([string]$j.R['priority'] -ceq 'Background') { $background = $background + (Get-DDBigSum -Values $j.D) }
    }

    # peers: aggregate by what matters for the picture (every peer listed is counted, whatever it moved), keep a few named
    $agg = [ordered]@{}
    $perPeer = [ordered]@{}
    foreach ($pd in (Get-DDPeerDeltas -Rows $peerInfo -Kind $kind -Part (& $part 'peers'))) {
        $p = $pd.P
        $same = [bool]$p['sameSubnet']
        $k = '{0}|{1}' -f $p['peerType'], $(if ($same) { 'true' } else { 'false' })
        if (-not $agg.Contains($k)) {
            $agg[$k] = @{ type = $p['peerType']; sameSubnet = $same; hashes = (New-Object 'System.Collections.Generic.HashSet[string]'); sent = $zero; received = $zero }
        }
        $a = $agg[$k]
        [void]$a.hashes.Add([string]$p['peerHash'])
        $a.sent = $a.sent + $pd.D[0]
        $a.received = $a.received + $pd.D[1]
        $h = Get-DDPeerHex16 -PeerHash ([string]$p['peerHash'])
        if ($null -ne $h -and ($pd.D[0] + $pd.D[1]) -gt $zero) {
            if (-not $perPeer.Contains($h)) { $perPeer[$h] = @{ h = $h; type = $p['peerType']; sent = $zero; received = $zero } }
            $x = $perPeer[$h]
            $x.sent = $x.sent + $pd.D[0]
            $x.received = $x.received + $pd.D[1]
        }
    }
    $peersOut = New-Object 'System.Collections.Generic.List[object]'
    foreach ($a in $agg.Values) {
        $peersOut.Add([ordered]@{ type = $a.type; sameSubnet = $a.sameSubnet; peers = $a.hashes.Count; sent = (ConvertTo-DDByteCount $a.sent); received = (ConvertTo-DDByteCount $a.received) })
    }
    $sortedPeers = Get-DDStableDescending -Items @($perPeer.Values) -Key { param($x) $x.sent + $x.received }
    $topPeersOut = New-Object 'System.Collections.Generic.List[object]'
    foreach ($x in @($sortedPeers | Select-Object -First $script:DDTopPeers)) {
        $topPeersOut.Add([ordered]@{ h = $x.h; type = $x.type; sent = (ConvertTo-DDByteCount $x.sent); received = (ConvertTo-DDByteCount $x.received) })
    }

    $conns = [ordered]@{}
    foreach ($cd in (Get-DDConnectionDeltas -Rows $connections -Kind $kind -Part (& $part 'connections'))) {
        if ($cd.D -eq 0) { continue }
        $c = $cd.C
        $connected = [bool]$c['connected']
        $k = '{0}|{1}|{2}' -f $c['peerType'], $c['statusCode'], $(if ($connected) { 'true' } else { 'false' })
        if (-not $conns.Contains($k)) { $conns[$k] = @{ type = $c['peerType']; status = $c['statusCode']; connected = $connected; n = 0 } }
        $conns[$k].n = $conns[$k].n + $cd.D
    }
    $connsOut = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in $conns.Values) { $connsOut.Add([ordered]@{ type = $c.type; status = $c.status; connected = $c.connected; n = $c.n }) }

    $recent = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($h in $RecentHresults) { [void]$recent.Add($h) }
    $errs = [ordered]@{}
    foreach ($e in $errorsIn) {
        $comp = ''; if ($null -ne $e['component']) { $comp = [string]$e['component'] }
        $k = '{0}|{1}' -f $e['hresult'], $comp
        if (-not $errs.Contains($k)) {
            $errs[$k] = @{ hresult = $e['hresult']; component = $e['component']; n = 0; first = $e['at']; last = $e['at']; files = (New-Object 'System.Collections.Generic.List[string]'); sample = $null }
        }
        $x = $errs[$k]
        $x.n = $x.n + 1
        if ([string]::CompareOrdinal([string]$e['at'], [string]$x.first) -lt 0) { $x.first = $e['at'] }
        if ([string]::CompareOrdinal([string]$e['at'], [string]$x.last) -gt 0) { $x.last = $e['at'] }
        if ($null -ne $e['fileId'] -and $x.files.Count -lt 3 -and -not $x.files.Contains([string]$e['fileId'])) { $x.files.Add([string]$e['fileId']) }
        if ($null -eq $x.sample -and $null -ne $e['raw'] -and -not $recent.Contains([string]$e['hresult'])) {
            $line = [string]$e['raw']
            $x.sample = $line.Substring(0, [math]::Min(200, $line.Length))
        }
    }
    $errsOut = New-Object 'System.Collections.Generic.List[object]'
    foreach ($x in $errs.Values) {
        $errsOut.Add([ordered]@{ hresult = $x.hresult; component = $x.component; n = $x.n; first = $x.first; last = $x.last; files = $x.files.ToArray(); sample = $x.sample })
    }

    $changed = Select-DDChangedConnectivity -Rows $connectivity -PreviousConnectivity $PreviousConnectivity

    $dev = $Raw['device']
    $net = $Raw['network']
    # Get-DeliveryOptimizationPerfSnap gives the three readings of the moment; every byte counter is the jobs' own increase.
    $perf = $null
    $snap = $Raw['perfSnap']
    if ($null -ne $snap) {
        $perf = [ordered]@{
            downloadHttpBytes       = ConvertTo-DDByteCount -Value $totals[0]
            downloadLanBytes        = ConvertTo-DDByteCount -Value $totals[1]
            downloadGroupBytes      = ConvertTo-DDByteCount -Value $totals[2]
            downloadInternetBytes   = ConvertTo-DDByteCount -Value $totals[3]
            downloadCacheHostBytes  = ConvertTo-DDByteCount -Value $totals[4]
            uploadLanBytes          = ConvertTo-DDByteCount -Value $totals[5]
            uploadGroupBytes        = ConvertTo-DDByteCount -Value $totals[6]
            uploadInternetBytes     = ConvertTo-DDByteCount -Value $totals[7]
            foregroundDownloadBytes = ConvertTo-DDByteCount -Value $foreground
            backgroundDownloadBytes = ConvertTo-DDByteCount -Value $background
            numberOfPeers           = $snap['numberOfPeers']
            cacheHostConnections    = $snap['cacheHostConnections']
            averageDownloadKBps     = $snap['averageDownloadKBps']
        }
    }

    $endpointsIn = @(); if ($null -ne $Raw['endpoints']) { $endpointsIn = @($Raw['endpoints']) }
    $endpointsOut = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in (Select-DDEndpointRows -Rows $endpointsIn -Max $script:DDTopEndpoints)) {
        $o = [ordered]@{}
        foreach ($k in $e.Keys) { $o[$k] = $e[$k] }
        $o['rx'] = $(if ($null -eq $e['rx']) { $null } else { ConvertTo-DDByteCount -Value (ConvertTo-DDBigInt $e['rx']) })
        $o['tx'] = $(if ($null -eq $e['tx']) { $null } else { ConvertTo-DDByteCount -Value (ConvertTo-DDBigInt $e['tx']) })
        $endpointsOut.Add($o)
    }

    $diagNc = @(); if ($null -ne $Diag -and $Diag.Contains('notCollected') -and $null -ne $Diag['notCollected']) { $diagNc = @($Diag['notCollected']) }
    $nc = New-Object 'System.Collections.Generic.List[object]'
    # The diagnosis records go first: with a full list the cap would drop them, and an unread diag.crash / diag.up reads as
    # "measured, healthy" (docs/08). There are at most two of them; the collection records fill the rest.
    foreach ($n in (@($diagNc) + @($notCollected) | Select-Object -First 64)) { $nc.Add($n) }
    $diagOut = ConvertTo-DDDiagSection -Diag $Diag

    $report = [ordered]@{
        schemaVersion       = 1
        kind                = 'telemetry'
        collector           = $Raw['collector']
        collectedAt         = $Raw['collectedAt']
        seq                 = $Seq
        inventoryHash       = $InventoryHash
        period              = [ordered]@{ from = $PeriodFrom; to = $PeriodTo }
        counters            = $kind
        vitals              = [ordered]@{
            onBattery        = $dev['onBattery']
            batteryPercent   = $dev['batteryPercent']
            systemDiskFreeGB = $dev['systemDiskFreeGB']
            cacheUsedBytes   = $dev['cacheUsedBytes']
            isVpnActive      = $net['isVpnActive']
            adapterType      = $net['adapterType']
            localSubnet      = $net['localSubnet']
            publicEgressHash = $net['publicEgressHash']
        }
        perf                = $perf
        files               = $filesOut.ToArray()
        filesOther          = $filesOther
        peers               = $peersOut.ToArray()
        topPeers            = $topPeersOut.ToArray()
        connections         = $connsOut.ToArray()
        connectivityChanged = $changed.ToArray()
        errors              = $errsOut.ToArray()
        notCollected        = $nc.ToArray()
        endpoints           = $endpointsOut.ToArray()
    }
    # Free space of the cache drive (docs/27 3.6): present only when the collection measured it; $null when the drive was not found.
    if ($dev -is [System.Collections.IDictionary] -and $dev.Contains('cacheDriveFreeGB')) { $report['vitals']['cacheDriveFreeGB'] = $dev['cacheDriveFreeGB'] }
    # A-05: battery low or critical, so the device page can say "On battery (low)".
    if ($dev -is [System.Collections.IDictionary] -and $dev.Contains('batteryLow')) { $report['vitals']['batteryLow'] = $dev['batteryLow'] }
    if ($null -ne $diagOut) { $report['diag'] = $diagOut }
    # Content sources (docs/08): only when the caller read the job list and passes what was summarised before. A baseline presents no
    # bytes, so it summarises no job either; Get-DDNextSourcesSeen then marks every finished job as summarised.
    if ($null -ne $SourcesSeen) {
        $allStatus = @(); if ($null -ne $Raw['status']) { $allStatus = @($Raw['status']) }
        $report['sources'] = $(if ($kind -eq 'baseline') { [ordered]@{} } else { ConvertTo-DDSourcesSection -Status $allStatus -Seen $SourcesSeen -Anonymised ([bool]$Raw['anonymised']) })
    }
    # DO's own counters for the calendar month (19 Oct 2026): sent as read, a snapshot, in a delta or snapshot report; not in a
    # baseline, which sends no byte counters (and so the state-loss report stays within the typical budget). compactMonth in compact.ts.
    if ($kind -ne 'baseline' -and $Raw.Contains('doMonth') -and $null -ne $Raw['doMonth']) { $report['month'] = ConvertTo-DDMonthSection -Month $Raw['doMonth'] }
    $report
}

function ConvertTo-DDMonthSection {
    # TelemetryV1.month from the bundle's doMonth (compactMonth in compact.ts): the same fields, byte counters as numbers when exact.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Month)
    $o = [ordered]@{ monthStart = $Month['monthStart'] }
    foreach ($k in 'httpBytes', 'cacheBytes', 'lanBytes', 'internetBytes') { $o[$k] = ConvertTo-DDByteCount -Value (ConvertTo-DDBigInt $Month[$k]) }
    $o['groupBytes'] = $(if ($null -eq $Month['groupBytes']) { $null } else { ConvertTo-DDByteCount -Value (ConvertTo-DDBigInt $Month['groupBytes']) })
    foreach ($k in 'uploadLanBytes', 'uploadInternetBytes') { $o[$k] = ConvertTo-DDByteCount -Value (ConvertTo-DDBigInt $Month[$k]) }
    $o
}

function Get-DDConnectivityState {
    # The map the next report is compared against (connectivityState in compact.ts).
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Connectivity)

    $m = [ordered]@{}
    foreach ($c in @($Connectivity)) { $m[(Get-DDConnectivityKey -Result $c)] = Get-DDConnectivityComposite -Result $c }
    $m
}
