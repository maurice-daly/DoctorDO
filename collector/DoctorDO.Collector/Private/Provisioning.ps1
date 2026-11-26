#Requires -Version 5.1
# Provisioning summary (ADR-0043): what the Enrollment Status Page tracked on this device and, read once soon after it,
# what Delivery Optimization downloaded. Microsoft documents the tracking under
# HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking ("Troubleshooting the Enrollment Status Page" and the
# EnrollmentStatusTracking CSP): per Win32 app an InstallationState (1 NotInstalled, 2 InProgress, 3 Completed, 4 Error)
# and RebootRequired (1 NotRequired, 2 SoftReboot, 3 HardReboot) under Device\Setup\Apps\Tracking\Sidecar\Win32App_{AppID}
# or the signed-in user's SID, and ESPTrackingInfo\Diagnostics, whose subkeys are named by the date and time a status was
# logged. The exact name format of those subkeys, and where the Win32 apps sit under Diagnostics, are TO-VERIFY: they are
# parsed leniently and an entry that does not parse is counted, not guessed.

Set-StrictMode -Version Latest

$script:DDEspRoot = 'SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking'
$script:DDProvisioningMaxApps = 30
$script:DDProvisioningMaxLargest = 10
# Delivery Optimization's job list is read for the summary only this soon after the last status the ESP logged: later, the
# jobs listed are this week's, not the provisioning's. How long DO keeps finished jobs is not documented.
$script:DDProvisioningDeliveryMaxHours = 168

function Get-DDEspTrackingRaw {
    <#
    .SYNOPSIS
        The EnrollmentStatusTracking key as a flat list of @{ Path; Values }, Path relative to the key ('Device\Setup\...'),
        Values name -> string. $null when the key does not exist (the device never showed the ESP). Bounded: 10 levels,
        3,000 keys, 64 values a key.
    #>
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $null }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $root = $base.OpenSubKey($script:DDEspRoot)
        if ($null -eq $root) { return $null }
        $rows = New-Object 'System.Collections.Generic.List[object]'
        $stack = New-Object 'System.Collections.Generic.Stack[object]'
        $stack.Push(@($root, '', 0))
        while ($stack.Count -gt 0 -and $rows.Count -lt 3000) {
            $item = $stack.Pop()
            $key = $item[0]
            try {
                $values = [ordered]@{}
                foreach ($n in @($key.GetValueNames() | Select-Object -First 64)) {
                    $v = $key.GetValue($n)
                    $values[[string]$n] = $(if ($v -is [byte[]]) { '(binary)' } elseif ($v -is [string[]]) { ($v -join ';') } else { [string]$v })
                }
                $rows.Add(@{ Path = [string]$item[1]; Values = $values })
                if ($item[2] -lt 10) {
                    foreach ($s in @($key.GetSubKeyNames())) {
                        $sub = $key.OpenSubKey($s)
                        if ($null -ne $sub) { $stack.Push(@($sub, $(if ($item[1]) { "$($item[1])\$s" } else { $s }), ($item[2] + 1))) }
                    }
                }
            } finally { $key.Dispose() }
        }
        while ($stack.Count -gt 0) { $stack.Pop()[0].Dispose() }
        , $rows.ToArray()
    } finally { $base.Dispose() }
}

function ConvertFrom-DDEspTimestamp {
    # A date and time in a subkey name (the ESP logs one per status), as UTC; $null when the text holds none. Accepts
    # 2026/10/18-16:19:18.153, 2026-10-18T16:19:18.153Z and the like (the exact format is TO-VERIFY).
    [CmdletBinding()]
    param([string] $Text)
    $m = [regex]::Match([string]$Text, '(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})[T _-]?(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d{1,7}))?')
    if (-not $m.Success) { return $null }
    try {
        $ms = 0
        if ($m.Groups[7].Success) { $ms = [int](([string]$m.Groups[7].Value + '000').Substring(0, 3)) }
        New-Object datetime ([int]$m.Groups[1].Value), ([int]$m.Groups[2].Value), ([int]$m.Groups[3].Value), ([int]$m.Groups[4].Value), ([int]$m.Groups[5].Value), ([int]$m.Groups[6].Value), $ms, ([System.DateTimeKind]::Utc)
    } catch { $null }
}

function ConvertTo-DDProvisioningSummary {
    <#
    .SYNOPSIS
        The inventory's `provisioning` section from the ESP tracking tree (Get-DDEspTrackingRaw) and, when it is read soon
        enough after provisioning, the DO job list (ConvertTo-DDStatusRow rows). $null without a tree. Pure.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $Tree,
        [AllowNull()][AllowEmptyCollection()] $Status,
        [double] $MinFileSizeMB = 50,
        [AllowNull()] $OsInstallDate,
        [Parameter(Mandatory)][datetime] $Now,
        # DOMaxCacheAge in effect (default 259,200 s) and this device's offset from UTC in hours, for the delivery window
        # (ConvertTo-DDProvisioningDelivery).
        [double] $MaxCacheAgeSeconds = 259200,
        [double] $ZoneOffsetHours = 0
    )
    if ($null -eq $Tree) { return $null }
    $rows = @($Tree)
    $stateName = @{ '1' = 'notInstalled'; '2' = 'inProgress'; '3' = 'completed'; '4' = 'error' }
    $rebootName = @{ '1' = 'notRequired'; '2' = 'soft'; '3' = 'hard' }
    $appRe = 'Win32App_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'

    # The apps: every Win32App_{id} key with an InstallationState, under Device\ (device setup) or a user's SID (account setup).
    $apps = [ordered]@{}
    foreach ($r in $rows) {
        $p = [string]$r.Path
        if ($p -like 'ESPTrackingInfo*') { continue }
        $leaf = ($p -split '\\')[-1]
        $m = [regex]::Match($leaf, "^$appRe(?:_\d+)?$")
        if (-not $m.Success -or -not $r.Values.Contains('InstallationState')) { continue }
        $phase = $(if ($p -like 'Device\*') { 'device' } elseif ($p -match '^S-1-') { 'user' } else { $null })
        if ($null -eq $phase) { continue }
        $id = $m.Groups[1].Value.ToLowerInvariant()
        $st = $stateName[[string]$r.Values['InstallationState']]
        $rb = $(if ($r.Values.Contains('RebootRequired')) { $rebootName[[string]$r.Values['RebootRequired']] } else { $null })
        $apps["$phase|$id"] = [ordered]@{ id = $id; phase = $phase; state = $(if ($st) { $st } else { 'unknown' }); reboot = $rb; firstStatusAt = $null; lastStatusAt = $null }
    }

    # The timeline: each Diagnostics subkey named by a date and time. A Win32 app named in its path or values is dated too.
    $first = $null; $last = $null; $unparsed = 0
    foreach ($r in $rows) {
        $p = [string]$r.Path
        if ($p -notlike 'ESPTrackingInfo\Diagnostics\*') { continue }
        $segments = @($p -split '\\' | Select-Object -Skip 2)
        $at = $null
        foreach ($s in $segments) { $t = ConvertFrom-DDEspTimestamp -Text $s; if ($null -ne $t) { $at = $t } }
        if ($null -eq $at) {
            if ($r.Values.Count -gt 0 -and $segments.Count -ge 2) { $unparsed++ }
            continue
        }
        if ($null -eq $first -or $at -lt $first) { $first = $at }
        if ($null -eq $last -or $at -gt $last) { $last = $at }
        $text = $p + ' ' + (@($r.Values.Keys) -join ' ')
        $phase = $(if ($p -match '\\S-1-') { 'user' } else { 'device' })
        foreach ($am in [regex]::Matches($text, $appRe)) {
            $k = "$phase|$($am.Groups[1].Value.ToLowerInvariant())"
            if (-not $apps.Contains($k)) { continue }
            $a = $apps[$k]
            if ($null -eq $a['firstStatusAt'] -or $at -lt $a['firstStatusAt']) { $a['firstStatusAt'] = $at }
            if ($null -eq $a['lastStatusAt'] -or $at -gt $a['lastStatusAt']) { $a['lastStatusAt'] = $at }
        }
    }

    $counts = {
        param($phase)
        $mine = @($apps.Values | Where-Object { $_['phase'] -eq $phase })
        [ordered]@{
            total = $mine.Count
            completed = @($mine | Where-Object { $_['state'] -eq 'completed' }).Count
            error = @($mine | Where-Object { $_['state'] -eq 'error' }).Count
            inProgress = @($mine | Where-Object { $_['state'] -eq 'inProgress' }).Count
            notInstalled = @($mine | Where-Object { $_['state'] -eq 'notInstalled' }).Count
        }
    }
    # An app's time needs two different dated statuses. Until the Diagnostics layout is verified (ADR-0043), one dated status
    # gives no duration: it keeps when it was seen (firstStatusAt) and leaves lastStatusAt null rather than send a span of 0.
    foreach ($a in $apps.Values) { if ($null -ne $a['firstStatusAt'] -and $a['firstStatusAt'] -eq $a['lastStatusAt']) { $a['lastStatusAt'] = $null } }
    # Longest first (unknown durations last), then by id, so the 30 kept are the ones worth looking at and the order is stable.
    $ordered = @($apps.Values | Sort-Object -Property @{ Expression = { if ($_['firstStatusAt'] -and $_['lastStatusAt']) { ($_['lastStatusAt'] - $_['firstStatusAt']).TotalSeconds } else { -1 } }; Descending = $true }, @{ Expression = { $_['phase'] } }, @{ Expression = { $_['id'] } })
    $appRows = @($ordered | Select-Object -First $script:DDProvisioningMaxApps | ForEach-Object {
            [ordered]@{
                id = $_['id']; phase = $_['phase']; state = $_['state']; reboot = $_['reboot']
                firstStatusAt = $(if ($_['firstStatusAt']) { Format-DDIso -Value $_['firstStatusAt'] } else { $null })
                lastStatusAt = $(if ($_['lastStatusAt']) { Format-DDIso -Value $_['lastStatusAt'] } else { $null })
            }
        })

    [ordered]@{
        esp = [ordered]@{
            firstStatusAt = $(if ($first) { Format-DDIso -Value $first } else { $null })
            lastStatusAt = $(if ($last) { Format-DDIso -Value $last } else { $null })
            statusesUnparsed = $unparsed
            deviceSetup = (& $counts 'device')
            accountSetup = (& $counts 'user')
        }
        appsTotal = $apps.Count
        apps = $appRows
        delivery = (ConvertTo-DDProvisioningDelivery -Status $Status -MinFileSizeMB $MinFileSizeMB -EspLast $last -OsInstallDate $OsInstallDate -Now $Now `
                -EspFirst $first -MaxCacheAgeSeconds $MaxCacheAgeSeconds -ZoneOffsetHours $ZoneOffsetHours)
    }
}

function ConvertTo-DDProvisioningDelivery {
    <#
    .SYNOPSIS
        What DO's job list held, summed by priority, when it is read within DDProvisioningDeliveryMaxHours of provisioning
        (the ESP's last status, or the OS install date when no status was dated). $null otherwise, or without a job list.
    .DESCRIPTION
        With a dated ESP (-EspFirst and -EspLast), only the jobs of the ESP's own time are summed, so a week of ordinary
        downloads read later is not counted as provisioning. A job is dated by its ExpireOn less DOMaxCacheAge (Learn:
        DOMaxCacheAge is how long a file is held "after downloading successfully"; DoctorDO's inference, to-verify), and
        kept when that falls between the ESP's first status and an hour after its last. Because the zone of the
        Diagnostics subkey names is to-verify (ADR-0043), the window is widened by the device's offset from UTC on both
        sides. A job that cannot be dated is left out; the jobs left out are counted (jobsOutsideEsp). When none is left,
        the result is $null (nothing attributable yet), never zero bytes. Without a cache age to subtract (0, unlimited) or
        a dated ESP, every job is summed, as before.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()] $Status, [double] $MinFileSizeMB, [AllowNull()] $EspLast, [AllowNull()] $OsInstallDate, [Parameter(Mandatory)][datetime] $Now,
        [AllowNull()] $EspFirst = $null, [double] $MaxCacheAgeSeconds = 259200, [double] $ZoneOffsetHours = 0)
    if ($null -eq $Status) { return $null }
    $anchor = $null; $anchorAt = $null
    if ($EspLast -is [datetime]) { $anchor = 'esp'; $anchorAt = $EspLast }
    elseif ($OsInstallDate) {
        $d = [datetime]::MinValue
        if ([datetime]::TryParse([string]$OsInstallDate, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $anchor = 'os-install'; $anchorAt = $d }
    }
    if ($null -eq $anchorAt) { return $null }
    $slack = [math]::Abs($ZoneOffsetHours)
    $ageHours = [math]::Round(($Now.ToUniversalTime() - $anchorAt).TotalHours, 1)
    # A last status up to the zone offset in the future is the unverified zone, not a clock fault: read as just now.
    if ($ageHours -lt 0 -and $anchor -eq 'esp' -and -$ageHours -le $slack) { $ageHours = 0 }
    if ($ageHours -lt 0 -or $ageHours -gt $script:DDProvisioningDeliveryMaxHours) { return $null }

    $outside = $null
    $all = @($Status | Where-Object { $null -ne $_ })
    if ($anchor -eq 'esp' -and $EspFirst -is [datetime] -and $MaxCacheAgeSeconds -gt 0) {
        $from = $EspFirst.AddHours(-$slack); $to = $EspLast.AddHours($slack + 1)
        $inEsp = @($all | Where-Object {
                $e = [datetime]::MinValue
                $ok = $_['expireOn'] -and [datetime]::TryParse([string]$_['expireOn'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$e)
                if ($ok) { $at = $e.AddSeconds(-$MaxCacheAgeSeconds); $ok = ($at -ge $from -and $at -le $to) }
                $ok
            })
        $outside = $all.Count - $inEsp.Count
        if ($inEsp.Count -eq 0) { return $null }
        $all = $inEsp
    }

    $big = { param($v) $n = [System.Numerics.BigInteger]::Zero; [void][System.Numerics.BigInteger]::TryParse([string]$v, [ref]$n); $n }
    $mix = { [ordered]@{ jobs = 0; http = [System.Numerics.BigInteger]::Zero; cache = [System.Numerics.BigInteger]::Zero; lan = [System.Numerics.BigInteger]::Zero; group = [System.Numerics.BigInteger]::Zero; internet = [System.Numerics.BigInteger]::Zero; downloadMs = [int64]0 } }
    $fg = & $mix; $bg = & $mix
    $minBytes = [System.Numerics.BigInteger]([math]::Floor($MinFileSizeMB * 1MB))
    $below = 0; $belowBytes = [System.Numerics.BigInteger]::Zero
    $rows = $all
    foreach ($r in $rows) {
        $t = $(if ([string]$r['priority'] -eq 'foreground') { $fg } else { $bg })
        $t['jobs']++
        $t['http'] += (& $big $r['bytesFromHttp']); $t['cache'] += (& $big $r['bytesFromCacheServer'])
        $t['lan'] += (& $big $r['bytesFromLanPeers']); $t['group'] += (& $big $r['bytesFromGroupPeers']); $t['internet'] += (& $big $r['bytesFromInternetPeers'])
        if ($null -ne $r['downloadMs']) { $t['downloadMs'] += [int64]$r['downloadMs'] }
        $size = & $big $r['fileSize']
        if ($size -lt $minBytes) { $below++; $belowBytes += $size }
    }
    $out = { param($t) [ordered]@{ jobs = $t['jobs']; bytes = [ordered]@{ http = $t['http'].ToString(); cache = $t['cache'].ToString(); lan = $t['lan'].ToString(); group = $t['group'].ToString(); internet = $t['internet'].ToString() }; downloadMs = $t['downloadMs'] } }
    $largest = @($rows | Sort-Object -Property @{ Expression = { & $big $_['fileSize'] }; Descending = $true }, @{ Expression = { [string]$_['fileId'] } } | Select-Object -First $script:DDProvisioningMaxLargest | ForEach-Object {
            $caller = $(if ($_['predefinedCallerApplication']) { ([string]$_['predefinedCallerApplication']) } else { $null })
            if ($caller -and $caller.Length -gt 64) { $caller = $caller.Substring(0, 64) }
            [ordered]@{
                sizeBytes = (& $big $_['fileSize']).ToString(); priority = $(if ([string]$_['priority'] -eq 'foreground') { 'foreground' } else { 'background' })
                http = (& $big $_['bytesFromHttp']).ToString(); cache = (& $big $_['bytesFromCacheServer']).ToString()
                peers = ((& $big $_['bytesFromLanPeers']) + (& $big $_['bytesFromGroupPeers']) + (& $big $_['bytesFromInternetPeers'])).ToString()
                downloadMs = $(if ($null -ne $_['downloadMs']) { [int64]$_['downloadMs'] } else { $null }); caller = $caller
            }
        })
    $d = [ordered]@{
        capturedAt = (Format-DDIso -Value $Now); anchor = $anchor; ageHours = $ageHours; jobs = $rows.Count
        foreground = (& $out $fg); background = (& $out $bg)
        belowMinFileSize = [ordered]@{ jobs = $below; bytes = $belowBytes.ToString(); minFileSizeMB = $MinFileSizeMB }
        largest = $largest
    }
    if ($null -ne $outside) { $d['jobsOutsideEsp'] = $outside }
    $d
}

function Resolve-DDProvisioning {
    # The section to send: the tracking (apps, timeline) as read now, which is final once the ESP has finished, and the
    # delivery snapshot as first captured, kept in the state file so later runs do not replace provisioning's downloads with
    # this week's. $null when the device has no ESP tracking.
    [CmdletBinding()]
    param([AllowNull()] $Fresh, [AllowNull()] $Stored)
    if ($null -eq $Fresh) { return $null }
    $out = [ordered]@{}
    foreach ($k in $Fresh.Keys) { $out[$k] = $Fresh[$k] }
    if ($Stored -is [System.Collections.IDictionary] -and $null -ne $Stored['delivery']) { $out['delivery'] = $Stored['delivery'] }
    $out
}
