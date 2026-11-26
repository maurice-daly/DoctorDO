#Requires -Version 5.1
# Mapping of Delivery Optimization cmdlet output to the BundleV1 row shapes (packages/schema/src/telemetry.ts).
#
# Property names of the DeliveryOptimization module's output objects (DOSwarmStats, DOFilePeerInfo, DOPeerInfo,
# DOPerfSnap, DOLogEntry) are only partly documented on Microsoft Learn (the cmdlet pages are stubs), so each
# mapper looks a field up under the candidate names seen in the monitoring article and reports what it could not
# find. All of that is `to-verify` until a Windows lab pass; the mappers are pure and tested on synthetic objects.

Set-StrictMode -Version Latest

$script:DDModeNames = @{ cdnonly = 0; httponly = 0; lan = 1; group = 2; internet = 3; simple = 99; bypass = 100 }

function ConvertTo-DDDownloadMode {
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return -1 }
    $n = 0
    if ([int]::TryParse([string]$Value, [ref]$n)) { return $n }
    $k = ([string]$Value).ToLowerInvariant()
    if ($script:DDModeNames.ContainsKey($k)) { return [int]$script:DDModeNames[$k] }
    -1
}

function ConvertTo-DDPriority {
    [CmdletBinding()]
    param($Value)
    $s = [string]$Value
    if ($s -match '(?i)^fore') { return 'Foreground' }
    if ($s -match '(?i)^back') { return 'Background' }
    'Unknown'
}

# PeerType as DeliveryOptimizationStatus.psm1 declares it (enum PeerType, read on Windows 11 26H2): 0 none, 1 LAN, 2 CDN,
# 3 Internet, 4 Group, 5 DOINC (Connected Cache), 6 LocalCache, 7 LinkLocal. The cmdlet emits the enum name
# ("PeerType_LAN"); the CIM class MSFT_DeliveryOptimizationFilePeerInfo emits the number. LocalCache is taken as a cache
# server (inferred from the name; not documented).
$script:DDPeerTypeNumbers = @{ 1 = 'Lan'; 2 = 'Cdn'; 3 = 'Internet'; 4 = 'Group'; 5 = 'CacheServer'; 6 = 'CacheServer'; 7 = 'Lan' }

function ConvertTo-DDPeerType {
    [CmdletBinding()]
    param($Value, [switch] $AllowCdn)
    $t = 'Unknown'
    $n = 0
    if ($null -ne $Value -and [int]::TryParse([string]$Value, [ref]$n)) {
        if ($script:DDPeerTypeNumbers.ContainsKey($n)) { $t = $script:DDPeerTypeNumbers[$n] }
    } else {
        $s = ([string]$Value) -replace '(?i)^PeerType_', ''
        switch -Regex ($s) {
            '(?i)^lan$|linklocal' { $t = 'Lan'; break }
            '(?i)^group' { $t = 'Group'; break }
            '(?i)^internet|^inet$' { $t = 'Internet'; break }
            '(?i)cache|^doinc$' { $t = 'CacheServer'; break }
            '(?i)^cdn$|^http$' { $t = 'Cdn'; break }
        }
    }
    if ($t -eq 'Cdn' -and -not $AllowCdn) { return 'Unknown' }
    $t
}

function ConvertTo-DDCacheHostName {
    # A Connected Cache host as DO reports it ([uri] on DOSwarmStats, text in the log and in policy), reduced to the bare
    # host or address: never a scheme, path, credentials or port. Anything that does not look like a host is dropped.
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $s = $s -replace '^(?i)[a-z][a-z0-9+.-]*://', ''
    $s = ($s -split '[/?#]')[0]
    if ($s.Contains('@')) { $s = $s.Substring($s.LastIndexOf('@') + 1) }
    if ($s -match '^\[(?<v6>[0-9A-Fa-f:.]+)\](:\d+)?$') { $s = $Matches['v6'] }
    elseif ($s -match '^(?<h>[^:]+):\d+$') { $s = $Matches['h'] }
    $s = $s.TrimEnd('.').ToLowerInvariant()
    if ($s.Length -gt 253 -or $s -notmatch '^[a-z0-9.:-]+$') { return $null }
    $s
}

function Get-DDUrlPathHint {
    [CmdletBinding()]
    param([AllowNull()][string] $Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    $u = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$u)) { return $null }
    # Microsoft Update catalog layout, /<shard>/msdownload/update/<software|driver>/<category>/...: the first two
    # segments are a shard letter and a constant, so the classifying pair is the kind and the category
    # (e.g. /software/defu). Observed on au.download.windowsupdate.com; meaning of each category is to-verify.
    if ($u.AbsolutePath -match '(?i)^/[a-z0-9]{1,2}/msdownload/update/(software|driver)/([a-z0-9]{2,8})(/|$)') {
        return '/{0}/{1}' -f $Matches[1].ToLowerInvariant(), $Matches[2].ToLowerInvariant()
    }
    $segs = @($u.AbsolutePath.Split('/') | Where-Object { $_ -ne '' -and $_ -notmatch '^[0-9a-fA-F-]{8,}$' } | Select-Object -First 2)
    if ($segs.Count -eq 0) { return $null }
    '/' + ($segs -join '/')
}

function ConvertTo-DDDownloadMs {
    <#
    .SYNOPSIS
        DownloadDuration in whole milliseconds, or $null. Microsoft documents it as "Total download time in seconds" (Monitor
        Delivery Optimization); the cmdlet returns a [TimeSpan] (verified on Windows 11 26H2), which is what this reads. A
        number, or text that is only a number ("172"), is taken as seconds, as documented, and text in TimeSpan form
        ("00:02:52.0970000") is parsed. Anything else is $null.
    #>
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    $ms = $null
    if ($Value -is [timespan]) { $ms = $Value.TotalMilliseconds }
    elseif ($Value -is [string]) {
        # A plain number is seconds, as documented. TimeSpan.TryParse would read '172' as 172 days.
        $d = 0.0
        $ts = [timespan]::Zero
        if ($Value.Trim() -match '^\d+(\.\d+)?$' -and [double]::TryParse($Value.Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $ms = $d * 1000 }
        elseif ([timespan]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$ts)) { $ms = $ts.TotalMilliseconds }
    } elseif ($Value -is [ValueType]) {
        $d = 0.0
        if ([double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $ms = $d * 1000 }
    }
    if ($null -eq $ms -or [double]::IsNaN($ms) -or $ms -lt 0 -or $ms -gt 9e15) { return $null }
    [long][math]::Round($ms, [System.MidpointRounding]::AwayFromZero)
}

function ConvertTo-DDStatusRow {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Item, [Parameter(Mandatory)] $Context)

    $url = Get-DDProp $Item 'SourceURL', 'SourceUrl'
    # ADR-0031: the Connected Cache server is infrastructure and is sent in clear, under -Anonymise as well.
    $cache = ConvertTo-DDCacheHostName (Get-DDProp $Item 'CacheHost')
    # Under -Anonymise a source host that is not a Microsoft content host (a customer's WSUS, file server or internal web
    # server) is pseudonymised like other internal topology, with the tenant's salt so the same server compares equal across the
    # tenant's devices. A Microsoft CDN host says nothing about the organisation.
    $urlHost = Get-DDUrlHost -Url ([string]$url)
    if ($Context.Anonymise -and $urlHost -and -not (Test-DDMicrosoftContentHost -HostName $urlHost)) { $urlHost = Protect-DDTopologyValue -Value $urlHost -Salt $Context.TenantSalt }
    # Documented: BytesFromHTTP "represents all HTTP sources, which includes BytesFromCacheServer". The contract's five
    # sources are disjoint (buildDeviceFlow sums them), so the cache bytes are taken out of the HTTP figure here.
    $httpAll = ConvertTo-DDBigInt (Get-DDProp $Item 'BytesFromHttp', 'BytesFromHTTP')
    $cacheBytes = ConvertTo-DDBigInt (Get-DDProp $Item 'BytesFromCacheServer')
    # A cache figure above the HTTP one (two counters read a moment apart) means the HTTP bytes all came from the cache: none
    # are left over, rather than counting the cache bytes twice.
    $httpOnly = $(if ($httpAll -ge $cacheBytes) { $httpAll - $cacheBytes } else { [System.Numerics.BigInteger]::Zero })
    $expire = Get-DDProp $Item 'ExpireOn'
    $expireIso = $null
    if ($expire -is [datetime]) { $expireIso = Format-DDIso -Value $expire }
    $caller = Get-DDProp $Item 'PredefinedCallerApplication'
    $numPeers = Get-DDProp $Item 'NumPeers'
    # A mode name the lookup does not know is sent as -1 ("unknown"), and named once in notCollected so it is not silent.
    $modeRaw = Get-DDProp $Item 'DownloadMode'
    $mode = ConvertTo-DDDownloadMode $modeRaw
    if ($mode -eq -1 -and $null -ne $modeRaw) { Add-DDNotCollected -Context $Context -Field 'status.downloadMode' -Reason 'error' -Detail ("a job's DownloadMode '{0}' is not a known mode; sent as -1" -f ([string]$modeRaw).Substring(0, [math]::Min(40, ([string]$modeRaw).Length))) }
    [ordered]@{
        fileId                      = [string](Get-DDProp $Item 'FileId', 'File ID')
        fileSize                    = (ConvertTo-DDBigInt (Get-DDProp $Item 'FileSize')).ToString()
        totalBytesDownloaded        = (ConvertTo-DDBigInt (Get-DDProp $Item 'TotalBytesDownloaded')).ToString()
        bytesFromHttp               = $httpOnly.ToString()
        bytesFromLanPeers           = (ConvertTo-DDBigInt (Get-DDProp $Item 'BytesFromLanPeers')).ToString()
        bytesFromGroupPeers         = (ConvertTo-DDBigInt (Get-DDProp $Item 'BytesFromGroupPeers')).ToString()
        bytesFromInternetPeers      = (ConvertTo-DDBigInt (Get-DDProp $Item 'BytesFromInternetPeers')).ToString()
        bytesFromCacheServer        = (ConvertTo-DDBigInt (Get-DDProp $Item 'BytesFromCacheServer')).ToString()
        downloadMode                = $mode
        status                      = [string](Get-DDProp $Item 'Status')
        priority                    = (ConvertTo-DDPriority (Get-DDProp $Item 'Priority'))
        numPeers                    = $(if ($null -ne $numPeers) { [math]::Max(0, [int]$numPeers) } else { 0 })
        predefinedCallerApplication = $(if ($null -ne $caller) { [string]$caller } else { $null })
        sourceUrlHost               = $urlHost
        sourceUrlPathHint           = (Get-DDUrlPathHint -Url ([string]$url))
        expireOn                    = $expireIso
        cacheHost                   = $cache
        # The job's whole DownloadDuration, waits included: what TelemetryV1.sources times a source by (docs/08).
        downloadMs                  = (ConvertTo-DDDownloadMs (Get-DDProp $Item 'DownloadDuration'))
        # What the job served to peers, by where they were found (documented: BytesToLanPeers, BytesToGroupPeers,
        # BytesToInternetPeers), running totals like the download counters: telemetry sends what they rose by (docs/08).
        bytesToLanPeers             = (ConvertTo-DDBigInt (Get-DDProp $Item 'BytesToLanPeers')).ToString()
        bytesToGroupPeers           = (ConvertTo-DDBigInt (Get-DDProp $Item 'BytesToGroupPeers')).ToString()
        bytesToInternetPeers        = (ConvertTo-DDBigInt (Get-DDProp $Item 'BytesToInternetPeers')).ToString()
    }
}

function ConvertTo-DDPeerRows {
    <#
    .SYNOPSIS
        Flatten `Get-DeliveryOptimizationStatus -PeerInfo` output. Accepts per-file objects that carry a
        collection of peers, or flat peer rows. Peer addresses are hashed here and never leave this function.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()] $Items,
        [Parameter(Mandatory)] $Context,
        [string] $LocalAddress,
        [int] $PrefixLength = 24,
        # The device's IPv6 prefixes (Get-DDNetworkFacts LocalNetworks), so an IPv6 peer on this network counts as same-subnet (A-14).
        [AllowNull()][AllowEmptyCollection()][string[]] $LocalNetworks = @()
    )
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $emit = {
        param($peer, $fileId)
        $ip = [string](Get-DDProp $peer 'IP', 'IPAddress', 'PeerIP')
        if (-not $ip) { return }
        $type = ConvertTo-DDPeerType (Get-DDProp $peer 'PeerType') -AllowCdn
        if ($type -eq 'Cdn') { return }  # an HTTP source listed among the swarm's connections is not a peer
        $same = $false
        if ($LocalAddress -or @($LocalNetworks).Count -gt 0) { $same = Test-DDSameSubnet -Address $ip -LocalAddress ([string]$LocalAddress) -PrefixLength $PrefixLength -LocalNetworks $LocalNetworks }
        if ($type -eq 'Lan' -and -not $LocalAddress) { $same = $true }
        $rows.Add([ordered]@{
                fileId        = $(if ($fileId) { [string]$fileId } else { 'unknown' })
                peerHash      = (Get-DDSaltedHash -Value $ip -Salt $Context.TenantSalt -Domain 'peer')
                peerType      = $type
                sameSubnet    = [bool]$same
                bytesSent     = (ConvertTo-DDBigInt (Get-DDProp $peer 'BytesSent')).ToString()
                bytesReceived = (ConvertTo-DDBigInt (Get-DDProp $peer 'BytesReceived')).ToString()
            })
    }
    foreach ($it in @($Items)) {
        # DOFilePeerInfo carries its peers in PeersInfo (DeliveryOptimizationStatus.psm1); Peers is this module's own shape.
        $inner = Get-DDProp $it 'Peers', 'PeersInfo', 'PeerInfo'
        $fid = Get-DDProp $it 'FileId', 'File ID'
        if ($null -ne $inner -and $inner -isnot [string]) { foreach ($p in @($inner)) { & $emit $p $fid } }
        elseif ($it -isnot [string]) { & $emit $it $fid }
    }
    , $rows.ToArray()
}

function ConvertTo-DDPerfSnap {
    <#
    .SYNOPSIS
        PerfSnapV1: the readings of `Get-DeliveryOptimizationPerfSnap` (documented: NumberOfPeers, CacheHostConnections,
        DownlinkUsageBps) and the byte counters of the jobs in the cache.
    .DESCRIPTION
        Microsoft documents no per-source byte totals for the service, so the byte counters are the running totals of the
        current Delivery Optimization jobs (Get-DeliveryOptimizationStatus): bytes by source, uploads by peer type
        (BytesTo*Peers) and bytes by priority. Telemetry never sends these sums: it sends each job's own increase since the last
        report (Compact.ps1, docs/08), so a job leaving the cache is not mistaken for a service restart. Collectors before 0.6.0
        read the byte counters from the undocumented -Verbose text when it parsed.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $Item,
        [AllowEmptyCollection()] $StatusRows = @()
    )
    if ($null -eq $Item) { return $null }
    $zero = [System.Numerics.BigInteger]::Zero
    $sum = {
        param($name)
        $t = $zero
        foreach ($r in @($StatusRows)) { $t += (ConvertTo-DDBigInt $r[$name]) }
        $t
    }
    $sumPriority = {
        param($pri)
        $t = $zero
        foreach ($r in @($StatusRows)) { if ($r['priority'] -eq $pri) { $t += (ConvertTo-DDBigInt $r['totalBytesDownloaded']) } }
        $t
    }
    $out = [ordered]@{
        downloadHttpBytes       = (& $sum 'bytesFromHttp').ToString()
        downloadLanBytes        = (& $sum 'bytesFromLanPeers').ToString()
        downloadGroupBytes      = (& $sum 'bytesFromGroupPeers').ToString()
        downloadInternetBytes   = (& $sum 'bytesFromInternetPeers').ToString()
        downloadCacheHostBytes  = (& $sum 'bytesFromCacheServer').ToString()
        uploadLanBytes          = (& $sum 'bytesToLanPeers').ToString()
        uploadGroupBytes        = (& $sum 'bytesToGroupPeers').ToString()
        uploadInternetBytes     = (& $sum 'bytesToInternetPeers').ToString()
        foregroundDownloadBytes = (& $sumPriority 'Foreground').ToString()
        backgroundDownloadBytes = (& $sumPriority 'Background').ToString()
    }
    $peers = Get-DDProp $Item 'NumberOfPeers', 'NumPeers'
    $cacheConn = Get-DDProp $Item 'CacheHostConnections'
    $down = Get-DDProp $Item 'DownlinkUsageBps'
    $out['numberOfPeers'] = $(if ($null -ne $peers) { [math]::Max(0, [int]$peers) } else { 0 })
    $out['cacheHostConnections'] = $(if ($null -ne $cacheConn) { [math]::Max(0, [int]$cacheConn) } else { $null })
    # DownlinkUsageBps is "average bandwidth currently used by Delivery Optimization for downloads"; the unit behind
    # "Bps" is not stated (to-verify). Treated as bytes per second, reported in KB/s.
    $out['averageDownloadKBps'] = $(if ($null -ne $down) { [math]::Round([math]::Max(0, [double]$down) / 1024, 1) } else { $null })
    $out
}

function ConvertTo-DDMonthTotals {
    <#
    .SYNOPSIS
        DoMonthTotals (BundleV1.doMonth): Delivery Optimization's own byte counters for the current calendar month, from
        `Get-DeliveryOptimizationPerfSnapThisMonth` (product owner, 19 Oct 2026: the "Delivery Optimization statistics" that
        Get-AutopilotDiagnostics prints from the same cmdlet).
    .DESCRIPTION
        Microsoft Learn (Monitor Delivery Optimization) says the cmdlet "returns data similar to data from
        Get-DeliveryOptimizationPerfSnap but limited to the current calendar month" and lists no fields. The names read here are
        the cmdlet's own properties on Windows 11 26H2 (19 Oct 2026): MonthStartDate, DownloadHttpBytes, DownloadCacheHostBytes,
        DownloadLanBytes, DownloadInternetBytes, UploadLanBytes, UploadInternetBytes. That build has no DownloadGroupBytes; it is
        read when a build has it and is otherwise null, never 0. DownloadHttpBytes includes the Connected Cache bytes, as Learn
        documents for the job-level BytesFromHTTP ("all HTTP sources, which includes BytesFromCacheServer").
        $null when there is no snapshot or it has no DownloadHttpBytes (a build whose cmdlet returns another shape): the caller
        records `doMonth` as not collected. Byte counters are decimal strings, as the bundle's other counters are.
    #>
    [CmdletBinding()]
    param([AllowNull()] $Item)
    if ($null -eq $Item -or $null -eq (Get-DDProp $Item 'DownloadHttpBytes')) { return $null }
    $count = {
        param($name)
        $v = ConvertTo-DDBigInt (Get-DDProp $Item $name)
        if ($v.Sign -lt 0) { $v = [System.Numerics.BigInteger]::Zero }
        $v.ToString()
    }
    $start = Get-DDProp $Item 'MonthStartDate'
    $group = Get-DDProp $Item 'DownloadGroupBytes'
    [ordered]@{
        # The device's own calendar date of the month's first day (the cmdlet returns local midnight).
        monthStart          = $(if ($start -is [datetime]) { $start.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) } else { $null })
        httpBytes           = (& $count 'DownloadHttpBytes')
        cacheBytes          = (& $count 'DownloadCacheHostBytes')
        lanBytes            = (& $count 'DownloadLanBytes')
        internetBytes       = (& $count 'DownloadInternetBytes')
        groupBytes          = $(if ($null -ne $group) { & $count 'DownloadGroupBytes' } else { $null })
        uploadLanBytes      = (& $count 'UploadLanBytes')
        uploadInternetBytes = (& $count 'UploadInternetBytes')
    }
}

# An HRESULT in a DO log message, in the three shapes the log uses: 0x80D02002 anywhere, "hr: 8007274c" (the peer-connect
# failure line, bare hex) and "errorCode = 80D02002" / "errorCode = 0x80D02002". Only failure codes (0x8...) are taken.
$script:DDHresultRx = '(?i)\b0x(?<h>8[0-9a-f]{7})\b|\b(?:hr|hresult|error ?code)\s*[:=]\s*(?:0x)?(?<h>8[0-9a-f]{7})\b'

function ConvertTo-DDErrorRows {
    <#
    .SYNOPSIS
        Extract HRESULTs from Delivery Optimization log entries (DOLogEntry: TimeCreated, Function, Message), normalised to
        0x and eight upper-case hex digits whichever shape the line used ($script:DDHresultRx).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()] $Entries,
        [Parameter(Mandatory)] $Context,
        [datetime] $Since = [datetime]::MinValue,
        [string[]] $KnownFileIds = @(),
        [int] $Max = 2000
    )
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in @($Entries)) {
        if ($rows.Count -ge $Max) { break }
        $msg = [string](Get-DDProp $e 'Message')
        if (-not $msg) { continue }
        $m = [regex]::Match($msg, $script:DDHresultRx)
        if (-not $m.Success) { continue }
        $t = Get-DDProp $e 'TimeCreated', 'Time', 'Timestamp'
        if ($t -isnot [datetime]) { continue }
        if ($t.ToUniversalTime() -lt $Since) { continue }
        $fn = Get-DDProp $e 'Function', 'Component'
        $fileId = $null
        foreach ($f in $KnownFileIds) { if ($f -and $msg.Contains($f)) { $fileId = $f; break } }
        $scrub = Protect-DDLogText -Text $msg -Anonymise:$Context.Anonymise -Salt $Context.Salt -ComputerName $Context.ComputerName
        $raw = ('{0} {1}: {2}' -f (Format-DDIso $t), $fn, $scrub)
        $rows.Add([ordered]@{
                at        = (Format-DDIso $t)
                hresult   = ('0x' + $m.Groups['h'].Value.ToUpperInvariant())
                component = $(if ($fn) { [string]$fn } else { $null })
                fileId    = $fileId
                message   = $scrub.Substring(0, [math]::Min(200, $scrub.Length))
                raw       = $raw.Substring(0, [math]::Min(2048, $raw.Length))
            })
    }
    , $rows.ToArray()
}

function ConvertTo-DDConnectionRows {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Items, [Parameter(Mandatory)] $Context)

    $rows = New-Object 'System.Collections.Generic.List[object]'
    $unrecognised = 0
    foreach ($c in @($Items)) {
        $dest = [string](Get-DDProp $c 'DestinationIP', 'DestinationIp', 'Destination', 'IP', 'PeerIP')
        if (-not $dest) { $unrecognised++; continue }
        $status = Get-DDProp $c 'StatusCode', 'Status', 'Result', 'ErrorCode'
        $conn = Get-DDProp $c 'Connected', 'ConnectionEstablished', 'IsConnected'
        $rows.Add([ordered]@{
                fileId          = $(if (Get-DDProp $c 'FileId') { [string](Get-DDProp $c 'FileId') } else { 'unknown' })
                destinationHash = (Get-DDSaltedHash -Value $dest -Salt $Context.TenantSalt -Domain 'peer')
                peerType        = (ConvertTo-DDPeerType (Get-DDProp $c 'PeerType', 'Type'))
                statusCode      = $(if ($null -ne $status) { [string]$status } else { '' })
                connected       = $(if ($null -ne $conn) { [bool]$conn } else { ([string]$status -match '^(200|0|Success)$') })
                bytesSent       = (ConvertTo-DDBigInt (Get-DDProp $c 'BytesSent')).ToString()
                bytesReceived   = (ConvertTo-DDBigInt (Get-DDProp $c 'BytesReceived')).ToString()
            })
    }
    if ($unrecognised -gt 0) {
        Add-DDNotCollected -Context $Context -Field 'connections' -Reason 'error' -Detail "$unrecognised connection row(s) had no destination the collector recognises (this Windows build may name it differently); left out"
    }
    , $rows.ToArray()
}

# Get-DOConfig property -> CSP setting name. Source (documented): "Monitor Delivery Optimization", section
# "Get-DOConfig -Verbose" https://learn.microsoft.com/windows/deployment/do/waas-delivery-optimization-monitor
# The two *Bps limits are reported in the cmdlet's unit, which is not stated (to-verify), so they are NOT folded
# into the KB/s policies DOMaxBackgroundDownloadBandwidth / DOMaxForegroundDownloadBandwidth: they keep their own names.
$script:DDDoConfigNames = @{
    batterypcttoseed                  = 'DOMinBatteryPercentageAllowedToUpload'
    mintotaldisksize                  = 'DOMinDiskSizeAllowedToPeer'
    mintotalram                       = 'DOMinRAMAllowedToPeer'
    vpnpeercachingallowed             = 'DOAllowVPNPeerCaching'
    sethourstolimitdownloadbackground = 'DOSetHoursToLimitBackgroundDownloadBandwidth'
    sethourstolimitdownloadforeground = 'DOSetHoursToLimitForegroundDownloadBandwidth'
    downloadmode                      = 'DODownloadMode'
    downbacklimitpct                  = 'DOPercentageMaxBackgroundBandwidth'
    downloadforegroundlimitpct        = 'DOPercentageMaxForegroundBandwidth'
    maxuploadratepct                  = 'DOMaxUploadBandwidth'
    uploadlimitmonthlygb              = 'DOMonthlyUploadDataCap'
    downbacklimitbps                  = 'DownBackLimitBps'
    downloadforegroundlimitbps        = 'DownloadForegroundLimitBps'
}
$script:DDDoConfigNotSettings = 'workingdirectory', 'vpnkeywords'

# Get-DOConfig's provider property names that do not follow "<setting>Provider" (DOConfig: MaxUploadRatePct is paired
# with MaxUploadRateProvider).
$script:DDDoConfigProviderAlias = @{ maxuploadrate = 'maxuploadratepct' }

function ConvertTo-DDProviderKind {
    <#
    .SYNOPSIS
        Who set a value, from Get-DOConfig's provider. Returns mdm, gp, local, admin, default or unknown.
    .DESCRIPTION
        Verified on Windows 11 26H2: the provider is a property of the output object typed as the module's enum
        ConfigProvider { RegistryProvider = 5; MdmProvider = 7; SettingsProvider = 8 ("Settings (UX) provider");
        AdminProvider = 9 ("Admin provider (powershell, WMI, etc.)"); DefaultProvider = 99 }, and the DO log's own
        downloadModeSrc field carries the same numbers. RegistryProvider is read as Group Policy: it is the provider for
        the registry-backed policy key (inferred from the name; the registry cross-check in Resolve-DDSettingSources
        confirms it per setting). The documented text form "Mdm Provider" / "Default Provider" is accepted too.
    #>
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return 'unknown' }
    $n = 0
    if ($Value -isnot [System.Enum] -and [int]::TryParse([string]$Value, [ref]$n)) {
        switch ($n) { 5 { return 'gp' } 7 { return 'mdm' } 8 { return 'local' } 9 { return 'admin' } 99 { return 'default' } default { return 'unknown' } }
    }
    $t = [string]$Value
    if ($t -match '(?i)^mdm') { return 'mdm' }
    if ($t -match '(?i)^registry|group|gpo') { return 'gp' }
    if ($t -match '(?i)^settings') { return 'local' }
    if ($t -match '(?i)^admin') { return 'admin' }
    if ($t -match '(?i)^default') { return 'default' }
    'unknown'
}

function ConvertTo-DDProviderName {
    # The contract's `provider` field (Mdm, GroupPolicy, Default, Unknown). The richer answer travels in `source`.
    [CmdletBinding()]
    param([AllowNull()] $Text)
    $k = $(if ([string]$Text -cin 'mdm', 'gp', 'local', 'admin', 'default', 'unknown') { [string]$Text } else { ConvertTo-DDProviderKind -Value $Text })
    switch ($k) {
        'mdm' { 'Mdm' } 'gp' { 'GroupPolicy' } 'default' { 'Default' } default { 'Unknown' }
    }
}

function ConvertFrom-DDDoConfig {
    <#
    .SYNOPSIS
        Build doConfig.effective from `Get-DOConfig -Verbose`.
    .DESCRIPTION
        Values come from the output object, whose property names are documented but are NOT the CSP names
        (MinTotalRAM is DOMinRAMAllowedToPeer): they are mapped through $script:DDDoConfigNames.

        Providers: on current Windows (verified on 26H2) each setting's provider is a property of the same object,
        "<Name>Provider", typed as the enum ConfigProvider (MdmProvider, DefaultProvider, ...). The first build of this collector read
        providers only from the verbose text and treated every "<Name>Provider" property as a setting of its own, which
        is why a managed device reported 28 settings, all "Unknown source". The documented verbose text
        ("DownloadMode:Simple DownloadModeProvider:Mdm Provider") is still accepted. A setting whose provider is not
        stated anywhere is reported as Unknown, never guessed. Each setting also carries `_kind` (mdm, gp, local,
        admin, default, unknown) for Resolve-DDSettingSources. WorkingDirectory and VpnKeywords are not policies: they
        are returned separately.
    #>
    [CmdletBinding()]
    param($Config, [AllowEmptyCollection()][string[]] $VerboseLines = @())

    $providers = @{}
    $verboseValues = @{}
    if ($null -ne $Config) {
        foreach ($prop in $Config.PSObject.Properties) {
            if ($prop.MemberType -notin 'NoteProperty', 'Property' -or $prop.Name -notmatch '(?i)^(?<n>.+)Provider$') { continue }
            $base = $Matches['n'].ToLowerInvariant()
            if ($script:DDDoConfigProviderAlias.ContainsKey($base)) { $base = $script:DDDoConfigProviderAlias[$base] }
            $providers[$base] = ConvertTo-DDProviderKind -Value $prop.Value
        }
    }
    foreach ($line in $VerboseLines) {
        foreach ($m in [regex]::Matches($line, '(?<n>[A-Za-z]+?)Provider\s*:\s*(?<p>[A-Za-z]+)')) {
            $base = $m.Groups['n'].Value.ToLowerInvariant()
            if ($script:DDDoConfigProviderAlias.ContainsKey($base)) { $base = $script:DDDoConfigProviderAlias[$base] }
            if (-not $providers.ContainsKey($base) -or $providers[$base] -eq 'unknown') { $providers[$base] = ConvertTo-DDProviderKind -Value $m.Groups['p'].Value }
        }
        foreach ($m in [regex]::Matches($line, '(?<n>[A-Za-z]+):(?<v>[^\s]+)')) {
            $n = $m.Groups['n'].Value
            if ($n -notmatch 'Provider$') { $verboseValues[$n.ToLowerInvariant()] = @{ Name = $n; Value = $m.Groups['v'].Value } }
        }
    }
    $eff = [ordered]@{}
    $aux = @{ wd = $null; vk = $null }
    $add = {
        param($rawName, $v)
        $key = $rawName.ToLowerInvariant()
        if ($key -in $script:DDDoConfigNotSettings) {
            if ($key -eq 'workingdirectory') { $aux.wd = $v } else { $aux.vk = $v }
            return
        }
        $name = $null
        if ($script:DDDoConfigNames.ContainsKey($key)) { $name = $script:DDDoConfigNames[$key] }
        else { $name = 'DO' + ($rawName -creplace '^DO', '') }
        $val = $null
        if ($null -ne $v) {
            $n = 0.0
            if ($v -is [string] -and [double]::TryParse($v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { $val = $n }
            elseif ($v -is [string]) { $val = $v }
            elseif ($v -is [bool]) { $val = $(if ($v) { 1 } else { 0 }) }
            elseif ($v -is [System.Enum]) { $val = [int]$v }
            elseif ($v -is [ValueType]) { $val = $v }
            else { $val = [string]$v }
        }
        if ($name -eq 'DODownloadMode' -and $val -is [string]) { $dm = ConvertTo-DDDownloadMode $val; if ($dm -ge 0) { $val = $dm } }
        if ($val -is [double] -and $val -eq [math]::Truncate($val) -and [math]::Abs($val) -lt 1e15) { $val = [long]$val }
        $kind = 'unknown'
        if ($providers.ContainsKey($key)) { $kind = $providers[$key] }
        $kinds[$name] = $kind
        $eff[$name] = [ordered]@{ value = $val; provider = (ConvertTo-DDProviderName -Text $kind) }
    }
    $kinds = @{}
    if ($null -ne $Config) {
        foreach ($prop in $Config.PSObject.Properties) {
            if ($prop.MemberType -notin 'NoteProperty', 'Property' -or $prop.Name -match '(?i)Provider$') { continue }
            & $add $prop.Name $prop.Value
        }
    } else {
        foreach ($k in $verboseValues.Keys) { if ($providers.ContainsKey($k)) { & $add $verboseValues[$k].Name $verboseValues[$k].Value } }
    }
    [pscustomobject]@{ Effective = $eff; Kinds = $kinds; WorkingDirectory = $aux.wd; VpnKeywords = $aux.vk }
}
