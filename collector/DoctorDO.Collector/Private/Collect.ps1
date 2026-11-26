#Requires -Version 5.1
# One collection pass producing a BundleV1-shaped dictionary ("raw"), plus the inventory projection and the
# state patches that follow a successful send. Nothing here changes device configuration.

Set-StrictMode -Version Latest

$script:CollectorName = 'DoctorDO.Collector'
# The sections Get-DDRawCollection narrates to a person at the console (Start-DDSection); a command that adds its own
# counts them on top. A test holds this to the calls.
$script:DDCollectionSections = 7
$script:DDDownloadModeNames = @{ '0' = 'HTTP only'; '1' = 'LAN'; '2' = 'Group'; '3' = 'Internet'; '99' = 'Simple'; '100' = 'Bypass' }

function Get-DDCollectorVersion {
    [CmdletBinding()]
    param()
    if ($null -ne (Get-Variable -Name CollectorVersion -Scope Script -ErrorAction SilentlyContinue)) { return $script:CollectorVersion }
    '1.2.1'
}

function Get-DDTenantSalt {
    [CmdletBinding()]
    param([AllowNull()][string] $TenantId, [Parameter(Mandatory)][string] $DeviceSalt)
    # Tenant-wide so peers and egress hashes compare equal across a tenant's devices (telemetry topPeers.h,
    # DO-NET-009); different between tenants. Falls back to the device salt when the tenant is unknown.
    if ($TenantId) { return (Get-DDSha256Hex -Text ('doctordo-tenant-v1|' + $TenantId.ToLowerInvariant())) }
    $DeviceSalt
}

function New-DDDoConfigSection {
    # The doConfig the bundle and inventory carry: no in-memory helpers (the _ keys), mdmWinsOverGp only when it was read.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $DoConfig)
    $c = [ordered]@{ effective = $DoConfig['effective']; stores = $DoConfig['stores'] }
    if ($DoConfig.Contains('workingDirectory')) { $c['workingDirectory'] = $DoConfig['workingDirectory'] }
    if ($DoConfig.Contains('mdmWinsOverGp') -and $null -ne $DoConfig['mdmWinsOverGp']) { $c['mdmWinsOverGp'] = [bool]$DoConfig['mdmWinsOverGp'] }
    if ($DoConfig.Contains('cacheFolder') -and $null -ne $DoConfig['cacheFolder']) { $c['cacheFolder'] = $DoConfig['cacheFolder'] }
    $c
}

function Get-DDRawCollection {
    <#
    .SYNOPSIS
        Collect everything once. Returns @{ Raw = <BundleV1-shaped dict>; Context; Facts }.
    .PARAMETER IncludeBundleExtras
        Also gather what only the local deep bundle carries (the log excerpt). The monthly perf snapshot
        (perfSnapMonth) was retired on 19 Oct 2026: it held the job list's sums, not the month's counters; doMonth has those.
    .PARAMETER FlushLogs
        Run Get-DeliveryOptimizationLog -Flush, which per Microsoft stops DoSvc before reading. Only the admin-run local
        bundle does this; fleet runs never touch the service.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Salt,
        [switch] $Anonymise,
        [switch] $SkipConnectivityChecks,
        [string] $PublicIpProbeUri,
        [string] $RangeProbeUri,
        [datetime] $Since = [datetime]::MinValue,
        [ValidateSet('single', 'fleet')][string] $Mode = 'fleet',
        [switch] $IncludeBundleExtras,
        [switch] $FlushLogs,
        # Endpoint health results are reused from this file while younger than -EndpointCacheMinutes (fleet runs); no
        # path means probe every time.
        [string] $EndpointCachePath,
        [ValidateRange(0, 10080)][int] $EndpointCacheMinutes = 360,
        # Hash the public egress address, read from the DO geo answer (else -PublicIpProbeUri). Off by default.
        [switch] $CollectPublicEgress,
        # Hash tenant-wide values (peers, egress, PAC fingerprints) with -Salt instead of the tenant's salt, so nothing
        # in the result can be matched to the fleet or enumerated from the tenant ID (the offline device report, ADR-0039).
        [switch] $IsolateSalt
    )

    $now = Get-DDNowUtc
    $computer = Get-DDHostName
    $ctx = New-DDContext -Salt $Salt -Anonymise:$Anonymise -ComputerName $computer

    if (-not (Test-DDWindows)) { Add-DDNotCollected -Context $ctx -Field 'platform' -Reason 'unsupported-os' -Detail 'not running on Windows; only portable facts can be collected' }
    if (-not (Test-DDElevated)) { Add-DDNotCollected -Context $ctx -Field 'platform.elevation' -Reason 'insufficient-rights' -Detail 'not elevated: Delivery Optimization logs and some registry keys may be unreadable' }
    if (Test-DDWow64Process) { Add-DDNotCollected -Context $ctx -Field 'platform.bitness' -Reason 'unsupported-os' -Detail '32-bit PowerShell on 64-bit Windows: dsregcmd, netsh winhttp and file reads see the 32-bit view; run 64-bit PowerShell' }

    Start-DDSection -Name 'Device and Windows'
    $dsregText = Invoke-DDStep -Context $ctx -Field 'management.dsreg' -Script { Get-DDDsregStatusText } -Default @()
    $dsreg = $null
    if (@($dsregText).Count -gt 0) {
        $dsreg = ConvertFrom-DDDsregStatus -Lines $dsregText
        if (-not $dsreg.Parsed) { $dsreg = $null }
    }
    $tenantId = $(if ($dsreg) { $dsreg.TenantId } else { $null })
    $ctx.TenantSalt = $(if ($IsolateSalt) { $Salt } else { Get-DDTenantSalt -TenantId $tenantId -DeviceSalt $Salt })
    Write-DDVerboseStep -Step 'Device identity (dsregcmd)' -Result { $(if ($dsreg) { 'join type ' + $dsreg.JoinType } else { 'not read' }) }

    $os = Get-DDOsFacts -Context $ctx
    if ($null -eq $os) { Add-DDNotCollected -Context $ctx -Field 'os' -Reason 'error' -Detail 'OS version registry values unavailable' }
    $cm = Invoke-DDStep -Context $ctx -Field 'management.configMgr' -Script { Get-DDConfigMgrRaw }
    $isCm = [bool]($cm -and $cm.Client)
    Write-DDVerboseStep -Step 'Windows version and ConfigMgr client' -Result { ('{0}; ConfigMgr client {1}' -f $(if ($os) { [string]$os.Os['build'] } else { 'version not read' }), $(if ($isCm) { 'yes' } else { 'no' })) }
    Complete-DDSection -Result {
        $join = $(if ($null -eq $dsreg) { 'join state not read' } else { @{ entra = 'Microsoft Entra joined'; hybrid = 'hybrid joined'; domain = 'domain joined'; registered = 'Entra registered'; none = 'not joined' }[[string]$dsreg.JoinType] })
        '{0}; {1}; {2}' -f $(if ($join) { $join } else { 'join type ' + $dsreg.JoinType }), $(if ($os) { 'Windows ' + [string]$os.Os['build'] } else { 'Windows version not read' }), $(if ($isCm) { 'ConfigMgr client' } else { 'no ConfigMgr client' })
    }

    Start-DDSection -Name 'Delivery Optimization settings'
    $doModule = Test-DDDeliveryOptimizationModule
    # DoSvc's state and its TCP table are read before any Delivery Optimization cmdlet runs (Get-DOConfig is next): DoSvc is
    # trigger-started and stops when idle, and Microsoft does not say whether the DO cmdlets start it, so a read after them could
    # describe a service the collector itself woke. The dosvc-running and listener checks describe the service as it was before
    # the collector's DO queries.
    $doSvc = Invoke-DDStep -Context $ctx -Field 'doSvc' -Script { Get-DDDoSvcState }
    $tcp = @()
    if ($doModule) { $tcp = @(Invoke-DDStep -Context $ctx -Field 'endpoints.tcp' -Script { Get-DDDoSvcTcpConnections } -Default @()) }
    $tcpRead = $doModule -and -not $ctx.NotCollected.Exists([Predicate[object]] { param($e) $e['field'] -eq 'endpoints.tcp' })
    $enrolments =@(Invoke-DDStep -Context $ctx -Field 'doConfig.enrollments' -Script { Get-DDEnrollmentRecords } -Default @())
    $doConfig = Get-DDDoConfiguration -Context $ctx -Enrollments $enrolments
    $effective = $doConfig['_rawEffective']      # unredacted, in memory only: probes need the real cache host
    $wd = $(if ($doConfig['_workingDirectory']) { [string]$doConfig['_workingDirectory'] } else { '' })
    Write-DDVerboseStep -Step 'Delivery Optimization configuration' -Result { ('{0} settings in effect; download mode {1}' -f $(if ($doConfig['effective'] -is [System.Collections.IDictionary]) { $doConfig['effective'].Count } else { 0 }), $(if ($null -ne $effective -and $effective.Contains('DODownloadMode')) { [string]$effective['DODownloadMode']['value'] } else { 'not set' })) }
    Complete-DDSection -Result {
        $mode = $(if ($null -ne $effective -and $effective.Contains('DODownloadMode')) { [string]$effective['DODownloadMode']['value'] } else { $null })
        $name = $(if ($null -ne $mode -and $script:DDDownloadModeNames.ContainsKey($mode)) { ' ({0})' -f $script:DDDownloadModeNames[$mode] } else { '' })
        '{0}; {1} in effect' -f $(if ($null -ne $mode) { "download mode $mode$name" } else { 'download mode not set' }), (Format-DDCount -Count $(if ($doConfig['effective'] -is [System.Collections.IDictionary]) { $doConfig['effective'].Count } else { 0 }) -Noun 'setting')
    }

    # The adapter DO uses, then the DO geo service's answer (the cache server it assigns, its DHCP flag, a captive portal),
    # then the network facts that depend on both (Health.ps1).
    Start-DDSection -Name 'Network'
    $netRaw = Invoke-DDStep -Context $ctx -Field 'network' -Script { Get-DDNetworkRaw }
    $doAdapter = Get-DDDoAdapterFacts -Context $ctx -DefaultInterfaceIndex $(if ($netRaw) { $netRaw.DefaultInterfaceIndex } else { $null })
    Write-DDVerboseStep -Step 'Adapter Delivery Optimization uses' -Result { $(if ($doAdapter) { '{0}, {1}' -f $doAdapter.Type, $doAdapter.Kind } else { 'none found' }) }
    $egressOn = [bool]$PublicIpProbeUri -or $CollectPublicEgress
    $geoCache = $(if ($EndpointCachePath) { Join-Path -Path (Split-Path -Path $EndpointCachePath -Parent) -ChildPath 'geo.json' } else { $null })
    $geoSig = $(if ($doAdapter) { '{0}|{1}' -f (Get-DDSubnetString -Address $doAdapter.IPv4 -PrefixLength $doAdapter.PrefixLength), $doAdapter.Kind } else { 'no-adapter' })
    $geo = Get-DDGeoFacts -Context $ctx -OsVersion $(if ($os) { $os.FullBuild } else { $null }) -Skip:$SkipConnectivityChecks -CachePath $geoCache `
        -MaxAgeMinutes $EndpointCacheMinutes -WantExternalIp:$egressOn -Signature (Get-DDSha256Hex -Text $geoSig) -Now $now
    Write-DDVerboseStep -Step 'Delivery Optimization geo service' -Result { ('{0}{1}' -f [string](Get-DDProp $geo 'Result'), $(if (Get-DDProp $geo 'Cached') { ' (cached)' } else { '' })) }
    $netFacts = Get-DDNetworkFacts -Context $ctx -PublicIpProbeUri $PublicIpProbeUri -VpnKeywords $doConfig['_vpnKeywords'] -Raw $netRaw -RawCollected `
        -DoAdapter $doAdapter -Geo $geo -Effective $effective -CollectPublicEgress:$CollectPublicEgress
    $geo.ExternalIp = $null   # used once, for the egress hash; never kept
    $net = $netFacts.Network
    Write-DDVerboseStep -Step 'Network facts (proxy, VPN, DHCP)' -Result { ('proxy {0}; VPN {1}; DHCP {2}' -f $(if ($net['proxy']['configured']) { 'configured' } else { 'none' }), $(if ($net['isVpnActive']) { 'active' } else { 'not active' }), [string]$netFacts.Dhcp['state']) }
    # Proxy auto-config (Pac.ps1, ADR-0038): the PACs in force, whether they name DO endpoints and what they answer for DO.
    $pac = Get-DDPacFacts -Context $ctx -Skip:$SkipConnectivityChecks
    if ($null -ne $pac) { $net['proxy']['pac'] = $pac }
    Write-DDVerboseStep -Step 'Proxy auto-config (PAC)' -Result { $(if ($null -eq $pac) { 'not read' } elseif (-not $pac['configured']) { 'none in force' } else { '{0} version(s); {1}' -f $pac['versions'], $(if ($pac['referencesDo'] -eq $true) { 'names DO endpoints' } elseif ($pac['referencesDo'] -eq $false) { 'names no DO endpoints' } else { 'not downloaded' }) }) }
    Complete-DDSection -Result {
        '{0}; proxy {1}; VPN {2}; PAC {3}; DO cloud {4}' -f $(if ($doAdapter) { $doAdapter.Type } else { 'no adapter found' }),
            $(if ($net['proxy']['configured']) { 'configured' } else { 'none' }), $(if ($net['isVpnActive']) { 'active' } else { 'not active' }),
            $(if ($null -eq $pac) { 'not read' } elseif ($pac['configured']) { 'in force' } else { 'none' }),
            $(switch ([string](Get-DDProp $geo 'Result')) { 'pass' { 'answered' } 'fail' { 'did not answer' } 'not-collected' { 'not asked' } default { $_ } })
    }

    Start-DDSection -Name 'Device, hardware and firewall'
    $cacheHost = Resolve-DDCacheHost -Effective $effective -Dhcp235 $netFacts.Dhcp235 -DhcpState ([string]$netFacts.Dhcp['state']) -Geo $geo `
        -VpnActive ([bool]$net['isVpnActive']) -OsBuild $(if ($os) { [string]$os.Os['build'] } else { $null })
    $staticDev = Get-DDStaticDeviceFacts -Context $ctx -Os $os -Dsreg $dsreg -IsConfigMgrClient $isCm -WorkingDirectory $wd
    $vitals = Get-DDDeviceVitals -Context $ctx -WorkingDirectory $wd
    $mgmt = Get-DDManagementFacts -Context $ctx -Dsreg $dsreg -IsConfigMgrClient $isCm -ConfigMgr $cm
    $hw = Get-DDHardwareFacts -Context $ctx
    $fw = Get-DDFirewallFacts -Context $ctx
    Write-DDVerboseStep -Step 'Device, hardware, management, firewall' -Result { ('{0} firewall rule(s) for DO' -f @($fw).Count) }
    Complete-DDSection -Result { '{0} for Delivery Optimization' -f (Format-DDCount -Count @($fw).Count -Noun 'firewall rule') }

    # Delivery Optimization state
    Start-DDSection -Name 'Jobs, peers and log'
    $status = New-Object 'System.Collections.Generic.List[object]'
    $peerRows = @(); $connRows = @(); $errorRows = @(); $perf = $null; $doMonth = $null; $logExcerpt = $null
    $statusRaw = @(); $entries = @(); $cacheServed = @()
    $peerAddresses = New-Object 'System.Collections.Generic.List[string]'
    if ($doModule) {
        $statusRaw = @(Invoke-DDStep -Context $ctx -Field 'status' -Script { Get-DDDOStatusRaw } -Default @())
        # Each row carries the job's own upload counters (BytesTo*Peers): telemetry sends what they rose by since the last report.
        foreach ($i in $statusRaw) { $status.Add((ConvertTo-DDStatusRow -Item $i -Context $ctx)) }
        $peerRaw = @(Invoke-DDStep -Context $ctx -Field 'peerInfo' -Script { Get-DDDOPeerInfoRaw } -Default @())
        $peerRows = ConvertTo-DDPeerRows -Items $peerRaw -Context $ctx -LocalAddress $netFacts.IPv4 -PrefixLength $netFacts.PrefixLength -LocalNetworks $netFacts.LocalNetworks
        foreach ($pr in $peerRaw) {
            $inner = Get-DDProp $pr 'Peers', 'PeersInfo', 'PeerInfo'
            $set = $(if ($null -ne $inner -and $inner -isnot [string]) { @($inner) } else { @($pr) })
            foreach ($p in $set) { $ip = [string](Get-DDProp $p 'IP', 'IPAddress', 'PeerIP'); if ($ip -and (Get-DDProp $p 'ConnectionEstablished') -ne $false) { $peerAddresses.Add($ip) } }
        }
        $ps = Invoke-DDStep -Context $ctx -Field 'perfSnap' -Script { Get-DDDOPerfSnapRaw }
        if ($ps) { $perf = ConvertTo-DDPerfSnap -Item $ps.Snap -StatusRows $status.ToArray() }
        # DO's own counters for the calendar month (19 Oct 2026): read on every run, because the device page and the offline report
        # show them (the totals Get-AutopilotDiagnostics prints). They replace the bundle's perfSnapMonth
        # (retired 19 Oct 2026, product owner), which only the local bundle carried and whose bytes were the job list's sums.
        $pm = Invoke-DDStep -Context $ctx -Field 'doMonth' -Script { Get-DDDOPerfSnapRaw -ThisMonth }
        if ($pm) {
            $doMonth = ConvertTo-DDMonthTotals -Item $pm.Snap
            if ($null -eq $doMonth) { Add-DDNotCollected -Context $ctx -Field 'doMonth' -Reason 'unsupported-os' -Detail 'Get-DeliveryOptimizationPerfSnapThisMonth returned no DownloadHttpBytes on this build' }
        }
        $entries = @(Invoke-DDStep -Context $ctx -Field 'errors' -Script { Get-DDDOLogEntries -Flush:$FlushLogs } -Default @())
        $ids = @($status | ForEach-Object { $_['fileId'] })
        $errorRows = ConvertTo-DDErrorRows -Entries $entries -Context $ctx -Since $Since -KnownFileIds $ids
        $connRows = ConvertTo-DDConnectionRows -Items @(Invoke-DDStep -Context $ctx -Field 'connections' -Script { Get-DDDOLogConnections } -Default @()) -Context $ctx
        if ($IncludeBundleExtras) {
            $redaction = Get-DDRedactionProfile
            $lines = New-Object 'System.Collections.Generic.List[string]'
            $bytes = 0
            foreach ($e in $entries) {
                $msg = [string](Get-DDProp $e 'Message'); if (-not $msg) { continue }
                $when = Get-DDProp $e 'TimeCreated'
                if ($when -is [datetime]) { $when = Format-DDIso -Value $when }
                $line = '{0} {1}: {2}' -f $when, (Get-DDProp $e 'Function'), $msg
                if (-not (Test-DDRetainedLogLine -Line $line -RedactionProfile $redaction)) { continue }
                $line = Protect-DDLogText -Text $line -Anonymise:$ctx.Anonymise -Salt $ctx.Salt -ComputerName $ctx.ComputerName
                $bytes += $line.Length + 1
                if ($bytes -gt [int]$redaction['limits']['maxExcerptBytes']) { break }
                $lines.Add($line)
            }
            $logExcerpt = ($lines -join "`n")
        }
    } else {
        foreach ($f in 'status', 'peerInfo', 'perfSnap', 'doMonth', 'errors', 'connections') {
            Add-DDNotCollected -Context $ctx -Field $f -Reason 'cmdlet-missing' -Detail 'DeliveryOptimization module not available (Windows 10 1703+ / Windows 11)'
        }
    }
    Write-DDVerboseStep -Step 'Delivery Optimization jobs, peers and log' -Result { $(if ($doModule) { '{0} file(s), {1} peer(s), {2} log entries; DoSvc {3}' -f $status.Count, @($peerRows).Count, @($entries).Count, $(if ($doSvc) { $doSvc.Status } else { 'not read' }) } else { 'DeliveryOptimization module not available' }) }
    Complete-DDSection -Result {
        if (-not $doModule) { return 'the DeliveryOptimization module is not available' }
        '{0}, {1}, {2}; DoSvc {3}' -f (Format-DDCount -Count $status.Count -Noun 'file'), (Format-DDCount -Count @($peerRows).Count -Noun 'peer'),
            (Format-DDCount -Count @($entries).Count -Noun 'log entry' -Plural 'log entries'), $(if ($doSvc) { ([string]$doSvc.Status).ToLowerInvariant() } else { 'not read' })
    }

    # Which endpoints served the bytes (ADR-0031): the job list's cache host, the peer list, the DO log and DoSvc's TCP
    # connections now. Addresses are reduced here, before anything is stored or sent.
    Start-DDSection -Name 'Connectivity'
    $endpoints = @()
    # Whether DoSvc itself is listening on TCP 7680, and whether it holds an established peer connection (TCP 7680 at either
    # end): from its own TCP table, $null when that was not read.
    $doSvcListening = $null; $doSvcPeerConnection = $null
    if ($doModule) {
        $obs = New-Object 'System.Collections.Generic.List[object]'
        foreach ($o in (ConvertFrom-DDStatusEndpoints -Items $statusRaw -At $now)) { $obs.Add($o) }
        foreach ($o in (ConvertFrom-DDPeerEndpoints -Items $peerRaw -At $now)) { $obs.Add($o) }
        $cacheSeen = @($obs | Where-Object { $_.Role -eq 'cache' } | ForEach-Object { [string]$_.Address })
        foreach ($o in (ConvertFrom-DDDoLogEndpoints -Entries $entries -CacheHosts $cacheSeen -LocalAddress $netFacts.IPv4 -PrefixLength $netFacts.PrefixLength -LocalNetworks $netFacts.LocalNetworks)) { $obs.Add($o) }
        $cacheSeen = @($obs | Where-Object { $_.Role -eq 'cache' } | ForEach-Object { [string]$_.Address })
        foreach ($o in (ConvertFrom-DDTcpEndpoints -Items $tcp -CacheHosts $cacheSeen -LocalAddress $netFacts.IPv4 -PrefixLength $netFacts.PrefixLength -At $now -LocalNetworks $netFacts.LocalNetworks)) { $obs.Add($o) }
        if ($tcpRead -and $null -ne $doSvc) { $doSvcListening = Test-DDDoSvcListening -Connections $tcp -DoSvc $doSvc }
        if ($tcpRead) { $doSvcPeerConnection = Test-DDDoSvcPeerConnection -Connections $tcp }
        $endpoints = Merge-DDEndpoints -Observations $obs.ToArray() -Context $ctx
        # Cache servers that actually served bytes: probed as "used" even where no policy names them (ADR-0031).
        $cacheServed = @($obs | Where-Object { $_.Role -eq 'cache' -and $null -ne $_.Rx -and [System.Numerics.BigInteger]$_.Rx -gt [System.Numerics.BigInteger]::Zero } | ForEach-Object { [string]$_.Address } | Select-Object -Unique)
    }
    Write-DDVerboseStep -Step 'Endpoints that served the bytes' -Result { ('{0} endpoint(s)' -f @($endpoints).Count) }

    # Endpoint health (docs/07, Data/endpoints.json): the manifest's endpoints tested from this device, on hosts it used
    # or Microsoft documents. The connectivity matrix reads its cloud, content, Teredo and cache checks from these results.
    $dlMode = $null
    if ($null -ne $effective -and $effective.Contains('DODownloadMode')) { $n = 0; if ([int]::TryParse([string]$effective['DODownloadMode']['value'], [ref]$n)) { $dlMode = $n } }
    $configuredCache = @()
    if ($null -ne $effective -and $effective.Contains('DOCacheHost') -and $effective['DOCacheHost']['value']) {
        $configuredCache = @(([string]$effective['DOCacheHost']['value']).Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { ConvertTo-DDCacheHostName $_ } | Where-Object { $_ })
    }
    # A cache server DHCP option 235 hands this device (DOCacheHostSource or the DO service's flag) is configured too.
    if ($cacheHost.Source -eq 'dhcp') { $configuredCache = @(@($cacheHost.Hosts) + @($configuredCache) | Select-Object -Unique) }
    $health = Invoke-DDStep -Context $ctx -Field 'connectivity.endpointHealth' -Default @() -Script {
            Get-DDEndpointHealth -Context $ctx -ModeNum $dlMode -StatusRaw $statusRaw -LogEntries $entries -ConfiguredCacheHosts $configuredCache `
                -UsedCacheHosts $cacheServed -Network $net -RangeProbeUri $RangeProbeUri -SkipProbes:$SkipConnectivityChecks `
                -CachePath $EndpointCachePath -MaxAgeMinutes $EndpointCacheMinutes -Now $now
        }
    Write-DDVerboseStep -Step 'Endpoint health' -Result { $(if ($SkipConnectivityChecks) { 'skipped (-SkipConnectivityChecks)' } else { Get-DDCountText -Rows $health }) }

    # The disk-size peering check is judged on the drive of the cache (docs/27 3.2), the system drive only when that drive's size is unknown.
    $diskGB = $staticDev['cacheDriveGB']; $diskDrive = Get-DDCacheDriveName -WorkingDirectory $wd
    if ($null -eq $diskGB) { $diskGB = $staticDev['systemDiskGB']; $diskDrive = $(if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }) }
    # A step like the others: a matrix that throws is recorded as not collected and the report is still sent, never a failed run.
    $matrix = Invoke-DDStep -Context $ctx -Field 'connectivity' -Script {
        Get-DDConnectivityMatrix -Context $ctx -DoEffective $effective -Network $net -FirewallRules $fw -ObservedStatus $status.ToArray() `
            -PeerAddresses $peerAddresses.ToArray() -DoSvc $doSvc -RamGB $staticDev['ramGB'] -DiskGB $diskGB -DiskDrive $diskDrive -Vitals $vitals `
            -EndpointResults $health -FirewallProfiles $netFacts.FirewallProfiles -SkipProbes:$SkipConnectivityChecks `
            -GeoAnswer $geo -CacheResolution $cacheHost -Dhcp $netFacts.Dhcp -CacheFolder $doConfig['cacheFolder'] -DoSvcListening $doSvcListening `
            -DoSvcPeerConnection $doSvcPeerConnection -PowerPlan $staticDev['powerPlan']
    }
    if ($null -eq $matrix) { $matrix = @() }
    Write-DDVerboseStep -Step 'Connectivity checks' -Result { (Get-DDCountText -Rows $matrix -Noun 'checks') }
    Complete-DDSection -Result { $(if ($SkipConnectivityChecks) { 'network not probed (-SkipConnectivityChecks); ' } else { '' }) + (Get-DDCountText -Rows $matrix -Noun 'checks') }

    # What the Enrollment Status Page tracked, and DO's job list when read soon after it (ADR-0043). Not on a device that never showed the ESP.
    Start-DDSection -Name 'Provisioning'
    $espTree = Invoke-DDStep -Context $ctx -Field 'provisioning' -Script { Get-DDEspTrackingRaw }
    $minCacheMB = 50
    if ($null -ne $effective -and $effective.Contains('DOMinFileSizeToCache')) { $mc = 0; if ([int]::TryParse([string]$effective['DOMinFileSizeToCache']['value'], [ref]$mc) -and $mc -gt 0) { $minCacheMB = $mc } }
    $statusRead = -not $ctx.NotCollected.Exists([Predicate[object]] { param($e) $e['field'] -eq 'status' })
    $provStatus = $null
    if ($statusRead) { $provStatus = $status.ToArray() }
    # DOMaxCacheAge in effect (Learn default 259,200 s) dates each job for the delivery window; the device's UTC offset widens it.
    $maxAge = 259200
    if ($null -ne $effective -and $effective.Contains('DOMaxCacheAge')) { $ma = 0.0; if ([double]::TryParse([string]$effective['DOMaxCacheAge']['value'], [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$ma) -and $ma -ge 0) { $maxAge = $ma } }
    $provisioning = ConvertTo-DDProvisioningSummary -Tree $espTree -Status $provStatus -MinFileSizeMB $minCacheMB `
        -OsInstallDate $(if ($os) { $os.Os['installDate'] } else { $null }) -Now $now -MaxCacheAgeSeconds $maxAge -ZoneOffsetHours ([System.TimeZoneInfo]::Local.GetUtcOffset($now).TotalHours)
    Write-DDVerboseStep -Step 'Provisioning (Enrollment Status Page)' -Result { $(if ($null -eq $provisioning) { 'not tracked on this device' } else { '{0} Win32 app(s) tracked; DO jobs {1}' -f $provisioning['appsTotal'], $(if ($provisioning['delivery']) { 'read' } else { 'not read (too long after provisioning, or none from its time)' }) }) }
    Complete-DDSection -Result { $(if ($null -eq $provisioning) { 'no Enrollment Status Page on this device' } else { '{0} tracked by the Enrollment Status Page' -f (Format-DDCount -Count ([int]$provisioning['appsTotal']) -Noun 'Win32 app') }) }

    $device = [ordered]@{}
    foreach ($k in $staticDev.Keys) { $device[$k] = $staticDev[$k] }
    foreach ($k in $vitals.Keys) { $device[$k] = $vitals[$k] }

    $raw = [ordered]@{
        schemaVersion = 1
        collector     = [ordered]@{ name = $script:CollectorName; version = (Get-DDCollectorVersion) }
        collectedAt   = (Format-DDIso -Value $now)
        mode          = $Mode
        anonymised    = [bool]$Anonymise
        device        = $device
        network       = $net
        doConfig      = (New-DDDoConfigSection -DoConfig $doConfig)
        firewallRules = $fw
        status        = $status.ToArray()
        peerInfo      = $peerRows
        connections   = $connRows
        perfSnap      = $perf
        endpoints     = @($endpoints)
        connectivity  = $matrix
        errors        = $errorRows
        notCollected  = $ctx.NotCollected.ToArray()
    }
    if ($null -ne $logExcerpt) { $raw['logExcerpt'] = $logExcerpt }
    # Optional in the contract (BundleV1.doMonth): absent, not null, when it was not read; notCollected then names it.
    if ($null -ne $doMonth) { $raw['doMonth'] = $doMonth }
    # Dsreg travels with the collection so the fleet send can select the device certificate without a second dsregcmd run.
    [pscustomobject]@{ Raw = $raw; Context = $ctx; Management = $mgmt; Hardware = $hw; Os = $os; Now = $now; Dsreg = $dsreg; DsregText = @($dsregText); Provisioning = $provisioning }
}

function ConvertTo-DDInventory {
    <#
    .SYNOPSIS
        Project a collection onto InventoryV1 (contracts/inventory-v1.schema.json).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Collection)

    $raw = $Collection.Raw
    $dev = [ordered]@{}
    foreach ($k in 'deviceId', 'hostname', 'osBuild', 'osEdition', 'isSupportedEdition', 'isVirtual', 'ramGB', 'systemDiskGB', 'cacheDriveGB', 'chassis', 'isConfigMgrClient', 'domainJoined', 'entraJoined') {
        $dev[$k] = $raw['device'][$k]
    }
    foreach ($k in 'powerPlan', 'uusVersion') { if ($raw['device'].Contains($k)) { $dev[$k] = $raw['device'][$k] } }
    $osObj = $(if ($Collection.Os) { $Collection.Os.Os } else { [ordered]@{ build = 'unknown'; ubr = $null; edition = 'unknown'; displayVersion = $null; installDate = $null } })
    $conf = [ordered]@{ effective = $raw['doConfig']['effective']; stores = $raw['doConfig']['stores'] }
    if ($raw['doConfig'].Contains('mdmWinsOverGp')) { $conf['mdmWinsOverGp'] = $raw['doConfig']['mdmWinsOverGp'] }
    if ($raw['doConfig'].Contains('workingDirectory')) { $conf['workingDirectory'] = $raw['doConfig']['workingDirectory'] }
    if ($raw['doConfig'].Contains('cacheFolder')) { $conf['cacheFolder'] = $raw['doConfig']['cacheFolder'] }
    $inv = [ordered]@{
        schemaVersion = 1
        kind          = 'inventory'
        collector     = $raw['collector']
        collectedAt   = $raw['collectedAt']
        anonymised    = $raw['anonymised']
        device        = $dev
        management    = $Collection.Management
        hardware      = $Collection.Hardware
        os            = $osObj
        network       = $raw['network']
        doConfig      = $conf
        firewallRules = $raw['firewallRules']
        connectivity  = $raw['connectivity']
        notCollected  = @($raw['notCollected'] | Select-Object -First 256)
    }
    if ($Collection.PSObject.Properties['Provisioning'] -and $null -ne $Collection.Provisioning) { $inv['provisioning'] = $Collection.Provisioning }
    $inv
}

# Facts that change with the network the device is on or the power plan in use. They stay in the inventory (and refresh at each
# keyframe) but never make the device send a new one: telemetry vitals carry the live subnet and egress hash (docs/27 3.4).
$script:DDVolatileNetworkKeys = 'localSubnet', 'defaultGateway', 'publicEgressHash', 'defaultRouteSubnet', 'dhcp'
$script:DDVolatileDoAdapterKeys = 'subnet'
$script:DDVolatileDeviceKeys = 'powerPlan'

function Copy-DDWithout {
    # A shallow copy of a dictionary without the named keys; anything that is not a dictionary comes back as it is.
    [CmdletBinding()]
    param($Source, [string[]] $Keys = @())
    if ($Source -isnot [System.Collections.IDictionary]) { return $Source }
    $c = [ordered]@{}
    foreach ($k in $Source.Keys) { if ([string]$k -notin $Keys) { $c[$k] = $Source[$k] } }
    $c
}

function Get-DDStableInventoryHash {
    # Change-detection hash: the inventory without the connectivity matrix (latencies jitter every run; real
    # changes travel in telemetry.connectivityChanged), collectedAt and notCollected, and without the volatile facts above
    # (the local subnet, gateway, egress hash, the DO adapter's subnet, the DHCP outcome and the power plan).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Inventory)
    $c = [ordered]@{}
    foreach ($k in $Inventory.Keys) { if ($k -ne 'connectivity') { $c[$k] = $Inventory[$k] } }
    if ($c.Contains('device')) { $c['device'] = Copy-DDWithout -Source $c['device'] -Keys $script:DDVolatileDeviceKeys }
    if ($c.Contains('network')) {
        $n = Copy-DDWithout -Source $c['network'] -Keys $script:DDVolatileNetworkKeys
        if ($n -is [System.Collections.IDictionary] -and $n.Contains('doAdapter')) { $n['doAdapter'] = Copy-DDWithout -Source $n['doAdapter'] -Keys $script:DDVolatileDoAdapterKeys }
        $c['network'] = $n
    }
    Get-DDInventoryHash -Inventory $c
}

function New-DDTelemetryFromCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Collection,
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)][string] $InventoryHash,
        [datetime] $Now = (Get-DDNowUtc)
    )
    $raw = $Collection.Raw
    $from = $null
    if ($State['lastTelemetryAt']) { $from = $State['lastTelemetryAt'] }
    if (-not $from) { $from = Format-DDIso -Value $Now.AddMinutes(-15) }
    $recent = Get-DDRecentHresultList -State $State -Now $Now
    # The diagnosis signals (Diag.ps1): the crash count and powered-on hours from the 24-hour cache in the state (refreshed here
    # when older, which is why the state is saved after a failed send too), and the flap totals including this run's changes.
    $diag = New-DDDiagInput -State $State -Connectivity $raw['connectivity'] -Now $Now
    # Content sources (docs/08): only when the job list was read; the jobs earlier reports summarised are skipped.
    $seen = $null
    if (Test-DDStatusRead -Raw $raw) { $seen = @(); if ($null -ne $State['sourcesSeen']) { $seen = @($State['sourcesSeen']) } }
    $args2 = @{
        Raw = $raw; Seq = ([int]($State['seq'] + 1)); InventoryHash = $InventoryHash; PeriodFrom = $from; PeriodTo = $raw['collectedAt']
        PreviousConnectivity = $State['lastConnectivity']; RecentHresults = $recent; Diag = $diag; SourcesSeen = $seen
    }
    # Byte counters (docs/08): a fleet report carries what moved since the last accepted one, measured against the state's counters,
    # and the first one (no counters: a new device or a lost state file) is a baseline that sends none. A single collection (the
    # offline device report) is one point in time: its counters are sent as read, a snapshot.
    if ($raw['mode'] -ne 'single') { $args2.PreviousCounters = $State['counters'] }
    ConvertTo-DDTelemetry @args2
}

function Test-DDStatusRead {
    # Whether this collection read the job list (Get-DeliveryOptimizationStatus): no notCollected record for `status`.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Raw)
    -not @(@($Raw['notCollected']) | Where-Object { $null -ne $_ -and [string]$_['field'] -eq 'status' }).Count
}

function Update-DDStateAfterTelemetry {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] $Collection, [Parameter(Mandatory)] $Telemetry, [Parameter(Mandatory)][datetime] $Now)
    $State['seq'] = [int64]$Telemetry['seq']
    $State['lastTelemetryAt'] = $Collection.Raw['collectedAt']
    # Each job's, peer's and log connection's counters as of this report: the next one sends what moved after it. Committed only
    # here, after HTTP 202, so a report that failed is followed by one that carries its bytes as well, never fewer.
    $State['counters'] = Get-DDNextCounters -Raw $Collection.Raw -Previous $State['counters']
    Update-DDFlapState -State $State -Rows $Collection.Raw['connectivity'] -Now $Now
    $State['lastConnectivity'] = Get-DDConnectivityState -Connectivity $Collection.Raw['connectivity']
    Add-DDRecentHresults -State $State -Hresults ([string[]]@($Telemetry['errors'] | ForEach-Object { $_['hresult'] })) -Now $Now
    # The jobs this report summarised are not summarised again; a report that could not read the job list changes nothing.
    if ($Telemetry.Contains('sources')) { $State['sourcesSeen'] = Get-DDNextSourcesSeen -Status @($Collection.Raw['status']) -Seen $State['sourcesSeen'] }
}

function Update-DDStateAfterInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] $Collection, [Parameter(Mandatory)] $Inventory, [Parameter(Mandatory)][string] $FullHash, [Parameter(Mandatory)][string] $StableHash, [datetime] $Now = (Get-DDNowUtc))
    Update-DDFlapState -State $State -Rows $Inventory['connectivity'] -Now $Now
    # The first inventory this state has seen accepted (none before it): the daily keyframes of the first week count from it.
    if (-not $State['lastInventoryHash'] -and -not $State['firstInventoryAt']) { $State['firstInventoryAt'] = $Inventory['collectedAt'] }
    $State['lastInventoryHash'] = $FullHash
    $State['lastStableHash'] = $StableHash
    $State['lastInventoryAt'] = $Inventory['collectedAt']
    $State['lastConnectivity'] = Get-DDConnectivityState -Connectivity $Inventory['connectivity']
    # The delivery snapshot is captured once (Resolve-DDProvisioning); the state keeps the section it was sent in.
    if ($Inventory.Contains('provisioning')) { $State['provisioning'] = $Inventory['provisioning'] }
}

function Get-DDRequiredFieldGaps {
    # Fields the contracts require to be non-null. If one is missing the report would be rejected by the schema, so the
    # run fails loudly (exit 3) instead of sending garbage; the reason is in notCollected.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Collection)
    $d = $Collection.Raw['device']
    $gaps = New-Object 'System.Collections.Generic.List[string]'
    foreach ($k in 'deviceId', 'osBuild', 'osEdition', 'ramGB', 'systemDiskGB') { if ($null -eq $d[$k] -or "$($d[$k])" -eq '') { $gaps.Add("device.$k") } }
    if ($null -eq $Collection.Os) { $gaps.Add('os') }
    , $gaps.ToArray()
}
