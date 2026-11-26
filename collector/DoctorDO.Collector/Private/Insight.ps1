#Requires -Version 5.1
# Where each Delivery Optimization setting came from, and which endpoints served the bytes.
#
# Pure functions: the registry, CIM, log and TCP reads are wrappers in Platform.ps1, so every rule here is tested on
# fixtures shaped like what Windows returned on a real device (see tests/Insight.Tests.ps1 for the provenance of each).

Set-StrictMode -Version Latest

# ---- configuration sources ---------------------------------------------------------------------------------------

# Values PolicyManager keeps beside each policy value (verified on Windows 11 26H2, PolicyManager\current\device\<Area>:
# "<Name>", "<Name>_ProviderSet" (DWORD 1), "<Name>_WinningProvider" (REG_SZ enrolment GUID, no braces); under
# PolicyManager\providers\<GUID>\default\Device\<Area>: "<Name>" and "<Name>_LastWrite").
$script:DDPolicyManagerSuffix = '(?i)_(ProviderSet|WinningProvider|LastWrite|ADMXInstanceData)$'

function ConvertFrom-DDRegistryData {
    # A registry dump value ({ name; type; data } from Get-DDRegistryValues) as a setting value: numbers stay numbers.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Value)
    $d = [string]$Value['data']
    if ($Value['type'] -in 'REG_DWORD', 'REG_QWORD') {
        $n = [long]0
        if ([long]::TryParse($d, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $n }
    }
    $d
}

function ConvertFrom-DDPolicyStore {
    <#
    .SYNOPSIS
        One registry store as name -> @{ Value; WinningProvider } (names lower-cased for lookup, original kept in Name).
        PolicyManager bookkeeping values (_ProviderSet, _WinningProvider, _LastWrite) are folded into their setting.
    #>
    [CmdletBinding()]
    param($Dump)
    $out = @{}
    if ($null -eq $Dump -or -not $Dump['Present']) { return $out }
    $winners = @{}
    foreach ($v in @($Dump['Values'])) {
        if ([string]$v['name'] -match '(?i)^(?<n>.+)_WinningProvider$') { $winners[$Matches['n'].ToLowerInvariant()] = ([string]$v['data']).Trim('{', '}', ' ') }
    }
    foreach ($v in @($Dump['Values'])) {
        $name = [string]$v['name']
        if ($name -match $script:DDPolicyManagerSuffix -or $name -eq '(Default)') { continue }
        $k = $name.ToLowerInvariant()
        $out[$k] = @{ Name = $name; Value = (ConvertFrom-DDRegistryData -Value $v); WinningProvider = $(if ($winners.ContainsKey($k)) { $winners[$k] } else { $null }) }
    }
    $out
}

function Resolve-DDMdmProvider {
    # Enrolment GUID -> @{ provider = intune|other; providerId }. "MS DM Server" is the ProviderID of an Intune enrolment
    # (HKLM\SOFTWARE\Microsoft\Enrollments\<GUID>, verified on an Intune-managed device; ConfigMgr co-management shows
    # as "WMI_Bridge_SCCM_Server").
    [CmdletBinding()]
    param([AllowNull()][string] $EnrollmentId, [AllowEmptyCollection()] $Enrollments = @())
    if (-not $EnrollmentId) { return $null }
    $rec = @($Enrollments | Where-Object { $_ -and ([string]$_.EnrollmentId).Trim('{', '}') -ieq $EnrollmentId.Trim('{', '}') }) | Select-Object -First 1
    $provId = $null
    if ($rec -and $rec.ProviderId) { $provId = ([string]$rec.ProviderId) -replace '[^\x20-\x7E]', '' }
    if ($provId -and $provId.Length -gt 64) { $provId = $provId.Substring(0, 64) }
    [ordered]@{ provider = $(if ($provId -eq 'MS DM Server') { 'intune' } else { 'other' }); providerId = $(if ($provId) { $provId } else { $null }) }
}

function Resolve-DDSettingSources {
    <#
    .SYNOPSIS
        Attribute every Delivery Optimization setting to the channel that set it, and add policies that Get-DOConfig
        does not report (DOGroupId, DOCacheHost, DOMaxCacheAge, ...) from the policy stores.
    .DESCRIPTION
        Evidence, strongest first:
          1. Get-DOConfig's own provider per setting (DO's statement of the value in force): basis do-service.
          2. Both MDM (PolicyManager\current\device\DeliveryOptimization) and Group Policy
             (HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization) hold a value: Policy CSP
             ControlPolicyConflict/MDMWinsOverGP = 1 means "the MDM policy is used and the GP policy is blocked", so MDM
             wins (basis mdm-wins-over-gp). Without it Microsoft says there is "a race condition and no guarantee which
             one wins", so the winner is left unknown (basis unresolved) and both are listed.
          3. One store only: that store (basis registry). The Settings app store
             (HKU\S-1-5-20\...\DeliveryOptimization\Settings) only annotates settings already known; its value names are
             not CSP names and are matched without the DO prefix.
        MDM attribution follows <Name>_WinningProvider to the enrolment's ProviderID.
    .OUTPUTS
        Ordered dictionary CSP name -> @{ value; provider; source = @{ kind; mdm; basis; setIn; alt } }.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $Effective,
        [hashtable] $Kinds = @{},
        $MdmStore,
        $PolicyStore,
        $LocalStore,
        [AllowEmptyCollection()] $Enrollments = @(),
        [AllowNull()] $MdmWinsOverGp
    )
    $mdm = ConvertFrom-DDPolicyStore -Dump $MdmStore
    $gp = ConvertFrom-DDPolicyStore -Dump $PolicyStore
    $local = ConvertFrom-DDPolicyStore -Dump $LocalStore

    $names = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    if ($null -ne $Effective) { foreach ($k in $Effective.Keys) { $names.Add([string]$k); $seen[([string]$k).ToLowerInvariant()] = $true } }
    foreach ($store in $mdm, $gp) {
        foreach ($e in $store.Values) {
            if ($e.Name -cmatch '^DO[A-Z]' -and -not $seen.ContainsKey($e.Name.ToLowerInvariant())) { $names.Add($e.Name); $seen[$e.Name.ToLowerInvariant()] = $true }
        }
    }

    $out = [ordered]@{}
    foreach ($name in $names) {
        $k = $name.ToLowerInvariant()
        $inMdm = $mdm.ContainsKey($k)
        $inGp = $gp.ContainsKey($k)
        $localKey = $(if ($local.ContainsKey($k)) { $k } elseif ($local.ContainsKey(($k -replace '^do', ''))) { $k -replace '^do', '' } else { $null })
        $setIn = New-Object 'System.Collections.Generic.List[string]'
        if ($inMdm) { $setIn.Add('mdm') }
        if ($inGp) { $setIn.Add('gp') }
        if ($localKey) { $setIn.Add('local') }

        $doKind = $null
        if ($Kinds.ContainsKey($name)) { $doKind = $Kinds[$name] }
        $kind = 'unknown'; $basis = 'unresolved'
        if ($doKind -and $doKind -ne 'unknown') { $kind = $doKind; $basis = 'do-service' }
        elseif ($inMdm -and $inGp) {
            if ($MdmWinsOverGp -eq $true) { $kind = 'mdm'; $basis = 'mdm-wins-over-gp' }
        } elseif ($inMdm) { $kind = 'mdm'; $basis = 'registry' }
        elseif ($inGp) { $kind = 'gp'; $basis = 'registry' }
        elseif ($localKey) { $kind = 'local'; $basis = 'registry' }

        $mdmInfo = $null
        if ($kind -eq 'mdm' -and $inMdm) { $mdmInfo = Resolve-DDMdmProvider -EnrollmentId $mdm[$k].WinningProvider -Enrollments $Enrollments }

        $value = $null
        if ($null -ne $Effective -and $Effective.Contains($name)) { $value = $Effective[$name]['value'] }
        elseif ($kind -eq 'gp' -and $inGp) { $value = $gp[$k].Value }
        elseif ($inMdm) { $value = $mdm[$k].Value }
        elseif ($inGp) { $value = $gp[$k].Value }

        $alt = New-Object 'System.Collections.Generic.List[object]'
        if ($setIn.Count -gt 1 -or ($setIn.Count -eq 1 -and $setIn[0] -ne $kind)) {
            if ($inMdm -and $kind -ne 'mdm') { $alt.Add([ordered]@{ store = 'mdm'; value = $mdm[$k].Value }) }
            if ($inGp -and $kind -ne 'gp') { $alt.Add([ordered]@{ store = 'gp'; value = $gp[$k].Value }) }
            if ($localKey -and $kind -ne 'local') { $alt.Add([ordered]@{ store = 'local'; value = $local[$localKey].Value }) }
        }
        $out[$name] = [ordered]@{
            value    = $value
            provider = (ConvertTo-DDProviderName -Text $kind)
            source   = [ordered]@{ kind = $kind; mdm = $mdmInfo; basis = $basis; setIn = $setIn.ToArray(); alt = $alt.ToArray() }
        }
    }
    $out
}

# ---- endpoints ---------------------------------------------------------------------------------------------------

$script:DDEndpointRoles = 'cache', 'cdn', 'lan', 'group', 'internet', 'peer'
$script:DDMaxEndpointRows = 256

function ConvertTo-DDNetworkPrefix {
    # '10.20.4.71' -> '10.20.4.0/24'; '2001:db8:1:2::5' -> '2001:db8:1::/48'. $null for anything that is not an address.
    [CmdletBinding()]
    param([AllowNull()][string] $Address)
    $ip = $null
    if (-not $Address -or -not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $null }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { return ('{0}.{1}.{2}.0/24' -f $b[0], $b[1], $b[2]) }
    for ($i = 6; $i -lt 16; $i++) { $b[$i] = 0 }
    ([System.Net.IPAddress]::new($b)).ToString() + '/48'
}

function Get-DDEndpointAddress {
    <#
    .SYNOPSIS
        The address of an endpoint as it may leave the device (ADR-0031).
    .DESCRIPTION
        Connected Cache servers and CDN nodes are infrastructure: sent in clear. Internet peers are other people's
        devices: always reduced to a /24 (IPv4) or /48 (IPv6) prefix. LAN and group peers are the organisation's own
        devices: in clear unless -Anonymise, then reduced to the prefix. Never a hash beside a prefix: a hash of an
        address inside a known /24 is undone by trying 256 values.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Role, [AllowNull()][string] $Address, [switch] $Anonymise)
    if (-not $Address) { return $null }
    if ($Role -in 'cache', 'cdn') { return (ConvertTo-DDCacheHostName -Value $Address) }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $null }
    if ([System.Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([System.Net.IPAddress]::Any) -or $ip.Equals([System.Net.IPAddress]::IPv6Any)) { return $null }
    if ($Role -eq 'internet' -or $Anonymise) { return (ConvertTo-DDNetworkPrefix -Address $ip.ToString()) }
    $ip.ToString().ToLowerInvariant()
}

function New-DDEndpointObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Role, [Parameter(Mandatory)][string] $Address, [Parameter(Mandatory)][string] $Via,
        $Rx = $null, $Tx = $null, [int] $Attempts = 0, [int] $Ok = 0, [int] $Fails = 0, $At = $null, [string] $Origin = $null
    )
    [pscustomobject]@{ Role = $Role; Address = $Address; Via = $Via; Rx = $Rx; Tx = $Tx; Attempts = $Attempts; Ok = $Ok; Fails = $Fails; At = $At; Origin = $Origin }
}

function ConvertTo-DDCacheOrigin {
    # The prefix DO writes before a cache host in its download telemetry ("cacheHost = Services:198.51.100.202"): Services
    # is the DO cloud service's assignment (the GEO response's CacheHost). Other prefixes are not observed (to-verify).
    [CmdletBinding()]
    param([AllowNull()][string] $Text)
    switch -Regex ([string]$Text) {
        '(?i)^services?$' { 'service' }
        '(?i)dhcp' { 'dhcp' }
        '(?i)polic|mdm|gp|admin|registry' { 'policy' }
        default { $null }
    }
}

function ConvertFrom-DDDoLogEndpoints {
    <#
    .SYNOPSIS
        Endpoint observations from Delivery Optimization log entries (Get-DeliveryOptimizationLog: TimeCreated, Function,
        Message).
    .DESCRIPTION
        Message formats, all read from a real DO log (Windows 11, DO client 10.1.0.15):
          CTelemetryLogger::TraceDownloadCompletedImpl  "... cdnIp = [150.171.109.244]:443;, cacheHost = Services:198.51.100.202,
                                                         bytes: [File: n, CDN: n, DOINC: n, ...]" (CDN includes DOINC, as
                                                         BytesFromHttp includes BytesFromCacheServer)
          CHttpPeerConn::Initiate                       "Swarm: <id>, initiating HTTP connection, IP: 198.51.100.202"
          CHttpPeerConn::_OnComplete                    "Swarm: <id>, HTTP connection: [198.51.100.202]:80, rLEDBAT? 0"
          CSwarmConn::Initiate                          "Swarm: <id>, initiating peer connection: [10.100.0.74]:7680"
          CTelemetryLogger::TraceErrorPeerComm          "FailurePeerConnect, hr: 8007274c, ..., peerIp: [10.100.0.74]:7680, peerId: , peerType: 1"
          CHttpDownloader::_DoSendRequest               "Unresponsive cache host 198.51.100.202"
          CConnMan::_StartNewHttpConns                  "Connecting to banned cache host 198.51.100.202. Time until fallback: ..."
          CServiceConfigProvider::_CallService          GEO response JSON with "CacheHost":"198.51.100.202" (the same JSON
                                                         holds the device's public address, which is never read here)
        No line with bytes per peer was found; peer bytes come from the peer list (CIM) instead.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()] $Entries,
        [AllowEmptyCollection()][string[]] $CacheHosts = @(),
        [string] $LocalAddress,
        [int] $PrefixLength = 24,
        # The device's IPv6 prefixes (Get-DDNetworkFacts LocalNetworks): an IPv6 peer inside one is on this network.
        [AllowEmptyCollection()][string[]] $LocalNetworks = @()
    )
    $obs = New-Object 'System.Collections.Generic.List[object]'
    $cache = @{}
    $origin = @{}
    $named = @{}  # cache hosts the log itself names (the ones passed in are only used to classify connections)
    foreach ($h in $CacheHosts) { $n = ConvertTo-DDCacheHostName $h; if ($n) { $cache[$n] = $true } }
    $ipRx = '(?<ip>[0-9A-Fa-f:.]+)'
    # first pass: every cache host the log names, so an HTTP connection to one is not mistaken for the CDN
    foreach ($e in @($Entries)) {
        $m = [string](Get-DDProp $e 'Message')
        if (-not $m) { continue }
        foreach ($x in [regex]::Matches($m, 'cacheHost = (?:(?<src>[A-Za-z]+):)?(?<h>[^,\s]+)')) {
            $n = ConvertTo-DDCacheHostName $x.Groups['h'].Value
            if ($n) { $cache[$n] = $true; $named[$n] = $true; $o = ConvertTo-DDCacheOrigin $x.Groups['src'].Value; if ($o) { $origin[$n] = $o } }
        }
        $g = [regex]::Match($m, '"CacheHost"\s*:\s*"(?<h>[^"]+)"')
        if ($g.Success) { $n = ConvertTo-DDCacheHostName $g.Groups['h'].Value; if ($n) { $cache[$n] = $true; $named[$n] = $true; if (-not $origin.ContainsKey($n)) { $origin[$n] = 'service' } } }
        $u = [regex]::Match($m, '(?:Unresponsive|banned) cache host (?<h>[^\s.,]+(?:\.[^\s.,]+)*)')
        if ($u.Success) { $n = ConvertTo-DDCacheHostName $u.Groups['h'].Value; if ($n) { $cache[$n] = $true; $named[$n] = $true } }
    }
    $peerRole = {
        param($ip, $typeNum)
        if ($null -ne $typeNum) {
            switch (ConvertTo-DDPeerType -Value $typeNum -AllowCdn) { 'Lan' { return 'lan' } 'Group' { return 'group' } 'Internet' { return 'internet' } 'CacheServer' { return 'cache' } 'Cdn' { return 'cdn' } }
        }
        # On this device's subnet, a link-local address, or inside one of its IPv6 prefixes.
        if (Test-DDSameSubnet -Address $ip -LocalAddress ([string]$LocalAddress) -PrefixLength $PrefixLength -LocalNetworks $LocalNetworks) { return 'lan' }
        'peer'
    }
    $httpRole = { param($a) $n = ConvertTo-DDCacheHostName $a; if ($n -and $cache.ContainsKey($n)) { 'cache' } else { 'cdn' } }
    foreach ($e in @($Entries)) {
        $m = [string](Get-DDProp $e 'Message')
        if (-not $m) { continue }
        $t = Get-DDProp $e 'TimeCreated', 'Time', 'Timestamp'
        if ($t -isnot [datetime]) { $t = $null }

        $done = [regex]::Match($m, 'cdnIp = \[?' + $ipRx + '\]?(?::(?<port>\d+))?;')
        if ($done.Success -and $m -match 'bytes: \[') {
            $cdnBytes = [System.Numerics.BigInteger]::Zero; $doinc = [System.Numerics.BigInteger]::Zero
            $b = [regex]::Match($m, 'bytes: \[[^\]]*?\bCDN: (?<cdn>\d+)'); if ($b.Success) { $cdnBytes = [System.Numerics.BigInteger]::Parse($b.Groups['cdn'].Value) }
            $b = [regex]::Match($m, 'bytes: \[[^\]]*?\bDOINC: (?<d>\d+)'); if ($b.Success) { $doinc = [System.Numerics.BigInteger]::Parse($b.Groups['d'].Value) }
            $ch = $null
            $c = [regex]::Match($m, 'cacheHost = (?:[A-Za-z]+:)?(?<h>[^,\s]+)'); if ($c.Success) { $ch = ConvertTo-DDCacheHostName $c.Groups['h'].Value }
            $ip = $done.Groups['ip'].Value
            if ((& $httpRole $ip) -eq 'cache') {
                $obs.Add((New-DDEndpointObservation -Role cache -Address $ip -Via log -Rx $doinc -At $t))
            } else {
                $http = $(if ($cdnBytes -ge $doinc) { $cdnBytes - $doinc } else { $cdnBytes })
                $obs.Add((New-DDEndpointObservation -Role cdn -Address $ip -Via log -Rx $http -At $t))
                if ($ch -and $doinc -gt 0) { $obs.Add((New-DDEndpointObservation -Role cache -Address $ch -Via log -Rx $doinc -At $t)) }
            }
            continue
        }
        $x = [regex]::Match($m, 'initiating HTTP connection, IP: ' + $ipRx)
        if ($x.Success) { $ip = $x.Groups['ip'].Value; $obs.Add((New-DDEndpointObservation -Role (& $httpRole $ip) -Address $ip -Via log -Attempts 1 -At $t)); continue }
        $x = [regex]::Match($m, 'HTTP connection: \[' + $ipRx + '\]')
        if ($x.Success) { $ip = $x.Groups['ip'].Value; $obs.Add((New-DDEndpointObservation -Role (& $httpRole $ip) -Address $ip -Via log -Ok 1 -At $t)); continue }
        $x = [regex]::Match($m, 'initiating peer connection: \[' + $ipRx + '\]')
        if ($x.Success) { $ip = $x.Groups['ip'].Value; $obs.Add((New-DDEndpointObservation -Role (& $peerRole $ip $null) -Address $ip -Via log -Attempts 1 -At $t)); continue }
        $x = [regex]::Match($m, 'peerIp: \[' + $ipRx + '\](?::\d+)?(?:,.*?peerType: (?<pt>\d+))?')
        if ($x.Success) {
            $ip = $x.Groups['ip'].Value
            $pt = $(if ($x.Groups['pt'].Success) { $x.Groups['pt'].Value } else { $null })
            $obs.Add((New-DDEndpointObservation -Role (& $peerRole $ip $pt) -Address $ip -Via log -Fails 1 -At $t)); continue
        }
        $x = [regex]::Match($m, '(?:Unresponsive|banned) cache host (?<h>[^\s,]+?)\.?(?:\s|$)')
        if ($x.Success) { $obs.Add((New-DDEndpointObservation -Role cache -Address $x.Groups['h'].Value -Via log -Fails 1 -At $t)); continue }
    }
    foreach ($h in $named.Keys) {
        $o = $(if ($origin.ContainsKey($h)) { $origin[$h] } else { $null })
        $obs.Add((New-DDEndpointObservation -Role cache -Address $h -Via log -Origin $o))
    }
    , $obs.ToArray()
}

function ConvertFrom-DDStatusEndpoints {
    # Connected Cache per file (Get-DeliveryOptimizationStatus CacheHost, documented "IP address for the cache server";
    # also set on files the cache served nothing for, so `rx` decides "used").
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Items, $At = $null)
    $obs = New-Object 'System.Collections.Generic.List[object]'
    foreach ($i in @($Items)) {
        $h = ConvertTo-DDCacheHostName (Get-DDProp $i 'CacheHost')
        if (-not $h) { continue }
        $conn = Get-DDProp $i 'CacheServerConnectionCount'
        $obs.Add((New-DDEndpointObservation -Role cache -Address $h -Via status -Rx (ConvertTo-DDBigInt (Get-DDProp $i 'BytesFromCacheServer')) -Attempts $(if ($null -ne $conn) { [int]$conn } else { 0 }) -At $At))
    }
    , $obs.ToArray()
}

function ConvertFrom-DDPeerEndpoints {
    # The swarm peer list (MSFT_DeliveryOptimizationFilePeerInfo: IPs, PeerTypes, BytesReceived, BytesSent,
    # ConnectionEstablished; flattened to one object per peer by Get-DDDOPeerInfoRaw).
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Items, $At = $null)
    $obs = New-Object 'System.Collections.Generic.List[object]'
    foreach ($it in @($Items)) {
        $inner = Get-DDProp $it 'Peers', 'PeersInfo', 'PeerInfo'
        $set = $(if ($null -ne $inner -and $inner -isnot [string]) { @($inner) } elseif ($it -isnot [string]) { @($it) } else { @() })
        foreach ($p in $set) {
            $ip = [string](Get-DDProp $p 'IP', 'IPAddress', 'PeerIP')
            if (-not $ip) { continue }
            $role = switch (ConvertTo-DDPeerType -Value (Get-DDProp $p 'PeerType') -AllowCdn) { 'Lan' { 'lan' } 'Group' { 'group' } 'Internet' { 'internet' } 'CacheServer' { 'cache' } 'Cdn' { 'cdn' } default { 'peer' } }
            $est = Get-DDProp $p 'ConnectionEstablished'
            $obs.Add((New-DDEndpointObservation -Role $role -Address $ip -Via peers -Rx (ConvertTo-DDBigInt (Get-DDProp $p 'BytesReceived')) -Tx (ConvertTo-DDBigInt (Get-DDProp $p 'BytesSent')) -Attempts 1 -Ok $(if ($est -eq $true) { 1 } else { 0 }) -At $At))
        }
    }
    , $obs.ToArray()
}

function ConvertFrom-DDTcpEndpoints {
    # DoSvc's TCP connections at the moment of collection (Get-NetTCPConnection -OwningProcess <DoSvc PID>; DoSvc runs in
    # its own svchost). Port 7680 either way is a peer; a connection to a known cache host is the cache. Other HTTPS is the
    # DO cloud service, not content, and is not reported.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Items, [AllowEmptyCollection()][string[]] $CacheHosts = @(), [string] $LocalAddress, [int] $PrefixLength = 24, $At = $null,
        [AllowEmptyCollection()][string[]] $LocalNetworks = @())
    $obs = New-Object 'System.Collections.Generic.List[object]'
    $cache = @{}
    foreach ($h in $CacheHosts) { $n = ConvertTo-DDCacheHostName $h; if ($n) { $cache[$n] = $true } }
    foreach ($c in @($Items)) {
        $remote = [string](Get-DDProp $c 'RemoteAddress')
        $state = [string](Get-DDProp $c 'State')
        if (-not $remote -or $state -match '(?i)^(Listen|Bound)$') { continue }
        $rp = [int](Get-DDProp $c 'RemotePort'); $lp = [int](Get-DDProp $c 'LocalPort')
        $when = Get-DDProp $c 'CreationTime'; if ($when -isnot [datetime]) { $when = $At }
        $ok = $(if ($state -match '(?i)^Established$') { 1 } else { 0 })
        $n = ConvertTo-DDCacheHostName $remote
        if ($n -and $cache.ContainsKey($n)) { $obs.Add((New-DDEndpointObservation -Role cache -Address $remote -Via tcp -Attempts 1 -Ok $ok -At $when)); continue }
        if ($rp -eq 7680 -or $lp -eq 7680) {
            $role = $(if (Test-DDSameSubnet -Address $remote -LocalAddress ([string]$LocalAddress) -PrefixLength $PrefixLength -LocalNetworks $LocalNetworks) { 'lan' } else { 'peer' })
            $obs.Add((New-DDEndpointObservation -Role $role -Address $remote -Via tcp -Attempts 1 -Ok $ok -At $when))
        }
    }
    , $obs.ToArray()
}

function Merge-DDEndpoints {
    <#
    .SYNOPSIS
        Fold endpoint observations into the bundle's `endpoints` rows: privacy applied, one row per role and address.
    .DESCRIPTION
        An address seen as an untyped peer takes the type another source gave it. Bytes are the largest any one source
        reported (the job list and the log overlap; adding them would count the same bytes twice). Rows are ordered
        cache first, then by bytes, then by connections, and capped.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Observations, [Parameter(Mandatory)] $Context, [int] $Max = $script:DDMaxEndpointRows)
    $typed = @{}
    foreach ($o in @($Observations)) { if ($o.Role -in 'lan', 'group', 'internet') { $typed[[string]$o.Address] = $o.Role } }
    $rows = [ordered]@{}
    foreach ($o in @($Observations)) {
        $role = [string]$o.Role
        if ($role -eq 'peer' -and $typed.ContainsKey([string]$o.Address)) { $role = $typed[[string]$o.Address] }
        if ($role -notin $script:DDEndpointRoles) { continue }
        $addr = Get-DDEndpointAddress -Role $role -Address ([string]$o.Address) -Anonymise:$Context.Anonymise
        if (-not $addr) { continue }
        $key = "$role|$addr"
        if (-not $rows.Contains($key)) {
            $rows[$key] = @{ role = $role; addr = $addr; raw = (New-Object 'System.Collections.Generic.HashSet[string]'); rx = @{}; tx = @{}; conns = 0; ok = 0; fails = 0; first = $null; last = $null; via = (New-Object 'System.Collections.Generic.List[string]'); origin = $null }
        }
        $r = $rows[$key]
        [void]$r.raw.Add(([string]$o.Address).ToLowerInvariant())
        if ($null -ne $o.Rx) { if (-not $r.rx.ContainsKey($o.Via)) { $r.rx[$o.Via] = [System.Numerics.BigInteger]::Zero }; $r.rx[$o.Via] += (ConvertTo-DDBigInt $o.Rx) }
        if ($null -ne $o.Tx) { if (-not $r.tx.ContainsKey($o.Via)) { $r.tx[$o.Via] = [System.Numerics.BigInteger]::Zero }; $r.tx[$o.Via] += (ConvertTo-DDBigInt $o.Tx) }
        $r.conns += [int]$o.Attempts; $r.ok += [int]$o.Ok; $r.fails += [int]$o.Fails
        if ($o.At -is [datetime]) {
            $u = $o.At.ToUniversalTime()
            if ($null -eq $r.first -or $u -lt $r.first) { $r.first = $u }
            if ($null -eq $r.last -or $u -gt $r.last) { $r.last = $u }
        }
        if (-not $r.via.Contains([string]$o.Via)) { $r.via.Add([string]$o.Via) }
        if ($o.Origin -and -not $r.origin) { $r.origin = [string]$o.Origin }
    }
    $best = { param($h) $m = $null; foreach ($v in $h.Values) { if ($null -eq $m -or $v -gt $m) { $m = $v } }; $m }
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $rows.Values) {
        $rx = & $best $r.rx; $tx = & $best $r.tx
        $list.Add([ordered]@{
                role   = $r.role
                addr   = $r.addr
                n      = [math]::Max(1, $r.raw.Count)
                rx     = $(if ($null -ne $rx) { $rx.ToString() } else { $null })
                tx     = $(if ($null -ne $tx) { $tx.ToString() } else { $null })
                conns  = $r.conns
                ok     = $r.ok
                fails  = $r.fails
                first  = $(if ($r.first) { Format-DDIso -Value $r.first } else { $null })
                last   = $(if ($r.last) { Format-DDIso -Value $r.last } else { $null })
                via    = @($r.via | Sort-Object)
                origin = $r.origin
            })
    }
    Select-DDEndpointRows -Rows $list.ToArray() -Max $Max
}

function Select-DDEndpointRows {
    # Order and cap endpoint rows: cache first, then bytes (rx + tx) descending, then connections, insertion order last.
    # The same rule as selectEndpoints in packages/wire/src/compact.ts.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Rows, [int] $Max)
    $wrapped = New-Object 'System.Collections.Generic.List[object]'
    $i = 0
    foreach ($r in @($Rows)) {
        $b = (ConvertTo-DDBigInt $r['rx']) + (ConvertTo-DDBigInt $r['tx'])
        $wrapped.Add([pscustomobject]@{ I = $i; C = $(if ($r['role'] -eq 'cache') { 0 } else { 1 }); B = $b; N = [int]$r['conns']; V = $r }); $i++
    }
    $cmp = [System.Comparison[object]] {
        param($a, $b)
        if ($a.C -ne $b.C) { return ($a.C - $b.C) }
        $c = [System.Numerics.BigInteger]::Compare($b.B, $a.B)
        if ($c -ne 0) { return $c }
        if ($a.N -ne $b.N) { return ($b.N - $a.N) }
        return ($a.I - $b.I)
    }
    $wrapped.Sort($cmp)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($w in $wrapped) { if ($out.Count -ge $Max) { break }; $out.Add($w.V) }
    , $out.ToArray()
}
