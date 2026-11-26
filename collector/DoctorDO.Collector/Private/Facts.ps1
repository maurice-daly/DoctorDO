#Requires -Version 5.1
# On-device fact builders for the inventory (docs/08 "Collection strategy"). Each builder calls wrappers from
# Platform.ps1 inside Invoke-DDStep, so a failing source becomes a notCollected record, never a crash and never
# a silent gap. Pure mapping helpers are separate functions with their own tests.

Set-StrictMode -Version Latest

# Delivery Optimization's own default keyword list, which it matches in the adapter's Description and FriendlyName (Learn, DO
# reference, "VPN keywords": "VPN", "Secure", and "Virtual Private Network"), then DoctorDO's list of VPN client names.
$script:DDDoDefaultVpnKeywords = @('vpn', 'secure', 'virtual private network')
$script:DDVpnKeywords = @($script:DDDoDefaultVpnKeywords) + @('tunnel', 'anyconnect', 'globalprotect', 'pangp', 'forti', 'wireguard', 'openvpn', 'tap-windows', 'juniper', 'pulse secure',
    'zscaler', 'nordlynx', 'sonicwall', 'checkpoint', 'wan miniport (ikev2)', 'wan miniport (l2tp)', 'wan miniport (pptp)', 'wan miniport (sstp)', 'cisco')
$script:DDNonVpnTunnel = 'teredo|6to4|isatap|hyper-v|virtualbox|vmware|bluetooth|loopback|ip-https'
$script:DDPlaceholderSerial = '(?i)^(none|n/a|default string|to be filled by o\.e\.m\.|system serial number|0|unknown|not specified)$'

function ConvertTo-DDVpnKeywordList {
    # The keywords DO is configured with (Get-DOConfig VpnKeywords, the DOVpnKeywords policy: "separate each by a comma"), as a
    # list of whole phrases: split on commas (and semicolons), never on spaces, so "Virtual Private Network" stays one keyword.
    [CmdletBinding()]
    param([AllowNull()] $Value)
    @($Value) | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_) -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique
}

function Get-DDVpnKeywordMatch {
    # The keyword that marks the adapter as a VPN, or $null: DoctorDO's own heuristic (DO's defaults, the built-in client names,
    # and the keywords DO is configured with), which can still differ from DO's decision. Known tunnels that are not VPNs never match.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Adapter, [AllowNull()][string[]] $ExtraKeywords = @())
    $text = ('{0} {1}' -f $Adapter.Name, $Adapter.Description).ToLowerInvariant()
    if ($text -match $script:DDNonVpnTunnel) { return $null }
    foreach ($k in (@($script:DDVpnKeywords) + @($ExtraKeywords | Where-Object { $_ }))) { $kw = ([string]$k).ToLowerInvariant(); if ($text.Contains($kw)) { return $kw } }
    $null
}

function Test-DDVpnAdapter {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Adapter, [AllowNull()][string[]] $ExtraKeywords = @())
    $null -ne (Get-DDVpnKeywordMatch -Adapter $Adapter -ExtraKeywords $ExtraKeywords)
}

function ConvertTo-DDAdapterType {
    [CmdletBinding()]
    param($Adapter, [AllowNull()][string[]] $ExtraKeywords = @())
    if ($null -eq $Adapter) { return 'Unknown' }
    if (Test-DDVpnAdapter -Adapter $Adapter -ExtraKeywords $ExtraKeywords) { return 'VPN' }
    $t = ('{0} {1} {2}' -f $Adapter.PhysicalMediaType, $Adapter.MediaType, $Adapter.Description).ToLowerInvariant()
    if ($t -match '802\.11|wi-?fi|wireless lan|wlan') { return 'Wi-Fi' }
    if ($t -match 'wireless wan|mobile broadband|cellular|wwan') { return 'Cellular' }
    if ($t -match '802\.3|ethernet') { return 'Ethernet' }
    'Other'
}

function ConvertFrom-DDProxyState {
    <#
    .SYNOPSIS
        Derive the proxy facts and scope from the WinINET registry state and `netsh winhttp show proxy`.
        Precedence rules: docs/17 section 4.3 (https://learn.microsoft.com/windows/deployment/do/delivery-optimization-proxy).
    #>
    [CmdletBinding()]
    param($Internet, [AllowNull()][string[]] $Netsh = @(), [switch] $IsSystem)

    $val = { param($set, $n) if ($null -eq $set) { return $null }; foreach ($v in @($set.Values)) { if ($v['name'] -ieq $n) { return $v['data'] } }; $null }
    $uEnable = & $val $Internet.User 'ProxyEnable'
    $uPac = & $val $Internet.User 'AutoConfigURL'
    $mEnable = & $val $Internet.Machine 'ProxyEnable'
    $mServer = & $val $Internet.Machine 'ProxyServer'
    $mPac = & $val $Internet.Machine 'AutoConfigURL'
    $override = & $val $Internet.User 'ProxyOverride'
    if (-not $override) { $override = & $val $Internet.Machine 'ProxyOverride' }
    $perUserPolicy = Get-DDProp $Internet 'ProxySettingsPerUser'
    $deviceWide = ($null -ne $perUserPolicy -and [int]$perUserPolicy -eq 0) -and ($mEnable -eq '1' -or $mServer -or $mPac)
    $perUser = (-not $IsSystem) -and ($uEnable -eq '1' -or $uPac)
    $scope = 'none'
    if ($deviceWide) { $scope = 'device-wide' } elseif ($perUser) { $scope = 'per-user' }
    $netshText = (@($Netsh) -join "`n")
    $netshConfigured = ($netshText -match '(?i)Proxy Server\(s\)\s*:') -and ($netshText -notmatch '(?i)Direct access')
    $pac = $(if ($deviceWide -and $mPac) { $mPac } else { $uPac })
    $auto = $false
    $conn = Get-DDProp $Internet 'DefaultConnectionSettings'
    if ($conn -is [string] -and $conn.Length -ge 18) { $flags = [Convert]::ToInt32($conn.Substring(16, 2), 16); $auto = (($flags -band 0x08) -ne 0) }
    [ordered]@{
        configured      = ($scope -ne 'none') -or $netshConfigured
        wininetScope    = $scope
        netshConfigured = [bool]$netshConfigured
        autoDetect      = [bool]$auto
        pacUrlHost      = $(if ($pac) { Get-DDUrlHost -Url $pac } else { $null })
        bypassLocal     = $(if ($override) { ([string]$override -match '<local>') } else { $false })
    }
}

function Get-DDNetworkFacts {
    <#
    .SYNOPSIS
        Network facts (packages/schema NetworkFacts). From October 2026 `localSubnet` is the subnet of the adapter DO uses
        (-DoAdapter, Select-DDDoAdapter), with the default route's subnet kept as `defaultRouteSubnet` when it differs; DHCP
        options 234 and 235 are read on that adapter when DO itself would read them; and the public egress, when egress
        collection is on (-CollectPublicEgress or -PublicIpProbeUri), comes from the DO geo answer first.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context, [string] $PublicIpProbeUri, [switch] $SkipPublicIp, $VpnKeywords,
        $Raw = $null, [switch] $RawCollected, $DoAdapter = $null, $Geo = $null, $Effective = $null, [switch] $CollectPublicEgress
    )

    $raw = $Raw
    if (-not $RawCollected) { $raw = Invoke-DDStep -Context $Context -Field 'network' -Script { Get-DDNetworkRaw } }
    $adapters = @(); $active = $null; $ipv4 = $null; $prefix = 24; $gateway = $null
    if ($raw) {
        $adapters = @($raw.Adapters)
        $active = $adapters | Where-Object { $_.IfIndex -eq $raw.DefaultInterfaceIndex } | Select-Object -First 1
        $ipv4 = $raw.IPv4; $gateway = $raw.Gateway
        if ($null -ne $raw.PrefixLength) { $prefix = [int]$raw.PrefixLength }
    }
    $extraKw = @(ConvertTo-DDVpnKeywordList -Value $VpnKeywords)
    $upVpn = @($adapters | Where-Object { $_.Status -eq 'Up' -and (Test-DDVpnAdapter -Adapter $_ -ExtraKeywords $extraKw) })
    # Which keyword marked each adapter, so the console can say why DoctorDO calls it a VPN; and whether DO's own default list
    # alone would (the documented keywords, without DoctorDO's client names or the configured ones).
    $matchedKw = @($upVpn | ForEach-Object { Get-DDVpnKeywordMatch -Adapter $_ -ExtraKeywords $extraKw } | Where-Object { $_ } | Select-Object -Unique -First 16 | ForEach-Object { $_.Substring(0, [math]::Min(64, $_.Length)) })
    $doDefault = @($upVpn | Where-Object { $t = ('{0} {1}' -f $_.Name, $_.Description).ToLowerInvariant(); @($script:DDDoDefaultVpnKeywords | Where-Object { $t.Contains($_) }).Count -gt 0 })
    $routeSubnet = $null
    if ($ipv4) { $routeSubnet = Get-DDSubnetString -Address $ipv4 -PrefixLength $prefix }
    $subnet = $routeSubnet
    $doAdapterOut = $null
    if ($null -ne $DoAdapter) {
        $doSubnet = Get-DDSubnetString -Address $DoAdapter.IPv4 -PrefixLength $DoAdapter.PrefixLength
        $doAdapterOut = [ordered]@{
            name = $(if ($Context.Anonymise) { $null } else { [string]$DoAdapter.Name })
            kind = [string]$DoAdapter.Kind; type = [string]$DoAdapter.Type; ifType = [int]$DoAdapter.IfType; subnet = $doSubnet
            defaultRoute = $DoAdapter.DefaultRoute
        }
        if ($doSubnet) { $subnet = $doSubnet; $ipv4 = $DoAdapter.IPv4; $prefix = [int]$DoAdapter.PrefixLength }
    }
    if ($gateway -and $Context.Anonymise) { $gateway = Protect-DDTopologyValue -Value $gateway -Salt $Context.Salt -Tag 'ip' }

    $cost = Invoke-DDStep -Context $Context -Field 'network.isMetered' -Script { Get-DDConnectionCost }
    if ($null -eq $cost) { Add-DDNotCollected -Context $Context -Field 'network.isMetered' -Reason 'unsupported-os' -Detail 'NetworkCostType needs the Windows Runtime (Windows PowerShell 5.1); reported as false' }
    $metered = ($cost -and $cost -ne 'Unrestricted' -and $cost -ne 'Unknown')

    $adSite = Invoke-DDStep -Context $Context -Field 'network.adSite' -Script { Get-DDAdSiteName }
    $internet = Invoke-DDStep -Context $Context -Field 'network.proxy' -Script { Get-DDInternetSettings }
    $netsh = Invoke-DDStep -Context $Context -Field 'network.proxy.netsh' -Script { Get-DDNetshWinHttpProxy } -Default @()
    $isSystem = Test-DDSystemContext
    if ($isSystem) { Add-DDNotCollected -Context $Context -Field 'network.proxy.wininetScope' -Reason 'insufficient-rights' -Detail 'per-user WinINET proxy is not observable from the SYSTEM account; device-wide and netsh are reported' }
    $proxy = [ordered]@{ configured = $false; wininetScope = 'none'; netshConfigured = $false; autoDetect = $false; pacUrlHost = $null; bypassLocal = $false }
    if ($internet) { $proxy = ConvertFrom-DDProxyState -Internet $internet -Netsh $netsh -IsSystem:$isSystem }
    if ($proxy['pacUrlHost'] -and $Context.Anonymise) { $proxy['pacUrlHost'] = Protect-DDTopologyValue -Value $proxy['pacUrlHost'] -Salt $Context.Salt }

    # DHCP options 234 and 235, on the adapter DO uses, only when DO itself would read them (Health.ps1).
    $dhcp = Get-DDDhcpFacts -Context $Context -Effective $Effective -Adapter $DoAdapter -Geo $Geo
    $v234 = $dhcp.Values['234']; $v235 = $dhcp.Values['235']
    foreach ($id in @($dhcp.Facts['wants'])) {
        if ($dhcp.Facts['state'] -ne 'answered') { Add-DDNotCollected -Context $Context -Field "network.dhcpOption$id" -Reason $(if ($dhcp.Facts['state'] -eq 'timeout') { 'timeout' } else { 'error' }) -Detail "DHCP option $id could not be read ($($dhcp.Facts['state']))" }
    }
    if ($Context.Anonymise) {
        # Hashed with the tenant's salt, like DOGroupId, so devices given the same group compare equal (linkable within the tenant).
        if ($v234) { $v234 = Protect-DDTopologyValue -Value $v234 -Salt $Context.TenantSalt -Tag 'redacted' }
        # DHCP option 235 names the Connected Cache server: infrastructure, kept in clear (ADR-0031).
    }

    $merge = Invoke-DDStep -Context $Context -Field 'network.localPolicyMergeEnabled' -Script { Get-DDFirewallProfilesRaw }
    $lpm = $null
    if ($merge) { $lpm = -not [bool](@($merge) | Where-Object { $_.AllowLocalFirewallRules -eq 'False' }) }

    # Public egress: only when egress collection is on. The DO geo answer (Microsoft's own service, which DO already
    # calls) is the source; -PublicIpProbeUri is the fallback when it gave none. Hashed at once with the tenant salt, as
    # before (a hash of an address can be reversed by enumeration by anyone who knows the tenant ID; unchanged here).
    $egress = $null
    $egressOn = ([bool]$PublicIpProbeUri -or $CollectPublicEgress) -and -not $SkipPublicIp
    if ($egressOn) {
        $ip = $(if ($null -ne $Geo -and $Geo.ExternalIp) { [string]$Geo.ExternalIp } else { $null })
        if (-not $ip -and $PublicIpProbeUri) { $ip = Invoke-DDStep -Context $Context -Field 'network.publicEgressHash' -Script { Invoke-DDPublicIpProbe -Uri $PublicIpProbeUri } }
        if ($ip) { $egress = Get-DDSaltedHash -Value $ip -Salt $Context.TenantSalt -Domain 'egress' }
        else { Add-DDNotCollected -Context $Context -Field 'network.publicEgressHash' -Reason 'error' -Detail 'egress collection is on, but neither the DO geo answer nor the probe URI gave a public address' }
        $ip = $null
    } else {
        Add-DDNotCollected -Context $Context -Field 'network.publicEgressHash' -Reason 'skipped-by-flag' -Detail 'egress collection is off: -CollectPublicEgress reads it from the DO geo answer; DoctorDO calls no third-party IP service by default'
    }

    $net = [ordered]@{
        adapterType               = (ConvertTo-DDAdapterType -Adapter $active -ExtraKeywords $extraKw)
        isVpnActive               = ($upVpn.Count -gt 0)
        vpnAdapterNames           = @($upVpn | Select-Object -First 16 | ForEach-Object { [string]$_.Name })
        matchesDefaultVpnKeywords = ($doDefault.Count -gt 0)
        vpnMatchedKeywords        = [string[]]$matchedKw
        isMetered                 = [bool]$metered
        localSubnet               = $subnet
        defaultGateway            = $gateway
        publicEgressHash          = $egress
        adSite                    = $adSite
        dhcpOption234             = $v234
        dhcpOption235             = $v235
        localPolicyMergeEnabled   = $lpm
        proxy                     = $proxy
    }
    if ($null -ne $doAdapterOut) { $net['doAdapter'] = $doAdapterOut }
    if ($null -ne $doAdapterOut -and $routeSubnet -and $routeSubnet -ne $subnet) { $net['defaultRouteSubnet'] = $routeSubnet }
    $net['dhcp'] = $dhcp.Facts
    # LocalNetworks: the device's IPv6 prefixes (in memory only), for Test-DDSameSubnet -LocalNetworks.
    $v6 = @(Get-DDProp $raw 'IPv6Networks' | Where-Object { $_ } | ForEach-Object { [string]$_ })
    [pscustomobject]@{ Network = $net; IPv4 = $ipv4; PrefixLength = $prefix; LocalNetworks = [string[]]$v6; FirewallProfiles = @($merge); Dhcp = $dhcp.Facts; Dhcp235 = $dhcp.Values['235'] }
}

function Get-DDEditionSupported {
    [CmdletBinding()]
    param([string] $EditionId)
    # DO policies apply to Pro, Enterprise, Education and IoT Enterprise (DMClient/DO policy CSP applicability tables).
    [bool]($EditionId -match '(?i)Professional|Enterprise|Education|IoTEnterprise|Server')
}

function ConvertTo-DDChassis {
    [CmdletBinding()]
    param([int[]] $ChassisTypes = @(), [bool] $IsVirtual)
    if ($IsVirtual) { return 'VM' }
    foreach ($t in $ChassisTypes) {
        if ($t -in 8, 9, 10, 14, 31, 32) { return 'Laptop' }
        if ($t -in 30) { return 'Tablet' }
        if ($t -in 17, 23, 28) { return 'Server' }
        if ($t -in 3, 4, 5, 6, 7, 13, 15, 16, 24, 34, 35, 36) { return 'Desktop' }
    }
    'Unknown'
}

function Get-DDOsFacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context)

    $cv = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $r = Invoke-DDStep -Context $Context -Field 'os' -Script {
        [pscustomobject]@{
            Major   = Get-DDRegistryValue -Path $cv -Name 'CurrentMajorVersionNumber'
            Minor   = Get-DDRegistryValue -Path $cv -Name 'CurrentMinorVersionNumber'
            Build   = Get-DDRegistryValue -Path $cv -Name 'CurrentBuild'
            Ubr     = Get-DDRegistryValue -Path $cv -Name 'UBR'
            Edition = Get-DDRegistryValue -Path $cv -Name 'EditionID'
            Product = Get-DDRegistryValue -Path $cv -Name 'ProductName'
            Display = $(if (Get-DDRegistryValue -Path $cv -Name 'DisplayVersion') { Get-DDRegistryValue -Path $cv -Name 'DisplayVersion' } else { Get-DDRegistryValue -Path $cv -Name 'ReleaseId' })
            Install = Get-DDRegistryValue -Path $cv -Name 'InstallDate'
        }
    }
    if ($null -eq $r -or -not $r.Build) { return $null }
    $major = $(if ($null -ne $r.Major) { [int]$r.Major } else { 10 })
    $minor = $(if ($null -ne $r.Minor) { [int]$r.Minor } else { 0 })
    $build = '{0}.{1}.{2}' -f $major, $minor, $r.Build
    $product = [string]$r.Product
    # Windows 11 still reports "Windows 10 ..." in ProductName; build 22000+ is Windows 11 (observed, widely documented behaviour).
    if ([int]$r.Build -ge 22000 -and $product -match '^Windows 10') { $product = $product -replace '^Windows 10', 'Windows 11' }
    $ubr = $(if ($null -ne $r.Ubr) { [int]$r.Ubr } else { $null })
    $install = $null
    # InstallDate counts seconds since 1970-01-01 UTC; the date is the UTC one. (Adding the seconds to a local 1970 time, as
    # before, shifted a date near midnight by the daylight-saving difference.)
    if ($null -ne $r.Install) { $install = [System.DateTimeOffset]::FromUnixTimeSeconds([int64][uint32]$r.Install).UtcDateTime.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) }
    [pscustomobject]@{
        Os = [ordered]@{ build = $build; ubr = $ubr; edition = $(if ($product) { $product } else { [string]$r.Edition }); displayVersion = $(if ($r.Display) { [string]$r.Display } else { $null }); installDate = $install }
        FullBuild = $(if ($null -ne $ubr) { "$build.$ubr" } else { $build })
        EditionId = [string]$r.Edition
    }
}

function Get-DDHardwareFacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context)

    $bios = 'HKLM\HARDWARE\DESCRIPTION\System\BIOS'
    $dev = Invoke-DDStep -Context $Context -Field 'hardware.devDetail' -Script { Get-DDDevDetail }
    $manu = Get-DDProp $dev 'OEM'
    $model = Get-DDProp $dev 'DevTyp'
    if (-not $manu) { $manu = Invoke-DDStep -Context $Context -Field 'hardware.manufacturer' -Script { Get-DDRegistryValue -Path $bios -Name 'SystemManufacturer' } }
    if (-not $model) { $model = Invoke-DDStep -Context $Context -Field 'hardware.model' -Script { Get-DDRegistryValue -Path $bios -Name 'SystemProductName' } }
    $biosVersion = Invoke-DDStep -Context $Context -Field 'hardware.biosVersion' -Script { Get-DDRegistryValue -Path $bios -Name 'BIOSVersion' }
    if ($biosVersion -is [array]) { $biosVersion = $biosVersion -join ' ' }
    $board = @(Invoke-DDStep -Context $Context -Field 'hardware.serialHash' -Script { Get-DDCim -ClassName 'Win32_BaseBoard' } -Default @())
    $serialHash = $null
    if ($board.Count -gt 0) {
        $sn = [string](Get-DDProp $board[0] 'SerialNumber')
        if ($sn -and $sn.Trim() -notmatch $script:DDPlaceholderSerial) { $serialHash = Get-DDSaltedHash -Value $sn.Trim() -Salt $Context.Salt -Domain 'serial' }
        else { Add-DDNotCollected -Context $Context -Field 'hardware.serialHash' -Reason 'error' -Detail 'baseboard serial number is empty or a placeholder' }
    }
    $cpus = @(Invoke-DDStep -Context $Context -Field 'hardware.cpu' -Script { Get-DDCim -ClassName 'Win32_Processor' } -Default @())
    $cpuName = $null; $cores = $null
    if ($cpus.Count -gt 0) {
        $cpuName = ([string](Get-DDProp $cpus[0] 'Name')).Trim()
        $sum = 0; foreach ($c in $cpus) { $n = Get-DDProp $c 'NumberOfLogicalProcessors'; if ($n) { $sum += [int]$n } }
        if ($sum -gt 0) { $cores = $sum }
    }
    $tpm = $null
    $tpmRaw = Invoke-DDStep -Context $Context -Field 'hardware.tpm' -Script { Get-DDTpmRaw }
    if ($tpmRaw) { $ver = ([string]$tpmRaw.SpecVersion).Split(',')[0].Trim(); $tpm = [ordered]@{ present = $true; version = $(if ($ver) { $ver } else { $null }) } }
    elseif ($null -ne $tpmRaw) { $tpm = $null }
    $disks = New-Object 'System.Collections.Generic.List[object]'
    foreach ($d in @(Invoke-DDStep -Context $Context -Field 'hardware.disks' -Script { Get-DDPhysicalDisks } -Default @())) {
        if ($disks.Count -ge 8 -or $d.Size -le 0) { continue }
        $kind = 'Unknown'
        if ($d.BusType -eq 17) { $kind = 'NVMe' } elseif ($d.MediaType -eq 4) { $kind = 'SSD' } elseif ($d.MediaType -eq 3) { $kind = 'HDD' }
        $disks.Add([ordered]@{ kind = $kind; sizeGB = [math]::Round($d.Size / 1GB, 1) })
    }
    [ordered]@{
        manufacturer = $(if ($manu) { ([string]$manu).Trim() } else { $null })
        model        = $(if ($model) { ([string]$model).Trim() } else { $null })
        serialHash   = $serialHash
        biosVersion  = $(if ($biosVersion) { ([string]$biosVersion).Trim() } else { $null })
        cpu          = [ordered]@{ name = $cpuName; logicalCores = $cores }
        tpm          = $tpm
        disks        = $disks.ToArray()
    }
}

function Get-DDManagementFacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, $Dsreg, [bool] $IsConfigMgrClient, $ConfigMgr)

    $enrol = @(Invoke-DDStep -Context $Context -Field 'management.mdm' -Script { Get-DDEnrollmentRecords } -Default @())
    $intune = $enrol | Where-Object { $_.ProviderId -eq 'MS DM Server' -or ([string]$_.DiscoveryUrl -match 'manage\.microsoft\.com') } | Select-Object -First 1
    $other = $enrol | Where-Object { $_.ProviderId } | Select-Object -First 1
    $rec = $(if ($intune) { $intune } else { $other })
    $guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $intuneId = $null
    if ($intune -and [string]$intune.EntDmId -match $guid) { $intuneId = ([string]$intune.EntDmId).ToLowerInvariant() }
    if ($intune -and -not $intuneId) { $intuneId = Invoke-DDStep -Context $Context -Field 'management.mdm.intuneDeviceId' -Script { Get-DDIntuneDeviceIdFromCertificate } }
    $serverHost = $null
    if ($rec -and $rec.DiscoveryUrl) { $serverHost = Get-DDUrlHost -Url ([string]$rec.DiscoveryUrl) }
    $mdm = [ordered]@{
        enrolled       = [bool]$rec
        provider       = $(if ($intune) { 'intune' } elseif ($rec) { 'other' } else { 'none' })
        enrolmentType  = $(if ($rec -and $null -ne $rec.EnrollmentType) { [string]$rec.EnrollmentType } else { $null })
        intuneDeviceId = $intuneId
        serverHost     = $serverHost
    }
    $join = 'none'; $entraId = $null; $tenant = $null
    if ($Dsreg) { $join = $Dsreg.JoinType; $entraId = $Dsreg.DeviceId; $tenant = $Dsreg.TenantId }
    else { Add-DDNotCollected -Context $Context -Field 'management.joinType' -Reason 'error' -Detail 'dsregcmd /status unavailable or unparseable' }

    $wuPol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $useWu = Invoke-DDStep -Context $Context -Field 'management.updateSource' -Script { Get-DDRegistryValue -Path "$wuPol\AU" -Name 'UseWUServer' }
    $source = 'wufb'
    if ($null -ne $useWu -and [int]$useWu -eq 1) { $source = $(if ($IsConfigMgrClient) { 'configmgr' } else { 'wsus' }) }
    elseif ($null -eq $useWu -and $Context.NotCollected.Exists([Predicate[object]] { param($e) $e['field'] -eq 'management.updateSource' })) { $source = 'unknown' }

    $cm = $null
    if ($ConfigMgr) {
        $flags = $(if ($ConfigMgr.PSObject.Properties['CoManagementFlags']) { $ConfigMgr.CoManagementFlags } else { $null })
        $cm = [ordered]@{ client = [bool]$ConfigMgr.Client; siteCode = $ConfigMgr.SiteCode; boundaryGroups = @(); coManagementFlags = $flags }
    }
    Add-DDNotCollected -Context $Context -Field 'management.autopilot' -Reason 'error' -Detail 'Autopilot group tag: Windows keeps no documented copy on the device (it belongs to the Autopilot registration in Intune); left empty'
    if ($ConfigMgr -and $ConfigMgr.Client) { Add-DDNotCollected -Context $Context -Field 'management.configMgr.boundaryGroups' -Reason 'error' -Detail 'boundary groups are not read (no verified on-device source); reported empty' }
    [ordered]@{
        joinType     = $join
        entraDeviceId = $entraId
        tenantId     = $tenant
        mdm          = $mdm
        configMgr    = $cm
        autopilot    = $null
        updateSource = $source
    }
}

function Get-DDDoStoreDumps {
    # Every value in each Delivery Optimization registry store, unredacted (in memory only). A store that could not be read
    # is absent and named in notCollected.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context)

    $defs = [ordered]@{
        policy                 = @('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization', 'documented')
        # Layout observed on Windows 11 26H2 (an Intune-managed device): <Name>, <Name>_ProviderSet, <Name>_WinningProvider. Microsoft
        # documents the Policy CSP, not this registry store, so it is tagged to-verify (the contract has no "observed" value).
        mdm                    = @('HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization', 'to-verify')
        serviceConfig          = @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config', 'to-verify')
        userSettings           = @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings', 'to-verify')
        # The Settings app's choices live in the NetworkService profile DoSvc runs as (readable only elevated).
        networkServiceSettings = @('HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings', 'to-verify')
        serviceState           = @('HKLM\SYSTEM\CurrentControlSet\Services\DoSvc', 'documented')
    }
    $dumps = [ordered]@{}
    foreach ($id in $defs.Keys) {
        $key = $defs[$id][0]
        $dump = Invoke-DDStep -Context $Context -Field "doConfig.stores.$id" -Script { Get-DDRegistryValues -Path $key }
        if ($null -eq $dump) { continue }
        $dumps[$id] = @{ Key = $key; Present = [bool]$dump.Present; Values = @($dump.Values | Select-Object -First 256); Confidence = $defs[$id][1] }
    }
    $dumps
}

function Get-DDDoStores {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, $Dumps = $null)

    if ($null -eq $Dumps) { $Dumps = Get-DDDoStoreDumps -Context $Context }
    $stores = [ordered]@{}
    foreach ($id in $Dumps.Keys) {
        $d = $Dumps[$id]
        $values = @($d.Values)
        if ($Context.Anonymise) { $values = Protect-DDRegistryValues -Values $values -Salt $Context.TenantSalt }
        $stores[$id] = [ordered]@{ key = $d.Key; present = [bool]$d.Present; values = @($values); confidence = $d.Confidence }
    }
    $stores
}

function Get-DDDoConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [AllowEmptyCollection()] $Enrollments = @())

    $effective = [ordered]@{}
    $kinds = @{}
    $workingDirectory = $null
    $vpnKeywords = $null
    if (Test-DDDeliveryOptimizationModule) {
        $cfg = Invoke-DDStep -Context $Context -Field 'doConfig.effective' -Script { Get-DDDOConfigRaw }
        if ($cfg) {
            $parsed = ConvertFrom-DDDoConfig -Config $cfg.Config -VerboseLines $cfg.Verbose
            $effective = $parsed.Effective
            $kinds = $parsed.Kinds
            $workingDirectory = $parsed.WorkingDirectory
            $vpnKeywords = $parsed.VpnKeywords
            if ($effective.Count -eq 0) { Add-DDNotCollected -Context $Context -Field 'doConfig.effective' -Reason 'error' -Detail 'Get-DOConfig returned no property the collector recognises (this Windows build may name them differently)' }
        }
    } else {
        Add-DDNotCollected -Context $Context -Field 'doConfig.effective' -Reason 'cmdlet-missing' -Detail 'DeliveryOptimization module not available (Windows 10 1703+ / Windows 11)'
    }
    $dumps = Get-DDDoStoreDumps -Context $Context
    # MDMWinsOverGP: its meaning is documented (Policy CSP ControlPolicyConflict); the registry path it is read from is observed.
    $wins = Invoke-DDStep -Context $Context -Field 'doConfig.mdmWinsOverGp' -Script { Get-DDRegistryValue -Path 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict' -Name 'MDMWinsOverGP' }
    $mdmWins = $(if ($null -eq $wins) { $null } else { [int]$wins -eq 1 })
    $pick = { param($id) if ($dumps.Contains($id)) { $dumps[$id] } else { $null } }
    $effective = Resolve-DDSettingSources -Effective $effective -Kinds $kinds -MdmStore (& $pick 'mdm') -PolicyStore (& $pick 'policy') -LocalStore (& $pick 'networkServiceSettings') -Enrollments $Enrollments -MdmWinsOverGp $mdmWins
    if (@($effective.Values | Where-Object { $_['source']['kind'] -eq 'unknown' }).Count -gt 0) {
        Add-DDNotCollected -Context $Context -Field 'doConfig.effective.provider' -Reason 'error' -Detail 'some settings have no provider in Get-DOConfig and no single policy store; reported as unknown'
    }

    $out = [ordered]@{ effective = $effective; stores = $null }
    $out['stores'] = Get-DDDoStores -Context $Context -Dumps $dumps
    if ($workingDirectory) { $out['workingDirectory'] = (Protect-DDLogText -Text ([string]$workingDirectory)) }
    $out['mdmWinsOverGp'] = $mdmWins
    $out['cacheFolder'] = Get-DDCacheFolderFacts -Context $Context -WorkingDirectory $(if ($workingDirectory) { [string]$workingDirectory } else { $null })
    $out['_vpnKeywords'] = $vpnKeywords
    $out['_workingDirectory'] = $workingDirectory
    $out['_rawEffective'] = $effective
    if ($Context.Anonymise) {
        # The group ID is organisation topology, hashed with the tenant's salt so that devices in one group compare equal across the
        # tenant (as peers do), and differ between tenants. The Connected Cache server is infrastructure and stays in clear (ADR-0031).
        $hide = { param($k, $v) if ($k -match '(?i)^DOGroupId$' -and $v) { Protect-DDTopologyValue -Value ([string]$v) -Salt $Context.TenantSalt -Tag 'redacted' } else { $v } }
        $anon = [ordered]@{}
        foreach ($k in $effective.Keys) {
            $e = $effective[$k]
            $src = $e['source']
            $alt = @(foreach ($a in @($src['alt'])) { [ordered]@{ store = $a['store']; value = (& $hide $k $a['value']) } })
            $anon[$k] = [ordered]@{
                value    = (& $hide $k $e['value'])
                provider = $e['provider']
                source   = [ordered]@{ kind = $src['kind']; mdm = $src['mdm']; basis = $src['basis']; setIn = $src['setIn']; alt = $alt }
            }
        }
        $out['effective'] = $anon
    }
    $out
}

function ConvertFrom-DDFirewallRaw {
    # A rule's display name and program pass through the log-line scrub: a per-user rule names a profile path such as
    # C:\Users\<name>\AppData\Local\...\app.exe. With an anonymised -Context the machine name and addresses go too.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Rules, $Context = $null)

    $scrub = {
        param([string] $s)
        if ($null -eq $Context) { return (Protect-DDLogText -Text $s) }
        Protect-DDLogText -Text $s -Anonymise:([bool]$Context.Anonymise) -Salt ([string]$Context.Salt) -ComputerName ([string]$Context.ComputerName)
    }
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in @($Rules)) {
        if ($out.Count -ge 64) { break }
        $profiles = New-Object 'System.Collections.Generic.List[string]'
        $p = [string]$r.Profile
        if ($p -match '(?i)\bAny\b|\bAll\b') { $profiles.AddRange([string[]]@('Domain', 'Private', 'Public')) }
        else { foreach ($n in 'Domain', 'Private', 'Public') { if ($p -match $n) { $profiles.Add($n) } } }
        $dir = $(if ([string]$r.Direction -match '(?i)out') { 'Outbound' } else { 'Inbound' })
        $act = $(if ([string]$r.Action -match '(?i)block') { 'Block' } else { 'Allow' })
        $row = [ordered]@{
            displayName = (& $scrub ([string]$r.DisplayName))
            direction   = $dir
            action      = $act
            enabled     = ([string]$r.Enabled -match '(?i)^(true|1)$')
            protocol    = [string]$r.Protocol
            localPort   = [string]$r.LocalPort
            program     = $(if ($r.Program) { & $scrub ([string]$r.Program) } else { $null })
            service     = $(if ($r.Service) { [string]$r.Service } else { $null })
            profiles    = $profiles.ToArray()
        }
        # Collectors from October 2026: the remote port, whether the rule is in force, and the remote address condition as
        # a category and a count. The addresses themselves are dropped here.
        $rp = Get-DDProp $r 'RemotePort'
        if ($null -ne $rp) { $s = [string]$rp; $row['remotePort'] = $s.Substring(0, [math]::Min(64, $s.Length)) }
        $ps = [string](Get-DDProp $r 'PrimaryStatus')
        if ($ps) { $row['primaryStatus'] = $(if ($ps -in 'OK', 'Inactive', 'Error') { $ps } else { 'Unknown' }) }
        $es = @(@(Get-DDProp $r 'EnforcementStatus') | Where-Object { [string]$_ -match '^[A-Za-z]{1,40}$' -and [string]$_ -ne 'NotApplicable' } | ForEach-Object { [string]$_ } | Select-Object -First 6)
        if ($es.Count -gt 0) { $row['enforcementStatus'] = [string[]]$es }
        if ($null -ne $r.PSObject.Properties['RemoteAddress']) {
            $scope = Get-DDRemoteScope -Addresses ([string[]]@($r.RemoteAddress))
            $row['remoteScope'] = $scope.Scope
            $row['remoteAddresses'] = [int]$scope.Count
        }
        $out.Add($row)
    }
    , $out.ToArray()
}

function Get-DDFirewallFacts {
    # The firewall rules. When Windows refused part of the listing (Get-DDFirewallRulesRaw returns a ReadRefused object
    # for each), 'firewallRules' is recorded as not collected: the rules read are kept, but they may be incomplete, and the
    # checks then do not call a rule absent (Test-DDFirewallRulesComplete).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context)
    $raw = Invoke-DDStep -Context $Context -Field 'firewallRules' -Script { Get-DDFirewallRulesRaw }
    if ($null -eq $raw) { return , @() }
    $refused = @(@($raw) | Where-Object { $null -ne $_ -and $null -ne (Get-DDProp $_ 'ReadRefused') })
    if ($refused.Count -gt 0) {
        $first = $refused[0].Error
        $reason = $(if ($null -ne $first) { Get-DDNotCollectedReason -ErrorRecord $first } else { 'error' })
        $why = $(if ($null -ne $first) { ': ' + ([string]$first.Exception.Message).Trim() } else { '' })
        Add-DDNotCollected -Context $Context -Field 'firewallRules' -Reason $reason -Detail ("Windows refused part of the listing of {0}, so rules may be missing{1}" -f (@($refused | ForEach-Object { [string]$_.ReadRefused }) -join ', '), $why)
    }
    ConvertFrom-DDFirewallRaw -Rules @(@($raw) | Where-Object { $null -ne $_ -and $null -eq (Get-DDProp $_ 'ReadRefused') }) -Context $Context
}

function Get-DDCacheDriveName {
    # The drive Delivery Optimization caches on, as "D:": the drive of the working directory the service reports (Get-DOConfig
    # WorkingDirectory, documented), else the system drive. The disk-size peering check and the free-space reading follow it
    # (Learn: "If the Modify Cache Drive policy is configured, the disk size check applies to the new working directory"
    # https://learn.microsoft.com/windows/deployment/do/waas-delivery-optimization-reference#minimum-disk-size-allowed-to-use-peer-caching).
    [CmdletBinding()]
    param([string] $WorkingDirectory)
    $drive = $(if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' })
    if ($WorkingDirectory -match '^[A-Za-z]:') { $drive = $WorkingDirectory.Substring(0, 2).ToUpperInvariant() }
    $drive
}

function Get-DDStaticDeviceFacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, $Os, $Dsreg, [bool] $IsConfigMgrClient, [string] $WorkingDirectory)

    $cs = @(Invoke-DDStep -Context $Context -Field 'device.computerSystem' -Script { Get-DDCim -ClassName 'Win32_ComputerSystem' } -Default @())
    $enc = @(Invoke-DDStep -Context $Context -Field 'device.chassis' -Script { Get-DDCim -ClassName 'Win32_SystemEnclosure' } -Default @())
    $model = [string](Get-DDProp ($cs | Select-Object -First 1) 'Model')
    $manu = [string](Get-DDProp ($cs | Select-Object -First 1) 'Manufacturer')
    $isVirtual = ($model -match '(?i)virtual|vmware|kvm|bochs|qemu|hyper-v') -or ($manu -match '(?i)vmware|qemu|xen|microsoft corporation' -and $model -match '(?i)virtual')
    $types = @()
    if ($enc.Count -gt 0) { $types = @($enc[0].ChassisTypes | ForEach-Object { [int]$_ }) }
    $chassis = ConvertTo-DDChassis -ChassisTypes $types -IsVirtual $isVirtual

    $memBytes = $null
    if ($cs.Count -gt 0 -and (Get-DDProp $cs[0] 'TotalPhysicalMemory')) { $memBytes = [double](Get-DDProp $cs[0] 'TotalPhysicalMemory') }
    if (-not $memBytes) { $memBytes = Invoke-DDStep -Context $Context -Field 'device.ramGB' -Script { Get-DDSystemMemoryBytes } }
    $sysDrive = $(if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' })
    $disks = @(Invoke-DDStep -Context $Context -Field 'device.disks' -Script { Get-DDLocalDisks } -Default @())
    $sys = $disks | Where-Object { $_.DeviceId -eq $sysDrive } | Select-Object -First 1
    $sysSize = $null
    if ($sys) { $sysSize = [double]$sys.Size }
    else { $sysSize = Invoke-DDStep -Context $Context -Field 'device.systemDiskGB' -Script { (Get-DDDriveInfo -Name $sysDrive).TotalSize } }

    # Cache drive: the drive of the DO working directory as the service reports it (Get-DOConfig WorkingDirectory,
    # documented), else the system drive. The disk-size peering check follows it.
    $cacheDrive = Get-DDCacheDriveName -WorkingDirectory $WorkingDirectory
    $cacheDisk = $disks | Where-Object { $_.DeviceId -eq $cacheDrive } | Select-Object -First 1
    $cacheGB = $null
    if ($cacheDisk) { $cacheGB = [math]::Round($cacheDisk.Size / 1GB, 1) }

    $edition = $(if ($Os) { $Os.Os['edition'] } else { $null })
    $deviceId = $null
    $deviceId = Get-DDSaltedHash -Value ('{0}|{1}' -f (Get-DDHostName), (Get-DDMachineGuid)) -Salt $Context.Salt -Domain 'device'
    $d = [ordered]@{
        deviceId           = $deviceId
        hostname           = $(if ($Context.Anonymise) { $null } else { Get-DDHostName })
        osBuild            = $(if ($Os) { $Os.FullBuild } else { $null })
        osEdition          = $edition
        isSupportedEdition = $(if ($Os) { Get-DDEditionSupported -EditionId $Os.EditionId } else { $false })
        isVirtual          = [bool]$isVirtual
        ramGB              = $(if ($memBytes) { [math]::Round($memBytes / 1GB, 1) } else { $null })
        systemDiskGB       = $(if ($sysSize) { [math]::Round($sysSize / 1GB, 1) } else { $null })
        cacheDriveGB       = $cacheGB
        chassis            = $chassis
        isConfigMgrClient  = $IsConfigMgrClient
        domainJoined       = $(if ($Dsreg) { [bool]$Dsreg.DomainJoined } else { $false })
        entraJoined        = $(if ($Dsreg) { [bool]$Dsreg.AzureAdJoined } else { $false })
    }
    # Collectors from October 2026: the active power plan beside the battery state, and the Unified Update Stack version
    # (a file Microsoft's DeliveryOptimizationTroubleshooter reads; not a documented interface, so absent is not an error).
    $plan = Invoke-DDStep -Context $Context -Field 'device.powerPlan' -Script { Get-DDActivePowerPlan }
    $d['powerPlan'] = $(if ($plan) { $s = [string]$plan; $s.Substring(0, [math]::Min(128, $s.Length)) } else { $null })
    $uus = Invoke-DDStep -Context $Context -Field 'device.uusVersion' -Script { Get-DDUusVersionRaw }
    $d['uusVersion'] = $(if ($uus -and ([string]$uus).Trim() -match '^[0-9A-Za-z.\-]{1,64}$') { ([string]$uus).Trim() } else { $null })
    foreach ($req in 'osBuild', 'osEdition', 'ramGB', 'systemDiskGB') {
        if ($null -eq $d[$req]) { Add-DDNotCollected -Context $Context -Field "device.$req" -Reason 'error' -Detail 'required inventory field could not be collected from any source' }
    }
    $d
}

function Get-DDSystemMemoryBytes {
    [CmdletBinding()]
    param()
    Add-Type -Verbose:$false -AssemblyName Microsoft.VisualBasic
    [double](New-Object Microsoft.VisualBasic.Devices.ComputerInfo).TotalPhysicalMemory
}

function Get-DDDriveInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Name)
    New-Object System.IO.DriveInfo($Name)
}

function Get-DDDeviceVitals {
    <#
    .SYNOPSIS
        The volatile device facts that ride with every telemetry report (battery, free space, cache use).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [string] $WorkingDirectory)

    $sysDrive = $(if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' })
    $disks = @(Invoke-DDStep -Context $Context -Field 'vitals.systemDiskFreeGB' -Script { Get-DDLocalDisks } -Default @())
    $sys = $disks | Where-Object { $_.DeviceId -eq $sysDrive } | Select-Object -First 1
    # $null, never 0, when the system drive is not among the local disks: 0 reads as "full".
    $free = $(if ($sys) { [math]::Round($sys.FreeSpace / 1GB, 1) } else { $null })
    if ($null -eq $free -and @($disks).Count -gt 0) { Add-DDNotCollected -Context $Context -Field 'vitals.systemDiskFreeGB' -Reason 'error' -Detail "the system drive $sysDrive is not among the local disks" }
    # Free space on the cache drive (docs/27 3.6): $null, never 0, when that drive is not among the local disks, because 0 reads as "full".
    $cacheDisk = $disks | Where-Object { $_.DeviceId -eq (Get-DDCacheDriveName -WorkingDirectory $WorkingDirectory) } | Select-Object -First 1
    $cacheFree = $(if ($cacheDisk) { [math]::Round($cacheDisk.FreeSpace / 1GB, 1) } else { $null })
    $bat = @(Invoke-DDStep -Context $Context -Field 'vitals.battery' -Script { Get-DDBatteryRaw } -Default @())
    $onBattery = $false; $pct = $null; $low = $null
    if ($bat.Count -gt 0) {
        $b = $bat[0]
        # Win32_Battery BatteryStatus: 1 Other ("The battery is discharging"), 2 Unknown ("The system has access to AC"), 3 Fully
        # Charged, 4 Low, 5 Critical, 6 to 9 Charging (and High, Low, Critical), 10 Undefined, 11 Partially Charged. Low and
        # Critical are read as on battery and low (Learn does not say whether AC is connected then; DoctorDO's reading): that is
        # when DO stops uploading, so they must not read as AC.
        $status = [int](Get-DDProp $b 'BatteryStatus')
        $onBattery = ($status -in 1, 4, 5)
        $low = ($status -in 4, 5)
        $est = Get-DDProp $b 'EstimatedChargeRemaining'
        if ($null -ne $est) { $pct = [math]::Min(100, [math]::Max(0, [double]$est)) }
    }
    $cacheUsed = $null
    $cachePath = $WorkingDirectory
    if (-not $cachePath -and $env:SystemRoot) { $cachePath = Join-Path $env:SystemRoot 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache' }
    if ($cachePath) {
        $sz = Invoke-DDStep -Context $Context -Field 'vitals.cacheUsedBytes' -Script { Get-DDDirectorySize -Path $cachePath }
        if ($null -ne $sz) { $cacheUsed = ([long]$sz).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    }
    # batteryLow: $null without a battery reading (no battery, or the read failed: then vitals.battery is in notCollected).
    [ordered]@{ onBattery = $onBattery; batteryPercent = $pct; batteryLow = $low; systemDiskFreeGB = $free; cacheDriveFreeGB = $cacheFree; cacheUsedBytes = $cacheUsed }
}
