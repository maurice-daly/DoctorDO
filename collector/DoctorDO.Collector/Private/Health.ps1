#Requires -Version 5.1
# Delivery Optimization health: the checks Microsoft's DeliveryOptimizationTroubleshooter 1.3.1 runs, reimplemented here
# from the documented Windows APIs and the behaviour Microsoft Learn describes (docs/07, docs/08). The troubleshooter
# publishes no licence, so none of its code is used; where DoctorDO follows its behaviour (the adapter DO uses, the
# verification object's size) the code says so and the docs label it as such.
#
# Pure functions first, each tested on its own (tests/Health.Tests.ps1); the orchestrators at the end call the wrappers in
# Platform.ps1 and ProbeNative.ps1 inside Invoke-DDStep, so a source that cannot be read becomes notCollected, never a
# crash and never a silent gap.

Set-StrictMode -Version Latest

$script:DDGeoUri = 'https://geo.prod.do.dsp.mp.microsoft.com/geo'
$script:DDGeoCacheVersion = 1
# The size of Microsoft's Connected Cache verification object as Microsoft's DeliveryOptimizationTroubleshooter 1.3.1
# checks it. Microsoft Learn ("Verify Connected Cache node functionality") documents the request and "StatusCode 200",
# not the size (checked 14 Oct 2026), so a different size is a warning, never a failure.
$script:DDMccVerifyLength = 302341
# IANA ifType values of physical media DO prefers: Ethernet variants (6 ethernetCsmacd, 62 fastEther, 69 fastEtherFX,
# 117 gigabitEthernet, 55 IEEE 802.12, 161 IEEE 802.3ad link aggregation) and 71 IEEE 802.11 (Wi-Fi).
$script:DDEthernetIfTypes = 6, 62, 69, 117, 55, 161
$script:DDWifiIfType = 71
$script:DDNetworkServiceSid = 'S-1-5-20'
$script:DDFirewallTcp = '^(?i)(TCP|6|Any|)$'
$script:DDFirewallUdp = '^(?i)(UDP|17|Any|)$'
# Microsoft FAQ, "Why is the Delivery Optimization service not listening on port 7680?"
$script:DDListenerReasons = 'DoSvc stops listening when idle (no downloads or uploads in progress); also when no files are in its cache, in Simple mode (99), on low battery, in Connected Standby, on a cellular network, or when the VPN setting does not allow peering (Microsoft FAQ)'

# ---- ports and firewall scope ----------------------------------------------------------------------------------------

function Test-DDPortSpec {
    # Whether a firewall port condition ("7680", "7000-8000, 443") names -Port explicitly. "Any" and keywords (RPC, ...)
    # do not: they are judged by the caller.
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string] $Spec, [Parameter(Mandatory)][int] $Port)
    if (-not $Spec) { return $false }
    foreach ($p in $Spec.Split(',')) {
        $t = $p.Trim()
        if ($t -match '^\d{1,5}$') { if ([int]$t -eq $Port) { return $true } }
        elseif ($t -match '^(\d{1,5})\s*-\s*(\d{1,5})$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true } }
    }
    $false
}

function Get-DDRemoteScope {
    <#
    .SYNOPSIS
        A rule's remote address condition as a category and a count, never the addresses: any | local-subnet | ranges |
        keywords | mixed. "Any" anywhere wins; LocalSubnet, LocalSubnet4 and LocalSubnet6 are the local subnet; other
        single-word values (Intranet, DefaultGateway, DNS ...) are keywords; everything else is a specific address, range
        or subnet.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][string[]] $Addresses)
    $a = @($Addresses | Where-Object { $_ })
    if ($a.Count -eq 0) { return [pscustomobject]@{ Scope = 'any'; Count = 0 } }
    $local = $false; $kw = $false; $n = 0
    foreach ($x in $a) {
        $t = $x.Trim()
        if ($t -ieq 'Any' -or $t -eq '*') { return [pscustomobject]@{ Scope = 'any'; Count = 0 } }
        if ($t -match '^(?i)LocalSubnet[46]?$') { $local = $true }
        elseif ($t -match '^(?i)[a-z][a-z0-9]*$') { $kw = $true }
        else { $n++ }
    }
    $kinds = @($local, $kw, ($n -gt 0)) | Where-Object { $_ }
    $scope = $(if (@($kinds).Count -gt 1) { 'mixed' } elseif ($local) { 'local-subnet' } elseif ($kw) { 'keywords' } else { 'ranges' })
    [pscustomobject]@{ Scope = $scope; Count = $n }
}

function Test-DDTcp7680Allow {
    # An inbound Allow rule for Delivery Optimization's TCP port: named for DO, bound to the dosvc service, or a TCP (or
    # any-protocol) rule whose local port names 7680. A UDP-only rule does not admit TCP 7680.
    # Delivery Optimization is the dosvc service in svchost.exe, so a rule limited to another program or another service
    # does not admit it, whatever its port: such a rule counts only with -AnyProgram (to name it in a finding).
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $Rule, [switch] $AnyProgram)
    if ($Rule['direction'] -ne 'Inbound' -or $Rule['action'] -ne 'Allow') { return $false }
    if ([string]$Rule['protocol'] -notmatch $script:DDFirewallTcp) { return $false }
    if (-not $AnyProgram -and -not (Test-DDAdmitsDoSvc -Rule $Rule)) { return $false }
    ([string]$Rule['displayName'] -match '(?i)Delivery Optimization') -or ([string]$Rule['service'] -match '(?i)^dosvc$') -or (Test-DDPortSpec -Spec ([string]$Rule['localPort']) -Port 7680)
}

function Test-DDAdmitsDoSvc {
    # Whether a rule's program and service conditions let the dosvc service (svchost.exe) through: each is unset, Any, or
    # names it. A service condition of * means "any service", which includes dosvc.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $Rule)
    $program = [string](Get-DDProp $Rule 'program')
    $service = [string](Get-DDProp $Rule 'service')
    if ($program -and $program -notmatch '^(?i)any$' -and $program -notmatch '(?i)(^|\\)svchost\.exe$') { return $false }
    -not ($service -and $service -notmatch '^(?i)(any|\*|dosvc)$')
}

function Get-DDScopeText {
    # What a rule is limited to, in words, for a rule Test-DDAdmitsDoSvc refuses.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Rule)
    $program = [string](Get-DDProp $Rule 'program')
    if ($program -and $program -notmatch '^(?i)any$' -and $program -notmatch '(?i)(^|\\)svchost\.exe$') { return "the program $([System.IO.Path]::GetFileName($program))" }
    "the service $([string](Get-DDProp $Rule 'service'))"
}

function Test-DDFirewallRulesComplete {
    # Whether the firewall rules were read in full: Get-DDFirewallFacts records 'firewallRules' as not collected when
    # Windows refused part of the listing (or all of it). Without the full list a rule that is not in it is unknown.
    [CmdletBinding()]
    [OutputType([bool])]
    param($Context)
    if ($null -eq $Context) { return $true }
    -not (@($Context.NotCollected | Where-Object { $_['field'] -eq 'firewallRules' }).Count -gt 0)
}

function Get-DDEnforcementText {
    # Why Windows says a rule is not in force (Get-NetFirewallRule EnforcementStatus), in words.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Rule)
    $words = @(foreach ($s in @(Get-DDProp $Rule 'enforcementStatus')) {
            switch ([string]$s) {
                'LocalFirewallRulesNotAllowed' { 'the firewall policy ignores local rules (local rule merging is off) and this is one'; break }
                'ProfileInactive' { 'its profile is not the active one'; break }
                'OptimizedOut' { 'Windows optimised it out'; break }
                'LocalPortProtocolConflict' { 'its port condition conflicts with another rule'; break }
                default { [string]$s }
            }
        })
    $(if ($words.Count -gt 0) { ': ' + ($words -join '; ') } else { '' })
}

function Get-DDOutboundBlocks {
    # Enabled outbound Block rules that name -Port (local or remote) for -Protocol (TCP or UDP).
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Rules = @(), [Parameter(Mandatory)][int] $Port, [ValidateSet('TCP', 'UDP')][string] $Protocol)
    $proto = $(if ($Protocol -eq 'TCP') { $script:DDFirewallTcp } else { $script:DDFirewallUdp })
    @(@($Rules) | Where-Object {
            $_['direction'] -eq 'Outbound' -and $_['action'] -eq 'Block' -and $_['enabled'] -and [string]$_['protocol'] -match $proto -and
            ((Test-DDPortSpec -Spec ([string]$_['localPort']) -Port $Port) -or (Test-DDPortSpec -Spec ([string](Get-DDProp $_ 'remotePort')) -Port $Port))
        })
}

function Get-DDDhcpBlockHints {
    <#
    .SYNOPSIS
        Why the DHCP client might not have received an option, from the firewall rules collected: enabled Block rules that
        name UDP 68 (the client's port, where answers arrive) or UDP 67 (the server's), and LocalPolicyMerge, which
        Microsoft says "can impact DHCP client and prevent it from retrieving this DHCP option".
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyCollection()] $Rules = @(), $LocalPolicyMerge)
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($port in 68, 67) {
        $hits = @(@($Rules) | Where-Object {
                $_['action'] -eq 'Block' -and $_['enabled'] -and [string]$_['protocol'] -match $script:DDFirewallUdp -and
                ((Test-DDPortSpec -Spec ([string]$_['localPort']) -Port $port) -or (Test-DDPortSpec -Spec ([string](Get-DDProp $_ 'remotePort')) -Port $port))
            })
        foreach ($h in ($hits | Select-Object -First 2)) { $out.Add(("an enabled {0} Block rule '{1}' names UDP {2}" -f $h['direction'].ToLowerInvariant(), $h['displayName'], $port)) }
    }
    if ($LocalPolicyMerge -eq $false) { $out.Add('local firewall rule merging is turned off (LocalPolicyMerge), which Microsoft says can stop the DHCP client retrieving option 235') }
    $out.ToArray()
}

function Test-DDDoSvcListening {
    # Whether DoSvc's own TCP table (Get-NetTCPConnection -OwningProcess <DoSvc PID>, which the collector already reads) holds
    # a Listen socket on TCP 7680. A stopped DoSvc has no table, so it is not listening. The caller passes only a table that
    # was read; an unread one stays $null upstream ("not collected").
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyCollection()] $Connections = @(), $DoSvc)
    if ($null -ne $DoSvc -and [string](Get-DDProp $DoSvc 'Status') -and [string](Get-DDProp $DoSvc 'Status') -ne 'Running') { return $false }
    [bool](@($Connections) | Where-Object { [string](Get-DDProp $_ 'State') -match '(?i)^Listen$' -and [int](Get-DDProp $_ 'LocalPort') -eq 7680 } | Select-Object -First 1)
}

function Test-DDDoSvcPeerConnection {
    # Whether DoSvc's own TCP table holds an established peer connection: TCP 7680 at either end (a peer connected in, or
    # DoSvc connected out to a peer). The caller passes only a table that was read.
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyCollection()] $Connections = @())
    [bool](@($Connections) | Where-Object { [string](Get-DDProp $_ 'State') -match '(?i)^Established$' -and ([int](Get-DDProp $_ 'LocalPort') -eq 7680 -or [int](Get-DDProp $_ 'RemotePort') -eq 7680) } | Select-Object -First 1)
}

# ---- the adapter DO uses -----------------------------------------------------------------------------------------------

function Select-DDDoAdapter {
    <#
    .SYNOPSIS
        The adapter Delivery Optimization uses, chosen as Microsoft's DeliveryOptimizationTroubleshooter states DO chooses it
        (it says its selection is "based on DO client's native code"): the first adapter, in Windows' enumeration order, that
        is up and has an IPv4 address that is neither loopback nor link-local and is physical (a connector is present and
        its type is an Ethernet variant or Wi-Fi); else the first such virtual adapter. $null when none qualifies.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Candidates = @(), $DefaultInterfaceIndex = $null)
    $first = $null; $virtual = $null
    foreach ($c in @($Candidates | Sort-Object -Property Order)) {
        if (-not $c.Up) { continue }
        $ip = @($c.IPv4) | Where-Object { [string]$_.Address -notmatch '^(127\.|169\.254\.|0\.)' } | Select-Object -First 1
        if ($null -eq $ip) { continue }
        $type = $(if ([int]$c.IfType -eq $script:DDWifiIfType) { 'Wi-Fi' } elseif ([int]$c.IfType -in $script:DDEthernetIfTypes) { 'Ethernet' } else { 'Other' })
        $physical = ($c.ConnectorPresent -eq $true) -and $type -ne 'Other'
        $pick = [pscustomobject]@{
            Id = [string]$c.Id; Name = [string]$c.Name; Kind = $(if ($physical) { 'physical' } else { 'virtual' }); Type = $type; IfType = [int]$c.IfType
            IfIndex = $c.IfIndex; IPv4 = [string]$ip.Address; PrefixLength = [int]$ip.PrefixLength
            DefaultRoute = $(if ($null -eq $DefaultInterfaceIndex -or $null -eq $c.IfIndex) { $null } else { [int]$c.IfIndex -eq [int]$DefaultInterfaceIndex })
        }
        if ($physical) { $first = $pick; break }
        if ($null -eq $virtual) { $virtual = $pick }
    }
    if ($first) { return $first }
    $virtual
}

# ---- DHCP options --------------------------------------------------------------------------------------------------------

function ConvertFrom-DDDhcpText {
    # A text DHCP option (234, 235) as the DHCP server sent it: ASCII, trailing NULs and white space removed, printable
    # characters only (anything else is unreadable, $null), at most 1024 characters.
    [CmdletBinding()]
    param([AllowNull()][byte[]] $Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $null }
    $s = [System.Text.Encoding]::ASCII.GetString($Bytes).TrimEnd([char]0, [char]32, [char]9, [char]13, [char]10)
    if ($s.Length -eq 0 -or $s -notmatch '^[\x20-\x7E]+$') { return $null }
    $s.Substring(0, [math]::Min(1024, $s.Length))
}

function Get-DDDhcpWants {
    # The options DO itself reads on this device: 234 when DOGroupIdSource = 3 ("DHCP Option ID"), 235 when
    # DOCacheHostSource is 1 or 2 or the DO service sets its cache-host flag.
    [CmdletBinding()]
    [OutputType([string[]])]
    param($Effective, $Geo)
    $num = { param($n) $v = Get-DDEffectiveValue -Effective $Effective -Name $n; $x = 0; if ($null -ne $v -and [int]::TryParse([string]$v, [ref]$x)) { $x } else { $null } }
    $w = New-Object 'System.Collections.Generic.List[string]'
    if ((& $num 'DOGroupIdSource') -eq 3) { $w.Add('234') }
    if ((& $num 'DOCacheHostSource') -in 1, 2 -or ($null -ne $Geo -and $Geo.CacheHostFlag -eq $true)) { $w.Add('235') }
    $w.ToArray()
}

function ConvertFrom-DDDhcpOutcome {
    <#
    .SYNOPSIS
        The DHCP facts (packages/schema DhcpFacts) and the option values from one DhcpRequestParams outcome.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]] $Wants = @(), $Outcome, [switch] $NoAdapter, [switch] $Unavailable)
    $facts = [ordered]@{ wants = @($Wants); state = 'not-queried'; subnetMask = $null; option234 = 'not-queried'; option235 = 'not-queried'; win32Error = $null }
    $values = @{ '234' = $null; '235' = $null }
    if (@($Wants).Count -eq 0) { return [pscustomobject]@{ Facts = $facts; Values = $values } }
    if ($NoAdapter) { $facts['state'] = 'no-adapter' }
    elseif ($Unavailable -or $null -eq $Outcome) { $facts['state'] = 'unavailable' }
    elseif ($Outcome.TimedOut) { $facts['state'] = 'timeout' }
    elseif (-not $Outcome.Attempted -or [int]$Outcome.Win32Error -ne 0) { $facts['state'] = 'api-failed'; $facts['win32Error'] = [int]$Outcome.Win32Error }
    else {
        $facts['state'] = 'answered'
        $byId = @{}
        foreach ($o in @($Outcome.Options)) { if ($null -ne $o) { $byId[[int]$o.OptionId] = $o } }
        $facts['subnetMask'] = ($byId.ContainsKey(1) -and $byId[1].Present -and @($byId[1].Data).Count -eq 4)
        foreach ($id in $Wants) {
            $o = $(if ($byId.ContainsKey([int]$id)) { $byId[[int]$id] } else { $null })
            $text = $(if ($o -and $o.Present) { ConvertFrom-DDDhcpText -Bytes ([byte[]]@($o.Data)) } else { $null })
            $facts["option$id"] = $(if ($text) { 'received' } else { 'absent' })
            $values[$id] = $text
        }
    }
    [pscustomobject]@{ Facts = $facts; Values = $values }
}

# ---- the DO geo service --------------------------------------------------------------------------------------------------

function ConvertFrom-DDGeoOutcome {
    <#
    .SYNOPSIS
        What the DO geo service answered (one GET of https://geo.prod.do.dsp.mp.microsoft.com/geo, the endpoint DO itself
        calls): a check result, a reason code, and the parts DoctorDO uses.
    .DESCRIPTION
        Expected: HTTP 200, Content-Type text/json, a body with Version and KeyValue_EndpointFullUri. An HTML answer, or a
        redirect, is what a captive portal or a proxy sign-in page gives (DoctorDO inference, as Microsoft's troubleshooter
        reports "Possible captive portal"). The body is read only under normal certificate validation, and a certificate not
        issued by Microsoft fails: the endpoint is certificate-pinned (Microsoft: "Using a proxy with Delivery Optimization"),
        so DO itself would refuse it. CacheHost and CacheHostFlag are kept; ExternalIpAddress is read only with
        -ReadExternalIp (egress collection on) and returned for hashing, never stored; nothing else in the body is read.
    #>
    [CmdletBinding()]
    param($Outcome, [switch] $ReadExternalIp)
    $g = [ordered]@{ Result = 'not-collected'; Code = 'not-run'; Detail = 'The DO geo service was not asked'; Evidence = $null; HttpStatus = $null; ContentType = $null; CacheHost = $null; CacheHostFlag = $null; ExternalIp = $null; Ms = $null; Cached = $false }
    if ($null -eq $Outcome) { return [pscustomobject]$g }
    $g.Ms = $(if ($null -ne $Outcome.Ms) { [double]$Outcome.Ms } else { $null })
    $g.HttpStatus = $(if ([int]$Outcome.Status -ge 100) { [int]$Outcome.Status } else { $null })
    $g.ContentType = $(if ($Outcome.ContentType) { ([string]$Outcome.ContentType).Split(';')[0].Trim().ToLowerInvariant() } else { $null })
    $g.Evidence = ('status={0}; content-type={1}; tls={2}{3}' -f $(if ($g.HttpStatus) { $g.HttpStatus } else { 'none' }), $(if ($g.ContentType) { $g.ContentType } else { '(none)' }),
        $(if (-not $Outcome.CertSeen) { 'none' } elseif ($Outcome.ChainOk -and $Outcome.NameOk) { 'valid' } else { 'invalid' }), $(if ($Outcome.ProxyUsed) { '; via proxy' }))
    $set = { param($r, $c, $d) $g.Result = $r; $g.Code = $c; $g.Detail = $d; [pscustomobject]$g }
    if (-not $Outcome.Attempted -or $null -eq $g.HttpStatus) {
        $why = $(if ($Outcome.TimedOut) { 'timed out' } elseif ($Outcome.Error) { [string]$Outcome.Error } else { 'no answer' })
        return (& $set 'fail' 'unreachable' "The DO geo service did not answer ($why): the device cannot reach the Delivery Optimization cloud service (DO-NET-001)")
    }
    if ($Outcome.CertSeen -and -not ($Outcome.ChainOk -and $Outcome.NameOk)) {
        return (& $set 'fail' 'tls-untrusted' 'The certificate presented for the DO geo service does not validate on this device: a captive portal, or an inspecting proxy whose root it does not trust')
    }
    if ($Outcome.CertSeen -and -not $Outcome.ChainMicrosoft) {
        return (& $set 'fail' 'tls-inspected' 'The DO geo service answered with a certificate not issued by Microsoft: TLS inspection on a certificate-pinned endpoint, so DO itself refuses the answer (DO-NET-006)')
    }
    if ($Outcome.Redirected -or ($g.HttpStatus -ge 300 -and $g.HttpStatus -lt 400)) {
        return (& $set 'warn' 'captive-portal' "The DO geo service request was redirected (HTTP $($g.HttpStatus)): a captive portal or a proxy sign-in page is likely in the path")
    }
    if ($g.HttpStatus -ne 200) { return (& $set 'fail' 'http-status' "The DO geo service answered HTTP $($g.HttpStatus), not 200 (DO-NET-001)") }
    if ($g.ContentType -eq 'text/html') {
        return (& $set 'warn' 'captive-portal' 'The DO geo service request was answered with a web page (text/html), not its JSON: a captive portal or a proxy block page is likely in the path')
    }
    if ($g.ContentType -notin 'text/json', 'application/json') { return (& $set 'fail' 'unexpected-type' "The DO geo service answered with Content-Type '$($g.ContentType)', not text/json") }
    $json = $null
    try { if ($null -ne $Outcome.Body -and @($Outcome.Body).Count -gt 0) { $json = ConvertFrom-DDJson -Text ([System.Text.Encoding]::UTF8.GetString([byte[]]@($Outcome.Body))) } } catch { $json = $null }
    if ($json -isnot [System.Collections.IDictionary]) { return (& $set 'fail' 'invalid-response' 'The DO geo service answer is not a JSON object') }
    $version = [string]$json['Version']
    $kv = [string]$json['KeyValue_EndpointFullUri']
    $kvOk = $false
    $u = $null
    if ($kv -and [System.Uri]::TryCreate($kv, [System.UriKind]::Absolute, [ref]$u)) { $kvOk = $u.Scheme -eq 'https' }
    if (-not $version -or -not $kvOk) { return (& $set 'fail' 'invalid-response' 'The DO geo service answer has no Version or no valid KeyValue_EndpointFullUri') }
    if ($json.Contains('CacheHost') -and $json['CacheHost']) { $g.CacheHost = ConvertTo-DDCacheHostName ([string]$json['CacheHost']) }
    if ($json.Contains('CacheHostFlag')) { $f = [string]$json['CacheHostFlag']; $g.CacheHostFlag = ($f -eq '1' -or $f -ieq 'true') }
    if ($ReadExternalIp -and $json.Contains('ExternalIpAddress')) {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse([string]$json['ExternalIpAddress'], [ref]$ip) -and $ip.ToString() -ne '0.0.0.0') { $g.ExternalIp = $ip.ToString() }
    }
    $json = $null
    & $set 'pass' 'ok' ("The DO geo service answered with its configuration (HTTP 200, text/json, Version and key-value endpoint present){0}" -f $(if ($g.CacheHost) { "; it assigns the cache server $($g.CacheHost)" } else { '' }))
}

function Read-DDGeoCache {
    # A previous geo result, while younger than -MaxAgeMinutes and taken on the same network (signature). Never holds the
    # public address.
    [CmdletBinding()]
    param([string] $Path, [Parameter(Mandatory)][string] $Signature, [Parameter(Mandatory)][datetime] $Now, [int] $MaxAgeMinutes)
    if (-not $Path -or $MaxAgeMinutes -le 0 -or -not (Test-Path -LiteralPath $Path)) { return $null }
    # Only from a folder the collector can trust (Test-DDTrustedDirectory): anyone able to plant the file could choose what is reported.
    if (Test-DDTrustedDirectory -Raw (Get-DDDirectorySecurityRaw -Path (Split-Path -Path $Path -Parent))) { return $null }
    try {
        $c = Read-DDJsonFile -Path $Path
        if ($c -isnot [System.Collections.IDictionary] -or $c['version'] -ne $script:DDGeoCacheVersion -or $c['signature'] -ne $Signature) { return $null }
        $at = [datetime]::MinValue
        if (-not [datetime]::TryParse([string]$c['at'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at)) { return $null }
        if (($Now - $at).TotalMinutes -gt $MaxAgeMinutes -or $at -gt $Now.AddMinutes(5)) { return $null }
        $g = $c['geo']
        [pscustomobject]@{ Result = [string]$g['Result']; Code = [string]$g['Code']; Detail = [string]$g['Detail']; Evidence = $g['Evidence']; HttpStatus = $g['HttpStatus']; ContentType = $g['ContentType']
            CacheHost = $g['CacheHost']; CacheHostFlag = $g['CacheHostFlag']; ExternalIp = $null; Ms = $g['Ms']; Cached = $true }
    } catch { $null }
}

function Save-DDGeoCache {
    [CmdletBinding()]
    param([string] $Path, [Parameter(Mandatory)][string] $Signature, [Parameter(Mandatory)][string] $At, [Parameter(Mandatory)] $Geo)
    if (-not $Path) { return }
    try {
        $unsafe = Initialize-DDStateDirectory -Path (Split-Path -Path $Path -Parent)
        if ($unsafe) { Write-Verbose "geo cache not saved: the folder is not safe to use ($unsafe)"; return }
        $keep = [ordered]@{ Result = $Geo.Result; Code = $Geo.Code; Detail = $Geo.Detail; Evidence = $Geo.Evidence; HttpStatus = $Geo.HttpStatus; ContentType = $Geo.ContentType; CacheHost = $Geo.CacheHost; CacheHostFlag = $Geo.CacheHostFlag; Ms = $Geo.Ms }
        $json = ConvertTo-DDCanonicalJson -InputObject ([ordered]@{ version = $script:DDGeoCacheVersion; at = $At; signature = $Signature; geo = $keep })
        $tmp = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N').Substring(0, 8))
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) } else { [System.IO.File]::Move($tmp, $Path) }
    } catch { Write-Verbose "geo cache not saved: $($_.Exception.Message)" }
}

# ---- the cache server DO will use ---------------------------------------------------------------------------------------

function Split-DDCacheHosts {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return , @() }
    , @(([string]$Value).Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { ConvertTo-DDCacheHostName $_ } | Where-Object { $_ } | Select-Object -First 4)
}

function Resolve-DDCacheHost {
    <#
    .SYNOPSIS
        The Connected Cache server DO will use, where it comes from and why, in Delivery Optimization's precedence.
    .DESCRIPTION
        Microsoft documents it ("Delivery Optimization reference", Cache host source precedence): with DOCacheHostSource = 1
        "DOCacheHost takes precedence. DHCP Option 235 isn't used"; with 2 (Force) "DHCP Option 235 overrides DOCacheHost";
        with DOCacheHostSource alone, clients query option 235 and fall back when DHCP gives nothing; a malformed option
        falls back to DOCacheHost. Without either policy, the DO service may assign a cache server in its geo answer
        (CacheHost), or set CacheHostFlag, which tells the client to read option 235 (the flag's meaning is how Microsoft's
        DeliveryOptimizationTroubleshooter reads it). DODisallowCacheServerDownloadsOnVPN (Windows 11 22H2 and later) turns
        cache servers off while a VPN is connected.
        Codes: policy | dhcp | dhcp-forced | service-dhcp | service | none | dhcp-expected-not-received |
        service-dhcp-not-received | dhcp-unreadable | vpn-disallowed | service-not-read.
    #>
    [CmdletBinding()]
    param($Effective, [AllowNull()][string] $Dhcp235, [string] $DhcpState = 'not-queried', $Geo, [bool] $VpnActive, [AllowNull()][string] $OsBuild)
    $policy = Split-DDCacheHosts (Get-DDEffectiveValue -Effective $Effective -Name 'DOCacheHost')
    $srcRaw = Get-DDEffectiveValue -Effective $Effective -Name 'DOCacheHostSource'
    $src = $null; $x = 0; if ($null -ne $srcRaw -and [int]::TryParse([string]$srcRaw, [ref]$x) -and $x -in 1, 2) { $src = $x }
    $dhcp = Split-DDCacheHosts $Dhcp235
    $geoRead = $null -ne $Geo -and $Geo.Result -eq 'pass'
    $geoHosts = @(if ($geoRead -and $Geo.CacheHost) { [string]$Geo.CacheHost })
    $flag = $(if ($geoRead) { $Geo.CacheHostFlag -eq $true } else { $null })
    $dhcpKnown = $DhcpState -eq 'answered'
    $build = 0; if ($OsBuild -match '^\d+\.\d+\.(\d+)') { $build = [int]$Matches[1] }
    $disallow = (Get-DDEffectiveValue -Effective $Effective -Name 'DODisallowCacheServerDownloadsOnVPN') -in 1, '1', $true
    $out = { param($hosts, $source, $code, $detail) [pscustomobject]@{ Hosts = @($hosts); Source = $source; Code = $code; Detail = $detail; HostSource = $src; ServiceFlag = $flag; VpnBlocked = $false } }
    $list = { param($h) (@($h) -join ', ') }
    $missing = $(if ($dhcpKnown) { 'DHCP option 235 was expected but not received' } else { "DHCP option 235 could not be read ($DhcpState)" })
    $missCode = $(if ($dhcpKnown) { 'dhcp-expected-not-received' } else { 'dhcp-unreadable' })

    $r = $null
    if ($src -eq 2) {
        if ($dhcp.Count -gt 0) { $r = & $out $dhcp 'dhcp' 'dhcp-forced' "DHCP option 235 gives $(& $list $dhcp); DOCacheHostSource = 2 (Force) makes it override DOCacheHost" }
        elseif ($policy.Count -gt 0) { $r = & $out $policy 'policy' $missCode "$missing; DOCacheHost ($(& $list $policy)) is used instead" }
        elseif ($geoHosts.Count -gt 0) { $r = & $out $geoHosts 'service' $missCode "$missing; the cache server the DO service assigns ($(& $list $geoHosts)) is used instead" }
        else { $r = & $out @() 'none' $missCode "$missing, and nothing else names a cache server: content comes from the CDN" }
    } elseif ($src -eq 1) {
        if ($policy.Count -gt 0) { $r = & $out $policy 'policy' 'policy' "DOCacheHost names $(& $list $policy); with DOCacheHostSource = 1 it takes precedence and DHCP option 235 is not used" }
        elseif ($dhcp.Count -gt 0) { $r = & $out $dhcp 'dhcp' 'dhcp' "DHCP option 235 gives $(& $list $dhcp) (DOCacheHostSource = 1)" }
        elseif ($geoHosts.Count -gt 0) { $r = & $out $geoHosts 'service' $missCode "$missing; the cache server the DO service assigns ($(& $list $geoHosts)) is used instead" }
        else { $r = & $out @() 'none' $missCode "$missing, and nothing else names a cache server: content comes from the CDN" }
    } elseif ($policy.Count -gt 0) {
        $r = & $out $policy 'policy' 'policy' "DOCacheHost names $(& $list $policy)"
    } elseif ($flag -eq $true) {
        if ($dhcp.Count -gt 0) { $r = & $out $dhcp 'dhcp' 'service-dhcp' "The DO service tells this device to use DHCP option 235, which gives $(& $list $dhcp)" }
        elseif ($geoHosts.Count -gt 0) { $r = & $out $geoHosts 'service' "$(if ($dhcpKnown) { 'service-dhcp-not-received' } else { 'dhcp-unreadable' })" "The DO service tells this device to use DHCP option 235, but $(if ($dhcpKnown) { 'none was received' } else { "it could not be read ($DhcpState)" }); the cache server it assigns ($(& $list $geoHosts)) is used instead" }
        else { $r = & $out @() 'none' "$(if ($dhcpKnown) { 'service-dhcp-not-received' } else { 'dhcp-unreadable' })" "The DO service tells this device to use DHCP option 235, but $(if ($dhcpKnown) { 'none was received' } else { "it could not be read ($DhcpState)" }): content comes from the CDN" }
    } elseif ($geoHosts.Count -gt 0) {
        $r = & $out $geoHosts 'service' 'service' "The DO service assigns the cache server $(& $list $geoHosts) (often an internet provider's Connected Cache)"
    } elseif (-not $geoRead) {
        $r = & $out @() 'none' 'service-not-read' 'No policy names a cache server, and the DO service''s own assignment was not read (its geo answer was not collected)'
    } else {
        $r = & $out @() 'none' 'none' 'No policy names a cache server, DHCP is not asked for one, and the DO service assigns none'
    }
    if ($disallow -and $VpnActive -and $build -ge 22621 -and $r.Hosts.Count -gt 0) {
        $r.VpnBlocked = $true
        $r.Code = 'vpn-disallowed'
        $r.Detail = "$($r.Detail). DODisallowCacheServerDownloadsOnVPN is set and a VPN is connected, so no cache server is used now"
    }
    $r
}

# ---- the cache folder -----------------------------------------------------------------------------------------------------

function Get-DDServiceSid {
    # The SID of a service account (NT SERVICE\<name>): S-1-5-80- followed by the SHA-1 of the upper-case name in UTF-16LE,
    # as five little-endian 32-bit numbers (what `sc.exe showsid` prints). Used when the name cannot be translated.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $Name)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Name.ToUpperInvariant())) } finally { $sha.Dispose() }
    'S-1-5-80-' + ((0, 4, 8, 12, 16 | ForEach-Object { [System.BitConverter]::ToUInt32($b, $_) }) -join '-')
}

function Get-DDAccessLevel {
    <#
    .SYNOPSIS
        full | partial | none for one SID: `full` is Full Control on the folder itself and inherited by its subfolders and
        files (container and object inherit), from one entry or two; `partial` is any other Allow entry.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Entries = @(), [Parameter(Mandatory)][string] $Sid)
    $mine = @(@($Entries) | Where-Object { [string]$_.Sid -eq $Sid -and [string]$_.Type -eq 'Allow' })
    if ($mine.Count -eq 0) { return 'none' }
    $full = { param($e) $r = [long]$e.Rights; (($r -band 2032127) -eq 2032127) -or (($r -band 268435456) -ne 0) }
    $here = @($mine | Where-Object { (& $full $_) -and [string]$_.Propagation -notmatch 'InheritOnly' }).Count -gt 0
    $down = @($mine | Where-Object { (& $full $_) -and [string]$_.Inheritance -match 'ContainerInherit' -and [string]$_.Inheritance -match 'ObjectInherit' -and [string]$_.Propagation -notmatch 'NoPropagateInherit' }).Count -gt 0
    $(if ($here -and $down) { 'full' } else { 'partial' })
}

function ConvertFrom-DDCacheFolderAcl {
    # packages/schema CacheFolderFacts from the folder's access rules (Get-DDCacheFolderAclRaw) and the state file.
    # -SystemRoot is the Windows folder the default cache path is under; a parameter so the mapping is the same wherever
    # it runs (the tests run on Linux too, where $env:SystemRoot does not exist). Without one, custom is unknown.
    [CmdletBinding()]
    param($Raw, [AllowNull()][string] $WorkingDirectory, $StateFile = $null, [AllowNull()][string] $SystemRoot = $env:SystemRoot)
    $default = $(if ($SystemRoot) { $SystemRoot.TrimEnd('\') + '\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache' } else { $null })
    $custom = $null
    if ($WorkingDirectory -and $default) { $custom = -not [string]::Equals($WorkingDirectory.TrimEnd('\'), $default.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase) }
    $f = [ordered]@{ custom = $custom; exists = $null; networkService = $null; doSvc = $null; denyEntries = $null; stateFile = $(if ($null -eq $StateFile) { $null } else { [bool]$StateFile }) }
    if ($null -eq $Raw) { return $f }
    $f['exists'] = [bool]$Raw.Exists
    if (-not $Raw.Exists) { return $f }
    $doSvc = $(if ($Raw.DoSvcSid) { [string]$Raw.DoSvcSid } else { Get-DDServiceSid -Name 'DoSvc' })
    $entries = @($Raw.Entries)
    $f['networkService'] = Get-DDAccessLevel -Entries $entries -Sid $script:DDNetworkServiceSid
    $f['doSvc'] = Get-DDAccessLevel -Entries $entries -Sid $doSvc
    $f['denyEntries'] = @($entries | Where-Object { [string]$_.Type -eq 'Deny' -and ([string]$_.Sid -eq $script:DDNetworkServiceSid -or [string]$_.Sid -eq $doSvc) }).Count
    $f
}

# ---- the new checks (Get-DDConnectivityMatrix adds them) ---------------------------------------------------------------

function New-DDHealthChecks {
    <#
    .SYNOPSIS
        The local checks of Delivery Optimization health (docs/07): the DO geo service, the cache server DO will use, DHCP
        options 235 and 234, the inbound rule's scope, outbound blocks on TCP 7680 and UDP 3544, the cache folder, the state
        file and uploading on battery. Each is a ConnectivityResult with a `code` that names why.
    #>
    [CmdletBinding()]
    param(
        $DoEffective, $Network, [AllowEmptyCollection()] $FirewallRules = @(), $Geo, $CacheHost, $Dhcp, $CacheFolder,
        $Vitals, [AllowNull()][string] $PowerPlan, $ModeNum, [switch] $SkipProbes, [bool] $BatteryCollected = $true,
        # False when Windows refused part of the firewall listing (Test-DDFirewallRulesComplete): no Block rule found then
        # proves nothing.
        [bool] $FirewallRulesComplete = $true
    )
    $checks = New-Object 'System.Collections.Generic.List[object]'
    $add = { param($id, $target, $proto, $port, $result, $detail, $code, $evidence) $c = New-DDCheck -CheckId $id -Target $target -Protocol $proto -Port $port -Result $result -Detail $detail -Evidence $evidence; if ($code) { $c['code'] = $code }; $checks.Add($c) }
    $peeringOff = ($null -ne $ModeNum -and $ModeNum -in 0, 99, 100)
    $modeText = $(if ($null -ne $ModeNum) { "DODownloadMode=$ModeNum" } else { 'DODownloadMode not determined' })
    $geoHost = $script:DDGeoUri -replace '^https://([^/]+)/.*$', '$1'

    # DO geo service (cloud)
    if ($null -ne $ModeNum -and $ModeNum -in 99, 100) { & $add 'do-geo' $geoHost 'https' 443 'not-applicable' "The DO cloud service is not used in $modeText" 'not-needed' $null }
    elseif ($null -eq $Geo -or $Geo.Code -eq 'not-run') { & $add 'do-geo' $geoHost 'https' 443 'not-collected' $(if ($SkipProbes) { 'skipped by -SkipConnectivityChecks' } else { 'The DO geo service was not asked' }) 'not-run' $null }
    else {
        $d = [string]$Geo.Detail
        if ($Geo.Cached) { $d = "$d (result reused from an earlier run on this network)" }
        & $add 'do-geo' $geoHost 'https' 443 ([string]$Geo.Result) $d ([string]$Geo.Code) $Geo.Evidence
        $checks[$checks.Count - 1]['latencyMs'] = $Geo.Ms
    }

    # The cache server DO will use
    $ch = $CacheHost
    if ($null -eq $ch) { & $add 'mcc-cache-host' '' 'local' $null 'not-collected' 'The cache server could not be resolved' 'not-run' $null }
    else {
        $target = $(if (@($ch.Hosts).Count -gt 0) { [string]@($ch.Hosts)[0] } else { '' })
        $state = switch ([string]$ch.Code) {
            { $_ -in 'policy', 'dhcp', 'dhcp-forced', 'service-dhcp', 'service' } { 'pass'; break }
            { $_ -in 'dhcp-expected-not-received', 'service-dhcp-not-received' } { 'warn'; break }
            'vpn-disallowed' { 'not-applicable'; break }
            'none' { 'not-applicable'; break }
            default { 'not-collected' }
        }
        $detail = [string]$ch.Detail
        if ($state -eq 'warn') {
            $hints = Get-DDDhcpBlockHints -Rules $FirewallRules -LocalPolicyMerge $(if ($Network) { $Network['localPolicyMergeEnabled'] } else { $null })
            if (@($hints).Count -gt 0) { $detail = "$detail. Possible causes: $(@($hints) -join '; ')" }
            $detail = "$detail (DO-NET-022)"
        }
        & $add 'mcc-cache-host' $target 'local' $null $state $detail ([string]$ch.Code) $null
    }

    # DHCP option 235 and 234
    $facts = $(if ($Dhcp) { $Dhcp } else { $null })
    $wants = $(if ($facts) { @($facts['wants']) } else { @() })
    $dhcpState = $(if ($facts) { [string]$facts['state'] } else { 'unavailable' })
    $unreadable = { param($what) switch ($dhcpState) { 'timeout' { "The DHCP client did not answer for $what within the collector's bound" } 'api-failed' { "The DHCP client API refused the request for $what (error $($facts['win32Error']))" } 'no-adapter' { "No adapter qualifies for DO, so $what was not read" } default { "$what could not be read on this device (DHCP client API unavailable)" } } }
    $hintText = {
        $h = Get-DDDhcpBlockHints -Rules $FirewallRules -LocalPolicyMerge $(if ($Network) { $Network['localPolicyMergeEnabled'] } else { $null })
        $(if (@($h).Count -gt 0) { ". Possible causes: $(@($h) -join '; ')" } else { '. No firewall rule collected blocks UDP 67 or 68: check that the DHCP server serves the option on this scope' })
    }
    if ($null -eq $facts) { & $add 'mcc-dhcp-235' '' 'udp' 67 'not-collected' 'DHCP option 235 was not read' 'not-run' $null }
    elseif ($wants -notcontains '235') { & $add 'mcc-dhcp-235' '' 'udp' 67 'not-applicable' 'Neither DOCacheHostSource nor the DO service asks this device to use DHCP option 235' 'not-wanted' $null }
    elseif ($facts['option235'] -eq 'received') { & $add 'mcc-dhcp-235' ([string]$Network['dhcpOption235']).Split(',')[0].Trim() 'udp' 67 'pass' 'DHCP option 235 received on the adapter DO uses' 'received' $null }
    elseif ($facts['option235'] -eq 'absent') {
        $sm = $(if ($facts['subnetMask']) { 'The DHCP client answers on this adapter (option 1 came back), so the server did not offer option 235' } else { 'Option 1 (the subnet mask) did not come back either: the adapter may not use DHCP' })
        & $add 'mcc-dhcp-235' '' 'udp' 67 'warn' ("DHCP option 235 expected but not received. $sm$(& $hintText) (DO-NET-022)") 'dhcp-expected-not-received' $null
    } else { & $add 'mcc-dhcp-235' '' 'udp' 67 'not-collected' (& $unreadable 'DHCP option 235') $dhcpState $null }

    if ($null -eq $facts) { & $add 'dhcp-option-234' '' 'udp' 67 'not-collected' 'DHCP option 234 was not read' 'not-run' $null }
    elseif ($wants -notcontains '234') { & $add 'dhcp-option-234' '' 'udp' 67 'not-applicable' 'DOGroupIdSource is not 3 (DHCP Option ID), so DO does not read option 234' 'not-wanted' $null }
    elseif ($null -ne $ModeNum -and $ModeNum -ne 2) { & $add 'dhcp-option-234' '' 'udp' 67 'not-applicable' "DOGroupIdSource applies only in Group (2) download mode ($modeText)" 'not-group-mode' $null }
    elseif ($facts['option234'] -eq 'received') { & $add 'dhcp-option-234' '' 'udp' 67 'pass' 'DHCP option 234 received: the Group ID comes from DHCP' 'received' $null }
    elseif ($facts['option234'] -eq 'absent') { & $add 'dhcp-option-234' '' 'udp' 67 'warn' ("DHCP option 234 expected but not received: DO falls back to the AD site, the domain SID or the Entra tenant ID, in that order (Microsoft)$(& $hintText) (DO-NET-023)") 'dhcp-expected-not-received' $null }
    else { & $add 'dhcp-option-234' '' 'udp' 67 'not-collected' (& $unreadable 'DHCP option 234') $dhcpState $null }

    # The inbound rule's scope
    $rules = @($FirewallRules)
    $active = @($rules | Where-Object { (Test-DDTcp7680Allow -Rule $_) -and $_['enabled'] -and ($null -eq (Get-DDProp $_ 'primaryStatus') -or (Get-DDProp $_ 'primaryStatus') -eq 'OK') })
    $restrict = Get-DDEffectiveValue -Effective $DoEffective -Name 'DORestrictPeerSelectionBy'
    if ($peeringOff) { & $add 'p2p-firewall-scope' 'local' 'local' 7680 'not-applicable' "Peering is disabled by $modeText" 'not-needed' $null }
    elseif ($active.Count -eq 0) { & $add 'p2p-firewall-scope' 'local' 'local' 7680 'not-applicable' 'No enabled inbound Allow rule for TCP 7680 is in force to judge (see the firewall rule check)' 'no-allow' $null }
    elseif (@($active | Where-Object { $null -eq (Get-DDProp $_ 'remoteScope') }).Count -eq $active.Count) { & $add 'p2p-firewall-scope' 'local' 'local' 7680 'not-collected' 'The remote address condition of the allow rules was not read' 'not-run' $null }
    else {
        $open = @($active | Where-Object { (Get-DDProp $_ 'remoteScope') -eq 'any' -and ([string](Get-DDProp $_ 'remotePort') -in '', 'Any') })
        if ($open.Count -gt 0) { & $add 'p2p-firewall-scope' 'local' 'local' 7680 'pass' "An allow rule admits TCP 7680 from any address and any remote port ('$($open[0]['displayName'])')" 'any' $null }
        else {
            $r0 = $active[0]
            $scope = [string](Get-DDProp $r0 'remoteScope')
            $what = switch ($scope) {
                'local-subnet' { 'the local subnet only'; break }
                'ranges' { "$([int](Get-DDProp $r0 'remoteAddresses')) specific address range(s) only"; break }
                'keywords' { 'named address groups only (for example Intranet or DefaultGateway)'; break }
                'mixed' { 'a mix of the local subnet, keywords and specific ranges'; break }
                default { 'a restricted set of remote ports' }
            }
            $portNote = $(if ([string](Get-DDProp $r0 'remotePort') -notin '', 'Any') { "; remote port limited to $((Get-DDProp $r0 'remotePort')), although peers connect from changing ports" } else { '' })
            $why = "Inbound TCP 7680 is allowed from $what ('$($r0['displayName'])')$portNote"
            $restricted = $null -ne $restrict -and [string]$restrict -in '1', '2'
            if ($ModeNum -in 2, 3 -and -not $restricted) {
                & $add 'p2p-firewall-scope' 'local' 'local' 7680 'warn' "$why. In Group and Internet modes peering crosses subnets (Microsoft: in group mode, peering occurs across internal subnets), so peers outside it are refused (DO-NET-018)" $(if ($portNote) { 'remote-port' } else { 'scoped' }) $null
            } elseif ($portNote) {
                & $add 'p2p-firewall-scope' 'local' 'local' 7680 'warn' "$why (DO-NET-018)" 'remote-port' $null
            } else {
                & $add 'p2p-firewall-scope' 'local' 'local' 7680 'pass' "$why. That matches $(if ($restricted) { 'DORestrictPeerSelectionBy, which keeps peers on the subnet' } else { "$modeText, whose peers share this device's network" })" 'scoped-ok' $null
            }
        }
    }

    # Outbound blocks: TCP 7680 to peers, UDP 3544 to the Teredo server
    $out7680 = @(Get-DDOutboundBlocks -Rules $rules -Port 7680 -Protocol TCP)
    if ($peeringOff) { & $add 'p2p-outbound-rule' 'local' 'local' 7680 'not-applicable' "Peering is disabled by $modeText" 'not-needed' $null }
    elseif ($out7680.Count -eq 0 -and -not $FirewallRulesComplete) { & $add 'p2p-outbound-rule' 'local' 'local' 7680 'not-collected' 'Windows refused to list every firewall rule (run it elevated), so an outbound Block rule for TCP 7680 could be among those not read' 'rules-unreadable' $null }
    elseif ($out7680.Count -eq 0) { & $add 'p2p-outbound-rule' 'local' 'local' 7680 'pass' 'No enabled outbound Block rule names TCP 7680' 'none' $null }
    else {
        $live = @($out7680 | Where-Object { $null -eq (Get-DDProp $_ 'primaryStatus') -or (Get-DDProp $_ 'primaryStatus') -eq 'OK' })
        if ($live.Count -gt 0) { & $add 'p2p-outbound-rule' 'local' 'local' 7680 'fail' "An enabled outbound Block rule names TCP 7680 ('$($live[0]['displayName'])'): this device cannot connect to peers (DO-NET-020)" 'outbound-blocked' $null }
        else { & $add 'p2p-outbound-rule' 'local' 'local' 7680 'warn' "An enabled outbound Block rule names TCP 7680 ('$($out7680[0]['displayName'])') but is not in force (status $((Get-DDProp $out7680[0] 'primaryStatus')))" 'outbound-block-inactive' $null }
    }
    $out3544 = @(Get-DDOutboundBlocks -Rules $rules -Port 3544 -Protocol UDP)
    if (-not ($ModeNum -in 2, 3)) { & $add 'teredo-outbound-rule' 'local' 'local' 3544 'not-applicable' "Teredo is only needed for Group or Internet mode ($modeText)" 'not-needed' $null }
    elseif ($out3544.Count -eq 0 -and -not $FirewallRulesComplete) { & $add 'teredo-outbound-rule' 'local' 'local' 3544 'not-collected' 'Windows refused to list every firewall rule (run it elevated), so an outbound Block rule for UDP 3544 could be among those not read' 'rules-unreadable' $null }
    elseif ($out3544.Count -eq 0) { & $add 'teredo-outbound-rule' 'local' 'local' 3544 'pass' 'No enabled outbound Block rule names UDP 3544' 'none' $null }
    else {
        $live = @($out3544 | Where-Object { $null -eq (Get-DDProp $_ 'primaryStatus') -or (Get-DDProp $_ 'primaryStatus') -eq 'OK' })
        if ($live.Count -gt 0) { & $add 'teredo-outbound-rule' 'local' 'local' 3544 'fail' "An enabled outbound Block rule names UDP 3544 ('$($live[0]['displayName'])'): Teredo cannot reach its server, so peers behind other NATs are out of reach (DO-NET-020)" 'outbound-blocked' $null }
        else { & $add 'teredo-outbound-rule' 'local' 'local' 3544 'warn' "An enabled outbound Block rule names UDP 3544 ('$($out3544[0]['displayName'])') but is not in force" 'outbound-block-inactive' $null }
    }

    # The cache folder and the state file
    $cf = $CacheFolder
    if ($null -eq $cf -or $null -eq $cf['exists']) { & $add 'do-cache-folder' '' 'local' $null 'not-collected' 'The cache folder''s permissions could not be read' 'not-run' $null }
    elseif (-not $cf['exists']) {
        if ($cf['custom']) { & $add 'do-cache-folder' '' 'local' $null 'fail' 'The cache folder DOModifyCacheDrive names does not exist: DO restricts its download mode without one (0x80D03809, "DO job download mode restricted due to absence of the cache folder") (DO-CFG-009)' 'cache-folder-missing' $null }
        else { & $add 'do-cache-folder' '' 'local' $null 'warn' 'The default cache folder does not exist yet; DoSvc creates it when it first caches content (DoctorDO inference)' 'cache-folder-missing' $null }
    }
    elseif ([int]$cf['denyEntries'] -gt 0) { & $add 'do-cache-folder' '' 'local' $null 'fail' "The cache folder has $($cf['denyEntries']) Deny entr$(if ([int]$cf['denyEntries'] -eq 1) { 'y' } else { 'ies' }) for NETWORK SERVICE or NT SERVICE\DoSvc: DoSvc cannot cache content, so it has nothing to share (DO-CFG-009)" 'cache-folder-denied' $null }
    elseif ($cf['networkService'] -ne 'full' -and $cf['doSvc'] -ne 'full') {
        & $add 'do-cache-folder' '' 'local' $null 'fail' "Neither NETWORK SERVICE ($($cf['networkService'])) nor NT SERVICE\DoSvc ($($cf['doSvc'])) has inheritable Full Control on the cache folder$(if ($cf['custom']) { ' that DOModifyCacheDrive names' }): DoSvc cannot cache content, so it has nothing to share (DO-CFG-009)" 'cache-folder-access' $null
    } else {
        & $add 'do-cache-folder' '' 'local' $null 'pass' "NETWORK SERVICE: $($cf['networkService']) access; NT SERVICE\DoSvc: $($cf['doSvc']) access; no Deny entry$(if ($cf['custom']) { '. Custom location (DOModifyCacheDrive)' })" 'ok' $null
    }
    if ($null -eq $cf -or $null -eq $cf['stateFile']) { & $add 'do-state-file' '' 'local' $null 'not-collected' 'Whether DoSvc''s state file exists could not be read' 'not-run' $null }
    elseif ($cf['stateFile']) { & $add 'do-state-file' '' 'local' $null 'pass' 'DoSvc''s state file (dosvcState.dat) is present' 'ok' $null }
    else { & $add 'do-state-file' '' 'local' $null 'warn' 'DoSvc''s state file (dosvcState.dat, under the NetworkService profile) is missing. DoSvc writes it when it runs; a missing file usually means the service has not run or its profile was reset (DoctorDO inference; Microsoft''s troubleshooter reports it as a failure) (DO-CFG-010)' 'state-file-missing' $null }

    # Uploading on battery
    $plan = $(if ($PowerPlan) { "; power plan: $PowerPlan" } else { '' })
    if ($peeringOff) { & $add 'power-upload' '' 'local' $null 'not-applicable' "Peering is disabled by $modeText" 'not-needed' $null }
    elseif (-not $BatteryCollected -or $null -eq $Vitals) { & $add 'power-upload' '' 'local' $null 'not-collected' 'The battery state could not be read' 'not-run' $null }
    elseif (-not $Vitals['onBattery']) { & $add 'power-upload' '' 'local' $null 'pass' "On AC power$plan" 'ac' $null }
    else {
        $min = Get-DDEffectiveValue -Effective $DoEffective -Name 'DOMinBatteryPercentageAllowedToUpload'
        $pct = $Vitals['batteryPercent']
        if ($null -eq $min -or [double]$min -le 0) { & $add 'power-upload' '' 'local' $null 'warn' "On battery$(if ($null -ne $pct) { " at $pct%" })$plan. DOMinBatteryPercentageAllowedToUpload is not set, and Microsoft: ""By default, devices won't upload while on battery""" 'battery-no-upload' $null }
        elseif ($null -ne $pct -and [double]$pct -ge [double]$min) { & $add 'power-upload' '' 'local' $null 'pass' "On battery at $pct%, at or above the $min% DOMinBatteryPercentageAllowedToUpload allows uploads from$plan" 'battery-ok' $null }
        else { & $add 'power-upload' '' 'local' $null 'warn' "On battery$(if ($null -ne $pct) { " at $pct%" }): uploads pause below $min% (DOMinBatteryPercentageAllowedToUpload)$plan" 'battery-below-threshold' $null }
    }
    , $checks.ToArray()
}

# ---- orchestrators --------------------------------------------------------------------------------------------------------

function Get-DDGeoFacts {
    <#
    .SYNOPSIS
        Ask the DO geo service once (or reuse a fleet run's recent answer on the same network), through the proxy WinHTTP
        would use. The public address is read only with -WantExternalIp, and then the answer is never cached.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [string] $OsVersion, [switch] $Skip, [string] $CachePath, [int] $MaxAgeMinutes = 360, [switch] $WantExternalIp, [string] $Signature = '', [datetime] $Now = (Get-DDNowUtc))
    if ($Skip) { return (ConvertFrom-DDGeoOutcome -Outcome $null) }
    $sig = "geo|$OsVersion|$Signature"
    if (-not $WantExternalIp) {
        $c = Read-DDGeoCache -Path $CachePath -Signature $sig -Now $Now -MaxAgeMinutes $MaxAgeMinutes
        if ($null -ne $c) { return $c }
    }
    $uri = '{0}?doClientVersion={1}' -f $script:DDGeoUri, [System.Uri]::EscapeDataString($(if ($OsVersion) { $OsVersion } else { '10.0' }))
    $px = Invoke-DDStep -Context $Context -Field 'connectivity.do-geo.proxy' -Script { Resolve-DDUrlProxy -Uri $uri }
    $o = Invoke-DDStep -Context $Context -Field 'connectivity.do-geo' -Script { Invoke-DDHttpFetch -Uri $uri -Proxy $(if ($px -and $px.Proxy) { [string]$px.Proxy } else { $null }) -ReadBodyFor @('text/json', 'application/json') }
    if ($null -eq $o) { return [pscustomobject]@{ Result = 'not-collected'; Code = 'not-run'; Detail = 'The DO geo service request could not run on this device'; Evidence = $null; HttpStatus = $null; ContentType = $null; CacheHost = $null; CacheHostFlag = $null; ExternalIp = $null; Ms = $null; Cached = $false } }
    $g = ConvertFrom-DDGeoOutcome -Outcome $o -ReadExternalIp:$WantExternalIp
    if ($g.Result -ne 'not-collected') { Save-DDGeoCache -Path $CachePath -Signature $sig -At (Format-DDIso -Value $Now) -Geo $g }
    $g
}

function Get-DDDoAdapterFacts {
    # The adapter DO uses (Select-DDDoAdapter) from the platform's adapter list, or $null with a notCollected record.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, $DefaultInterfaceIndex)
    $candidates = Invoke-DDStep -Context $Context -Field 'network.doAdapter' -Script { Get-DDAdapterCandidatesRaw }
    if ($null -eq $candidates) { return $null }
    $pick = Select-DDDoAdapter -Candidates @($candidates) -DefaultInterfaceIndex $DefaultInterfaceIndex
    if ($null -eq $pick) { Add-DDNotCollected -Context $Context -Field 'network.doAdapter' -Reason 'error' -Detail 'no adapter is up with a usable IPv4 address' }
    $pick
}

function Get-DDDhcpFacts {
    <#
    .SYNOPSIS
        Read DHCP options 234 and 235 on the adapter DO uses, only when DO itself would read them (Get-DDDhcpWants), with
        option 1 beside them as the sanity check. Returns @{ Facts; Values }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, $Effective, $Adapter, $Geo, [int] $TimeoutMs = 8000)
    $wants = @(Get-DDDhcpWants -Effective $Effective -Geo $Geo)
    if ($wants.Count -eq 0) { return (ConvertFrom-DDDhcpOutcome -Wants @()) }
    if ($null -eq $Adapter -or -not $Adapter.Id) { return (ConvertFrom-DDDhcpOutcome -Wants $wants -NoAdapter) }
    $ids = [int[]](@(1) + @($wants | ForEach-Object { [int]$_ }))
    $o = Invoke-DDStep -Context $Context -Field 'network.dhcp' -Script { Get-DDDhcpOptionsRaw -AdapterId ([string]$Adapter.Id) -OptionIds $ids -TimeoutMs $TimeoutMs }
    ConvertFrom-DDDhcpOutcome -Wants $wants -Outcome $o -Unavailable:($null -eq $o)
}

function Get-DDCacheFolderFacts {
    # Cache folder access and the state file (packages/schema CacheFolderFacts).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [AllowNull()][string] $WorkingDirectory)
    $path = $WorkingDirectory
    if (-not $path -and $env:SystemRoot) { $path = Join-Path $env:SystemRoot 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache' }
    $raw = $null
    if ($path) { $raw = Invoke-DDStep -Context $Context -Field 'doConfig.cacheFolder' -Script { Get-DDCacheFolderAclRaw -Path $path } }
    $state = Invoke-DDStep -Context $Context -Field 'doConfig.cacheFolder.stateFile' -Script { Test-DDDoStateFile }
    ConvertFrom-DDCacheFolderAcl -Raw $raw -WorkingDirectory $WorkingDirectory -StateFile $state
}
