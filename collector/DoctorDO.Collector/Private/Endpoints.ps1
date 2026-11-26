#Requires -Version 5.1
# Endpoint health (docs/07-connectivity-validation.md, Data/endpoints.json).
#
#  * The manifest (Data/endpoints.json) is the single source of truth for what is tested; the TypeScript side is
#    generated from it. Each entry becomes one result per host tested, checkId 'ep:<id>', with an `endpoint` object.
#  * Hosts are never guessed. For a wildcard: the hosts this device used (Get-DeliveryOptimizationStatus SourceURL, hosts
#    named in the DO log), then the hosts a cited Microsoft page names, else 'not testable (wildcard)' with no probe.
#    Never enumerated.
#  * Probes are DNS, TCP, a TLS handshake that judges the certificate, one HEAD (or Microsoft's documented Connected Cache
#    verification request), and one Range: bytes=0-0 request for a file the device itself downloaded. Through the proxy
#    WinHTTP would use for DoSvc in the background context, with a direct TCP connect to compare.
#  * Bounded: 4 s per stage, 8 rows at a time, 40 s in total; results cached on the device (default 6 h) so repeated
#    fleet runs do not hammer the endpoints.
#  * Privacy (docs/10, ADR-0031): no URL, path or query leaves the device; resolved addresses only for CDN and Connected
#    Cache hosts; the issuer name of a non-Microsoft certificate only without -Anonymise; never the public IP.

Set-StrictMode -Version Latest

$script:DDEndpointManifest = $null
$script:DDEndpointAddressServices = @('do-content', 'wu-content', 'office-cdn', 'intune', 'mcc')
$script:DDEndpointCacheVersion = 2   # 2: verification GET for Connected Cache, strict Content-Range (October 2026)
$script:DDServiceWords = @{ 'office-cdn' = 'Microsoft 365 Apps or Teams'; 'intune' = 'Intune app'; 'store' = 'Xbox or Microsoft Store'; 'edge' = 'Microsoft Edge' }

function Get-DDEndpointManifest {
    [CmdletBinding()]
    param()
    if ($null -eq $script:DDEndpointManifest) {
        $script:DDEndpointManifest = Read-DDJsonFile -Path (Join-Path -Path $script:ModuleRoot -ChildPath 'Data/endpoints.json')
    }
    $script:DDEndpointManifest
}

function Test-DDHostPattern {
    <#
    .SYNOPSIS
        Host-pattern match, identical to matchesPattern in packages/analysis (both run the manifest's patternTests).
        Case-insensitive, trailing dot ignored; a leading '*.' is one or more whole labels, a leading '*' any prefix,
        '*' inside a label any run of letters, digits and hyphens within it.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string] $Pattern, [Parameter(Mandatory)][AllowEmptyString()][string] $HostName)
    $h = $HostName.Trim().ToLowerInvariant().TrimEnd('.')
    $p = $Pattern.Trim().ToLowerInvariant()
    if ($p -cnotmatch '^[a-z0-9.*-]+$' -or $h -cnotmatch '^[a-z0-9.-]+$') { return $false }
    $prefix = ''
    if ($p.StartsWith('*.')) { $prefix = '(?:[a-z0-9-]+\.)+'; $p = $p.Substring(2) }
    elseif ($p.StartsWith('*')) { $prefix = '[a-z0-9.-]*'; $p = $p.Substring(1) }
    $body = (($p.Split('*') | ForEach-Object { $_.Replace('.', '\.') }) -join '[a-z0-9-]*')
    [regex]::IsMatch($h, "^$prefix$body$")
}

function Get-DDEndpointForHost {
    # The most specific manifest entry a host matches (endpointForHost in packages/analysis), or $null.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Manifest, [Parameter(Mandatory)][string] $HostName)
    $best = $null; $bestLen = -1
    foreach ($e in @($Manifest['endpoints'])) {
        if ($e['scope'] -eq 'configured') { continue }
        if (-not (Test-DDHostPattern -Pattern $e['pattern'] -HostName $HostName)) { continue }
        $len = ([string]$e['pattern']).Replace('*', '').Length
        if ($len -gt $bestLen -or ($len -eq $bestLen -and [string]::CompareOrdinal([string]$e['id'], [string]$best['id']) -lt 0)) { $best = $e; $bestLen = $len }
    }
    $best
}

function Get-DDObservedEndpointUse {
    <#
    .SYNOPSIS
        What the device itself used, from data the collector already gathered: the hosts of the DO job list's SourceURL
        (each with one URL kept in memory for a byte-range request), hosts named in DO log lines, and the callers. Only
        hosts that fall under a manifest entry are kept. URLs never leave this function except as a probe target.
    #>
    [CmdletBinding()]
    param(
        $Manifest = (Get-DDEndpointManifest),
        [AllowEmptyCollection()] $StatusRaw = @(),
        [AllowEmptyCollection()] $LogEntries = @(),
        [string] $RangeProbeUri
    )
    $hosts = @{}   # host -> @{ Id; Host; Count; Url; Size; Sources }
    $note = {
        param([string] $h, [string] $url, [string] $source, [int] $weight, $size = $null)
        $h = $h.Trim().ToLowerInvariant().TrimEnd('.')
        if (-not $h -or $h -match '^[0-9.]+$' -or $h.Contains(':')) { return }
        $e = Get-DDEndpointForHost -Manifest $Manifest -HostName $h
        if ($null -eq $e) { return }
        if (-not $hosts.ContainsKey($h)) { $hosts[$h] = [pscustomobject]@{ Id = [string]$e['id']; Host = $h; Count = 0; Url = $null; Size = $null; Sources = New-Object 'System.Collections.Generic.List[string]' } }
        $x = $hosts[$h]
        $x.Count += $weight
        # The file's size travels with its URL: a 206 must then report exactly that total (Content-Range).
        if ($url -and -not $x.Url -and $url -match '^(?i)https?://') { $x.Url = $url; $x.Size = $size }
        if (-not $x.Sources.Contains($source)) { $x.Sources.Add($source) }
    }
    # Newest content first, so the URL kept for the byte-range request is the one most likely still served.
    $rows = @($StatusRaw | Sort-Object -Property @{ Expression = { $v = Get-DDProp $_ 'ExpireOn'; if ($v -is [datetime]) { $v } else { [datetime]::MinValue } } } -Descending)
    $callers = New-Object 'System.Collections.Generic.List[string]'
    foreach ($s in $rows) {
        $c = [string](Get-DDProp $s 'PredefinedCallerApplication')
        if ($c -and -not $callers.Contains($c)) { $callers.Add($c) }
        $url = [string](Get-DDProp $s 'SourceURL')
        $h = Get-DDUrlHost -Url $url
        $size = ConvertTo-DDBigInt (Get-DDProp $s 'FileSize')
        if ($h) { & $note $h $url 'status' 1 $(if ($size -gt [System.Numerics.BigInteger]::Zero) { $size.ToString() } else { $null }) }
    }
    if ($RangeProbeUri) { $h = Get-DDUrlHost -Url $RangeProbeUri; if ($h) { & $note $h $RangeProbeUri 'parameter' 0 } }
    $rx = [regex]'(?i)\b((?:[a-z0-9-]+\.)+(?:microsoft\.com|windowsupdate\.com|office\.net|static\.microsoft|xboxlive\.com|live\.com|windows\.com|akamaized\.net))\b'
    foreach ($e in @($LogEntries)) {
        $msg = [string](Get-DDProp $e 'Message')
        if (-not $msg) { continue }
        foreach ($m in $rx.Matches($msg)) { & $note $m.Groups[1].Value $null 'log' 1 }
    }
    [pscustomobject]@{ Hosts = @($hosts.Values | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Host'; Descending = $false }); Callers = $callers.ToArray() }
}

function Get-DDEndpointPlan {
    <#
    .SYNOPSIS
        One row per host to test (or per entry that is not testable or not applicable), in manifest order.
    #>
    [CmdletBinding()]
    param(
        $Manifest = (Get-DDEndpointManifest),
        [Parameter(Mandatory)] $Observed,
        $ModeNum,
        [AllowEmptyCollection()][string[]] $ConfiguredCacheHosts = @(),
        [AllowEmptyCollection()][string[]] $UsedCacheHosts = @()
    )
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $modeText = $(if ($null -ne $ModeNum) { "DODownloadMode=$ModeNum" } else { 'DODownloadMode not determined' })
    foreach ($e in @($Manifest['endpoints'])) {
        $id = [string]$e['id']
        $ports = @($e['ports'] | ForEach-Object { [int]$_['port'] })
        $protos = @($e['ports'] | ForEach-Object { [string]$_['protocol'] })
        $base = @{ Id = $id; Entry = $e; Ports = $ports; Protocols = $protos; PrimaryPort = $ports[0]; PrimaryProtocol = $protos[0] }
        $add = {
            param($hostName, $basis, $url, $why, $size = $null)
            $r = [pscustomobject]($base + @{ Host = $hostName; Basis = $basis; RangeUrl = $url; RangeSize = $size; Skip = $why })
            $rows.Add($r)
        }
        if ($null -ne $ModeNum -and @($e['modes']) -notcontains [int]$ModeNum) { & $add '' 'not-applicable' $null "Not needed in $modeText"; continue }
        $obs = @($Observed.Hosts | Where-Object { $_.Id -eq $id })
        if ($e['scope'] -eq 'configured') {
            # Configured first (DOCacheHost), then servers that served this device without being configured (ADR-0031).
            $list = New-Object 'System.Collections.Generic.List[object]'
            foreach ($h in $ConfiguredCacheHosts) { if ($h -and -not ($list | Where-Object { $_.Host -eq $h })) { $list.Add([pscustomobject]@{ Host = [string]$h; Basis = 'configured' }) } }
            foreach ($h in $UsedCacheHosts) { if ($h -and -not ($list | Where-Object { $_.Host -eq $h })) { $list.Add([pscustomobject]@{ Host = [string]$h; Basis = 'observed' }) } }
            if ($list.Count -eq 0) { & $add '' 'not-applicable' $null 'No Connected Cache server configured or used'; continue }
            $path = [string]$e['probePath']['path']
            foreach ($x in @($list.ToArray() | Select-Object -First ([int]$e['maxHosts']))) {
                $hp = $(if ($x.Host.Contains(':')) { "[$($x.Host)]" } else { $x.Host })
                & $add $x.Host $x.Basis ("http://$hp$path") $null
            }
            continue
        }
        if ($e['scope'] -eq 'when-used') {
            $byCaller = @($Observed.Callers | Where-Object { $c = ([string]$_).ToLowerInvariant(); @($e['callers'] | Where-Object { $c.Contains([string]$_) }).Count -gt 0 }).Count -gt 0
            if ($obs.Count -eq 0 -and -not $byCaller) { & $add '' 'not-applicable' $null "Not used here: no $($script:DDServiceWords[[string]$e['service']]) content in this device's Delivery Optimization jobs"; continue }
        }
        if (-not $e['wildcard']) {
            $o = $obs | Select-Object -First 1
            & $add ([string]$e['pattern']) $(if ($o) { 'observed' } else { 'documented' }) $null $null
            continue
        }
        $picked = New-Object 'System.Collections.Generic.List[string]'
        foreach ($o in $obs) {
            if ($picked.Count -ge [int]$e['maxHosts']) { break }
            $picked.Add($o.Host)
            & $add $o.Host 'observed' $(if ($e['range']) { $o.Url } else { $null }) $null $(if ($e['range']) { Get-DDProp $o 'Size' } else { $null })
        }
        foreach ($d in @($e['documentedHosts'])) {
            if ($picked.Count -ge [int]$e['maxHosts']) { break }
            if ($picked.Contains([string]$d['host'])) { continue }
            $picked.Add([string]$d['host'])
            & $add ([string]$d['host']) 'documented' $null $null
        }
        if ($picked.Count -eq 0) { & $add '' 'not-testable' $null 'Not testable: wildcard, no observed host and none documented' }
    }
    , $rows.ToArray()
}

function Resolve-DDProbeProxy {
    <#
    .SYNOPSIS
        The proxy WinHTTP would use for each row's URL in DoSvc's background context: a netsh winhttp proxy wins, else
        the WinINET configuration (WPAD, PAC, static), per "Using a proxy with Delivery Optimization" with no user signed
        in. Under SYSTEM that is the device's configuration; run interactively it is this account's (Context 'user'). A
        signed-in user's own proxy, which DoSvc uses for that user's downloads, is not modelled. Mockable seam. Returns
        host -> @{ Source; Proxy; Error; Context = 'no-user' | 'user' }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Rows, [int] $TimeoutMs = 4000, [int] $BudgetMs = 8000)
    $out = @{}
    if (-not (Test-DDWindows)) { return $out }
    Initialize-DDNative
    $context = $(if (Test-DDSystemContext) { 'no-user' } else { 'user' })
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($r in @($Rows)) {
        if (-not $r.Host -or $out.ContainsKey($r.Host)) { continue }
        if ($sw.ElapsedMilliseconds -ge $BudgetMs) { $out[$r.Host] = [pscustomobject]@{ Source = 'unresolved'; Proxy = $null; Error = 'proxy resolution budget exhausted'; Context = $context }; continue }
        $scheme = $(if ($r.PrimaryProtocol -eq 'https') { 'https' } else { 'http' })
        $hp = $(if ($r.Host.Contains(':')) { "[$($r.Host)]" } else { $r.Host })
        $d = [DoctorDO.Net.WinHttpProxy]::ForUrl("${scheme}://$hp/", $TimeoutMs)
        $out[$r.Host] = [pscustomobject]@{ Source = $d.Source; Proxy = $d.Proxy; Error = $d.Error; Context = $context }
    }
    $out
}

function Invoke-DDEndpointProbeBatch {
    <#
    .SYNOPSIS
        Run the endpoint probes (DoctorDO.Net.EndpointProbe). Mockable seam for the tests.
    .PARAMETER Specs
        Objects with Tag, Host, Ports, Protocols, Tls, Http, RangeUrl, Proxy, WantAddresses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()] $Specs,
        [int] $ProbeTimeoutMs = 4000,
        [int] $TotalTimeoutMs = 40000,
        [int] $MaxConcurrency = 8
    )
    $list = @($Specs)
    if ($list.Count -eq 0) { return @() }
    Initialize-DDNative
    $arr = New-Object 'DoctorDO.Net.EndpointRowSpec[]' $list.Count
    for ($i = 0; $i -lt $list.Count; $i++) {
        $s = New-Object DoctorDO.Net.EndpointRowSpec
        $s.Tag = [string]$list[$i].Tag; $s.Host = [string]$list[$i].Host
        $s.Ports = [int[]]@($list[$i].Ports); $s.Protocols = [string[]]@($list[$i].Protocols)
        $s.Tls = [bool]$list[$i].Tls; $s.Http = [bool]$list[$i].Http
        $s.RangeUrl = $(if ($list[$i].RangeUrl) { [string]$list[$i].RangeUrl } else { $null })
        $s.VerifyUrl = $(if ($null -ne $list[$i].PSObject.Properties['VerifyUrl'] -and $list[$i].VerifyUrl) { [string]$list[$i].VerifyUrl } else { $null })
        $s.Proxy = $(if ($list[$i].Proxy) { [string]$list[$i].Proxy } else { $null })
        $s.WantAddresses = [bool]$list[$i].WantAddresses
        $arr[$i] = $s
    }
    @([DoctorDO.Net.EndpointProbe]::RunRows($arr, $ProbeTimeoutMs, $TotalTimeoutMs, $MaxConcurrency))
}

function Get-DDIssuerCommonName {
    [CmdletBinding()]
    param([AllowNull()][string] $DistinguishedName)
    if (-not $DistinguishedName) { return $null }
    $m = [regex]::Match($DistinguishedName, '(?i)(?:^|,\s*)CN=("[^"]+"|[^,]+)')
    if (-not $m.Success) { $m = [regex]::Match($DistinguishedName, '(?i)(?:^|,\s*)O=("[^"]+"|[^,]+)') }
    if (-not $m.Success) { return $null }
    $v = $m.Groups[1].Value.Trim('"', ' ')
    $v.Substring(0, [math]::Min(64, $v.Length))
}

function ConvertTo-DDEndpointResult {
    <#
    .SYNOPSIS
        One plan row and its probe outcome as a ConnectivityResult with `endpoint` (packages/schema EndpointProbe).
        Stage semantics live here, not in the native code, so they are tested with mocked outcomes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Row, $Outcome, $Proxy, [Parameter(Mandatory)] $Context, [Parameter(Mandatory)][string] $At)

    $e = $Row.Entry
    $id = $Row.Id
    $protocol = $(if ($Row.PrimaryProtocol -eq 'udp') { 'udp' } else { $Row.PrimaryProtocol })
    $hasHttps = @($Row.Protocols) -contains 'https'
    $tcpPorts = @(for ($i = 0; $i -lt @($Row.Ports).Count; $i++) { if (@($Row.Protocols)[$i] -ne 'udp') { @($Row.Ports)[$i] } })
    $na = 'not-applicable'; $nc = 'not-collected'
    $stage = [ordered]@{ dns = $nc; tcp = $nc; tls = $nc; http = $nc; range = $nc }
    $proxyOut = [ordered]@{ source = 'none'; used = $false; direct = $null }
    if ($Proxy) { $proxyOut['source'] = [string]$Proxy.Source }
    $ep = [ordered]@{ id = $id; basis = [string]$Row.Basis }
    $dnsTypes = @(); $addrs = @(); $httpStatus = $null; $cert = $null

    $finish = {
        param($result, $latency, $detail, $evidence, $code, $message)
        foreach ($k in $stage.Keys) { $ep[$k] = $stage[$k] }
        $ep['dnsTypes'] = @($dnsTypes); $ep['addrs'] = @($addrs); $ep['httpStatus'] = $httpStatus
        $ep['cert'] = $cert; $ep['proxy'] = $proxyOut
        $m = Protect-DDLogText -Text ([string]$message)
        $ep['err'] = $(if ($code) { [ordered]@{ code = $code; message = $m.Substring(0, [math]::Min(200, $m.Length)) } } else { $null })
        $ep['at'] = $At; $ep['cached'] = $false
        $o = [ordered]@{ checkId = "ep:$id"; target = [string]$Row.Host; protocol = $protocol; port = $Row.PrimaryPort; result = $result; latencyMs = $latency; detail = $detail }
        if ($evidence) { $ev = Protect-DDLogText -Text $evidence; $o['evidence'] = $ev.Substring(0, [math]::Min(512, $ev.Length)) }
        $o['endpoint'] = $ep
        $o
    }

    if ($Row.Basis -eq 'not-applicable') {
        foreach ($k in @($stage.Keys)) { $stage[$k] = $na }
        return (& $finish $na $null $Row.Skip $null $null $null)
    }
    if ($Row.Basis -eq 'not-testable') {
        return (& $finish $nc $null ("Not testable: wildcard {0}, no observed host and none documented" -f $e['pattern']) $null $null $null)
    }
    if ($null -eq $Outcome) { return (& $finish $nc $null 'skipped by -SkipConnectivityChecks' $null $null $null) }
    if ($Outcome.TimedOut) { return (& $finish $nc $null 'Not probed: the endpoint-health time budget ran out first' $null 'budget-exhausted' 'total probe budget exhausted') }

    $proxied = [bool]$Proxy -and [bool]$Proxy.Proxy
    $proxyOut['used'] = [bool]$Outcome.ProxyUsed
    $ev = New-Object 'System.Collections.Generic.List[string]'
    $why = New-Object 'System.Collections.Generic.List[string]'
    $code = $null; $msg = $null
    $fail = { param($c, $m) if (-not $code) { Set-Variable -Name code -Value $c -Scope 1; Set-Variable -Name msg -Value $m -Scope 1 } }

    # DNS
    $types = @(([string]$Outcome.DnsTypes).Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) | Where-Object { $_ -in 'A', 'AAAA' })
    $dnsTypes = $types
    if ($Outcome.DnsOk) {
        $stage['dns'] = 'pass'
        if ($e['service'] -in $script:DDEndpointAddressServices) { $addrs = @(([string]$Outcome.Addresses).Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) | Select-Object -First 2) }
        $ev.Add(("dns={0} {1}ms" -f ($types -join ','), [math]::Round([double]$Outcome.DnsMs)))
        $why.Add("Resolved ($($types -join ', '))")
    } elseif ($Outcome.DnsAttempted) {
        # Through an explicit proxy the proxy resolves the name, so local resolution is not needed.
        $stage['dns'] = $(if ($proxied) { 'not-applicable' } else { 'fail' })
        $ev.Add("dns failed: $($Outcome.DnsError)")
        # "Name does not exist" (NXDOMAIN) is not the same as "blocked": Microsoft still lists some names that no longer
        # resolve anywhere (emdl.ws.microsoft.com, 13 Oct 2026). On a low-stakes entry that is a warning, not a failure.
        $nx = ([string]$Outcome.DnsError) -match 'HostNotFound|NoData|NXDOMAIN'
        if ($proxied) { $why.Add('Does not resolve on the device; through the proxy it does not need to') }
        elseif ($nx) {
            if ($e['severity'] -eq 'advisory') { $stage['dns'] = 'warn' }
            & $fail 'dns-nxdomain' 'The name does not exist in DNS (NXDOMAIN)'
            $why.Add('The name does not exist in DNS. Microsoft still lists it; if every device says the same, it is more likely retired than blocked')
        }
        else { & $fail 'dns-failed' "DNS resolution failed: $($Outcome.DnsError)"; $why.Add("Name does not resolve ($($Outcome.DnsError))") }
    }

    # TCP
    $ports = @($Outcome.Ports)
    $latency = $null
    if ($tcpPorts.Count -eq 0) { $stage['tcp'] = $na }
    elseif ($ports.Count -gt 0) {
        $bad = @($ports | Where-Object { -not $_.Ok })
        $stage['tcp'] = $(if ($bad.Count -eq 0) { 'pass' } else { 'fail' })
        $firstOk = @($ports | Where-Object { $_.Ok }) | Select-Object -First 1
        if ($null -ne $firstOk) { $latency = [double]$firstOk.Ms }
        foreach ($p in $ports) {
            $via = $(if ($p.ViaProxy) { ' via proxy' } else { '' })
            if ($p.Ok) { $ev.Add(("tcp:{0}{1} {2}ms" -f $p.Port, $via, [math]::Round([double]$p.Ms))) }
            else { $ev.Add(("tcp:{0}{1} {2}" -f $p.Port, $via, $(if ($p.TimedOut) { 'timeout' } else { $p.Error }))) }
        }
        foreach ($p in $bad) {
            if ($p.ViaProxy -and $p.ProxyStatus -eq 407) { & $fail 'proxy-auth-required' "The proxy requires authentication for TCP $($p.Port) (407)" }
            elseif ($p.ViaProxy -and $p.ProxyStatus -ge 400) { & $fail 'proxy-denied' "The proxy refused TCP $($p.Port) ($($p.ProxyStatus))" }
            elseif ($p.TimedOut) { & $fail 'tcp-timeout' "TCP $($p.Port) timed out (black-holed or filtered)" }
            else { & $fail 'tcp-failed' "TCP $($p.Port) failed: $($p.Error)" }
        }
        # Through a proxy an HTTPS port is tested with CONNECT, so the proxy reached the host; an HTTP port only reaches the
        # proxy (ProxyOnly), and the HTTP or byte-range request is what shows whether the proxy reaches the host.
        $proxyOnly = @($ports | Where-Object { $_.Ok -and (Get-DDProp $_ 'ProxyOnly') -eq $true } | ForEach-Object { $_.Port })
        $tunnelled = @($ports | Where-Object { $_.Ok -and (Get-DDProp $_ 'ProxyOnly') -ne $true } | ForEach-Object { $_.Port })
        if ($bad.Count -gt 0) { $why.Add($msg) }
        elseif ($proxyOnly.Count -eq 0) { $why.Add("TCP $($tcpPorts -join ', ') connected$(if ($proxied) { ' through the proxy' })") }
        else {
            $shown = $(if ($e['http']) { 'the HTTP request shows whether it reaches the host' } elseif ($Row.RangeUrl) { 'the byte-range request shows whether it reaches the host' } else { 'whether it reaches the host on that port is not tested' })
            $why.Add((@($(if ($tunnelled.Count -gt 0) { "TCP $($tunnelled -join ', ') connected through the proxy" }), "the proxy is reachable for TCP $($proxyOnly -join ', ') ($shown)") | Where-Object { $_ }) -join '; ')
        }
    }

    # TLS
    if (-not $hasHttps) { $stage['tls'] = $na }
    elseif ($Outcome.TlsAttempted) {
        if ($Outcome.TlsHandshake) {
            $issuer = $(if ($Outcome.ChainMicrosoft) { 'microsoft' } elseif ($Outcome.ChainOk) { 'other-trusted' } else { 'untrusted' })
            $cn = $null
            if ($issuer -ne 'microsoft' -and -not $Context.Anonymise) { $cn = Get-DDIssuerCommonName -DistinguishedName ([string]$Outcome.Issuer) }
            $cert = [ordered]@{ issuer = $issuer; nameOk = [bool]$Outcome.NameOk; chainOk = [bool]$Outcome.ChainOk; issuerCn = $cn }
            $ev.Add(("tls={0} issuer={1} name={2} chain={3}" -f $Outcome.TlsProtocol, $issuer, $(if ($Outcome.NameOk) { 'ok' } else { 'mismatch' }), $(if ($Outcome.ChainOk) { 'ok' } else { 'untrusted' })))
            # The words follow the structured field: 'microsoft' is never described as "not Microsoft", whatever -Anonymise hides.
            $who = $(if ($issuer -eq 'microsoft') { 'a Microsoft certification authority' } elseif ($cn) { "'$cn'" } else { 'a certificate authority that is not Microsoft' })
            if ($e['pinned'] -and $issuer -ne 'microsoft') {
                $stage['tls'] = 'fail'; & $fail 'tls-inspected' "Certificate issued by $who on a certificate-pinned endpoint: TLS inspection in the path"
                $why.Add("TLS: certificate issued by $who. This endpoint is certificate-pinned, so something is inspecting TLS (DO-NET-006)")
            } elseif (-not $Outcome.ChainOk) {
                $stage['tls'] = 'fail'; & $fail 'tls-untrusted' "The certificate chain does not validate on this device (issuer $who)"
                $why.Add("TLS: the certificate chain does not validate (issuer $who)")
            } elseif (-not $Outcome.NameOk) {
                $stage['tls'] = 'fail'; & $fail 'tls-name-mismatch' 'The certificate does not name this host'
                $why.Add('TLS: the certificate does not name this host')
            } else {
                $stage['tls'] = 'pass'
                $why.Add("TLS handshake completed, certificate valid$(if ($issuer -eq 'microsoft') { ' and issued by Microsoft' })")
            }
        } else {
            $stage['tls'] = 'fail'; & $fail 'tls-failed' "TLS handshake failed: $($Outcome.TlsError)"
            $ev.Add("tls failed: $($Outcome.TlsError)"); $why.Add("TLS handshake failed ($($Outcome.TlsError))")
        }
    }

    # HTTP (for the Connected Cache, the documented verification request is the HTTP check)
    $isMcc = ($e['scope'] -eq 'configured')
    $verified = $isMcc -and (Get-DDProp $Outcome 'VerifyAttempted') -eq $true
    if ($verified) {
        # Microsoft's documented verification request, sent without a range: "If successful, there should be an HTTP
        # response with StatusCode 200" (Verify Connected Cache node functionality). Content-Type and Content-Length are
        # checked as Microsoft's DeliveryOptimizationTroubleshooter 1.3.1 checks them; the size is not on Learn, so a
        # different one is a warning. The body is never read.
        $vs = [int](Get-DDProp $Outcome 'VerifyStatus')
        $vt = [string](Get-DDProp $Outcome 'VerifyContentType'); if ($vt) { $vt = $vt.Split(';')[0].Trim().ToLowerInvariant() }
        $vl = Get-DDProp $Outcome 'VerifyContentLength'; $vl = $(if ($null -ne $vl -and [long]$vl -ge 0) { [long]$vl } else { $null })
        $bad = $(if ($Row.Basis -eq 'configured') { 'fail' } else { 'warn' })
        $note = $(if ($Row.Basis -eq 'configured') { '' } else { ' (an ISP or service-assigned cache may not answer the Enterprise verification request)' })
        if ($vs -ge 100) { $httpStatus = $vs }
        $ev.Add(('verify GET {0} type={1} length={2}' -f $(if ($vs -ge 100) { $vs } else { 'none' }), $(if ($vt) { $vt } else { '(none)' }), $(if ($null -ne $vl) { $vl } else { '(none)' })))
        if ($vs -eq 200 -and $vt -eq 'text/html') {
            $stage['http'] = $bad; & $fail 'mcc-not-content' 'The cache answered the verification request with a web page (text/html)'
            $why.Add("The verification request was answered with a web page, not content: a captive portal, a proxy block page or a misconfigured cache$note (DO-NET-024)")
        } elseif ($vs -eq 200 -and $vt -and $vt -ne 'application/octet-stream') {
            $stage['http'] = 'warn'; & $fail 'mcc-unexpected-type' "The cache answered the verification request with Content-Type $vt, not application/octet-stream"
            $why.Add("The verification request returned Content-Type $vt, not application/octet-stream$note")
        } elseif ($vs -eq 200 -and $null -ne $vl -and $vl -ne $script:DDMccVerifyLength) {
            $stage['http'] = 'warn'; & $fail 'mcc-size-mismatch' ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "The verification object is {0:N0} bytes, not the {1:N0} Microsoft's troubleshooter expects", $vl, $script:DDMccVerifyLength))
            $why.Add([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "The verification object came back as {0:N0} bytes, not {1:N0}: a different object, or a truncated one", $vl, $script:DDMccVerifyLength))
        } elseif ($vs -eq 200) {
            $stage['http'] = 'pass'
            $why.Add(("Answered Microsoft's verification request (HTTP 200, {0}, {1})" -f $(if ($vt) { $vt } else { 'no Content-Type' }), $(if ($null -ne $vl) { [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0:N0} bytes', $vl) } else { 'length not stated' })))
        } elseif ($vs -ge 300 -and $vs -lt 400) {
            $stage['http'] = $bad; & $fail 'mcc-not-content' "The verification request was redirected (HTTP $vs)"
            $why.Add("The verification request was redirected (HTTP $vs): a captive portal or a proxy sign-in page$note (DO-NET-024)")
        } elseif ($vs -gt 0) { $stage['http'] = $bad; & $fail 'http-status' "The cache answered the verification request with HTTP $vs"; $why.Add("The verification request returned HTTP $vs$note") }
        else { $stage['http'] = $bad; & $fail 'http-no-response' "No answer to the verification request: $((Get-DDProp $Outcome 'VerifyError'))"; $why.Add("No answer to the verification request$note") }
    } elseif ($isMcc) {
        if ($Outcome.RangeAttempted) {
            $st = [int]$Outcome.RangeStatus
            if ($st -ge 100) { $httpStatus = $st }
            # Microsoft documents the verification request for Connected Cache for Enterprise and Education nodes. A cache
            # this device was handed but nobody configured (an ISP's, assigned by the DO service) need not answer it.
            $bad = $(if ($Row.Basis -eq 'configured') { 'fail' } else { 'warn' })
            $note = $(if ($Row.Basis -eq 'configured') { '' } else { ' (an ISP or service-assigned cache may not answer the Enterprise verification request)' })
            if ($st -ge 200 -and $st -lt 300) { $stage['http'] = 'pass'; $why.Add("Answered Microsoft's verification request (HTTP $st)") }
            elseif ($st -gt 0) { $stage['http'] = $bad; & $fail 'http-status' "The cache answered the verification request with HTTP $st"; $why.Add("The verification request returned HTTP $st$note") }
            else { $stage['http'] = $bad; & $fail 'http-no-response' "No answer to the verification request: $($Outcome.RangeError)"; $why.Add("No answer to the verification request$note") }
        }
    } elseif (-not $e['http']) { $stage['http'] = $na }
    elseif ($Outcome.HttpAttempted) {
        $st = [int]$Outcome.HttpStatus
        if ($st -lt 0) { $st = - $st }
        $httpStatus = $(if ($st -ge 100) { $st } else { $null })
        if ($st -eq 407) { $stage['http'] = 'fail'; & $fail 'proxy-auth-required' 'The proxy requires authentication (407); DoSvc as NetworkService may not satisfy it'; $why.Add('HTTP: the proxy requires authentication (407)') }
        elseif ($proxied -and ($st -eq 403 -or $st -ge 500)) { $stage['http'] = 'warn'; & $fail 'proxy-refused' "The proxy answered HTTP $st"; $why.Add("HTTP: the proxy answered $st, which may be a block page") }
        elseif ($st -ge 100) { $stage['http'] = 'pass'; $why.Add("HTTP answered ($st)") }
        else { $stage['http'] = 'fail'; & $fail 'http-no-response' "No HTTP answer: $($Outcome.HttpError)"; $why.Add("No HTTP answer ($($Outcome.HttpError))") }
        $ev.Add("http HEAD $(if ($st -ge 100) { $st } else { 'none' })$(if ($Outcome.HttpVia) { ' via' })")
    }

    # Byte range
    if (-not $e['range']) { $stage['range'] = $na }
    elseif ($Outcome.RangeAttempted) {
        $st = [int]$Outcome.RangeStatus
        if ($st -lt 0) { $st = - $st }
        if ($st -ge 100) { $httpStatus = $st }
        $where = $(if ($isMcc) { "Microsoft's verification object" } else { 'a file this device downloaded' })
        if ($st -eq 206) {
            # A 206 must describe the range asked for (bytes 0-0) and the whole file's size: DO cannot work out a file's
            # size from a 206 without it (0x80D0201C, "Unable to determine file size from HTTP 206 status code").
            $bad = Test-DDRangeAnswer -ContentRange ([string]$Outcome.ContentRange) -ContentLength (Get-DDProp $Outcome 'RangeContentLength') -ExpectedTotal $(if ($isMcc) { $null } else { Get-DDProp $Row 'RangeSize' })
            if ($bad) {
                $stage['range'] = 'fail'; & $fail 'range-mismatch' "The 206 answer on $where $bad"
                $why.Add("Byte range on $where returned 206, but $bad (DO-NET-004)")
            } else { $stage['range'] = 'pass'; $why.Add("Byte range on $where returned 206 for exactly the bytes asked for") }
        } elseif ($st -eq 200) {
            $stage['range'] = $(if ($isMcc) { 'warn' } else { 'fail' })
            & $fail 'range-ignored' "A Range: bytes=0-0 request on $where was answered 200 with the whole object"
            $why.Add("Byte range on $where was answered 200 with the whole object: something in the path removed or ignored the Range header (DO-NET-004)")
        } elseif ($st -eq 407) {
            $stage['range'] = 'fail'; & $fail 'proxy-auth-required' 'The proxy requires authentication (407)'; $why.Add('Byte range: the proxy requires authentication (407)')
        } elseif ($st -ge 300) {
            $stage['range'] = $nc; $why.Add("Byte range inconclusive: $where is no longer served (HTTP $st)")
        } elseif ($isMcc) {
            $stage['range'] = $nc   # no answer at all is already the HTTP verdict above
        } else {
            $stage['range'] = 'warn'; & $fail 'range-no-response' "No answer to the byte-range request: $($Outcome.RangeError)"; $why.Add("No answer to the byte-range request ($($Outcome.RangeError))")
        }
        $ev.Add(("range {0}{1}{2}" -f $(if ($st -ge 100) { $st } else { 'none' }), $(if ($Outcome.ContentRange) { " Content-Range=$($Outcome.ContentRange)" }), $(if ($Outcome.AcceptRanges) { " Accept-Ranges=$($Outcome.AcceptRanges)" } elseif ($st -eq 200) { ' Accept-Ranges=(absent)' })))
    } elseif ($Row.Basis -ne 'observed' -and -not $isMcc) {
        $stage['range'] = $nc   # byte ranges are requested only for a file this device downloaded
    }
    if ($tcpPorts.Count -gt 0 -and $stage['tcp'] -eq 'fail') { foreach ($k in 'tls', 'http', 'range') { if ($stage[$k] -ne $na -and $stage[$k] -ne 'fail') { $stage[$k] = $nc } } }

    # Proxy comparison
    if ($Outcome.DirectAttempted) {
        $proxyOut['direct'] = $(if ($Outcome.DirectOk) { 'pass' } else { 'fail' })
        $ev.Add("direct tcp:$($Row.PrimaryPort) $(if ($Outcome.DirectOk) { 'ok' } else { 'blocked' })")
    }
    # The proxy model (Resolve-DDProbeProxy) is WinHTTP's for DoSvc with no user signed in when the collector runs as SYSTEM;
    # interactively it is this account's settings, netsh first. The evidence says which.
    $modelled = $(if ($Proxy -and (Get-DDProp $Proxy 'Context') -eq 'user') { "this account's settings, netsh first" } else { 'as DoSvc with no user signed in' })
    if ($Proxy -and $Proxy.Source -eq 'unresolved') {
        $ev.Add("proxy unresolved: $($Proxy.Error); probed direct (assumed)")
        $why.Add('The proxy WinHTTP would use could not be resolved, so the host was probed direct (assumed)')
    }
    elseif ($proxied) { $ev.Add("proxy=$($Proxy.Source) ($modelled)") }
    elseif ($Proxy -and [string]$Proxy.Source -notin 'none', '') { $ev.Add("proxy=$($Proxy.Source), direct for this host ($modelled)") }

    # UDP-only endpoints (Teredo): resolution is all a probe can confirm.
    if ($tcpPorts.Count -eq 0) {
        foreach ($k in 'tcp', 'tls', 'http', 'range') { $stage[$k] = $na }
        if ($stage['dns'] -eq 'pass') { $why.Add("UDP $($Row.PrimaryPort) cannot be confirmed by a connectionless probe") }
    }

    $sev = @{ 'fail' = 3; 'warn' = 2; 'pass' = 1 }
    $worst = 0
    foreach ($k in @($stage.Keys)) { $v = $stage[$k]; if ($sev.ContainsKey($v) -and $sev[$v] -gt $worst) { $worst = $sev[$v] } }
    $result = switch ($worst) { 3 { 'fail' } 2 { 'warn' } 1 { 'pass' } default { 'not-collected' } }
    $detail = ($why -join '; ')
    if ($Row.Basis -eq 'observed') { $detail = "$detail. Host used by this device" } elseif ($Row.Basis -eq 'configured') { $detail = "$detail. Configured cache server" }
    & $finish $result $latency $detail ($ev -join '; ') $code $msg
}

function Test-DDRangeAnswer {
    <#
    .SYNOPSIS
        What is wrong with a 206 answer to "Range: bytes=0-0", in words, or $null when it is right: Content-Range must be
        "bytes 0-0/<total>" with a total above zero (and equal to -ExpectedTotal, the size DO reported for the file, when
        known), and Content-Length, when sent, must be 1. RFC 9110 section 14.4 defines the header.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $ContentRange, $ContentLength = $null, $ExpectedTotal = $null)
    if (-not $ContentRange) { return 'carries no Content-Range header' }
    $m = [regex]::Match($ContentRange, '^\s*bytes\s+(\d+)-(\d+)/(\d+|\*)\s*$')
    if (-not $m.Success) { return "carries a Content-Range DoctorDO cannot read ('$ContentRange')" }
    if ($m.Groups[1].Value -ne '0' -or $m.Groups[2].Value -ne '0') { return "is for bytes $($m.Groups[1].Value)-$($m.Groups[2].Value), not the 0-0 asked for" }
    if ($m.Groups[3].Value -eq '*') { return 'does not state the file''s total size (Content-Range bytes 0-0/*)' }
    $total = [System.Numerics.BigInteger]::Parse($m.Groups[3].Value)
    if ($total -le [System.Numerics.BigInteger]::Zero) { return 'states a total size of 0' }
    if ($null -ne $ExpectedTotal -and [string]$ExpectedTotal -ne '') {
        $want = ConvertTo-DDBigInt $ExpectedTotal
        if ($want -gt [System.Numerics.BigInteger]::Zero -and $want -ne $total) { return "states a total of $total bytes, not the $want bytes Delivery Optimization reported for the file" }
    }
    if ($null -ne $ContentLength -and [long]$ContentLength -ge 0 -and [long]$ContentLength -ne 1) { return "has a Content-Length of $ContentLength for a one-byte range" }
    $null
}

function Read-DDEndpointCache {
    [CmdletBinding()]
    param([string] $Path, [Parameter(Mandatory)][string] $Signature, [Parameter(Mandatory)][datetime] $Now, [int] $MaxAgeMinutes)
    if (-not $Path -or $MaxAgeMinutes -le 0 -or -not (Test-Path -LiteralPath $Path)) { return $null }
    # Only from a folder the collector can trust (Test-DDTrustedDirectory): its rows are reported, and signed, as this device's results.
    if (Test-DDTrustedDirectory -Raw (Get-DDDirectorySecurityRaw -Path (Split-Path -Path $Path -Parent))) { return $null }
    try {
        $c = Read-DDJsonFile -Path $Path
        if ($c -isnot [System.Collections.IDictionary] -or $c['version'] -ne $script:DDEndpointCacheVersion -or $c['signature'] -ne $Signature) { return $null }
        $at = [datetime]::MinValue
        if (-not [datetime]::TryParse([string]$c['at'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$at)) { return $null }
        if (($Now - $at).TotalMinutes -gt $MaxAgeMinutes -or $at -gt $Now.AddMinutes(5)) { return $null }
        $rows = @($c['results'] | Where-Object { $_ -is [System.Collections.IDictionary] -and ([string]$_['checkId']).StartsWith('ep:') })
        foreach ($r in $rows) { if ($r['endpoint'] -is [System.Collections.IDictionary]) { $r['endpoint']['cached'] = $true } }
        , $rows
    } catch { $null }
}

function Save-DDEndpointCache {
    [CmdletBinding()]
    param([string] $Path, [Parameter(Mandatory)][string] $Signature, [Parameter(Mandatory)][string] $At, [Parameter(Mandatory)][AllowEmptyCollection()] $Results)
    if (-not $Path) { return }
    try {
        $unsafe = Initialize-DDStateDirectory -Path (Split-Path -Path $Path -Parent)
        if ($unsafe) { Write-Verbose "endpoint cache not saved: the folder is not safe to use ($unsafe)"; return }
        $json = ConvertTo-DDCanonicalJson -InputObject ([ordered]@{ version = $script:DDEndpointCacheVersion; at = $At; signature = $Signature; results = @($Results) })
        $tmp = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N').Substring(0, 8))
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) } else { [System.IO.File]::Move($tmp, $Path) }
    } catch { Write-Verbose "endpoint cache not saved: $($_.Exception.Message)" }
}

function Get-DDEndpointHealth {
    <#
    .SYNOPSIS
        Test the manifest's endpoints from this device and return ConnectivityResults (checkId ep:<id>), at most 40.
    .PARAMETER CachePath
        Where results are kept between runs; reused while younger than -MaxAgeMinutes and the plan, subnet and VPN state
        are unchanged. No path means always probe (the interactive Test-DOConnectivity and device report paths).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        $ModeNum,
        [AllowEmptyCollection()] $StatusRaw = @(),
        [AllowEmptyCollection()] $LogEntries = @(),
        [AllowEmptyCollection()][string[]] $ConfiguredCacheHosts = @(),
        [AllowEmptyCollection()][string[]] $UsedCacheHosts = @(),
        $Network,
        [string] $RangeProbeUri,
        [switch] $SkipProbes,
        [string] $CachePath,
        [int] $MaxAgeMinutes = 360,
        [int] $ProbeTimeoutMs = 4000,
        [int] $TotalTimeoutMs = 40000,
        [datetime] $Now = (Get-DDNowUtc)
    )
    $manifest = Get-DDEndpointManifest
    $observed = Get-DDObservedEndpointUse -Manifest $manifest -StatusRaw $StatusRaw -LogEntries $LogEntries -RangeProbeUri $RangeProbeUri
    $plan = [object[]](Get-DDEndpointPlan -Manifest $manifest -Observed $observed -ModeNum $ModeNum -ConfiguredCacheHosts $ConfiguredCacheHosts -UsedCacheHosts $UsedCacheHosts)
    $at = Format-DDIso -Value $Now
    $probeIdx = @(for ($i = 0; $i -lt $plan.Count; $i++) { if ($plan[$i].Basis -notin 'not-testable', 'not-applicable') { $i } })
    $probeRows = @($probeIdx | ForEach-Object { $plan[$_] })

    $results = New-Object 'System.Collections.Generic.List[object]'
    if ($SkipProbes) {
        foreach ($r in $plan) { $results.Add((ConvertTo-DDEndpointResult -Row $r -Outcome $null -Proxy $null -Context $Context -At $at)) }
        return , @($results.ToArray() | Select-Object -First 40)
    }

    $subnet = $(if ($Network) { [string]$Network['localSubnet'] } else { '' })
    $vpn = $(if ($Network) { [string]$Network['isVpnActive'] } else { '' })
    $sigText = (@($plan | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Id, $_.Host, $_.Basis, [bool]$_.RangeUrl }) + "subnet=$subnet" + "vpn=$vpn" + "manifest=$($manifest['verified'])") -join "`n"
    $signature = Get-DDSha256Hex -Text $sigText
    $cached = Read-DDEndpointCache -Path $CachePath -Signature $signature -Now $Now -MaxAgeMinutes $MaxAgeMinutes
    if ($null -ne $cached -and @($cached).Count -gt 0) { return , @(@($cached) | Select-Object -First 40) }

    $proxies = Invoke-DDStep -Context $Context -Field 'connectivity.proxyResolution' -Script { Resolve-DDProbeProxy -Rows $probeRows } -Default @{}
    $specs = New-Object 'System.Collections.Generic.List[object]'
    foreach ($i in $probeIdx) {
        $r = $plan[$i]
        $px = $(if ($proxies -and $proxies.ContainsKey($r.Host)) { $proxies[$r.Host] } else { $null })
        $isMcc = ($r.Entry['scope'] -eq 'configured')
        $specs.Add([pscustomobject]@{
                Tag = "row:$i"; Host = $r.Host; Ports = $r.Ports; Protocols = $r.Protocols
                Tls = (@($r.Protocols) -contains 'https'); Http = ([bool]$r.Entry['http'] -and -not $isMcc)
                RangeUrl = $r.RangeUrl; RangeSize = $r.RangeSize; VerifyUrl = $(if ($isMcc) { $r.RangeUrl } else { $null })
                Proxy = $(if ($px -and $px.Proxy -and -not $isMcc) { $px.Proxy } else { $null })
                WantAddresses = ($r.Entry['service'] -in $script:DDEndpointAddressServices)
            })
    }
    $outcomes = @{}
    if ($specs.Count -gt 0) {
        $res = @(Invoke-DDStep -Context $Context -Field 'connectivity.endpoints' -Script { Invoke-DDEndpointProbeBatch -Specs $specs.ToArray() -ProbeTimeoutMs $ProbeTimeoutMs -TotalTimeoutMs $TotalTimeoutMs } -Default @())
        foreach ($o in $res) { $outcomes[[string]$o.Tag] = $o }
    }
    for ($i = 0; $i -lt $plan.Count; $i++) {
        $r = $plan[$i]
        $o = $null; $px = $null
        if ($probeIdx -contains $i) {
            $tag = "row:$i"
            if ($outcomes.ContainsKey($tag)) { $o = $outcomes[$tag] } else { $o = [pscustomobject]@{ TimedOut = $true } }
            if ($proxies -and $proxies.ContainsKey($r.Host) -and $r.Entry['scope'] -ne 'configured') { $px = $proxies[$r.Host] }
        }
        $results.Add((ConvertTo-DDEndpointResult -Row $r -Outcome $o -Proxy $px -Context $Context -At $at))
    }
    $out = @($results.ToArray() | Select-Object -First 40)
    if ($outcomes.Count -gt 0) { Save-DDEndpointCache -Path $CachePath -Signature $signature -At $at -Results $out }
    , $out
}
