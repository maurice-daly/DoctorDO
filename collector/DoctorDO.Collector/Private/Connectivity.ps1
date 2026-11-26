#Requires -Version 5.1
# Connectivity matrix (docs/07-connectivity-validation.md, endpoints from docs/17-network-requirements.md).
#
#  * One engine: network probes are batched through Invoke-DDNetProbeBatch (5 s per probe, 60 s total, parallel),
#    local checks are computed from facts already collected. Test-DOConnectivity and the inventory/telemetry
#    paths all call Get-DDConnectivityMatrix.
#  * Results: pass | fail | warn | not-applicable | not-collected. A check that was not run is `not-collected`,
#    never a pass. Applicability is computed from the device's actual download mode.
#  * Network targets come from endpoint health (Endpoints.ps1, Data/endpoints.json): the cloud, content, Teredo and
#    Connected Cache checks below are read from those results, so each host is probed once, on a host the device used
#    or one Microsoft documents, never a guessed one. Only the peer checks probe here.

Set-StrictMode -Version Latest

$script:DDTeredoHost = 'win1910.ipv6.microsoft.com'               # documented (CFG #firewall); also manifest entry teredo-do

function New-DDCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $CheckId,
        [string] $Target = '',
        [ValidateSet('dns', 'tcp', 'http', 'https', 'udp', 'local')][string] $Protocol = 'local',
        $Port = $null,
        [Parameter(Mandatory)][ValidateSet('pass', 'fail', 'warn', 'not-applicable', 'not-collected')][string] $Result,
        $LatencyMs = $null,
        [Parameter(Mandatory)][string] $Detail,
        [string] $Evidence
    )
    $o = [ordered]@{ checkId = $CheckId; target = $Target; protocol = $Protocol; port = $Port; result = $Result; latencyMs = $LatencyMs; detail = $Detail }
    if ($Evidence) {
        $e = Protect-DDLogText -Text $Evidence
        $o['evidence'] = $e.Substring(0, [math]::Min(512, $e.Length))
    }
    $o
}

function Get-DDEffectiveValue {
    [CmdletBinding()]
    param($Effective, [Parameter(Mandatory)][string] $Name)
    if ($null -ne $Effective -and $Effective.Contains($Name)) { return $Effective[$Name]['value'] }
    $null
}

# NetTeredoConfiguration.Type in the NetworkTransition module (MSFT_NetTeredoConfiguration.cdxml).
$script:DDTeredoTypes = @{ 0 = 'default'; 1 = 'relay'; 2 = 'client'; 3 = 'server'; 4 = 'disabled'; 5 = 'automatic'; 6 = 'enterpriseclient'; 7 = 'natawareclient' }

function ConvertTo-DDTeredoWord {
    # One Teredo state or error word, lower case: "probe(primary server)" -> probe, "Qualified" -> qualified; none -> $null.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $w = ([regex]::Match($Text.Trim(), '^[A-Za-z_-]+')).Value.ToLowerInvariant()
    if (-not $w -or $w -eq 'none') { return $null }
    $w
}

function ConvertFrom-DDTeredoState {
    <#
    .SYNOPSIS
        Teredo facts from `netsh interface teredo show state` (English output only): @{ Type; State; Error; ServerName;
        Source = 'netsh' }, or $null when the text has no Type line. State is the operational state (qualified, dormant,
        probe, offline), not the configured Type; $null when the text has no State line.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]] $Lines)
    $text = @($Lines) -join "`n"
    $line = { param($name) $m = [regex]::Match($text, "(?im)^\s*$name\s*:\s*(.*?)\s*$"); if ($m.Success) { $m.Groups[1].Value } else { $null } }
    $type = & $line 'Type'
    if (-not $type) { return $null }
    $state = & $line 'State'; $err = & $line 'Error'; $server = & $line 'Server Name'
    $errText = $(if ($err -and $err.Trim() -ne 'none') { $err.Trim() } else { $null })
    [pscustomobject]@{ Type = ([regex]::Match($type, '^\S+')).Value.ToLowerInvariant(); State = (ConvertTo-DDTeredoWord $state); Error = $errText
        ServerName = $(if ($server) { $server.Trim().TrimEnd('.').ToLowerInvariant() } else { $null }); Source = 'netsh' }
}

function ConvertFrom-DDTeredoRaw {
    # Teredo facts from the Teredo classes (Get-DDTeredoStateRaw), shaped as ConvertFrom-DDTeredoState's. No state object is
    # Microsoft's "Teredo is not active": State 'inactive'.
    [CmdletBinding()]
    param($Raw)
    if ($null -eq $Raw) { return $null }
    $type = $null
    if ($null -ne $Raw.Type) { $n = 0; if ([int]::TryParse([string]$Raw.Type, [ref]$n) -and $script:DDTeredoTypes.ContainsKey($n)) { $type = $script:DDTeredoTypes[$n] } else { $type = ([string]$Raw.Type).ToLowerInvariant() } }
    $state = $(if ($Raw.StatePresent) { ConvertTo-DDTeredoWord ([string]$Raw.State) } else { 'inactive' })
    $err = $(if ($Raw.StatePresent -and $Raw.Error -and ([string]$Raw.Error).Trim() -ne 'none') { ([string]$Raw.Error).Trim() } else { $null })
    $server = Get-DDProp $Raw 'ServerName'
    [pscustomobject]@{ Type = $type; State = $state; Error = $err; ServerName = $(if ($server) { ([string]$server).Trim().TrimEnd('.').ToLowerInvariant() } else { $null }); Source = 'cim' }
}

function Get-DDTeredoFacts {
    # The Teredo classes first (language independent), netsh when they cannot be read. $null, with notCollected, when
    # neither can.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context)
    $cim = $null
    try { $cim = ConvertFrom-DDTeredoRaw -Raw (Get-DDTeredoStateRaw) } catch { Write-Verbose "Teredo classes not read ($($_.Exception.GetType().Name)); trying netsh" }
    if ($null -ne $cim -and $cim.Type) { return $cim }
    Invoke-DDStep -Context $Context -Field 'connectivity.teredo-state' -Script {
        $t = ConvertFrom-DDTeredoState -Lines (Get-DDTeredoStateText)
        if ($null -eq $t) { throw [System.FormatException]::new('netsh interface teredo show state gave no Type line (its output is read in English only)') }
        $t
    }
}

# The matrix is capped (the inventory schema allows 128 results): 88 checks plus up to 40 endpoint-health rows
# (MAX_ENDPOINT_RESULTS in packages/schema).
$script:DDMaxMatrixChecks = 88
$script:DDMaxEndpointRows = 40

function Select-DDMatrixRows {
    <#
    .SYNOPSIS
        At most -Max of the checks, none of the one-per-check results lost to the per-host rows (docs/27 3.3). Priority order:
        the first row of every checkId (health, local and prerequisite checks, and one row per per-host group) in matrix order,
        then the further per-host rows (more peers, content hosts, cache hosts) in matrix order until the cap. The result keeps
        matrix order. Dropped is how many rows did not fit. Pure.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Checks = @(), [int] $Max = $script:DDMaxMatrixChecks)

    $all = @($Checks)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $primary = New-Object 'System.Collections.Generic.List[int]'
    $extra = New-Object 'System.Collections.Generic.List[int]'
    for ($i = 0; $i -lt $all.Count; $i++) {
        if ($seen.Add([string]$all[$i]['checkId'])) { $primary.Add($i) } else { $extra.Add($i) }
    }
    $take = New-Object 'System.Collections.Generic.List[int]'
    foreach ($i in $primary) { if ($take.Count -lt $Max) { $take.Add($i) } }
    foreach ($i in $extra) { if ($take.Count -lt $Max) { $take.Add($i) } }
    $take.Sort()
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($i in $take) { $rows.Add($all[$i]) }
    [pscustomobject]@{ Rows = $rows.ToArray(); Dropped = ($all.Count - $rows.Count) }
}

function Get-DDConnectivityMatrix {
    <#
    .SYNOPSIS
        Build the full connectivity matrix from probes and local facts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        $DoEffective,
        $Network,
        [AllowEmptyCollection()] $FirewallRules = @(),
        [AllowEmptyCollection()] $ObservedStatus = @(),
        [AllowEmptyCollection()][string[]] $PeerAddresses = @(),
        $DoSvc,
        $RamGB,
        # Capacity of the drive the DO cache is on, in GB (the system drive when the cache drive's size is unknown), and that
        # drive's name for the text. The disk-size check follows the cache drive (docs/27 3.2).
        [Alias('SystemDiskGB')] $DiskGB,
        [string] $DiskDrive = '',
        $Vitals,
        [AllowEmptyCollection()] $EndpointResults = @(),
        $FirewallProfiles,
        [switch] $SkipProbes,
        [int] $ProbeTimeoutMs = 5000,
        [int] $TotalTimeoutMs = 60000,
        # Delivery Optimization health (Health.ps1): the DO geo answer, the cache server DO will use, the DHCP facts, the
        # cache folder, whether DoSvc itself listens on TCP 7680 ($null: not read), the active power plan.
        $GeoAnswer, $CacheResolution, $Dhcp, $CacheFolder, $DoSvcListening = $null, [string] $PowerPlan,
        # Whether DoSvc's own TCP table holds an established peer connection (TCP 7680 at either end); $null: not read.
        $DoSvcPeerConnection = $null
    )

    $checks = New-Object 'System.Collections.Generic.List[object]'
    $mode = Get-DDEffectiveValue -Effective $DoEffective -Name 'DODownloadMode'
    $modeNum = $null; if ($null -ne $mode) { $n = 0; if ([int]::TryParse([string]$mode, [ref]$n)) { $modeNum = $n } }
    $peeringOff = ($null -ne $modeNum -and $modeNum -in 0, 99, 100)
    $peering = ($null -ne $modeNum -and $modeNum -in 1, 2, 3)
    $modeText = $(if ($null -ne $modeNum) { "DODownloadMode=$modeNum" } else { 'DODownloadMode not determined' })
    $skipDetail = 'skipped by -SkipConnectivityChecks'

    # ---- network probes --------------------------------------------------------------------------------------
    $specs = New-Object 'System.Collections.Generic.List[object]'
    $addSpec = { param($kind, $target, $port, $tag) $specs.Add([pscustomobject]@{ Kind = $kind; Target = $target; Port = $port; Tag = $tag }) }
    $cacheHost = [string](Get-DDEffectiveValue -Effective $DoEffective -Name 'DOCacheHost')
    $cacheHosts = @()
    if ($cacheHost) { $cacheHosts = @($cacheHost.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() } | Select-Object -First 2) }
    $peers = @($PeerAddresses | Select-Object -First 3)
    if (-not $SkipProbes -and $peering) { for ($i = 0; $i -lt $peers.Count; $i++) { & $addSpec 'tcp' $peers[$i] 7680 "peer:$i" } }
    $out = @{}
    $peerProbeFailed = $false
    if ($specs.Count -gt 0) {
        # Inside a step like every other native entry point: where run-time compilation is refused (Constrained Language
        # Mode, application control) the peer probes are not collected and the rest of the matrix still runs.
        $res = @(Invoke-DDStep -Context $Context -Field 'connectivity.peers' -Default @() -Script { Invoke-DDNetProbeBatch -Specs $specs.ToArray() -ProbeTimeoutMs $ProbeTimeoutMs -TotalTimeoutMs $TotalTimeoutMs })
        $peerProbeFailed = $Context.NotCollected.Exists([Predicate[object]] { param($e) $e['field'] -eq 'connectivity.peers' })
        foreach ($r in $res) { $out[[string]$r.Tag] = $r }
    }
    $probe = { param($tag) if ($out.ContainsKey($tag)) { $out[$tag] } else { $null } }
    $fromProbe = {
        param($r, $okDetail, $failPrefix)
        if ($null -eq $r -and $peerProbeFailed) { return @{ Result = 'not-collected'; Detail = 'The peer probe could not run on this device (see notCollected: connectivity.peers)'; Ms = $null } }
        if ($null -eq $r) { return @{ Result = 'not-collected'; Detail = $skipDetail; Ms = $null } }
        if ($r.Ok) { return @{ Result = 'pass'; Detail = $okDetail; Ms = [double]$r.Ms } }
        if ($r.TimedOut) { return @{ Result = 'fail'; Detail = "$failPrefix timed out after $ProbeTimeoutMs ms (black-holed or filtered)"; Ms = [double]$r.Ms } }
        @{ Result = 'fail'; Detail = "$failPrefix failed: $($r.Error)"; Ms = [double]$r.Ms }
    }

    # ---- cloud service, content and metadata: read from endpoint health ----------------------------------------
    $ep = @($EndpointResults | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['endpoint'] })
    $rowsOf = { param([string] $id) @($ep | Where-Object { $_['endpoint']['id'] -eq $id -and $_['endpoint']['basis'] -notin 'not-testable', 'not-applicable' }) }
    $noEp = $(if ($SkipProbes) { $skipDetail } else { 'endpoint health did not run' })
    # The handshake completed even when the certificate was then judged (inspection, untrusted chain, wrong name).
    $handshake = { param($r) $r['endpoint']['tls'] -eq 'pass' -or ($r['endpoint']['err'] -and [string]$r['endpoint']['err']['code'] -like 'tls-*' -and [string]$r['endpoint']['err']['code'] -ne 'tls-failed') }
    $errText = { param($r, $fallback) if ($r['endpoint']['err']) { [string]$r['endpoint']['err']['message'] } else { $fallback } }

    $cloud = @(& $rowsOf 'do-cloud')
    $geo = @(@($cloud | Where-Object { $_['endpoint']['basis'] -eq 'documented' }) + @($cloud)) | Select-Object -First 1
    $cloudTarget = $(if ($geo) { [string]$geo['target'] } else { 'geo.prod.do.dsp.mp.microsoft.com' })
    if (-not $geo -or $geo['endpoint']['dns'] -eq 'not-collected') { $checks.Add((New-DDCheck -CheckId 'do-cloud-dns' -Target $cloudTarget -Protocol dns -Result 'not-collected' -Detail $noEp)) }
    elseif ($geo['endpoint']['dns'] -eq 'fail') { $checks.Add((New-DDCheck -CheckId 'do-cloud-dns' -Target $cloudTarget -Protocol dns -Result 'fail' -Detail (& $errText $geo 'DNS resolution failed'))) }
    else { $checks.Add((New-DDCheck -CheckId 'do-cloud-dns' -Target $cloudTarget -Protocol dns -Result 'pass' -Detail "Resolved ($((@($geo['endpoint']['dnsTypes']) -join ', ')))")) }

    if (-not $geo -or $geo['endpoint']['tcp'] -eq 'not-collected') { $checks.Add((New-DDCheck -CheckId 'do-cloud-tls' -Target $cloudTarget -Protocol https -Port 443 -Result 'not-collected' -Detail $(if ($geo -and $geo['endpoint']['dns'] -eq 'fail') { 'Not attempted: the name does not resolve' } else { $noEp }))) }
    elseif ($geo['endpoint']['tcp'] -eq 'fail') { $checks.Add((New-DDCheck -CheckId 'do-cloud-tls' -Target $cloudTarget -Protocol https -Port 443 -Result 'fail' -LatencyMs $geo['latencyMs'] -Detail ((& $errText $geo 'TCP 443 connect failed') + ' (DO-NET-001)'))) }
    elseif (& $handshake $geo) { $checks.Add((New-DDCheck -CheckId 'do-cloud-tls' -Target $cloudTarget -Protocol https -Port 443 -Result 'pass' -LatencyMs $geo['latencyMs'] -Detail 'TLS handshake succeeded')) }
    else { $checks.Add((New-DDCheck -CheckId 'do-cloud-tls' -Target $cloudTarget -Protocol https -Port 443 -Result 'fail' -LatencyMs $geo['latencyMs'] -Detail ((& $errText $geo 'TLS handshake failed') + ' (DO-NET-001)'))) }

    $inspect = {
        param($id, $r)
        $h = [string]$r['target']
        $c = $r['endpoint']['cert']
        if ($null -eq $c) { return New-DDCheck -CheckId $id -Target $h -Protocol https -Port 443 -Result 'not-collected' -Detail 'TLS handshake did not complete, issuer not observed' }
        if ($c['issuer'] -eq 'microsoft') { return New-DDCheck -CheckId $id -Target $h -Protocol https -Port 443 -Result 'pass' -LatencyMs $r['latencyMs'] -Detail 'Certificate issued by a Microsoft CA' }
        $who = $(if ($c['issuerCn']) { "'$($c['issuerCn'])'" } else { 'a certificate authority that is not Microsoft' })
        New-DDCheck -CheckId $id -Target $h -Protocol https -Port 443 -Result 'fail' -LatencyMs $r['latencyMs'] -Detail "Certificate issued by $who, not Microsoft: TLS inspection on a pinned DO endpoint (DO-NET-006); there is no workaround" -Evidence ("issuer=$($c['issuer'])" + $(if ($c['issuerCn']) { "; issuerCn=$($c['issuerCn'])" }))
    }
    if ($geo) { $checks.Add((& $inspect 'do-cloud-inspect' $geo)) } else { $checks.Add((New-DDCheck -CheckId 'do-cloud-inspect' -Target $cloudTarget -Protocol https -Port 443 -Result 'not-collected' -Detail $noEp)) }
    $pinnedRows = @(@($cloud) + @(& $rowsOf 'do-array') | Where-Object { $_['endpoint']['tcp'] -eq 'pass' })
    if ($pinnedRows.Count -eq 0) { $checks.Add((New-DDCheck -CheckId 'proxy-tls-inspection' -Target $cloudTarget -Protocol https -Port 443 -Result 'not-collected' -Detail $(if ($geo) { 'No pinned DO endpoint completed a connection, so no certificate was observed' } else { $noEp }))) }
    foreach ($r in $pinnedRows) { $checks.Add((& $inspect 'proxy-tls-inspection' $r)) }

    $tcpCheck = {
        param($checkId, $r, $suffix)
        $port = $r['port']
        $x = $r['endpoint']['tcp']
        $res = $(if ($x -eq 'pass') { 'pass' } elseif ($x -eq 'fail') { 'fail' } else { 'not-collected' })
        # Through a proxy, an HTTP port's connection reaches only the proxy (an HTTPS one is a CONNECT the proxy completed).
        $via = $r['endpoint']['proxy'] -and $r['endpoint']['proxy']['used']
        $ok = $(if (-not $via) { "TCP $port connected" } elseif ($r['protocol'] -eq 'https') { "TCP $port connected through the proxy" } else { "TCP $port`: the proxy is reachable; the HTTP check shows whether it reaches the host" })
        $d = $(if ($res -eq 'pass') { $ok } elseif ($res -eq 'fail') { & $errText $r "TCP $port connect failed" } elseif ($r['endpoint']['dns'] -eq 'fail') { 'Not attempted: the name does not resolve' } else { $noEp })
        New-DDCheck -CheckId $checkId -Target ([string]$r['target']) -Protocol tcp -Port $port -Result $res -LatencyMs $r['latencyMs'] -Detail "$d$suffix"
    }
    $content = @(& $rowsOf 'do-content')
    if ($content.Count -eq 0) { $checks.Add((New-DDCheck -CheckId 'do-content-cdn' -Target '' -Protocol tcp -Port 80 -Result 'not-collected' -Detail $noEp)) }
    foreach ($r in $content) { $checks.Add((& $tcpCheck 'do-content-cdn' $r '')) }
    $wu = @(& $rowsOf 'wu-content')
    if ($wu.Count -eq 0) { $checks.Add((New-DDCheck -CheckId 'do-metadata-wu' -Target '' -Protocol tcp -Port 80 -Result 'not-collected' -Detail $noEp)) }
    foreach ($r in $wu) { $checks.Add((& $tcpCheck 'do-metadata-wu' $r '')) }

    $ranged = @($ep | Where-Object { $_['endpoint']['range'] -in 'pass', 'fail', 'warn' -and $_['endpoint']['id'] -ne 'mcc' })
    if ($ranged.Count -eq 0) {
        $why = $(if ($SkipProbes) { $skipDetail } elseif (@($ObservedStatus).Count -eq 0) { 'No file in the DO job list to test: byte ranges are only requested for a file this device downloaded' } else { 'No file this device downloaded could be tested (none still served, or none on a Microsoft content host)' })
        $checks.Add((New-DDCheck -CheckId 'do-range-support' -Target '' -Protocol http -Result 'not-collected' -Detail $why))
    }
    foreach ($r in $ranged) {
        $x = $r['endpoint']['range']
        $code = $(if ($r['endpoint']['err']) { [string]$r['endpoint']['err']['code'] } else { $null })
        $d = $(if ($x -eq 'pass') { 'Range request on a file this device downloaded returned 206 Partial Content, with a Content-Range for exactly the bytes asked for' }
            elseif ($x -eq 'fail' -and $code -eq 'range-mismatch') { (& $errText $r 'The 206 answer did not describe the range asked for') + ' (DO-NET-004)' }
            elseif ($x -eq 'fail') { 'No 206: the Range request was answered with the whole object; byte ranges are stripped or ignored in the path (DO-NET-004)' }
            else { & $errText $r 'No answer to the byte-range request' })
        $ev = $(if ($r.Contains('evidence')) { [string]$r['evidence'] } else { $null })
        $c = New-DDCheck -CheckId 'do-range-support' -Target ([string]$r['target']) -Protocol http -Port $r['port'] -Result $x -LatencyMs $r['latencyMs'] -Detail $d -Evidence $ev
        if ($code -in 'range-ignored', 'range-mismatch') { $c['code'] = $code }
        $checks.Add($c)
    }

    $byCaller = @($ep | Where-Object { $_['endpoint']['id'] -in 'office-cdn', 'office-cdn-net', 'm365-static', 'intune-win32', 'xbox' -and $_['endpoint']['basis'] -ne 'not-applicable' })
    if ($byCaller.Count -eq 0) { $checks.Add((New-DDCheck -CheckId 'do-content-by-caller' -Protocol tcp -Result 'not-applicable' -Detail 'no content types beyond Windows Update observed in the current DO jobs')) }
    foreach ($r in $byCaller) {
        $label = [string](@((Get-DDEndpointManifest)['endpoints']) | Where-Object { $_['id'] -eq $r['endpoint']['id'] } | Select-Object -First 1)['label']
        if ($r['endpoint']['basis'] -eq 'not-testable') { $checks.Add((New-DDCheck -CheckId 'do-content-by-caller' -Protocol tcp -Port $r['port'] -Result 'not-collected' -Detail "Not testable: wildcard, no observed host (content type: $label)")); continue }
        $checks.Add((& $tcpCheck 'do-content-by-caller' $r " (content type: $label)"))
    }

    # ---- peer to peer --------------------------------------------------------------------------------------------
    # Who listens on 7680: DoSvc's own TCP table when it was read (the collector reads it for the endpoint rows), else any
    # process's listener (the earlier source, which cannot tell DoSvc from another program on the port).
    $listening = $false
    $byDoSvc = $null -ne $DoSvcListening
    if ($byDoSvc) { $listening = [bool]$DoSvcListening }
    else {
        $ports = @(Invoke-DDStep -Context $Context -Field 'connectivity.p2p-listener' -Script { Get-DDListeningTcpPorts } -Default @())
        $listening = $ports -contains 7680
    }
    $listenKnown = $byDoSvc -or -not $Context.NotCollected.Exists([Predicate[object]] { param($e) $e['field'] -eq 'connectivity.p2p-listener' })
    $stopped = $null -ne $DoSvc -and [string](Get-DDProp $DoSvc 'Status') -and [string](Get-DDProp $DoSvc 'Status') -ne 'Running'
    $who = $(if ($byDoSvc) { 'DoSvc' } else { 'A process' })
    # A transfer is active while a job is Downloading or DoSvc holds a peer connection (TCP 7680 at either end). A Caching
    # job has finished ("download completed successfully and is ready to upload or uploading", Microsoft) and stays so for
    # days, so it does not by itself mean DoSvc must be listening.
    $statusIs = { param($rx) [bool](@($ObservedStatus) | Where-Object { [string](Get-DDProp $_ 'status') -match $rx } | Select-Object -First 1) }
    $downloading = & $statusIs '^(?i)downloading$'
    $cached = & $statusIs '^(?i)caching$'
    $activeTransfer = $downloading -or ($DoSvcPeerConnection -eq $true)
    # The reasons Microsoft's FAQ gives for not listening that this device's own facts show (battery, VPN, cellular).
    $batteryRead = -not $Context.NotCollected.Exists([Predicate[object]] { param($e) $e['field'] -eq 'vitals.battery' })
    $quiet = New-Object 'System.Collections.Generic.List[string]'
    if ($batteryRead -and $null -ne $Vitals -and $Vitals['onBattery']) { $quiet.Add('it is on battery') }
    if ($null -ne $Network -and $Network['isVpnActive'] -and (Get-DDEffectiveValue -Effective $DoEffective -Name 'DOAllowVPNPeerCaching') -ne 1) { $quiet.Add('a VPN is connected and DOAllowVPNPeerCaching does not allow peering over it') }
    if ($null -ne $Network -and $Network['adapterType'] -eq 'Cellular') { $quiet.Add('it is on a cellular network') }
    $quietText = ($quiet -join '; ')
    $transferText = $(if ($downloading) { 'a job is downloading' } else { 'DoSvc holds a peer connection' })
    if ($peeringOff) { $checks.Add((New-DDCheck -CheckId 'p2p-listener' -Target 'localhost' -Protocol tcp -Port 7680 -Result 'not-applicable' -Detail "Peering is disabled by $modeText")) }
    elseif ($listening) { $checks.Add((New-DDCheck -CheckId 'p2p-listener' -Target 'localhost' -Protocol tcp -Port 7680 -Result 'pass' -Detail "$who is listening on TCP 7680")) }
    elseif ($activeTransfer -and $quiet.Count -gt 0) { $checks.Add((New-DDCheck -CheckId 'p2p-listener' -Target 'localhost' -Protocol tcp -Port 7680 -Result 'warn' -Detail "Not listening although $transferText. Microsoft documents that DoSvc does not listen while $quietText")) }
    elseif ($activeTransfer) { $checks.Add((New-DDCheck -CheckId 'p2p-listener' -Target 'localhost' -Protocol tcp -Port 7680 -Result 'fail' -Detail "Not listening although $transferText, and none of the reasons Microsoft gives for that (battery, VPN, cellular network) applies to this device")) }
    elseif ($stopped) { $checks.Add((New-DDCheck -CheckId 'p2p-listener' -Target 'localhost' -Protocol tcp -Port 7680 -Result 'warn' -Detail 'DoSvc is not running (it stops when idle), so nothing listens on TCP 7680')) }
    elseif ($cached) { $checks.Add((New-DDCheck -CheckId 'p2p-listener' -Target 'localhost' -Protocol tcp -Port 7680 -Result 'warn' -Detail "Not listening. Its jobs are finished and cached ('Caching'), and no download or peer connection is active: DoSvc stops listening when idle$(if ($quiet.Count -gt 0) { ", and while $quietText" })")) }
    else { $checks.Add((New-DDCheck -CheckId 'p2p-listener' -Target 'localhost' -Protocol tcp -Port 7680 -Result 'warn' -Detail 'Not listening. Expected when idle: DoSvc stops listening with no transfers, no cached files, low battery, Connected Standby, cellular or VPN restrictions')) }

    if ($peeringOff) { $checks.Add((New-DDCheck -CheckId 'p2p-outbound' -Protocol tcp -Port 7680 -Result 'not-applicable' -Detail "Peering is disabled by $modeText")) }
    elseif ($peers.Count -eq 0) { $checks.Add((New-DDCheck -CheckId 'p2p-outbound' -Protocol tcp -Port 7680 -Result 'not-applicable' -Detail 'No peers known to this device right now')) }
    else {
        for ($i = 0; $i -lt $peers.Count; $i++) {
            $r = & $probe "peer:$i"; $x = & $fromProbe $r 'TCP 7680 connected' 'TCP 7680 connect'
            $tgt = 'peer:' + (Get-DDShortHash -Value $peers[$i] -Salt $Context.TenantSalt -Domain 'peer')
            $checks.Add((New-DDCheck -CheckId 'p2p-outbound' -Target $tgt -Protocol tcp -Port 7680 -Result $x.Result -LatencyMs $x.Ms -Detail $x.Detail))
        }
    }
    # firewall rules: inbound Allow rules for TCP 7680 found by port as well as by name (Test-DDTcp7680Allow); a rule that
    # is enabled but whose PrimaryStatus is not OK is not in force, and one limited to another program or service does
    # not admit Delivery Optimization. When Windows refused part of the listing, a rule not found is unknown, not absent.
    $rules = @($FirewallRules)
    $fwComplete = Test-DDFirewallRulesComplete -Context $Context
    $tcpAllow = @($rules | Where-Object { (Test-DDTcp7680Allow -Rule $_) -and $_['enabled'] })
    $otherScope = @($rules | Where-Object { $_['enabled'] -and (Test-DDTcp7680Allow -Rule $_ -AnyProgram) -and -not (Test-DDTcp7680Allow -Rule $_) })
    $inForce = @($tcpAllow | Where-Object { $null -eq (Get-DDProp $_ 'primaryStatus') -or (Get-DDProp $_ 'primaryStatus') -eq 'OK' })
    $notInForce = @($tcpAllow | Where-Object { $null -ne (Get-DDProp $_ 'primaryStatus') -and (Get-DDProp $_ 'primaryStatus') -ne 'OK' })
    $blockers = @($rules | Where-Object { $_['direction'] -eq 'Inbound' -and $_['action'] -eq 'Block' -and $_['enabled'] -and $_['displayName'] -notmatch '(?i)Delivery Optimization' -and
            ([string]$_['localPort'] -match '(?i)(^|,)\s*Any\s*(,|$)' -or [string]$_['localPort'] -eq '' -or (Test-DDPortSpec -Spec ([string]$_['localPort']) -Port 7680)) -and [string]$_['protocol'] -match '^(?i)(TCP|6|Any|)$' })
    # A profile whose policy refuses every inbound connection ("block all incoming", AllowInboundRules=False) overrides
    # any allow rule. Only enabled profiles count: a disabled firewall blocks nothing.
    $shields = @(@($FirewallProfiles) | Where-Object { $null -ne $_ -and [string](Get-DDProp $_ 'AllowInboundRules') -eq 'False' -and [string](Get-DDProp $_ 'Enabled') -ne 'False' } | ForEach-Object { [string](Get-DDProp $_ 'Name') })
    $fwCheck = $null
    $profiles = @(@($FirewallProfiles) | Where-Object { $null -ne $_ })
    $allOff = $profiles.Count -gt 0 -and @($profiles | Where-Object { [string](Get-DDProp $_ 'Enabled') -ne 'False' }).Count -eq 0
    if ($peeringOff) { $fwCheck = New-DDCheck -CheckId 'p2p-firewall-rule' -Protocol local -Port 7680 -Result 'not-applicable' -Detail "Peering is disabled by $modeText" }
    elseif ($allOff) { $fwCheck = New-DDCheck -CheckId 'p2p-firewall-rule' -Protocol local -Port 7680 -Result 'pass' -Detail 'Windows Defender Firewall is off on every profile, so it blocks nothing (another firewall may be in its place)'; $fwCheck['code'] = 'firewall-off' }
    elseif ($shields.Count -gt 0) { $fwCheck = New-DDCheck -CheckId 'p2p-firewall-rule' -Protocol local -Port 7680 -Result 'fail' -Detail "Firewall policy blocks all inbound connections on the $($shields -join ', ') profile (AllowInboundRules=False), whatever the Delivery Optimization rules say (DO-NET-010)"; $fwCheck['code'] = 'inbound-shield' }
    elseif ($blockers.Count -gt 0) { $fwCheck = New-DDCheck -CheckId 'p2p-firewall-rule' -Protocol local -Port 7680 -Result 'fail' -Detail "An enabled inbound Block rule could shadow the DO allow rules: '$($blockers[0]['displayName'])' (DO-NET-010)"; $fwCheck['code'] = 'shadowed' }
    elseif ($inForce.Count -eq 0 -and -not $fwComplete) {
        $read = $(if ($notInForce.Count -gt 0) { " The one it could read, '$($notInForce[0]['displayName'])', is enabled but its status is $((Get-DDProp $notInForce[0] 'primaryStatus'))$(Get-DDEnforcementText -Rule $notInForce[0])." } else { ' None of those it could read admits TCP 7680.' })
        $fwCheck = New-DDCheck -CheckId 'p2p-firewall-rule' -Protocol local -Port 7680 -Result 'not-collected' -Detail "Windows refused to list every firewall rule (run it elevated), so whether a rule admits TCP 7680 is not known.$read"
        $fwCheck['code'] = 'rules-unreadable'
    }
    elseif ($inForce.Count -eq 0 -and $notInForce.Count -gt 0) {
        $fwCheck = New-DDCheck -CheckId 'p2p-firewall-rule' -Protocol local -Port 7680 -Result 'fail' -Detail "The inbound Allow rule for TCP 7680 '$($notInForce[0]['displayName'])' is enabled but its status is $((Get-DDProp $notInForce[0] 'primaryStatus')), so it is not in force$(Get-DDEnforcementText -Rule $notInForce[0]) (DO-NET-019)"
        $fwCheck['code'] = 'not-in-force'
    }
    elseif ($inForce.Count -eq 0) {
        $scopeNote = $(if ($otherScope.Count -gt 0) { ". '$($otherScope[0]['displayName'])' names TCP 7680 but admits only $(Get-DDScopeText -Rule $otherScope[0]), not Delivery Optimization (the dosvc service in svchost.exe)" } else { '' })
        $fwCheck = New-DDCheck -CheckId 'p2p-firewall-rule' -Protocol local -Port 7680 -Result 'fail' -Detail "No enabled inbound Allow rule for TCP 7680 found, by name or by port (absent or disabled, DO-NET-010)$scopeNote"; $fwCheck['code'] = 'no-allow'
    }
    else {
        $named = @($inForce | ForEach-Object { "'$($_['displayName'])'" } | Select-Object -First 2) -join ', '
        $partial = $(if (-not $fwComplete) { '. Windows refused to list every rule, so a Block rule could be among those not read' } else { '' })
        $fwCheck = New-DDCheck -CheckId 'p2p-firewall-rule' -Protocol local -Port 7680 -Result 'pass' -Detail "$($inForce.Count) enabled inbound Allow rule(s) admit TCP 7680 ($named), no shadowing Block rule$partial"
    }
    $checks.Add($fwCheck)

    # Inbound from peers, as far as the device can tell: its firewall admits TCP 7680 and DoSvc listens on it. Whether the
    # network between devices lets peers through is not measured here.
    $inb = { param($r, $d, $code) $c = New-DDCheck -CheckId 'p2p-inbound' -Target 'localhost' -Protocol tcp -Port 7680 -Result $r -Detail $d; if ($code) { $c['code'] = $code }; $checks.Add($c) }
    if ($peeringOff) { & $inb 'not-applicable' "Peering is disabled by $modeText" $null }
    elseif ($fwCheck['result'] -eq 'fail') { & $inb 'fail' "Peers cannot connect in: the firewall refuses TCP 7680 on this device (see the firewall rule check)" 'firewall' }
    elseif (-not $listenKnown) { & $inb 'not-collected' 'Cannot be tested from this device alone: a peer has to try to connect to it' $null }
    elseif ($listening -and $fwCheck['result'] -eq 'pass') { & $inb 'pass' "$who is listening on TCP 7680 and the firewall admits it: ready to serve peers. Whether the network between devices lets them in is not measured from the device" 'listening' }
    elseif ($listening) { & $inb 'not-collected' "$who is listening on TCP 7680, but the firewall rules could not be judged" $null }
    elseif ($stopped) { & $inb 'warn' "DoSvc is not running, so it is not listening on TCP 7680 and cannot serve peers now. $($script:DDListenerReasons)" 'not-listening' }
    else { & $inb 'warn' "Not listening on TCP 7680 now, so it cannot serve peers at this moment. $($script:DDListenerReasons)" 'not-listening' }

    $lpm = $null; if ($Network) { $lpm = $Network['localPolicyMergeEnabled'] }
    if ($null -eq $lpm) { $checks.Add((New-DDCheck -CheckId 'local-policy-merge' -Protocol local -Result 'not-collected' -Detail 'LocalPolicyMerge state could not be read')) }
    elseif ($lpm) { $checks.Add((New-DDCheck -CheckId 'local-policy-merge' -Protocol local -Result 'pass' -Detail 'Local firewall rules are merged')) }
    else { $checks.Add((New-DDCheck -CheckId 'local-policy-merge' -Protocol local -Result 'warn' -Detail 'LocalPolicyMerge is disabled: this can stop the DHCP client retrieving option 235, breaking Connected Cache discovery (DO-NET-011)')) }

    # Teredo: the operational State (qualified, dormant, probe, offline; none: not active), not only the configured Type.
    # Microsoft: "If the state is 'offline', Teredo is not active, which prevents the user from connecting to other users
    # via their Teredo addresses"; Windows also keeps it offline on a network with a domain controller.
    if ($modeNum -in 2, 3) {
        $t = Get-DDTeredoFacts -Context $Context
        $qualified = $null -ne $t -and $t.State -eq 'qualified'
        $r = & $rowsOf 'teredo-do' | Select-Object -First 1
        # UDP 3544 cannot be confirmed by a connectionless probe; a qualified Teredo client has reached its server over it.
        if ($null -eq $r -or $r['endpoint']['dns'] -eq 'not-collected') { $checks.Add((New-DDCheck -CheckId 'teredo-endpoint' -Target $script:DDTeredoHost -Protocol udp -Port 3544 -Result 'not-collected' -Detail $noEp)) }
        elseif ($r['endpoint']['dns'] -eq 'pass' -and $qualified -and $t.ServerName -eq $script:DDTeredoHost) { $checks.Add((New-DDCheck -CheckId 'teredo-endpoint' -Target $script:DDTeredoHost -Protocol udp -Port 3544 -Result 'pass' -Detail 'Name resolves, and Teredo is qualified with this server, so UDP 3544 to it works')) }
        elseif ($r['endpoint']['dns'] -eq 'pass') { $checks.Add((New-DDCheck -CheckId 'teredo-endpoint' -Target $script:DDTeredoHost -Protocol udp -Port 3544 -Result 'not-collected' -Detail "Name resolves; whether UDP 3544 reaches it cannot be measured by a connectionless probe$(if ($qualified) { ' (Teredo is qualified with another server)' } else { ', and Teredo is not qualified on this device to show it' })")) }
        else { $checks.Add((New-DDCheck -CheckId 'teredo-endpoint' -Target $script:DDTeredoHost -Protocol udp -Port 3544 -Result 'fail' -Detail "$(& $errText $r 'Name does not resolve') (DO-NET-003)")) }
        $tc = { param($result, $code, $detail) $c = New-DDCheck -CheckId 'teredo-state' -Protocol local -Result $result -Detail $detail -Evidence $(if ($t) { "type=$($t.Type); state=$(if ($t.State) { $t.State } else { '(not reported)' }); error=$(if ($t.Error) { $t.Error } else { 'none' }); source=$($t.Source)" }); if ($code) { $c['code'] = $code }; $checks.Add($c) }
        $typeText = $(if ($t -and $t.Type) { "type $($t.Type)" } else { 'type not reported' })
        $errNote = $(if ($t -and $t.Error) { "; error: $($t.Error)" } else { '' })
        if ($null -eq $t) { & $tc 'not-collected' $null 'The Teredo state could not be read' }
        elseif ($t.Type -eq 'disabled') { & $tc 'fail' 'disabled' 'Teredo is disabled; Group (2) and Internet (3) modes need it to reach peers behind other NATs (DO-NET-003)' }
        elseif ($t.State -eq 'qualified') { & $tc 'pass' 'qualified' "Teredo is qualified ($typeText): it has reached its server over UDP 3544" }
        elseif ($t.State -eq 'dormant') { & $tc 'pass' 'dormant' "Teredo is dormant ($typeText): configured and idle, it qualifies again when it is needed" }
        elseif (-not $t.State) { & $tc 'not-collected' $null "Teredo is configured ($typeText); its state was not reported, so whether it is active is not known" }
        elseif ($t.State -eq 'inactive') { & $tc 'warn' 'inactive' "Teredo is not active ($typeText)$errNote, so peers behind other NATs cannot be reached through it. Windows keeps Teredo offline on a network with a domain controller" }
        else { & $tc 'warn' $(if ($t.State -eq 'offline') { 'offline' } else { 'not-qualified' }) "Teredo is $($t.State) ($typeText)$errNote, so peers behind other NATs cannot be reached through it. Windows keeps Teredo offline on a network with a domain controller" }
    } else {
        $why = "Teredo is only needed for Group or Internet mode ($modeText)"
        $checks.Add((New-DDCheck -CheckId 'teredo-endpoint' -Target $script:DDTeredoHost -Protocol udp -Port 3544 -Result 'not-applicable' -Detail $why))
        $checks.Add((New-DDCheck -CheckId 'teredo-state' -Protocol local -Result 'not-applicable' -Detail $why))
    }

    # ---- Connected Cache -----------------------------------------------------------------------------------------
    # The cache server is infrastructure and is reported in clear, under -Anonymise as well (ADR-0031).
    $tag = { param($h) $h }
    if ($cacheHosts.Count -eq 0) {
        $checks.Add((New-DDCheck -CheckId 'mcc-config' -Protocol local -Result 'not-applicable' -Detail 'No DOCacheHost configured'))
        $checks.Add((New-DDCheck -CheckId 'mcc-reachable' -Protocol tcp -Port 80 -Result 'not-applicable' -Detail 'No DOCacheHost configured'))
        $checks.Add((New-DDCheck -CheckId 'mcc-serving' -Protocol http -Result 'not-applicable' -Detail 'No DOCacheHost configured'))
    } else {
        $checks.Add((New-DDCheck -CheckId 'mcc-config' -Target (& $tag $cacheHosts[0]) -Protocol local -Result 'pass' -Detail "$($cacheHosts.Count) cache host(s) configured"))
        $reach = $false; $verified = $false
        $mccRows = @(& $rowsOf 'mcc')
        foreach ($h in $cacheHosts) {
            $bare = ConvertTo-DDCacheHostName $h
            $r = $mccRows | Where-Object { $_['target'] -eq $bare } | Select-Object -First 1
            if ($null -eq $r) { $checks.Add((New-DDCheck -CheckId 'mcc-reachable' -Target (& $tag $h) -Protocol tcp -Port 80 -Result 'not-collected' -Detail $noEp)); continue }
            $x = & $tcpCheck 'mcc-reachable' $r ''
            if ($x['result'] -eq 'pass') { $reach = $true }
            if ($r['endpoint']['http'] -eq 'pass') { $verified = $true }
            $checks.Add($x)
        }
        $cacheBytes = [System.Numerics.BigInteger]::Zero
        foreach ($s in @($ObservedStatus)) { $cacheBytes += (ConvertTo-DDBigInt (Get-DDProp $s 'bytesFromCacheServer')) }
        if (@($ObservedStatus).Count -eq 0 -and $verified) { $checks.Add((New-DDCheck -CheckId 'mcc-serving' -Target (& $tag $cacheHosts[0]) -Protocol http -Result 'pass' -Detail "Answers Microsoft's verification request; no DO jobs to inspect right now")) }
        elseif (@($ObservedStatus).Count -eq 0) { $checks.Add((New-DDCheck -CheckId 'mcc-serving' -Target (& $tag $cacheHosts[0]) -Protocol http -Result 'not-collected' -Detail 'No DO jobs to inspect right now')) }
        elseif ($cacheBytes -gt 0) { $checks.Add((New-DDCheck -CheckId 'mcc-serving' -Target (& $tag $cacheHosts[0]) -Protocol http -Result 'pass' -Detail 'BytesFromCacheServer is above zero in current jobs')) }
        elseif ($reach) { $checks.Add((New-DDCheck -CheckId 'mcc-serving' -Target (& $tag $cacheHosts[0]) -Protocol http -Result 'warn' -Detail 'Cache host is reachable but delivered nothing in current jobs')) }
        else { $checks.Add((New-DDCheck -CheckId 'mcc-serving' -Target (& $tag $cacheHosts[0]) -Protocol http -Result 'fail' -Detail 'Cache host unreachable and nothing delivered (DO-NET-007)')) }
    }

    # ---- proxy ---------------------------------------------------------------------------------------------------
    $checks.Add((New-DDCheck -CheckId 'proxy-source-ip' -Protocol local -Result 'not-applicable' -Detail 'Evaluated by the service by comparing network.publicEgressHash across devices on one subnet (DO-NET-009)'))
    if ($null -eq $Network) { $checks.Add((New-DDCheck -CheckId 'proxy-scope' -Protocol local -Result 'not-collected' -Detail 'proxy state could not be read')) }
    else {
        $px = $Network['proxy']
        if (-not $px['configured']) { $checks.Add((New-DDCheck -CheckId 'proxy-scope' -Protocol local -Result 'pass' -Detail 'No proxy configured')) }
        elseif ($px['wininetScope'] -eq 'per-user') { $checks.Add((New-DDCheck -CheckId 'proxy-scope' -Protocol local -Result 'fail' -Detail 'Per-user WinINET proxy only: background downloads (NetworkService) will not use it (DO-NET-012)')) }
        elseif ($px['wininetScope'] -eq 'none' -and $px['netshConfigured']) { $checks.Add((New-DDCheck -CheckId 'proxy-scope' -Protocol local -Result 'warn' -Detail 'netsh winhttp proxy only: not used by interactive downloads, no PAC or authentication; device-wide WinINET is recommended (DO-NET-012)')) }
        else { $checks.Add((New-DDCheck -CheckId 'proxy-scope' -Protocol local -Result 'pass' -Detail "Device-wide proxy ($($px['wininetScope']))")) }
    }
    $checks.Add((Get-DDPacCheck -Network $Network -Checks $checks.ToArray()))

    # ---- local prerequisites -------------------------------------------------------------------------------------
    if ($null -eq $DoSvc) { $checks.Add((New-DDCheck -CheckId 'dosvc-running' -Target 'DoSvc' -Protocol local -Result 'not-collected' -Detail 'DoSvc state could not be read')) }
    elseif ($DoSvc.StartType -eq 'Disabled') {
        $c = New-DDCheck -CheckId 'dosvc-running' -Target 'DoSvc' -Protocol local -Result 'fail' -Detail 'DoSvc start type is Disabled; no amount of policy will make DO work'
        $c['code'] = 'start-disabled'
        $checks.Add($c)
    }
    elseif ($DoSvc.Status -eq 'Running') { $checks.Add((New-DDCheck -CheckId 'dosvc-running' -Target 'DoSvc' -Protocol local -Result 'pass' -Detail "DoSvc running ($($DoSvc.StartType))")) }
    else { $checks.Add((New-DDCheck -CheckId 'dosvc-running' -Target 'DoSvc' -Protocol local -Result 'warn' -Detail "DoSvc is $($DoSvc.Status) ($($DoSvc.StartType)); it is trigger-started and stops when idle")) }

    if ($null -eq $modeNum) { $checks.Add((New-DDCheck -CheckId 'download-mode' -Protocol local -Result 'not-collected' -Detail 'Effective DODownloadMode not available')) }
    elseif ($peeringOff) { $checks.Add((New-DDCheck -CheckId 'download-mode' -Protocol local -Result 'warn' -Detail "DODownloadMode=$modeNum disables peering; peer-to-peer checks are not-applicable")) }
    else { $checks.Add((New-DDCheck -CheckId 'download-mode' -Protocol local -Result 'pass' -Detail "DODownloadMode=$modeNum")) }

    # Defaults when the setting is not configured: 4 GB RAM and 32 GB disk, from the Delivery Optimization reference
    # (https://learn.microsoft.com/windows/deployment/do/waas-delivery-optimization-reference). The Policy CSP page
    # (https://learn.microsoft.com/windows/client-management/mdm/policy-csp-deliveryoptimization) lists 0 for the same settings, so
    # the defaults are a documented assumption; a setting that is configured is always used as set.
    $minRamSet = Get-DDEffectiveValue -Effective $DoEffective -Name 'DOMinRAMAllowedToPeer'; $minRam = $minRamSet; if ($null -eq $minRam) { $minRam = 4 }
    $minDiskSet = Get-DDEffectiveValue -Effective $DoEffective -Name 'DOMinDiskSizeAllowedToPeer'; $minDisk = $minDiskSet; if ($null -eq $minDisk) { $minDisk = 32 }
    $driveText = $(if ($DiskDrive) { "cache drive $DiskDrive" } else { 'cache drive' })
    if ($peeringOff) { $checks.Add((New-DDCheck -CheckId 'resource-eligibility' -Protocol local -Result 'not-applicable' -Detail "Peering is disabled by $modeText")) }
    elseif ($null -eq $RamGB -or $null -eq $DiskGB) { $checks.Add((New-DDCheck -CheckId 'resource-eligibility' -Protocol local -Result 'not-collected' -Detail 'RAM or disk size unavailable')) }
    else {
        $why = New-Object 'System.Collections.Generic.List[string]'
        $ramFail = [double]$RamGB -lt [double]$minRam
        $diskFail = [double]$DiskGB -lt [double]$minDisk
        if ($ramFail) { $why.Add("RAM $RamGB GB < DOMinRAMAllowedToPeer $minRam GB") }
        if ($diskFail) { $why.Add("$driveText $DiskGB GB < DOMinDiskSizeAllowedToPeer $minDisk GB") }
        $assumed = @(@($(if ($null -eq $minRamSet) { 'DOMinRAMAllowedToPeer' }), $(if ($null -eq $minDiskSet) { 'DOMinDiskSizeAllowedToPeer' })) | Where-Object { $_ })
        $assumedText = $(if ($assumed.Count -gt 0) { " ($($assumed -join ' and ') not set: documented default assumed)" } else { '' })
        if ($why.Count -gt 0) {
            $c = New-DDCheck -CheckId 'resource-eligibility' -Protocol local -Result 'fail' -Detail ('Excluded from peering by its own policy: ' + ($why -join '; ') + $assumedText)
            $c['code'] = $(if ($ramFail -and $diskFail) { 'ram-disk' } elseif ($ramFail) { 'ram' } else { 'disk' })
            $checks.Add($c)
        }
        else { $checks.Add((New-DDCheck -CheckId 'resource-eligibility' -Protocol local -Result 'pass' -Detail "RAM $RamGB GB and $driveText $DiskGB GB meet the minimums ($minRam GB / $minDisk GB)")) }
    }

    if ($peeringOff) { $checks.Add((New-DDCheck -CheckId 'adapter-eligibility' -Protocol local -Result 'not-applicable' -Detail "Peering is disabled by $modeText")) }
    elseif ($null -eq $Network) { $checks.Add((New-DDCheck -CheckId 'adapter-eligibility' -Protocol local -Result 'not-collected' -Detail 'adapter facts unavailable')) }
    else {
        $vpnAllowed = Get-DDEffectiveValue -Effective $DoEffective -Name 'DOAllowVPNPeerCaching'
        $why = New-Object 'System.Collections.Generic.List[string]'
        if ($Network['isVpnActive'] -and -not ($vpnAllowed -eq 1)) { $why.Add('VPN active and DOAllowVPNPeerCaching is not enabled') }
        if ($Network['isMetered']) { $why.Add('metered connection') }
        if ($Network['adapterType'] -eq 'Cellular') { $why.Add('cellular adapter') }
        if ($why.Count -gt 0) { $checks.Add((New-DDCheck -CheckId 'adapter-eligibility' -Protocol local -Result 'warn' -Detail ('Peering restricted: ' + ($why -join '; ')))) }
        else { $checks.Add((New-DDCheck -CheckId 'adapter-eligibility' -Protocol local -Result 'pass' -Detail "Adapter type $($Network['adapterType'])")) }
    }

    # ---- Delivery Optimization health (Health.ps1): geo service, cache server in use, DHCP 235/234, rule scope, outbound
    # blocks, cache folder, state file, uploading on battery ---------------------------------------------------------------
    foreach ($c in (New-DDHealthChecks -DoEffective $DoEffective -Network $Network -FirewallRules $rules -Geo $GeoAnswer -CacheHost $CacheResolution -Dhcp $Dhcp `
                -CacheFolder $CacheFolder -Vitals $Vitals -PowerPlan $PowerPlan -ModeNum $modeNum -SkipProbes:$SkipProbes -BatteryCollected $batteryRead `
                -FirewallRulesComplete $fwComplete)) { $checks.Add($c) }

    if ($SkipProbes) { Add-DDNotCollected -Context $Context -Field 'connectivity' -Reason 'skipped-by-flag' -Detail 'network probes skipped by -SkipConnectivityChecks' }
    $kept = Select-DDMatrixRows -Checks $checks.ToArray() -Max $script:DDMaxMatrixChecks
    if ($kept.Dropped -gt 0) {
        Add-DDNotCollected -Context $Context -Field 'connectivity' -Reason 'error' -Detail "$($kept.Dropped) per-host connectivity row(s) not sent: the matrix is capped at $($script:DDMaxMatrixChecks) checks plus $($script:DDMaxEndpointRows) endpoint-health rows"
    }
    , @(@($kept.Rows) + @($ep | Select-Object -First $script:DDMaxEndpointRows))
}
