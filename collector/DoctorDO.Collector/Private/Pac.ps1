#Requires -Version 5.1
# Proxy auto-config (PAC) inspection (docs/17 section 4.3, ADR-0038): network.proxy.pac.
#
#  * Which setup scripts are in force: the device-wide one when the per-machine policy is on, else each signed-in user's
#    and NetworkService's (DoSvc's account). Read from the registry only (Get-DDPacSourcesRaw); no hive is ever loaded.
#  * Each PAC is downloaded once, directly, as WinHTTP would (http and https only, 1 MB at most), and searched for the
#    Delivery Optimization endpoints of Data/endpoints.json. WinHTTP then evaluates it for one DO cloud and one DO content
#    URL, so an admin can check the PAC when DO has connectivity issues.
#  * Privacy: nothing about the PAC leaves the device but a tenant-salted fingerprint (so the console can count versions
#    across devices), which scopes use it, a count of signed-in user profiles, which DO endpoint groups it names and what
#    it answers for them (direct or proxy). Never its URL, host, text or the proxies it names; never a user or SID.

Set-StrictMode -Version Latest

# Endpoint services (Data/endpoints.json) a PAC is searched for, and the URL WinHTTP evaluates for each route.
$script:DDPacServices = @('do-cloud', 'do-content', 'wu-content')
$script:DDPacRouteUrls = [ordered]@{ doCloud = 'https://geo.prod.do.dsp.mp.microsoft.com/geo'; doContent = 'http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/' }
$script:DDPacMaxItems = 4
$script:DDPacMaxBytes = 1048576   # WinHTTP rejects a larger PAC

function ConvertFrom-DDConnectionSettings {
    <#
    .SYNOPSIS
        WinINET's DefaultConnectionSettings (hex): flags at byte 8 (0x04 setup script, 0x08 automatically detect), then
        three length-prefixed strings: proxy server, bypass list, setup script URL. $null when it cannot be parsed.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Hex)
    if ([string]::IsNullOrEmpty($Hex) -or $Hex.Length -lt 24 -or ($Hex.Length % 2) -ne 0 -or $Hex -notmatch '^[0-9a-fA-F]+$') { return $null }
    $b = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    $pos = 12; $strings = @()
    for ($n = 0; $n -lt 3; $n++) {
        if ($pos + 4 -gt $b.Length) { break }
        $len = [BitConverter]::ToInt32($b, $pos); $pos += 4
        if ($len -lt 0 -or $pos + $len -gt $b.Length) { break }
        $strings += [System.Text.Encoding]::ASCII.GetString($b, $pos, $len)
        $pos += $len
    }
    [pscustomobject]@{ Flags = [BitConverter]::ToInt32($b, 8); AutoConfigUrl = $(if ($strings.Count -ge 3 -and $strings[2]) { $strings[2] } else { $null }) }
}

function Get-DDPacSources {
    <#
    .SYNOPSIS
        The setup scripts in force, from Get-DDPacSourcesRaw: @{ Scope; Url }. With the per-machine policy on, only the
        device's (users cannot set their own); otherwise each signed-in user's and NetworkService's. An AutoConfigURL value
        wins; else the connection blob's URL, which counts only with its setup-script flag set.
    #>
    [CmdletBinding()]
    param($Raw)
    if ($null -eq $Raw) { return }
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in @($Raw.Entries)) {
        if ([bool]$Raw.PerMachine -ne ($e.Scope -eq 'device')) { continue }
        $url = [string]$e.AutoConfigUrl
        if (-not $url.Trim()) {
            $c = ConvertFrom-DDConnectionSettings -Hex $e.Connections
            if ($null -ne $c -and ($c.Flags -band 4) -and $c.AutoConfigUrl) { $url = $c.AutoConfigUrl }
        }
        if ($url.Trim()) { $out.Add([pscustomobject]@{ Scope = [string]$e.Scope; Url = $url.Trim() }) }
    }
    $out.ToArray()
}

function Get-DDPacDomainNames {
    # The names a PAC would test for a manifest pattern: its fixed part ('*.do.dsp.mp.microsoft.com' -> do.dsp.mp.microsoft.com)
    # and the parents of that down to three labels (dsp.mp.microsoft.com, mp.microsoft.com), never microsoft.com itself.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Pattern)
    $labels = @($Pattern.Trim().ToLowerInvariant().TrimEnd('.').Split('.'))
    $i = 0
    while ($i -lt $labels.Count -and $labels[$i].Contains('*')) { $i++ }
    $fixed = @($labels | Select-Object -Skip $i)
    for ($k = 0; $k -lt $fixed.Count; $k++) {
        if ($k -eq 0 -or ($fixed.Count - $k) -ge 3) { ($fixed | Select-Object -Skip $k) -join '.' }
    }
}

function Get-DDPacDoReferences {
    <#
    .SYNOPSIS
        The Delivery Optimization endpoint services (Data/endpoints.json) a PAC's text names, sorted: do-cloud, do-content,
        wu-content. A name counts as a whole DNS name (the character before and after is not a letter, digit or hyphen).
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Text, [Parameter(Mandatory)] $Manifest)
    if ([string]::IsNullOrEmpty($Text)) { return }
    $found = New-Object 'System.Collections.Generic.SortedSet[string]'
    foreach ($e in @($Manifest['endpoints'])) {
        $svc = [string]$e['service']
        if ($script:DDPacServices -notcontains $svc -or $found.Contains($svc)) { continue }
        $names = @(Get-DDPacDomainNames -Pattern ([string]$e['pattern']))
        for ($j = 0; $j -lt $names.Count; $j++) {
            # The pattern's own name counts with any subdomain (its wildcard); a parent only as a name in its own right, so
            # "mp.microsoft.com" inside "do.dsp.mp.microsoft.com" or "foo.mp.microsoft.com" is not a rule for every DO host.
            $before = $(if ($j -eq 0) { '(?<![a-z0-9-])' } else { '(?<![a-z0-9-])(?<![a-z0-9-]\.)' })
            if ([regex]::IsMatch($Text, '(?i)' + $before + [regex]::Escape($names[$j]) + '(?![a-z0-9-])')) { [void]$found.Add($svc); break }
        }
    }
    @($found)
}

function ConvertTo-DDPacFetchState {
    # The outcome of one PAC download (Invoke-DDHttpFetch): ok | too-large | timeout | failed.
    [CmdletBinding()]
    param($Outcome)
    if ($null -eq $Outcome) { return 'failed' }
    if ($Outcome.Body -and $Outcome.BodyTruncated) { return 'too-large' }
    if ($Outcome.Body) { return 'ok' }
    if ($Outcome.TimedOut) { return 'timeout' }
    'failed'
}

function Get-DDPacFacts {
    <#
    .SYNOPSIS
        network.proxy.pac (packages/schema PacFacts): whether a PAC is in force on this device, whether it names Delivery
        Optimization endpoints, how many different PACs are in force, and what each answers for DO. $null when the
        registry could not be read. -Skip (-SkipConnectivityChecks) reads the registry only: nothing is downloaded or run.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [switch] $Skip, [int] $BudgetMs = 15000)

    $raw = Invoke-DDStep -Context $Context -Field 'network.proxy.pac' -Script { Get-DDPacSourcesRaw }
    if ($null -eq $raw) { return $null }
    if ([int]$raw.UsersUnreadable -gt 0) {
        Add-DDNotCollected -Context $Context -Field 'network.proxy.pac.users' -Reason 'insufficient-rights' -Detail "$([int]$raw.UsersUnreadable) signed-in user profile(s) could not be read; the collector reads them when run as SYSTEM or elevated"
    }
    $sources = @(Get-DDPacSources -Raw $raw)
    $pac = [ordered]@{ configured = ($sources.Count -gt 0); versions = 0; referencesDo = $null; userProfiles = [int]$raw.UsersRead; items = @() }
    if ($sources.Count -eq 0) { return $pac }

    # One entry per PAC URL, with the scopes that use it and how many signed-in users point at it.
    $byUrl = [ordered]@{}
    foreach ($s in $sources) {
        $k = $s.Url.ToLowerInvariant()
        if (-not $byUrl.Contains($k)) { $byUrl[$k] = [pscustomobject]@{ Url = $s.Url; Scopes = (New-Object 'System.Collections.Generic.SortedSet[string]'); Users = 0 } }
        [void]$byUrl[$k].Scopes.Add($s.Scope)
        if ($s.Scope -eq 'user') { $byUrl[$k].Users++ }
    }
    if ($byUrl.Count -gt $script:DDPacMaxItems) {
        Add-DDNotCollected -Context $Context -Field 'network.proxy.pac.items' -Reason 'error' -Detail "$($byUrl.Count) different PAC URLs are in force; the first $($script:DDPacMaxItems) are reported"
    }

    $manifest = Get-DDEndpointManifest
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $items = [ordered]@{}
    foreach ($g in @($byUrl.Values | Select-Object -First $script:DDPacMaxItems)) {
        $u = $null
        $web = [System.Uri]::TryCreate($g.Url, [System.UriKind]::Absolute, [ref]$u) -and $u.Scheme -in 'http', 'https'
        $fetch = $(if (-not $web) { 'unsupported' } else { 'skipped' }); $text = $null
        $routes = [ordered]@{ doCloud = $null; doContent = $null }
        if ($web -and -not $Skip -and $sw.ElapsedMilliseconds -lt $BudgetMs) {
            # Errors are recorded without their message: it can carry the PAC's URL.
            try {
                $f = Invoke-DDHttpFetch -Uri $g.Url -TimeoutMs 5000 -MaxBody $script:DDPacMaxBytes -ReadBodyFor @('')
                $fetch = ConvertTo-DDPacFetchState -Outcome $f
                if ($f.Body) { $text = [System.Text.Encoding]::UTF8.GetString([byte[]]$f.Body) }
            } catch { $fetch = 'failed'; Add-DDNotCollected -Context $Context -Field 'network.proxy.pac' -Reason (Get-DDNotCollectedReason -ErrorRecord $_) -Detail 'the PAC could not be downloaded' }
            foreach ($r in @($script:DDPacRouteUrls.Keys)) {
                if ($sw.ElapsedMilliseconds -ge $BudgetMs) { break }
                try {
                    $d = Resolve-DDPacProxy -Uri $script:DDPacRouteUrls[$r] -PacUrl $g.Url -TimeoutMs 4000
                    $routes[$r] = $(if ($null -eq $d -or $d.Error) { 'error' } elseif ($d.Proxy) { 'proxy' } else { 'direct' })
                } catch { $routes[$r] = 'error' }
            }
        }
        $basis = $(if ($fetch -eq 'ok') { 'content' } else { 'url' })
        $id = 'pac:' + $(if ($basis -eq 'content') { Get-DDShortHash -Value $text -Salt $Context.TenantSalt -Domain 'pac' } else { Get-DDShortHash -Value $g.Url.ToLowerInvariant() -Salt $Context.TenantSalt -Domain 'pac-url' })
        if ($items.Contains($id)) {
            # Two URLs serving the same script are one version.
            $it = $items[$id]
            $it['scopes'] = @(@($it['scopes']) + @($g.Scopes) | Sort-Object -Unique)
            $it['userProfiles'] += $g.Users
            continue
        }
        $items[$id] = [ordered]@{
            id           = $id
            basis        = $basis
            scopes       = @($g.Scopes)
            userProfiles = [int]$g.Users
            fetch        = $fetch
            doReferences = @(Get-DDPacDoReferences -Text $text -Manifest $manifest)
            routes       = $routes
        }
        $text = $null
    }
    $list = @($items.Values)
    $read = @($list | Where-Object { $_['fetch'] -in 'ok', 'too-large' })
    $pac['versions'] = $list.Count
    $pac['referencesDo'] = $(if ($read.Count -gt 0) { [bool](@($read | Where-Object { @($_['doReferences']).Count -gt 0 }).Count) } else { $null })
    $pac['items'] = $list
    $pac
}

function Get-DDPacCheck {
    <#
    .SYNOPSIS
        The proxy-pac connectivity check (DO-NET-025) from network.proxy.pac and the checks already in the matrix: whether a
        PAC is in force and names DO endpoints, whether more than one is in force, and, when DO's own endpoints are failing
        on this device, a pointer to the PAC with what it answers for DO.
    #>
    [CmdletBinding()]
    param($Network, [AllowEmptyCollection()] $Checks = @())
    $px = $(if ($Network -is [System.Collections.IDictionary]) { $Network['proxy'] } else { $null })
    $pac = $(if ($px -is [System.Collections.IDictionary] -and $px.Contains('pac')) { $px['pac'] } else { $null })
    if ($null -eq $pac) { return New-DDCheck -CheckId 'proxy-pac' -Protocol local -Result 'not-collected' -Detail 'PAC configuration could not be read' }
    if (-not $pac['configured']) { return New-DDCheck -CheckId 'proxy-pac' -Protocol local -Result 'not-applicable' -Detail 'No proxy auto-config (PAC) script in force' }

    $items = @($pac['items'])
    $scopeWords = @{ device = 'device-wide'; user = 'signed-in users'; service = 'NetworkService (DoSvc)' }
    $scopes = @($items | ForEach-Object { @($_['scopes']) } | Sort-Object -Unique)
    $names = @($items | ForEach-Object { @($_['doReferences']) } | Sort-Object -Unique)
    $routeOf = { param($k) @($items | ForEach-Object { $_['routes'][$k] } | Where-Object { $_ } | Sort-Object -Unique) }
    $cloud = @(& $routeOf 'doCloud'); $content = @(& $routeOf 'doContent')
    $cloudProxy = $cloud -contains 'proxy'
    $unread = [bool](@($items | Where-Object { $_['fetch'] -in 'failed', 'timeout' }).Count)
    $tooLarge = [bool](@($items | Where-Object { $_['fetch'] -eq 'too-large' }).Count)
    $fileUrl = [bool](@($items | Where-Object { $_['fetch'] -eq 'unsupported' }).Count)
    $skipped = $items.Count -gt 0 -and -not (@($items | Where-Object { $_['fetch'] -ne 'skipped' }).Count)
    $doIssue = [bool](@($Checks | Where-Object { $_['checkId'] -in 'do-cloud-dns', 'do-cloud-tls', 'do-cloud-inspect', 'proxy-tls-inspection', 'do-content-cdn', 'do-range-support' -and $_['result'] -eq 'fail' }).Count)

    $versions = [int]$pac['versions']
    $summary = 'PAC in force ({0}); {1}; {2} version{3}' -f (($scopes | ForEach-Object { $scopeWords[$_] }) -join ', '),
        $(if ($pac['referencesDo'] -eq $true) { "names DO endpoints ($($names -join ', '))" } elseif ($pac['referencesDo'] -eq $false) { 'names no DO endpoints' } elseif ($skipped) { 'not downloaded (connectivity checks skipped)' } else { 'could not be read' }),
        $versions, $(if ($versions -eq 1) { '' } else { 's' })
    $problems = New-Object 'System.Collections.Generic.List[string]'
    if ($fileUrl) { $problems.Add('a file:// PAC, which WinHTTP and so Delivery Optimization cannot use') }
    if ($versions -gt 1) { $problems.Add('different PACs apply to the device, signed-in users or NetworkService, so downloads can be routed differently depending on who is signed in') }
    if ($unread) { $problems.Add('the PAC could not be downloaded') }
    if ($tooLarge) { $problems.Add('the PAC is larger than 1 MB, which WinHTTP rejects') }
    if ($cloudProxy) { $problems.Add('it sends the DO cloud service (*.do.dsp.mp.microsoft.com) through a proxy, where Microsoft recommends direct access') }
    if ($doIssue -and $problems.Count -eq 0 -and ($pac['referencesDo'] -eq $true -or $content -contains 'proxy')) { $problems.Add('it names or proxies DO endpoints that are failing on this device') }

    $result = $(if ($doIssue -and $cloudProxy) { 'fail' } elseif ($problems.Count -gt 0) { 'warn' } else { 'pass' })
    $detail = $summary
    if ($problems.Count -gt 0) { $detail += ': ' + ($problems -join '; ') }
    if ($doIssue -and $problems.Count -gt 0) { $detail += '. DO endpoint checks are failing on this device: check the PAC' }
    $detail += ' (DO-NET-025)'
    $evidence = 'versions={0} scopes={1} names={2} doCloud={3} doContent={4}' -f $versions, ($scopes -join ','), $(if ($names.Count) { $names -join ',' } else { 'none' }),
        $(if ($cloud.Count) { $cloud -join ',' } else { 'not-evaluated' }), $(if ($content.Count) { $content -join ',' } else { 'not-evaluated' })
    New-DDCheck -CheckId 'proxy-pac' -Protocol local -Result $result -Detail $detail -Evidence $evidence
}
