#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:Manifest = InModuleScope DoctorDO.Collector { Get-DDEndpointManifest }
    function global:Get-EpRows { param($Matrix) , @($Matrix | Where-Object { ([string]$_['checkId']).StartsWith('ep:') }) }
    function global:Get-EpRow { param($Matrix, [string] $Id, [string] $Target) , @((Get-EpRows $Matrix) | Where-Object { $_['endpoint']['id'] -eq $Id -and (-not $Target -or $_['target'] -eq $Target) }) }
}

Describe 'Endpoint manifest (Data/endpoints.json)' {
    It 'is versioned, dated and cites Microsoft Learn for every entry' {
        $script:Manifest['version'] | Should -Be 1
        $script:Manifest['verified'] | Should -Match '^\d{4}-\d{2}-\d{2}$'
        foreach ($s in $script:Manifest['sources'].Values) { $s['url'] | Should -Match '^https://learn\.microsoft\.com/' }
        foreach ($e in $script:Manifest['endpoints']) {
            @($e['citations']).Count | Should -BeGreaterThan 0
            foreach ($c in $e['citations']) { $script:Manifest['sources'].Contains($c['source']) | Should -BeTrue }
            $e['wildcard'] | Should -Be ([string]$e['pattern']).Contains('*')
        }
    }

    It 'matches hosts exactly as the shared vectors say (the TypeScript side runs the same vectors)' {
        InModuleScope DoctorDO.Collector -Parameters @{ M = $script:Manifest } {
            param($M)
            foreach ($t in $M['patternTests']) { Test-DDHostPattern -Pattern $t['pattern'] -HostName $t['host'] | Should -Be $t['match'] -Because "$($t['pattern']) ~ $($t['host'])" }
        }
    }

    It 'sorts a host into the most specific entry it matches' {
        InModuleScope DoctorDO.Collector -Parameters @{ M = $script:Manifest } {
            param($M)
            (Get-DDEndpointForHost -Manifest $M -HostName '1d.tlu.dl.delivery.mp.microsoft.com')['id'] | Should -Be 'do-content'
            (Get-DDEndpointForHost -Manifest $M -HostName 'fe3cr.delivery.mp.microsoft.com')['id'] | Should -Be 'wu-service'
            (Get-DDEndpointForHost -Manifest $M -HostName 'array614.prod.do.dsp.mp.microsoft.com')['id'] | Should -Be 'do-array'
            (Get-DDEndpointForHost -Manifest $M -HostName 'ctldl.windowsupdate.com')['id'] | Should -Be 'wu-ctl'
            Get-DDEndpointForHost -Manifest $M -HostName 'wsus01.corp.contoso.com' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Endpoint health: which hosts are tested' {
    It 'tests a wildcard on the hosts the device used first, then documented ones, up to its limit, and never invents one' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDDOLogEntries { @([pscustomobject]@{ TimeCreated = [datetime]::UtcNow; Function = 'x'; Message = 'GET https://array614.prod.do.dsp.mp.microsoft.com/join and https://kv601.prod.do.dsp.mp.microsoft.com/all' }) }
        $m = Get-DOConnectivityMatrix
        $cloud = Get-EpRow $m 'do-cloud'
        ($cloud | ForEach-Object { $_['target'] }) | Should -Be @('kv601.prod.do.dsp.mp.microsoft.com', 'geo.prod.do.dsp.mp.microsoft.com')
        ($cloud | ForEach-Object { $_['endpoint']['basis'] }) | Should -Be @('observed', 'documented')
        (Get-EpRow $m 'do-array')[0]['target'] | Should -Be 'array614.prod.do.dsp.mp.microsoft.com'
        $known = @($script:Manifest['endpoints'] | ForEach-Object { $_['pattern']; $_['documentedHosts'] | ForEach-Object { $_['host'] } }) + 'kv601.prod.do.dsp.mp.microsoft.com', 'array614.prod.do.dsp.mp.microsoft.com', 'tlu.dl.delivery.mp.microsoft.com', 'x.dl.delivery.mp.microsoft.com'
        foreach ($r in (Get-EpRows $m)) { if ($r['target']) { $known | Should -Contain $r['target'] } }
    }

    It 'reports a wildcard with no observed or documented host as not testable, with no probe and no target' {
        Initialize-FakeDevice
        $m = Get-DOConnectivityMatrix
        $x = (Get-EpRow $m 'wu-update')[0]
        $x['target'] | Should -Be ''
        $x['result'] | Should -Be 'not-collected'
        $x['endpoint']['basis'] | Should -Be 'not-testable'
        $x['detail'] | Should -Match 'Not testable: wildcard'
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch -ParameterFilter { @($Specs | Where-Object { $_.Host -like '*.update.microsoft.com' }).Count -gt 0 } -Times 0
    }

    It 'probes content types only where the device uses them' {
        Initialize-FakeDevice
        $m = Get-DOConnectivityMatrix
        (Get-EpRow $m 'intune-win32')[0]['endpoint']['basis'] | Should -Be 'not-applicable'
        (Get-EpRow $m 'office-cdn')[0]['target'] | Should -Be 'officecdn.microsoft.com' -Because 'the fake device has Office Click-to-Run jobs'
    }

    It 'leaves Teredo out in LAN mode, and tests it in Group mode' {
        Initialize-FakeDevice -DownloadMode 'Lan'
        (Get-EpRow (Get-DOConnectivityMatrix) 'teredo-do')[0]['result'] | Should -Be 'not-applicable'
        Initialize-FakeDevice -DownloadMode 'Group'
        $t = (Get-EpRow (Get-DOConnectivityMatrix) 'teredo-do')[0]
        $t['endpoint']['dns'] | Should -Be 'pass'
        $t['endpoint']['tcp'] | Should -Be 'not-applicable' -Because 'UDP 3544 cannot be confirmed by a connectionless probe'
    }

    It 'probes the configured Connected Cache with Microsoft''s verification request, and keeps it in clear under -Anonymise' {
        Initialize-FakeDevice -CacheHost 'mcc01.contoso.example'
        $m = Get-DOConnectivityMatrix -Anonymise
        $x = (Get-EpRow $m 'mcc')[0]
        $x['target'] | Should -Be 'mcc01.contoso.example'
        $x['endpoint']['basis'] | Should -Be 'configured'
        $x['endpoint']['http'] | Should -Be 'pass'
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch -ParameterFilter {
            @($Specs | Where-Object { $_.Host -eq 'mcc01.contoso.example' -and $_.RangeUrl -eq 'http://mcc01.contoso.example/filestreamingservice/files/7bc846e0-af9c-49be-a03d-bb04428c9bb5/Microsoft.png?cacheHostOrigin=dl.delivery.mp.microsoft.com' }).Count -eq 1
        } -Times 1 -Exactly
    }
}

Describe 'Endpoint health: what each stage means' {
    BeforeEach { Initialize-FakeDevice }

    It 'a name that does not resolve fails at DNS, and the later stages are not run (not passes)' {
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { New-FakeEndpointOutcome -Spec $s -DnsFail:($s.Host -eq 'geo.prod.do.dsp.mp.microsoft.com') } }
        $m = Get-DOConnectivityMatrix
        $x = (Get-EpRow $m 'do-cloud')[0]
        $x['result'] | Should -Be 'fail'
        $x['endpoint']['dns'] | Should -Be 'fail'
        $x['endpoint']['tcp'] | Should -Be 'not-collected'
        $x['endpoint']['tls'] | Should -Be 'not-collected'
        $x['endpoint']['err']['code'] | Should -Be 'dns-failed'
        ($m | Where-Object checkId -eq 'do-cloud-dns').result | Should -Be 'fail'
    }

    It 'a name that does not exist is a warning on a low-stakes entry (possibly retired), and still a failure on a critical one' {
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch {
            foreach ($s in @($Specs)) { New-FakeEndpointOutcome -Spec $s -DnsFail:($s.Host -in 'emdl.ws.microsoft.com', 'fe3.delivery.mp.microsoft.com') -DnsError 'SocketException HostNotFound' }
        }
        $m = Get-DOConnectivityMatrix
        $emdl = (Get-EpRow $m 'wu-emdl')[0]
        $emdl['result'] | Should -Be 'warn'
        $emdl['endpoint']['err']['code'] | Should -Be 'dns-nxdomain'
        $emdl['detail'] | Should -Match 'retired'
        $wu = (Get-EpRow $m 'wu-service')[0]
        $wu['result'] | Should -Be 'fail'
        $wu['endpoint']['err']['code'] | Should -Be 'dns-nxdomain'
    }

    It 'a cache this device was handed but nobody configured that ignores the Enterprise verification request is a warning, a configured one a failure' {
        Initialize-FakeDevice -CacheHost 'mcc01.contoso.example'
        Mock -ModuleName DoctorDO.Collector Get-DDDOStatusRaw {
            @([pscustomobject]@{ FileId = ('{0:x40}' -f 1); FileSize = 7MB; BytesToLanPeers = 0; BytesToInternetPeers = 0; TotalBytesDownloaded = 7MB; BytesFromHttp = 0; BytesFromLanPeers = 0; BytesFromGroupPeers = 0; BytesFromInternetPeers = 0
                    BytesFromCacheServer = 7MB; DownloadMode = 2; Status = 'Complete'; Priority = 'Background'; NumPeers = 0; PredefinedCallerApplication = 'WU Client Download'
                    SourceURL = 'http://1d.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/0000-aaaa?P1=1'; ExpireOn = [datetime]::new(2026, 10, 20, 0, 0, 0, [System.DateTimeKind]::Utc); CacheHost = '198.51.100.203' })
        }
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch {
            foreach ($s in @($Specs)) { if ($s.Host -in '198.51.100.203', 'mcc01.contoso.example') { $o = New-FakeEndpointOutcome -Spec $s -VerifyStatus 0; $o.VerifyError = 'IOException: timeout'; $o.RangeStatus = 0; $o.RangeError = 'IOException: timeout'; $o } else { New-FakeEndpointOutcome -Spec $s } }
        }
        $m = Get-DOConnectivityMatrix
        $isp = (Get-EpRow $m 'mcc' '198.51.100.203')[0]
        $isp['endpoint']['basis'] | Should -Be 'observed'
        $isp['result'] | Should -Be 'warn'
        $isp['detail'] | Should -Match 'ISP or service-assigned'
        $mine = (Get-EpRow $m 'mcc' 'mcc01.contoso.example')[0]
        $mine['endpoint']['basis'] | Should -Be 'configured'
        $mine['result'] | Should -Be 'fail'
    }

    It 'a black-holed port is a TCP timeout, and the derived content check fails with the reason' {
        Initialize-FakeDevice -ProbeFailures
        $m = Get-DOConnectivityMatrix
        $x = (Get-EpRow $m 'do-content')[0]
        $x['endpoint']['tcp'] | Should -Be 'fail'
        $x['endpoint']['err']['code'] | Should -Be 'tcp-timeout'
        $x['endpoint']['http'] | Should -Be 'not-collected'
        (@($m | Where-Object checkId -eq 'do-content-cdn'))[0].detail | Should -Match 'timed out'
    }

    It 'judges certificates: inspection on a pinned endpoint, an untrusted chain, a wrong name; another trusted CA is fine where nothing is pinned' {
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch {
            foreach ($s in @($Specs)) {
                switch ($s.Host) {
                    'fe3.delivery.mp.microsoft.com' { New-FakeEndpointOutcome -Spec $s -NotMicrosoft }
                    'msedge.api.cdp.microsoft.com' { New-FakeEndpointOutcome -Spec $s -Issuer 'CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc' }
                    'login.live.com' { New-FakeEndpointOutcome -Spec $s -NotMicrosoft -Untrusted }
                    'displaycatalog.mp.microsoft.com' { New-FakeEndpointOutcome -Spec $s -NameMismatch }
                    default { New-FakeEndpointOutcome -Spec $s }
                }
            }
        }
        $m = Get-DOConnectivityMatrix
        $wu = (Get-EpRow $m 'wu-service')[0]
        $wu['endpoint']['tls'] | Should -Be 'fail'
        $wu['endpoint']['err']['code'] | Should -Be 'tls-inspected'
        $wu['endpoint']['cert']['issuer'] | Should -Be 'other-trusted'
        $wu['endpoint']['cert']['issuerCn'] | Should -Be 'Contoso SSL Inspection CA'
        $edge = (Get-EpRow $m 'edge-update')[0]
        $edge['endpoint']['tls'] | Should -Be 'pass'
        $edge['endpoint']['cert']['issuer'] | Should -Be 'other-trusted'
        (Get-EpRow $m 'wu-msa')[0]['endpoint']['err']['code'] | Should -Be 'tls-untrusted'
        (Get-EpRow $m 'store-catalog')[0]['endpoint']['err']['code'] | Should -Be 'tls-name-mismatch'
    }

    It 'a byte-range request answered 200 means ranges are stripped; a file no longer served is inconclusive, not a failure' {
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { New-FakeEndpointOutcome -Spec $s -RangeStatus $(if ($s.Host -eq 'tlu.dl.delivery.mp.microsoft.com') { 200 } else { 404 }) } }
        $m = Get-DOConnectivityMatrix
        $x = (Get-EpRow $m 'do-content' 'tlu.dl.delivery.mp.microsoft.com')[0]
        $x['endpoint']['range'] | Should -Be 'fail'
        $x['endpoint']['err']['code'] | Should -Be 'range-ignored'
        $x['endpoint']['httpStatus'] | Should -Be 200
        ($m | Where-Object checkId -eq 'do-range-support').result | Should -Be 'fail'
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { New-FakeEndpointOutcome -Spec $s -RangeStatus 404 } }
        $y = (Get-EpRow (Get-DOConnectivityMatrix) 'do-content' 'tlu.dl.delivery.mp.microsoft.com')[0]
        $y['endpoint']['range'] | Should -Be 'not-collected'
        $y['result'] | Should -Be 'pass'
    }

    It 'records the proxy DoSvc would use, a proxy that wants authentication, and whether a direct connection differs' {
        Mock -ModuleName DoctorDO.Collector Resolve-DDProbeProxy { $o = @{}; foreach ($r in @($Rows)) { if ($r.Host) { $o[$r.Host] = [pscustomobject]@{ Source = 'netsh'; Proxy = 'proxy.contoso.example:8080'; Error = $null } } }; $o }
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch {
            foreach ($s in @($Specs)) {
                if ($s.Host -eq 'fe3.delivery.mp.microsoft.com') { New-FakeEndpointOutcome -Spec $s -ViaProxy -ProxyStatus 407 }
                else { New-FakeEndpointOutcome -Spec $s -ViaProxy -DirectBlocked }
            }
        }
        $m = Get-DOConnectivityMatrix
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch -ParameterFilter { @($Specs | Where-Object { $_.Host -eq 'geo.prod.do.dsp.mp.microsoft.com' -and $_.Proxy -eq 'proxy.contoso.example:8080' }).Count -eq 1 } -Times 1
        $geo = (Get-EpRow $m 'do-cloud' 'geo.prod.do.dsp.mp.microsoft.com')[0]
        $geo['endpoint']['proxy']['source'] | Should -Be 'netsh'
        $geo['endpoint']['proxy']['used'] | Should -BeTrue
        $geo['endpoint']['proxy']['direct'] | Should -Be 'fail'
        $wu = (Get-EpRow $m 'wu-service')[0]
        $wu['endpoint']['err']['code'] | Should -Be 'proxy-auth-required'
        $wu['result'] | Should -Be 'fail'
    }

    It 'through a proxy, says an HTTP port reached the proxy only, and that the host behind it is not tested where no HTTP request is sent (D-09)' {
        Mock -ModuleName DoctorDO.Collector Resolve-DDProbeProxy { $o = @{}; foreach ($r in @($Rows)) { if ($r.Host) { $o[$r.Host] = [pscustomobject]@{ Source = 'pac'; Proxy = 'proxy.contoso.example:8080'; Error = $null; Context = 'no-user' } } }; $o }
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch {
            foreach ($s in @($Specs)) {
                $o = New-FakeEndpointOutcome -Spec $s -ViaProxy
                $tcp = @(for ($i = 0; $i -lt @($s.Protocols).Count; $i++) { if (@($s.Protocols)[$i] -ne 'udp') { @($s.Protocols)[$i] } })
                for ($i = 0; $i -lt @($o.Ports).Count; $i++) { $o.Ports[$i] | Add-Member -NotePropertyName ProxyOnly -NotePropertyValue ($tcp[$i] -eq 'http') }
                $o
            }
        }
        Mock -ModuleName DoctorDO.Collector Get-DDDOStatusRaw {
            @([pscustomobject]@{ FileId = ('{0:x40}' -f 9); FileSize = 1048576; Status = 'Caching'; PredefinedCallerApplication = 'IntuneManagementExtension (Intune)'; SourceURL = 'http://swda01-mscdn.manage.microsoft.com/abc/file.intunewin'
                    ExpireOn = [datetime]::new(2026, 10, 20, 0, 0, 0, [System.DateTimeKind]::Utc); BytesFromHttp = 1; BytesToLanPeers = 0; BytesToInternetPeers = 0; TotalBytesDownloaded = 1; BytesFromLanPeers = 0; BytesFromGroupPeers = 0; BytesFromInternetPeers = 0; BytesFromCacheServer = 0 })
        }
        $m = Get-DOConnectivityMatrix
        $content = (Get-EpRow $m 'wu-content')[0]
        $content['detail'] | Should -Match 'the proxy is reachable for TCP 80 \(the HTTP request shows whether it reaches the host\)'
        $content['detail'] | Should -Not -Match 'TCP 80 connected'
        $win32 = (Get-EpRow $m 'intune-win32')[0]
        $win32['detail'] | Should -Match 'TCP 443 connected through the proxy; the proxy is reachable for TCP 80 \(the byte-range request shows whether it reaches the host\)'
        $cloud = (Get-EpRow $m 'do-cloud')[0]
        $cloud['detail'] | Should -Match 'TCP 443 connected through the proxy'
        # The matrix check derived from the row says the same.
        ($m | Where-Object { $_['checkId'] -eq 'do-metadata-wu' } | Select-Object -First 1)['detail'] | Should -Match 'the proxy is reachable'
    }

    It 'names the proxy context it modelled, and says a row whose proxy could not be resolved was probed direct (assumed) (D-07, D-13)' {
        $global:DDProxyContext = 'no-user'
        Mock -ModuleName DoctorDO.Collector Resolve-DDProbeProxy {
            $o = @{}
            foreach ($r in @($Rows)) {
                if (-not $r.Host) { continue }
                $o[$r.Host] = $(if ($r.Host -eq 'adl.windows.com') { [pscustomobject]@{ Source = 'unresolved'; Proxy = $null; Error = 'proxy resolution budget exhausted'; Context = $global:DDProxyContext } }
                    elseif ($r.Host -eq 'ctldl.windowsupdate.com') { [pscustomobject]@{ Source = 'pac'; Proxy = $null; Error = $null; Context = $global:DDProxyContext } }
                    else { [pscustomobject]@{ Source = 'netsh'; Proxy = 'proxy.contoso.example:8080'; Error = $null; Context = $global:DDProxyContext } })
            }
            $o
        }
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { New-FakeEndpointOutcome -Spec $s -ViaProxy:([bool]$s.Proxy) } }
        $m = Get-DOConnectivityMatrix
        (Get-EpRow $m 'do-cloud')[0]['evidence'] | Should -Match 'proxy=netsh \(as DoSvc with no user signed in\)'
        (Get-EpRow $m 'wu-ctl')[0]['evidence'] | Should -Match 'proxy=pac, direct for this host'
        $adl = (Get-EpRow $m 'wu-compat')[0]
        $adl['evidence'] | Should -Match 'proxy unresolved: proxy resolution budget exhausted; probed direct \(assumed\)'
        $adl['detail'] | Should -Match 'probed direct \(assumed\)'
        $global:DDProxyContext = 'user'
        (Get-EpRow (Get-DOConnectivityMatrix) 'do-cloud')[0]['evidence'] | Should -Match "proxy=netsh \(this account's settings, netsh first\)"
    }

    It 'sends resolved addresses only for CDN and Connected Cache hosts, never for service hosts' {
        $m = Get-DOConnectivityMatrix
        @((Get-EpRow $m 'do-content')[0]['endpoint']['addrs']).Count | Should -BeGreaterThan 0
        @((Get-EpRow $m 'do-cloud')[0]['endpoint']['addrs']).Count | Should -Be 0
        @((Get-EpRow $m 'wu-service')[0]['endpoint']['addrs']).Count | Should -Be 0
    }

    It 'never sends a URL, a path or a query string, and keeps the issuer name out under -Anonymise' {
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { New-FakeEndpointOutcome -Spec $s -NotMicrosoft -RangeStatus 200 } }
        $json = ConvertTo-Json -InputObject @(Get-EpRows (Get-DOConnectivityMatrix -Anonymise)) -Depth 10 -Compress
        $json | Should -Not -Match 'P2=secret|P1=|filestreamingservice/files/0|https?://'
        $json | Should -Not -Match 'Contoso SSL Inspection'
    }

    It 'a row the time budget never reached is not collected, not failed' {
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { if ($s.Host -eq 'adl.windows.com') { [pscustomobject]@{ Tag = $s.Tag; TimedOut = $true } } else { New-FakeEndpointOutcome -Spec $s } } }
        $x = (Get-EpRow (Get-DOConnectivityMatrix) 'wu-compat')[0]
        $x['result'] | Should -Be 'not-collected'
        $x['endpoint']['err']['code'] | Should -Be 'budget-exhausted'
    }

    It 'fails the firewall check when policy blocks every inbound connection on an active profile' {
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallProfilesRaw { @([pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; AllowLocalFirewallRules = 'True'; AllowInboundRules = 'False'; DefaultInboundAction = 'Block' }) }
        $x = (Get-DOConnectivityMatrix) | Where-Object checkId -eq 'p2p-firewall-rule'
        $x.result | Should -Be 'fail'
        $x.detail | Should -Match 'AllowInboundRules=False'
    }

    It 'stays within the matrix and report caps' {
        $m = Get-DOConnectivityMatrix
        (Get-EpRows $m).Count | Should -BeLessOrEqual 40
        $m.Count | Should -BeLessOrEqual 128
    }
}

Describe 'Firewall rules as the device enforces them (NetSecurity cmdlets mocked)' {
    It 'reads the active store, the program from the application filter and the service from the service filter' {
        if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) { Set-ItResult -Skipped -Because 'the NetSecurity module is Windows only'; return }
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallRule {
            if ($PesterBoundParameters.ContainsKey('DisplayName') -or $PesterBoundParameters.ContainsKey('Name')) { @([pscustomobject]@{ InstanceID = 'r1'; DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any' }) }
            else { @([pscustomobject]@{ InstanceID = 'b1'; DisplayName = 'Baseline: block 7680'; Direction = 'Inbound'; Action = 'Block'; Enabled = 'True'; Profile = 'Public' }) }
        } -ParameterFilter { $PolicyStore -eq 'ActiveStore' }
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallPortFilter { [pscustomobject]@{ Protocol = 'TCP'; LocalPort = @('7680') } } -RemoveParameterType AssociatedNetFirewallRule
        # The real application filter has Program (and AppPath) but no Service property.
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallApplicationFilter { [pscustomobject]@{ Program = '%SystemRoot%\system32\svchost.exe'; AppPath = '%SystemRoot%\system32\svchost.exe' } } -RemoveParameterType AssociatedNetFirewallRule
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallServiceFilter { [pscustomobject]@{ Service = 'dosvc' } } -RemoveParameterType AssociatedNetFirewallRule
        $r = @(InModuleScope DoctorDO.Collector { Get-DDFirewallRulesRaw } | ForEach-Object { $_ })
        $r.Count | Should -Be 2
        @($r | Where-Object DisplayName -like 'Delivery*')[0].Service | Should -Be 'dosvc'
        @($r | Where-Object DisplayName -like 'Delivery*')[0].Program | Should -Be '%SystemRoot%\system32\svchost.exe'
        # By Name and by display name, then the inbound Block rules (the filter here has no ID, so no lookup behind it).
        Should -Invoke -ModuleName DoctorDO.Collector Get-NetFirewallRule -ParameterFilter { $PolicyStore -eq 'ActiveStore' } -Times 3 -Exactly
        @($r | Where-Object { $null -ne $_.PSObject.Properties['ReadRefused'] }).Count | Should -Be 0 -Because 'nothing was refused'
    }

    It 'returns what it read plus one ReadRefused object for a listing Windows refused, and none for a filter that matches nothing' {
        if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) { Set-ItResult -Skipped -Because 'the NetSecurity module is Windows only'; return }
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallRule {
            if ($PesterBoundParameters.ContainsKey('DisplayName')) { @([pscustomobject]@{ InstanceID = 'r1'; DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any' }) }
            else { Write-Error -Message 'No matching MSFT_NetFirewallRule objects found by CIM query' -Category ObjectNotFound }
        } -ParameterFilter { $PolicyStore -eq 'ActiveStore' }
        # Without elevation: what can be read comes back, with one "Access is denied" error.
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallPortFilter {
            if ($PesterBoundParameters.ContainsKey('PolicyStore')) {
                [pscustomobject]@{ Protocol = 'UDP'; LocalPort = @('5353') }
                Write-Error -Message 'Access is denied.' -Category PermissionDenied
            } else { [pscustomobject]@{ Protocol = 'TCP'; LocalPort = @('7680') } }
        } -RemoveParameterType AssociatedNetFirewallRule
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallApplicationFilter { [pscustomobject]@{ Program = '%SystemRoot%\system32\svchost.exe' } } -RemoveParameterType AssociatedNetFirewallRule
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallServiceFilter { [pscustomobject]@{ Service = 'dosvc' } } -RemoveParameterType AssociatedNetFirewallRule
        $r = @(InModuleScope DoctorDO.Collector { Get-DDFirewallRulesRaw } | ForEach-Object { $_ })
        @($r | Where-Object DisplayName -eq 'Delivery Optimization (TCP-In)').Count | Should -Be 1
        $refused = @($r | Where-Object { $null -ne $_.PSObject.Properties['ReadRefused'] })
        $refused.Count | Should -Be 1 -Because 'the empty Block-rule query is ObjectNotFound, not a refusal'
        $refused[0].ReadRefused | Should -Be 'the port filters'
        $refused[0].Error.Exception.Message | Should -Match 'Access is denied'
    }

    It 'finds the built-in rule on a non-English Windows by its Name, and takes every status from the active store (issue 1)' {
        if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) { Set-ItResult -Skipped -Because 'the NetSecurity module is Windows only'; return }
        # German Windows: the display name is translated, so the English display-name query finds nothing. Local rule
        # merging is off: the built-in rule is Inactive in the active store. A custom Intune rule, found only by its port
        # filter, is in force.
        $builtIn = [pscustomobject]@{ InstanceID = 'DeliveryOptimization-TCP-In'; Name = 'DeliveryOptimization-TCP-In'; DisplayName = 'Uebermittlungsoptimierung (TCP eingehend)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'
            PrimaryStatus = 'Inactive'; EnforcementStatus = @('LocalFirewallRulesNotAllowed') }
        $intune = [pscustomobject]@{ InstanceID = '{6f1e2d3c-0000-4000-8000-00000000c0de}'; Name = '{6f1e2d3c-0000-4000-8000-00000000c0de}'; DisplayName = 'Contoso - DO peers'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'
            PrimaryStatus = 'OK'; EnforcementStatus = @('NotApplicable') }
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallRule {
            if ($PesterBoundParameters.ContainsKey('DisplayName')) { return }
            if ($PesterBoundParameters.ContainsKey('Name')) {
                if (@($Name) -contains 'DeliveryOptimization*' -or @($Name) -contains 'DeliveryOptimization-TCP-In') { return $builtIn }
                if (@($Name) -contains '{6f1e2d3c-0000-4000-8000-00000000c0de}') { return $intune }
                return
            }
            Write-Error -Message 'No matching MSFT_NetFirewallRule objects found by CIM query' -Category ObjectNotFound
        } -ParameterFilter { $PolicyStore -eq 'ActiveStore' }
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallPortFilter {
            if ($PesterBoundParameters.ContainsKey('PolicyStore')) {
                [pscustomobject]@{ InstanceID = 'DeliveryOptimization-TCP-In'; Protocol = 'TCP'; LocalPort = @('7680') }
                [pscustomobject]@{ InstanceID = '{6f1e2d3c-0000-4000-8000-00000000c0de}'; Protocol = 'TCP'; LocalPort = @('7680') }
            } else { [pscustomobject]@{ Protocol = 'TCP'; LocalPort = @('7680') } }
        } -RemoveParameterType AssociatedNetFirewallRule
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallApplicationFilter { [pscustomobject]@{ Program = '%SystemRoot%\system32\svchost.exe' } } -RemoveParameterType AssociatedNetFirewallRule
        Mock -ModuleName DoctorDO.Collector Get-NetFirewallServiceFilter { [pscustomobject]@{ Service = 'dosvc' } } -RemoveParameterType AssociatedNetFirewallRule
        $r = @(InModuleScope DoctorDO.Collector { Get-DDFirewallRulesRaw } | ForEach-Object { $_ } | Where-Object { $null -eq $_.PSObject.Properties['ReadRefused'] })
        $r.Count | Should -Be 2
        ($r | Where-Object DisplayName -like 'Uebermittlung*').PrimaryStatus | Should -Be 'Inactive' -Because 'the active store says so; the stored rule behind the filter would say OK'
        ($r | Where-Object DisplayName -eq 'Contoso - DO peers').PrimaryStatus | Should -Be 'OK'
        Should -Invoke -ModuleName DoctorDO.Collector Get-NetFirewallRule -ParameterFilter { $PolicyStore -ne 'ActiveStore' } -Times 0 -Exactly -Because 'a rule is never read outside the active store'
    }
}

Describe 'Endpoint health: the on-device cache' {
    It 'reuses fresh results instead of probing again, and probes again on another subnet' {
        Initialize-FakeDevice
        $path = Join-Path (Join-Path $TestDrive ('ddep-' + [guid]::NewGuid().ToString('N'))) 'endpoint-health.json'
        try {
            InModuleScope DoctorDO.Collector -Parameters @{ P = $path; P2 = 'x' } {
                param($P, $P2)
                $ctx = New-DDContext -Salt 'abc' -ComputerName $P2
                $st = @(Get-DDDOStatusRaw)
                $net = @{ localSubnet = '10.20.4.0/22'; isVpnActive = $false }
                $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
                $a = Get-DDEndpointHealth -Context $ctx -ModeNum 2 -StatusRaw $st -Network $net -CachePath $P -MaxAgeMinutes 360 -Now $now
                $b = Get-DDEndpointHealth -Context $ctx -ModeNum 2 -StatusRaw $st -Network $net -CachePath $P -MaxAgeMinutes 360 -Now $now.AddHours(2)
                Should -Invoke Invoke-DDEndpointProbeBatch -Times 1 -Exactly
                @($b).Count | Should -Be @($a).Count
                (@($b) | Where-Object { $_['endpoint']['basis'] -eq 'documented' } | Select-Object -First 1)['endpoint']['cached'] | Should -BeTrue
                (@($b) | Select-Object -First 1)['endpoint']['at'] | Should -Be '2026-10-12T08:00:00Z'
                $null = Get-DDEndpointHealth -Context $ctx -ModeNum 2 -StatusRaw $st -Network @{ localSubnet = '192.168.1.0/24'; isVpnActive = $false } -CachePath $P -MaxAgeMinutes 360 -Now $now.AddHours(3)
                Should -Invoke Invoke-DDEndpointProbeBatch -Times 2 -Exactly
                $null = Get-DDEndpointHealth -Context $ctx -ModeNum 2 -StatusRaw $st -Network @{ localSubnet = '192.168.1.0/24'; isVpnActive = $false } -CachePath $P -MaxAgeMinutes 360 -Now $now.AddHours(10)
                Should -Invoke Invoke-DDEndpointProbeBatch -Times 3 -Exactly
            }
        } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Endpoint probe engine (real sockets on loopback)' {
    BeforeAll {
        InModuleScope DoctorDO.Collector { Initialize-DDNative }
        if (-not ('DDTest.FakeHttp' -as [type])) {
            $refs = $(if ($PSVersionTable.PSVersion.Major -ge 6) { @('System.Net.Primitives', 'System.Net.Sockets', 'System.Collections', 'System.Threading', 'System.Threading.Thread', 'System.Threading.ThreadPool', 'System.Text.Encoding.Extensions', 'System.Runtime', 'netstandard') } else { @('System.dll') })
            Add-Type -ReferencedAssemblies $refs -TypeDefinition @'
namespace DDTest
{
    using System; using System.Collections.Generic; using System.Net; using System.Net.Sockets; using System.Text; using System.Threading;
    // A loopback HTTP server (or forward proxy) that records each request head and answers with a fixed status and a
    // body far larger than the head, so a client that reads the body would be caught by the byte count it sends.
    public class FakeHttp
    {
        TcpListener l; public List<string> Requests = new List<string>(); public int Port; public int Status = 206; public int ConnectStatus = 200;
        public void Start() { l = new TcpListener(IPAddress.Loopback, 0); l.Start(); Port = ((IPEndPoint)l.LocalEndpoint).Port; Thread t = new Thread(Loop); t.IsBackground = true; t.Start(); }
        public void Stop() { try { l.Stop(); } catch (Exception) { } }
        void Loop() { while (true) { TcpClient c; try { c = l.AcceptTcpClient(); } catch (Exception) { return; } ThreadPool.QueueUserWorkItem(delegate (object o) { Handle(c); }); } }
        void Handle(TcpClient c)
        {
            try
            {
                NetworkStream s = c.GetStream(); s.ReadTimeout = 3000;
                StringBuilder sb = new StringBuilder(); byte[] b = new byte[1];
                while (sb.Length < 8192) { int n = s.Read(b, 0, 1); if (n <= 0) break; sb.Append((char)b[0]); if (sb.ToString().EndsWith("\r\n\r\n")) break; }
                string head = sb.ToString(); lock (Requests) Requests.Add(head);
                if (head.StartsWith("CONNECT")) { byte[] r = Encoding.ASCII.GetBytes("HTTP/1.1 " + ConnectStatus + " X\r\n\r\n"); s.Write(r, 0, r.Length); return; }
                string extra = Status == 206 ? "Content-Range: bytes 0-0/1048576\r\nAccept-Ranges: bytes\r\n" : "";
                byte[] h = Encoding.ASCII.GetBytes("HTTP/1.1 " + Status + " X\r\n" + extra + "Content-Length: 1048576\r\n\r\n");
                s.Write(h, 0, h.Length);
                if (!head.StartsWith("HEAD")) { byte[] body = new byte[65536]; for (int i = 0; i < 16; i++) s.Write(body, 0, body.Length); }
            }
            catch (Exception) { }
            finally { try { c.Close(); } catch (Exception) { } }
        }
    }
}
'@
        }
    }

    It 'sends HEAD and a one-byte Range request, reads only the head, and tells 206 from 200' {
        $srv = New-Object DDTest.FakeHttp; $srv.Start()
        try {
            $port = $srv.Port
            $o = InModuleScope DoctorDO.Collector -Parameters @{ Port = $port } {
                param($Port)
                Invoke-DDEndpointProbeBatch -ProbeTimeoutMs 3000 -TotalTimeoutMs 10000 -Specs @([pscustomobject]@{ Tag = 't'; Host = '127.0.0.1'; Ports = @($Port); Protocols = @('http'); Tls = $false; Http = $true; RangeUrl = "http://127.0.0.1:$Port/filestreamingservice/files/abc?P1=1"; Proxy = $null; WantAddresses = $true })
            }
            $o[0].DnsOk | Should -BeTrue
            $o[0].Ports[0].Ok | Should -BeTrue
            $o[0].HttpStatus | Should -Be 206
            $o[0].RangeStatus | Should -Be 206
            $o[0].ContentRange | Should -Be 'bytes 0-0/1048576'
            $reqs = @($srv.Requests)
            @($reqs | Where-Object { $_ -match '^HEAD / HTTP/1.1' }).Count | Should -Be 1
            $get = $reqs | Where-Object { $_ -match '^GET ' } | Select-Object -First 1
            $get | Should -Match '^GET /filestreamingservice/files/abc\?P1=1 HTTP/1.1'
            $get | Should -Match "Range: bytes=0-0`r`n"
            $srv.Status = 200
            $o2 = InModuleScope DoctorDO.Collector -Parameters @{ Port = $port } {
                param($Port)
                Invoke-DDEndpointProbeBatch -ProbeTimeoutMs 3000 -TotalTimeoutMs 10000 -Specs @([pscustomobject]@{ Tag = 't'; Host = '127.0.0.1'; Ports = @($Port); Protocols = @('http'); Tls = $false; Http = $false; RangeUrl = "http://127.0.0.1:$Port/x"; Proxy = $null; WantAddresses = $false })
            }
            $o2[0].RangeStatus | Should -Be 200
            $o2[0].RangeMs | Should -BeLessThan 3000 -Because 'the 1 MB body is never read'
        } finally { $srv.Stop() }
    }

    It 'goes through a proxy the way WinHTTP does: absolute-form for HTTP, CONNECT for HTTPS, and reports a 407' {
        $px = New-Object DDTest.FakeHttp; $px.Status = 200; $px.ConnectStatus = 407; $px.Start()
        try {
            $proxy = "127.0.0.1:$($px.Port)"
            $o = InModuleScope DoctorDO.Collector -Parameters @{ Proxy = $proxy } {
                param($Proxy)
                Invoke-DDEndpointProbeBatch -ProbeTimeoutMs 3000 -TotalTimeoutMs 15000 -Specs @(
                    [pscustomobject]@{ Tag = 'h'; Host = 'cdn.example.invalid'; Ports = @(80); Protocols = @('http'); Tls = $false; Http = $true; RangeUrl = 'http://cdn.example.invalid/f?x=1'; Proxy = $Proxy; WantAddresses = $false },
                    [pscustomobject]@{ Tag = 's'; Host = 'svc.example.invalid'; Ports = @(443); Protocols = @('https'); Tls = $true; Http = $false; RangeUrl = $null; Proxy = $Proxy; WantAddresses = $false })
            }
            $h = $o | Where-Object Tag -eq 'h'; $s = $o | Where-Object Tag -eq 's'
            $h.DnsOk | Should -BeFalse -Because '.invalid never resolves; through a proxy the probe carries on'
            $h.ProxyUsed | Should -BeTrue
            $h.HttpStatus | Should -Be 200
            $h.RangeStatus | Should -Be 200
            $s.Ports[0].Ok | Should -BeFalse
            $s.Ports[0].ProxyStatus | Should -Be 407
            $reqs = @($px.Requests)
            @($reqs | Where-Object { $_ -match '^HEAD http://cdn\.example\.invalid/ HTTP/1.1' }).Count | Should -Be 1
            @($reqs | Where-Object { $_ -match '^GET http://cdn\.example\.invalid/f\?x=1 HTTP/1.1' -and $_ -match 'Range: bytes=0-0' }).Count | Should -Be 1
            @($reqs | Where-Object { $_ -match '^CONNECT svc\.example\.invalid:443 HTTP/1.1' }).Count | Should -BeGreaterThan 0
        } finally { $px.Stop() }
    }

    It 'parses WinHTTP proxy lists and bypass lists' {
        InModuleScope DoctorDO.Collector {
            [DoctorDO.Net.WinHttpProxy]::Pick('http=p:8080;https=q:8443', 'https') | Should -Be 'q:8443'
            [DoctorDO.Net.WinHttpProxy]::Pick('http://proxy.contoso.example:3128/', 'http') | Should -Be 'proxy.contoso.example:3128'
            [DoctorDO.Net.WinHttpProxy]::Pick('proxy', 'http') | Should -Be 'proxy:80'
            [DoctorDO.Net.WinHttpProxy]::Bypassed('intranet', '<local>') | Should -BeTrue
            [DoctorDO.Net.WinHttpProxy]::Bypassed('geo.prod.do.dsp.mp.microsoft.com', '*.do.dsp.mp.microsoft.com;<local>') | Should -BeTrue
            [DoctorDO.Net.WinHttpProxy]::Bypassed('fe3.delivery.mp.microsoft.com', '*.do.dsp.mp.microsoft.com') | Should -BeFalse
        }
    }

    It 'forgets a failed WPAD lookup after ten minutes, so a long-lived session tries it again (D-13)' {
        InModuleScope DoctorDO.Collector {
            $t = [DoctorDO.Net.WinHttpProxy]
            $flags = [System.Reflection.BindingFlags]'NonPublic, Static'
            $at = $t.GetField('autoDetectFailedAt', $flags)
            $failed = $t.GetProperty('autoDetectFailed', $flags)
            $before = $at.GetValue($null)
            try {
                $at.SetValue($null, [datetime]::UtcNow.AddMinutes(-2))
                $failed.GetValue($null) | Should -BeTrue
                $at.SetValue($null, [datetime]::UtcNow.AddMinutes(-11))
                $failed.GetValue($null) | Should -BeFalse
            } finally { $at.SetValue($null, $before) }
        }
    }
}

Describe 'Bounded fetches: a PAC, and the public IP probe (real sockets on loopback)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'NetStubs.ps1')
        InModuleScope DoctorDO.Collector { Initialize-DDNative }
    }

    It 'reads a PAC served without a Content-Type, and refuses one cut short of its Content-Length (D-10)' {
        $pac = 'function FindProxyForURL(url, host) { return "DIRECT"; }'
        $noType = New-NetStub -Mode 'no-type' -Body $pac
        $short = New-NetStub -Mode 'short-body' -Body 'function FindProxyForURL('
        try {
            $r = InModuleScope DoctorDO.Collector -Parameters @{ A = $noType.Port; B = $short.Port } {
                param($A, $B)
                $f1 = Invoke-DDHttpFetch -Uri "http://127.0.0.1:$A/proxy.pac" -TimeoutMs 3000 -MaxBody 1048576 -ReadBodyFor @('')
                $f2 = Invoke-DDHttpFetch -Uri "http://127.0.0.1:$B/proxy.pac" -TimeoutMs 3000 -MaxBody 1048576 -ReadBodyFor @('')
                [pscustomobject]@{ Text = [System.Text.Encoding]::UTF8.GetString([byte[]]@($f1.Body)); State1 = (ConvertTo-DDPacFetchState -Outcome $f1); Short = $f2; State2 = (ConvertTo-DDPacFetchState -Outcome $f2) }
            }
            $r.Text | Should -Be $pac
            $r.State1 | Should -Be 'ok'
            $r.Short.BodyIncomplete | Should -BeTrue
            $r.Short.Body | Should -BeNullOrEmpty
            $r.State2 | Should -Be 'failed'
        } finally { $noType.Stop(); $short.Stop() }
    }

    It 'reads at most 65 bytes of an answer, and abandons a server that dribbles it, within the bound (D-02)' {
        $fast = New-NetStub -Mode 'dribble-body' -DribbleMs 0
        $slow = New-NetStub -Mode 'dribble-body' -DribbleMs 1000
        try {
            $r = InModuleScope DoctorDO.Collector -Parameters @{ A = $fast.Port; B = $slow.Port } {
                param($A, $B)
                $f1 = [DoctorDO.Net.EndpointProbe]::Fetch("http://127.0.0.1:$A/ip", $null, 2000, 65, [string[]]@(''))
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $f2 = [DoctorDO.Net.EndpointProbe]::Fetch("http://127.0.0.1:$B/ip", $null, 1500, 65, [string[]]@(''))
                [pscustomobject]@{ Fast = $f1; Slow = $f2; Seconds = $sw.Elapsed.TotalSeconds }
            }
            @($r.Fast.Body).Count | Should -Be 65
            $r.Fast.BodyTruncated | Should -BeTrue -Because 'it announced 100 MB'
            $r.Slow.TimedOut | Should -BeTrue
            $r.Slow.Body | Should -BeNullOrEmpty
            $r.Seconds | Should -BeLessThan 6
        } finally { $fast.Stop(); $slow.Stop() }
    }

    It 'the public IP probe returns within its bound when the server sends its headers one byte at a time (D-02)' {
        $cert = New-StubCertificate -Subject 'CN=localhost' -DnsName 'localhost'
        $stub = New-NetStub -Mode 'dribble-tls' -Cert $cert -DribbleMs 1000
        try {
            $r = InModuleScope DoctorDO.Collector -Parameters @{ P = $stub.Port } {
                param($P)
                Mock Resolve-DDUrlProxy { $null }
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $ip = Invoke-DDPublicIpProbe -Uri "https://127.0.0.1:$P/ip" -TimeoutMs 1500
                [pscustomobject]@{ Ip = $ip; Seconds = $sw.Elapsed.TotalSeconds }
            }
            $r.Ip | Should -BeNullOrEmpty
            $r.Seconds | Should -BeLessThan 8 -Because 'every stage is bounded; the earlier HttpWebRequest read the body with a 300 s per-read time-out'
            @($stub.Lines()) | Should -Contain 'GET /ip HTTP/1.1'
        } finally { $stub.Stop() }
    }

    It 'the public IP probe reads only the address: anything else, a redirect or more than 64 bytes gives nothing' {
        InModuleScope DoctorDO.Collector {
            Mock Resolve-DDUrlProxy { $null }
            Mock Invoke-DDHttpFetch { [pscustomobject]@{ Status = 200; Redirected = $false; BodyTruncated = $false; Body = [System.Text.Encoding]::ASCII.GetBytes("203.0.113.9`n") } }
            Invoke-DDPublicIpProbe -Uri 'https://ip.contoso.example/' | Should -Be '203.0.113.9'
            Should -Invoke Invoke-DDHttpFetch -Times 1 -Exactly -ParameterFilter { $MaxBody -eq 65 -and @($ReadBodyFor) -contains '' }
            Mock Invoke-DDHttpFetch { [pscustomobject]@{ Status = 200; Redirected = $false; BodyTruncated = $true; Body = [System.Text.Encoding]::ASCII.GetBytes('1' * 65) } }
            Invoke-DDPublicIpProbe -Uri 'https://ip.contoso.example/' | Should -BeNullOrEmpty
            Mock Invoke-DDHttpFetch { [pscustomobject]@{ Status = 302; Redirected = $true; BodyTruncated = $false; Body = $null } }
            Invoke-DDPublicIpProbe -Uri 'https://ip.contoso.example/' | Should -BeNullOrEmpty
            Mock Invoke-DDHttpFetch { [pscustomobject]@{ Status = 200; Redirected = $false; BodyTruncated = $false; Body = [System.Text.Encoding]::ASCII.GetBytes('not an address') } }
            Invoke-DDPublicIpProbe -Uri 'https://ip.contoso.example/' | Should -BeNullOrEmpty
            { Invoke-DDPublicIpProbe -Uri 'http://ip.contoso.example/' } | Should -Throw '*https*'
        }
    }
}
