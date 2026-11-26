#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
}

Describe 'Connectivity matrix (probes mocked)' {
    It 'covers every check family in docs/07 and uses only allowed result values' {
        Initialize-FakeDevice -CacheHost 'cache.contoso.example' -Dhcp235
        $m = Get-DOConnectivityMatrix
        $ids = $m | ForEach-Object { $_.checkId } | Select-Object -Unique
        foreach ($want in 'do-cloud-dns', 'do-cloud-tls', 'do-cloud-inspect', 'do-content-cdn', 'do-metadata-wu', 'do-range-support', 'do-content-by-caller', 'p2p-listener', 'p2p-outbound', 'p2p-inbound', 'p2p-firewall-rule', 'local-policy-merge', 'teredo-endpoint', 'teredo-state', 'mcc-config', 'mcc-dhcp-235', 'mcc-reachable', 'mcc-serving', 'proxy-tls-inspection', 'proxy-source-ip', 'proxy-scope', 'proxy-pac', 'dosvc-running', 'download-mode', 'resource-eligibility', 'adapter-eligibility',
                'do-geo', 'mcc-cache-host', 'dhcp-option-234', 'p2p-firewall-scope', 'p2p-outbound-rule', 'teredo-outbound-rule', 'do-cache-folder', 'do-state-file', 'power-upload') {
            $ids | Should -Contain $want
        }
        ($m | ForEach-Object { $_.result } | Select-Object -Unique) | Where-Object { $_ -notin 'pass', 'fail', 'warn', 'not-applicable', 'not-collected' } | Should -BeNullOrEmpty
        $m.Count | Should -BeLessOrEqual 128
    }

    It 'reports the PAC in force without its URL: not applicable without one, a warning when it proxies the DO cloud service (DO-NET-025)' {
        Initialize-FakeDevice
        (Get-DOConnectivityMatrix | Where-Object checkId -eq 'proxy-pac').result | Should -Be 'not-applicable'
        Initialize-FakeDevice -Pac proxied
        $c = Get-DOConnectivityMatrix | Where-Object checkId -eq 'proxy-pac'
        $c.result | Should -Be 'warn'
        $c.detail | Should -Match 'PAC in force \(device-wide\); names DO endpoints \(wu-content\); 1 version: it sends the DO cloud service'
        $c.evidence | Should -Be 'versions=1 scopes=device names=wu-content doCloud=proxy doContent=proxy'
        "$($c.detail) $($c.evidence) $($c.target)" | Should -Not -Match 'contoso'
    }

    It 'records the FQDN it probed, not the wildcard pattern' {
        Initialize-FakeDevice
        $m = Get-DOConnectivityMatrix
        ($m | Where-Object checkId -eq 'do-cloud-tls').target | Should -Be 'geo.prod.do.dsp.mp.microsoft.com'
        ($m | ForEach-Object { $_.target }) | Where-Object { $_ -match '\*' } | Should -BeNullOrEmpty
    }

    It 'never reports a check it did not run as a pass: with no file to test, the range check is not-collected; an idle DoSvc makes inbound a warning, not a fail' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDDOStatusRaw { @() }
        $m = Get-DOConnectivityMatrix
        ($m | Where-Object checkId -eq 'do-range-support').result | Should -Be 'not-collected'
        ($m | Where-Object checkId -eq 'do-range-support').detail | Should -Match 'only requested for a file this device downloaded'
        # DoSvc runs but holds no Listen socket on 7680 in its own TCP table: idle, as Microsoft's FAQ explains.
        $in = $m | Where-Object checkId -eq 'p2p-inbound'
        $in.result | Should -Be 'warn'
        $in.code | Should -Be 'not-listening'
        $in.detail | Should -Match 'idle'
        # Nothing asks DO to read DHCP option 235 here, so the check does not apply (not a pass, not a failure).
        ($m | Where-Object checkId -eq 'mcc-dhcp-235').result | Should -Be 'not-applicable'
    }

    It 'tests byte ranges on a file the device itself downloaded, and reads the result into do-range-support' {
        Initialize-FakeDevice
        $x = @((Get-DOConnectivityMatrix) | Where-Object checkId -eq 'do-range-support')
        $x.Count | Should -Be 1
        $x[0].result | Should -Be 'pass'
        $x[0].target | Should -Be 'tlu.dl.delivery.mp.microsoft.com'
    }

    It 'computes applicability from the download mode: LAN mode makes Teredo not-applicable, Group mode applies it' {
        Initialize-FakeDevice -DownloadMode 'Lan'
        $lan = Get-DOConnectivityMatrix
        ($lan | Where-Object checkId -eq 'teredo-endpoint').result | Should -Be 'not-applicable'
        ($lan | Where-Object checkId -eq 'teredo-state').result | Should -Be 'not-applicable'
        Initialize-FakeDevice -DownloadMode 'Group'
        $grp = Get-DOConnectivityMatrix
        # Teredo is qualified with DO's server, so UDP 3544 to it works; a resolving name alone is not a warning any more.
        ($grp | Where-Object checkId -eq 'teredo-endpoint').result | Should -Be 'pass'
        ($grp | Where-Object checkId -eq 'teredo-state').result | Should -Be 'pass'
        ($grp | Where-Object checkId -eq 'teredo-state').code | Should -Be 'qualified'
    }

    It 'with peering disabled (mode 99) the peer-to-peer checks are not-applicable, not passes' {
        Initialize-FakeDevice -DownloadMode 'Simple'
        $m = Get-DOConnectivityMatrix
        foreach ($id in 'p2p-listener', 'p2p-outbound', 'p2p-firewall-rule', 'resource-eligibility', 'adapter-eligibility') { ($m | Where-Object checkId -eq $id).result | Should -Be 'not-applicable' }
        ($m | Where-Object checkId -eq 'download-mode').result | Should -Be 'warn'
    }

    It 'a listener that is not up is a warning when idle, never a failure' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDListeningTcpPorts { @(443) }
        Mock -ModuleName DoctorDO.Collector Get-DDDOStatusRaw { @() }
        ((Get-DOConnectivityMatrix) | Where-Object checkId -eq 'p2p-listener').result | Should -Be 'warn'
    }

    It 'flags TLS inspection when the certificate issuer is not Microsoft' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { New-FakeEndpointOutcome -Spec $s -NotMicrosoft } }
        $m = Get-DOConnectivityMatrix
        $x = $m | Where-Object checkId -eq 'do-cloud-inspect'
        $x.result | Should -Be 'fail'
        $x.detail | Should -Match 'DO-NET-006'
        $x.evidence | Should -Match 'Contoso SSL Inspection CA'
        ($m | Where-Object checkId -eq 'do-cloud-tls').result | Should -Be 'pass' -Because 'the handshake itself completed'
        # The issuer's name is sent without -Anonymise only.
        ((Get-DOConnectivityMatrix -Anonymise) | Where-Object checkId -eq 'do-cloud-inspect').detail | Should -Not -Match 'Contoso'
    }

    It 'turns a black-holed endpoint into a fail with a timeout detail' {
        Initialize-FakeDevice -ProbeFailures
        $m = Get-DOConnectivityMatrix
        $cdn = $m | Where-Object checkId -eq 'do-content-cdn'
        $cdn[0].result | Should -Be 'fail'
        $cdn[0].detail | Should -Match 'timed out'
    }

    It 'fails the firewall check when a Block rule could shadow the Delivery Optimization allow rules' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            , @([pscustomobject]@{ DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '7680'; Program = $null; Service = 'dosvc' },
                [pscustomobject]@{ DisplayName = 'Baseline: block inbound'; Direction = 'Inbound'; Action = 'Block'; Enabled = 'True'; Profile = 'Any'; Protocol = 'Any'; LocalPort = 'Any'; Program = $null; Service = $null })
        }
        $x = (Get-DOConnectivityMatrix) | Where-Object checkId -eq 'p2p-firewall-rule'
        $x.result | Should -Be 'fail'
        $x.detail | Should -Match 'DO-NET-010'
    }

    It 'warns when LocalPolicyMerge is disabled' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallProfilesRaw { @([pscustomobject]@{ Name = 'Domain'; AllowLocalFirewallRules = 'False' }) }
        ((Get-DOConnectivityMatrix) | Where-Object checkId -eq 'local-policy-merge').result | Should -Be 'warn'
    }

    It 'probes the configured cache host and reports it in clear, under -Anonymise too (ADR-0031: infrastructure)' {
        Initialize-FakeDevice -CacheHost 'cache.contoso.example'
        $m = Get-DOConnectivityMatrix -Anonymise
        $x = $m | Where-Object checkId -eq 'mcc-reachable'
        $x.target | Should -Be 'cache.contoso.example'
        $x.result | Should -Be 'pass'
    }
}

Describe 'Probe engine (real sockets on loopback)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'NetStubs.ps1')
        InModuleScope DoctorDO.Collector { Initialize-DDNative }
    }

    It 'peer probes tell an open port from a refused one, on the endpoint engine, each bounded by the probe timeout' {
        InModuleScope DoctorDO.Collector {
            $open = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $open.Start()
            try {
                $closed = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $closed.Start(); $closedPort = $closed.LocalEndpoint.Port; $closed.Stop()
                $specs = @(
                    [pscustomobject]@{ Kind = 'tcp'; Target = '127.0.0.1'; Port = $open.LocalEndpoint.Port; Tag = 'open' },
                    [pscustomobject]@{ Kind = 'tcp'; Target = '127.0.0.1'; Port = $closedPort; Tag = 'closed' },
                    [pscustomobject]@{ Kind = 'dns'; Target = 'localhost'; Port = 0; Tag = 'dns' })
                # Windows retries a connect that is refused for about two seconds before failing it (observed on Windows 11),
                # so the per-probe bound there must be longer for "refused" to be told apart from "timed out".
                $probeMs = $(if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') { 3000 } else { 1500 })
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $r = Invoke-DDNetProbeBatch -Specs $specs -ProbeTimeoutMs $probeMs -TotalTimeoutMs 10000
                $sw.Stop()
                $by = @{}; foreach ($x in $r) { $by[$x.Tag] = $x }
                @($r).Count | Should -Be 3
                $by['open'].Ok | Should -BeTrue
                $by['closed'].Ok | Should -BeFalse
                $by['closed'].TimedOut | Should -BeFalse
                $by['closed'].Error | Should -Match '^SocketException ConnectionRefused$' -Because 'the socket error by name, not a localised message'
                # Only TCP connects remain: the DNS, TLS and byte-range probe kinds were never used and are not compiled.
                $by['dns'].Ok | Should -BeFalse
                $by['dns'].Error | Should -Be 'unknown probe kind'
                ('DoctorDO.Net.Probe' -as [type]) | Should -BeNullOrEmpty
                $sw.Elapsed.TotalSeconds | Should -BeLessThan 6 -Because 'probes run in parallel and each is bounded'
            } finally { $open.Stop() }
        }
    }

    It 'bounds a stage that never answers: a TLS handshake to a silent listener times out at the probe timeout' {
        InModuleScope DoctorDO.Collector {
            $silent = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $silent.Start()   # accepts, never speaks TLS
            try {
                $row = New-Object DoctorDO.Net.EndpointRowSpec
                $row.Tag = 'hang'; $row.Host = '127.0.0.1'; $row.Ports = [int[]]@($silent.LocalEndpoint.Port); $row.Protocols = [string[]]@('https'); $row.Tls = $true
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $o = [DoctorDO.Net.EndpointProbe]::Run($row, 1500)
                $sw.Stop()
                $o.Ports[0].Ok | Should -BeTrue
                $o.TlsHandshake | Should -BeFalse
                $o.TlsError | Should -Match 'timeout'
                $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
            } finally { $silent.Stop() }
        }
    }

    It 'honours the total budget: a row still running when the budget ends is reported, not awaited' {
        InModuleScope DoctorDO.Collector {
            $silent = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $silent.Start()
            try {
                $row = New-Object DoctorDO.Net.EndpointRowSpec
                $row.Tag = 'slow'; $row.Host = '127.0.0.1'; $row.Ports = [int[]]@($silent.LocalEndpoint.Port); $row.Protocols = [string[]]@('https'); $row.Tls = $true
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $r = [DoctorDO.Net.EndpointProbe]::RunRows(@($row), 8000, 1000, 8)
                $sw.Stop()
                $r[0].TimedOut | Should -BeTrue
                $sw.Elapsed.TotalSeconds | Should -BeLessThan 4
            } finally { $silent.Stop() }
        }
    }

    It 'reports a proxy that refuses CONNECT (reset, or an answer that is not HTTP) as a failure, and only a silent one as a time-out (D-08)' -ForEach @(
        @{ Mode = 'reset'; TimedOut = $false }
        @{ Mode = 'html'; TimedOut = $false }
        @{ Mode = 'silent'; TimedOut = $true }
    ) {
        $stub = New-NetStub -Mode $Mode
        try {
            InModuleScope DoctorDO.Collector -Parameters @{ P = $stub.Port; T = $TimedOut } {
                param($P, $T)
                $row = New-Object DoctorDO.Net.EndpointRowSpec
                # A name that never resolves (RFC 6761): through a proxy the device need not resolve it, and no direct
                # comparison is attempted, so nothing leaves the loopback interface.
                $row.Tag = 'x'; $row.Host = 'doctordo-test.invalid'; $row.Ports = [int[]]@(443); $row.Protocols = [string[]]@('https'); $row.Tls = $true; $row.Proxy = "127.0.0.1:$P"
                $o = [DoctorDO.Net.EndpointProbe]::Run($row, 1500)
                $o.Ports[0].Ok | Should -BeFalse
                $o.Ports[0].TimedOut | Should -Be $T
                $o.Ports[0].Error | Should -Match '^proxy CONNECT '
                $o.DirectAttempted | Should -BeFalse
            }
        } finally { $stub.Stop() }
    }

    It 'through a proxy, an HTTP port reaches only the proxy and says so (D-09)' {
        $stub = New-NetStub -Mode 'silent'
        try {
            InModuleScope DoctorDO.Collector -Parameters @{ P = $stub.Port } {
                param($P)
                $row = New-Object DoctorDO.Net.EndpointRowSpec
                $row.Tag = 'x'; $row.Host = 'doctordo-test.invalid'; $row.Ports = [int[]]@(80); $row.Protocols = [string[]]@('http'); $row.Proxy = "127.0.0.1:$P"
                $o = [DoctorDO.Net.EndpointProbe]::Run($row, 1500)
                $o.Ports[0].Ok | Should -BeTrue
                $o.Ports[0].ProxyOnly | Should -BeTrue -Because 'no CONNECT is sent for an HTTP port; the connection reached the proxy only'
            }
        } finally { $stub.Stop() }
    }
}

Describe 'TLS inspection: who issued the certificate is judged on the issuing chain, never the leaf''s subject (D-01)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'NetStubs.ps1')
        InModuleScope DoctorDO.Collector { Initialize-DDNative }
        # A substitute certificate an inspecting proxy could present: issued by its own CA, its subject copied from the
        # Microsoft origin certificate (O=Microsoft Corporation, the host's name).
        $script:InspectorCa = New-StubCertificate -Subject 'CN=Contoso TLS Inspection CA, O=Contoso' -Ca
        $script:Cloned = New-StubCertificate -Subject 'CN=doctordo-test.invalid, O=Microsoft Corporation, L=Redmond, S=WA, C=US' -Issuer $script:InspectorCa -DnsName 'doctordo-test.invalid'
    }

    It 'a cloned Microsoft subject issued by another CA is not Microsoft''s, with or without the inspector''s CA in the chain' {
        $chain = New-StubChain -Leaf $script:Cloned -Extra @($script:InspectorCa)
        @($chain.ChainElements).Count | Should -BeGreaterOrEqual 2 -Because 'the test builds the issuing chain from the throwaway CA'
        [DoctorDO.Net.EndpointProbe]::IssuedByMicrosoft($script:Cloned, $chain) | Should -BeFalse
        [DoctorDO.Net.EndpointProbe]::IssuedByMicrosoft($script:Cloned, $null) | Should -BeFalse
    }

    It 'Microsoft CA names under a root that is neither Microsoft''s nor one that cross-signs Microsoft''s CAs are not Microsoft''s' {
        $root = New-StubCertificate -Subject 'CN=Contoso Root, O=Contoso' -Ca
        $copied = New-StubCertificate -Subject 'CN=Microsoft Azure RSA TLS Issuing CA 99, O=Microsoft Corporation, C=US' -Issuer $root -Ca
        $leaf = New-StubCertificate -Subject 'CN=doctordo-test.invalid' -Issuer $copied -DnsName 'doctordo-test.invalid'
        [DoctorDO.Net.EndpointProbe]::IssuedByMicrosoft($leaf, (New-StubChain -Leaf $leaf -Extra @($copied, $root))) | Should -BeFalse
    }

    It 'a chain of Microsoft-named certification authorities is Microsoft''s, judged by name (the limit of this check)' {
        $root = New-StubCertificate -Subject 'CN=Microsoft Test Root Certificate Authority, O=Microsoft Corporation, C=US' -Ca
        $issuing = New-StubCertificate -Subject 'CN=Microsoft Test TLS Issuing CA 01, O=Microsoft Corporation, C=US' -Issuer $root -Ca
        $leaf = New-StubCertificate -Subject 'CN=doctordo-test.invalid' -Issuer $issuing -DnsName 'doctordo-test.invalid'
        [DoctorDO.Net.EndpointProbe]::IssuedByMicrosoft($leaf, (New-StubChain -Leaf $leaf -Extra @($issuing, $root))) | Should -BeTrue
        # With no chain beyond the leaf, its issuer's name is all there is.
        [DoctorDO.Net.EndpointProbe]::IssuedByMicrosoft($leaf, $null) | Should -BeTrue
        # A name that only contains "Microsoft" in another attribute is not a Microsoft CA.
        $odd = New-StubCertificate -Subject 'CN=Contoso Issuing CA, OU=Microsoft Corporation, O=Contoso' -Ca
        $leaf2 = New-StubCertificate -Subject 'CN=doctordo-test.invalid, O=Microsoft Corporation' -Issuer $odd -DnsName 'doctordo-test.invalid'
        [DoctorDO.Net.EndpointProbe]::IssuedByMicrosoft($leaf2, (New-StubChain -Leaf $leaf2 -Extra @($odd))) | Should -BeFalse
    }

    It 'through an inspecting proxy (CA not trusted), a pinned endpoint fails as inspected, and the field and the words agree' {
        $stub = New-NetStub -Mode 'inspect' -Cert $script:Cloned
        try {
            $o = InModuleScope DoctorDO.Collector -Parameters @{ P = $stub.Port } {
                param($P)
                $row = New-Object DoctorDO.Net.EndpointRowSpec
                $row.Tag = 'x'; $row.Host = 'doctordo-test.invalid'; $row.Ports = [int[]]@(443); $row.Protocols = [string[]]@('https'); $row.Tls = $true; $row.Proxy = "127.0.0.1:$P"
                [DoctorDO.Net.EndpointProbe]::Run($row, 3000)
            }
            # (The TCP stage opens and closes one tunnel before the handshake opens another: the stub sees one cut short.)
            $o.TlsHandshake | Should -BeTrue -Because $o.TlsError
            $o.CertSeen | Should -BeTrue
            $o.ChainMicrosoft | Should -BeFalse -Because 'the leaf''s subject says Microsoft, its issuer does not'
            $o.ChainOk | Should -BeFalse
            $o.Issuer | Should -Match 'Contoso TLS Inspection CA'
            $r = InModuleScope DoctorDO.Collector -Parameters @{ O = $o } {
                param($O)
                $m = Get-DDEndpointManifest
                $e = @($m['endpoints']) | Where-Object { $_['id'] -eq 'do-cloud' } | Select-Object -First 1
                $row = [pscustomobject]@{ Id = 'do-cloud'; Entry = $e; Ports = @(443); Protocols = @('https'); PrimaryPort = 443; PrimaryProtocol = 'https'; Host = 'doctordo-test.invalid'; Basis = 'documented'; RangeUrl = $null; RangeSize = $null; Skip = $null }
                ConvertTo-DDEndpointResult -Row $row -Outcome $O -Proxy ([pscustomobject]@{ Source = 'netsh'; Proxy = '127.0.0.1:1'; Error = $null; Context = 'no-user' }) -Context (New-DDContext -Salt 'aa') -At '2026-10-19T08:00:00Z'
            }
            $r['endpoint']['tls'] | Should -Be 'fail'
            $r['endpoint']['err']['code'] | Should -Be 'tls-inspected'
            $r['endpoint']['cert']['issuer'] | Should -Be 'untrusted'
            $r['detail'] | Should -Match "Contoso TLS Inspection CA"
            $r['detail'] | Should -Not -Match 'issued by Microsoft'
        } finally { $stub.Stop() }
    }

    It 'describes an untrusted chain issued by Microsoft as Microsoft''s, never as "not Microsoft"' {
        $r = InModuleScope DoctorDO.Collector {
            $m = Get-DDEndpointManifest
            $e = @($m['endpoints']) | Where-Object { $_['id'] -eq 'store-catalog' } | Select-Object -First 1
            $row = [pscustomobject]@{ Id = 'store-catalog'; Entry = $e; Ports = @(443); Protocols = @('https'); PrimaryPort = 443; PrimaryProtocol = 'https'; Host = 'displaycatalog.mp.microsoft.com'; Basis = 'documented'; RangeUrl = $null; RangeSize = $null; Skip = $null }
            $spec = [pscustomobject]@{ Tag = 'x'; Host = 'displaycatalog.mp.microsoft.com'; Ports = @(443); Protocols = @('https'); Tls = $true; Http = $false; RangeUrl = $null; WantAddresses = $false }
            $o = New-FakeEndpointOutcome -Spec $spec -Untrusted
            ConvertTo-DDEndpointResult -Row $row -Outcome $o -Proxy $null -Context (New-DDContext -Salt 'aa' -Anonymise) -At '2026-10-19T08:00:00Z'
        }
        $r['endpoint']['cert']['issuer'] | Should -Be 'microsoft'
        $r['endpoint']['err']['code'] | Should -Be 'tls-untrusted'
        $r['detail'] | Should -Match 'issuer a Microsoft certification authority'
        $r['detail'] | Should -Not -Match 'not Microsoft'
    }
}

Describe 'Teredo state: the operational State, not only the configured Type (D-04, D-11)' {
    It 'reads <Name>' -ForEach @(
        @{ Name = 'qualified'; Raw = @{ Type = 2; ServerName = 'win1910.ipv6.microsoft.com.'; StatePresent = $true; State = 'qualified'; Error = 'none' }; Result = 'pass'; Code = 'qualified'; Endpoint = 'pass' }
        @{ Name = 'dormant'; Raw = @{ Type = 0; ServerName = 'win1910.ipv6.microsoft.com.'; StatePresent = $true; State = 'Dormant'; Error = 'none' }; Result = 'pass'; Code = 'dormant'; Endpoint = 'not-collected' }
        @{ Name = 'offline with an error'; Raw = @{ Type = 6; ServerName = 'win1910.ipv6.microsoft.com.'; StatePresent = $true; State = 'offline'; Error = 'client is in a managed network' }; Result = 'warn'; Code = 'offline'; Endpoint = 'not-collected' }
        @{ Name = 'not active (no state object)'; Raw = @{ Type = 0; ServerName = 'win1910.ipv6.microsoft.com.'; StatePresent = $false; State = $null; Error = $null }; Result = 'warn'; Code = 'inactive'; Endpoint = 'not-collected' }
        @{ Name = 'disabled'; Raw = @{ Type = 4; ServerName = 'win1910.ipv6.microsoft.com.'; StatePresent = $false; State = $null; Error = $null }; Result = 'fail'; Code = 'disabled'; Endpoint = 'not-collected' }
        @{ Name = 'qualified with another server'; Raw = @{ Type = 2; ServerName = 'teredo.contoso.example'; StatePresent = $true; State = 'qualified'; Error = 'none' }; Result = 'pass'; Code = 'qualified'; Endpoint = 'not-collected' }
    ) {
        Initialize-FakeDevice -DownloadMode 'Group'
        $global:DDTeredoRaw = [pscustomobject]$Raw
        Mock -ModuleName DoctorDO.Collector Get-DDTeredoStateRaw { $global:DDTeredoRaw }
        $m = Get-DOConnectivityMatrix
        $t = $m | Where-Object checkId -eq 'teredo-state'
        $t.result | Should -Be $Result
        $t.code | Should -Be $Code
        $t.evidence | Should -Match 'source=cim'
        ($m | Where-Object checkId -eq 'teredo-endpoint').result | Should -Be $Endpoint
        Should -Invoke -ModuleName DoctorDO.Collector Get-DDTeredoStateText -Times 0 -Exactly -Because 'the language-independent classes come first'
    }

    It 'falls back to netsh when the Teredo classes cannot be read, and records not collected when netsh is not in English' {
        Initialize-FakeDevice -DownloadMode 'Group'
        Mock -ModuleName DoctorDO.Collector Get-DDTeredoStateRaw { throw [System.Management.Automation.CommandNotFoundException]::new('Get-CimInstance') }
        Mock -ModuleName DoctorDO.Collector Get-DDTeredoStateText { @('Teredo Parameters', '---', 'Type                    : client', 'Server Name             : win1910.ipv6.microsoft.com.', 'State                   : offline', 'Error                   : none') }
        $t = (Get-DOConnectivityMatrix) | Where-Object checkId -eq 'teredo-state'
        $t.result | Should -Be 'warn'
        $t.evidence | Should -Match 'source=netsh'
        Mock -ModuleName DoctorDO.Collector Get-DDTeredoStateText { @('Teredo-Parameter', 'Typ : Client', 'Zustand : offline') }
        $m = InModuleScope DoctorDO.Collector { $c = New-DDContext -Salt 'aa'; $x = Get-DDConnectivityMatrix -Context $c -DoEffective @{ DODownloadMode = @{ value = 3 } }; [pscustomobject]@{ M = $x; N = $c.NotCollected.ToArray() } }
        ($m.M | Where-Object { $_['checkId'] -eq 'teredo-state' })['result'] | Should -Be 'not-collected'
        ($m.N | Where-Object { $_['field'] -eq 'connectivity.teredo-state' }).detail | Should -Match 'English'
    }
}

Describe 'A failed run-time compile degrades the peer probes, never the collection (D-03)' {
    It 'records the peer probes as not collected and still builds the rest of the matrix' {
        Initialize-FakeDevice -DownloadMode 'Group'
        Mock -ModuleName DoctorDO.Collector Invoke-DDNetProbeBatch { throw [System.NotSupportedException]::new('Constrained Language Mode or application control: runtime-compiled native code is not allowed') }
        $r = InModuleScope DoctorDO.Collector {
            $c = New-DDContext -Salt 'aa'
            $x = Get-DDConnectivityMatrix -Context $c -DoEffective @{ DODownloadMode = @{ value = 2 } } -PeerAddresses @('10.20.4.55')
            [pscustomobject]@{ M = $x; N = $c.NotCollected.ToArray() }
        }
        $p = $r.M | Where-Object { $_['checkId'] -eq 'p2p-outbound' }
        $p['result'] | Should -Be 'not-collected'
        $p['detail'] | Should -Match 'could not run'
        ($r.N | Where-Object { $_['field'] -eq 'connectivity.peers' }) | Should -Not -BeNullOrEmpty
        @($r.M | Where-Object { $_['checkId'] -eq 'p2p-firewall-rule' }).Count | Should -Be 1
    }

    It 'a fleet run whose matrix throws still reports, with connectivity not collected (exit 0, not 3)' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDConnectivityMatrix { throw [System.InvalidOperationException]::new('boom') }
        Mock -ModuleName DoctorDO.Collector Send-DoctorDOReport { [pscustomobject]@{ Outcome = 'Accepted'; StatusCode = 202; RetryAfterSeconds = $null; Kind = $Report['kind']; CompressedBytes = 1; BudgetResult = 'within'; ExitCode = 0; Message = 'Accepted.' } }
        $st = Join-Path $TestDrive 'state\state.json'
        $r = Invoke-DoctorDOCollector -Fleet -IngestUri 'https://ingest.contoso.example/v1/ingest' -StatePath $st
        $r.ExitCode | Should -Be 0 -Because $r.Outcome
        ($r.NotCollected | Where-Object { $_['field'] -eq 'connectivity' }).detail | Should -Be 'boom'
    }

    It 'Initialize-DDNative refuses outside Full Language mode with a typed error, like the DHCP helper' {
        $src = (Get-Command -Module DoctorDO.Collector -Name Get-DOConnectivityMatrix).Module.Invoke({ ${function:Initialize-DDNative}.ToString() })
        $guard = $src.IndexOf('Test-DDFullLanguage')
        $guard | Should -BeGreaterThan 0
        $guard | Should -BeLessThan $src.IndexOf('Add-Type -Verbose') -Because 'the language mode is checked before anything is compiled'
    }
}

Describe 'TCP 7680 listener: a transfer is active only while downloading or with a peer connection (A-06)' {
    BeforeEach {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDListeningTcpPorts { @() }
        $script:Matrix = {
            param($Status, $Vitals = @{ onBattery = $false }, $Network = $null, $PeerConnection = $null)
            InModuleScope DoctorDO.Collector -Parameters @{ S = $Status; V = $Vitals; N = $Network; P = $PeerConnection } {
                param($S, $V, $N, $P)
                $rows = @($S | ForEach-Object { [ordered]@{ status = $_ } })
                $x = Get-DDConnectivityMatrix -Context (New-DDContext -Salt 'aa') -DoEffective @{ DODownloadMode = @{ value = 1 } } -ObservedStatus $rows -Vitals $V -Network $N -DoSvc ([pscustomobject]@{ Status = 'Running'; StartType = 'Manual' }) -DoSvcListening $false -DoSvcPeerConnection $P -SkipProbes
                $x | Where-Object { $_['checkId'] -eq 'p2p-listener' }
            }
        }
    }

    It 'a cached job without a listener is a warning, not a failure' {
        $l = & $script:Matrix @('Caching')
        $l['result'] | Should -Be 'warn'
        $l['detail'] | Should -Match "cached \('Caching'\)"
    }

    It 'a cached job without a listener names the reasons the device shows (battery, VPN, cellular)' {
        $l = & $script:Matrix @('Caching') @{ onBattery = $true } @{ isVpnActive = $true; adapterType = 'Cellular'; proxy = @{ configured = $false } }
        $l['result'] | Should -Be 'warn'
        $l['detail'] | Should -Match 'on battery'
        $l['detail'] | Should -Match 'VPN'
        $l['detail'] | Should -Match 'cellular'
    }

    It 'a download without a listener fails when no documented reason applies, and warns when one does' {
        (& $script:Matrix @('Downloading'))['result'] | Should -Be 'fail'
        $w = & $script:Matrix @('Downloading') @{ onBattery = $true }
        $w['result'] | Should -Be 'warn'
        $w['detail'] | Should -Match 'Microsoft documents'
    }

    It 'an established peer connection in DoSvc''s TCP table counts as a transfer' {
        (& $script:Matrix @() @{ onBattery = $false } $null $true)['result'] | Should -Be 'fail'
        (& $script:Matrix @() @{ onBattery = $false } $null $false)['result'] | Should -Be 'warn'
        InModuleScope DoctorDO.Collector {
            Test-DDDoSvcPeerConnection -Connections @([pscustomobject]@{ LocalPort = 51234; RemotePort = 7680; State = 'Established' }) | Should -BeTrue
            Test-DDDoSvcPeerConnection -Connections @([pscustomobject]@{ LocalPort = 7680; RemotePort = 0; State = 'Listen' }) | Should -BeFalse
            Test-DDDoSvcPeerConnection -Connections @([pscustomobject]@{ LocalPort = 51234; RemotePort = 443; State = 'Established' }) | Should -BeFalse
        }
    }
}
