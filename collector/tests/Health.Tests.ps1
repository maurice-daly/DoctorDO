#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Delivery Optimization health (Private/Health.ps1): the troubleshooter-parity checks. Pure functions are tested directly;
# the end-to-end cases run the whole collection with every Windows call mocked (TestHelpers.ps1).
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
}

Describe 'Firewall port conditions and remote scope' {
    It 'matches an explicit port, a range and a list, and never "Any" or a keyword' {
        InModuleScope DoctorDO.Collector {
            Test-DDPortSpec -Spec '7680' -Port 7680 | Should -BeTrue
            Test-DDPortSpec -Spec '7000-8000' -Port 7680 | Should -BeTrue
            Test-DDPortSpec -Spec '443, 7680' -Port 7680 | Should -BeTrue
            Test-DDPortSpec -Spec 'Any' -Port 7680 | Should -BeFalse
            Test-DDPortSpec -Spec 'RPC' -Port 7680 | Should -BeFalse
            Test-DDPortSpec -Spec '' -Port 7680 | Should -BeFalse
        }
    }

    It 'reduces remote addresses to a category and a count, never keeping an address' {
        InModuleScope DoctorDO.Collector {
            (Get-DDRemoteScope -Addresses @('Any')).Scope | Should -Be 'any'
            (Get-DDRemoteScope -Addresses @()).Scope | Should -Be 'any'
            (Get-DDRemoteScope -Addresses @('LocalSubnet')).Scope | Should -Be 'local-subnet'
            $r = Get-DDRemoteScope -Addresses @('10.0.0.0/8', '192.168.1.1-192.168.1.20')
            $r.Scope | Should -Be 'ranges'; $r.Count | Should -Be 2
            (Get-DDRemoteScope -Addresses @('Intranet')).Scope | Should -Be 'keywords'
            (Get-DDRemoteScope -Addresses @('LocalSubnet', '10.0.0.0/8')).Scope | Should -Be 'mixed'
            (Get-DDRemoteScope -Addresses @('LocalSubnet', 'Any')).Scope | Should -Be 'any'
        }
    }

    It 'maps a rule with its status, remote port and scope, and drops the addresses' {
        InModuleScope DoctorDO.Collector {
            $r = (ConvertFrom-DDFirewallRaw -Rules @([pscustomobject]@{ DisplayName = 'Contoso DO peers'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Domain'
                        Protocol = 'TCP'; LocalPort = '7680'; RemotePort = 'Any'; RemoteAddress = @('LocalSubnet'); PrimaryStatus = 'OK'; EnforcementStatus = @('NotApplicable'); Program = $null; Service = $null }))[0]
            $r['remoteScope'] | Should -Be 'local-subnet'
            $r['remoteAddresses'] | Should -Be 0
            $r['primaryStatus'] | Should -Be 'OK'
            $r['remotePort'] | Should -Be 'Any'
            $r.Contains('remoteAddress') | Should -BeFalse
            $r.Contains('enforcementStatus') | Should -BeFalse -Because 'NotApplicable says nothing'
        }
    }
}

Describe 'The adapter Delivery Optimization uses' {
    It 'takes the first physical adapter that is up with a usable IPv4 address, else the first virtual one' {
        InModuleScope DoctorDO.Collector {
            $c = @(
                [pscustomobject]@{ Order = 0; Id = '{v}'; Name = 'vEthernet (Default Switch)'; Up = $true; IfType = 6; IfIndex = 30; ConnectorPresent = $false; IPv4 = @([pscustomobject]@{ Address = '172.20.0.1'; PrefixLength = 20 }) },
                [pscustomobject]@{ Order = 1; Id = '{d}'; Name = 'Ethernet 2'; Up = $false; IfType = 6; IfIndex = 5; ConnectorPresent = $true; IPv4 = @([pscustomobject]@{ Address = '10.1.1.5'; PrefixLength = 24 }) },
                [pscustomobject]@{ Order = 2; Id = '{l}'; Name = 'Ethernet'; Up = $true; IfType = 6; IfIndex = 7; ConnectorPresent = $true; IPv4 = @([pscustomobject]@{ Address = '169.254.10.2'; PrefixLength = 16 }) },
                [pscustomobject]@{ Order = 3; Id = '{w}'; Name = 'Wi-Fi'; Up = $true; IfType = 71; IfIndex = 12; ConnectorPresent = $true; IPv4 = @([pscustomobject]@{ Address = '10.20.9.41'; PrefixLength = 22 }) })
            $p = Select-DDDoAdapter -Candidates $c -DefaultInterfaceIndex 30
            $p.Name | Should -Be 'Wi-Fi'
            $p.Kind | Should -Be 'physical'
            $p.Type | Should -Be 'Wi-Fi'
            $p.DefaultRoute | Should -BeFalse -Because 'the default route here is the virtual switch'
            $v = Select-DDDoAdapter -Candidates @($c[0], $c[1], $c[2])
            $v.Name | Should -Be 'vEthernet (Default Switch)'
            $v.Kind | Should -Be 'virtual'
            Select-DDDoAdapter -Candidates @($c[1], $c[2]) | Should -BeNullOrEmpty
        }
    }

    It 'reports the DO adapter''s subnet as localSubnet and keeps the default route''s when it differs' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDAdapterCandidatesRaw {
            , @([pscustomobject]@{ Order = 0; Id = '{w}'; Name = 'Wi-Fi'; Up = $true; IfType = 71; IfIndex = 12; ConnectorPresent = $true; IPv4 = @([pscustomobject]@{ Address = '10.20.9.41'; PrefixLength = 24 }) })
        }
        $inv = Get-DOInventory -StatePath (Join-Path ([System.IO.Path]::GetTempPath()) ("dd-{0}.json" -f [guid]::NewGuid().ToString('N')))
        $inv.network.localSubnet | Should -Be '10.20.9.0/24'
        $inv.network.defaultRouteSubnet | Should -Be '10.20.4.0/22'
        $inv.network.doAdapter.type | Should -Be 'Wi-Fi'
        $inv.network.doAdapter.defaultRoute | Should -BeFalse
        $inv.network.doAdapter.name | Should -Be 'Wi-Fi'
        (Get-DOInventory -StatePath (Join-Path ([System.IO.Path]::GetTempPath()) ("dd-{0}.json" -f [guid]::NewGuid().ToString('N'))) -Anonymise).network.doAdapter.name | Should -BeNullOrEmpty
    }
}

Describe 'DHCP options 234 and 235' {
    It 'reads text options, and tells "not offered" (the subnet mask came back) from "unreadable"' {
        InModuleScope DoctorDO.Collector {
            ConvertFrom-DDDhcpText -Bytes ([System.Text.Encoding]::ASCII.GetBytes("mcc01.contoso.example`0")) | Should -Be 'mcc01.contoso.example'
            ConvertFrom-DDDhcpText -Bytes ([byte[]](1, 2, 3)) | Should -BeNullOrEmpty
            $ok = [pscustomobject]@{ Attempted = $true; TimedOut = $false; Win32Error = 0; Options = @(
                    [pscustomobject]@{ OptionId = 1; Present = $true; Data = [byte[]](255, 255, 255, 0) },
                    [pscustomobject]@{ OptionId = 235; Present = $false; Data = $null }) }
            $r = ConvertFrom-DDDhcpOutcome -Wants @('235') -Outcome $ok
            $r.Facts['state'] | Should -Be 'answered'
            $r.Facts['subnetMask'] | Should -BeTrue
            $r.Facts['option235'] | Should -Be 'absent'
            (ConvertFrom-DDDhcpOutcome -Wants @('235') -Outcome ([pscustomobject]@{ Attempted = $true; TimedOut = $true; Win32Error = 0; Options = @() })).Facts['state'] | Should -Be 'timeout'
            $f = (ConvertFrom-DDDhcpOutcome -Wants @('234') -Outcome ([pscustomobject]@{ Attempted = $true; TimedOut = $false; Win32Error = 2; Options = @() })).Facts
            $f['state'] | Should -Be 'api-failed'; $f['win32Error'] | Should -Be 2
            (ConvertFrom-DDDhcpOutcome -Wants @()).Facts['state'] | Should -Be 'not-queried'
            (ConvertFrom-DDDhcpOutcome -Wants @('235') -Unavailable).Facts['state'] | Should -Be 'unavailable'
        }
    }

    It 'asks only for what DO itself reads: 234 with DOGroupIdSource 3, 235 with DOCacheHostSource or the service flag' {
        InModuleScope DoctorDO.Collector {
            $e = { param($h) $o = [ordered]@{}; foreach ($k in $h.Keys) { $o[$k] = [ordered]@{ value = $h[$k]; provider = 'Mdm' } }; $o }
            @(Get-DDDhcpWants -Effective (& $e @{ DOGroupIdSource = 3 })) | Should -Be @('234')
            @(Get-DDDhcpWants -Effective (& $e @{ DOCacheHostSource = 2 })) | Should -Be @('235')
            @(Get-DDDhcpWants -Effective (& $e @{}) -Geo ([pscustomobject]@{ CacheHostFlag = $true })) | Should -Be @('235')
            @(Get-DDDhcpWants -Effective (& $e @{ DOGroupIdSource = 1 })).Count | Should -Be 0
        }
    }

    It 'reads option 235 on the DO adapter when DOCacheHostSource is set, and sends it in clear (infrastructure)' {
        Initialize-FakeDevice -Dhcp235
        $inv = Get-DOInventory -StatePath (Join-Path ([System.IO.Path]::GetTempPath()) ("dd-{0}.json" -f [guid]::NewGuid().ToString('N'))) -Anonymise
        $inv.network.dhcpOption235 | Should -Be '10.20.9.15'
        $inv.network.dhcp.state | Should -Be 'answered'
        $inv.network.dhcp.option235 | Should -Be 'received'
        $c = $inv.connectivity | Where-Object checkId -eq 'mcc-dhcp-235'
        $c.result | Should -Be 'pass'
        $c.target | Should -Be '10.20.9.15'
        $h = $inv.connectivity | Where-Object checkId -eq 'mcc-cache-host'
        $h.code | Should -Be 'dhcp'
        $h.target | Should -Be '10.20.9.15'
        Should -Invoke -ModuleName DoctorDO.Collector Get-DDDhcpOptionsRaw -ParameterFilter { $AdapterId -eq '{8A63F27C-0000-4000-8000-000000000007}' -and ($OptionIds -contains 1) -and ($OptionIds -contains 235) }
    }

    It 'hashes option 234 under -Anonymise, like DOGroupId' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDRegistryValues {
            if ($Path -match 'Policies\\Microsoft\\Windows\\DeliveryOptimization$') { @{ Present = $true; Values = @([ordered]@{ name = 'DODownloadMode'; type = 'REG_DWORD'; data = '2' }, [ordered]@{ name = 'DOGroupIdSource'; type = 'REG_DWORD'; data = '3' }) } }
            else { @{ Present = $false; Values = @() } }
        }
        Mock -ModuleName DoctorDO.Collector Get-DDDhcpOptionsRaw {
            [pscustomobject]@{ Attempted = $true; TimedOut = $false; Win32Error = 0; Options = @(foreach ($id in $OptionIds) { [pscustomobject]@{ OptionId = $id; Present = $true; Data = $(if ($id -eq 1) { [byte[]](255, 255, 252, 0) } else { [System.Text.Encoding]::ASCII.GetBytes('a1b2c3d4-0000-4000-8000-0000000000aa') }) } }) }
        }
        $inv = Get-DOInventory -StatePath (Join-Path ([System.IO.Path]::GetTempPath()) ("dd-{0}.json" -f [guid]::NewGuid().ToString('N'))) -Anonymise
        $inv.network.dhcpOption234 | Should -Match '^redacted:[0-9a-f]{16}$'
        ($inv.connectivity | Where-Object checkId -eq 'dhcp-option-234').result | Should -Be 'pass'
    }

    It 'says why 235 did not arrive: a UDP 68 block rule and local rule merging turned off' {
        InModuleScope DoctorDO.Collector {
            $rules = @([ordered]@{ displayName = 'Block DHCP in'; direction = 'Inbound'; action = 'Block'; enabled = $true; protocol = 'UDP'; localPort = '68'; remotePort = 'Any'; program = $null; service = $null; profiles = @('Public') })
            $h = @(Get-DDDhcpBlockHints -Rules $rules -LocalPolicyMerge $false)
            $h.Count | Should -Be 2
            $h[0] | Should -Match "inbound Block rule 'Block DHCP in' names UDP 68"
            $h[1] | Should -Match 'LocalPolicyMerge'
            $eff = [ordered]@{ DOCacheHostSource = [ordered]@{ value = 1; provider = 'Mdm' } }
            $dhcp = [ordered]@{ wants = @('235'); state = 'answered'; subnetMask = $true; option234 = 'not-queried'; option235 = 'absent'; win32Error = $null }
            $ch = Resolve-DDCacheHost -Effective $eff -DhcpState 'answered' -Geo ([pscustomobject]@{ Result = 'pass'; CacheHost = $null; CacheHostFlag = $null })
            $checks = New-DDHealthChecks -DoEffective $eff -Network @{ localPolicyMergeEnabled = $false; dhcpOption235 = $null } -FirewallRules $rules -CacheHost $ch -Dhcp $dhcp -ModeNum 2
            $x = $checks | Where-Object { $_['checkId'] -eq 'mcc-dhcp-235' }
            $x['result'] | Should -Be 'warn'
            $x['code'] | Should -Be 'dhcp-expected-not-received'
            $x['detail'] | Should -Match 'UDP 68'
            $x['detail'] | Should -Match 'DO-NET-022'
            $y = $checks | Where-Object { $_['checkId'] -eq 'mcc-cache-host' }
            $y['result'] | Should -Be 'warn'
            $y['code'] | Should -Be 'dhcp-expected-not-received'
        }
    }
}

Describe 'The cache server DO will use (precedence)' {
    BeforeAll {
        $script:Eff = { param($h) $o = [ordered]@{}; foreach ($k in $h.Keys) { $o[$k] = [ordered]@{ value = $h[$k]; provider = 'Mdm' } }; $o }
        $script:Geo = { param($cacheHost, $flag) [pscustomobject]@{ Result = 'pass'; CacheHost = $cacheHost; CacheHostFlag = $flag } }
    }
    It 'follows Microsoft''s table: Force overrides DOCacheHost; Source 1 leaves DOCacheHost in charge; DHCP alone when only the source is set' {
        $e = $script:Eff; $g = $script:Geo
        InModuleScope DoctorDO.Collector -Parameters @{ E = $e; G = $g } {
            param($E, $G)
            $r = Resolve-DDCacheHost -Effective (& $E @{ DOCacheHost = 'mcc01.contoso.example'; DOCacheHostSource = 2 }) -Dhcp235 '10.20.9.15' -DhcpState 'answered' -Geo (& $G $null $null)
            $r.Source | Should -Be 'dhcp'; $r.Code | Should -Be 'dhcp-forced'; @($r.Hosts) | Should -Be @('10.20.9.15')
            $r = Resolve-DDCacheHost -Effective (& $E @{ DOCacheHost = 'mcc01.contoso.example'; DOCacheHostSource = 2 }) -DhcpState 'answered' -Geo (& $G $null $null)
            $r.Source | Should -Be 'policy'; $r.Code | Should -Be 'dhcp-expected-not-received'
            $r = Resolve-DDCacheHost -Effective (& $E @{ DOCacheHost = 'mcc01.contoso.example'; DOCacheHostSource = 1 }) -Dhcp235 '10.20.9.15' -DhcpState 'answered' -Geo (& $G $null $null)
            $r.Source | Should -Be 'policy'; $r.Code | Should -Be 'policy'
            $r = Resolve-DDCacheHost -Effective (& $E @{ DOCacheHostSource = 1 }) -Dhcp235 '10.20.9.15' -DhcpState 'answered' -Geo (& $G $null $null)
            $r.Source | Should -Be 'dhcp'; $r.Code | Should -Be 'dhcp'
            $r = Resolve-DDCacheHost -Effective (& $E @{ DOCacheHostSource = 1 }) -DhcpState 'timeout' -Geo (& $G $null $null)
            $r.Code | Should -Be 'dhcp-unreadable'
        }
    }

    It 'uses the DO service''s assignment without a policy, its DHCP flag, and says when it could not be read' {
        $e = $script:Eff; $g = $script:Geo
        InModuleScope DoctorDO.Collector -Parameters @{ E = $e; G = $g } {
            param($E, $G)
            $r = Resolve-DDCacheHost -Effective (& $E @{}) -DhcpState 'not-queried' -Geo (& $G '198.51.100.205' $null)
            $r.Source | Should -Be 'service'; $r.Code | Should -Be 'service'
            $r = Resolve-DDCacheHost -Effective (& $E @{}) -Dhcp235 '10.20.9.15' -DhcpState 'answered' -Geo (& $G '198.51.100.205' $true)
            $r.Source | Should -Be 'dhcp'; $r.Code | Should -Be 'service-dhcp'
            $r = Resolve-DDCacheHost -Effective (& $E @{}) -DhcpState 'answered' -Geo (& $G '198.51.100.205' $true)
            $r.Source | Should -Be 'service'; $r.Code | Should -Be 'service-dhcp-not-received'
            $r = Resolve-DDCacheHost -Effective (& $E @{}) -Geo ([pscustomobject]@{ Result = 'not-collected'; CacheHost = $null; CacheHostFlag = $null })
            $r.Code | Should -Be 'service-not-read'
            (Resolve-DDCacheHost -Effective (& $E @{}) -Geo (& $G $null $null)).Code | Should -Be 'none'
        }
    }

    It 'turns cache servers off on a VPN when DODisallowCacheServerDownloadsOnVPN is set, on Windows 11 22H2 and later' {
        $e = $script:Eff; $g = $script:Geo
        InModuleScope DoctorDO.Collector -Parameters @{ E = $e; G = $g } {
            param($E, $G)
            $eff = & $E @{ DOCacheHost = 'mcc01.contoso.example'; DODisallowCacheServerDownloadsOnVPN = 1 }
            $r = Resolve-DDCacheHost -Effective $eff -Geo (& $G $null $null) -VpnActive $true -OsBuild '10.0.26100'
            $r.Code | Should -Be 'vpn-disallowed'; $r.VpnBlocked | Should -BeTrue
            (Resolve-DDCacheHost -Effective $eff -Geo (& $G $null $null) -VpnActive $true -OsBuild '10.0.19045').Code | Should -Be 'policy'
            (Resolve-DDCacheHost -Effective $eff -Geo (& $G $null $null) -VpnActive $false -OsBuild '10.0.26100').Code | Should -Be 'policy'
        }
    }
}

Describe 'The DO geo service answer' {
    It 'accepts text/json with Version and a key-value endpoint, keeps the cache host and flag, and reads the public address only when asked' {
        InModuleScope DoctorDO.Collector {
            $o = [pscustomobject]@{ Attempted = $true; TimedOut = $false; Error = $null; Ms = 40; Status = 200; ContentType = 'text/json'; Redirected = $false; CertSeen = $true; ChainOk = $true; NameOk = $true; ChainMicrosoft = $true; ProxyUsed = $false
                Body = [System.Text.Encoding]::UTF8.GetBytes('{"ExternalIpAddress":"203.0.113.7","KeyValue_EndpointFullUri":"https://kv801.prod.do.dsp.mp.microsoft.com/all","Version":"ABC","CacheHost":"198.51.100.205","CacheHostFlag":1}') }
            $g = ConvertFrom-DDGeoOutcome -Outcome $o
            $g.Result | Should -Be 'pass'; $g.Code | Should -Be 'ok'
            $g.CacheHost | Should -Be '198.51.100.205'
            $g.CacheHostFlag | Should -BeTrue
            $g.ExternalIp | Should -BeNullOrEmpty
            (ConvertFrom-DDGeoOutcome -Outcome $o -ReadExternalIp).ExternalIp | Should -Be '203.0.113.7'
        }
    }

    It 'calls an HTML answer or a redirect a possible captive portal, and fails what DO itself could not use' {
        InModuleScope DoctorDO.Collector {
            $base = @{ Attempted = $true; TimedOut = $false; Error = $null; Ms = 40; Status = 200; ContentType = 'text/json'; Redirected = $false; CertSeen = $true; ChainOk = $true; NameOk = $true; ChainMicrosoft = $true; ProxyUsed = $false; Body = $null }
            $mk = { param($over) $h = $base.Clone(); foreach ($k in $over.Keys) { $h[$k] = $over[$k] }; [pscustomobject]$h }
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ ContentType = 'text/html; charset=utf-8' })).Code | Should -Be 'captive-portal'
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ ContentType = 'text/html' })).Result | Should -Be 'warn'
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ Status = 302; Redirected = $true })).Code | Should -Be 'captive-portal'
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ Status = 503 })).Code | Should -Be 'http-status'
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ ContentType = 'application/xml' })).Code | Should -Be 'unexpected-type'
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ Body = [System.Text.Encoding]::UTF8.GetBytes('{"Version":""}') })).Code | Should -Be 'invalid-response'
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ ChainOk = $false })).Code | Should -Be 'tls-untrusted'
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ ChainMicrosoft = $false })).Code | Should -Be 'tls-inspected'
            (ConvertFrom-DDGeoOutcome -Outcome (& $mk @{ Status = 0; Error = 'SocketException TimedOut'; TimedOut = $true })).Code | Should -Be 'unreachable'
            (ConvertFrom-DDGeoOutcome -Outcome $null).Result | Should -Be 'not-collected'
        }
    }

    It 'reports a captive portal in the matrix, and makes the geo answer the egress source only with -CollectPublicEgress' {
        Initialize-FakeDevice -Geo captive
        $x = (Get-DOConnectivityMatrix) | Where-Object checkId -eq 'do-geo'
        $x.result | Should -Be 'warn'
        $x.code | Should -Be 'captive-portal'
        Initialize-FakeDevice
        $st = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-{0}.json" -f [guid]::NewGuid().ToString('N'))
        $off = Get-DOInventory -StatePath $st
        $off.network.publicEgressHash | Should -BeNullOrEmpty
        ($off.notCollected | Where-Object field -eq 'network.publicEgressHash').reason | Should -Be 'skipped-by-flag'
        Mock -ModuleName DoctorDO.Collector Invoke-DDPublicIpProbe { '198.51.100.9' }
        $on = Get-DOInventory -StatePath $st -CollectPublicEgress
        $on.network.publicEgressHash | Should -Match '^sha256:[0-9a-f]{64}$'
        $want = InModuleScope DoctorDO.Collector { Get-DDSaltedHash -Value '203.0.113.7' -Salt (Get-DDTenantSalt -TenantId '9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10' -DeviceSalt 'x') -Domain 'egress' }
        $on.network.publicEgressHash | Should -Be $want
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDPublicIpProbe -Times 0 -Exactly -Because 'no third party is asked when the geo answer gives the address'
    }

    It 'caches the geo answer for fleet runs without ever writing the public address' {
        InModuleScope DoctorDO.Collector -Parameters @{ Root = $TestDrive } {
            param($Root)
            # Its own folder, judged as off Windows and left unprotected (the real ACL would lock the test runner out): the
            # cache folder's ACL checks have their own tests (Unit.Tests.ps1).
            Mock Get-DDDirectorySecurityRaw { $null }
            Mock Protect-DDPath { }
            $p = Join-Path (Join-Path $Root ('ddgeo-' + [guid]::NewGuid().ToString('N'))) 'geo.json'
            try {
                $g = [pscustomobject]@{ Result = 'pass'; Code = 'ok'; Detail = 'ok'; Evidence = 'status=200'; HttpStatus = 200; ContentType = 'text/json'; CacheHost = '198.51.100.205'; CacheHostFlag = $null; ExternalIp = '203.0.113.7'; Ms = 30; Cached = $false }
                $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
                Save-DDGeoCache -Path $p -Signature 's1' -At (Format-DDIso -Value $now) -Geo $g
                (Get-Content -LiteralPath $p -Raw) | Should -Not -Match '203\.0\.113\.7'
                $c = Read-DDGeoCache -Path $p -Signature 's1' -Now $now.AddHours(1) -MaxAgeMinutes 360
                $c.Cached | Should -BeTrue; $c.CacheHost | Should -Be '198.51.100.205'
                Read-DDGeoCache -Path $p -Signature 'other-network' -Now $now.AddHours(1) -MaxAgeMinutes 360 | Should -BeNullOrEmpty
                Read-DDGeoCache -Path $p -Signature 's1' -Now $now.AddHours(7) -MaxAgeMinutes 360 | Should -BeNullOrEmpty
            } finally { Remove-Item -LiteralPath $p -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Cache folder access and the state file' {
    It 'derives the DoSvc service SID as sc.exe showsid prints it' {
        InModuleScope DoctorDO.Collector { Get-DDServiceSid -Name 'DoSvc' | Should -Be 'S-1-5-80-3055155277-3816794035-3994065555-2874236192-2193176987' }
    }

    It 'grades access by SID: Full Control here and inherited is full, from one entry or two; anything less is partial' {
        InModuleScope DoctorDO.Collector {
            $one = @([pscustomobject]@{ Sid = 'S-1-5-20'; Type = 'Allow'; Rights = 2032127; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'None' })
            Get-DDAccessLevel -Entries $one -Sid 'S-1-5-20' | Should -Be 'full'
            $two = @([pscustomobject]@{ Sid = 'S-1-5-20'; Type = 'Allow'; Rights = 2032127; Inheritance = 'None'; Propagation = 'None' },
                [pscustomobject]@{ Sid = 'S-1-5-20'; Type = 'Allow'; Rights = 268435456; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'InheritOnly' })
            Get-DDAccessLevel -Entries $two -Sid 'S-1-5-20' | Should -Be 'full'
            Get-DDAccessLevel -Entries @([pscustomobject]@{ Sid = 'S-1-5-20'; Type = 'Allow'; Rights = 1179817; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'None' }) -Sid 'S-1-5-20' | Should -Be 'partial'
            Get-DDAccessLevel -Entries $one -Sid 'S-1-5-19' | Should -Be 'none'
            $f = ConvertFrom-DDCacheFolderAcl -Raw ([pscustomobject]@{ Exists = $true; DoSvcSid = $null; Entries = @($one + [pscustomobject]@{ Sid = 'S-1-5-80-3055155277-3816794035-3994065555-2874236192-2193176987'; Type = 'Deny'; Rights = 2032127; Inheritance = 'None'; Propagation = 'None' }) }) -WorkingDirectory 'D:\DOCache' -StateFile $true -SystemRoot 'C:\Windows'
            (ConvertFrom-DDCacheFolderAcl -Raw $null -WorkingDirectory 'C:\WINDOWS\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\' -SystemRoot 'C:\Windows')['custom'] | Should -BeFalse
            (ConvertFrom-DDCacheFolderAcl -Raw $null -WorkingDirectory 'D:\DOCache' -SystemRoot '')['custom'] | Should -BeNullOrEmpty -Because 'without the Windows folder the default path is unknown'
            $f['networkService'] | Should -Be 'full'
            $f['denyEntries'] | Should -Be 1
            $f['custom'] | Should -BeTrue
            $f['stateFile'] | Should -BeTrue
        }
    }

    It 'fails a cache folder DoSvc cannot write, and a custom one that does not exist; warns on a missing state file' {
        InModuleScope DoctorDO.Collector {
            $run = { param($cf) New-DDHealthChecks -CacheFolder $cf -ModeNum 1 }
            $c = & $run ([ordered]@{ custom = $true; exists = $true; networkService = 'partial'; doSvc = 'none'; denyEntries = 0; stateFile = $true })
            ($c | Where-Object { $_['checkId'] -eq 'do-cache-folder' })['result'] | Should -Be 'fail'
            ($c | Where-Object { $_['checkId'] -eq 'do-cache-folder' })['detail'] | Should -Match 'DO-CFG-009'
            $c = & $run ([ordered]@{ custom = $true; exists = $false; networkService = $null; doSvc = $null; denyEntries = $null; stateFile = $false })
            ($c | Where-Object { $_['checkId'] -eq 'do-cache-folder' })['code'] | Should -Be 'cache-folder-missing'
            ($c | Where-Object { $_['checkId'] -eq 'do-cache-folder' })['result'] | Should -Be 'fail'
            ($c | Where-Object { $_['checkId'] -eq 'do-state-file' })['result'] | Should -Be 'warn'
            $c = & $run ([ordered]@{ custom = $false; exists = $true; networkService = 'full'; doSvc = 'none'; denyEntries = 0; stateFile = $true })
            ($c | Where-Object { $_['checkId'] -eq 'do-cache-folder' })['result'] | Should -Be 'pass'
            $c = & $run $null
            ($c | Where-Object { $_['checkId'] -eq 'do-cache-folder' })['result'] | Should -Be 'not-collected'
        }
    }

    It 'carries the cache folder facts in the inventory and the bundle, and reports insufficient rights as not collected' {
        Initialize-FakeDevice
        $st = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-{0}.json" -f [guid]::NewGuid().ToString('N'))
        $inv = Get-DOInventory -StatePath $st
        $inv.doConfig.cacheFolder.networkService | Should -Be 'full'
        $inv.doConfig.cacheFolder.stateFile | Should -BeTrue
        Assert-ValidAgainstSchema -Object $inv -SchemaFile (Get-ContractPath 'inventory-v1.schema.json')
        Mock -ModuleName DoctorDO.Collector Get-DDCacheFolderAclRaw { throw [System.UnauthorizedAccessException]::new('Access to the path is denied.') }
        $inv = Get-DOInventory -StatePath $st
        ($inv.notCollected | Where-Object field -eq 'doConfig.cacheFolder').reason | Should -Be 'insufficient-rights'
        ($inv.connectivity | Where-Object checkId -eq 'do-cache-folder').result | Should -Be 'not-collected'
    }
}

Describe 'Inbound rules for TCP 7680: by port, in force, and scoped' {
    It 'passes a custom-named Intune rule found by its port (no false DO-NET-010), and warns when it is scoped to the local subnet in Group mode' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            , @([pscustomobject]@{ DisplayName = 'Contoso - Allow peer caching'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Domain'; Protocol = 'TCP'; LocalPort = '7680'; RemotePort = 'Any'
                    RemoteAddress = @('LocalSubnet'); PrimaryStatus = 'OK'; Program = $null; Service = $null })
        }
        $m = Get-DOConnectivityMatrix
        $fw = $m | Where-Object checkId -eq 'p2p-firewall-rule'
        $fw.result | Should -Be 'pass'
        $fw.detail | Should -Match 'Contoso - Allow peer caching'
        $sc = $m | Where-Object checkId -eq 'p2p-firewall-scope'
        $sc.result | Should -Be 'warn'
        $sc.code | Should -Be 'scoped'
        $sc.detail | Should -Match 'local subnet only'
        $sc.detail | Should -Match 'DO-NET-018'
        Initialize-FakeDevice -DownloadMode 'Lan'
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            , @([pscustomobject]@{ DisplayName = 'Contoso - Allow peer caching'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Domain'; Protocol = 'TCP'; LocalPort = '7680'; RemotePort = 'Any'
                    RemoteAddress = @('LocalSubnet'); PrimaryStatus = 'OK'; Program = $null; Service = $null })
        }
        ((Get-DOConnectivityMatrix) | Where-Object checkId -eq 'p2p-firewall-scope').result | Should -Be 'pass' -Because 'LAN-mode peers share this network'
    }

    It 'fails an enabled allow rule that is not in force, and says why' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            , @([pscustomobject]@{ DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '7680'; RemotePort = 'Any'
                    RemoteAddress = @('Any'); PrimaryStatus = 'Inactive'; EnforcementStatus = @('LocalFirewallRulesNotAllowed', 'ProfileInactive'); Program = $null; Service = 'dosvc' })
        }
        $m = Get-DOConnectivityMatrix
        $fw = $m | Where-Object checkId -eq 'p2p-firewall-rule'
        $fw.result | Should -Be 'fail'
        $fw.code | Should -Be 'not-in-force'
        $fw.detail | Should -Match 'local rule merging is off'
        $fw.detail | Should -Match 'DO-NET-019'
        ($m | Where-Object checkId -eq 'p2p-inbound').result | Should -Be 'fail'
    }

    It 'fails outbound blocks on TCP 7680 and, in Group mode, UDP 3544' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            , @([pscustomobject]@{ DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '7680'; RemotePort = 'Any'; RemoteAddress = @('Any'); PrimaryStatus = 'OK'; Program = $null; Service = 'dosvc' },
                [pscustomobject]@{ DisplayName = 'Baseline: no P2P out'; Direction = 'Outbound'; Action = 'Block'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = 'Any'; RemotePort = '7680'; RemoteAddress = @('Any'); PrimaryStatus = 'OK'; Program = $null; Service = $null },
                [pscustomobject]@{ DisplayName = 'Baseline: no Teredo'; Direction = 'Outbound'; Action = 'Block'; Enabled = 'True'; Profile = 'Any'; Protocol = 'UDP'; LocalPort = 'Any'; RemotePort = '3544'; RemoteAddress = @('Any'); PrimaryStatus = 'OK'; Program = $null; Service = $null })
        }
        $m = Get-DOConnectivityMatrix
        ($m | Where-Object checkId -eq 'p2p-outbound-rule').result | Should -Be 'fail'
        ($m | Where-Object checkId -eq 'p2p-outbound-rule').detail | Should -Match 'DO-NET-020'
        ($m | Where-Object checkId -eq 'teredo-outbound-rule').result | Should -Be 'fail'
        ($m | Where-Object checkId -eq 'p2p-firewall-rule').result | Should -Be 'pass' -Because 'an outbound block does not shadow the inbound allow rule'
    }

    It 'does not count a rule limited to another program or service, whatever its port, and names it (issue 1)' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            , @([pscustomobject]@{ DisplayName = 'Contoso Agent (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '1024-65535'; RemotePort = 'Any'
                    RemoteAddress = @('Any'); PrimaryStatus = 'OK'; Program = 'C:\Program Files\Contoso\agent.exe'; Service = 'Any' },
                [pscustomobject]@{ DisplayName = 'Update service 7680'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '7680'; RemotePort = 'Any'
                    RemoteAddress = @('Any'); PrimaryStatus = 'OK'; Program = '%SystemRoot%\system32\svchost.exe'; Service = 'wuauserv' })
        }
        $m = Get-DOConnectivityMatrix
        $fw = $m | Where-Object checkId -eq 'p2p-firewall-rule'
        $fw.result | Should -Be 'fail' -Because 'neither rule lets the dosvc service through'
        $fw.code | Should -Be 'no-allow'
        $fw.detail | Should -Match 'DO-NET-010'
        $fw.detail | Should -Match "'Contoso Agent \(TCP-In\)' names TCP 7680 but admits only the program agent\.exe"
        ($m | Where-Object checkId -eq 'p2p-inbound').result | Should -Be 'fail'
        ($m | Where-Object checkId -eq 'p2p-firewall-scope').code | Should -Be 'no-allow' -Because 'the scope check judges only rules that admit Delivery Optimization'
    }

    It 'lets through only rules whose program and service admit the dosvc service' {
        InModuleScope DoctorDO.Collector {
            $r = { param($p, $s) @{ direction = 'Inbound'; action = 'Allow'; protocol = 'TCP'; localPort = '7680'; displayName = 'x'; program = $p; service = $s } }
            Test-DDTcp7680Allow -Rule (& $r $null $null) | Should -BeTrue
            Test-DDTcp7680Allow -Rule (& $r 'Any' 'Any') | Should -BeTrue
            Test-DDTcp7680Allow -Rule (& $r '%SystemRoot%\system32\svchost.exe' 'dosvc') | Should -BeTrue
            Test-DDTcp7680Allow -Rule (& $r 'C:\WINDOWS\System32\SVCHOST.EXE' '*') | Should -BeTrue -Because '* is any service'
            Test-DDTcp7680Allow -Rule (& $r 'System' 'Any') | Should -BeFalse -Because 'the kernel is not DoSvc'
            Test-DDTcp7680Allow -Rule (& $r 'C:\Tools\notsvchost.exe' 'Any') | Should -BeFalse
            Test-DDTcp7680Allow -Rule (& $r 'Any' 'BITS') | Should -BeFalse
            Test-DDTcp7680Allow -Rule (& $r 'C:\Tools\agent.exe' 'Any') -AnyProgram | Should -BeTrue
        }
    }

    It 'says not collected instead of absent when Windows refused part of the listing (issue 1, not elevated)' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            $denied = [System.Management.Automation.ErrorRecord]::new([System.UnauthorizedAccessException]::new('Access is denied.'), 'HRESULT 0x80070005', 'PermissionDenied', $null)
            , @([pscustomobject]@{ DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '7680'; RemotePort = 'Any'
                    RemoteAddress = @('Any'); PrimaryStatus = 'Inactive'; EnforcementStatus = @('LocalFirewallRulesNotAllowed'); Program = '%SystemRoot%\system32\svchost.exe'; Service = 'dosvc' },
                [pscustomobject]@{ ReadRefused = 'the port filters'; Error = $denied })
        }
        $inv = Get-DOInventory -StatePath (Join-Path ([System.IO.Path]::GetTempPath()) ("dd-{0}.json" -f [guid]::NewGuid().ToString('N')))
        $nc = $inv.notCollected | Where-Object field -eq 'firewallRules'
        $nc.reason | Should -Be 'insufficient-rights'
        $nc.detail | Should -Match 'the port filters'
        @($inv.firewallRules).Count | Should -Be 1 -Because 'what was read is kept, without the refusal object'
        $fw = $inv.connectivity | Where-Object checkId -eq 'p2p-firewall-rule'
        $fw.result | Should -Be 'not-collected' -Because 'a custom-named rule in force could be among those not read'
        $fw.code | Should -Be 'rules-unreadable'
        $fw.detail | Should -Match "Delivery Optimization \(TCP-In\)', is enabled but its status is Inactive: the firewall policy ignores local rules"
        $fw.detail | Should -Not -Match 'DO-NET-010'
        ($inv.connectivity | Where-Object checkId -eq 'p2p-inbound').result | Should -Not -Be 'fail'
        ($inv.connectivity | Where-Object checkId -eq 'p2p-outbound-rule').result | Should -Be 'not-collected'
        ($inv.connectivity | Where-Object checkId -eq 'p2p-outbound-rule').code | Should -Be 'rules-unreadable'
    }

    It 'still passes on an in-force rule when the listing was incomplete, and still fails on a Block rule it read' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            $denied = [System.Management.Automation.ErrorRecord]::new([System.UnauthorizedAccessException]::new('Access is denied.'), 'HRESULT 0x80070005', 'PermissionDenied', $null)
            , @([pscustomobject]@{ DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '7680'; RemotePort = 'Any'
                    RemoteAddress = @('Any'); PrimaryStatus = 'OK'; Program = $null; Service = 'dosvc' },
                [pscustomobject]@{ ReadRefused = 'the port filters'; Error = $denied })
        }
        $fw = (Get-DOConnectivityMatrix) | Where-Object checkId -eq 'p2p-firewall-rule'
        $fw.result | Should -Be 'pass'
        $fw.detail | Should -Match 'a Block rule could be among those not read'
        Mock -ModuleName DoctorDO.Collector Get-DDFirewallRulesRaw {
            , @([pscustomobject]@{ DisplayName = 'Baseline: block inbound'; Direction = 'Inbound'; Action = 'Block'; Enabled = 'True'; Profile = 'Any'; Protocol = 'Any'; LocalPort = 'Any'; Program = $null; Service = $null },
                [pscustomobject]@{ ReadRefused = 'the port filters'; Error = $null })
        }
        $x = (Get-DOConnectivityMatrix) | Where-Object checkId -eq 'p2p-firewall-rule'
        $x.result | Should -Be 'fail' -Because 'a Block rule that was read is evidence, whatever was not read'
        $x.code | Should -Be 'shadowed'
    }
}

Describe 'TCP 7680 listener from DoSvc''s own TCP table' {
    It 'is listening only with a Listen socket on 7680, and not while DoSvc is stopped' {
        InModuleScope DoctorDO.Collector {
            Test-DDDoSvcListening -Connections @([pscustomobject]@{ LocalPort = 7680; State = 'Listen' }) -DoSvc ([pscustomobject]@{ Status = 'Running' }) | Should -BeTrue
            Test-DDDoSvcListening -Connections @([pscustomobject]@{ LocalPort = 51234; State = 'Established' }) -DoSvc ([pscustomobject]@{ Status = 'Running' }) | Should -BeFalse
            Test-DDDoSvcListening -Connections @([pscustomobject]@{ LocalPort = 7680; State = 'Listen' }) -DoSvc ([pscustomobject]@{ Status = 'Stopped' }) | Should -BeFalse
        }
    }

    It 'makes p2p-inbound a pass when DoSvc listens and the firewall admits it, and reads DoSvc rather than any process' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDDoSvcTcpConnections { @([pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 7680; RemoteAddress = '0.0.0.0'; RemotePort = 0; State = 'Listen'; CreationTime = $null }) }
        Mock -ModuleName DoctorDO.Collector Get-DDListeningTcpPorts { @() }
        $m = Get-DOConnectivityMatrix
        ($m | Where-Object checkId -eq 'p2p-listener').detail | Should -Be 'DoSvc is listening on TCP 7680'
        $in = $m | Where-Object checkId -eq 'p2p-inbound'
        $in.result | Should -Be 'pass'
        $in.code | Should -Be 'listening'
        $in.detail | Should -Match 'not measured'
        Should -Invoke -ModuleName DoctorDO.Collector Get-DDListeningTcpPorts -Times 0 -Exactly
    }

    It 'reads DoSvc''s TCP table only when it can tell DoSvc''s connections apart, and never turns a failed read into "no connections" (D-14)' -Skip:([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
        InModuleScope DoctorDO.Collector {
            Mock Test-DDWindows { $true }
            Mock Test-DDCommandAvailable { $true }
            $global:DDSvcInProcess = 1
            Mock Get-CimInstance -ParameterFilter { $Filter -eq "Name='DoSvc'" } { [pscustomobject]@{ Name = 'DoSvc'; ProcessId = 4980 } }
            Mock Get-CimInstance -ParameterFilter { $Filter -eq 'ProcessId=4980' } { @(1..$global:DDSvcInProcess | ForEach-Object { [pscustomobject]@{ Name = "svc$_"; ProcessId = 4980 } }) }
            Mock Get-NetTCPConnection { [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 7680; RemoteAddress = '0.0.0.0'; RemotePort = 0; State = 'Listen'; CreationTime = $null } }
            @(Get-DDDoSvcTcpConnections).Count | Should -Be 1
            # No connection for the PID is Get-NetTCPConnection's ObjectNotFound: an empty table, not a failure.
            Mock Get-NetTCPConnection { throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('No matching MSFT_NetTCPConnection objects found'), 'CmdletizationQuery_NotFound_OwningProcess,Get-NetTCPConnection', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null) }
            @(Get-DDDoSvcTcpConnections).Count | Should -Be 0
            # Any other failure throws, so the caller records endpoints.tcp as not collected instead of "not listening".
            Mock Get-NetTCPConnection { throw [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('WMI provider failure'), 'HRESULT 0x80041013', [System.Management.Automation.ErrorCategory]::NotSpecified, $null) }
            { Get-DDDoSvcTcpConnections } | Should -Throw '*provider failure*'
            # DoSvc sharing its svchost with other services: the PID's table would mix theirs in.
            Mock Get-NetTCPConnection { [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 7680; RemoteAddress = '0.0.0.0'; RemotePort = 0; State = 'Listen'; CreationTime = $null } }
            $global:DDSvcInProcess = 3
            { Get-DDDoSvcTcpConnections } | Should -Throw '*shares its process with 2 other service*'
        }
    }

    It 'falls back to any process''s listener when the DoSvc table could not be read' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDDoSvcTcpConnections { throw [System.Management.Automation.CommandNotFoundException]::new('Get-NetTCPConnection is not available.') }
        $m = Get-DOConnectivityMatrix
        ($m | Where-Object checkId -eq 'p2p-listener').detail | Should -Be 'A process is listening on TCP 7680'
    }
}

Describe 'Byte ranges and the Connected Cache verification download' {
    It 'accepts only a 206 that describes the range asked for and the file''s whole size' {
        InModuleScope DoctorDO.Collector {
            Test-DDRangeAnswer -ContentRange 'bytes 0-0/46867792' -ContentLength 1 -ExpectedTotal '46867792' | Should -BeNullOrEmpty
            Test-DDRangeAnswer -ContentRange 'bytes 0-0/46867792' | Should -BeNullOrEmpty
            Test-DDRangeAnswer -ContentRange $null | Should -Match 'no Content-Range'
            Test-DDRangeAnswer -ContentRange 'bytes 0-1023/46867792' | Should -Match 'not the 0-0 asked for'
            Test-DDRangeAnswer -ContentRange 'bytes 0-0/*' | Should -Match 'total size'
            Test-DDRangeAnswer -ContentRange 'bytes 0-0/1048576' -ExpectedTotal '46867792' | Should -Match 'not the 46867792 bytes'
            Test-DDRangeAnswer -ContentRange 'bytes 0-0/46867792' -ContentLength 1024 | Should -Match 'Content-Length of 1024'
        }
    }

    It 'fails do-range-support with evidence when the 206 does not match' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { New-FakeEndpointOutcome -Spec $s -ContentRange 'bytes 0-1023/1048576' } }
        $x = @((Get-DOConnectivityMatrix) | Where-Object checkId -eq 'do-range-support')[0]
        $x.result | Should -Be 'fail'
        $x.code | Should -Be 'range-mismatch'
        $x.detail | Should -Match 'DO-NET-004'
        $x.evidence | Should -Match 'Content-Range=bytes 0-1023/1048576'
    }

    It 'checks the verification download''s status, Content-Type and length without reading it' {
        Initialize-FakeDevice -CacheHost 'mcc01.contoso.example'
        $m = Get-DOConnectivityMatrix
        $ok = @($m | Where-Object { $_.checkId -eq 'ep:mcc' })[0]
        $ok.endpoint.http | Should -Be 'pass'
        $ok.detail | Should -Match '302,341 bytes'
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { if ($s.Host -eq 'mcc01.contoso.example') { New-FakeEndpointOutcome -Spec $s -VerifyContentType 'text/html; charset=utf-8' -VerifyContentLength 5120 } else { New-FakeEndpointOutcome -Spec $s } } }
        $html = @((Get-DOConnectivityMatrix) | Where-Object { $_.checkId -eq 'ep:mcc' })[0]
        $html.result | Should -Be 'fail'
        $html.endpoint.err.code | Should -Be 'mcc-not-content'
        $html.detail | Should -Match 'captive portal'
        Mock -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch { foreach ($s in @($Specs)) { if ($s.Host -eq 'mcc01.contoso.example') { New-FakeEndpointOutcome -Spec $s -VerifyContentLength 1000 } else { New-FakeEndpointOutcome -Spec $s } } }
        $size = @((Get-DOConnectivityMatrix) | Where-Object { $_.checkId -eq 'ep:mcc' })[0]
        $size.endpoint.http | Should -Be 'warn'
        $size.endpoint.err.code | Should -Be 'mcc-size-mismatch'
    }

    It 'asks for the verification object with a GET and no range, beside the byte-range request' {
        Initialize-FakeDevice -CacheHost 'mcc01.contoso.example'
        $null = Get-DOConnectivityMatrix
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDEndpointProbeBatch -ParameterFilter {
            $m = @($Specs | Where-Object { $_.Host -eq 'mcc01.contoso.example' })[0]
            $m -and $m.VerifyUrl -like 'http://mcc01.contoso.example/filestreamingservice/files/7bc846e0-af9c-49be-a03d-bb04428c9bb5/Microsoft.png?cacheHostOrigin=dl.delivery.mp.microsoft.com' -and $m.RangeUrl -eq $m.VerifyUrl
        }
    }
}

Describe 'Uploading on battery, the power plan and the update stack version' {
    It 'passes on AC power, warns on battery below the threshold or without one, and names the plan' {
        InModuleScope DoctorDO.Collector {
            $e = [ordered]@{ DOMinBatteryPercentageAllowedToUpload = [ordered]@{ value = 40; provider = 'Mdm' } }
            $c = New-DDHealthChecks -DoEffective $e -Vitals @{ onBattery = $false; batteryPercent = $null } -PowerPlan 'Balanced' -ModeNum 2
            ($c | Where-Object { $_['checkId'] -eq 'power-upload' })['detail'] | Should -Match 'On AC power; power plan: Balanced'
            $c = New-DDHealthChecks -DoEffective $e -Vitals @{ onBattery = $true; batteryPercent = 25 } -ModeNum 2
            ($c | Where-Object { $_['checkId'] -eq 'power-upload' })['code'] | Should -Be 'battery-below-threshold'
            $c = New-DDHealthChecks -DoEffective $e -Vitals @{ onBattery = $true; batteryPercent = 80 } -ModeNum 2
            ($c | Where-Object { $_['checkId'] -eq 'power-upload' })['result'] | Should -Be 'pass'
            $c = New-DDHealthChecks -DoEffective ([ordered]@{}) -Vitals @{ onBattery = $true; batteryPercent = 80 } -ModeNum 2
            ($c | Where-Object { $_['checkId'] -eq 'power-upload' })['code'] | Should -Be 'battery-no-upload'
            $c = New-DDHealthChecks -DoEffective $e -Vitals @{ onBattery = $true; batteryPercent = 80 } -ModeNum 99
            ($c | Where-Object { $_['checkId'] -eq 'power-upload' })['result'] | Should -Be 'not-applicable'
        }
    }

    It 'sends the power plan and the UUS version as device facts, and validates against the contract' {
        Initialize-FakeDevice
        $inv = Get-DOInventory -StatePath (Join-Path ([System.IO.Path]::GetTempPath()) ("dd-{0}.json" -f [guid]::NewGuid().ToString('N')))
        $inv.device.powerPlan | Should -Be 'Balanced'
        $inv.device.uusVersion | Should -Be '1510.2610.1012.0'
        Assert-ValidAgainstSchema -Object $inv -SchemaFile (Get-ContractPath 'inventory-v1.schema.json')
    }
}
