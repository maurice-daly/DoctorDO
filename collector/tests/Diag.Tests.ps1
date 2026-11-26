#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# docs/27 section 3: composite connectivity state, the cache-drive eligibility check, the matrix cap, the stable inventory hash,
# the cache drive's free space, dsregcmd in the local bundle, and the diagnosis signals (crash, up, flap).
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
}

Describe 'Connectivity state: a changed reason code is re-sent (3.1)' {
    It 'stores result|code, with an empty code when the check has none' {
        InModuleScope DoctorDO.Collector {
            Get-DDConnectivityComposite -Result ([ordered]@{ checkId = 'a'; result = 'pass' }) | Should -BeExactly 'pass|'
            Get-DDConnectivityComposite -Result ([ordered]@{ checkId = 'a'; result = 'fail'; code = 'not-in-force' }) | Should -BeExactly 'fail|not-in-force'
            $m = Get-DDConnectivityState -Connectivity @([ordered]@{ checkId = 'p2p-firewall-rule'; target = ''; protocol = 'local'; port = 7680; result = 'fail'; code = 'absent' })
            $m['p2p-firewall-rule||local|7680'] | Should -BeExactly 'fail|absent'
        }
    }

    It 'sends a check whose code changed while its result stayed fail, and nothing when neither changed' {
        InModuleScope DoctorDO.Collector {
            $row = { param($code) $r = [ordered]@{ checkId = 'p2p-firewall-rule'; target = ''; protocol = 'local'; port = 7680; result = 'fail'; latencyMs = $null; detail = 'x' }; if ($code) { $r['code'] = $code }; $r }
            $other = [ordered]@{ checkId = 'dosvc-running'; target = 'DoSvc'; protocol = 'local'; port = $null; result = 'pass'; latencyMs = $null; detail = 'ok' }
            $before = Get-DDConnectivityState -Connectivity @((& $row 'not-in-force'), $other)
            $sent = Select-DDChangedConnectivity -Rows @((& $row 'absent'), $other) -PreviousConnectivity $before
            $sent.Count | Should -Be 1
            $sent[0]['code'] | Should -Be 'absent'
            (Select-DDChangedConnectivity -Rows @((& $row 'not-in-force'), $other) -PreviousConnectivity $before).Count | Should -Be 0
            # a code disappearing is a change too
            (Select-DDChangedConnectivity -Rows @((& $row $null), $other) -PreviousConnectivity $before).Count | Should -Be 1
        }
    }

    It 'compares an old state file holding bare results on the result alone: nothing resent unless the result moved' {
        InModuleScope DoctorDO.Collector {
            $rows = @([ordered]@{ checkId = 'dosvc-running'; target = 'DoSvc'; protocol = 'local'; port = $null; result = 'pass'; latencyMs = $null; detail = 'ok' })
            $old = [ordered]@{ 'dosvc-running|DoSvc|local|' = 'pass' }
            (Select-DDChangedConnectivity -Rows $rows -PreviousConnectivity $old).Count | Should -Be 0
            (Select-DDChangedConnectivity -Rows $rows -PreviousConnectivity ([ordered]@{ 'dosvc-running|DoSvc|local|' = 'warn' })).Count | Should -Be 1
            (Select-DDChangedConnectivity -Rows $rows -PreviousConnectivity (Get-DDConnectivityState -Connectivity $rows)).Count | Should -Be 0
        }
    }

    It 'resends a whole endpoint group only when a member changed' {
        InModuleScope DoctorDO.Collector {
            $ep = { param($h, $res) [ordered]@{ checkId = 'ep:do-content'; target = $h; protocol = 'http'; port = 80; result = $res; latencyMs = 5; detail = 'd' } }
            $rows = @((& $ep 'a.example' 'pass'), (& $ep 'b.example' 'pass'))
            $prev = Get-DDConnectivityState -Connectivity $rows
            (Select-DDChangedConnectivity -Rows $rows -PreviousConnectivity $prev).Count | Should -Be 0
            (Select-DDChangedConnectivity -Rows @((& $ep 'a.example' 'pass'), (& $ep 'b.example' 'fail')) -PreviousConnectivity $prev).Count | Should -Be 2
        }
    }
}

Describe 'Resource eligibility judges the cache drive (3.2)' {
    BeforeAll {
        function script:Invoke-Matrix {
            param($Ram = 16, $Disk = 476, $Drive = 'C:', $Effective = $null, $DoSvc = $null, $Endpoints = @(), [switch] $SkipProbes)
            InModuleScope DoctorDO.Collector -Parameters @{ Ram = $Ram; Disk = $Disk; Drive = $Drive; Effective = $Effective; DoSvc = $DoSvc; Endpoints = $Endpoints; Skip = [bool]$SkipProbes } {
                param($Ram, $Disk, $Drive, $Effective, $DoSvc, $Endpoints, $Skip)
                $ctx = New-DDContext -Salt 'salt'
                $eff = @{ DODownloadMode = @{ value = 1 } }
                if ($Effective) { foreach ($k in $Effective.Keys) { $eff[$k] = @{ value = $Effective[$k] } } }
                $m = Get-DDConnectivityMatrix -Context $ctx -DoEffective $eff -RamGB $Ram -DiskGB $Disk -DiskDrive $Drive -DoSvc $DoSvc -DoSvcListening $true -EndpointResults $Endpoints -SkipProbes:$Skip
                [pscustomobject]@{ Matrix = @($m); NotCollected = $ctx.NotCollected.ToArray() }
            }
        }
    }

    It 'fails when the cache drive is small and the system drive is large, names the drive, and says disk' {
        $r = Invoke-Matrix -Disk 16 -Drive 'D:'
        $c = $r.Matrix | Where-Object checkId -eq 'resource-eligibility'
        $c.result | Should -Be 'fail'
        $c.code | Should -Be 'disk'
        $c.detail | Should -Match 'cache drive D: 16 GB < DOMinDiskSizeAllowedToPeer 32 GB'
        $c.detail | Should -Match 'documented default assumed'
    }

    It 'passes when the cache drive is large (whatever the system drive is)' {
        $c = (Invoke-Matrix -Disk 931 -Drive 'D:').Matrix | Where-Object checkId -eq 'resource-eligibility'
        $c.result | Should -Be 'pass'
        $c.PSObject.Properties['code'] | Should -BeNullOrEmpty
        $c.detail | Should -Match 'cache drive D: 931 GB'
    }

    It 'emits ram, disk or ram-disk by what failed, and honours a configured minimum' {
        ((Invoke-Matrix -Ram 2 -Disk 500).Matrix | Where-Object checkId -eq 'resource-eligibility').code | Should -Be 'ram'
        ((Invoke-Matrix -Ram 2 -Disk 10).Matrix | Where-Object checkId -eq 'resource-eligibility').code | Should -Be 'ram-disk'
        $c = (Invoke-Matrix -Ram 8 -Disk 100 -Effective @{ DOMinDiskSizeAllowedToPeer = 256; DOMinRAMAllowedToPeer = 4 }).Matrix | Where-Object checkId -eq 'resource-eligibility'
        $c.code | Should -Be 'disk'
        $c.detail | Should -Match 'DOMinDiskSizeAllowedToPeer 256 GB'
        $c.detail | Should -Not -Match 'default assumed'
    }

    It 'is not-collected when the size is unknown and not-applicable when peering is off' {
        ((Invoke-Matrix -Disk $null).Matrix | Where-Object checkId -eq 'resource-eligibility').result | Should -Be 'not-collected'
        ((Invoke-Matrix -Effective @{ DODownloadMode = 99 }).Matrix | Where-Object checkId -eq 'resource-eligibility').result | Should -Be 'not-applicable'
    }

    It 'end to end: a cache on a small D: volume fails the matrix check while the large C: volume would pass' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDLocalDisks { @([pscustomobject]@{ DeviceId = 'C:'; Size = [long](476GB); FreeSpace = [long](210GB) }, [pscustomobject]@{ DeviceId = 'D:'; Size = [long](16GB); FreeSpace = [long](4GB) }) }
        Mock -ModuleName DoctorDO.Collector Get-DDDOConfigRaw {
            [pscustomobject]@{ Config = [pscustomobject]@{ DownloadMode = 1; MinTotalRAM = 4; WorkingDirectory = 'D:\DOCache' }; Verbose = @('DownloadMode:1 DownloadModeProvider:GroupPolicy Provider') }
        }
        $c = (Get-DOConnectivityMatrix -Anonymise) | Where-Object checkId -eq 'resource-eligibility'
        $c.result | Should -Be 'fail'
        $c.code | Should -Be 'disk'
        $c.detail | Should -Match 'cache drive D: 16 GB'
        Mock -ModuleName DoctorDO.Collector Get-DDLocalDisks { @([pscustomobject]@{ DeviceId = 'C:'; Size = [long](476GB); FreeSpace = [long](210GB) }, [pscustomobject]@{ DeviceId = 'D:'; Size = [long](931GB); FreeSpace = [long](400GB) }) }
        ((Get-DOConnectivityMatrix -Anonymise) | Where-Object checkId -eq 'resource-eligibility').result | Should -Be 'pass'
    }

    It 'dosvc-running carries code start-disabled when the service is Disabled' {
        $c = (Invoke-Matrix -DoSvc ([pscustomobject]@{ Status = 'Stopped'; StartType = 'Disabled' })).Matrix | Where-Object checkId -eq 'dosvc-running'
        $c.result | Should -Be 'fail'
        $c.code | Should -Be 'start-disabled'
        $w = (Invoke-Matrix -DoSvc ([pscustomobject]@{ Status = 'Stopped'; StartType = 'Manual' })).Matrix | Where-Object checkId -eq 'dosvc-running'
        $w.result | Should -Be 'warn'
        $w.PSObject.Properties['code'] | Should -BeNullOrEmpty
    }
}

Describe 'The matrix is cut by priority, never by position (3.3)' {
    It 'keeps the first row of every check and drops the extra per-host rows when over the cap' {
        InModuleScope DoctorDO.Collector {
            $rows = @()
            $rows += 1..3 | ForEach-Object { [ordered]@{ checkId = "net-$_"; target = ''; result = 'pass' } }
            $rows += 1..60 | ForEach-Object { [ordered]@{ checkId = 'do-content-cdn'; target = "h$_.example"; result = 'pass' } }
            $rows += 1..40 | ForEach-Object { [ordered]@{ checkId = "health-$_"; target = ''; result = 'pass' } }
            $r = Select-DDMatrixRows -Checks $rows -Max 88
            @($r.Rows).Count | Should -Be 88
            $r.Dropped | Should -Be 15
            $ids = @($r.Rows | ForEach-Object { $_['checkId'] })
            1..40 | ForEach-Object { $ids | Should -Contain "health-$_" }
            @($ids | Where-Object { $_ -eq 'do-content-cdn' }).Count | Should -Be 45
            # matrix order is kept, and the first host rows survive rather than the last
            @($r.Rows | Where-Object { $_['checkId'] -eq 'do-content-cdn' })[0]['target'] | Should -Be 'h1.example'
            @($r.Rows | Where-Object { $_['checkId'] -eq 'do-content-cdn' })[44]['target'] | Should -Be 'h45.example'
            $r.Rows[0]['checkId'] | Should -Be 'net-1'
        }
    }

    It 'drops nothing under the cap' {
        InModuleScope DoctorDO.Collector {
            $rows = 1..10 | ForEach-Object { [ordered]@{ checkId = 'x'; target = "h$_"; result = 'pass' } }
            $r = Select-DDMatrixRows -Checks $rows -Max 88
            @($r.Rows).Count | Should -Be 10
            $r.Dropped | Should -Be 0
        }
    }

    It 'with 100 content hosts every health check survives and the loss is recorded in notCollected' {
        $eps = 1..100 | ForEach-Object {
            [ordered]@{ checkId = 'ep:do-content'; target = "h$_.delivery.example"; protocol = 'http'; port = 80; result = 'pass'; latencyMs = 5; detail = 'd'
                endpoint = [ordered]@{ id = 'do-content'; basis = 'documented'; dns = 'pass'; tcp = 'pass'; tls = 'not-collected'; http = 'pass'; range = 'not-collected'; err = $null } }
        }
        $r = Invoke-Matrix -Endpoints $eps
        @($r.Matrix | Where-Object { $_.checkId -notlike 'ep:*' }).Count | Should -BeLessOrEqual 88
        foreach ($id in 'do-geo', 'mcc-cache-host', 'dhcp-option-234', 'p2p-firewall-scope', 'p2p-outbound-rule', 'teredo-outbound-rule', 'do-cache-folder', 'do-state-file', 'power-upload', 'dosvc-running', 'resource-eligibility', 'adapter-eligibility') {
            @($r.Matrix | Where-Object checkId -eq $id).Count | Should -BeGreaterThan 0 -Because $id
        }
        @($r.Matrix | Where-Object checkId -eq 'do-content-cdn').Count | Should -BeLessThan 100
        $nc = $r.NotCollected | Where-Object { $_['field'] -eq 'connectivity' }
        $nc | Should -Not -BeNullOrEmpty
        $nc['detail'] | Should -Match '\d+ per-host connectivity row\(s\) not sent'
    }
}

Describe 'The stable inventory hash ignores volatile network facts (3.4)' {
    BeforeAll {
        function script:Get-Hashes {
            param([scriptblock] $Change)
            InModuleScope DoctorDO.Collector -Parameters @{ Change = $Change } {
                param($Change)
                $c = Get-DDRawCollection -Salt 'salt' -Anonymise
                $a = ConvertTo-DDInventory -Collection $c
                $before = @{ Full = Get-DDInventoryHash -Inventory $a; Stable = Get-DDStableInventoryHash -Inventory $a }
                & $Change $a
                [pscustomobject]@{ FullChanged = ((Get-DDInventoryHash -Inventory $a) -ne $before.Full); StableChanged = ((Get-DDStableInventoryHash -Inventory $a) -ne $before.Stable) }
            }
        }
    }
    BeforeEach { Initialize-FakeDevice }

    It 'a different subnet, gateway, egress hash, DO adapter subnet, DHCP outcome or power plan sends no new inventory' {
        $r = Get-Hashes -Change {
            param($inv)
            $inv['network']['localSubnet'] = '192.168.77.0/24'
            $inv['network']['defaultGateway'] = 'ip:ffffffffffffffff'
            $inv['network']['publicEgressHash'] = 'sha256:' + ('b' * 64)
            $inv['network']['defaultRouteSubnet'] = '172.16.0.0/16'
            $inv['network']['dhcp'] = [ordered]@{ state = 'timeout' }
            $inv['device']['powerPlan'] = 'High performance'
            if ($inv['network'].Contains('doAdapter')) { $inv['network']['doAdapter']['subnet'] = '192.168.77.0/24' }
        }
        $r.FullChanged | Should -BeTrue -Because 'the full hash still sees them (a keyframe refreshes them)'
        $r.StableChanged | Should -BeFalse
    }

    It 'a firewall rule, a DO setting, the OS build or the adapter type does send a new inventory' {
        (Get-Hashes -Change { param($inv) $inv['firewallRules'] = @() }).StableChanged | Should -BeTrue
        (Get-Hashes -Change { param($inv) $inv['doConfig']['effective']['DODownloadMode'] = [ordered]@{ value = 3; source = 'x' } }).StableChanged | Should -BeTrue
        (Get-Hashes -Change { param($inv) $inv['device']['osBuild'] = '99999.1' }).StableChanged | Should -BeTrue
        (Get-Hashes -Change { param($inv) $inv['network']['adapterType'] = 'Cellular' }).StableChanged | Should -BeTrue
        (Get-Hashes -Change { param($inv) $inv['network']['proxy']['configured'] = -not $inv['network']['proxy']['configured'] }).StableChanged | Should -BeTrue
    }
}

Describe 'Free space of the cache drive (3.6)' {
    BeforeAll {
        function script:Get-Vitals {
            param([string] $WorkingDirectory)
            InModuleScope DoctorDO.Collector -Parameters @{ Wd = $WorkingDirectory } { param($Wd) Get-DDDeviceVitals -Context (New-DDContext -Salt 's') -WorkingDirectory $Wd }
        }
    }
    BeforeEach {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDLocalDisks { @([pscustomobject]@{ DeviceId = 'C:'; Size = [long](476GB); FreeSpace = [long](210GB) }, [pscustomobject]@{ DeviceId = 'D:'; Size = [long](16GB); FreeSpace = [long](1GB) }) }
    }

    It 'reads the drive of the working directory' {
        $v = Get-Vitals -WorkingDirectory 'D:\DOCache'
        $v['cacheDriveFreeGB'] | Should -Be 1
        $v['systemDiskFreeGB'] | Should -Be 210
    }

    It 'defaults to the system drive when no working directory is known' {
        (Get-Vitals -WorkingDirectory '')['cacheDriveFreeGB'] | Should -Be 210
    }

    It 'is $null, not 0, when the drive is not found (0 reads as full)' {
        $v = Get-Vitals -WorkingDirectory 'E:\DOCache'
        $v.Contains('cacheDriveFreeGB') | Should -BeTrue
        $v['cacheDriveFreeGB'] | Should -BeNullOrEmpty
        $v['cacheDriveFreeGB'] -eq 0 | Should -BeFalse
    }

    It 'travels in telemetry vitals: the value, a null, and nothing at all when the raw device has no such key' {
        InModuleScope DoctorDO.Collector {
            $raw = { param($dev) [ordered]@{ schemaVersion = 1; collector = [ordered]@{ name = 'x'; version = '0' }; collectedAt = '2026-10-12T08:00:00Z'; device = $dev; network = [ordered]@{}; connectivity = @() } }
            $t = ConvertTo-DDTelemetry -Raw (& $raw ([ordered]@{ cacheDriveFreeGB = 1.5 })) -Seq 1 -InventoryHash 'sha256:x' -PeriodFrom 'a' -PeriodTo 'b'
            $t['vitals']['cacheDriveFreeGB'] | Should -Be 1.5
            $t = ConvertTo-DDTelemetry -Raw (& $raw ([ordered]@{ cacheDriveFreeGB = $null })) -Seq 1 -InventoryHash 'sha256:x' -PeriodFrom 'a' -PeriodTo 'b'
            $t['vitals'].Contains('cacheDriveFreeGB') | Should -BeTrue
            $t['vitals']['cacheDriveFreeGB'] | Should -BeNullOrEmpty
            $t = ConvertTo-DDTelemetry -Raw (& $raw ([ordered]@{})) -Seq 1 -InventoryHash 'sha256:x' -PeriodFrom 'a' -PeriodTo 'b'
            $t['vitals'].Contains('cacheDriveFreeGB') | Should -BeFalse
        }
    }

    It 'gives the system drive''s free space as $null, never 0, when that drive is not among the local disks, and says why (A-11)' {
        Mock -ModuleName DoctorDO.Collector Get-DDLocalDisks { @([pscustomobject]@{ DeviceId = 'Q:'; Size = [long](16GB); FreeSpace = [long](1GB) }) }
        InModuleScope DoctorDO.Collector {
            $ctx = New-DDContext -Salt 's'
            $v = Get-DDDeviceVitals -Context $ctx -WorkingDirectory ''
            $v.Contains('systemDiskFreeGB') | Should -BeTrue
            $v['systemDiskFreeGB'] | Should -BeNullOrEmpty
            ($ctx.NotCollected | Where-Object { $_['field'] -eq 'vitals.systemDiskFreeGB' }).reason | Should -Be 'error'
        }
    }
}

Describe 'Battery state (A-05)' {
    It 'BatteryStatus <Status> reads as on battery <On>, low <Low>' -ForEach @(
        @{ Status = 1; On = $true; Low = $false }
        @{ Status = 2; On = $false; Low = $false }
        @{ Status = 3; On = $false; Low = $false }
        @{ Status = 4; On = $true; Low = $true }
        @{ Status = 5; On = $true; Low = $true }
        @{ Status = 6; On = $false; Low = $false }
        @{ Status = 8; On = $false; Low = $false }
        @{ Status = 11; On = $false; Low = $false }
    ) {
        Initialize-FakeDevice
        $global:DDBatteryStatus = $Status
        Mock -ModuleName DoctorDO.Collector Get-DDBatteryRaw { @([pscustomobject]@{ BatteryStatus = $global:DDBatteryStatus; EstimatedChargeRemaining = 9 }) }
        $v = InModuleScope DoctorDO.Collector { Get-DDDeviceVitals -Context (New-DDContext -Salt 's') -WorkingDirectory '' }
        $v['onBattery'] | Should -Be $On
        $v['batteryLow'] | Should -Be $Low
        $v['batteryPercent'] | Should -Be 9
    }

    It 'has no low flag without a battery, and none when the read failed (which is recorded, so it never reads as AC)' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDBatteryRaw { @() }
        $v = InModuleScope DoctorDO.Collector { Get-DDDeviceVitals -Context (New-DDContext -Salt 's') -WorkingDirectory '' }
        $v['onBattery'] | Should -BeFalse
        $v.Contains('batteryLow') | Should -BeTrue
        $v['batteryLow'] | Should -BeNullOrEmpty
        Mock -ModuleName DoctorDO.Collector Get-DDBatteryRaw { throw 'Invalid class' }
        InModuleScope DoctorDO.Collector {
            $ctx = New-DDContext -Salt 's'
            (Get-DDDeviceVitals -Context $ctx -WorkingDirectory '')['batteryLow'] | Should -BeNullOrEmpty
            @($ctx.NotCollected | Where-Object { $_['field'] -eq 'vitals.battery' }).Count | Should -Be 1
        }
    }
}

Describe 'VPN keywords (A-04)' {
    It 'splits the keywords DO is configured with on commas and semicolons only, so a phrase stays whole' {
        InModuleScope DoctorDO.Collector {
            $kw = @(ConvertTo-DDVpnKeywordList -Value 'VPN,Secure, Virtual Private Network;ContosoVPN')
            $kw | Should -Be @('VPN', 'Secure', 'Virtual Private Network', 'ContosoVPN')
            $kw = @(ConvertTo-DDVpnKeywordList -Value @('VPN', 'Virtual Private Network'))
            $kw | Should -Be @('VPN', 'Virtual Private Network') -Because 'a list from Get-DOConfig is not joined with spaces first'
            @(ConvertTo-DDVpnKeywordList -Value $null).Count | Should -Be 0
        }
    }

    It 'does not call ordinary adapters VPNs when DO is configured with a phrase (the probe in the finding)' {
        InModuleScope DoctorDO.Collector {
            $kw = @(ConvertTo-DDVpnKeywordList -Value 'VPN,Secure,Virtual Private Network')
            Test-DDVpnAdapter -Adapter ([pscustomobject]@{ Name = 'Ethernet'; Description = 'Intel(R) 82579LM Gigabit Network Connection' }) -ExtraKeywords $kw | Should -BeFalse
            Test-DDVpnAdapter -Adapter ([pscustomobject]@{ Name = 'Wi-Fi Direct'; Description = 'Microsoft Wi-Fi Direct Virtual Adapter' }) -ExtraKeywords $kw | Should -BeFalse
            Get-DDVpnKeywordMatch -Adapter ([pscustomobject]@{ Name = 'Corp'; Description = 'Contoso Virtual Private Network Adapter' }) | Should -Be 'virtual private network' -Because 'DO''s documented defaults are in the built-in list'
            Get-DDVpnKeywordMatch -Adapter ([pscustomobject]@{ Name = 'Corp'; Description = 'Contoso Secure Access' }) | Should -Be 'secure'
            Get-DDVpnKeywordMatch -Adapter ([pscustomobject]@{ Name = 'Corp'; Description = 'Acme Tunnel Driver' }) -ExtraKeywords @('Acme') | Should -Be 'tunnel'
            Get-DDVpnKeywordMatch -Adapter ([pscustomobject]@{ Name = 'Corp'; Description = 'Acme Remote Access' }) -ExtraKeywords @('Acme Remote') | Should -Be 'acme remote'
            Get-DDVpnKeywordMatch -Adapter ([pscustomobject]@{ Name = 'Teredo'; Description = 'Teredo Tunneling Pseudo-Interface' }) | Should -BeNullOrEmpty
        }
    }

    It 'reports which keyword matched, and matches DO''s default list only when one of its own keywords did' {
        Initialize-FakeDevice
        $up = { param($name, $desc) [pscustomobject]@{ Name = $name; Description = $desc; Status = 'Up'; MediaType = '802.3'; PhysicalMediaType = '802.3'; IfIndex = 9; IfType = 6 } }
        $raw = [pscustomobject]@{ DefaultInterfaceIndex = 7; Gateway = '10.20.4.1'; IPv4 = '10.20.4.71'; PrefixLength = 22
            Adapters = @((& $up 'Ethernet' 'Intel(R) Ethernet Connection'), (& $up 'GP' 'PANGP Virtual Ethernet Adapter')) }
        $n = InModuleScope DoctorDO.Collector -Parameters @{ Raw = $raw } { param($Raw) (Get-DDNetworkFacts -Context (New-DDContext -Salt 's') -Raw $Raw -RawCollected -VpnKeywords 'VPN,Secure,Virtual Private Network' -SkipPublicIp).Network }
        $n['isVpnActive'] | Should -BeTrue
        @($n['vpnMatchedKeywords']) | Should -Be @('pangp')
        $n['matchesDefaultVpnKeywords'] | Should -BeFalse -Because 'PANGP is DoctorDO''s client name, not one of DO''s default keywords'
        $raw.Adapters = @((& $up 'Corp VPN' 'WAN Miniport (IKEv2)'))
        $n = InModuleScope DoctorDO.Collector -Parameters @{ Raw = $raw } { param($Raw) (Get-DDNetworkFacts -Context (New-DDContext -Salt 's') -Raw $Raw -RawCollected -SkipPublicIp).Network }
        @($n['vpnMatchedKeywords']) | Should -Be @('vpn')
        $n['matchesDefaultVpnKeywords'] | Should -BeTrue
    }
}

Describe 'dsregcmd /status in the local bundle (3.7)' {
    BeforeAll {
        $script:Dsreg = @(
            '+----------------------------------------------------------------------+', '| Device State                                                         |', '+----------------------------------------------------------------------+',
            '             AzureAdJoined : YES', '          EnterpriseJoined : NO', '              DomainJoined : YES', '                DomainName : CONTOSO', '',
            '+----------------------------------------------------------------------+', '| Device Details                                                       |', '+----------------------------------------------------------------------+',
            '                  DeviceId : 3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20', '                Thumbprint : 9A1B2C3D4E5F60718293A4B5C6D7E8F901234567',
            '           KeyContainerId : 7d3a5f6e-1c2b-4a9d-8e7f-0a1b2c3d4e5f', '              KeyProvider : Microsoft Platform Crypto Provider', '',
            '+----------------------------------------------------------------------+', '| Tenant Details                                                       |', '+----------------------------------------------------------------------+',
            '                TenantName : Contoso', '                  TenantId : 9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10',
            '               AuthCodeUrl : https://login.microsoftonline.com/9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10/oauth2/authorize', '',
            '+----------------------------------------------------------------------+', '| SSO State                                                            |', '+----------------------------------------------------------------------+',
            '                AzureAdPrt : YES', '      Executing Account Name : CONTOSO\alice, alice@contoso.com', '          Previous Prt Attempt : 2026-10-12 07:41:02.000 UTC',
            '               WamDefaultId : https://login.microsoft.com', '          NgcKeyId : {2f4c6e8a-0b1d-4c3e-9f5a-7b8c9d0e1f2a}', '      Prt Cache : 4c1f8e2a9b3d7c5e6f0a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcd')
    }

    It 'under -Anonymise leaves no GUID, thumbprint, long hex string, address, tenant or account name' {
        InModuleScope DoctorDO.Collector -Parameters @{ Lines = $script:Dsreg } {
            param($Lines)
            $name = 'CONTOSO-LT-0042'
            $t = Protect-DDDsregText -Lines $Lines -Anonymise -Salt 'salt' -ComputerName $name
            $t | Should -Not -Match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
            $t | Should -Not -Match '\b[0-9a-fA-F]{32,}\b'
            $t | Should -Not -Match '@'
            $t | Should -Not -Match 'alice|Contoso|CONTOSO'
            # what an admin reads it for survives
            $t | Should -Match 'AzureAdJoined : YES'
            $t | Should -Match 'AzureAdPrt : YES'
            $t | Should -Match 'KeyProvider : Microsoft Platform Crypto Provider'
        }
    }

    It 'under -Anonymise a realistic multi-section dsregcmd /status keeps no GUID, thumbprint, address, logon name, domain suffix, tenant or user name' {
        $full = @'
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : YES
                DomainName : CORP
               Device Name : PC01.corp.contoso.com

+----------------------------------------------------------------------+
| Device Details                                                       |
+----------------------------------------------------------------------+

                  DeviceId : 3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20
                Thumbprint : 9A1B2C3D4E5F60718293A4B5C6D7E8F901234567
 DeviceCertificateValidity : [ 2026-01-02 08:00:00.000 UTC -- 2036-01-02 08:30:00.000 UTC ]
            KeyContainerId : 7d3a5f6e-1c2b-4a9d-8e7f-0a1b2c3d4e5f
               KeyProvider : Microsoft Platform Crypto Provider
              TpmProtected : YES

+----------------------------------------------------------------------+
| Tenant Details                                                       |
+----------------------------------------------------------------------+

                TenantName : Fabrikam Holdings
                  TenantId : 9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10
                      Idp : login.windows.net
               AuthCodeUrl : https://login.microsoftonline.com/9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10/oauth2/authorize
            AccessTokenUrl : https://login.microsoftonline.com/9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10/oauth2/token
                    MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc

+----------------------------------------------------------------------+
| User State                                                           |
+----------------------------------------------------------------------+

                    NgcSet : YES
                  NgcKeyId : {2f4c6e8a-0b1d-4c3e-9f5a-7b8c9d0e1f2a}
                  CanReset : DestructiveOnly

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : NO
      AzureAdPrtAuthority : https://login.microsoftonline.com/9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10
           Previous Prt Attempt : 2026-10-12 07:41:02.000 UTC
              Attempt Status : 0xc000006d
               User Identity : jsmith
                  Credential Type : Password
          Correlation ID : c4a7e1d2-3b5f-4a6c-8d9e-0f1a2b3c4d5e
            Endpoint URI : https://login.microsoftonline.com/9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10/oauth2/token
                  HTTP Error : 0x0
                 HTTP status : 400
            Server Error Code : invalid_grant
                Server Error : AADSTS50126: Error validating credentials for FABRIKAM\jsmith. Trace ID: 0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d
              Server Message : The user jsmith@fabrikam.com does not exist in the directory 'Fabrikam Holdings'.
                               Contact the Fabrikam Holdings administrator, John Smith.
        Diagnostics Reference : https://aka.ms/aadsts?code=50126&user=jsmith
           Client ErrorCode : 0xcaa20003

+----------------------------------------------------------------------+
| Diagnostic Data                                                      |
+----------------------------------------------------------------------+

     Executing Account Name : FABRIKAM\jsmith, jsmith@fabrikam.com
              KeySignTest : PASSED

+----------------------------------------------------------------------+
| Work Account 1                                                       |
+----------------------------------------------------------------------+

         WorkplaceDeviceId : 5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f70819
      WorkplaceThumbprint : 0123456789ABCDEF0123456789ABCDEF01234567
      WorkplaceTenantName : Fabrikam Holdings
           WorkplaceTenantId : 9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10
'@ -split "\r?\n"
        InModuleScope DoctorDO.Collector -Parameters @{ Lines = $full } {
            param($Lines)
            foreach ($name in 'PC01', 'A-DIFFERENT-NAME') {
                $t = Protect-DDDsregText -Lines $Lines -Anonymise -Salt 'salt' -ComputerName $name
                $t | Should -Not -Match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
                $t | Should -Not -Match '\b[0-9a-fA-F]{32,}\b'
                $t | Should -Not -Match '@'
                $t | Should -Not -Match '\w\\\w' -Because 'a DOMAIN\user logon name'
                $t | Should -Not -Match 'corp|fabrikam|contoso|jsmith|john|smith|holdings'
                $t | Should -Match 'Device Name : <host>\s'
                # the value of every free-text line is gone, and the message continuation with it
                $t | Should -Match 'Server Message : <removed>'
                $t | Should -Match 'Server Error : <removed>'
                $t | Should -Match 'Diagnostics Reference : <removed>'
                $t | Should -Match 'Previous Prt Attempt : <removed>'
                $t | Should -Not -Match 'does not exist|Contact the|AADSTS|invalid_grant'
                # what an admin reads it for survives, codes included
                $t | Should -Match 'AzureAdJoined : YES'
                $t | Should -Match 'KeyProvider : Microsoft Platform Crypto Provider'
                $t | Should -Match 'KeySignTest : PASSED'
                $t | Should -Match 'Client ErrorCode : 0xcaa20003'
                $t | Should -Match 'HTTP status : 400'
                $t | Should -Match 'Attempt Status : 0xc000006d'
            }
        }
    }

    It 'under -Anonymise masks the host of every URL and UNC path except Microsoft''s own, even when no identity line named the domain' {
        $adv = @'
+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : YES
     EnterprisePrtAuthority : https://sts.contoso.com/adfs
         Domain Controller : \\dc01.corp.contoso.com
               ShareHint : \\FILESRV01\netlogon\policy
             AuthCodeUrl : https://login.microsoftonline.com/9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10/oauth2/authorize
             WamDefaultId : https://login.microsoft.com
           DrsEndpoint : https://enterpriseregistration.windows.net/EnrollmentServer/device/
               MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
             Storage : https://tenantstore.blob.core.windows.net/logs
             Ldap : ldap://DC02.corp.contoso.com:389/CN=x
'@ -split "\r?\n"
        InModuleScope DoctorDO.Collector -Parameters @{ Lines = $adv } {
            param($Lines)
            $name = 'PC01'
            $t = Protect-DDDsregText -Lines $Lines -Anonymise -Salt 'salt' -ComputerName $name
            $t | Should -Not -Match 'contoso|corp|dc01|dc02|filesrv|tenantstore|sts\.'
            $t | Should -Match 'EnterprisePrtAuthority : https://<host>/adfs'
            $t | Should -Match 'Domain Controller : \\\\<host>\s'
            $t | Should -Match 'ShareHint : \\\\<host>(\\|$)'
            $t | Should -Match 'ldap://<host>:389'
            # Microsoft's own endpoints stay: an admin reads them to see which service was reached
            $t | Should -Match 'https://login\.microsoftonline\.com/'
            $t | Should -Match 'WamDefaultId : https://login\.microsoft\.com'
            $t | Should -Match 'https://enterpriseregistration\.windows\.net/'
            $t | Should -Match 'https://enrollment\.manage\.microsoft\.com/'
            $t | Should -Match 'AzureAdPrt : YES'
        }
    }

    It 'the allow-list of Microsoft hosts is one list, matches whole labels, and never keeps a customer-named storage host' {
        InModuleScope DoctorDO.Collector {
            foreach ($h in 'login.microsoftonline.com', 'enterpriseregistration.windows.net', 'enrollment.manage.microsoft.com', 'LOGIN.MICROSOFT.COM', 'device.login.microsoftonline.com') {
                Test-DDDsregPublicHost -HostName $h | Should -BeTrue -Because $h
            }
            foreach ($h in 'sts.contoso.com', 'microsoft.com.evil.example', 'notmicrosoft.com', 'contoso.blob.core.windows.net', 'dc01', '') {
                Test-DDDsregPublicHost -HostName $h | Should -BeFalse -Because "'$h'"
            }
        }
    }

    It 'under -Anonymise a value line that looks like "key : value" inside a blanked message is still blanked; the next real field is kept' {
        $adv = @'
          Previous Prt Attempt : 2026-10-12 07:41:02.000 UTC
              Server Message : The user zed was refused.
                               second line : contact the administrator, alice
                               Reference : ask bob
  note : the account is carol
           Client ErrorCode : 0xcaa20003
                 HTTP status : 400
'@ -split "\r?\n"
        InModuleScope DoctorDO.Collector -Parameters @{ Lines = $adv } {
            param($Lines)
            $name = 'PC01'
            $t = Protect-DDDsregText -Lines $Lines -Anonymise -Salt 'salt' -ComputerName $name
            $t | Should -Not -Match 'zed|alice|bob|carol|administrator|second line|refused'
            $t | Should -Match 'Server Message : <removed>'
            $t | Should -Match 'Client ErrorCode : 0xcaa20003'
            $t | Should -Match 'HTTP status : 400'
        }
    }

    It 'under -Anonymise masks account names of any length, in the lines that name them and wherever else they appear' {
        $adv = @'
      Executing Account Name : CORP\ab, ab@corp.example
                 User Identity : q
             Logon Hint : ab signed in as q from AB
                AzureAdPrt : YES
                 CanReset : DestructiveOnly
'@ -split "\r?\n"
        InModuleScope DoctorDO.Collector -Parameters @{ Lines = $adv } {
            param($Lines)
            $name = 'PC01'
            $t = Protect-DDDsregText -Lines $Lines -Anonymise -Salt 'salt' -ComputerName $name
            $t | Should -Not -Match '(?i)(?<![A-Za-z0-9])(ab|q)(?![A-Za-z0-9])'
            $t | Should -Not -Match 'corp'
            $t | Should -Match 'AzureAdPrt : YES'
            $t | Should -Match 'CanReset : DestructiveOnly'
        }
    }

    It 'without -Anonymise keeps the ids an admin needs but still removes the UPN' {
        InModuleScope DoctorDO.Collector -Parameters @{ Lines = $script:Dsreg } {
            param($Lines)
            $t = Protect-DDDsregText -Lines $Lines
            $t | Should -Match '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20'
            $t | Should -Not -Match 'alice@contoso.com'
            $t | Should -Match '<upn>'
        }
    }

    It 'Get-DDLocalBundleExtras adds dsregcmd-status.txt from the text it is given, and names it Missing when dsregcmd fails' {
        InModuleScope DoctorDO.Collector -Parameters @{ Lines = $script:Dsreg } {
            param($Lines)
            Mock Get-DDRegistryTree { [ordered]@{ key = 'k'; present = $false; values = @(); subkeys = @() } }
            Mock Get-DDNlmCostText { @('Cost : unrestricted') }
            $e = Get-DDLocalBundleExtras -Anonymise -Salt 's' -DsregText $Lines
            $e.Files.Keys | Should -Contain 'dsregcmd-status.txt'
            Mock Get-DDDsregStatusText { throw 'dsregcmd failed' }
            $e2 = Get-DDLocalBundleExtras -Anonymise -Salt 's'
            $e2.Files.Keys | Should -Not -Contain 'dsregcmd-status.txt'
            ($e2.Missing -join ' ') | Should -Match 'dsregcmd-status.txt'
        }
    }

    It 'a fleet run never carries it: no dsregcmd text in inventory or telemetry' {
        Initialize-FakeDevice
        $inv = Get-DOInventory -StatePath (Join-Path ([System.IO.Path]::GetTempPath()) ("dd-ds-" + [guid]::NewGuid().ToString('N') + '/state.json')) -Anonymise
        (ConvertTo-Json -InputObject $inv -Depth 32 -Compress) | Should -Not -Match 'Device Details|Tenant Details|EnterpriseJoined'
    }
}

Describe 'Parser: DoSvc unexpected terminations (3.8)' {
    BeforeAll { $script:Now = [datetime]::new(2026, 10, 17, 12, 0, 0, [System.DateTimeKind]::Utc) }

    It 'counts 7031 and 7034 for the DoSvc display name in the window and ignores everything else' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $ev = { param($id, $days, $name, $prov) [pscustomobject]@{ Id = $id; Provider = $(if ($prov) { $prov } else { 'Service Control Manager' }); TimeCreated = $Now.AddDays(-$days); Name = $name } }
            $events = @(
                (& $ev 7034 1 'Delivery Optimization'), (& $ev 7031 2 'Delivery Optimization'), (& $ev 7034 6.9 'delivery optimization'),
                (& $ev 7034 2 'Windows Search'), (& $ev 7036 2 'Delivery Optimization'), (& $ev 7034 8 'Delivery Optimization'),
                (& $ev 7034 1 'Delivery Optimization' 'SomeOtherSource'))
            Get-DDDoSvcCrashCount -Events $events -ServiceDisplayName 'Delivery Optimization' -Now $Now | Should -Be 3
            Get-DDDoSvcCrashCount -Events @() -ServiceDisplayName 'Delivery Optimization' -Now $Now | Should -Be 0
            Get-DDDoSvcCrashCount -Events $null -ServiceDisplayName 'Delivery Optimization' -Now $Now | Should -Be 0
        }
    }

    It 'matches the localised display name read from the same device, and a Properties[0].Value event' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $de = "Optimierung der $([char]0x00DC)bermittlung"
            $events = @([pscustomobject]@{ Id = 7034; TimeCreated = $Now.AddHours(-3); Name = $de },
                [pscustomobject]@{ Id = 7031; TimeCreated = $Now.AddHours(-4); Properties = @([pscustomobject]@{ Value = $de }, [pscustomobject]@{ Value = 2 }) },
                [pscustomobject]@{ Id = 7034; TimeCreated = $Now.AddHours(-5); Name = 'Delivery Optimization' })
            Get-DDDoSvcCrashCount -Events $events -ServiceDisplayName $de -Now $Now | Should -Be 2
        }
    }

    It 'caps at 99, the wire limit' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $events = 1..150 | ForEach-Object { [pscustomobject]@{ Id = 7034; TimeCreated = $Now.AddMinutes(-$_); Name = 'Delivery Optimization' } }
            Get-DDDoSvcCrashCount -Events $events -ServiceDisplayName 'Delivery Optimization' -Now $Now | Should -Be 99
        }
    }
}

Describe 'System-log read for the DoSvc crash count is filtered by the log, not after the 5,000-event cap (3.8)' {
    It 'New-DDSystemEventFilter adds the service name as event data only when one is given' {
        InModuleScope DoctorDO.Collector {
            $start = [datetime]::new(2026, 10, 5, 8, 0, 0, [System.DateTimeKind]::Utc)
            $f = New-DDSystemEventFilter -ProviderName 'Service Control Manager' -Id 7031, 7034 -StartTime $start -DataValue 'Delivery Optimization'
            $f['LogName'] | Should -Be 'System'
            $f['ProviderName'] | Should -Be 'Service Control Manager'
            @($f['Id']) | Should -Be @(7031, 7034)
            $f['Data'] | Should -Be 'Delivery Optimization'
            $f['StartTime'] | Should -Be $start
            (New-DDSystemEventFilter -ProviderName 'Microsoft-Windows-Kernel-General' -Id 12, 13 -StartTime $start).Contains('Data') | Should -BeFalse
        }
    }

    It 'the DoSvc crash read passes its display name down to the event query; the uptime read does not filter' {
        Mock -ModuleName DoctorDO.Collector Get-DDSystemEventsRaw { @() }
        InModuleScope DoctorDO.Collector {
            $null = Get-DDServiceTerminationEventsRaw -Days 7 -TimeoutSec 5 -ServiceDisplayName 'Delivery Optimization'
            Should -Invoke Get-DDSystemEventsRaw -Times 1 -Exactly -ParameterFilter { $ProviderName -eq 'Service Control Manager' -and $DataValue -eq 'Delivery Optimization' -and $Id -contains 7034 -and $Id -contains 7031 }
            $null = Get-DDKernelGeneralEventsRaw -Days 7 -TimeoutSec 5
            Should -Invoke Get-DDSystemEventsRaw -Times 1 -Exactly -ParameterFilter { $ProviderName -eq 'Microsoft-Windows-Kernel-General' -and -not $DataValue }
        }
    }

    It 'reads again by provider and ID alone when the event-data filter finds nothing, so a filter that never matches cannot read as healthy (A-08)' {
        Mock -ModuleName DoctorDO.Collector Get-DDSystemEventsRaw {
            if ($PesterBoundParameters['DataValue']) { @() } else { @([pscustomobject]@{ Id = 7031; Provider = 'Service Control Manager'; TimeCreated = [datetime]::UtcNow.AddHours(-1); Name = 'Delivery Optimization' }) }
        }
        InModuleScope DoctorDO.Collector {
            $rows = @(Get-DDServiceTerminationEventsRaw -Days 7 -TimeoutSec 5 -ServiceDisplayName 'Delivery Optimization')
            $rows.Count | Should -Be 1
            Should -Invoke Get-DDSystemEventsRaw -Times 2 -Exactly
            Should -Invoke Get-DDSystemEventsRaw -Times 1 -Exactly -ParameterFilter { -not $DataValue -and $ProviderName -eq 'Service Control Manager' -and $TimeoutSec -ge 1 -and $TimeoutSec -le 5 }
            Get-DDDoSvcCrashCount -Events $rows -ServiceDisplayName 'Delivery Optimization' -Now ([datetime]::UtcNow) | Should -Be 1
        }
    }

    It 'does not read twice when the filtered read found events' {
        Mock -ModuleName DoctorDO.Collector Get-DDSystemEventsRaw { @([pscustomobject]@{ Id = 7034; Provider = 'Service Control Manager'; TimeCreated = [datetime]::UtcNow; Name = 'Delivery Optimization' }) }
        InModuleScope DoctorDO.Collector {
            $null = Get-DDServiceTerminationEventsRaw -Days 7 -TimeoutSec 5 -ServiceDisplayName 'Delivery Optimization'
            Should -Invoke Get-DDSystemEventsRaw -Times 1 -Exactly
        }
    }

    It 'Get-DDDiagSignals asks for the service it read from Get-Service, not for every service' {
        Initialize-FakeDevice
        InModuleScope DoctorDO.Collector {
            $null = Get-DDDiagSignals -State (New-DDState) -Now ([datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc))
            Should -Invoke Get-DDServiceTerminationEventsRaw -Times 1 -Exactly -ParameterFilter { $ServiceDisplayName -eq 'Delivery Optimization' }
        }
    }
}

Describe 'Parser: hours powered on per day (3.8)' {
    BeforeAll { $script:Now = [datetime]::new(2026, 10, 17, 12, 0, 0, [System.DateTimeKind]::Utc) }

    It 'is 24 when the window holds no start or shutdown: the device has been up throughout' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            Get-DDPoweredOnHours -Events @() -Now $Now | Should -Be 24
        }
    }

    It 'a laptop on 8 hours a day: six sessions of 8 hours in the window is 48 hours over 7 days' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $kg = 'Microsoft-Windows-Kernel-General'
            $events = foreach ($d in 6..1) {
                $day = $Now.Date.AddDays(-$d)
                [pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $day.AddHours(9) }
                [pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $day.AddHours(17) }
            }
            # a first event that is a start only says the device was off before it: the mean is over the whole 7 days
            Get-DDPoweredOnHours -Events @($events) -Now $Now | Should -Be ([math]::Round(48 / 7, 2))
        }
    }

    It 'a new device is averaged over the history it has, not over seven days with most of them empty' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $kg = 'Microsoft-Windows-Kernel-General'
            # enrolled 2 days ago, on for 10 hours a day: 20 hours over 2 days is 10 a day, not 20 / 7 = 2.9
            $events = @([pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddDays(-2) }, [pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-2).AddHours(10) },
                [pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddDays(-1) }, [pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-1).AddHours(10) })
            Get-DDPoweredOnHours -Events $events -Now $Now -HistoryStart $Now.AddDays(-2) | Should -Be 10
        }
    }

    It 'a device that is mostly off is not over-estimated: one 8-hour session 1.5 days ago is 1.14 hours a day, not 5' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $kg = 'Microsoft-Windows-Kernel-General'
            $events = @([pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddDays(-1.5) }, [pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-1.5).AddHours(8) })
            $expected = [math]::Round(8 / 7, 2)
            # no evidence of how old the device is: the window is the history
            Get-DDPoweredOnHours -Events $events -Now $Now | Should -Be $expected
            # a System log and an install date that reach back past the window: not new
            Get-DDPoweredOnHours -Events $events -Now $Now -HistoryStart $Now.AddDays(-400) | Should -Be $expected
            # the same at the window's edge
            Get-DDPoweredOnHours -Events $events -Now $Now -HistoryStart $Now.AddDays(-7) | Should -Be $expected
        }
    }

    It 'a device whose history starts inside the window is judged over that history, whatever its first event is' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $kg = 'Microsoft-Windows-Kernel-General'
            # installed 4 days ago, switched on at once for 12 hours, off since: 12 over 4 days is 3 a day
            $up = @([pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddDays(-4) }, [pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-4).AddHours(12) })
            Get-DDPoweredOnHours -Events $up -Now $Now -HistoryStart $Now.AddDays(-4) | Should -Be 3
            # first event a shutdown on a log that starts 4 days ago: the device was running from the log's start
            $down = @([pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-3) })
            Get-DDPoweredOnHours -Events $down -Now $Now -HistoryStart $Now.AddDays(-4) | Should -Be ([math]::Round(24 / 4, 2))
        }
    }

    It 'Get-DDDeviceHistoryStartRaw returns the older of the install date and the oldest System record, and survives either failing' {
        Mock -ModuleName DoctorDO.Collector Test-DDWindows { $true }
        InModuleScope DoctorDO.Collector {
            $install = [datetime]::new(2026, 10, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
            $oldest = [datetime]::new(2026, 10, 10, 0, 0, 0, [System.DateTimeKind]::Utc)
            Mock Get-DDCim { @([pscustomobject]@{ InstallDate = $install }) }
            Mock Invoke-DDWithTimeout { $oldest }
            (Get-DDDeviceHistoryStartRaw -TimeoutSec 5).ToUniversalTime() | Should -Be $install
            Mock Get-DDCim { @([pscustomobject]@{ InstallDate = $oldest.AddDays(5) }) }
            (Get-DDDeviceHistoryStartRaw -TimeoutSec 5).ToUniversalTime() | Should -Be $oldest
            Mock Get-DDCim { throw 'CIM is unavailable' }
            (Get-DDDeviceHistoryStartRaw -TimeoutSec 5).ToUniversalTime() | Should -Be $oldest
            Mock Invoke-DDWithTimeout { throw [System.TimeoutException]::new('Timed out after 5 s.') }
            Get-DDDeviceHistoryStartRaw -TimeoutSec 5 | Should -BeNullOrEmpty
        }
    }

    It 'Get-DDDiagSignals hands the device history start to the mean' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDKernelGeneralEventsRaw {
            $n = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            @([pscustomobject]@{ Id = 12; Provider = 'Microsoft-Windows-Kernel-General'; TimeCreated = $n.AddDays(-1.5); Name = $null },
                [pscustomobject]@{ Id = 13; Provider = 'Microsoft-Windows-Kernel-General'; TimeCreated = $n.AddDays(-1.5).AddHours(8); Name = $null })
        }
        InModuleScope DoctorDO.Collector {
            $n = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            # an old device that is mostly off: 8 hours in 7 days is 1 a day (the event log's history is not the events'), which DO-DIAG-002 (under 4) must see
            (Get-DDDiagSignals -State (New-DDState) -Now $n).Up | Should -Be 1
            Should -Invoke Get-DDDeviceHistoryStartRaw -Times 1 -Exactly
        }
    }

    It 'has no mean with less than 24 hours of history: nothing is reported rather than a tiny number' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $kg = 'Microsoft-Windows-Kernel-General'
            Get-DDPoweredOnHours -Events @([pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddHours(-9) }) -Now $Now -HistoryStart $Now.AddHours(-9) | Should -BeNullOrEmpty
            Get-DDPoweredOnHours -Events @([pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddHours(-24) }) -Now $Now -HistoryStart $Now.AddHours(-24) | Should -Be 24 -Because 'exactly 24 hours of history, up throughout'
            # a first event that is a shutdown means the device was running at the window start: the whole window is history
            Get-DDPoweredOnHours -Events @([pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddHours(-9) }, [pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddHours(-8) }) -Now $Now | Should -Not -BeNullOrEmpty
        }
    }

    It 'diag.up is left out and named not collected, with a reason, for a device that is under a day old' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDKernelGeneralEventsRaw {
            $n = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            @([pscustomobject]@{ Id = 12; Provider = 'Microsoft-Windows-Kernel-General'; TimeCreated = $n.AddHours(-9); Name = $null })
        }
        Mock -ModuleName DoctorDO.Collector Get-DDDeviceHistoryStartRaw { [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc).AddHours(-9) }
        InModuleScope DoctorDO.Collector {
            $r = Get-DDDiagSignals -State (New-DDState) -Now ([datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc))
            $r.Up | Should -BeNullOrEmpty
            $r.Crash | Should -Be 2
            $up = @($r.NotCollected | Where-Object { $_['field'] -eq 'diag.up' })
            $up.Count | Should -Be 1
            $up[0]['reason'] | Should -Be 'error'
            $up[0]['detail'] | Should -Match '24 hours'
            (ConvertTo-DDDiagSection -Diag ([ordered]@{ crash = $r.Crash; up = $r.Up; flap = [ordered]@{} })).Contains('up') | Should -BeFalse
        }
    }

    It 'a session open at the window start counts from the start, one still open ends now' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $kg = 'Microsoft-Windows-Kernel-General'
            # shut down 1 day after the window began, booted again 12 hours ago, still running
            $events = @([pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-6) }, [pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddHours(-12) })
            # 24 h + 12 h = 36 h over 7 days
            Get-DDPoweredOnHours -Events $events -Now $Now | Should -Be ([math]::Round(36 / 7, 2))
        }
    }

    It 'two starts with no shutdown between (power loss) is an upper bound: the first session ends at the second start' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $kg = 'Microsoft-Windows-Kernel-General'
            $events = @([pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddDays(-3) }, [pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddDays(-2) },
                [pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-1) })
            # -3d to -2d (24 h), -2d to -1d (24 h)
            # the device was installed at the first start, so the history is the 3 days since: 48 hours is 16 a day
            Get-DDPoweredOnHours -Events $events -Now $Now -HistoryStart $Now.AddDays(-3) | Should -Be 16
        }
    }

    It 'ignores the same IDs from other providers and events outside the window, and does not depend on input order' {
        InModuleScope DoctorDO.Collector -Parameters @{ Now = $script:Now } {
            param($Now)
            $kg = 'Microsoft-Windows-Kernel-General'
            $good = @([pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-5) }, [pscustomobject]@{ Id = 12; Provider = $kg; TimeCreated = $Now.AddHours(-12) })
            $noise = @([pscustomobject]@{ Id = 12; Provider = 'Other-Source'; TimeCreated = $Now.AddDays(-4) }, [pscustomobject]@{ Id = 13; Provider = $kg; TimeCreated = $Now.AddDays(-20) },
                [pscustomobject]@{ Id = 41; Provider = 'Microsoft-Windows-Kernel-Power'; TimeCreated = $Now.AddDays(-4) })
            $a = Get-DDPoweredOnHours -Events ($good + $noise) -Now $Now
            $b = Get-DDPoweredOnHours -Events @(($good + $noise)[($good.Count + $noise.Count - 1)..0]) -Now $Now
            $a | Should -Be $b
            $a | Should -Be (Get-DDPoweredOnHours -Events $good -Now $Now)
            $a | Should -Be ([math]::Round((2 * 24 + 12) / 7, 2))
        }
    }
}

Describe 'Get-DDDiagSignals: cached for 24 hours, bounded, never reads a failure as healthy (3.8)' {
    BeforeEach {
        Initialize-FakeDevice
        $script:T0 = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
    }

    It 'reads once, caches in the state, and reads again after 24 hours' {
        InModuleScope DoctorDO.Collector -Parameters @{ T0 = $script:T0 } {
            param($T0)
            $st = New-DDState
            $a = Get-DDDiagSignals -State $st -Now $T0
            $a.Cached | Should -BeFalse
            $a.Crash | Should -Be 2
            $a.Up | Should -Be 1
            @($a.NotCollected).Count | Should -Be 0
            $st['diag']['at'] | Should -Be '2026-10-12T08:00:00Z'
            $b = Get-DDDiagSignals -State $st -Now $T0.AddHours(23)
            $b.Cached | Should -BeTrue
            $b.Crash | Should -Be 2
            Should -Invoke Get-DDServiceTerminationEventsRaw -Times 1 -Exactly
            Should -Invoke Get-DDKernelGeneralEventsRaw -Times 1 -Exactly
            (Get-DDDiagSignals -State $st -Now $T0.AddHours(25)).Cached | Should -BeFalse
            Should -Invoke Get-DDServiceTerminationEventsRaw -Times 2 -Exactly
        }
    }

    It 'survives the state file: a saved and re-read state still serves the cache' {
        $sp = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-diag-" + [guid]::NewGuid().ToString('N') + '/state.json')
        InModuleScope DoctorDO.Collector -Parameters @{ T0 = $script:T0; Sp = $sp } {
            param($T0, $Sp)
            $st = New-DDState
            $null = Get-DDDiagSignals -State $st -Now $T0
            Save-DDState -Path $Sp -State $st
            $back = (Read-DDState -Path $Sp).State
            $c = Get-DDDiagSignals -State $back -Now $T0.AddHours(2)
            $c.Cached | Should -BeTrue
            $c.Crash | Should -Be 2
            Should -Invoke Get-DDServiceTerminationEventsRaw -Times 1 -Exactly
        }
    }

    It 'a read that times out is $null and named diag.crash with reason timeout; the other signal is still measured' {
        Mock -ModuleName DoctorDO.Collector Get-DDServiceTerminationEventsRaw { throw [System.TimeoutException]::new('Timed out after 5 s.') }
        InModuleScope DoctorDO.Collector -Parameters @{ T0 = $script:T0 } {
            param($T0)
            $st = New-DDState
            $r = Get-DDDiagSignals -State $st -Now $T0
            $r.Crash | Should -BeNullOrEmpty
            $r.Up | Should -Be 1
            @($r.NotCollected).Count | Should -Be 1
            $r.NotCollected[0]['field'] | Should -Be 'diag.crash'
            $r.NotCollected[0]['reason'] | Should -Be 'timeout'
            # the failure is cached too: no 5 s bound paid again within the day
            $again = Get-DDDiagSignals -State $st -Now $T0.AddHours(1)
            $again.Cached | Should -BeTrue
            $again.NotCollected[0]['field'] | Should -Be 'diag.crash'
        }
    }

    It 'a missing DoSvc, a disabled event log and a non-Windows host each name the field with a reason' {
        Mock -ModuleName DoctorDO.Collector Get-DDDoSvcDisplayName { $null }
        Mock -ModuleName DoctorDO.Collector Get-DDKernelGeneralEventsRaw { throw [System.UnauthorizedAccessException]::new('Attempted to perform an unauthorized operation.') }
        InModuleScope DoctorDO.Collector -Parameters @{ T0 = $script:T0 } {
            param($T0)
            $r = Get-DDDiagSignals -State (New-DDState) -Now $T0
            $r.Crash | Should -BeNullOrEmpty
            $r.Up | Should -BeNullOrEmpty
            ($r.NotCollected | Where-Object { $_['field'] -eq 'diag.crash' })['reason'] | Should -Be 'error'
            ($r.NotCollected | Where-Object { $_['field'] -eq 'diag.up' })['reason'] | Should -Be 'insufficient-rights'
        }
    }

    It 'bounds the reads to 5 s together: no wrapper is given more than the bound, and an exhausted bound is a timeout' {
        InModuleScope DoctorDO.Collector -Parameters @{ T0 = $script:T0 } {
            param($T0)
            $null = Get-DDDiagSignals -State (New-DDState) -Now $T0
            Should -Invoke Get-DDServiceTerminationEventsRaw -ParameterFilter { $TimeoutSec -le 5 -and $TimeoutSec -ge 1 } -Times 1 -Exactly
            Should -Invoke Get-DDKernelGeneralEventsRaw -ParameterFilter { $TimeoutSec -le 5 -and $TimeoutSec -ge 1 } -Times 1 -Exactly
            $r = Get-DDDiagSignals -State (New-DDState) -Now $T0 -BoundSec 0 -Refresh
            @($r.NotCollected | ForEach-Object { $_['reason'] } | Select-Object -Unique) | Should -Be @('timeout')
            @($r.NotCollected).Count | Should -Be 2
        }
    }

    It 'an unreadable cache in the state is ignored, not trusted' {
        InModuleScope DoctorDO.Collector -Parameters @{ T0 = $script:T0 } {
            param($T0)
            $st = New-DDState
            $st['diag'] = [ordered]@{ at = 'yesterday'; crash = 5; up = 3 }
            $r = Get-DDDiagSignals -State $st -Now $T0
            $r.Cached | Should -BeFalse
            $r.Crash | Should -Be 2
        }
    }
}

Describe 'Flap counters (3.8)' {
    BeforeAll {
        # Defined in the module's scope: the InModuleScope blocks below run there and cannot see the test script's functions.
        InModuleScope DoctorDO.Collector {
            function script:Row { param($id, $res, $code = $null, $target = '') $r = [ordered]@{ checkId = $id; target = $target; protocol = 'local'; port = $null; result = $res; latencyMs = $null; detail = 'd' }; if ($code) { $r['code'] = $code }; $r }
        }
    }

    It 'counts a change once per check per run, however many targets; a check seen for the first time is not a change' {
        InModuleScope DoctorDO.Collector {
            $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            $rows0 = @((Row 'a' 'pass'), (Row 'p2p-outbound' 'pass' $null 'x'), (Row 'p2p-outbound' 'pass' $null 'y'))
            $prev = Get-DDConnectivityState -Connectivity $rows0
            (Merge-DDFlapCounts -Counts $null -Rows $rows0 -PreviousConnectivity $prev -Now $now).Count | Should -Be 0
            $rows1 = @((Row 'a' 'fail'), (Row 'p2p-outbound' 'fail' $null 'x'), (Row 'p2p-outbound' 'fail' $null 'y'), (Row 'new-check' 'fail'))
            $c = Merge-DDFlapCounts -Counts $null -Rows $rows1 -PreviousConnectivity $prev -Now $now
            $c['a']['20261012'] | Should -Be 1
            $c['p2p-outbound']['20261012'] | Should -Be 1
            $c.Contains('new-check') | Should -BeFalse
            # nothing to compare against (first run, or a lost state): nothing is counted
            (Merge-DDFlapCounts -Counts $null -Rows $rows1 -PreviousConnectivity $null -Now $now).Count | Should -Be 0
            (Merge-DDFlapCounts -Counts $null -Rows $rows1 -PreviousConnectivity ([ordered]@{}) -Now $now).Count | Should -Be 0
        }
    }

    It 'a code change alone is a change, and committing twice for one run counts it once' {
        InModuleScope DoctorDO.Collector {
            $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            $st = New-DDState
            $r0 = @((Row 'p2p-firewall-rule' 'fail' 'not-in-force'))
            $st['lastConnectivity'] = Get-DDConnectivityState -Connectivity $r0
            $r1 = @((Row 'p2p-firewall-rule' 'fail' 'absent'))
            Update-DDFlapState -State $st -Rows $r1 -Now $now
            $st['lastConnectivity'] = Get-DDConnectivityState -Connectivity $r1
            Update-DDFlapState -State $st -Rows $r1 -Now $now
            $st['flapCounts']['p2p-firewall-rule']['20261012'] | Should -Be 1
        }
    }

    It 'DoSvc idling is not a flap: p2p-listener and dosvc-running flipping between pass and warn all week report nothing' {
        InModuleScope DoctorDO.Collector {
            $t = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            $st = New-DDState
            $last = $null
            foreach ($i in 0..11) {
                $res = $(if ($i % 2 -eq 0) { 'pass' } else { 'warn' })
                $rows = @((Row 'p2p-listener' $res), (Row 'dosvc-running' $res), (Row 'p2p-inbound' $res $(if ($res -eq 'pass') { 'listening' } else { 'not-listening' })), (Row 'proxy-scope' $res))
                $coll = [pscustomobject]@{ Raw = [ordered]@{ collectedAt = (Format-DDIso -Value $t.AddHours($i)); connectivity = $rows; perfSnap = $null; errors = @() } }
                $last = ConvertTo-DDDiagSection -Diag (New-DDDiagInput -State $st -Connectivity $rows -Now $t.AddHours($i))
                Update-DDStateAfterTelemetry -State $st -Collection $coll -Telemetry ([ordered]@{ seq = $i + 1; errors = @() }) -Now $t.AddHours($i)
            }
            $st['flapCounts'].Count | Should -Be 0 -Because 'pass to warn is never a flap, and the idle warns are read as pass'
            $last.Contains('flap') | Should -BeFalse
        }
    }

    It 'the first run after an upgrade counts no flap and resends nothing that did not change: old state holds the bare result' {
        InModuleScope DoctorDO.Collector {
            $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            $rows = @((Row 'a' 'pass'), (Row 'p2p-firewall-rule' 'fail' 'no-allow'), (Row 'ep:do-cloud' 'pass'), (Row 'ep:do-cloud' 'warn' $null 'second'), (Row 'dhcp-option-234' 'pass'))
            # what a collector before result|code kept: the bare result, whatever the code
            $old = [ordered]@{}
            foreach ($r in $rows) { $old[(Get-DDConnectivityKey -Result $r)] = [string]$r['result'] }
            (Merge-DDFlapCounts -Counts $null -Rows $rows -PreviousConnectivity $old -Now $now).Count | Should -Be 0
            (Select-DDChangedConnectivity -Rows $rows -PreviousConnectivity $old).Count | Should -Be 0
            # a real change is still seen, and still not counted as a flap (the old code is unknown)
            $moved = @((Row 'a' 'fail'), (Row 'dhcp-option-234' 'pass'))
            $sel = Select-DDChangedConnectivity -Rows $moved -PreviousConnectivity $old
            $sel.Count | Should -Be 1
            $sel[0]['checkId'] | Should -Be 'a'
            (Merge-DDFlapCounts -Counts $null -Rows $moved -PreviousConnectivity $old -Now $now).Count | Should -Be 0
            # once the new composite is stored the next comparison is normal again
            $new = Get-DDConnectivityState -Connectivity $rows
            (Select-DDChangedConnectivity -Rows $rows -PreviousConnectivity $new).Count | Should -Be 0
            (Merge-DDFlapCounts -Counts $null -Rows @((Row 'a' 'fail')) -PreviousConnectivity $new -Now $now)['a']['20261012'] | Should -Be 1
        }
    }

    It 'counts a transition that involves fail, and a code change within one non-pass result; not the rest' {
        InModuleScope DoctorDO.Collector {
            $t = { param($id, $from, $to, $code = $null) Test-DDConnectivityFlap -CheckId $id -Previous $from -Result (Row $id $to $code) }
            (& $t 'dosvc-running' 'pass|' 'fail' 'start-disabled') | Should -BeTrue
            (& $t 'dosvc-running' 'fail|start-disabled' 'pass') | Should -BeTrue
            (& $t 'dosvc-running' 'fail|start-disabled' 'warn') | Should -BeTrue -Because 'fail to idle is a recovery from fail'
            (& $t 'dosvc-running' 'warn|' 'fail' 'start-disabled') | Should -BeTrue
            (& $t 'p2p-listener' 'pass|' 'fail') | Should -BeTrue
            (& $t 'p2p-firewall-rule' 'fail|no-allow' 'fail' 'shadowed') | Should -BeTrue
            (& $t 'p2p-firewall-rule' 'fail|shadowed' 'not-collected') | Should -BeTrue
            (& $t 'some-check' 'warn|a' 'warn' 'b') | Should -BeTrue
            (& $t 'some-check' 'pass|' 'warn') | Should -BeFalse
            (& $t 'some-check' 'warn|' 'pass') | Should -BeFalse
            (& $t 'some-check' 'warn|a' 'warn' 'a') | Should -BeFalse
            (& $t 'some-check' 'fail|a' 'fail' 'a') | Should -BeFalse
            (& $t 'some-check' 'pass|' 'not-collected') | Should -BeFalse
            (& $t 'some-check' 'not-collected|timeout' 'not-collected' 'error') | Should -BeFalse -Because 'a different reason for a failed read is not the device changing'
            (& $t 'some-check' 'not-applicable|no-pac' 'not-applicable' 'no-proxy') | Should -BeFalse
            (& $t 'some-check' 'not-collected|a' 'not-applicable' 'b') | Should -BeFalse
            (& $t 'some-check' 'warn|a' 'not-collected' 'b') | Should -BeFalse
            (& $t 'some-check' 'not-applicable|a' 'warn' 'b') | Should -BeFalse
            (& $t 'some-check' 'not-collected|a' 'not-collected' 'a') | Should -BeFalse
            (& $t 'some-check' 'not-applicable|' 'pass') | Should -BeFalse
            (& $t 'dosvc-running' 'pass|' 'warn') | Should -BeFalse
            (& $t 'dosvc-running' 'warn|' 'warn') | Should -BeFalse
            (& $t 'p2p-inbound' 'warn|not-listening' 'pass' 'listening') | Should -BeFalse
        }
    }

    It 'keeps seven days: older buckets expire, and the totals add the days up' {
        InModuleScope DoctorDO.Collector {
            $now = [datetime]::new(2026, 10, 17, 8, 0, 0, [System.DateTimeKind]::Utc)
            $counts = [ordered]@{ a = [ordered]@{ '20261010' = 5; '20261011' = 1; '20261015' = 2 }; gone = [ordered]@{ '20261001' = 9 } }
            $m = Merge-DDFlapCounts -Counts $counts -Rows @() -PreviousConnectivity $null -Now $now
            $m.Contains('gone') | Should -BeFalse
            $m['a'].Contains('20261010') | Should -BeFalse -Because '10 October is 7 days before 17 October: the window is the 7 UTC days 11 to 17 October'
            (Get-DDFlapTotals -Counts $m)['a'] | Should -Be 3
        }
    }

    It 'is bounded to 64 checks, keeping those that changed most' {
        InModuleScope DoctorDO.Collector {
            $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            $rows0 = 1..80 | ForEach-Object { Row ("c$('{0:D2}' -f $_)") 'pass' }
            $rows1 = 1..80 | ForEach-Object { Row ("c$('{0:D2}' -f $_)") 'fail' }
            $counts = [ordered]@{}
            foreach ($i in 1..10) { $counts["old$i"] = [ordered]@{ '20261012' = 7 } }
            $m = Merge-DDFlapCounts -Counts $counts -Rows $rows1 -PreviousConnectivity (Get-DDConnectivityState -Connectivity $rows0) -Now $now
            $m.Count | Should -Be 64
            foreach ($i in 1..10) { $m.Contains("old$i") | Should -BeTrue }
        }
    }

    It 'ConvertTo-DDValidFlapCounts drops what does not fit the wire pattern or has no usable bucket' {
        InModuleScope DoctorDO.Collector {
            $v = ConvertTo-DDValidFlapCounts -Candidate ([ordered]@{ ok = [ordered]@{ '20261012' = 3; 'bad' = 2; '20261013' = 'x'; '20261014' = 500 }; 'Bad Name!' = [ordered]@{ '20261012' = 1 }; none = [ordered]@{}; notdict = 5 })
            @($v.Keys) | Should -Be @('ok')
            $v['ok']['20261012'] | Should -Be 3
            $v['ok']['20261014'] | Should -Be 99
            $v['ok'].Contains('bad') | Should -BeFalse
            (ConvertTo-DDValidFlapCounts -Candidate 'junk').Count | Should -Be 0
        }
    }

    It 'Select-DDFlapCounts emits only counts of 2 or more, the top 8, ties by name, capped at 99' {
        InModuleScope DoctorDO.Collector {
            $t = [ordered]@{ one = 1; zz = 2; aa = 2; big = 250 }
            foreach ($i in 1..10) { $t["k$i"] = 3 }
            $s = Select-DDFlapCounts -Counts $t
            $s.Count | Should -Be 8
            $s.Contains('one') | Should -BeFalse
            @($s.Keys)[0] | Should -Be 'big'
            $s['big'] | Should -Be 99
            @($s.Keys)[1] | Should -Be 'k1'
            (Select-DDFlapCounts -Counts ([ordered]@{ aa = 2; zz = 2 })).Keys | Should -Be @('aa', 'zz')
            (Select-DDFlapCounts -Counts ([ordered]@{ 'ep:do-content' = 2 })).Contains('ep:do-content') | Should -BeTrue
            (Select-DDFlapCounts -Counts $null).Count | Should -Be 0
        }
    }

    It 'three runs that flip a check back and forth put it in the report once it changed twice, and a lost state clears it' {
        InModuleScope DoctorDO.Collector {
            $t = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            $st = New-DDState
            $sent = @()
            foreach ($i in 0..3) {
                $res = $(if ($i % 2 -eq 0) { 'pass' } else { 'fail' })
                $coll = [pscustomobject]@{ Raw = [ordered]@{ collectedAt = (Format-DDIso -Value $t.AddHours($i)); connectivity = @((Row 'dhcp-option-234' $res)); perfSnap = $null; errors = @() } }
                $diag = New-DDDiagInput -State $st -Connectivity $coll.Raw['connectivity'] -Now $t.AddHours($i)
                $sent += , (ConvertTo-DDDiagSection -Diag $diag)
                Update-DDStateAfterTelemetry -State $st -Collection $coll -Telemetry ([ordered]@{ seq = $i + 1; errors = @() }) -Now $t.AddHours($i)
            }
            $sent[0].Contains('flap') | Should -BeFalse
            $sent[1].Contains('flap') | Should -BeFalse -Because 'one change'
            $sent[2]['flap']['dhcp-option-234'] | Should -Be 2
            $sent[3]['flap']['dhcp-option-234'] | Should -Be 3
            $st['lastConnectivity']['dhcp-option-234||local|'] | Should -Be 'fail|'
        }
    }
}

Describe 'TelemetryV1.diag (3.8)' {
    It 'is left out when the collector measured nothing, and an empty object when it measured and all is healthy' {
        InModuleScope DoctorDO.Collector {
            $raw = [ordered]@{ schemaVersion = 1; collector = [ordered]@{ name = 'x'; version = '0' }; collectedAt = '2026-10-12T08:00:00Z'; device = [ordered]@{}; network = [ordered]@{}; connectivity = @() }
            $none = ConvertTo-DDTelemetry -Raw $raw -Seq 1 -InventoryHash 'sha256:x' -PeriodFrom 'a' -PeriodTo 'b'
            $none.Contains('diag') | Should -BeFalse
            (ConvertTo-DDCanonicalJson -InputObject $none) | Should -Not -Match '"diag"'
            $healthy = ConvertTo-DDTelemetry -Raw $raw -Seq 1 -InventoryHash 'sha256:x' -PeriodFrom 'a' -PeriodTo 'b' -Diag ([ordered]@{ crash = 0; flap = [ordered]@{ a = 1 } })
            $healthy['diag'].Count | Should -Be 0
            (ConvertTo-DDCanonicalJson -InputObject $healthy) | Should -Match '"diag":\{\}'
        }
    }

    It 'sends crash only when above 0 (absence means none), up whenever it was measured, flap for checks that changed twice' {
        InModuleScope DoctorDO.Collector {
            $d = ConvertTo-DDDiagSection -Diag ([ordered]@{ crash = 4; up = 3; flap = [ordered]@{ 'ep:do-content' = 2; solo = 1 } })
            (ConvertTo-DDCanonicalJson -InputObject $d) | Should -BeExactly '{"crash":4,"flap":{"ep:do-content":2},"up":3}'
            (ConvertTo-DDCanonicalJson -InputObject (ConvertTo-DDDiagSection -Diag ([ordered]@{ crash = 0; up = 0 }))) | Should -BeExactly '{"up":0}'
            (ConvertTo-DDCanonicalJson -InputObject (ConvertTo-DDDiagSection -Diag ([ordered]@{ crash = $null; up = $null }))) | Should -BeExactly '{}'
            (ConvertTo-DDDiagSection -Diag ([ordered]@{ crash = 500; up = 99 }))['crash'] | Should -Be 99
            (ConvertTo-DDDiagSection -Diag ([ordered]@{ up = 99 }))['up'] | Should -Be 24
            ConvertTo-DDDiagSection -Diag $null | Should -BeNullOrEmpty
        }
    }

    It 'puts the diag notCollected records first, so a full collection list cannot push them past the 64 cap' {
        InModuleScope DoctorDO.Collector {
            $nc = 1..64 | ForEach-Object { [ordered]@{ field = "f$_"; reason = 'error' } }
            $raw = [ordered]@{ schemaVersion = 1; collector = [ordered]@{ name = 'x'; version = '0' }; collectedAt = '2026-10-12T08:00:00Z'; device = [ordered]@{}; network = [ordered]@{}; connectivity = @(); notCollected = $nc[0..9] }
            $dg = @([ordered]@{ field = 'diag.crash'; reason = 'timeout' }, [ordered]@{ field = 'diag.up'; reason = 'error' })
            $t = ConvertTo-DDTelemetry -Raw $raw -Seq 1 -InventoryHash 'sha256:x' -PeriodFrom 'a' -PeriodTo 'b' -Diag ([ordered]@{ up = 9; notCollected = $dg })
            @($t['notCollected']).Count | Should -Be 12
            $t['notCollected'][0]['field'] | Should -Be 'diag.crash'
            $t['notCollected'][1]['field'] | Should -Be 'diag.up'
            $t['notCollected'][2]['field'] | Should -Be 'f1'
            # a full list: the cap drops the last collection records, never the diagnosis ones
            $raw['notCollected'] = $nc
            $full = @((ConvertTo-DDTelemetry -Raw $raw -Seq 1 -InventoryHash 'sha256:x' -PeriodFrom 'a' -PeriodTo 'b' -Diag ([ordered]@{ notCollected = $dg }))['notCollected'])
            $full.Count | Should -Be 64
            @($full | Where-Object { $_['field'] -like 'diag.*' }).Count | Should -Be 2
            $full[63]['field'] | Should -Be 'f62'
        }
    }

    It 'a fleet telemetry from the fake device carries diag with crash 2 and up 1, and it stays small' {
        Initialize-FakeDevice -FileCount 40
        $sp = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-dg-" + [guid]::NewGuid().ToString('N') + '/state.json')
        $t = Get-DOTelemetry -StatePath $sp -Anonymise
        $t['diag']['crash'] | Should -Be 2
        $t['diag']['up'] | Should -Be 1
        $t['diag'].Contains('flap') | Should -BeFalse
        InModuleScope DoctorDO.Collector -Parameters @{ T = $t } {
            param($T)
            $with = (ConvertTo-DDReportBytes -Report $T).Gzip.Length
            $T2 = [ordered]@{}; foreach ($k in $T.Keys) { if ($k -ne 'diag') { $T2[$k] = $T[$k] } }
            $without = (ConvertTo-DDReportBytes -Report $T2).Gzip.Length
            ($with - $without) | Should -BeLessThan 32 -Because 'typical diag is under 32 bytes compressed (docs/27 3.8)'
            # worst case: eight flapping checks, crash, up
            $flap = [ordered]@{}; foreach ($i in 1..8) { $flap["check-$i-flapping"] = 40 + $i }
            $T3 = [ordered]@{}; foreach ($k in $T.Keys) { $T3[$k] = $T[$k] }
            $T3['diag'] = ConvertTo-DDDiagSection -Diag ([ordered]@{ crash = 12; up = 3; flap = $flap })
            (((ConvertTo-DDReportBytes -Report $T3).Gzip.Length) - $without) | Should -BeLessThan 160 -Because 'worst diag is under 160 bytes compressed (docs/27 3.8)'
        }
    }

    It 'the state file keeps flap counters and the diag cache across runs and discards a corrupt block' {
        InModuleScope DoctorDO.Collector {
            $s = ConvertTo-DDValidState -Candidate ([ordered]@{ flapCounts = [ordered]@{ a = [ordered]@{ '20261012' = 2 } }; diag = [ordered]@{ at = '2026-10-12T08:00:00Z'; crash = 1; up = 5; nc = @() } })
            $s['flapCounts']['a']['20261012'] | Should -Be 2
            $s['diag']['up'] | Should -Be 5
            $bad = ConvertTo-DDValidState -Candidate ([ordered]@{ flapCounts = 'x'; diag = [ordered]@{ at = 'nope'; crash = 1 } })
            $bad['flapCounts'].Count | Should -Be 0
            $bad['diag'] | Should -BeNullOrEmpty
            (New-DDState).Contains('flapCounts') | Should -BeTrue
        }
    }
}
