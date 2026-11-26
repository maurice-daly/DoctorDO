#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:InventorySchema = (Resolve-Path (Join-Path $PSScriptRoot '../../contracts/inventory-v1.schema.json')).Path
    $script:State = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-inv-" + [guid]::NewGuid().ToString('N') + '/state.json')
}

Describe 'Get-DOInventory with every Windows call mocked' {
    BeforeEach { Initialize-FakeDevice }

    It 'emits an inventory that validates against contracts/inventory-v1.schema.json' {
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        Assert-ValidAgainstSchema -Object $inv -SchemaFile $script:InventorySchema
    }

    It 'reports the PACs in force as fingerprints, scopes and counts, and never their URL, host or text (ADR-0038)' {
        Initialize-FakeDevice -Pac users
        $inv = Get-DOInventory -StatePath $script:State
        Assert-ValidAgainstSchema -Object $inv -SchemaFile $script:InventorySchema
        $pac = $inv.network.proxy.pac
        $pac.configured | Should -BeTrue
        $pac.versions | Should -Be 2
        $pac.referencesDo | Should -BeTrue
        $pac.userProfiles | Should -Be 2
        @($pac.items).Count | Should -Be 2
        foreach ($i in $pac.items) {
            $i.id | Should -Match '^pac:[0-9a-f]{16}$'
            $i.basis | Should -Be 'content'
            $i.scopes | Should -Be @('user')
            $i.userProfiles | Should -Be 1
            $i.routes.doCloud | Should -Be 'direct'
        }
        @($pac.items | Where-Object { @($_.doReferences).Count -gt 0 })[0].doReferences | Should -Be @('do-cloud', 'do-content')
        $json = $inv | ConvertTo-Json -Depth 32 -Compress
        $json | Should -Not -Match 'pac\.contoso\.example|proxy\.contoso\.example|FindProxyForURL|old\.pac|S-1-5-21'
    }

    It 'counts one PAC served under two URLs as one version, and the device PAC alone under the per-machine policy' {
        Initialize-FakeDevice -Pac device
        $pac = (Get-DOInventory -StatePath $script:State).network.proxy.pac
        $pac.versions | Should -Be 1
        $pac.items[0].scopes | Should -Be @('device') -Because "a user's own PAC is not in force while the per-machine policy is on"
        $pac.items[0].userProfiles | Should -Be 0
    }

    It 'reads the PAC configuration but downloads and runs nothing with -SkipConnectivityChecks' {
        Initialize-FakeDevice -Pac device
        $inv = Get-DOInventory -StatePath $script:State -SkipConnectivityChecks
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDHttpFetch -ParameterFilter { $Uri -like '*.pac' } -Times 0 -Exactly
        Should -Invoke -ModuleName DoctorDO.Collector Resolve-DDPacProxy -Times 0 -Exactly
        $inv.network.proxy.pac.configured | Should -BeTrue
        $inv.network.proxy.pac.referencesDo | Should -BeNullOrEmpty
        $inv.network.proxy.pac.items[0].fetch | Should -Be 'skipped'
        $inv.network.proxy.pac.items[0].basis | Should -Be 'url'
    }

    It 'reads identity from dsregcmd and the Intune device id from the enrolment' {
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        $inv.management.joinType | Should -Be 'hybrid'
        $inv.management.entraDeviceId | Should -Be '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20'
        $inv.management.tenantId | Should -Be '9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10'
        $inv.management.mdm.provider | Should -Be 'intune'
        $inv.management.mdm.intuneDeviceId | Should -Be 'c0a8e1d2-77b4-4f09-b3a1-5e2d9c4f6a88'
        $inv.management.mdm.serverHost | Should -Be 'enrollment.manage.microsoft.com'
        $inv.device.domainJoined | Should -BeTrue
        $inv.device.entraJoined | Should -BeTrue
        $inv.management.configMgr.coManagementFlags | Should -BeNullOrEmpty -Because 'no Configuration Manager client'
    }

    It 'reports a co-managed client''s workload flags with its site code' {
        Mock -ModuleName DoctorDO.Collector Get-DDConfigMgrRaw { [pscustomobject]@{ Client = $true; SiteCode = 'CON'; CoManagementFlags = 25 } }
        $inv = Get-DOInventory -StatePath $script:State
        $inv.management.configMgr.client | Should -BeTrue
        $inv.management.configMgr.siteCode | Should -Be 'CON'
        $inv.management.configMgr.coManagementFlags | Should -Be 25
        $inv.management.mdm.provider | Should -Be 'intune' -Because 'the client and the Intune enrolment together are co-management'
    }

    It 'collects hardware, OS and static device facts' {
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        $inv.hardware.manufacturer | Should -Be 'Contoso Devices'
        $inv.hardware.model | Should -Be 'Contoso Laptop 14'
        $inv.hardware.biosVersion | Should -Be '1.8.2'
        $inv.hardware.cpu.logicalCores | Should -Be 12
        $inv.hardware.tpm.version | Should -Be '2.0'
        $inv.hardware.disks[0].kind | Should -Be 'NVMe'
        $inv.os.build | Should -Be '10.0.26100'
        $inv.os.ubr | Should -Be 4061
        $inv.os.edition | Should -Be 'Windows 11 Enterprise' -Because 'Windows 11 still reports "Windows 10" in ProductName'
        $inv.os.installDate | Should -Be '2026-03-14'
        $inv.device.osBuild | Should -Be '10.0.26100.4061'
        $inv.device.ramGB | Should -Be 16
        $inv.device.chassis | Should -Be 'Laptop'
        $inv.device.isSupportedEdition | Should -BeTrue
        $inv.device.isVirtual | Should -BeFalse
    }

    It 'keeps the whole DO policy key (unknown values included) and records the effective value with its provider' {
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        ($inv.doConfig.stores.policy.values | ForEach-Object { $_.name }) | Should -Contain 'DOMadeUpFutureSetting'
        $inv.doConfig.stores.policy.confidence | Should -Be 'documented'
        $inv.doConfig.stores.mdm.present | Should -BeFalse
        $inv.doConfig.stores.mdm.confidence | Should -Be 'to-verify' -Because 'the PolicyManager layout was observed on a managed device; Microsoft documents the CSP, not this store (A-12)'
        $inv.doConfig.stores.serviceState.present | Should -BeTrue
        $inv.doConfig.effective.DODownloadMode.value | Should -Be 2 -Because 'the name "Group" maps to mode 2'
        $inv.doConfig.effective.DODownloadMode.provider | Should -Be 'GroupPolicy'
        $inv.doConfig.effective.DOGroupId.provider | Should -Be 'Mdm'
        $inv.doConfig.effective.DOMinRAMAllowedToPeer.provider | Should -Be 'Default' -Because 'MinTotalRAM is mapped to its CSP name'
        $inv.doConfig.effective.DOMinBatteryPercentageAllowedToUpload.provider | Should -Be 'Mdm'
        $inv.doConfig.workingDirectory | Should -Match 'DeliveryOptimization\\Cache$'
    }

    It 'lists firewall rules, with profiles expanded' {
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        $inv.firewallRules.Count | Should -Be 2
        @($inv.firewallRules[0].profiles).Count | Should -Be 3
        $inv.firewallRules[1].profiles | Should -Be @('Domain', 'Private')
    }

    It 'never silently omits a field it could not collect: Autopilot, public egress and others land in notCollected; DHCP options DO does not read are said to be not queried' {
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        $fields = $inv.notCollected | ForEach-Object { $_.field }
        # No DOCacheHostSource, DOGroupIdSource 3 or service flag: DO reads neither option, so neither is asked for.
        $inv.network.dhcp.state | Should -Be 'not-queried'
        $fields | Should -Not -Contain 'network.dhcpOption235'
        $fields | Should -Contain 'management.autopilot'
        $fields | Should -Contain 'network.publicEgressHash'
        $inv.network.dhcpOption235 | Should -BeNullOrEmpty
        $inv.management.autopilot | Should -BeNullOrEmpty
        ($inv.notCollected | Where-Object field -eq 'network.publicEgressHash').reason | Should -Be 'skipped-by-flag'
    }

    It 'says so when it runs in 32-bit PowerShell on 64-bit Windows, whose file and WinHTTP views are not the device''s (A-16)' {
        Mock -ModuleName DoctorDO.Collector Test-DDWow64Process { $true }
        $inv = Get-DOInventory -StatePath $script:State
        ($inv.notCollected | Where-Object field -eq 'platform.bitness').reason | Should -Be 'unsupported-os'
        Mock -ModuleName DoctorDO.Collector Test-DDWow64Process { $false }
        @((Get-DOInventory -StatePath $script:State).notCollected | Where-Object field -eq 'platform.bitness').Count | Should -Be 0
    }

    It 'reads the DoSvc state and its TCP table before any Delivery Optimization cmdlet, which might start the service (A-09)' {
        $global:DDOrder = New-Object 'System.Collections.Generic.List[string]'
        Mock -ModuleName DoctorDO.Collector Get-DDDoSvcState { $global:DDOrder.Add('service'); [pscustomobject]@{ Status = 'Stopped'; StartType = 'Manual' } }
        Mock -ModuleName DoctorDO.Collector Get-DDDoSvcTcpConnections { $global:DDOrder.Add('tcp'); @() }
        Mock -ModuleName DoctorDO.Collector Get-DDDOConfigRaw { $global:DDOrder.Add('Get-DOConfig'); $null }
        Mock -ModuleName DoctorDO.Collector Get-DDDOStatusRaw { $global:DDOrder.Add('Get-DeliveryOptimizationStatus'); @() }
        Mock -ModuleName DoctorDO.Collector Get-DDDOPerfSnapRaw { $global:DDOrder.Add('Get-DeliveryOptimizationPerfSnap'); $null }
        $inv = Get-DOInventory -StatePath $script:State
        $first = [math]::Min($global:DDOrder.IndexOf('Get-DOConfig'), $global:DDOrder.IndexOf('Get-DeliveryOptimizationStatus'))
        $global:DDOrder.IndexOf('service') | Should -BeLessThan $first
        $global:DDOrder.IndexOf('tcp') | Should -BeLessThan $first
        ($inv.connectivity | Where-Object checkId -eq 'dosvc-running').result | Should -Be 'warn' -Because 'the state read first, Stopped, is the one the check reports'
    }

    It 'turns a failing source into a typed notCollected record instead of crashing' {
        Mock -ModuleName DoctorDO.Collector Get-DDTpmRaw { throw [System.UnauthorizedAccessException]::new('Access is denied.') }
        Mock -ModuleName DoctorDO.Collector Get-DDDOConfigRaw { throw [System.Management.Automation.CommandNotFoundException]::new('Get-DOConfig is not recognized as a cmdlet') }
        $inv = Get-DOInventory -StatePath $script:State
        ($inv.notCollected | Where-Object field -eq 'hardware.tpm').reason | Should -Be 'insufficient-rights'
        ($inv.notCollected | Where-Object field -eq 'doConfig.effective').reason | Should -Be 'cmdlet-missing'
        $inv.hardware.tpm | Should -BeNullOrEmpty
    }

    It 'marks everything DO-specific not-collected on a build without the DeliveryOptimization module' {
        Initialize-FakeDevice -NoDoModule
        $inv = Get-DOInventory -StatePath $script:State
        ($inv.notCollected | Where-Object field -eq 'doConfig.effective').reason | Should -Be 'cmdlet-missing'
        # Policy still applies without the cmdlets: the Group Policy key is read and attributed from the registry.
        $inv.doConfig.effective.DODownloadMode.value | Should -Be 2
        $inv.doConfig.effective.DODownloadMode.source.kind | Should -Be 'gp'
        $inv.doConfig.effective.DODownloadMode.source.basis | Should -Be 'registry'
        # still schema-valid
        Assert-ValidAgainstSchema -Object $inv -SchemaFile $script:InventorySchema
    }

    It 'skips every probe with -SkipConnectivityChecks and says not-collected, never pass' {
        $inv = Get-DOInventory -StatePath $script:State -SkipConnectivityChecks
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDNetProbeBatch -Times 0
        ($inv.connectivity | Where-Object { $_.checkId -eq 'do-cloud-tls' }).result | Should -Be 'not-collected'
        ($inv.notCollected | Where-Object field -eq 'connectivity').reason | Should -Be 'skipped-by-flag'
    }

    It 'under -Anonymise carries no hostname, no raw addresses and no raw DOGroupId' {
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        $json = ConvertTo-Json -InputObject $inv -Depth 32 -Compress
        $inv.device.hostname | Should -BeNullOrEmpty
        $json | Should -Not -Match 'CONTOSO-LT-0042'
        $json | Should -Not -Match '10\.20\.4\.(71|1|55)\b'
        $json | Should -Not -Match 'a1b2c3d4-aaaa-bbbb-cccc-0123456789ab'
        $inv.network.localSubnet | Should -Be '10.20.4.0/22'
        $inv.device.deviceId | Should -Match '^sha256:[0-9a-f]{64}$'
        $inv.network.defaultGateway | Should -Match '^ip:[0-9a-f]{16}$'
    }

    It 'without -Anonymise keeps the hostname but still never emits a peer address' {
        $inv = Get-DOInventory -StatePath $script:State
        $inv.device.hostname | Should -Be 'CONTOSO-LT-0042'
        (ConvertTo-Json -InputObject $inv -Depth 32 -Compress) | Should -Not -Match '10\.20\.4\.55'
    }

    It 'produces the same change-detection hash for two runs of an unchanged device' {
        InModuleScope DoctorDO.Collector {
            $s = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-h-" + [guid]::NewGuid().ToString('N') + '/state.json')
            $salt = (Read-DDState -Path $s).State['salt']
            $a = ConvertTo-DDInventory -Collection (Get-DDRawCollection -Salt $salt -Anonymise)
            $b = ConvertTo-DDInventory -Collection (Get-DDRawCollection -Salt $salt -Anonymise)
            (Get-DDStableInventoryHash -Inventory $a) | Should -Be (Get-DDStableInventoryHash -Inventory $b)
        }
    }

    It 'changes the change-detection hash when the device changes' {
        InModuleScope DoctorDO.Collector {
            $salt = 'ab' * 16
            $a = ConvertTo-DDInventory -Collection (Get-DDRawCollection -Salt $salt -Anonymise)
            Mock Get-DDRegistryValue { if ($Name -eq 'UBR') { 4999 } elseif ($Name -eq 'CurrentBuild') { '26100' } elseif ($Name -eq 'CurrentMajorVersionNumber') { 10 } elseif ($Name -eq 'CurrentMinorVersionNumber') { 0 } elseif ($Name -eq 'EditionID') { 'Enterprise' } elseif ($Name -eq 'ProductName') { 'Windows 11 Enterprise' } else { $null } }
            $b = ConvertTo-DDInventory -Collection (Get-DDRawCollection -Salt $salt -Anonymise)
            (Get-DDStableInventoryHash -Inventory $a) | Should -Not -Be (Get-DDStableInventoryHash -Inventory $b)
        }
    }
}
