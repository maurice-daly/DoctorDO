#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:InventorySchema = (Resolve-Path (Join-Path $PSScriptRoot '../../contracts/inventory-v1.schema.json')).Path
    $script:State = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-prov-" + [guid]::NewGuid().ToString('N') + '/state.json')
    $script:AppA = '0a1b2c3d-1111-4222-8333-444455556666'
    $script:AppB = '9f8e7d6c-aaaa-4bbb-8ccc-ddddeeeeffff'
    $script:AppU = '12345678-90ab-4cde-8f01-23456789abcd'
    # The tree as Get-DDEspTrackingRaw returns it, in the layout "Troubleshooting the Enrollment Status Page" documents.
    $global:FakeEspTree = @(
        @{ Path = 'Device\Setup\Apps\Tracking\Sidecar'; Values = [ordered]@{} }
        @{ Path = "Device\Setup\Apps\Tracking\Sidecar\Win32App_$($script:AppA)_1"; Values = [ordered]@{ InstallationState = '3'; RebootRequired = '1' } }
        @{ Path = "Device\Setup\Apps\Tracking\Sidecar\Win32App_$($script:AppB)_1"; Values = [ordered]@{ InstallationState = '4' } }
        @{ Path = "S-1-12-1-1-2-3-4\Setup\Apps\Tracking\Sidecar\Win32App_$($script:AppU)_1"; Values = [ordered]@{ InstallationState = '3'; RebootRequired = '2' } }
        @{ Path = 'ESPTrackingInfo\Diagnostics\Sidecar\2026/10/18-09:00:05.120'; Values = [ordered]@{ "./Device/Vendor/MSFT/EnrollmentStatusTracking/Setup/Apps/Tracking/Sidecar/Win32App_$($script:AppA)_1/InstallationState" = '2' } }
        @{ Path = 'ESPTrackingInfo\Diagnostics\Sidecar\2026/10/18-09:12:45.000'; Values = [ordered]@{ "./Device/Vendor/MSFT/EnrollmentStatusTracking/Setup/Apps/Tracking/Sidecar/Win32App_$($script:AppA)_1/InstallationState" = '3' } }
        @{ Path = 'ESPTrackingInfo\Diagnostics\Sidecar\2026/10/18-09:13:00.000'; Values = [ordered]@{ "./Device/Vendor/MSFT/EnrollmentStatusTracking/Setup/Apps/Tracking/Sidecar/Win32App_$($script:AppB)_1/InstallationState" = '4' } }
        @{ Path = 'ESPTrackingInfo\Diagnostics\ExpectedPolicies\2026-10-18T08:58:00.000Z'; Values = [ordered]@{ EntDMID = '1' } }
        @{ Path = 'ESPTrackingInfo\Diagnostics\S-1-12-1-1-2-3-4\Sidecar\2026/10/18-09:20:00.000'; Values = [ordered]@{ "Win32App_$($script:AppU)_1" = '3' } }
        @{ Path = 'ESPTrackingInfo\Diagnostics\ExpectedNetworkProfiles\not a date'; Values = [ordered]@{ wifi = '1' } }
    )
    $global:FakeStatus = @(
        [ordered]@{ fileId = 'f1'; fileSize = '734003200'; priority = 'Foreground'; bytesFromHttp = '734003200'; bytesFromCacheServer = '0'; bytesFromLanPeers = '0'; bytesFromGroupPeers = '0'; bytesFromInternetPeers = '0'; downloadMs = 600000; predefinedCallerApplication = 'IntuneAppDownload' }
        [ordered]@{ fileId = 'f2'; fileSize = '2097152'; priority = 'Foreground'; bytesFromHttp = '0'; bytesFromCacheServer = '2097152'; bytesFromLanPeers = '0'; bytesFromGroupPeers = '0'; bytesFromInternetPeers = '0'; downloadMs = 1500; predefinedCallerApplication = $null }
        [ordered]@{ fileId = 'f3'; fileSize = '104857600'; priority = 'Background'; bytesFromHttp = '4857600'; bytesFromCacheServer = '0'; bytesFromLanPeers = '100000000'; bytesFromGroupPeers = '0'; bytesFromInternetPeers = '0'; downloadMs = 90000; predefinedCallerApplication = 'WU Client Download' }
    )
}

Describe 'ConvertFrom-DDEspTimestamp' {
    It 'reads the date forms a Diagnostics subkey may carry, as UTC, and nothing else' {
        InModuleScope DoctorDO.Collector {
            $t = ConvertFrom-DDEspTimestamp -Text '2026/10/18-16:19:18.153'
            $t.Kind | Should -Be 'Utc'
            $t.ToString('yyyy-MM-dd HH:mm:ss.fff', [cultureinfo]::InvariantCulture) | Should -Be '2026-10-18 16:19:18.153'
            (ConvertFrom-DDEspTimestamp -Text '2026-10-18T16:19:18.1534567Z').Millisecond | Should -Be 153
            ConvertFrom-DDEspTimestamp -Text 'Sidecar' | Should -BeNullOrEmpty
            ConvertFrom-DDEspTimestamp -Text '2026/13/45-99:99:99' | Should -BeNullOrEmpty
        }
    }
}

Describe 'ConvertTo-DDProvisioningSummary' {
    It 'counts the apps per phase from their InstallationState, dates them from Diagnostics and dates the ESP' {
        InModuleScope DoctorDO.Collector -Parameters @{ A = $script:AppA; B = $script:AppB; U = $script:AppU } {
            $s = ConvertTo-DDProvisioningSummary -Tree $global:FakeEspTree -Status $null -Now ([datetime]::new(2026, 10, 18, 10, 0, 0, [System.DateTimeKind]::Utc))
            $s.esp.firstStatusAt | Should -Be '2026-10-18T08:58:00Z'
            $s.esp.lastStatusAt | Should -Be '2026-10-18T09:20:00Z'
            $s.esp.statusesUnparsed | Should -Be 1
            $s.esp.deviceSetup.total | Should -Be 2
            $s.esp.deviceSetup.completed | Should -Be 1
            $s.esp.deviceSetup.error | Should -Be 1
            $s.esp.accountSetup.total | Should -Be 1
            $s.appsTotal | Should -Be 3
            $app = $s.apps | Where-Object { $_.id -eq $A }
            $app.phase | Should -Be 'device'
            $app.state | Should -Be 'completed'
            $app.reboot | Should -Be 'notRequired'
            $app.firstStatusAt | Should -Be '2026-10-18T09:00:05Z'
            $app.lastStatusAt | Should -Be '2026-10-18T09:12:45Z'
            $s.apps[0].id | Should -Be $A -Because 'the longest is first'
            ($s.apps | Where-Object { $_.id -eq $U }).phase | Should -Be 'user'
            ($s.apps | Where-Object { $_.id -eq $U }).reboot | Should -Be 'soft'
            # One dated status is a time, not a span: no duration of 0 is sent (A-10).
            ($s.apps | Where-Object { $_.id -eq $U }).firstStatusAt | Should -Be '2026-10-18T09:20:00Z'
            ($s.apps | Where-Object { $_.id -eq $U }).lastStatusAt | Should -BeNullOrEmpty
            $s.delivery | Should -BeNullOrEmpty -Because 'no job list was read'
        }
    }
    It 'is $null without an ESP tracking key' {
        InModuleScope DoctorDO.Collector { ConvertTo-DDProvisioningSummary -Tree $null -Status @() -Now ([datetime]::UtcNow) | Should -BeNullOrEmpty }
    }
    It 'keeps 30 apps at most, and counts them all' {
        InModuleScope DoctorDO.Collector {
            $tree = @(1..35 | ForEach-Object { @{ Path = ('Device\Setup\Apps\Tracking\Sidecar\Win32App_{0}_1' -f ([guid]::new('00000000-0000-4000-8000-{0:d12}' -f $_))); Values = [ordered]@{ InstallationState = '3' } } })
            $s = ConvertTo-DDProvisioningSummary -Tree $tree -Status $null -Now ([datetime]::UtcNow)
            $s.appsTotal | Should -Be 35
            @($s.apps).Count | Should -Be 30
            $s.esp.firstStatusAt | Should -BeNullOrEmpty
        }
    }
}

Describe 'ConvertTo-DDProvisioningDelivery' {
    It 'sums the job list by priority, counts the jobs below DOMinFileSizeToCache and lists the largest' {
        InModuleScope DoctorDO.Collector {
            $d = ConvertTo-DDProvisioningDelivery -Status $global:FakeStatus -MinFileSizeMB 10 -EspLast ([datetime]::new(2026, 10, 18, 9, 20, 0, [System.DateTimeKind]::Utc)) -Now ([datetime]::new(2026, 10, 18, 11, 20, 0, [System.DateTimeKind]::Utc))
            $d.anchor | Should -Be 'esp'
            $d.ageHours | Should -Be 2
            $d.jobs | Should -Be 3
            $d.foreground.jobs | Should -Be 2
            $d.foreground.bytes.http | Should -Be '734003200'
            $d.foreground.bytes.cache | Should -Be '2097152'
            $d.foreground.downloadMs | Should -Be 601500
            $d.background.bytes.lan | Should -Be '100000000'
            $d.belowMinFileSize.jobs | Should -Be 1
            $d.belowMinFileSize.bytes | Should -Be '2097152'
            $d.belowMinFileSize.minFileSizeMB | Should -Be 10
            $d.largest[0].sizeBytes | Should -Be '734003200'
            $d.largest[0].priority | Should -Be 'foreground'
            $d.largest[0].caller | Should -Be 'IntuneAppDownload'
            $d.largest[1].peers | Should -Be '100000000'
        }
    }
    It 'is $null more than 7 days after provisioning, or with no date to measure from' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDProvisioningDelivery -Status $global:FakeStatus -MinFileSizeMB 50 -EspLast ([datetime]::new(2026, 10, 1, 0, 0, 0, [System.DateTimeKind]::Utc)) -Now ([datetime]::new(2026, 10, 18, 0, 0, 0, [System.DateTimeKind]::Utc)) | Should -BeNullOrEmpty
            ConvertTo-DDProvisioningDelivery -Status $global:FakeStatus -MinFileSizeMB 50 -EspLast $null -OsInstallDate $null -Now ([datetime]::UtcNow) | Should -BeNullOrEmpty
        }
    }
    It 'with a dated ESP, sums only the jobs of the ESP''s own time (ExpireOn less DOMaxCacheAge) and counts the rest (A-10)' {
        InModuleScope DoctorDO.Collector {
            $first = [datetime]::new(2026, 10, 18, 9, 0, 0, [System.DateTimeKind]::Utc); $last = $first.AddMinutes(50)
            $job = { param($id, $finished) $r = [ordered]@{ fileId = $id; fileSize = '1048576'; priority = 'Foreground'; bytesFromHttp = '1048576'; bytesFromCacheServer = '0'; bytesFromLanPeers = '0'; bytesFromGroupPeers = '0'; bytesFromInternetPeers = '0'; downloadMs = 1000; predefinedCallerApplication = $null; expireOn = $null }
                if ($null -ne $finished) { $r['expireOn'] = Format-DDIso -Value $finished.AddSeconds(259200) }; $r }
            $status = @((& $job 'during' $first.AddMinutes(20)), (& $job 'before' $first.AddDays(-2)), (& $job 'later' $last.AddHours(30)), (& $job 'undated' $null))
            $now = $last.AddHours(40)
            $d = ConvertTo-DDProvisioningDelivery -Status $status -MinFileSizeMB 50 -EspFirst $first -EspLast $last -Now $now
            $d.jobs | Should -Be 1
            $d.jobsOutsideEsp | Should -Be 3
            $d.largest.Count | Should -Be 1
            # The zone of the ESP's dates is to-verify: the device's UTC offset widens the window on both sides.
            $wide = ConvertTo-DDProvisioningDelivery -Status @((& $job 'east' $first.AddHours(-2))) -MinFileSizeMB 50 -EspFirst $first -EspLast $last -Now $now -ZoneOffsetHours 3
            $wide.jobs | Should -Be 1
            ConvertTo-DDProvisioningDelivery -Status @((& $job 'east' $first.AddHours(-2))) -MinFileSizeMB 50 -EspFirst $first -EspLast $last -Now $now | Should -BeNullOrEmpty -Because 'nothing from the ESP''s time is never sent as zero bytes'
            # No cache age to subtract (0: unlimited): every job, as before, and no count.
            $all = ConvertTo-DDProvisioningDelivery -Status $status -MinFileSizeMB 50 -EspFirst $first -EspLast $last -Now $now -MaxCacheAgeSeconds 0
            $all.jobs | Should -Be 4
            $all.Contains('jobsOutsideEsp') | Should -BeFalse
            # A last status up to the zone offset ahead of the clock reads as just now.
            (ConvertTo-DDProvisioningDelivery -Status @((& $job 'during' $first.AddMinutes(20))) -MinFileSizeMB 50 -EspFirst $first -EspLast $last -Now $last.AddHours(-1) -ZoneOffsetHours 2).ageHours | Should -Be 0
        }
    }

    It 'falls back to the OS install date when no ESP status was dated, and reads an empty job list as no jobs' {
        InModuleScope DoctorDO.Collector {
            $d = ConvertTo-DDProvisioningDelivery -Status @() -MinFileSizeMB 50 -EspLast $null -OsInstallDate '2026-10-17' -Now ([datetime]::new(2026, 10, 18, 12, 0, 0, [System.DateTimeKind]::Utc))
            $d.anchor | Should -Be 'os-install'
            $d.jobs | Should -Be 0
            $d.ageHours | Should -Be 36
        }
    }
}

Describe 'Resolve-DDProvisioning: the delivery snapshot is captured once' {
    It 'keeps the stored snapshot, takes the tracking as read now, and drops everything when the ESP key is gone' {
        InModuleScope DoctorDO.Collector {
            $stored = [ordered]@{ esp = [ordered]@{}; delivery = [ordered]@{ capturedAt = '2026-10-18T11:20:00Z'; jobs = 3 } }
            $fresh = [ordered]@{ esp = [ordered]@{ lastStatusAt = '2026-10-18T09:20:00Z' }; appsTotal = 4; apps = @(); delivery = $null }
            $r = Resolve-DDProvisioning -Fresh $fresh -Stored $stored
            $r.delivery.capturedAt | Should -Be '2026-10-18T11:20:00Z'
            $r.appsTotal | Should -Be 4
            Resolve-DDProvisioning -Fresh $null -Stored $stored | Should -BeNullOrEmpty
            (Resolve-DDProvisioning -Fresh $fresh -Stored $null).delivery | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-DOInventory with an ESP-tracked device' {
    BeforeEach { Initialize-FakeDevice }

    It 'adds a provisioning section that validates against the contract, and none on a device without the ESP key' {
        Mock -ModuleName DoctorDO.Collector Get-DDEspTrackingRaw { $global:FakeEspTree }
        $inv = Get-DOInventory -StatePath $script:State
        Assert-ValidAgainstSchema -Object $inv -SchemaFile $script:InventorySchema
        $inv.provisioning.appsTotal | Should -Be 3
        $inv.provisioning.esp.deviceSetup.error | Should -Be 1

        Mock -ModuleName DoctorDO.Collector Get-DDEspTrackingRaw { $null }
        $inv2 = Get-DOInventory -StatePath $script:State
        $inv2.Contains('provisioning') | Should -BeFalse
    }
}

Describe 'The state keeps the provisioning section it was sent in' {
    It 'stores it after an inventory and reads it back through the state validation' {
        InModuleScope DoctorDO.Collector {
            $state = New-DDState
            $inv = [ordered]@{ collectedAt = '2026-10-18T11:20:00Z'; connectivity = @(); provisioning = [ordered]@{ esp = [ordered]@{ lastStatusAt = '2026-10-18T09:20:00Z' }; delivery = [ordered]@{ jobs = 3 } } }
            Update-DDStateAfterInventory -State $state -Collection ([pscustomobject]@{ Raw = @{} }) -Inventory $inv -FullHash ('sha256:' + ('a' * 64)) -StableHash ('sha256:' + ('b' * 64)) -Now ([datetime]::new(2026, 10, 18, 11, 20, 0, [System.DateTimeKind]::Utc))
            $back = ConvertTo-DDValidState -Candidate (ConvertFrom-DDJson -Text (ConvertTo-DDCanonicalJson -InputObject $state))
            $back['provisioning']['delivery']['jobs'] | Should -Be 3
            (ConvertTo-DDValidState -Candidate ([ordered]@{ provisioning = 'nonsense' }))['provisioning'] | Should -BeNullOrEmpty
        }
    }
}
