#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    $script:Intune = (Resolve-Path (Join-Path $PSScriptRoot '../intune')).Path
    . (Join-Path $script:Intune 'Detect-DoctorDO.ps1')
    . (Join-Path $script:Intune 'Remediate-DoctorDO.ps1')
}

Describe 'Detection script' {
    It 'is compliant (exit 0) inside the window and non-compliant (exit 1) outside it or when nothing was ever recorded' {
        Mock Get-ItemProperty { [pscustomobject]@{ LastSuccessfulCollection = '2026-10-12T06:00:00Z' } }
        $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
        (Test-DoctorDOCollectionFresh -MaxAgeHours 26 -RegistryPath 'HKLM:\x' -Now $now).Fresh | Should -BeTrue
        (Test-DoctorDOCollectionFresh -MaxAgeHours 1 -RegistryPath 'HKLM:\x' -Now $now).Fresh | Should -BeFalse
        Mock Get-ItemProperty { throw 'not found' }
        $r = Test-DoctorDOCollectionFresh -MaxAgeHours 26 -RegistryPath 'HKLM:\x' -Now $now
        $r.Fresh | Should -BeFalse; $r.Message | Should -Match 'no successful'
        Mock Get-ItemProperty { [pscustomobject]@{ LastSuccessfulCollection = 'banana' } }
        (Test-DoctorDOCollectionFresh -MaxAgeHours 26 -RegistryPath 'HKLM:\x' -Now $now).Fresh | Should -BeFalse
    }

    It 'output is never empty and is stable between runs (Intune: empty output means "issue not found"; avoid timestamps)' {
        Mock Get-ItemProperty { [pscustomobject]@{ LastSuccessfulCollection = '2026-10-12T06:00:00Z' } }
        $a = (Test-DoctorDOCollectionFresh -MaxAgeHours 26 -RegistryPath 'HKLM:\x' -Now ([datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc))).Message
        $b = (Test-DoctorDOCollectionFresh -MaxAgeHours 26 -RegistryPath 'HKLM:\x' -Now ([datetime]::new(2026, 10, 12, 9, 30, 0, [System.DateTimeKind]::Utc))).Message
        $a | Should -Not -BeNullOrEmpty
        $a | Should -Be $b
    }

    Context 'the window is shorter than the schedule, so a daily schedule collects every day' {
        BeforeAll {
            # The default the script ships with, read from its param block, so the tests pin what Intune actually runs.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Intune 'Detect-DoctorDO.ps1'), [ref]$null, [ref]$null)
            $p = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MaxAgeHours' }
            $script:DefaultMaxAge = [int]$p.DefaultValue.Value
            $script:Collected = '2026-10-12T08:10:00Z'
            $script:At = { param([double] $Hours) ([datetime]::Parse($script:Collected, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)).AddHours($Hours) }
        }
        BeforeEach { Mock Get-ItemProperty { [pscustomobject]@{ LastSuccessfulCollection = $script:Collected } } }

        It 'defaults to 22 hours: under the 24 hours between daily runs' {
            $script:DefaultMaxAge | Should -Be 22
            $script:DefaultMaxAge | Should -BeLessThan 24
        }

        It 'a collection 24 hours old on a daily schedule is due: detection exits 1 and remediation runs' {
            (Test-DoctorDOCollectionFresh -MaxAgeHours $script:DefaultMaxAge -RegistryPath 'HKLM:\x' -Now (& $script:At 24)).Fresh | Should -BeFalse
            # The remediation's start jitter (up to 600 s) and the run itself put the timestamp minutes after detection, so the
            # next daily detection sees a little under 24 hours: still due.
            (Test-DoctorDOCollectionFresh -MaxAgeHours $script:DefaultMaxAge -RegistryPath 'HKLM:\x' -Now (& $script:At 23.75)).Fresh | Should -BeFalse
            # The old default, 26, found that collection fresh and skipped the day: every device reported every other day.
            (Test-DoctorDOCollectionFresh -MaxAgeHours 26 -RegistryPath 'HKLM:\x' -Now (& $script:At 24)).Fresh | Should -BeTrue
        }

        It 'a collection 3 hours old is fresh: no second run after a catch-up' {
            (Test-DoctorDOCollectionFresh -MaxAgeHours $script:DefaultMaxAge -RegistryPath 'HKLM:\x' -Now (& $script:At 3)).Fresh | Should -BeTrue
        }

        It 'weekly: 160 hours finds a collection 168 hours old due and one 150 hours old fresh' {
            (Test-DoctorDOCollectionFresh -MaxAgeHours 160 -RegistryPath 'HKLM:\x' -Now (& $script:At 168)).Fresh | Should -BeFalse
            (Test-DoctorDOCollectionFresh -MaxAgeHours 160 -RegistryPath 'HKLM:\x' -Now (& $script:At 150)).Fresh | Should -BeTrue
        }

        It 'the help and the README say the same numbers' {
            $text = Get-Content (Join-Path $script:Intune 'Detect-DoctorDO.ps1') -Raw
            $text | Should -Match 'Default 22'
            $text | Should -Match 'Use 160 for a weekly'
            $readme = Get-Content (Join-Path $script:Intune 'README.md') -Raw
            $readme | Should -Match '\(default 22; use 160 for a weekly cadence\)'
            $readme | Should -Match '\| `-MaxAgeHours` \| `Detect-DoctorDO\.ps1` \| 22 \|'
        }
    }

    It 'run as a script, exits with the right code and performs no collection' {
        $pwsh = (Get-Process -Id $PID).Path
        # With no module installed the detection says so first (the remediation installs it); the collection check is in Remediation.Tests.ps1.
        $out = & $pwsh -NoProfile -File (Join-Path $script:Intune 'Detect-DoctorDO.ps1') -RegistryPath 'HKLM:\SOFTWARE\DoctorDO-does-not-exist' -ModulesPath (Join-Path $TestDrive 'no-modules') -LogPath (Join-Path $TestDrive 'detect.log')
        $LASTEXITCODE | Should -Be 1
        ($out -join ' ') | Should -Match 'is not installed for all users'
        (Get-Content (Join-Path $script:Intune 'Detect-DoctorDO.ps1') -Raw) | Should -Not -Match 'Invoke-DoctorDOCollector|Get-DOInventory|Send-DoctorDOReport'
    }
}

Describe 'Remediation script' {
    It 'refuses to run unconfigured and never contacts anything (exit 3)' {
        $global:DDCalled = $false
        $r = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri '' -ConfiguredIngestUri 'https://REPLACE-WITH-YOUR-INGEST-HOST/v1/ingest' -Collector { $global:DDCalled = $true; [pscustomobject]@{ ExitCode = 0 } }
        $r.ExitCode | Should -Be 3
        $r.Message | Should -Match 'not configured'
        $global:DDCalled | Should -BeFalse
    }

    It 'rejects a non-https endpoint' {
        Resolve-DoctorDOIngestUri -Explicit 'http://ingest.example/v1/ingest' -Configured '' -FromEnvironment '' | Should -BeNullOrEmpty
        (Resolve-DoctorDOIngestUri -Explicit '' -Configured 'https://ingest.example/v1/ingest' -FromEnvironment '').Host | Should -Be 'ingest.example'
    }

    It 'jitters the start within the bound, then runs the collector and passes its exit code through' {
        $global:DDSlept = @()
        $global:DDHost = $null
        $r = Invoke-DoctorDORemediation -MaxJitterSeconds 120 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' -Sleep { param($s) $global:DDSlept += $s } -Collector { param($u) $global:DDHost = $u.Host; [pscustomobject]@{ ExitCode = 6; Message = 'no certificate' } }
        $r.ExitCode | Should -Be 6
        $r.Message | Should -Be 'no certificate'
        $global:DDHost | Should -Be 'ingest.example'
        @($global:DDSlept).Count | Should -BeLessOrEqual 1
        if (@($global:DDSlept).Count -eq 1) { $global:DDSlept[0] | Should -BeLessOrEqual 120 }
        1..50 | ForEach-Object { Get-DoctorDOStartDelay -MaxJitterSeconds 30 } | ForEach-Object { $_ | Should -BeLessOrEqual 30 }
        Get-DoctorDOStartDelay -MaxJitterSeconds 0 | Should -Be 0
    }

    It 'accepts only https://<host>/v1/ingest, completing a bare host (the path is signed)' {
        (Resolve-DoctorDOIngestUri -Explicit 'https://func-x.azurewebsites.net' -Configured '' -FromEnvironment '').AbsoluteUri | Should -BeExactly 'https://func-x.azurewebsites.net/v1/ingest'
        (Resolve-DoctorDOIngestUri -Explicit 'https://func-x.azurewebsites.net/v1/ingest' -Configured '' -FromEnvironment '').AbsoluteUri | Should -BeExactly 'https://func-x.azurewebsites.net/v1/ingest'
        Resolve-DoctorDOIngestUri -Explicit 'https://func-x.azurewebsites.net/api/ingest' -Configured '' -FromEnvironment '' | Should -BeNullOrEmpty
        Resolve-DoctorDOIngestUri -Explicit 'https://func-x.azurewebsites.net/v1/ingest?code=abc' -Configured '' -FromEnvironment '' | Should -BeNullOrEmpty
    }

    It 'passes the device anchor to the collector: entra-device by default, tenant-ca when configured' {
        $global:DDAnchor = $null
        $c = { param($u, $a) $global:DDAnchor = $a; [pscustomobject]@{ ExitCode = 0 } }
        $null = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' -Collector $c
        $global:DDAnchor | Should -Be 'entra-device'
        $null = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' -ConfiguredDeviceAnchor 'tenant-ca' -Collector $c
        $global:DDAnchor | Should -Be 'tenant-ca'
        $null = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' -DeviceAnchor 'Entra-Device' -ConfiguredDeviceAnchor 'tenant-ca' -Collector $c
        $global:DDAnchor | Should -Be 'entra-device' -Because 'an explicit value wins and is case-insensitive'
    }

    It 'passes -CollectPublicEgress to the collector only when a setting turns it on; off by default (F-12)' {
        $global:DDEgress = 'unset'
        $c = { param($u, $a, $e) $global:DDEgress = $e; [pscustomobject]@{ ExitCode = 0 } }
        $null = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' -Collector $c
        $global:DDEgress | Should -BeFalse
        $null = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' -Collector $c -CollectPublicEgress $true
        $global:DDEgress | Should -BeTrue
        $null = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' -Collector $c -ConfiguredCollectPublicEgress $true
        $global:DDEgress | Should -BeTrue
        Resolve-DoctorDOCollectPublicEgress -Explicit $false -Configured $false -FromEnvironment '1' | Should -BeTrue
        Resolve-DoctorDOCollectPublicEgress -Explicit $false -Configured $false -FromEnvironment 'TRUE' | Should -BeTrue
        Resolve-DoctorDOCollectPublicEgress -Explicit $false -Configured $false -FromEnvironment '' | Should -BeFalse
        Resolve-DoctorDOCollectPublicEgress -Explicit $false -Configured $false -FromEnvironment 'no' | Should -BeFalse
        # The script ships with it off, and the collector call passes it on.
        $text = Get-Content (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -Raw
        $text | Should -Match '(?m)^\$ConfiguredCollectPublicEgress = \$false'
        $text | Should -Match 'Invoke-DoctorDOCollector -Fleet -IngestUri \$uri -DeviceAnchor \$anchor -CollectPublicEgress:\(\[bool\]\$egress\)'
    }

    It 'refuses an unknown device anchor (exit 3) without running the collector' {
        $global:DDCalled = $false
        $r = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' -ConfiguredDeviceAnchor 'scep' -Collector { $global:DDCalled = $true; [pscustomobject]@{ ExitCode = 0 } }
        $r.ExitCode | Should -Be 3
        $r.Message | Should -Match 'device anchor'
        $global:DDCalled | Should -BeFalse
    }

    It 'the shipped script defaults to entra-device and calls the collector with -DeviceAnchor' {
        $t = Get-Content (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -Raw
        $t | Should -Match "ConfiguredDeviceAnchor = 'entra-device'"
        $t | Should -Match 'Invoke-DoctorDOCollector -Fleet -IngestUri \$uri -DeviceAnchor \$anchor'
        $t | Should -Match 'Run this script using the logged-on credentials = No'
    }

    It 'contains no secret, key or token' {
        $t = Get-Content (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -Raw
        $t | Should -Not -Match '(?i)apikey|ingest[-_ ]?key|tenant[-_ ]?key|password|secret|bearer'
    }
}

Describe 'Connectivity check and platform guard (real, unmocked, on Linux)' {
    It 'Test-DOConnectivity -SkipConnectivityChecks -Json runs in a fresh session and never reports a skipped probe as a pass' {
        $pwsh = (Get-Process -Id $PID).Path
        $json = & $pwsh -NoProfile -Command "Import-Module '$(Join-Path $PSScriptRoot '../DoctorDO.Collector/DoctorDO.Collector.psd1')'; Test-DOConnectivity -SkipConnectivityChecks -Json"
        $LASTEXITCODE | Should -Be 0
        $rows = $json | ConvertFrom-Json
        ($rows | Where-Object checkId -eq 'do-cloud-tls').result | Should -Be 'not-collected'
        ($rows | Where-Object { $_.checkId -like 'do-content-cdn' }).result | Should -Not -Contain 'pass'
    }

    It 'Invoke-DoctorDOCollector exits 2 off Windows instead of pretending' -Skip:([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
        $pwsh = (Get-Process -Id $PID).Path
        $out = & $pwsh -NoProfile -Command "Import-Module '$(Join-Path $PSScriptRoot '../DoctorDO.Collector/DoctorDO.Collector.psd1')'; (Invoke-DoctorDOCollector -OutputPath ([IO.Path]::GetTempPath())).ExitCode"
        $out | Select-Object -Last 1 | Should -Be '2'
    }
}
