#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:BundleSchema = Get-ContractPath 'bundle-v1.schema.json'
    $script:Uri = [uri]'https://ingest.contoso.example/v1/ingest'
    function New-Dirs { $d = Join-Path ([System.IO.Path]::GetTempPath()) ('dd-inv-' + [guid]::NewGuid().ToString('N')); [pscustomobject]@{ Out = (Join-Path $d 'out'); State = (Join-Path $d 'state/state.json') } }
}

Describe 'Invoke-DoctorDOCollector: local deep bundle' {
    BeforeEach { Initialize-FakeDevice; $script:D = New-Dirs }

    It 'writes a zip with manifest.json and a bundle.json that validates against bundle-v1.schema.json' {
        $r = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -Anonymise -Bundle
        $r.ExitCode | Should -Be 0
        $r.BundlePath | Should -Exist
        $r.Sha256 | Should -Match '^[0-9A-F]{64}$'
        $r.SchemaVersion | Should -Be 1
        $r.DeviceId | Should -Match '^sha256:'
        $r.Anonymised | Should -BeTrue
        $r.DurationMs | Should -BeGreaterOrEqual 0
        $r.NotCollected | Should -Not -BeNullOrEmpty
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($r.BundlePath)
        try {
            # Local bundle only: the DoSvc service key, the network cost and dsregcmd /status travel beside bundle.json (never in fleet reports).
            ($zip.Entries.FullName | Sort-Object) | Should -Be @('bundle.json', 'dosvc-registry.json', 'dsregcmd-status.txt', 'manifest.json', 'nlm-cost.txt')
            $bundle = (New-Object System.IO.StreamReader($zip.GetEntry('bundle.json').Open())).ReadToEnd()
            $manifest = (New-Object System.IO.StreamReader($zip.GetEntry('manifest.json').Open())).ReadToEnd() | ConvertFrom-Json
            $reg = (New-Object System.IO.StreamReader($zip.GetEntry('dosvc-registry.json').Open())).ReadToEnd() | ConvertFrom-Json
            $reg.key | Should -Be 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc'
            @($reg.values | Where-Object name -eq 'Start').Count | Should -Be 1
            (New-Object System.IO.StreamReader($zip.GetEntry('nlm-cost.txt').Open())).ReadToEnd() | Should -Match 'Cost : unrestricted'
            $dsreg = (New-Object System.IO.StreamReader($zip.GetEntry('dsregcmd-status.txt').Open())).ReadToEnd()
            $dsreg | Should -Match 'AzureAdJoined : YES'
            $dsreg | Should -Not -Match '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' -Because '-Anonymise removes the tenant and device ids'
        } finally { $zip.Dispose() }
        @($manifest.files.name) | Should -Contain 'nlm-cost.txt'
        Assert-ValidAgainstSchema -Object $bundle -SchemaFile $script:BundleSchema
        $manifest.files[0].name | Should -Be 'bundle.json'
        $manifest.anonymised | Should -BeTrue
        $b = $bundle | ConvertFrom-Json
        $b.mode | Should -Be 'single'
        $b.status.Count | Should -Be 30 -Because 'a local bundle keeps every file row, unlike telemetry'
        $b.logExcerpt | Should -Not -BeNullOrEmpty
        $bundle | Should -Not -Match 'CONTOSO-LT-0042'
        $bundle | Should -Not -Match 'alice'
    }

    It 'flushes the DO log (which stops DoSvc, per Microsoft) in the admin-run local bundle unless -NoFlush' {
        $global:DDFlush = @()
        Mock -ModuleName DoctorDO.Collector Get-DDDOLogEntries { $global:DDFlush += [bool]$Flush; @() }
        $null = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State
        $null = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -NoFlush
        $global:DDFlush | Should -Be @($true, $false)
    }

    It 'is read-only: a local bundle never writes state, registry or the network' {
        Mock -ModuleName DoctorDO.Collector Send-DoctorDOReport { }
        Mock -ModuleName DoctorDO.Collector Invoke-DDHttpPost { }
        $null = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -Bundle
        Test-Path $script:D.State | Should -BeFalse
        Should -Invoke -ModuleName DoctorDO.Collector Send-DoctorDOReport -Times 0
        Should -Invoke -ModuleName DoctorDO.Collector Set-DDLastSuccess -Times 0
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDHttpPost -Times 0
    }

    It 'includes the redacted log excerpt only with -IncludeLog' {
        $r = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -IncludeLog -Anonymise
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($r.BundlePath)
        try {
            $zip.GetEntry('doctordo.log') | Should -Not -BeNullOrEmpty
            $log = (New-Object System.IO.StreamReader($zip.GetEntry('doctordo.log').Open())).ReadToEnd()
        } finally { $zip.Dispose() }
        $log | Should -Match '0x80D02002'
        $log | Should -Not -Match 'plain information line' -Because 'only retained-event lines'
        $log | Should -Not -Match 'alice|CONTOSO-LT-0042|10\.20\.4\.55'
    }

    It 'exit 1 when not elevated, exit 2 when not on Windows, exit 3 when collection throws' {
        Mock -ModuleName DoctorDO.Collector Test-DDElevated { $false }
        (Invoke-DoctorDOCollector -OutputPath $script:D.Out).ExitCode | Should -Be 1
        Mock -ModuleName DoctorDO.Collector Test-DDElevated { $true }
        Mock -ModuleName DoctorDO.Collector Test-DDWindows { $false }
        (Invoke-DoctorDOCollector -OutputPath $script:D.Out).ExitCode | Should -Be 2
        Mock -ModuleName DoctorDO.Collector Test-DDWindows { $true }
        Mock -ModuleName DoctorDO.Collector Get-DDRawCollection { throw 'kaboom' }
        $r = Invoke-DoctorDOCollector -OutputPath $script:D.Out
        $r.ExitCode | Should -Be 3
        $r.Message | Should -Match 'kaboom'
    }

    It 'sets LASTEXITCODE so a wrapper script can exit with it' {
        Mock -ModuleName DoctorDO.Collector Test-DDElevated { $false }
        $null = Invoke-DoctorDOCollector -OutputPath $script:D.Out
        $global:LASTEXITCODE | Should -Be 1
    }
}

Describe 'Verbose logging cycle (T-027): guaranteed restore' {
    BeforeEach {
        Initialize-FakeDevice; $script:D = New-Dirs
        $global:DDVerbose = @{ State = $false; Calls = New-Object System.Collections.Generic.List[string]; DisableThrows = $false; DisableNoEffect = $false }
        Mock -ModuleName DoctorDO.Collector Get-DDDOVerboseLogState { $global:DDVerbose.State }
        Mock -ModuleName DoctorDO.Collector Enable-DDDOVerboseLogs { $global:DDVerbose.Calls.Add('enable'); $global:DDVerbose.State = $true }
        Mock -ModuleName DoctorDO.Collector Disable-DDDOVerboseLogs {
            $global:DDVerbose.Calls.Add('disable')
            if ($global:DDVerbose.DisableThrows) { throw 'access denied' }
            if (-not $global:DDVerbose.DisableNoEffect) { $global:DDVerbose.State = $false }
        }
        Mock -ModuleName DoctorDO.Collector Wait-DDReproduction { $global:DDVerbose.Calls.Add('wait'); 'key' }
    }

    It 'enables, waits for the reproduction, collects, then restores the previous state' {
        $r = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue
        $r.ExitCode | Should -Be 0
        ($global:DDVerbose.Calls -join ',') | Should -Be 'enable,wait,disable'
        $global:DDVerbose.State | Should -BeFalse
    }

    It 'records the guided reproduction in the bundle manifest, and never stops or restarts DoSvc anywhere in the module' {
        $read = {
            param($r)
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($r.BundlePath)
            try { (New-Object System.IO.StreamReader($zip.GetEntry('manifest.json').Open())).ReadToEnd() | ConvertFrom-Json } finally { $zip.Dispose() }
        }
        $manifest = & $read (Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue)
        $manifest.reproduction.verboseEnabledByCollector | Should -BeTrue
        $manifest.reproduction.endedBy | Should -Be 'key'
        $manifest.reproduction.restored | Should -BeTrue
        $manifest.reproduction.dosvcStopped | Should -BeTrue -Because 'the default log flush stops DoSvc (F-11)'
        (& $read (Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue -NoFlush)).reproduction.dosvcStopped | Should -BeFalse
        $root = (Resolve-Path (Join-Path $PSScriptRoot '../DoctorDO.Collector')).Path
        foreach ($f in (Get-ChildItem -Path $root -Recurse -Include *.ps1, *.psm1 -File)) {
            $t = $null; $e = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
            $svc = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in 'Stop-Service', 'Restart-Service', 'Set-Service', 'Install-Module' }, $true)
            @($svc).Count | Should -Be 0 -Because "$($f.Name) must not stop, restart or reconfigure a service, or install a module"
        }
    }

    It 'restores even when collection throws' {
        Mock -ModuleName DoctorDO.Collector Get-DDRawCollection { throw 'collection blew up' }
        $r = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue
        $r.ExitCode | Should -Be 3
        ($global:DDVerbose.Calls -join ',') | Should -Be 'enable,wait,disable'
        $global:DDVerbose.State | Should -BeFalse
    }

    It 'restores when the pipeline is stopped mid-wait (what Ctrl-C does), using a real stoppable runspace' {
        $shared = [hashtable]::Synchronized(@{ State = $false; Calls = (New-Object System.Collections.ArrayList) })
        $modulePath = (Resolve-Path (Join-Path $PSScriptRoot '../DoctorDO.Collector/DoctorDO.Collector.psd1')).Path
        $ps = [System.Management.Automation.PowerShell]::Create()
        try {
            $null = $ps.AddScript({
                    param($Shared, $ModulePath)
                    Import-Module $ModulePath -Force -DisableNameChecking
                    $m = Get-Module DoctorDO.Collector
                    & $m {
                        param($S)
                        $script:S = $S
                        function Get-DDDOVerboseLogState { $script:S.State }
                        function Enable-DDDOVerboseLogs { [void]$script:S.Calls.Add('enable'); $script:S.State = $true }
                        function Disable-DDDOVerboseLogs { [void]$script:S.Calls.Add('disable'); $script:S.State = $false }
                        function Wait-DDReproduction { [void]$script:S.Calls.Add('wait'); Start-Sleep -Seconds 60 }
                        Invoke-DDVerboseCycle -Collect { 'collected' } -TimeoutMinutes 1
                    } $Shared
                }).AddArgument($shared).AddArgument($modulePath)
            $null = $ps.BeginInvoke()
            $deadline = (Get-Date).AddSeconds(30)
            while (-not ($shared.Calls -contains 'wait') -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
            $shared.Calls | Should -Contain 'wait' -Because 'the cycle reached the reproduction wait'
            $ps.Stop()      # equivalent of Ctrl-C: PipelineStoppedException is raised inside the cycle
            $deadline = (Get-Date).AddSeconds(15)
            while (-not ($shared.Calls -contains 'disable') -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
        } finally { $ps.Dispose() }
        ($shared.Calls -join ',') | Should -Be 'enable,wait,disable'
        $shared.State | Should -BeFalse
    }

    It 'leaves verbose logging as it found it when it was already on' {
        $global:DDVerbose.State = $true
        $null = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue
        $global:DDVerbose.Calls | Should -Not -Contain 'enable'
        $global:DDVerbose.Calls | Should -Not -Contain 'disable'
        $global:DDVerbose.State | Should -BeTrue
    }

    It 'exit 4 with the exact manual command when restoration throws' {
        $global:DDVerbose.DisableThrows = $true
        $r = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue 3>$null
        $r.ExitCode | Should -Be 4
        $r.Message | Should -Match 'Disable-DeliveryOptimizationVerboseLogs'
        $r.BundlePath | Should -Exist -Because 'the bundle is still written'
    }

    It 'exit 4 when restoration is verified and found not to have taken effect' {
        $global:DDVerbose.DisableNoEffect = $true
        (Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue 3>$null).ExitCode | Should -Be 4
    }

    It 'refuses to enable what it cannot restore: unknown previous state means no change at all' {
        Mock -ModuleName DoctorDO.Collector Get-DDDOVerboseLogState { $null }
        $r = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue
        $r.ExitCode | Should -Be 3
        $r.Message | Should -Match 'will not be enabled'
        $global:DDVerbose.Calls.Count | Should -Be 0
    }

    It 'with the state unreadable, -AssumeVerboseLoggingOff lets the operator state it; restoration then calls Disable' {
        Mock -ModuleName DoctorDO.Collector Get-DDDOVerboseLogState { $null }
        $r = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State -ReproduceIssue -AssumeVerboseLoggingOff
        $r.ExitCode | Should -Be 0
        ($global:DDVerbose.Calls -join ',') | Should -Be 'enable,wait,disable'
    }

    It 'never enables verbose logging without -ReproduceIssue' {
        $null = Invoke-DoctorDOCollector -OutputPath $script:D.Out -StatePath $script:D.State
        $global:DDVerbose.Calls.Count | Should -Be 0
    }

    It 'the wait is bounded: an unattended run auto-continues (default 15 minutes)' {
        (Get-Command Invoke-DoctorDOCollector).Parameters['ReproduceTimeoutMinutes'].Attributes.Where({ $_ -is [System.Management.Automation.ValidateRangeAttribute] }).MaxRange | Should -Be 60
        InModuleScope DoctorDO.Collector { (Get-Command Invoke-DDVerboseCycle).Parameters['TimeoutMinutes'] | Should -Not -BeNullOrEmpty }
    }
}

Describe 'Parameter rules' {
    It '-Fleet and -ReproduceIssue are mutually exclusive (rejected by the parameter sets)' {
        { Invoke-DoctorDOCollector -Fleet -IngestUri 'https://x.example/v1/ingest' -ReproduceIssue } | Should -Throw
    }
    It '-Fleet requires -IngestUri and -WhatIfRedaction is exclusive' {
        { Invoke-DoctorDOCollector -Fleet } | Should -Throw
        { Invoke-DoctorDOCollector -WhatIfRedaction -Fleet -IngestUri 'https://x.example/v1/ingest' } | Should -Throw
        { Invoke-DoctorDOCollector -WhatIfRedaction -OutputPath C:\Temp } | Should -Throw
    }
    It 'has no key or secret parameter' {
        $names = (Get-Command Invoke-DoctorDOCollector).Parameters.Keys
        $names | Where-Object { $_ -match 'Key$|Secret|Token|Password|Credential' } | Should -BeNullOrEmpty
        (Get-Command Send-DoctorDOReport).Parameters.Keys | Where-Object { $_ -match 'Key$|Secret|Token|Password|Credential' } | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-DoctorDOCollector -Fleet: inventory once, telemetry after' {
    BeforeEach {
        Initialize-FakeDevice -FileCount 40
        $script:D = New-Dirs
        $global:DDSent = New-Object System.Collections.Generic.List[object]
        $global:DDSendOutcome = 'Accepted'
        $global:DDNow = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
        Mock -ModuleName DoctorDO.Collector Get-DDNowUtc { $global:DDNow }
        Mock -ModuleName DoctorDO.Collector Send-DoctorDOReport {
            $global:DDSent.Add($Report)
            $o = $global:DDSendOutcome
            $exit = @{ Accepted = 0; RateLimited = 5; BackOff = 5; NoCertificate = 6; NetworkError = 5 }[$o]
            [pscustomobject]@{ Outcome = $o; StatusCode = 202; RetryAfterSeconds = $(if ($o -eq 'RateLimited') { 600 } else { $null }); Kind = $Report['kind']; CompressedBytes = 1; BudgetResult = 'within'; ExitCode = $exit; Message = $o }
        }
        $script:Run = { param([hashtable] $Extra = @{}) Invoke-DoctorDOCollector -Fleet -IngestUri $script:Uri -StatePath $script:D.State @Extra }
    }

    It 'first run: sends the inventory then the telemetry, anonymised by default, and commits state' {
        $r = & $script:Run
        $r.ExitCode | Should -Be 0
        ($global:DDSent | ForEach-Object { $_['kind'] }) | Should -Be @('inventory', 'telemetry')
        $global:DDSent[0]['anonymised'] | Should -BeTrue
        $global:DDSent[0]['device']['hostname'] | Should -BeNullOrEmpty
        $global:DDSent[1]['inventoryHash'] | Should -Be (InModuleScope DoctorDO.Collector -Parameters @{ I = $global:DDSent[0] } { param($I) Get-DDInventoryHash -Inventory $I }) -Because 'telemetry names the inventory it belongs to'
        $global:DDSent[1]['seq'] | Should -Be 1
        # A new device's first telemetry is a baseline: the 40 jobs already in its cache are not this period's traffic (docs/08).
        $global:DDSent[1]['counters'] | Should -Be 'baseline'
        @($global:DDSent[1]['files']).Count | Should -Be 0
        $st = InModuleScope DoctorDO.Collector -Parameters @{ P = $script:D.State } { param($P) (Read-DDState -Path $P).State }
        $st['seq'] | Should -Be 1
        $st['lastInventoryHash'] | Should -Match '^sha256:'
        @($st['counters']['jobs']['entries'].Keys).Count | Should -Be 40
        Should -Invoke -ModuleName DoctorDO.Collector Set-DDLastSuccess -Times 2
    }

    It 'never flushes the DO log in fleet mode: a fleet run must not stop DoSvc on thousands of devices' {
        $global:DDFlush = @()
        Mock -ModuleName DoctorDO.Collector Get-DDDOLogEntries { $global:DDFlush += [bool]$Flush; @() }
        $null = & $script:Run
        $global:DDFlush | Should -Be @($false)
    }

    It 'second run with nothing changed: telemetry only, seq 2, counters as deltas, no connectivity changes' {
        $null = & $script:Run
        $global:DDSent.Clear()
        $global:DDNow = $global:DDNow.AddMinutes(30)
        $r = & $script:Run
        $r.ExitCode | Should -Be 0
        ($global:DDSent | ForEach-Object { $_['kind'] }) | Should -Be @('telemetry')
        $global:DDSent[0]['seq'] | Should -Be 2
        $global:DDSent[0]['counters'] | Should -Be 'delta'
        @($global:DDSent[0]['files']).Count | Should -Be 0 -Because 'the jobs still in the cache moved nothing since the last report'
        $global:DDSent[0]['perf']['downloadHttpBytes'] | Should -Be 0
        $global:DDSent[0]['connectivityChanged'].Count | Should -Be 0
        $global:DDSent[0]['period']['from'] | Should -Be '2026-10-12T08:00:00Z'
    }

    It 'a telemetry report that is not accepted commits no counters: the next one carries both periods'' bytes, never fewer' {
        $null = & $script:Run
        # Job 1 moves 1,000 bytes; the report is refused; it moves 500 more; the next report is accepted.
        $global:DDGrow = 1000
        Mock -ModuleName DoctorDO.Collector Get-DDDOStatusRaw {
            @([pscustomobject]@{ FileId = ('{0:x40}' -f 1); FileSize = 7MB; TotalBytesDownloaded = 7MB; BytesFromHttp = [long](7MB * 0.5) + $global:DDGrow; BytesFromLanPeers = [long](7MB * 0.4)
                    BytesFromGroupPeers = [long](7MB * 0.1); BytesFromInternetPeers = 0; BytesFromCacheServer = 0; BytesToLanPeers = 1000; DownloadMode = 2; Status = 'Caching'; Priority = 'Background' })
        }
        $global:DDSent.Clear()
        $global:DDSendOutcome = 'NetworkError'
        $global:DDNow = $global:DDNow.AddHours(1)
        (& $script:Run).ExitCode | Should -Be 5
        $global:DDSent[0]['files'][0]['b'][0] | Should -Be 1000
        $global:DDGrow = 1500
        $global:DDSent.Clear()
        $global:DDSendOutcome = 'Accepted'
        $global:DDNow = $global:DDNow.AddHours(1)
        (& $script:Run).ExitCode | Should -Be 0
        $global:DDSent[0]['files'][0]['b'][0] | Should -Be 1500 -Because 'what the refused report carried is sent again with what came after'
        $global:DDSent[0]['period']['from'] | Should -Be '2026-10-12T08:00:00Z' -Because 'the period runs from the last accepted report'
    }

    It 'sends a new inventory when the device changes (a patch raises the UBR)' {
        $null = & $script:Run
        $global:DDSent.Clear()
        Mock -ModuleName DoctorDO.Collector Get-DDRegistryValue {
            $cv = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            if ($Path -eq $cv) { switch ($Name) { 'CurrentMajorVersionNumber' { 10 } 'CurrentMinorVersionNumber' { 0 } 'CurrentBuild' { '26100' } 'UBR' { 5000 } 'EditionID' { 'Enterprise' } 'ProductName' { 'Windows 10 Enterprise' } 'DisplayVersion' { '24H2' } 'InstallDate' { 1773446400 } default { $null } } }
            elseif ($Name -eq 'BIOSVersion') { @('1.8.2') } else { $null }
        }
        $null = & $script:Run
        ($global:DDSent | ForEach-Object { $_['kind'] }) | Should -Be @('inventory', 'telemetry')
        $global:DDSent[0]['os']['ubr'] | Should -Be 5000
    }

    It 'sends a keyframe inventory daily in the first week after the first one was accepted, then every 7 days, and -ForceInventory on demand (E-02)' {
        $start = $global:DDNow
        $kinds = { $k = @($global:DDSent | ForEach-Object { $_['kind'] }); $global:DDSent.Clear(); , $k }
        $null = & $script:Run
        (& $kinds) | Should -Be @('inventory', 'telemetry')
        # A daily schedule's start jitter can bring the next run a little under 24 hours later: still a keyframe.
        $global:DDNow = $start.AddHours(23.8)
        $null = & $script:Run
        (& $kinds) | Should -Be @('inventory', 'telemetry') -Because 'a device the server dropped at enrolment comes back within a day'
        $global:DDNow = $start.AddHours(23.8 + 12)
        $null = & $script:Run
        (& $kinds) | Should -Be @('telemetry')
        # Past the first week the keyframe is every -KeyframeDays (7) again: 6.5 days after the last one is not due, 7 is.
        $global:DDNow = $start.AddDays(7.5)
        $null = & $script:Run
        (& $kinds) | Should -Be @('telemetry')
        $global:DDNow = $start.AddHours(23.8).AddDays(7.05)
        $null = & $script:Run
        (& $kinds) | Should -Be @('inventory', 'telemetry')
        $null = & $script:Run @{ ForceInventory = $true }
        (& $kinds) | Should -Be @('inventory', 'telemetry')
    }

    It 'counts the first week from the first inventory this state saw accepted, not from a later one' {
        InModuleScope DoctorDO.Collector {
            $inv = [ordered]@{ collectedAt = '2026-10-12T08:00:00Z'; connectivity = @() }
            $fresh = New-DDState
            Update-DDStateAfterInventory -State $fresh -Collection ([pscustomobject]@{ Raw = $null }) -Inventory $inv -FullHash ('sha256:' + 'a' * 64) -StableHash ('sha256:' + 'b' * 64) -Now ([datetime]::UtcNow)
            $fresh['firstInventoryAt'] | Should -Be '2026-10-12T08:00:00Z'
            $inv['collectedAt'] = '2026-10-13T08:00:00Z'
            Update-DDStateAfterInventory -State $fresh -Collection ([pscustomobject]@{ Raw = $null }) -Inventory $inv -FullHash ('sha256:' + 'c' * 64) -StableHash ('sha256:' + 'b' * 64) -Now ([datetime]::UtcNow)
            $fresh['firstInventoryAt'] | Should -Be '2026-10-12T08:00:00Z'
            # A device whose state predates the field (an inventory already sent) gets no first week now.
            $old = New-DDState
            $old['lastInventoryHash'] = 'sha256:' + 'a' * 64
            Update-DDStateAfterInventory -State $old -Collection ([pscustomobject]@{ Raw = $null }) -Inventory $inv -FullHash ('sha256:' + 'c' * 64) -StableHash ('sha256:' + 'b' * 64) -Now ([datetime]::UtcNow)
            $old['firstInventoryAt'] | Should -BeNullOrEmpty
            (ConvertTo-DDValidState -Candidate $fresh)['firstInventoryAt'] | Should -Be '2026-10-12T08:00:00Z'
        }
    }

    It 'a lost state file means a full inventory and a full telemetry again, safely' {
        $null = & $script:Run
        Remove-Item (Split-Path $script:D.State) -Recurse -Force
        $global:DDSent.Clear()
        $null = & $script:Run
        ($global:DDSent | ForEach-Object { $_['kind'] }) | Should -Be @('inventory', 'telemetry')
        $global:DDSent[1]['seq'] | Should -Be 1
        $global:DDSent[1]['connectivityChanged'].Count | Should -Be 0 -Because 'the inventory just carried the full matrix'
        $global:DDSent[1]['counters'] | Should -Be 'baseline' -Because 'with the counters lost, the cache is not presented again as new traffic'
        @($global:DDSent[1]['files']).Count | Should -Be 0
    }

    It 'a corrupt state file is replaced, not fatal' {
        $null = & $script:Run
        [System.IO.File]::WriteAllText($script:D.State, 'garbage{')
        $global:DDSent.Clear()
        (& $script:Run).ExitCode | Should -Be 0
        ($global:DDSent | ForEach-Object { $_['kind'] }) | Should -Be @('inventory', 'telemetry')
    }

    It 'does not commit state when the service does not accept: the same deltas are sent next time' {
        $global:DDSendOutcome = 'NetworkError'
        $r = & $script:Run
        $r.ExitCode | Should -Be 5
        ($global:DDSent | ForEach-Object { $_['kind'] }) | Should -Be @('inventory') -Because 'no telemetry after a failed inventory'
        $st = InModuleScope DoctorDO.Collector -Parameters @{ P = $script:D.State } { param($P) (Read-DDState -Path $P).State }
        $st['lastInventoryHash'] | Should -BeNullOrEmpty
        $st['seq'] | Should -Be 0
        Should -Invoke -ModuleName DoctorDO.Collector Set-DDLastSuccess -Times 0
    }

    It 'exit 6 and the Intune prerequisite when there is no certificate' {
        $global:DDSendOutcome = 'NoCertificate'
        $r = & $script:Run
        $r.ExitCode | Should -Be 6
    }

    It '429: honours Retry-After, skips runs until it has passed, then resumes' {
        $global:DDSendOutcome = 'RateLimited'
        $r = & $script:Run
        $r.ExitCode | Should -Be 5
        $global:DDSent.Clear()
        $global:DDSendOutcome = 'Accepted'
        $global:DDNow = $global:DDNow.AddSeconds(300)
        $r = & $script:Run
        $r.Outcome | Should -Be 'BackingOff'; $r.ExitCode | Should -Be 0
        $global:DDSent.Count | Should -Be 0
        $global:DDNow = $global:DDNow.AddSeconds(400)
        (& $script:Run).Outcome | Should -Be 'Success'
        $global:DDSent.Count | Should -BeGreaterThan 0
    }

    It '401/503: exponential back-off grows with consecutive failures, capped at one hour' {
        $global:DDSendOutcome = 'BackOff'
        $waits = @()
        foreach ($i in 1..4) {
            $null = & $script:Run
            $st = InModuleScope DoctorDO.Collector -Parameters @{ P = $script:D.State } { param($P) (Read-DDState -Path $P).State }
            $until = [datetime]::Parse($st['backoffUntil'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
            $waits += ($until - $global:DDNow).TotalSeconds
            $global:DDNow = $until.AddSeconds(1)
        }
        $waits[3] | Should -BeGreaterThan $waits[0]
        ($waits | Measure-Object -Maximum).Maximum | Should -BeLessOrEqual 3630
    }

    It 'a network error backs off as well: the next run inside the window sends nothing (D-12)' {
        $global:DDSendOutcome = 'NetworkError'
        (& $script:Run).ExitCode | Should -Be 5
        $st = InModuleScope DoctorDO.Collector -Parameters @{ P = $script:D.State } { param($P) (Read-DDState -Path $P).State }
        $st['backoffUntil'] | Should -Not -BeNullOrEmpty
        $global:DDSent.Clear()
        $global:DDNow = $global:DDNow.AddSeconds(30)
        $r = & $script:Run
        $r.Outcome | Should -Be 'BackingOff'
        $r.ExitCode | Should -Be 0 -Because 'one failed run does not mark the device as failing'
        $global:DDSent.Count | Should -Be 0
    }

    It 'after three failed runs in a row a run that skips for the back-off exits 5, so Intune shows a device that cannot report (D-12)' {
        $global:DDSendOutcome = 'BackOff'
        (& $script:Run).ExitCode | Should -Be 5
        $seed = { param([int] $Failures) InModuleScope DoctorDO.Collector -Parameters @{ P = $script:D.State; F = $Failures; U = $global:DDNow.AddMinutes(30).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture) } { param($P, $F, $U) $s = (Read-DDState -Path $P).State; $s['consecutiveFailures'] = [int64]$F; $s['backoffUntil'] = $U; Save-DDState -Path $P -State $s } }
        & $seed 2
        $r = & $script:Run
        $r.Outcome | Should -Be 'BackingOff'
        $r.ExitCode | Should -Be 0
        & $seed 3
        $r = & $script:Run
        $r.Outcome | Should -Be 'BackingOff'
        $r.ExitCode | Should -Be 5
        $r.Message | Should -Match 'the last 3 run\(s\) could not report'
        $global:DDSent.Count | Should -Be 1 -Because 'only the first run sent anything'
        # An accepted report after the window clears it.
        $global:DDSendOutcome = 'Accepted'
        $global:DDNow = $global:DDNow.AddMinutes(31)
        (& $script:Run).ExitCode | Should -Be 0
        (InModuleScope DoctorDO.Collector -Parameters @{ P = $script:D.State } { param($P) (Read-DDState -Path $P).State })['consecutiveFailures'] | Should -Be 0
    }

    It 'turns anonymisation off only when asked: -Anonymise:$false keeps the hostname' {
        $null = & $script:Run @{ Anonymise = $false }
        $global:DDSent[0]['anonymised'] | Should -BeFalse
        $global:DDSent[0]['device']['hostname'] | Should -Be 'CONTOSO-LT-0042'
    }

    It 'every report it sends validates against its contract and fits its budget' {
        $null = & $script:Run
        $inv = Get-ContractPath 'inventory-v1.schema.json'; $tel = Get-ContractPath 'telemetry-v1.schema.json'
        Assert-ValidAgainstSchema -Object $global:DDSent[0] -SchemaFile $inv
        Assert-ValidAgainstSchema -Object $global:DDSent[1] -SchemaFile $tel
        InModuleScope DoctorDO.Collector -Parameters @{ I = $global:DDSent[0]; T = $global:DDSent[1] } {
            param($I, $T)
            (ConvertTo-DDReportBytes -Report $I).Gzip.Length | Should -BeLessThan (10 * 1024)
            (ConvertTo-DDReportBytes -Report $T).Gzip.Length | Should -BeLessThan (4 * 1024)
        }
    }

    It 'a skipped-connectivity run still reports, with not-collected results' {
        $r = & $script:Run @{ SkipConnectivityChecks = $true }
        $r.ExitCode | Should -Be 0
        ($global:DDSent[0]['connectivity'] | Where-Object { $_['checkId'] -eq 'do-cloud-tls' })['result'] | Should -Be 'not-collected'
    }
}

Describe 'Required fields' {
    It 'fails with exit 3 rather than sending a report the schema would reject' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDCim { @() }
        Mock -ModuleName DoctorDO.Collector Get-DDLocalDisks { @() }
        Mock -ModuleName DoctorDO.Collector Get-DDSystemMemoryBytes { throw 'no VB' }
        Mock -ModuleName DoctorDO.Collector Get-DDDriveInfo { throw 'no drive' }
        Mock -ModuleName DoctorDO.Collector Send-DoctorDOReport { }
        $d = New-Dirs
        $r = Invoke-DoctorDOCollector -Fleet -IngestUri $script:Uri -StatePath $d.State
        $r.ExitCode | Should -Be 3
        $r.Message | Should -Match 'device.ramGB'
        Should -Invoke -ModuleName DoctorDO.Collector Send-DoctorDOReport -Times 0
        (Invoke-DoctorDOCollector -OutputPath $d.Out -StatePath $d.State).ExitCode | Should -Be 3
    }
}

Describe 'Reproduction wait (unmocked)' {
    It 'the reproduction wait really is bounded: with no key pressed it returns timeout after the allotted time' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = InModuleScope DoctorDO.Collector { Wait-DDReproduction -TimeoutMinutes 0.02 -InformationAction SilentlyContinue }
        $sw.Stop()
        $r | Should -Be 'timeout'
        $sw.Elapsed.TotalSeconds | Should -BeGreaterThan 1
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
    }

}
