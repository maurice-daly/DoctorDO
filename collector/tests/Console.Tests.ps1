#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# What a person at the console sees (1.1.0): the summary by area and the checks that need attention (Console.ps1), the
# narration of the hand-run commands and when it stays silent (Progress.ps1), and the short views of their results
# (DoctorDO.Collector.format.ps1xml).
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:Version = (Get-Module DoctorDO.Collector).Version.ToString()
    $script:Esc = [string][char]27
    function New-DDTestRow {
        param([string] $Id, [string] $Result, [string] $Detail = 'detail', [string] $Target = '', $Port = $null)
        [ordered]@{ checkId = $Id; target = $Target; protocol = 'tcp'; port = $Port; result = $Result; latencyMs = $null; detail = $Detail }
    }
    # The narration of a run: the messages of the Information records tagged DoctorDO.
    function Get-DDNarrationLines {
        param([scriptblock] $Run)
        @(& $Run 6>&1 | Where-Object { $_ -is [System.Management.Automation.InformationRecord] -and $_.Tags -contains 'DoctorDO' } | ForEach-Object { [string]$_.MessageData })
    }
}

Describe 'The summary by area' {
    It 'puts each check the catalogue names in the catalogue''s area, and knows no other' {
        $catalogue = Join-Path $PSScriptRoot '../../packages/analysis/src/connectivity/catalogue.ts'
        if (-not (Test-Path -LiteralPath $catalogue)) { Set-ItResult -Skipped -Because 'the analysis package is not in this copy'; return }
        $pairs = [regex]::Matches((Get-Content -LiteralPath $catalogue -Raw), "\{ id: '([a-z0-9-]+)', category: '([a-z0-9]+)'")
        $pairs.Count | Should -BeGreaterThan 30
        foreach ($p in $pairs) {
            InModuleScope DoctorDO.Collector -Parameters @{ Id = $p.Groups[1].Value } { param($Id) Get-DDCheckArea -CheckId $Id } | Should -Be $p.Groups[2].Value -Because $p.Groups[1].Value
        }
        $known = InModuleScope DoctorDO.Collector { @($script:DDCheckArea.Keys) }
        @($known).Count | Should -Be $pairs.Count
    }

    It 'has an area for every check a device produces' {
        Initialize-FakeDevice -ProbeFailures -Dhcp235 -Pac device
        $rows = @(Get-DOConnectivityMatrix)
        $rows.Count | Should -BeGreaterThan 30
        foreach ($r in $rows) {
            InModuleScope DoctorDO.Collector -Parameters @{ Id = $r['checkId'] } { param($Id) Get-DDCheckArea -CheckId $Id } | Should -Not -Be 'other' -Because $r['checkId']
        }
    }

    It 'counts each area by result, a dash for none, with a total, every line the same width' {
        $rows = @(
            (New-DDTestRow 'do-cloud-dns' 'pass'), (New-DDTestRow 'do-geo' 'fail'),
            (New-DDTestRow 'p2p-inbound' 'warn'), (New-DDTestRow 'p2p-listener' 'not-applicable'),
            (New-DDTestRow 'ep:wu-emdl' 'warn'), (New-DDTestRow 'ep:mcc' 'not-collected'), (New-DDTestRow 'brand-new-check' 'pass'))
        $lines = @(InModuleScope DoctorDO.Collector -Parameters @{ Rows = $rows } { param($Rows) Format-DDAreaTable -Rows $Rows })
        $lines[0] | Should -Match '^  Area +Pass +Warn +Fail +N/A +Not collected$'
        $lines | Should -Contain ($lines | Where-Object { $_ -match '^  Cloud service ' })
        ($lines | Where-Object { $_ -match '^  Cloud service ' }) | Should -Match 'Cloud service +1 +- +1 +- +-$'
        ($lines | Where-Object { $_ -match '^  Peer-to-peer ' }) | Should -Match 'Peer-to-peer +- +1 +- +1 +-$'
        ($lines | Where-Object { $_ -match '^  Microsoft endpoints ' }) | Should -Match 'Microsoft endpoints +- +1 +- +- +1$'
        ($lines | Where-Object { $_ -match '^  Other checks ' }) | Should -Match 'Other checks +1 '
        $lines[-1] | Should -Match '^  Total \(7 checks\) +2 +2 +1 +1 +1$'
        @($lines | Where-Object { $_ -match 'Content|Connected Cache|Proxy|Local' }).Count | Should -Be 0 -Because 'an area with no checks has no line'
        @($lines | ForEach-Object { $_.Length } | Sort-Object -Unique).Count | Should -Be 1
        ($lines -join '') | Should -Not -Match $script:Esc
    }

    It 'colours only the fail and warn counts, and only when asked' {
        $rows = @((New-DDTestRow 'do-geo' 'fail'), (New-DDTestRow 'p2p-inbound' 'warn'), (New-DDTestRow 'do-cloud-dns' 'pass'))
        $lines = @(InModuleScope DoctorDO.Collector -Parameters @{ Rows = $rows } { param($Rows) Format-DDAreaTable -Rows $Rows -Colour })
        ($lines | Where-Object { $_ -match 'Cloud service' }) | Should -Match ([regex]::Escape("$($script:Esc)[31m"))
        ($lines | Where-Object { $_ -match 'Peer-to-peer' }) | Should -Match ([regex]::Escape("$($script:Esc)[33m"))
        $lines[0] | Should -Not -Match $script:Esc
    }

    It 'says when no check ran' {
        InModuleScope DoctorDO.Collector { Format-DDAreaTable -Rows @() } | Should -Be '  No connectivity checks ran.'
    }
}

Describe 'The checks that need attention' {
    It 'lists failures before warnings, with where each looked, the detail wrapped to the width, and stops at the limit' {
        $long = ('word ' * 40).Trim()
        $rows = @(
            (New-DDTestRow 'p2p-inbound' 'warn' $long 'localhost' 7680), (New-DDTestRow 'do-geo' 'fail' $long 'geo.prod.do.dsp.mp.microsoft.com' 443),
            (New-DDTestRow 'do-cloud-dns' 'pass'), (New-DDTestRow 'local-policy-merge' 'warn' 'merge off'),
            (New-DDTestRow 'p2p-firewall-rule' 'fail' 'rule inactive' '' 7680), (New-DDTestRow 'mcc-serving' 'fail' 'not serving'))
        $lines = @(InModuleScope DoctorDO.Collector -Parameters @{ Rows = $rows } { param($Rows) Format-DDAttention -Rows $Rows -Width 60 -Limit 4 -More 'see the report' })
        $lines[0] | Should -Be '  Needs attention (3 fail, 2 warn)'
        $entries = @($lines | Where-Object { $_ -match '^    (FAIL|WARN)  ' })
        $entries.Count | Should -Be 4
        $entries[0] | Should -Match '^    FAIL  do-geo +geo\.prod\.do\.dsp\.mp\.microsoft\.com:443$'
        $entries[1] | Should -Match '^    FAIL  p2p-firewall-rule +port 7680$'
        $entries[2] | Should -Match '^    FAIL  mcc-serving$'
        $entries[3] | Should -Match '^    WARN  p2p-inbound +localhost:7680$'
        foreach ($l in ($lines | Where-Object { $_ -match '^ {10}\S' })) { $l.Length | Should -BeLessOrEqual 60 }
        @($lines | Where-Object { $_ -match '^ {10}word' }).Count | Should -BeGreaterThan 2 -Because 'the long detail is wrapped'
        $lines[-1] | Should -Be '    ... and 1 more: see the report'
    }

    It 'says so in one line when nothing failed or warned' {
        $rows = @((New-DDTestRow 'do-cloud-dns' 'pass'), (New-DDTestRow 'mcc-config' 'not-applicable'))
        InModuleScope DoctorDO.Collector -Parameters @{ Rows = $rows } { param($Rows) Format-DDAttention -Rows $Rows } | Should -Be '  Nothing needs attention: no check failed or warned.'
    }

    It 'with one check to show, shows that one (a single dictionary is not unrolled into its keys)' {
        $rows = @((New-DDTestRow 'do-geo' 'fail' 'down'))
        $lines = @(InModuleScope DoctorDO.Collector -Parameters @{ Rows = $rows } { param($Rows) Format-DDAttention -Rows $Rows -Limit 8 -More 'x' })
        $lines[0] | Should -Be '  Needs attention (1 fail)'
        @($lines | Where-Object { $_ -match '^    FAIL  do-geo' }).Count | Should -Be 1
        ($lines -join "`n") | Should -Not -Match 'more'
    }

    It 'the full list has every check once, under its area, failures first within it' {
        $rows = @((New-DDTestRow 'p2p-listener' 'pass'), (New-DDTestRow 'p2p-inbound' 'fail'), (New-DDTestRow 'p2p-outbound' 'not-applicable'), (New-DDTestRow 'do-cloud-dns' 'pass'))
        $lines = @(InModuleScope DoctorDO.Collector -Parameters @{ Rows = $rows } { param($Rows) Format-DDCheckList -Rows $Rows -Width 100 })
        $heads = @($lines | Where-Object { $_ -match '^  \S' -and $_ -notmatch '^  n/a:' })
        $heads[0] | Should -Be '  Cloud service (1 pass)'
        $heads[1] | Should -Be '  Peer-to-peer (1 fail, 1 pass, 1 not-applicable)'
        $p2p = @($lines | Where-Object { $_ -match '^    \S+ +p2p-' })
        $p2p[0] | Should -Match '^    FAIL  p2p-inbound'
        $p2p[1] | Should -Match '^    pass  p2p-listener'
        $p2p[2] | Should -Match '^    n/a   p2p-outbound'
    }
}

Describe 'Narration of the commands people run by hand' {
    BeforeEach {
        Initialize-FakeDevice -ProbeFailures
        $script:Out = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleColour { $false }
    }

    It 'New-DoctorDODeviceReport tells a person at the console each section as it ends, then the summary, naming no host' {
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleNarration { $true }
        $lines = Get-DDNarrationLines { New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen }
        $lines[0] | Should -Be "DoctorDO.Collector $($script:Version): device report"
        $lines[1] | Should -Match '^PowerShell \S+ \((Core|Desktop)\), (elevated|not elevated|running as SYSTEM), started \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC$'
        $sections = @($lines | Where-Object { $_ -match '^  \[\d/8\] ' })
        $names = @($sections | ForEach-Object { ([regex]::Match($_, '^  \[\d/8\] (.+?) \.{2,} ')).Groups[1].Value })
        $names | Should -Be @('Device and Windows', 'Delivery Optimization settings', 'Network', 'Device, hardware and firewall', 'Jobs, peers and log', 'Connectivity', 'Provisioning', 'Report')
        @($sections | ForEach-Object { ([regex]::Match($_, '^  \[(\d)/8\]')).Groups[1].Value }) | Should -Be @('1', '2', '3', '4', '5', '6', '7', '8')
        @($sections | ForEach-Object { $_.IndexOf('. ') + 2 } | Sort-Object -Unique).Count | Should -Be 1 -Because 'every result starts in the same column'
        $sections[5] | Should -Match '\d+ checks: .*\d+ fail'
        $sections[7] | Should -Match 'HTML \d'
        @($lines | Where-Object { $_ -match '^  Total \(\d+ checks\)' }).Count | Should -Be 1
        @($lines | Where-Object { $_ -match '^  Needs attention \(\d+ fail' }).Count | Should -Be 1
        ($lines -join "`n") | Should -Not -Match 'CONTOSO-LT-0042'
        ($lines -join "`n") | Should -Not -Match $script:Esc
    }

    It 'shows the section under way in a progress bar, and clears it at the end' {
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleNarration { $true }
        Mock -ModuleName DoctorDO.Collector Write-Progress { }
        $null = New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen 6>$null
        Should -Invoke -ModuleName DoctorDO.Collector Write-Progress -Times 1 -Exactly -ParameterFilter { $Status -eq '[1/8] Device and Windows' -and $PercentComplete -eq 0 }
        Should -Invoke -ModuleName DoctorDO.Collector Write-Progress -Times 1 -Exactly -ParameterFilter { $Status -eq '[8/8] Report' }
        Should -Invoke -ModuleName DoctorDO.Collector Write-Progress -Times 1 -Exactly -ParameterFilter { $Completed }
    }

    It 'says nothing where nobody is watching (the default on the fake device), and -Verbose keeps its own header' {
        Mock -ModuleName DoctorDO.Collector Write-Progress { }
        @(Get-DDNarrationLines { New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen }).Count | Should -Be 0
        $verbose = @(New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen -Verbose 4>&1 6>$null | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object { $_.Message })
        $verbose[0] | Should -Be "DoctorDO.Collector $($script:Version) - New-DoctorDODeviceReport"
        Should -Invoke -ModuleName DoctorDO.Collector Write-Progress -Times 0 -Exactly
    }

    It 'with -Verbose for a person at the console, the narration has the header and -Verbose only the steps' {
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleNarration { $true }
        $all = @(New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen -Verbose 4>&1 6>&1)
        $verbose = @($all | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object { $_.Message })
        @($verbose | Where-Object { $_ -match '^DoctorDO\.Collector ' -or $_ -match '^-{10,}$' }).Count | Should -Be 0
        @($verbose | Where-Object { $_ -match '^\[ *\d+\.\ds\] Device identity \(dsregcmd\) ' }).Count | Should -Be 1
        @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] -and [string]$_.MessageData -like 'DoctorDO.Collector *: device report' }).Count | Should -Be 1
    }

    It '-InformationAction SilentlyContinue silences the narration and the written lines, even for a person at the console' {
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleNarration { $true }
        $records = @(New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen -InformationAction SilentlyContinue 6>&1 | Where-Object { $_ -is [System.Management.Automation.InformationRecord] })
        $records.Count | Should -Be 0
    }

    It 'colours the narration only where the console renders colour' {
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleNarration { $true }
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleColour { $true }
        $lines = Get-DDNarrationLines { New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen }
        ($lines | Where-Object { $_ -match '\[6/8\]' }) | Should -Match ([regex]::Escape("$($script:Esc)[31m") + '\d+ fail')
    }

    It 'Test-DOConnectivity narrates the seven sections and returns plain text: the areas, what needs attention, and every check with -Detailed' {
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleNarration { $true }
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleColour { $true }
        $all = @(Test-DOConnectivity 6>&1)
        # Colour is on here: the counters are wrapped in escape sequences, taken off before matching.
        $narration = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData -replace "$($script:Esc)\[[0-9;]*m", '' })
        @($narration | Where-Object { $_ -match '\[\d/7\] ' }).Count | Should -Be 7
        $text = @($all | Where-Object { $_ -is [string] }) -join "`n"
        $text | Should -Match '(?m)^  Total \(\d+ checks\)'
        $text | Should -Match '(?m)^  Needs attention \(\d+ fail'
        $text | Should -Match 'Test-DOConnectivity -Detailed'
        $text | Should -Not -Match $script:Esc -Because 'the output is text a person saves or pipes on'
        $detailed = @(Test-DOConnectivity -Detailed -InformationAction SilentlyContinue) -join "`n"
        foreach ($id in @(Get-DOConnectivityMatrix | ForEach-Object { $_['checkId'] } | Select-Object -Unique)) {
            $detailed | Should -Match ('(?m)^    \S+ +' + [regex]::Escape($id) + '(\s|$)')
        }
    }

    It 'Invoke-DoctorDOCollector narrates the bundle as the last of eight sections' {
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleNarration { $true }
        $state = Join-Path $TestDrive ('state-' + [guid]::NewGuid().ToString('N') + '/state.json')
        $lines = Get-DDNarrationLines { Invoke-DoctorDOCollector -OutputPath $script:Out -StatePath $state }
        $lines[0] | Should -Be "DoctorDO.Collector $($script:Version): support bundle"
        @($lines | Where-Object { $_ -match '^  \[8/8\] Bundle \.+ zip \d' }).Count | Should -Be 1
        @($lines | Where-Object { $_ -match '^  Total \(\d+ checks\)' }).Count | Should -Be 1
    }

    It 'Invoke-DoctorDOCollector -WhatIfRedaction is not narrated' {
        Mock -ModuleName DoctorDO.Collector Test-DDConsoleNarration { $true }
        @(Get-DDNarrationLines { Invoke-DoctorDOCollector -WhatIfRedaction }).Count | Should -Be 0
    }

    It 'Get-DDRawCollection starts and completes as many sections as the commands count on' {
        $counts = InModuleScope DoctorDO.Collector {
            $fn = (Get-Command Get-DDRawCollection).ScriptBlock.Ast
            $names = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
            @{ Start = @($names | Where-Object { $_ -eq 'Start-DDSection' }).Count; Complete = @($names | Where-Object { $_ -eq 'Complete-DDSection' }).Count; Declared = $script:DDCollectionSections }
        }
        $counts.Start | Should -Be $counts.Declared
        $counts.Complete | Should -Be $counts.Declared
    }
}

Describe 'Whether anyone is watching' {
    It 'nobody is when Get-DDNonInteractiveReason gives a reason' {
        InModuleScope DoctorDO.Collector {
            Mock Get-DDNonInteractiveReason { 'running as SYSTEM' }
            Test-DDConsoleNarration | Should -BeFalse
        }
    }

    It 'the caller''s -InformationAction SilentlyContinue or Ignore asks for quiet; Continue does not' {
        InModuleScope DoctorDO.Collector {
            Test-DDInformationQuiet -BoundParameters @{ InformationAction = [System.Management.Automation.ActionPreference]::SilentlyContinue } | Should -BeTrue
            Test-DDInformationQuiet -BoundParameters @{ InformationAction = [System.Management.Automation.ActionPreference]::Ignore } | Should -BeTrue
            Test-DDInformationQuiet -BoundParameters @{ InformationAction = [System.Management.Automation.ActionPreference]::Continue } | Should -BeFalse
            Test-DDInformationQuiet -BoundParameters @{} | Should -BeFalse
        }
    }

    It 'no colour when NO_COLOR is set' {
        $saved = $env:NO_COLOR
        try {
            $env:NO_COLOR = '1'
            InModuleScope DoctorDO.Collector { Test-DDConsoleColour } | Should -BeFalse
        } finally { $env:NO_COLOR = $saved }
    }
}

Describe 'The short views of the results' {
    BeforeEach {
        Initialize-FakeDevice
        $script:Out = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    }

    It 'a device report shows its path, size, what was not collected and how long it took; Format-List * still shows all' {
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen -InformationAction SilentlyContinue
        $r.PSObject.TypeNames[0] | Should -Be 'DoctorDO.DeviceReport'
        $shown = $r | Out-String -Width 400
        foreach ($label in 'Path', 'Size', 'NotCollected', 'Duration') { $shown | Should -Match "(?m)^$label +: " }
        $shown | Should -Not -Match 'Sha256|DeviceId|JsonPath|PdfPath'
        ($r | Format-List * | Out-String -Width 400) | Should -Match 'Sha256'
    }

    It 'a collector result shows its outcome with the exit code and its message' {
        Mock -ModuleName DoctorDO.Collector Test-DDElevated { $false }
        Mock -ModuleName DoctorDO.Collector Test-DDSystemContext { $false }
        $r = Invoke-DoctorDOCollector -OutputPath $script:Out -InformationAction SilentlyContinue
        $r.PSObject.TypeNames[0] | Should -Be 'DoctorDO.CollectorResult'
        $shown = $r | Out-String -Width 400
        $shown | Should -Match '(?m)^Outcome +: NotElevated \(exit 1\)\r?$'
        $shown | Should -Match '(?m)^Message +: Run from an elevated session'
        $shown | Should -Not -Match 'SchemaVersion|BundlePath|Reports'
    }
}
