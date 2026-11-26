#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:Contracts = (Resolve-Path (Join-Path $PSScriptRoot '../../contracts')).Path
    # The data the report embeds, read back as the browser would (< is '<' again once parsed).
    # A JSON file the command wrote, parsed the module's way (dates stay strings; objects are ordered dictionaries).
    function Read-DDJsonTestFile {
        param([Parameter(Mandatory)][string] $Path)
        $text = [System.IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false)))
        InModuleScope DoctorDO.Collector -Parameters @{ Text = $text } { param($Text) ConvertFrom-DDJson -Text $Text }
    }
    function Get-ReportData {
        param([Parameter(Mandatory)][string] $Path)
        $html = [System.IO.File]::ReadAllText($Path)
        $m = [regex]::Match($html, '(?s)<script type="application/json" id="doctordo-data">(.*?)</script>')
        $m.Success | Should -BeTrue
        InModuleScope DoctorDO.Collector -Parameters @{ Text = $m.Groups[1].Value } { param($Text) ConvertFrom-DDJson -Text $Text }
    }
}

Describe 'New-DoctorDODeviceReport (the offline device report, ADR-0039)' {
    BeforeEach {
        Initialize-FakeDevice
        $script:Out = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    }

    It 'writes one HTML file with the device embedded, its inventory and telemetry valid against the contracts' {
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -InformationAction SilentlyContinue
        Split-Path $r.Path -Leaf | Should -Be 'DoctorDO-CONTOSO-LT-0042-20261012-080000.html'
        $r.HostName | Should -Be 'CONTOSO-LT-0042'
        $r.Anonymised | Should -BeFalse
        $r.Bytes | Should -Be (Get-Item -LiteralPath $r.Path).Length
        @(Get-ChildItem -LiteralPath $script:Out).Count | Should -Be 1 -Because 'only the report is written; no .tmp is left'
        $d = Get-ReportData -Path $r.Path
        $d['kind'] | Should -Be 'doctordo-device-report'
        $d['version'] | Should -Be 1
        $d['inventory']['device']['hostname'] | Should -Be 'CONTOSO-LT-0042'
        @($d['telemetry']).Count | Should -Be 1
        $d['telemetry'][0]['period']['from'] | Should -Be $d['telemetry'][0]['period']['to'] -Because 'one collection is one point in time'
        $hash = InModuleScope DoctorDO.Collector -Parameters @{ Inv = $d['inventory'] } { param($Inv) Get-DDInventoryHash -Inventory $Inv }
        $d['telemetry'][0]['inventoryHash'] | Should -Be $hash
        Assert-ValidAgainstSchema -Object $d['inventory'] -SchemaFile (Join-Path $script:Contracts 'inventory-v1.schema.json')
        Assert-ValidAgainstSchema -Object $d['telemetry'][0] -SchemaFile (Join-Path $script:Contracts 'telemetry-v1.schema.json')
    }

    It 'keeps the page script byte for byte, so its CSP hash still holds' {
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -InformationAction SilentlyContinue
        $template = [System.IO.File]::ReadAllText((InModuleScope DoctorDO.Collector { Get-DDReportTemplatePath }))
        $page = [regex]::Match($template, '(?s)<script>(.*)</script>\s*</body>').Groups[1].Value
        $page.Length | Should -BeGreaterThan 100000
        [System.IO.File]::ReadAllText($r.Path).Contains("<script>$page</script>") | Should -BeTrue
        [System.IO.File]::ReadAllText($r.Path) | Should -Match "connect-src 'none'"
    }

    # (No angle brackets in the name: Pester expands <name> in test names.)
    It 'cannot be broken out of: a value carrying a closing script tag stays data, and a replacement token stays literal' {
        Initialize-FakeDevice -Hostname 'PC</script><script>alert(1)</script><!--$&$1'
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -InformationAction SilentlyContinue
        $html = [System.IO.File]::ReadAllText($r.Path)
        $html | Should -Not -Match '</script><script>alert'
        $html | Should -Not -Match '<!--\$'
        $block = [regex]::Match($html, '(?s)id="doctordo-data">(.*?)</script>').Groups[1].Value
        $block | Should -Not -Match '<'
        (Get-ReportData -Path $r.Path)['inventory']['device']['hostname'] | Should -Be 'PC</script><script>alert(1)</script><!--$&$1'
        Split-Path $r.Path -Leaf | Should -Match '^DoctorDO-PC-[A-Za-z0-9-]+-\d{8}-\d{6}\.html$'
    }

    It 'anonymised: no host name, tenant, Entra or Intune ID, site code or AD site anywhere, and says why they are absent' {
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Anonymise -InformationAction SilentlyContinue
        Split-Path $r.Path -Leaf | Should -Be 'DoctorDO-report-20261012-080000.html'
        $r.HostName | Should -BeNullOrEmpty
        $html = [System.IO.File]::ReadAllText($r.Path)
        foreach ($s in 'CONTOSO-LT-0042', '9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10', '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20', 'c0a8e1d2-77b4-4f09-b3a1-5e2d9c4f6a88', 'MAN-01') {
            $html.IndexOf($s, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1 -Because "$s identifies the device or its organisation"
        }
        $inv = (Get-ReportData -Path $r.Path)['inventory']
        $inv['anonymised'] | Should -BeTrue
        $inv['management']['tenantId'] | Should -BeNullOrEmpty
        $inv['network']['adSite'] | Should -BeNullOrEmpty
        $skipped = @($inv['notCollected'] | Where-Object { $_['reason'] -eq 'skipped-by-flag' } | ForEach-Object { $_['field'] })
        foreach ($f in 'management.entraDeviceId', 'management.tenantId', 'management.mdm.intuneDeviceId', 'network.adSite') { $skipped | Should -Contain $f }
        Assert-ValidAgainstSchema -Object $inv -SchemaFile (Join-Path $script:Contracts 'inventory-v1.schema.json')
    }

    It 'carries no PAC URL, proxy name or SID (ADR-0038)' {
        Initialize-FakeDevice -Pac users
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -InformationAction SilentlyContinue
        [System.IO.File]::ReadAllText($r.Path) | Should -Not -Match 'pac\.contoso\.example|proxy\.contoso\.example|FindProxyForURL|S-1-5-21'
        (Get-ReportData -Path $r.Path)['inventory']['network']['proxy']['pac']['versions'] | Should -Be 2
    }

    It 'is read-only: no state file, no upload, no verbose logging, DoSvc never stopped' {
        Mock -ModuleName DoctorDO.Collector Read-DDState { throw 'state read' }
        Mock -ModuleName DoctorDO.Collector Save-DDState { throw 'state written' }
        Mock -ModuleName DoctorDO.Collector Invoke-DDHttpPost { throw 'uploaded' }
        Mock -ModuleName DoctorDO.Collector Invoke-DDVerboseCycle { throw 'verbose cycle' }
        New-DoctorDODeviceReport -OutputPath $script:Out -InformationAction SilentlyContinue | Out-Null
        Should -Invoke -ModuleName DoctorDO.Collector Read-DDState -Times 0 -Exactly
        Should -Invoke -ModuleName DoctorDO.Collector Save-DDState -Times 0 -Exactly
        Should -Invoke -ModuleName DoctorDO.Collector Get-DDDOLogEntries -ParameterFilter { $Flush } -Times 0 -Exactly
        Should -Invoke -ModuleName DoctorDO.Collector Get-DDDOLogEntries -Times 1
    }

    It 'warns, and still writes the report, when not elevated; opens it on -Open' {
        Mock -ModuleName DoctorDO.Collector Test-DDElevated { $false }
        Mock -ModuleName DoctorDO.Collector Invoke-Item { }
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Open -InformationAction SilentlyContinue -WarningVariable w -WarningAction SilentlyContinue
        "$w" | Should -Match 'Not running elevated'
        Test-Path -LiteralPath $r.Path | Should -BeTrue
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $r.Path }
    }

    It 'with -Verbose, prints a header, one aligned line per step and a summary, naming no host' {
        $lines = @(New-DoctorDODeviceReport -OutputPath $script:Out -Verbose -InformationAction SilentlyContinue 4>&1 |
                Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object { $_.Message })
        $lines[0] | Should -Be 'DoctorDO.Collector 1.2.1 - New-DoctorDODeviceReport'
        $lines[1] | Should -Match '^PowerShell \S+ \((Core|Desktop)\), (elevated|not elevated|running as SYSTEM), started \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC$'
        $steps = @($lines | Where-Object { $_ -match '^\[' })
        foreach ($s in $steps) { $s | Should -Match '^\[ *\d+\.\ds\] .+ \.{2,} .+$' }
        $col = @(@($steps | Where-Object { $_ -notmatch '^\[ *\d+\.\ds\]   not collected' } | ForEach-Object { $_.IndexOf(' ...') + ($_.Substring($_.IndexOf(' ...') + 1) -replace '^(\.+).*', '$1').Length }) | Sort-Object -Unique)
        $col.Count | Should -Be 1 -Because 'every result starts in the same column'
        foreach ($want in 'Report page', 'Device identity \(dsregcmd\)', 'Delivery Optimization configuration', 'Proxy auto-config \(PAC\)', 'Endpoint health', 'Connectivity checks', 'Report data', 'Done') {
            @($steps | Where-Object { $_ -match "^\[ *\d+\.\ds\] $want " }).Count | Should -Be 1 -Because "one line for $want"
        }
        ($steps | Where-Object { $_ -match '\] Connectivity checks ' }) | Should -Match '\d+ checks: \d+ pass'
        ($lines -join "`n") | Should -Not -Match 'CONTOSO-LT-0042|alice'
    }

    It 'without -Verbose, prints nothing beyond the result' {
        $out = @(New-DoctorDODeviceReport -OutputPath $script:Out -InformationAction SilentlyContinue *>&1 | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })
        $out.Count | Should -Be 1
        $out[0].Path | Should -Match 'DoctorDO-CONTOSO-LT-0042-'
    }

    It '-Format Json writes only the data: pretty-printed UTF-8 without a byte order mark, a schema and the collector version first' {
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Format Json -InformationAction SilentlyContinue
        $r.Format | Should -Be 'Json'
        $r.Path | Should -Be $r.JsonPath
        Split-Path $r.Path -Leaf | Should -Be 'DoctorDO-CONTOSO-LT-0042-20261012-080000.json'
        @(Get-ChildItem -LiteralPath $script:Out).Count | Should -Be 1 -Because 'no page and no .tmp'
        $bytes = [System.IO.File]::ReadAllBytes($r.Path)
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse -Because 'no BOM'
        $r.Bytes | Should -Be $bytes.Length
        $r.JsonBytes | Should -Be $bytes.Length
        $r.JsonSha256 | Should -Be $r.Sha256
        $text = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes)
        $text | Should -Match '^\{\r?\n  "schema": "doctordo-device-report/1",\r?\n  "collectorVersion": "\d+\.\d+\.\d+",\r?\n  "'
        $text.TrimEnd().Split("`n").Count | Should -BeGreaterThan 200 -Because 'one member per line'
        $text | Should -Match '\n    "device": \{\r?\n      "'
        $text | Should -Not -Match '\\u003c' -Because 'a file, not an HTML data block: < is written as itself'
        $j = Read-DDJsonTestFile -Path $r.Path
        $j['schema'] | Should -Be 'doctordo-device-report/1'
        $j['collectorVersion'] | Should -Be (Get-Module DoctorDO.Collector).Version.ToString()
    }

    It '-Format Json needs no page, so a missing page is not an error for it' {
        Mock -ModuleName DoctorDO.Collector Get-DDReportTemplatePath { Join-Path $TestDrive 'absent.html' }
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Format Json -InformationAction SilentlyContinue
        Test-Path -LiteralPath $r.JsonPath | Should -BeTrue
        { New-DoctorDODeviceReport -OutputPath $script:Out -Format Both } | Should -Throw '*is missing from the module*'
    }

    It '-Format Both writes the page and the JSON from one collection, and the JSON is exactly the data the page embeds' {
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Format Both -InformationAction SilentlyContinue
        Split-Path $r.Path -Leaf | Should -Be 'DoctorDO-CONTOSO-LT-0042-20261012-080000.html'
        Split-Path $r.JsonPath -Leaf | Should -Be 'DoctorDO-CONTOSO-LT-0042-20261012-080000.json'
        @(Get-ChildItem -LiteralPath $script:Out).Count | Should -Be 2
        $r.Sha256 | Should -Not -Be $r.JsonSha256
        $fromHtml = Get-ReportData -Path $r.Path
        $fromJson = Read-DDJsonTestFile -Path $r.JsonPath
        $fromJson.Remove('schema'); $fromJson.Remove('collectorVersion')
        $canon = InModuleScope DoctorDO.Collector -Parameters @{ A = $fromHtml; B = $fromJson } { param($A, $B) @((ConvertTo-DDCanonicalJson -InputObject $A), (ConvertTo-DDCanonicalJson -InputObject $B)) }
        $canon[1] | Should -BeExactly $canon[0]
        $canon[0].Length | Should -BeGreaterThan 5000
        @($fromJson.Keys | Sort-Object) | Should -Be @('generatedAt', 'inventory', 'kind', 'telemetry', 'version')
        Assert-ValidAgainstSchema -Object $fromJson['inventory'] -SchemaFile (Join-Path $script:Contracts 'inventory-v1.schema.json')
        Assert-ValidAgainstSchema -Object $fromJson['telemetry'][0] -SchemaFile (Join-Path $script:Contracts 'telemetry-v1.schema.json')
    }

    It 'the default is still the page alone, and the result says so' {
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -InformationAction SilentlyContinue
        $r.Format | Should -Be 'Html'
        $r.JsonPath | Should -BeNullOrEmpty
        $r.JsonSha256 | Should -BeNullOrEmpty
        @(Get-ChildItem -LiteralPath $script:Out -Filter *.json).Count | Should -Be 0
    }

    It '-Anonymise applies to the JSON exactly as to the page: no identifiers anywhere, the same data, no host name in the name' {
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Format Both -Anonymise -InformationAction SilentlyContinue
        Split-Path $r.JsonPath -Leaf | Should -Be 'DoctorDO-report-20261012-080000.json'
        $text = [System.IO.File]::ReadAllText($r.JsonPath)
        foreach ($s in 'CONTOSO-LT-0042', '9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10', '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20', 'c0a8e1d2-77b4-4f09-b3a1-5e2d9c4f6a88', 'MAN-01') {
            $text.IndexOf($s, [System.StringComparison]::OrdinalIgnoreCase) | Should -Be -1 -Because "$s identifies the device or its organisation"
        }
        $j = Read-DDJsonTestFile -Path $r.JsonPath
        $j['inventory']['anonymised'] | Should -BeTrue
        $j['inventory']['management']['tenantId'] | Should -BeNullOrEmpty
        $skipped = @($j['inventory']['notCollected'] | Where-Object { $_['reason'] -eq 'skipped-by-flag' } | ForEach-Object { $_['field'] })
        foreach ($f in 'management.entraDeviceId', 'management.tenantId', 'management.mdm.intuneDeviceId', 'network.adSite') { $skipped | Should -Contain $f }
        $html = Get-ReportData -Path $r.Path
        @($j['inventory']['notCollected']).Count | Should -Be @($html['inventory']['notCollected']).Count
        $j['inventory']['device']['deviceId'] | Should -Be $html['inventory']['device']['deviceId']
        $j['telemetry'][0]['inventoryHash'] | Should -Be $html['telemetry'][0]['inventoryHash']
    }

    It 'keeps a closing script tag in a value as plain data in the JSON, and survives braces, quotes and backslashes in values' {
        Initialize-FakeDevice -Hostname 'PC</script>{"a":[1,2]}\"x'
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Format Json -InformationAction SilentlyContinue
        (Read-DDJsonTestFile -Path $r.JsonPath)['inventory']['device']['hostname'] | Should -Be 'PC</script>{"a":[1,2]}\"x'
        Split-Path $r.Path -Leaf | Should -Match '^DoctorDO-PC-[A-Za-z0-9-]+-\d{8}-\d{6}\.json$'
    }

    It 'creates the folder, replaces a report of the same name, and leaves no .tmp, for the JSON as for the page' {
        $nested = Join-Path $script:Out 'a/b'
        $r1 = New-DoctorDODeviceReport -OutputPath $nested -Format Both -InformationAction SilentlyContinue
        Test-Path -LiteralPath $r1.JsonPath | Should -BeTrue
        [System.IO.File]::WriteAllText($r1.JsonPath, 'stale'); [System.IO.File]::WriteAllText($r1.Path, 'stale')
        $r2 = New-DoctorDODeviceReport -OutputPath $nested -Format Both -InformationAction SilentlyContinue
        $r2.JsonPath | Should -Be $r1.JsonPath
        [System.IO.File]::ReadAllText($r2.JsonPath) | Should -Match '^\{'
        [System.IO.File]::ReadAllText($r2.Path) | Should -Match '^<!doctype html'
        @(Get-ChildItem -LiteralPath $nested).Count | Should -Be 2
        { New-DoctorDODeviceReport -OutputPath $nested -Format Xml } | Should -Throw '*Format*'
    }

    It '-FileName gives every format the same fixed name, which the next run replaces (19 Oct 2026)' {
        $r1 = New-DoctorDODeviceReport -OutputPath $script:Out -FileName 'DoctorDO-DeviceReport' -Format Both -Anonymise -InformationAction SilentlyContinue
        Split-Path $r1.Path -Leaf | Should -Be 'DoctorDO-DeviceReport.html'
        Split-Path $r1.JsonPath -Leaf | Should -Be 'DoctorDO-DeviceReport.json' -Because 'the name is used as given, also with -Anonymise'
        [System.IO.File]::WriteAllText($r1.Path, 'stale')
        Initialize-FakeDevice -Hostname 'CONTOSO-LT-0043'
        $r2 = New-DoctorDODeviceReport -OutputPath $script:Out -FileName 'DoctorDO-DeviceReport' -Format Both -InformationAction SilentlyContinue
        $r2.Path | Should -Be $r1.Path
        (Get-ReportData -Path $r2.Path)['inventory']['device']['hostname'] | Should -Be 'CONTOSO-LT-0043'
        @(Get-ChildItem -LiteralPath $script:Out | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('DoctorDO-DeviceReport.html', 'DoctorDO-DeviceReport.json')
    }

    It '-FileName refuses a path, an extension, a character or a device name Windows will not take, before collecting anything' {
        foreach ($bad in 'logs\report', 'logs/report', '..\report', 'report.html', 'report.PDF', 'report.json', 'a:b', 'what?', 'report.', ' report', 'CON', 'nul.report', 'COM1', 'lpt9', ('x' * 201)) {
            { New-DoctorDODeviceReport -OutputPath $script:Out -FileName $bad } | Should -Throw "*-FileName '$bad' cannot be used*"
        }
        { New-DoctorDODeviceReport -OutputPath $script:Out -FileName '' } | Should -Throw
        Should -Invoke -ModuleName DoctorDO.Collector Get-DDDOLogEntries -Times 0 -Exactly
        Test-Path -LiteralPath $script:Out | Should -BeFalse
        InModuleScope DoctorDO.Collector {
            foreach ($good in 'DoctorDO-DeviceReport', 'Report v2.1', 'CONSOLE', 'COM10', 'report_2026-10-19') { Test-DDReportBaseName -Name $good | Should -BeNullOrEmpty }
        }
    }

    It '-Open opens the file in Path: the page, or the JSON with -Format Json' {
        Mock -ModuleName DoctorDO.Collector Invoke-Item { }
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Format Both -Open -InformationAction SilentlyContinue
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $r.Path -and $LiteralPath -like '*.html' }
        $j = New-DoctorDODeviceReport -OutputPath $script:Out -Format Json -Open -InformationAction SilentlyContinue
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $j.JsonPath }
    }

    It 'opens the page by itself when a person is at the session, and not with -NoOpen' {
        Mock -ModuleName DoctorDO.Collector Get-DDNonInteractiveReason { $null }
        Mock -ModuleName DoctorDO.Collector Invoke-Item { }
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -InformationAction SilentlyContinue
        $r.Opened | Should -Be $r.Path
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $r.Path }
        $n = New-DoctorDODeviceReport -OutputPath $script:Out -NoOpen -InformationAction SilentlyContinue
        $n.Opened | Should -BeNullOrEmpty
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 1 -Exactly -Because 'the -NoOpen run opened nothing'
    }

    It 'opens nothing where nobody is at the session, and says why under -Verbose; -Open still opens it there' {
        Mock -ModuleName DoctorDO.Collector Get-DDNonInteractiveReason { 'running as SYSTEM' }
        Mock -ModuleName DoctorDO.Collector Invoke-Item { }
        $lines = @(New-DoctorDODeviceReport -OutputPath $script:Out -Verbose -InformationAction SilentlyContinue 4>&1 |
                Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object { $_.Message })
        @($lines | Where-Object { $_ -match '\] Open \.+ not opened: running as SYSTEM$' }).Count | Should -Be 1
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 0 -Exactly
        $r = New-DoctorDODeviceReport -OutputPath $script:Out -Open -InformationAction SilentlyContinue
        $r.Opened | Should -Be $r.Path
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 1 -Exactly
    }

    It 'never opens a JSON file unasked, and refuses -Open with -NoOpen before collecting anything' {
        Mock -ModuleName DoctorDO.Collector Get-DDNonInteractiveReason { $null }
        Mock -ModuleName DoctorDO.Collector Invoke-Item { }
        $j = New-DoctorDODeviceReport -OutputPath $script:Out -Format Json -InformationAction SilentlyContinue
        $j.Opened | Should -BeNullOrEmpty
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 0 -Exactly
        { New-DoctorDODeviceReport -OutputPath $script:Out -Open -NoOpen } | Should -Throw '*-Open or -NoOpen, not both*'
    }

    Context 'PDF' {
        BeforeEach {
            $global:DDPrinted = $null
            Mock -ModuleName DoctorDO.Collector Find-DDPdfBrowser { [pscustomobject]@{ Name = 'Microsoft Edge'; Path = 'C:\Fake\Edge\msedge.exe' } }
            # The browser, faked: it records what it was asked to print and whether that page was on disk, and writes a PDF.
            Mock -ModuleName DoctorDO.Collector Invoke-DDHeadlessPrint {
                $local = ([uri]$Url).LocalPath
                $global:DDPrinted = @{ Browser = $Browser; Url = $Url; PdfPath = $PdfPath; SourceExisted = (Test-Path -LiteralPath $local); Source = $local }
                [System.IO.File]::WriteAllText($PdfPath, "%PDF-1.7`n% fake`n")
            }
        }
        AfterAll { Remove-Variable -Name DDPrinted -Scope Global -ErrorAction SilentlyContinue }

        It '-Format Html,Pdf prints the page it wrote, from a file URL ending #print, and opens the PDF' {
            Mock -ModuleName DoctorDO.Collector Get-DDNonInteractiveReason { $null }
            Mock -ModuleName DoctorDO.Collector Invoke-Item { }
            $r = New-DoctorDODeviceReport -OutputPath $script:Out -Format Html, Pdf -InformationAction SilentlyContinue
            $r.Format | Should -Be 'Html,Pdf'
            Split-Path $r.Path -Leaf | Should -Be 'DoctorDO-CONTOSO-LT-0042-20261012-080000.html'
            Split-Path $r.PdfPath -Leaf | Should -Be 'DoctorDO-CONTOSO-LT-0042-20261012-080000.pdf'
            $r.PdfBytes | Should -Be (Get-Item -LiteralPath $r.PdfPath).Length
            $r.PdfSha256 | Should -Not -Be $r.Sha256
            $global:DDPrinted.Browser | Should -Be 'C:\Fake\Edge\msedge.exe'
            $global:DDPrinted.Url | Should -Match '^file:///.+\.html#print$'
            $global:DDPrinted.Source | Should -Be $r.Path
            @(Get-ChildItem -LiteralPath $script:Out).Count | Should -Be 2
            $r.Opened | Should -Be $r.PdfPath
            Should -Invoke -ModuleName DoctorDO.Collector Invoke-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $r.PdfPath }
        }

        It '-Format Pdf alone keeps only the PDF: the page it printed is removed again' {
            $r = New-DoctorDODeviceReport -OutputPath $script:Out -Format Pdf -Anonymise -InformationAction SilentlyContinue
            $r.Path | Should -Be $r.PdfPath
            Split-Path $r.Path -Leaf | Should -Be 'DoctorDO-report-20261012-080000.pdf'
            $global:DDPrinted.SourceExisted | Should -BeTrue -Because 'the browser prints a file'
            Test-Path -LiteralPath $global:DDPrinted.Source | Should -BeFalse
            @(Get-ChildItem -LiteralPath $script:Out | ForEach-Object { $_.Name }) | Should -Be @('DoctorDO-report-20261012-080000.pdf')
            $r.JsonPath | Should -BeNullOrEmpty
            $r.Opened | Should -BeNullOrEmpty -Because 'the fake device is not an interactive session'
        }

        It '-FileName with -Format Pdf alone replaces the PDF of that name and keeps nothing else (19 Oct 2026)' {
            $r1 = New-DoctorDODeviceReport -OutputPath $script:Out -FileName 'DoctorDO-DeviceReport' -Format Pdf -InformationAction SilentlyContinue
            Split-Path $r1.PdfPath -Leaf | Should -Be 'DoctorDO-DeviceReport.pdf'
            [System.IO.File]::WriteAllText($r1.PdfPath, 'stale')
            $r2 = New-DoctorDODeviceReport -OutputPath $script:Out -FileName 'DoctorDO-DeviceReport' -Format Pdf -InformationAction SilentlyContinue
            $r2.PdfPath | Should -Be $r1.PdfPath
            [System.IO.File]::ReadAllText($r2.PdfPath) | Should -Match '^%PDF-'
            @(Get-ChildItem -LiteralPath $script:Out | ForEach-Object { $_.Name }) | Should -Be @('DoctorDO-DeviceReport.pdf')
        }

        It 'without Edge or Chrome, throws naming both before collecting anything' {
            Mock -ModuleName DoctorDO.Collector Find-DDPdfBrowser { $null }
            { New-DoctorDODeviceReport -OutputPath $script:Out -Format Pdf } | Should -Throw '*Microsoft Edge or Google Chrome*'
            Should -Invoke -ModuleName DoctorDO.Collector Get-DDDOLogEntries -Times 0 -Exactly
            Test-Path -LiteralPath $script:Out | Should -BeFalse
        }

        It 'throws when the browser writes no PDF, and leaves no page of its own behind' {
            Mock -ModuleName DoctorDO.Collector Invoke-DDHeadlessPrint { $global:DDPrinted = @{ Source = ([uri]$Url).LocalPath } }
            { New-DoctorDODeviceReport -OutputPath $script:Out -Format Pdf -InformationAction SilentlyContinue } | Should -Throw '*did not write the PDF*'
            Test-Path -LiteralPath $global:DDPrinted.Source | Should -BeFalse
            @(Get-ChildItem -LiteralPath $script:Out).Count | Should -Be 0
        }
    }

    It 'ConvertTo-DDPrettyJson only moves whitespace: the same value back, empty containers kept, structural characters in strings untouched' {
        $text = InModuleScope DoctorDO.Collector {
            $o = [ordered]@{ a = @(); b = [ordered]@{}; c = @(1, 2); d = 'x{[,:]}"\'; e = [ordered]@{ f = $null; g = $true } }
            $c = ConvertTo-DDCanonicalJson -InputObject $o
            $p = ConvertTo-DDPrettyJson -Json $c
            @($c, $p, (ConvertTo-DDCanonicalJson -InputObject (ConvertFrom-DDJson -Text $p)))
        }
        $text[2] | Should -BeExactly $text[0]
        $text[1] | Should -Match '"a": \[\],'
        $text[1] | Should -Match '"b": \{\},'
        $text[1] | Should -Match '"d": "x\{\[,:\]\}\\"\\\\"'
    }

    It 'refuses a missing or damaged page with a reason, and runs on Windows only' {
        $template = [System.IO.File]::ReadAllText((InModuleScope DoctorDO.Collector { Get-DDReportTemplatePath }))
        Mock -ModuleName DoctorDO.Collector Get-DDReportTemplatePath { Join-Path $TestDrive 'absent.html' }
        { New-DoctorDODeviceReport -OutputPath $script:Out } | Should -Throw '*is missing from the module*'
        $twice = Join-Path $TestDrive 'twice.html'
        [System.IO.File]::WriteAllText($twice, $template.Replace('</body>', '"__DOCTORDO_REPORT_DATA__"</body>'))
        Mock -ModuleName DoctorDO.Collector Get-DDReportTemplatePath { $twice }
        { New-DoctorDODeviceReport -OutputPath $script:Out } | Should -Throw '*placeholder*'
        $crlf = Join-Path $TestDrive 'crlf.html'
        $i = $template.IndexOf('<script>')
        [System.IO.File]::WriteAllText($crlf, $template.Substring(0, $i) + $template.Substring($i).Replace("`n", "`r`n"))
        Mock -ModuleName DoctorDO.Collector Get-DDReportTemplatePath { $crlf }
        { New-DoctorDODeviceReport -OutputPath $script:Out } | Should -Throw '*Content-Security-Policy hash*'
        Mock -ModuleName DoctorDO.Collector Test-DDWindows { $false }
        { New-DoctorDODeviceReport -OutputPath $script:Out } | Should -Throw '*Windows only*'
        Test-Path -LiteralPath $script:Out | Should -BeFalse -Because 'nothing is written when the report cannot be made'
    }
}

Describe 'Opening and printing the report: the platform side' {
    It 'Find-DDPdfBrowser takes Edge from its App Paths key, and falls back to Chrome in the standard folders' {
        $saved = @{ X86 = ${env:ProgramFiles(x86)}; Pf = $env:ProgramFiles; Local = $env:LOCALAPPDATA }
        try {
            $edge = Join-Path $TestDrive 'apppaths\msedge.exe'
            New-Item -ItemType File -Path $edge -Force | Out-Null
            ${env:ProgramFiles(x86)} = Join-Path $TestDrive 'pf86'; $env:ProgramFiles = Join-Path $TestDrive 'pf'; $env:LOCALAPPDATA = Join-Path $TestDrive 'local'
            Mock -ModuleName DoctorDO.Collector Test-DDWindows { $true }
            Mock -ModuleName DoctorDO.Collector Get-DDRegistryValue { $null }
            Mock -ModuleName DoctorDO.Collector Get-DDRegistryValue -ParameterFilter { $Path -like 'HKLM\*\App Paths\msedge.exe' } { '"' + (Join-Path $TestDrive 'apppaths\msedge.exe') + '"' }
            $b = InModuleScope DoctorDO.Collector { Find-DDPdfBrowser }
            $b.Name | Should -Be 'Microsoft Edge'
            $b.Path | Should -Be $edge
            Remove-Item -LiteralPath $edge
            $chrome = Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
            New-Item -ItemType File -Path $chrome -Force | Out-Null
            $c = InModuleScope DoctorDO.Collector { Find-DDPdfBrowser }
            $c.Name | Should -Be 'Google Chrome'
            $c.Path | Should -Be $chrome
            Remove-Item -LiteralPath $chrome
            InModuleScope DoctorDO.Collector { Find-DDPdfBrowser } | Should -BeNullOrEmpty
        } finally {
            ${env:ProgramFiles(x86)} = $saved.X86; $env:ProgramFiles = $saved.Pf; $env:LOCALAPPDATA = $saved.Local
        }
    }

    It 'Get-DDNonInteractiveReason refuses another platform, and a process Intune, the Task Scheduler or ConfigMgr started' {
        Mock -ModuleName DoctorDO.Collector Test-DDWindows { $false }
        InModuleScope DoctorDO.Collector { Get-DDNonInteractiveReason } | Should -Be 'not Windows'
        if ($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows) {
            Mock -ModuleName DoctorDO.Collector Test-DDWindows { $true }
            foreach ($parent in 'AgentExecutor', 'svchost', 'CcmExec') {
                $global:DDParent = $parent
                Mock -ModuleName DoctorDO.Collector Get-DDParentProcessName { $global:DDParent }
                # Whatever this test host is (a desktop, or a CI service in session 0), it is never taken as a person.
                InModuleScope DoctorDO.Collector { Get-DDNonInteractiveReason } | Should -Not -BeNullOrEmpty -Because "a process $parent started"
            }
            Remove-Variable -Name DDParent -Scope Global
        }
    }

    It 'prints from a file URL with #print, and recognises a PDF by its first bytes' {
        $page = Join-Path $TestDrive 'a b\DoctorDO-PC-20261012-080000.html'
        $url = InModuleScope DoctorDO.Collector -Parameters @{ P = $page } { param($P) Get-DDReportPrintUrl -Path $P }
        $url | Should -Match '^file:///.+/a%20b/DoctorDO-PC-20261012-080000\.html#print$'
        $pdf = Join-Path $TestDrive 'x.pdf'
        [System.IO.File]::WriteAllText($pdf, '%PDF-1.7')
        InModuleScope DoctorDO.Collector -Parameters @{ P = $pdf } { param($P) Test-DDPdfFile -Path $P } | Should -BeTrue
        [System.IO.File]::WriteAllText($pdf, '')
        InModuleScope DoctorDO.Collector -Parameters @{ P = $pdf } { param($P) Test-DDPdfFile -Path $P } | Should -BeFalse
        InModuleScope DoctorDO.Collector -Parameters @{ P = (Join-Path $TestDrive 'none.pdf') } { param($P) Test-DDPdfFile -Path $P } | Should -BeFalse
    }
}
