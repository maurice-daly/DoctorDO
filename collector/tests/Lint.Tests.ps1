#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Stand-in for PSScriptAnalyzer (not obtainable here, see README): parser, strict mode, approved verbs, no aliases,
# no Invoke-Expression, no Write-Host, no empty catch, no PowerShell 7-only syntax (the module targets 5.1), help present.
BeforeDiscovery {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:Files = @(Get-ChildItem -Path $root -Recurse -Include *.ps1, *.psm1, *.psd1 -File | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' } | ForEach-Object { @{ Path = $_.FullName; Name = $_.FullName.Substring($root.Length + 1) } })
}
BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:Verbs = (Get-Verb).Verb
    function Get-Ast { param($Path) $t = $null; $e = $null; $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$t, [ref]$e); @{ Ast = $ast; Tokens = $t; Errors = $e } }
}

Describe 'Static checks: <Name>' -ForEach $script:Files {
    BeforeAll { $script:P = Get-Ast -Path $Path }

    It 'parses without errors' { $script:P.Errors | Should -BeNullOrEmpty }

    It 'is pure ASCII (Windows PowerShell 5.1 reads a BOM-less file as the ANSI code page; Intune wants UTF-8)' {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'uses no Invoke-Expression, no Write-Host, and no command alias' {
        $cmds = $script:P.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        foreach ($c in $cmds) {
            $n = $c.GetCommandName()
            if (-not $n) { continue }
            $n | Should -Not -BeIn @('Invoke-Expression', 'iex', 'Write-Host')
            $cmd = Get-Command -Name $n -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cmd -and $cmd.CommandType -eq 'Alias') { throw "alias '$n' used at line $($c.Extent.StartLineNumber)" }
        }
    }

    It 'has no empty catch block' {
        $empty = $script:P.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CatchClauseAst] -and $n.Body.Statements.Count -eq 0 }, $true)
        $empty | Should -BeNullOrEmpty
    }

    It 'uses no syntax that Windows PowerShell 5.1 cannot parse (ternary, ??, ?., &&, ||, -Parallel)' {
        $bad = $script:P.Ast.FindAll({ param($n) $n.GetType().Name -in 'TernaryExpressionAst', 'PipelineChainAst', 'NullConditionalMemberAccessAst', 'NullConditionalIndexExpressionAst' }, $true)
        $bad | Should -BeNullOrEmpty
        ($script:P.Tokens | Where-Object { $_.Text -in '??', '??=', '?.', '?[' }) | Should -BeNullOrEmpty
        ($script:P.Tokens | Where-Object { $_.Kind -eq 'Parameter' -and $_.Text -eq '-Parallel' }) | Should -BeNullOrEmpty
    }

    It 'defines only functions with approved verbs' {
        $fns = $script:P.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        foreach ($f in $fns) { ($f.Name.Split('-')[0]) | Should -BeIn $script:Verbs -Because "function $($f.Name)" }
    }

    It 'declares no password, key or secret parameter' {
        $params = $script:P.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)
        foreach ($p in $params) { $p.Name.VariablePath.UserPath | Should -Not -Match '^(Password|Secret|ApiKey|IngestKey|TenantKey|Token|Credential)$' }
    }
}

Describe 'Strict mode' {
    It 'every module and script file sets Set-StrictMode -Version Latest' {
        $files = Get-ChildItem -Path $script:Root -Recurse -Include *.ps1, *.psm1 -File | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]|[\\/]Public[\\/]' }
        foreach ($f in $files) { (Get-Content -LiteralPath $f.FullName -Raw) | Should -Match 'Set-StrictMode -Version Latest' -Because $f.Name }
    }
    It 'the module root sets strict mode before dot-sourcing anything' {
        $t = Get-Content -LiteralPath (Join-Path $script:Root 'DoctorDO.Collector/DoctorDO.Collector.psm1') -Raw
        $t.IndexOf('Set-StrictMode -Version Latest') | Should -BeLessThan $t.IndexOf('. $file.FullName')
    }
}

Describe 'Module manifest' {
    It 'is valid, exports exactly the Public functions, and agrees on the version' {
        $psd1 = Join-Path $script:Root 'DoctorDO.Collector/DoctorDO.Collector.psd1'
        $m = Test-ModuleManifest -Path $psd1
        $m.Version.ToString() | Should -Be '1.2.3'
        $public = Get-ChildItem (Join-Path $script:Root 'DoctorDO.Collector/Public') -Filter *.ps1 | ForEach-Object { $_.BaseName }
        ($m.ExportedFunctions.Keys | Sort-Object) | Should -Be ($public | Sort-Object)
        # The version the collector reports in its data (collector.version) is the manifest's.
        (Get-Content (Join-Path $script:Root 'DoctorDO.Collector/DoctorDO.Collector.psm1') -Raw) | Should -Match ("CollectorVersion = '" + [regex]::Escape($m.Version.ToString()) + "'")
        $m.PowerShellVersion.ToString() | Should -Be '5.1'
    }
    It 'the LicenseUri and ProjectUri are the DoctorDO site''s licence and get-started pages, which anyone can open' {
        $d = Import-PowerShellDataFile -LiteralPath (Join-Path $script:Root 'DoctorDO.Collector/DoctorDO.Collector.psd1')
        $d.PrivateData.PSData.LicenseUri | Should -Be 'https://www.doctor-do.com/licence/'
        $d.PrivateData.PSData.ProjectUri | Should -Be 'https://www.doctor-do.com/get-started/'
    }
    It 'links nowhere in the DoctorDO GitHub repository, which is private: help, messages and data use the site''s pages' {
        $files = Get-ChildItem -LiteralPath (Join-Path $script:Root 'DoctorDO.Collector') -Recurse -File
        $hits = foreach ($f in $files) { if ((Get-Content -LiteralPath $f.FullName -Raw) -match '(?i)github(usercontent)?\.com/maurice-daly') { $f.Name } }
        $hits | Should -BeNullOrEmpty
    }
    It 'the FileList names every file of the module folder, and nothing else (the remediation accepts exactly these)' {
        $moduleRoot = Join-Path $script:Root 'DoctorDO.Collector'
        $d = Import-PowerShellDataFile -LiteralPath (Join-Path $moduleRoot 'DoctorDO.Collector.psd1')
        $onDisk = @(Get-ChildItem -LiteralPath $moduleRoot -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($moduleRoot.Length).TrimStart('\', '/').Replace('\', '/') } | Sort-Object)
        @($d.FileList | Sort-Object) | Should -Be $onDisk
        @($d.FileList | Where-Object { $_ -match '\\|^/|\.\.' }).Count | Should -Be 0
    }
    It 'every public function has comment-based help with a synopsis' {
        Import-Module (Join-Path $script:Root 'DoctorDO.Collector/DoctorDO.Collector.psd1') -Force -DisableNameChecking
        foreach ($c in (Get-Command -Module DoctorDO.Collector)) { (Get-Help $c.Name).Synopsis | Should -Not -BeNullOrEmpty -Because $c.Name; (Get-Help $c.Name).Synopsis | Should -Not -Match '^\s*\S+\s*\[' -Because "$($c.Name) has real help" }
    }
    It 'the module has no dependency beyond built-in modules' {
        $m = Test-ModuleManifest -Path (Join-Path $script:Root 'DoctorDO.Collector/DoctorDO.Collector.psd1')
        @($m.RequiredModules).Count | Should -Be 0
    }
}

Describe 'PSScriptAnalyzer stand-in across the tests too' {
    It 'passes no string literal to a -ComputerName parameter (PSAvoidUsingComputerNameHardcoded, enforced in CI)' {
        $bad = foreach ($f in Get-ChildItem -Path $script:Root -Recurse -Include *.ps1, *.psm1 -File) {
            $ast = (Get-Ast -Path $f.FullName).Ast
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $els = $c.CommandElements
                for ($i = 0; $i -lt $els.Count; $i++) {
                    $e = $els[$i]
                    if ($e -isnot [System.Management.Automation.Language.CommandParameterAst] -or $e.ParameterName -ne 'ComputerName') { continue }
                    $arg = $e.Argument
                    if (-not $arg -and $i + 1 -lt $els.Count) { $arg = $els[$i + 1] }
                    if ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst]) { "$($f.Name):$($c.Extent.StartLineNumber)" }
                }
            }
        }
        $bad | Should -BeNullOrEmpty
    }
}
