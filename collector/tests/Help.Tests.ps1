#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Command-line help (Get-Help <command> -Full) for every exported command, from the comment-based help in Public/*.ps1:
# a synopsis written for it and a description, at least two examples each with an explanation, every parameter
# documented and no help for a parameter the command does not have, at least one related link; and the
# about_DoctorDO.Collector topic in en-US. The commands are taken from the manifest, so a new export needs its help.
BeforeDiscovery {
    $psd1 = Join-Path $PSScriptRoot '../DoctorDO.Collector/DoctorDO.Collector.psd1'
    $script:Commands = @((Import-PowerShellDataFile -Path $psd1)['FunctionsToExport'] | ForEach-Object { @{ Name = $_ } })
}
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:ModuleRoot = (Resolve-Path (Join-Path $PSScriptRoot '../DoctorDO.Collector')).Path
    $script:CommonNames = @([System.Management.Automation.PSCmdlet]::CommonParameters) + @([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)
    # The text of a help node (description, remarks: arrays of objects with a Text property), strict-mode safe.
    function Get-HelpText {
        param($Node)
        if ($null -eq $Node) { return '' }
        $parts = foreach ($n in @($Node)) {
            if ($n -is [string]) { $n }
            elseif ($null -ne $n.PSObject.Properties['Text']) { [string]$n.Text }
        }
        (@($parts) -join "`n").Trim()
    }
    function Get-HelpProperty {
        param($Object, [string] $Name)
        if ($null -eq $Object) { return $null }
        $p = $Object.PSObject.Properties[$Name]
        if ($null -eq $p) { return $null }
        $p.Value
    }
}

Describe 'Help for <Name>' -ForEach $script:Commands {
    BeforeAll {
        $script:Cmd = Get-Command -Name $Name -Module DoctorDO.Collector -ErrorAction SilentlyContinue
        $script:Help = Get-Help -Name $Name -Full
        $script:Own = @()
        if ($null -ne $script:Cmd) {
            $script:Own = @($script:Cmd.Parameters.Keys | Where-Object { $_ -notin $script:CommonNames })
        }
    }

    It 'is exported by the module' {
        $script:Cmd | Should -Not -BeNullOrEmpty
    }

    It 'has a synopsis written for it, not the generated syntax line' {
        $s = [string](Get-HelpProperty $script:Help 'Synopsis')
        $s.Trim() | Should -Not -BeNullOrEmpty
        $s | Should -Not -Match ('^\s*' + [regex]::Escape($Name) + '\s*(\[|$)') -Because 'Get-Help falls back to the syntax when there is no .SYNOPSIS'
    }

    It 'has a description' {
        (Get-HelpText (Get-HelpProperty $script:Help 'description')) | Should -Not -BeNullOrEmpty
    }

    It 'has at least two examples, each with code and an explanation' {
        $examples = @()
        $node = Get-HelpProperty $script:Help 'examples'
        if ($null -ne $node) { $examples = @(Get-HelpProperty $node 'example' | Where-Object { $null -ne $_ }) }
        $examples.Count | Should -BeGreaterOrEqual 2
        $i = 0
        foreach ($e in $examples) {
            $i++
            ([string](Get-HelpProperty $e 'code')).Trim() | Should -Not -BeNullOrEmpty -Because "example $i needs a command"
            (Get-HelpText (Get-HelpProperty $e 'remarks')) | Should -Not -BeNullOrEmpty -Because "example $i needs an explanation after a blank line"
        }
    }

    It 'documents every parameter' {
        $documented = @{}
        $node = Get-HelpProperty $script:Help 'parameters'
        if ($null -ne $node) {
            foreach ($p in @(Get-HelpProperty $node 'parameter' | Where-Object { $null -ne $_ })) {
                if (Get-HelpText (Get-HelpProperty $p 'description')) { $documented[[string]$p.name] = $true }
            }
        }
        $undocumented = @($script:Own | Where-Object { -not $documented.ContainsKey($_) })
        $undocumented | Should -BeNullOrEmpty -Because "each parameter of $Name needs a .PARAMETER entry"
    }

    It 'documents no parameter the command does not have' {
        $helpContent = $script:Cmd.ScriptBlock.Ast.GetHelpContent()
        $helpContent | Should -Not -BeNullOrEmpty
        $own = @($script:Own | ForEach-Object { $_.ToUpperInvariant() })
        $stale = @($helpContent.Parameters.Keys | Where-Object { $_.ToUpperInvariant() -notin $own })
        $stale | Should -BeNullOrEmpty -Because 'a .PARAMETER for a removed or renamed parameter is stale help'
    }

    It 'has at least one related link' {
        @($script:Cmd.ScriptBlock.Ast.GetHelpContent().Links).Count | Should -BeGreaterOrEqual 1
    }
}

Describe 'about_DoctorDO.Collector' {
    BeforeAll {
        $script:About = Join-Path $script:ModuleRoot 'en-US/about_DoctorDO.Collector.help.txt'
    }

    It 'ships in en-US as pure ASCII (Windows PowerShell 5.1 reads a BOM-less file as the ANSI code page)' {
        Test-Path -LiteralPath $script:About -PathType Leaf | Should -BeTrue
        $bytes = [System.IO.File]::ReadAllBytes($script:About)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'names the topic and every exported command' {
        $text = [System.IO.File]::ReadAllText($script:About)
        $text | Should -Match '(?m)^\s*about_DoctorDO\.Collector\s*$'
        $text | Should -Match '(?m)^SHORT DESCRIPTION'
        foreach ($c in @(Get-Command -Module DoctorDO.Collector)) { $text | Should -Match ([regex]::Escape($c.Name)) -Because "the topic should list $($c.Name)" }
    }
}
