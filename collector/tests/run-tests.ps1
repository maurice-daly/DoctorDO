#Requires -Version 5.1
<#
.SYNOPSIS
    Run the collector's Pester 5 suite.
.DESCRIPTION
    Pester 5 is required (the suite uses Pester 5 syntax). The suite mocks every Windows-only call, so it runs on
    Linux and macOS under PowerShell 7 as well as on Windows. Exit code 0 when everything passes.
.PARAMETER PesterPath
    Path to Pester.psd1 when Pester 5 is not installed in a module path.
.PARAMETER Output
    Pester output verbosity (default Detailed).
.EXAMPLE
    .\run-tests.ps1
.EXAMPLE
    .\run-tests.ps1 -PesterPath ..\..\.tools\psmodules\pester\5.9.1\tools\Pester.psd1
#>
[CmdletBinding()]
param([string] $PesterPath, [string] $Output = 'Detailed')

Set-StrictMode -Version Latest
if ($PesterPath) { Import-Module -Name $PesterPath -Force } else { Import-Module -Name Pester -MinimumVersion 5.0.0 -Force }
$cfg = New-PesterConfiguration
$cfg.Run.Path = $PSScriptRoot
$cfg.Run.Exit = $true
$cfg.Output.Verbosity = $Output
$cfg.CodeCoverage.Enabled = $false
Invoke-Pester -Configuration $cfg
