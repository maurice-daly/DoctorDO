#Requires -Version 5.1
# Copyright (c) 2026 Maurice Daly. SPDX-License-Identifier: MIT (see LICENSE in this folder).
# The DoctorDO.Collector module that this script installs is not MIT: it has its own licence (LICENSE in the module folder).

<#
.SYNOPSIS
    Win32 app install and uninstall script for the DoctorDO.Collector module.
.DESCRIPTION
    Package this script with the module folder that Save-PSResource (or Save-Module) writes, unchanged:

        Save-PSResource -Name DoctorDO.Collector -Path .\package
        Copy-Item .\Install-DoctorDOCollector.ps1 .\package
        IntuneWinAppUtil.exe -c .\package -s Install-DoctorDOCollector.ps1 -o .\out

    Install copies DoctorDO.Collector\<version> from beside this script to
    %ProgramFiles%\WindowsPowerShell\Modules\DoctorDO.Collector\<version>, the 64-bit module folder that Windows
    PowerShell 5.1 (which Intune remediations use) and PowerShell 7 both search. -Uninstall removes that version again.
    Nothing else on the device is changed.

    Intune starts powershell.exe from a Win32 app command line as a 32-bit process, where %ProgramFiles% is
    "Program Files (x86)". The script relaunches itself in 64-bit PowerShell first, so the module always lands in the
    64-bit folder. (Intune does not expand environment variables in the uninstall command, which is why the commands
    below call powershell.exe and leave the switch to 64-bit to the script.)

    Intune settings:
        Install command    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-DoctorDOCollector.ps1
        Uninstall command  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-DoctorDOCollector.ps1 -Uninstall
        Install behavior   System
        Detection rule     File: %ProgramFiles%\WindowsPowerShell\Modules\DoctorDO.Collector\<version>, DoctorDO.Collector.psd1 exists,
                           "Associated with a 32-bit app on 64-bit clients" = No

    Exit codes: 0 done; 1 failed (the output line says why).
.PARAMETER Uninstall
    Remove the module version this package carries instead of installing it.
.PARAMETER ModulesPath
    The module folder to install to. Default: %ProgramFiles%\WindowsPowerShell\Modules (64-bit). For testing only.
.EXAMPLE
    .\Install-DoctorDOCollector.ps1

    Installs the module version in this package for all users.
.EXAMPLE
    .\Install-DoctorDOCollector.ps1 -Uninstall

    Removes that version again; other versions of the module are left alone.
#>
[CmdletBinding()]
param(
    [switch] $Uninstall,
    [string] $ModulesPath = ''
)

Set-StrictMode -Version Latest

function Install-DoctorDOCollectorModule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string] $SourceRoot, [Parameter(Mandatory)][string] $ModulesPath, [switch] $Uninstall)

    $source = Join-Path -Path $SourceRoot -ChildPath 'DoctorDO.Collector'
    $manifest = Get-ChildItem -LiteralPath $source -Filter 'DoctorDO.Collector.psd1' -Recurse -Depth 1 -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $manifest) { return [pscustomobject]@{ ExitCode = 1; Message = "No DoctorDO.Collector module folder beside the script ($source)." } }
    $version = [string](Import-PowerShellDataFile -LiteralPath $manifest.FullName)['ModuleVersion']
    $target = Join-Path -Path (Join-Path -Path $ModulesPath -ChildPath 'DoctorDO.Collector') -ChildPath $version
    if ($Uninstall) {
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
        $parent = Split-Path -Path $target -Parent
        if ((Test-Path -LiteralPath $parent) -and @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) { Remove-Item -LiteralPath $parent -Force }
        return [pscustomobject]@{ ExitCode = 0; Message = "DoctorDO.Collector $version removed from $ModulesPath." }
    }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Copy-Item -Path (Join-Path -Path $manifest.DirectoryName -ChildPath '*') -Destination $target -Recurse -Force
    if (-not (Test-Path -LiteralPath (Join-Path -Path $target -ChildPath 'DoctorDO.Collector.psd1'))) {
        return [pscustomobject]@{ ExitCode = 1; Message = "Copy to $target did not complete." }
    }
    [pscustomobject]@{ ExitCode = 0; Message = "DoctorDO.Collector $version installed to $target." }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([System.Environment]::Is64BitOperatingSystem -and -not [System.Environment]::Is64BitProcess) {
        $sysnative = Join-Path -Path $env:windir -ChildPath 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        if ($Uninstall) { $relaunch += '-Uninstall' }
        if ($ModulesPath) { $relaunch += @('-ModulesPath', $ModulesPath) }
        & $sysnative @relaunch
        exit $LASTEXITCODE
    }
    if (-not $ModulesPath) { $ModulesPath = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsPowerShell\Modules' }
    try {
        $r = Install-DoctorDOCollectorModule -SourceRoot $PSScriptRoot -ModulesPath $ModulesPath -Uninstall:$Uninstall
    } catch {
        $r = [pscustomobject]@{ ExitCode = 1; Message = "DoctorDO.Collector install failed: $($_.Exception.Message)" }
    }
    Write-Output $r.Message
    exit $r.ExitCode
}
